// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Inspect is a parsed docker.inspect result. Every field comes from the
// host; fields that do not fit are left empty.
type Inspect struct {
	Phase            string // done or precheck
	Reason           string
	Container        string
	ID               string // first 12 hex digits
	FullID           string // full 64 hex digits
	Name             string
	Image            string
	ImageID          string // image configuration ID (sha256:...), the platform digest
	Created          string // container creation time, RFC 3339 UTC, "" if not parseable
	ImageCreated     string // image creation time, RFC 3339 UTC, "" if not parseable
	Platform         string // image platform "os/arch" or "os/arch/variant"
	Digests          []string
	ImageDigestIndex string // first registry manifest/index digest, "" if none
	Status           string
	ExitCode         int
	Started          string // RFC 3339 in UTC, "" if never
	Finished         string
	Restarts         int
	RestartPolicy    string
	Health           string
	FailingStreak    int
	Mounts           []Mount
	Ports            []PortMap
	Networks         []Network
}

// Mount is one mount of a container.
type Mount struct {
	Type, Name, Source, Destination string
	ReadOnly                        bool
}

// PortMap is one published port: container port and protocol, host address.
type PortMap struct{ Container, Host string }

// Network is one network of a container with its address there.
type Network struct{ Name, IP string }

// ErrInspectFormat means the result is not a docker.inspect result.
var ErrInspectFormat = errors.New("dockerhost: not a docker.inspect result")

const (
	maxMounts   = 100
	maxPorts    = 200
	maxNetworks = 50
	maxDigests  = 20
	maxImage    = 64 << 10 // one image's metadata, after base64 decode
)

var (
	imageIDRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	digestRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	portRe        = regexp.MustCompile(`^[0-9]{1,5}/(tcp|udp|sctp)$`)
	hostPortRe    = regexp.MustCompile(`^[0-9]{1,5}$`)
	hostIPRe      = regexp.MustCompile(`^[0-9A-Fa-f.:]{0,45}$`)
	ipRe          = regexp.MustCompile(`^[0-9A-Fa-f.:]{0,45}$`)
	netNameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	mountTypes    = map[string]bool{"bind": true, "volume": true, "tmpfs": true, "npipe": true, "cluster": true, "image": true}
	restartPolicy = map[string]bool{"": true, "no": true, "always": true, "unless-stopped": true, "on-failure": true}
	healthStates  = map[string]bool{"starting": true, "healthy": true, "unhealthy": true}
)

func text(s string, limit int) string {
	if printable(s, limit) {
		return s
	}
	return ""
}

// when returns an RFC 3339 time in UTC, or "" for docker's zero time and
// anything that is not a time.
func when(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// createdFromList parses a `docker ps` {{.CreatedAt}} value (docker renders
// it in Go's default time layout) or RFC 3339, and returns RFC 3339 in UTC.
func createdFromList(s string) string {
	s = text(s, 64)
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05 -0700 MST"} {
		if t, err := time.Parse(layout, s); err == nil && t.Year() >= 2000 {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// platformFrom builds "os/arch" or "os/arch/variant" from image fields.
func platformFrom(os, arch, variant string) string {
	os, arch, variant = text(os, 32), text(arch, 32), text(variant, 32)
	if os == "" && arch == "" {
		return ""
	}
	p := os + "/" + arch
	if variant != "" {
		p += "/" + variant
	}
	return p
}

// ParseInspect reads a docker.inspect result.
func ParseInspect(result []byte) (Inspect, error) {
	var doc struct {
		Format    string `json:"format"`
		Phase     string `json:"phase"`
		Reason    string `json:"reason"`
		Container string `json:"container"`
		Inspect   string `json:"inspect"`
		Image     string `json:"image"`
		Digests   string `json:"digests"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-inspect-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return Inspect{}, ErrInspectFormat
	}
	in := Inspect{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		in.Reason = text(doc.Reason, 300)
		return in, nil
	}
	if containerRe.MatchString(doc.Container) {
		in.Container = doc.Container
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Inspect)
	if err != nil || len(raw) > maxRawSize {
		return Inspect{}, ErrInspectFormat
	}
	var c struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Image   string `json:"image"`
		ImageID string `json:"image_id"`
		Created string `json:"created"`
		State   struct {
			Status     string `json:"Status"`
			ExitCode   int    `json:"ExitCode"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
			Health     *struct {
				Status        string `json:"Status"`
				FailingStreak int    `json:"FailingStreak"`
			} `json:"Health"`
		} `json:"state"`
		Restarts      int    `json:"restarts"`
		RestartPolicy string `json:"restart_policy"`
		Mounts        []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"mounts"`
		Ports    map[string][]struct{ HostIp, HostPort string } `json:"ports"`
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"networks"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return Inspect{}, ErrInspectFormat
	}
	if idRe.MatchString(c.ID) {
		in.ID = c.ID[:12]
		in.FullID = c.ID
	}
	in.Created = when(c.Created)
	if n := strings.TrimPrefix(c.Name, "/"); nameRe.MatchString(n) {
		in.Name = n
	}
	in.Image = text(c.Image, 300)
	if imageIDRe.MatchString(c.ImageID) {
		in.ImageID = c.ImageID
	}
	if states[c.State.Status] {
		in.Status = c.State.Status
	}
	if c.State.ExitCode >= -1 && c.State.ExitCode <= 1<<16 {
		in.ExitCode = c.State.ExitCode
	}
	in.Started, in.Finished = when(c.State.StartedAt), when(c.State.FinishedAt)
	if c.Restarts >= 0 {
		in.Restarts = c.Restarts
	}
	if restartPolicy[c.RestartPolicy] {
		in.RestartPolicy = c.RestartPolicy
	}
	if h := c.State.Health; h != nil && healthStates[h.Status] {
		in.Health = h.Status
		if h.FailingStreak >= 0 {
			in.FailingStreak = h.FailingStreak
		}
	}
	for _, m := range c.Mounts {
		if len(in.Mounts) >= maxMounts {
			break
		}
		if !mountTypes[m.Type] || !printable(m.Destination, 500) || !strings.HasPrefix(m.Destination, "/") {
			continue
		}
		in.Mounts = append(in.Mounts, Mount{Type: m.Type, Name: text(m.Name, 255), Source: text(m.Source, 500),
			Destination: m.Destination, ReadOnly: !m.RW})
	}
	for port, binds := range c.Ports {
		if !portRe.MatchString(port) {
			continue
		}
		for _, b := range binds {
			if len(in.Ports) >= maxPorts {
				break
			}
			if hostIPRe.MatchString(b.HostIp) && hostPortRe.MatchString(b.HostPort) {
				in.Ports = append(in.Ports, PortMap{Container: port, Host: joinHostPort(b.HostIp, b.HostPort)})
			}
		}
		if len(binds) == 0 && len(in.Ports) < maxPorts {
			in.Ports = append(in.Ports, PortMap{Container: port})
		}
	}
	sort.Slice(in.Ports, func(i, j int) bool {
		a, b := in.Ports[i], in.Ports[j]
		if a.Container != b.Container {
			return portLess(a.Container, b.Container)
		}
		return a.Host < b.Host
	})
	for name, n := range c.Networks {
		if len(in.Networks) >= maxNetworks {
			break
		}
		if !netNameRe.MatchString(name) {
			continue
		}
		ip := n.IPAddress
		if !ipRe.MatchString(ip) {
			ip = ""
		}
		if ip == "" && ipRe.MatchString(n.GlobalIPv6Address) {
			ip = n.GlobalIPv6Address
		}
		in.Networks = append(in.Networks, Network{Name: name, IP: ip})
	}
	sort.Slice(in.Networks, func(i, j int) bool { return in.Networks[i].Name < in.Networks[j].Name })
	if doc.Image != "" {
		if b, err := base64.StdEncoding.DecodeString(doc.Image); err == nil && len(b) <= maxImage {
			var im struct {
				ID           string   `json:"id"`
				Created      string   `json:"created"`
				OS           string   `json:"os"`
				Architecture string   `json:"architecture"`
				Variant      string   `json:"variant"`
				RepoDigests  []string `json:"repo_digests"`
			}
			if json.Unmarshal(b, &im) == nil {
				if imageIDRe.MatchString(im.ID) {
					in.ImageID = im.ID
				}
				in.ImageCreated = when(im.Created)
				in.Platform = platformFrom(im.OS, im.Architecture, im.Variant)
				for _, x := range im.RepoDigests {
					if len(in.Digests) < maxDigests && digestRe.MatchString(x) {
						in.Digests = append(in.Digests, x)
					}
				}
			}
		}
	} else if b, err := base64.StdEncoding.DecodeString(doc.Digests); err == nil && len(b) <= maxRawSize {
		var ds []string
		if json.Unmarshal(b, &ds) == nil {
			for _, x := range ds {
				if len(in.Digests) < maxDigests && digestRe.MatchString(x) {
					in.Digests = append(in.Digests, x)
				}
			}
		}
	}
	if len(in.Digests) > 0 {
		in.ImageDigestIndex = in.Digests[0]
	}
	return in, nil
}

func joinHostPort(ip, port string) string {
	switch {
	case ip == "":
		return port
	case strings.Contains(ip, ":"):
		return "[" + ip + "]:" + port
	}
	return ip + ":" + port
}

// portLess orders "80/tcp" before "443/tcp" before "53/udp".
func portLess(a, b string) bool {
	pa, protoA, _ := strings.Cut(a, "/")
	pb, protoB, _ := strings.Cut(b, "/")
	if protoA != protoB {
		return protoA < protoB
	}
	na, _ := strconv.Atoi(pa)
	nb, _ := strconv.Atoi(pb)
	return na < nb
}
