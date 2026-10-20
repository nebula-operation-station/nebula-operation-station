// SPDX-License-Identifier: AGPL-3.0-or-later

// Package discoveryjob is the file format between nebula-server and
// nebula-discovery (spec 12, M9-2): a job the server writes into the
// spool, the fixed Nmap arguments for it, and the result discovery writes
// back. Both sides validate everything they read; scan results are
// untrusted network data (spec 09).
package discoveryjob

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Formats.
const (
	JobFormat    = "nebula-discovery-job-v1"
	ResultFormat = "nebula-discovery-result-v1"
)

// Mode of a scan (decision 2 of the M9 plan).
type Mode string

// Modes.
const (
	ModePing     Mode = "ping"     // host discovery (-sn)
	ModePorts    Mode = "ports"    // selected ports (-sS -p LIST)
	ModeServices Mode = "services" // service discovery (-sV --top-ports 100)
	ModeFullTCP  Mode = "full_tcp" // every TCP port (-sS -p-)
	ModeCustom   Mode = "custom"   // fixed allowlist of options
)

// Modes lists the modes in display order.
var Modes = []Mode{ModePing, ModePorts, ModeServices, ModeFullTCP, ModeCustom}

// Limits.
const (
	MaxTargets       = 16
	MaxAddresses     = 1 << 16 // per job
	MaxPortItems     = 32
	MaxJobBytes      = 16 << 10
	MaxResultBytes   = 32 << 20
	MaxNmapXMLBytes  = 64 << 20
	MaxHosts         = MaxAddresses
	MaxPortsPerHost  = 200
	MaxText          = 128
	MinV4PrefixBits  = 16
	MinV6PrefixBits  = 112
	MaxTopPorts      = 1000
	DefaultTiming    = 3
	nmapHostTimeout  = "10m"
	nmapMaxRetries   = "2"
	defaultTopPorts  = "100"
	idPattern        = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	portsItemPattern = `^[0-9]{1,5}(-[0-9]{1,5})?$`
)

var (
	idRe        = regexp.MustCompile(idPattern)
	portsItemRe = regexp.MustCompile(portsItemPattern)
)

// Custom are the options of a custom scan: a fixed set, never free-form
// Nmap arguments.
type Custom struct {
	NoPing   bool   `json:"no_ping"`   // -Pn
	Version  bool   `json:"version"`   // -sV
	OS       bool   `json:"os"`        // -O
	UDP      bool   `json:"udp"`       // -sU (needs ports or top_ports)
	OpenOnly bool   `json:"open_only"` // --open
	TopPorts int    `json:"top_ports"` // --top-ports N, 0 = none
	Ports    string `json:"ports"`     // -p LIST, "" = none
	Timing   int    `json:"timing"`    // -T2..-T4, 0 = default (3)
}

// Job is one scan request.
type Job struct {
	Format    string   `json:"format"`
	ID        string   `json:"id"`
	Mode      Mode     `json:"mode"`
	Targets   []string `json:"targets"`
	Ports     string   `json:"ports,omitempty"`
	Custom    *Custom  `json:"custom,omitempty"`
	CreatedAt int64    `json:"created_at"`
}

// ValidID reports whether s is a job ID (a lowercase UUID).
func ValidID(s string) bool { return idRe.MatchString(s) }

// ParseTarget parses one target: an address or a prefix (masked).
func ParseTarget(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q is not an address or prefix", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is not an address or prefix", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Size is the number of addresses of a target prefix.
func Size(p netip.Prefix) int {
	return 1 << (p.Addr().BitLen() - p.Bits())
}

// Targets parses and checks a target list: 1 to MaxTargets addresses or
// prefixes of one address family, IPv4 at most /16 and IPv6 at most /112
// each, at most MaxAddresses together. It returns the normalized prefixes.
func Targets(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 || len(list) > MaxTargets {
		return nil, fmt.Errorf("give 1 to %d targets", MaxTargets)
	}
	var out []netip.Prefix
	total := 0
	for _, s := range list {
		p, err := ParseTarget(s)
		if err != nil {
			return nil, err
		}
		if p.Addr().Is4() && p.Bits() < MinV4PrefixBits || p.Addr().Is6() && p.Bits() < MinV6PrefixBits {
			return nil, fmt.Errorf("target %s is too large (at most /%d for IPv4, /%d for IPv6)", p, MinV4PrefixBits, MinV6PrefixBits)
		}
		if len(out) > 0 && out[0].Addr().Is4() != p.Addr().Is4() {
			return nil, errors.New("targets must all be IPv4 or all IPv6")
		}
		total += Size(p)
		if total > MaxAddresses {
			return nil, fmt.Errorf("at most %d addresses per scan", MaxAddresses)
		}
		out = append(out, p)
	}
	return out, nil
}

// NormalizePorts checks a port list ("22,80,8000-8100") and returns it
// sorted and deduplicated by item.
func NormalizePorts(s string) (string, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if s == "" {
		return "", errors.New("give at least one port")
	}
	items := strings.Split(s, ",")
	if len(items) > MaxPortItems {
		return "", fmt.Errorf("at most %d port items", MaxPortItems)
	}
	type rng struct{ lo, hi int }
	var rs []rng
	seen := map[rng]bool{}
	for _, it := range items {
		if !portsItemRe.MatchString(it) {
			return "", fmt.Errorf("%q is not a port or range", it)
		}
		lo, hi, _ := strings.Cut(it, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if hi != "" {
			b, _ = strconv.Atoi(hi)
		}
		if a < 1 || b > 65535 || b < a {
			return "", fmt.Errorf("%q is not a port range within 1-65535", it)
		}
		r := rng{a, b}
		if !seen[r] {
			seen[r] = true
			rs = append(rs, r)
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo || rs[i].lo == rs[j].lo && rs[i].hi < rs[j].hi })
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = strconv.Itoa(r.lo)
		if r.hi != r.lo {
			parts[i] += "-" + strconv.Itoa(r.hi)
		}
	}
	return strings.Join(parts, ","), nil
}

// Validate checks a job completely; discovery runs only valid jobs.
func (j *Job) Validate() error {
	switch {
	case j.Format != JobFormat:
		return errors.New("unknown job format")
	case !ValidID(j.ID):
		return errors.New("invalid job ID")
	case j.CreatedAt <= 0:
		return errors.New("invalid creation time")
	}
	if _, err := Targets(j.Targets); err != nil {
		return err
	}
	switch j.Mode {
	case ModePing, ModeServices, ModeFullTCP:
		if j.Ports != "" || j.Custom != nil {
			return errors.New("this mode takes no ports or options")
		}
	case ModePorts:
		if j.Custom != nil {
			return errors.New("this mode takes no options")
		}
		p, err := NormalizePorts(j.Ports)
		if err != nil {
			return err
		}
		if p != j.Ports {
			return errors.New("ports are not normalized")
		}
	case ModeCustom:
		if j.Ports != "" || j.Custom == nil {
			return errors.New("a custom scan takes its ports in the options")
		}
		return j.Custom.validate()
	default:
		return errors.New("unknown mode")
	}
	return nil
}

func (c *Custom) validate() error {
	if c.Ports != "" {
		p, err := NormalizePorts(c.Ports)
		if err != nil {
			return err
		}
		if p != c.Ports {
			return errors.New("ports are not normalized")
		}
	}
	switch {
	case c.Ports != "" && c.TopPorts != 0:
		return errors.New("give ports or top ports, not both")
	case c.TopPorts < 0 || c.TopPorts > MaxTopPorts:
		return fmt.Errorf("top ports must be 1 to %d", MaxTopPorts)
	case c.UDP && c.Ports == "" && c.TopPorts == 0:
		return errors.New("a UDP scan needs ports or top ports")
	case c.Timing != 0 && (c.Timing < 2 || c.Timing > 4):
		return errors.New("timing must be 2, 3 or 4")
	}
	return nil
}

// Args returns the Nmap arguments of a valid job. XML goes to stdout.
// Every argument is fixed or built from validated values; targets come
// last and never start with "-".
func (j *Job) Args() ([]string, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	targets, _ := Targets(j.Targets)
	args := []string{"--privileged", "-oX", "-", "--no-stylesheet", "--max-retries", nmapMaxRetries, "--host-timeout", nmapHostTimeout}
	if targets[0].Addr().Is6() {
		args = append(args, "-6")
	}
	timing := DefaultTiming
	switch j.Mode {
	case ModePing:
		args = append(args, "-sn")
	case ModePorts:
		args = append(args, "-sS", "-p", j.Ports)
	case ModeServices:
		args = append(args, "-sS", "-sV", "--top-ports", defaultTopPorts)
	case ModeFullTCP:
		args = append(args, "-sS", "-p-")
	case ModeCustom:
		c := j.Custom
		args = append(args, "-sS")
		if c.UDP {
			args = append(args, "-sU")
		}
		if c.Ports != "" {
			ports := c.Ports
			if c.UDP {
				ports = "T:" + ports + ",U:" + ports
			}
			args = append(args, "-p", ports)
		}
		if c.TopPorts != 0 {
			args = append(args, "--top-ports", strconv.Itoa(c.TopPorts))
		}
		if c.Version {
			args = append(args, "-sV")
		}
		if c.OS {
			args = append(args, "-O")
		}
		if c.NoPing {
			args = append(args, "-Pn")
		}
		if c.OpenOnly {
			args = append(args, "--open")
		}
		if c.Timing != 0 {
			timing = c.Timing
		}
	}
	args = append(args, "-T"+strconv.Itoa(timing))
	for _, t := range targets {
		if t.IsSingleIP() {
			args = append(args, t.Addr().String())
		} else {
			args = append(args, t.String())
		}
	}
	return args, nil
}

// Describe is a short human text of a job's scan.
func (j *Job) Describe() string {
	switch j.Mode {
	case ModePing:
		return "host discovery"
	case ModePorts:
		return "ports " + j.Ports
	case ModeServices:
		return "service discovery (top 100 ports)"
	case ModeFullTCP:
		return "all TCP ports"
	case ModeCustom:
		if j.Custom == nil {
			return "custom"
		}
		c := j.Custom
		var p []string
		if c.Ports != "" {
			p = append(p, "ports "+c.Ports)
		}
		if c.TopPorts != 0 {
			p = append(p, "top "+strconv.Itoa(c.TopPorts)+" ports")
		}
		for _, f := range []struct {
			on   bool
			text string
		}{{c.UDP, "UDP"}, {c.Version, "versions"}, {c.OS, "OS"}, {c.NoPing, "no ping"}, {c.OpenOnly, "open only"}} {
			if f.on {
				p = append(p, f.text)
			}
		}
		if c.Timing != 0 {
			p = append(p, "T"+strconv.Itoa(c.Timing))
		}
		return "custom: " + strings.Join(p, ", ")
	}
	return string(j.Mode)
}
