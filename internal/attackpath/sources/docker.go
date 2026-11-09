// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
)

// Limits of the Docker adapter.
const (
	// MaxDockerHosts bounds the Docker hosts one read returns.
	MaxDockerHosts = 1000
	// MaxContainersPerHost bounds the containers read per host.
	MaxContainersPerHost = 1000
	// containerIDLen is the short container ID used in node IDs; the full
	// 64-digit ID would not fit attackpath.MaxIDBytes with a long host ID.
	containerIDLen = 12
)

// DockerHost is one managed host's Docker inventory: the docker.inspect
// results of its containers.
type DockerHost struct {
	// HostID is the inventory ID of the Docker host.
	HostID string
	// Complete is set when the inventory read was complete: exit success,
	// every container entry parsed, no list limit reached (ADR 0011 D3).
	Complete bool
	// Containers are the parsed docker.inspect results.
	Containers []dockerhost.Inspect
}

// DockerReader reads the stored Docker inventory read-only.
type DockerReader interface {
	DockerHosts(ctx context.Context) ([]DockerHost, error)
}

// Docker returns the container edges of ADR 0011 D10: Docker host →
// container control edges (owning the host owns its containers) and
// container → host escape edges where docker.inspect proves one, i.e. a
// bind mount of the Docker socket or a directory above it (including the
// host's root). Container IDs are "ctr:<host>/<12-hex-id>".
//
// docker.inspect does not report whether a container runs privileged, so
// a container without a proven escape is UncertainEscapeUnverified: its
// escape is not excluded, only not proven. An incomplete host read and a
// precheck-only inspect are UncertainPartialData. The coverage unit is a
// Docker host: covered when its read was complete and every container was
// fully inspected.
//
// A read error yields StatusUnknown and an error wrapping
// ErrSourceUnavailable; the Result is still meant to be merged.
func Docker(ctx context.Context, r DockerReader) (Result, error) {
	c := newCollector(SourceDocker)
	if r == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: no reader: %w", ErrSourceUnavailable)
	}
	hosts, err := r.DockerHosts(ctx)
	if err != nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: read inventory: %w: %w", ErrSourceUnavailable, err)
	}
	if len(hosts) > MaxDockerHosts {
		hosts = hosts[:MaxDockerHosts]
		c.truncated = true
	}
	for _, h := range hosts {
		c.r.Coverage.Total++
		if dockerHost(c, h) {
			c.r.Coverage.Covered++
		} else {
			c.partial()
		}
	}
	return c.result(), nil
}

// dockerHost adds one host's containers; it reports whether the host was
// covered.
func dockerHost(c *collector, h DockerHost) bool {
	host, ok := nodeID("host:", h.HostID)
	if !ok {
		c.uncertain(UncertainInvalidRecord, "")
		return false
	}
	if !c.node(attackpath.Node{ID: host, Kind: attackpath.NodeHost}) {
		return false
	}
	covered := h.Complete
	if !h.Complete {
		c.uncertain(UncertainPartialData, host)
	}
	ctrs := h.Containers
	if len(ctrs) > MaxContainersPerHost {
		ctrs = ctrs[:MaxContainersPerHost]
		c.uncertain(UncertainTruncated, host)
		covered = false
	}
	for _, in := range ctrs {
		short, ok := shortContainerID(in)
		if !ok {
			c.uncertain(UncertainInvalidRecord, host)
			covered = false
			continue
		}
		id, ok := nodeID("ctr:", h.HostID, short)
		if !ok {
			c.uncertain(UncertainInvalidRecord, host)
			covered = false
			continue
		}
		if !c.node(attackpath.Node{ID: id, Kind: attackpath.NodeContainer, Label: label(strings.TrimPrefix(in.Name, "/"))}) {
			covered = false
			continue
		}
		c.edge(attackpath.Edge{From: host, To: id, Kind: attackpath.EdgeControl})
		if in.Phase != "done" {
			c.uncertain(UncertainPartialData, id)
			c.uncertain(UncertainEscapeUnverified, id)
			covered = false
			continue
		}
		if socketMounted(in.Mounts) {
			c.edge(attackpath.Edge{From: id, To: host, Kind: attackpath.EdgeEscape, Escape: attackpath.EscapeDockerSocket})
			continue
		}
		c.uncertain(UncertainEscapeUnverified, id)
	}
	return covered
}

// shortContainerID returns the 12-digit lowercase hex container ID.
func shortContainerID(in dockerhost.Inspect) (string, bool) {
	id := in.ID
	if len(in.FullID) == 64 {
		id = in.FullID[:containerIDLen]
	}
	if len(id) != containerIDLen {
		return "", false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return id, true
}

// dockerSockets are the rootful Docker socket paths.
var dockerSockets = []string{"/var/run/docker.sock", "/run/docker.sock"}

// socketMounted reports whether a bind mount exposes a Docker socket: the
// socket itself, a directory above it (which includes "/"), or a rootless
// socket under /run/user/<uid>/.
func socketMounted(mounts []dockerhost.Mount) bool {
	for _, m := range mounts {
		if m.Type != "bind" || !strings.HasPrefix(m.Source, "/") {
			continue
		}
		src := path.Clean(m.Source)
		for _, s := range dockerSockets {
			if src == s || src == "/" || strings.HasPrefix(s, src+"/") {
				return true
			}
		}
		if src == "/run/user" {
			return true
		}
		if rest, ok := strings.CutPrefix(src, "/run/user/"); ok {
			uid, tail, _ := strings.Cut(rest, "/")
			if uid != "" && (tail == "" || tail == "docker.sock") {
				return true
			}
		}
	}
	return false
}
