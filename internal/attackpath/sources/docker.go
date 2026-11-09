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

// DockerConfig configures the Docker adapter.
type DockerConfig struct {
	// Reader reads the stored Docker inventory.
	Reader DockerReader
	// Hosts reads the managed hosts: each is expected to have a Docker
	// inventory, and one without is UncertainDockerUnread.
	Hosts HostLister
	// Managed are the IDs of the other managed nodes, the guests and PVE
	// nodes (ManagedNodes of the Placements result). Each is expected to be
	// a managed host with a Docker inventory, like the hosts; a guest that
	// is no managed host is UncertainDockerUnread.
	Managed []string
	// Aliases maps a managed host node ID to the node of the same machine
	// (the Placements result's Aliases), so a host and its guest or PVE
	// node are one expected node.
	Aliases map[string]string
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
// managed node: every managed host of cfg.Hosts and every guest and PVE
// node of cfg.Managed, after cfg.Aliases. A node is covered (and listed in
// Result.Covered) when the Docker inventory of the host it is was read
// completely and every container was fully inspected. A node without a
// Docker inventory entry (never read, cut by MaxDockerHosts, or a guest
// that is no managed host) is UncertainDockerUnread and uncovered, so the
// source is never complete while a managed node's containers are unknown.
// An inventory entry that fails validation is one more uncovered unit; an
// entry of a host that is not managed (removed or stale) is skipped and
// adds no node.
//
// A read error of either store yields StatusUnknown and an error wrapping
// ErrSourceUnavailable; the Result is still meant to be merged.
func Docker(ctx context.Context, cfg DockerConfig) (Result, error) {
	c := newCollector(SourceDocker)
	if cfg.Reader == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: no reader: %w", ErrSourceUnavailable)
	}
	if cfg.Hosts == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: no host lister: %w", ErrSourceUnavailable)
	}
	managed, err := cfg.Hosts.List(ctx)
	if err != nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: list hosts: %w: %w", ErrSourceUnavailable, err)
	}
	hosts, err := cfg.Reader.DockerHosts(ctx)
	if err != nil {
		c.unavailable()
		return c.result(), fmt.Errorf("docker source: read inventory: %w: %w", ErrSourceUnavailable, err)
	}
	if len(hosts) > MaxDockerHosts {
		hosts = hosts[:MaxDockerHosts]
		c.truncated = true
	}
	expected := expectedNodes(c, managed, cfg.Managed, cfg.Aliases)
	want := make(map[string]bool, len(expected))
	for _, id := range expected {
		want[id] = true
	}
	// read maps an expected node to whether every inventory entry of it
	// was covered.
	read := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		id, ok := nodeID("host:", h.HostID)
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			c.r.Coverage.Total++
			c.partial()
			continue
		}
		target := resolveAlias(cfg.Aliases, id)
		if !want[target] {
			continue // not a managed host
		}
		covered := dockerHost(c, h)
		if prev, seen := read[target]; seen {
			covered = covered && prev
		}
		read[target] = covered
	}
	for _, id := range expected {
		c.r.Coverage.Total++
		covered, seen := read[id]
		switch {
		case !seen:
			c.uncertain(UncertainDockerUnread, id)
			c.partial()
		case covered:
			c.r.Coverage.Covered++
			c.r.Covered = append(c.r.Covered, id)
		default:
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
