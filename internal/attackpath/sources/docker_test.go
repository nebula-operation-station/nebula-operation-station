// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// fakeDocker is a fixture Docker inventory.
type fakeDocker struct {
	hosts []DockerHost
	err   error
}

func (f fakeDocker) DockerHosts(context.Context) ([]DockerHost, error) { return f.hosts, f.err }

func ctr(short, name string, mounts ...dockerhost.Mount) dockerhost.Inspect {
	return dockerhost.Inspect{Phase: "done", ID: short, FullID: short + strings.Repeat("0", 52), Name: "/" + name, Mounts: mounts}
}

func bind(src string) dockerhost.Mount {
	return dockerhost.Mount{Type: "bind", Source: src, Destination: "/x"}
}

func labDocker() fakeDocker {
	return fakeDocker{hosts: []DockerHost{
		{HostID: "web", Complete: true, Containers: []dockerhost.Inspect{
			ctr("aaaaaaaaaaaa", "proxy", bind("/var/run/docker.sock")),
			ctr("bbbbbbbbbbbb", "app", bind("/srv/app"), dockerhost.Mount{Type: "volume", Source: "/var/run/docker.sock"}),
		}},
		{HostID: "nas", Complete: false, Containers: []dockerhost.Inspect{
			{Phase: "precheck", ID: "cccccccccccc", Name: "/db"},
		}},
	}}
}

func TestDockerControlAndProvenEscapeEdges(t *testing.T) {
	r, err := Docker(context.Background(), dockerConfig(labDocker(), "web", "nas"))
	if err != nil {
		t.Fatal(err)
	}
	want := []attackpath.Edge{
		{From: "ctr:web/aaaaaaaaaaaa", To: "host:web", Kind: attackpath.EdgeEscape, Escape: attackpath.EscapeDockerSocket},
		{From: "host:nas", To: "ctr:nas/cccccccccccc", Kind: attackpath.EdgeControl},
		{From: "host:web", To: "ctr:web/aaaaaaaaaaaa", Kind: attackpath.EdgeControl},
		{From: "host:web", To: "ctr:web/bbbbbbbbbbbb", Kind: attackpath.EdgeControl},
	}
	if !slices.Equal(r.Edges, want) {
		t.Fatalf("edges\n got %v\nwant %v", r.Edges, want)
	}
	for _, u := range []Uncertainty{
		{SourceDocker, UncertainEscapeUnverified, "ctr:web/bbbbbbbbbbbb"},
		{SourceDocker, UncertainEscapeUnverified, "ctr:nas/cccccccccccc"},
		{SourceDocker, UncertainPartialData, "ctr:nas/cccccccccccc"},
		{SourceDocker, UncertainPartialData, "host:nas"},
	} {
		if !slices.Contains(r.Uncertain, u) {
			t.Errorf("missing %s in %v", u, r.Uncertain)
		}
	}
	if hasUncertainty(r.Uncertain, UncertainEscapeUnverified, "ctr:web/aaaaaaaaaaaa") {
		t.Fatal("proven escape still flagged unverified")
	}
	if r.Status != StatusPartial || r.Coverage != (Coverage{Covered: 1, Total: 2}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
}

func TestDockerSocketMountDetection(t *testing.T) {
	for src, want := range map[string]bool{
		"/var/run/docker.sock":         true,
		"/run/docker.sock":             true,
		"/var/run":                     true,
		"/var/run/":                    true,
		"/var":                         true,
		"/":                            true,
		"/run":                         true,
		"/run/user/1000/docker.sock":   true,
		"/run/user/1000":               true,
		"/run/user":                    true,
		"/var/run/../run/docker.sock":  true,
		"/var/lib/docker":              false,
		"/srv":                         false,
		"/run/user/1000/other.sock":    false,
		"relative/var/run/docker.sock": false,
		"/var/run/docker.sock.bak":     false,
	} {
		if got := socketMounted([]dockerhost.Mount{bind(src)}); got != want {
			t.Errorf("%q: got %v, want %v", src, got, want)
		}
	}
	if socketMounted([]dockerhost.Mount{{Type: "volume", Source: "/var/run/docker.sock"}}) {
		t.Error("volume counted as bind mount")
	}
}

func TestDockerRejectsBadIDsAndNames(t *testing.T) {
	f := fakeDocker{hosts: []DockerHost{
		{HostID: "bad host", Complete: true},
		{HostID: "web", Complete: true, Containers: []dockerhost.Inspect{
			{Phase: "done", ID: "AAAAAAAAAAAA"},
			{Phase: "done", ID: "../etc"},
			{Phase: "done", ID: "dddddddddddd", Name: "/x" + string(rune(0x2066)) + "y"},
		}},
	}}
	r, err := Docker(context.Background(), dockerConfig(f, "web"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") || !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "host:web") {
		t.Fatalf("uncertain %v", r.Uncertain)
	}
	if r.Coverage != (Coverage{0, 2}) {
		t.Fatalf("coverage %+v", r.Coverage)
	}
	for _, n := range r.Nodes {
		if n.ID == "ctr:web/dddddddddddd" && n.Label != "" {
			t.Fatalf("bidi label kept %q", n.Label)
		}
	}
}

func TestDockerReadErrorIsUnknown(t *testing.T) {
	r, err := Docker(context.Background(), dockerConfig(fakeDocker{err: errors.New("x")}, "web"))
	if !errors.Is(err, ErrSourceUnavailable) || r.Status != StatusUnknown || len(r.Nodes) != 0 {
		t.Fatalf("err %v result %+v", err, r)
	}
	if _, err := Docker(context.Background(), DockerConfig{Hosts: fakeHosts{}}); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal(err)
	}
}

// dockerConfig returns a Docker config over f whose inventory holds the
// managed hosts ids.
func dockerConfig(f fakeDocker, ids ...string) DockerConfig {
	var hs []inventory.Host
	for _, id := range ids {
		hs = append(hs, inventory.Host{ID: id})
	}
	return DockerConfig{Reader: f, Hosts: fakeHosts{hosts: hs}}
}

func TestDockerUnreadManagedHostIsUncertain(t *testing.T) {
	// "quiet" is managed but the Docker inventory has no entry for it:
	// its containers and escape edges are unknown, not absent.
	cfg := dockerConfig(fakeDocker{hosts: []DockerHost{{HostID: "web", Complete: true}}}, "web", "quiet")
	r, err := Docker(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.Uncertain, Uncertainty{SourceDocker, UncertainDockerUnread, "host:quiet"}) {
		t.Fatalf("unread host not named in %v", r.Uncertain)
	}
	if hasUncertainty(r.Uncertain, UncertainDockerUnread, "host:web") {
		t.Fatal("read host flagged unread")
	}
	if r.Status == StatusComplete || r.Coverage != (Coverage{Covered: 1, Total: 2}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}

	// An empty Docker inventory with managed hosts is never complete.
	r, err = Docker(context.Background(), dockerConfig(fakeDocker{}, "a", "b"))
	if err != nil || r.Status == StatusComplete || r.Coverage != (Coverage{Covered: 0, Total: 2}) {
		t.Fatalf("empty inventory: %v status %s coverage %+v", err, r.Status, r.Coverage)
	}

	// Every managed host read completely is complete.
	r, err = Docker(context.Background(), dockerConfig(fakeDocker{hosts: []DockerHost{{HostID: "web", Complete: true}}}, "web"))
	if err != nil || r.Status != StatusComplete || len(r.Uncertain) != 0 || r.Coverage != (Coverage{Covered: 1, Total: 1}) {
		t.Fatalf("all read: %v status %s uncertain %v coverage %+v", err, r.Status, r.Uncertain, r.Coverage)
	}
}

func TestDockerUnlinkedGuestIsUnread(t *testing.T) {
	// Guest 100 is host web, PVE node pve1 is host hv1; guest 101 is no
	// managed host, so no Docker inventory can exist for it.
	cfg := dockerConfig(fakeDocker{hosts: []DockerHost{{HostID: "web", Complete: true}, {HostID: "hv1", Complete: true}}}, "web", "hv1")
	cfg.Managed = []string{"guest:lab/100", "guest:lab/101", "pve:lab/pve1"}
	cfg.Aliases = map[string]string{"host:web": "guest:lab/100", "host:hv1": "pve:lab/pve1"}
	r, err := Docker(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Uncertain, []Uncertainty{{SourceDocker, UncertainDockerUnread, "guest:lab/101"}}) {
		t.Fatalf("uncertain %v", r.Uncertain)
	}
	if r.Status != StatusPartial || r.Coverage != (Coverage{Covered: 2, Total: 3}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
	if want := []string{"guest:lab/100", "pve:lab/pve1"}; !slices.Equal(r.Covered, want) {
		t.Fatalf("covered %v, want %v", r.Covered, want)
	}
	// Invalid managed IDs are reported, not expected.
	cfg.Managed = []string{"guest:a b"}
	r, err = Docker(context.Background(), cfg)
	if err != nil || !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") || r.Status != StatusPartial {
		t.Fatalf("invalid managed id: %v %+v", err, r)
	}
}

func TestDockerSkipsUnmanagedInventoryHosts(t *testing.T) {
	// "old" has a stored Docker inventory but is no longer managed.
	cfg := dockerConfig(fakeDocker{hosts: []DockerHost{
		{HostID: "old", Complete: true, Containers: []dockerhost.Inspect{ctr("aaaaaaaaaaaa", "x")}},
		{HostID: "web", Complete: true},
	}}, "web")
	r, err := Docker(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage != (Coverage{Covered: 1, Total: 1}) || r.Status != StatusComplete {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
	for _, n := range r.Nodes {
		if strings.Contains(n.ID, "old") {
			t.Fatalf("unmanaged host node %s added", n.ID)
		}
	}
	if !slices.Equal(r.Covered, []string{"host:web"}) {
		t.Fatalf("covered %v", r.Covered)
	}
	// A stale alias of the unmanaged host does not make it cover a guest.
	cfg.Managed = []string{"guest:r/1"}
	cfg.Aliases = map[string]string{"host:old": "guest:r/1"}
	r, err = Docker(context.Background(), cfg)
	if err != nil || slices.Contains(r.Covered, "guest:r/1") || !hasUncertainty(r.Uncertain, UncertainDockerUnread, "guest:r/1") {
		t.Fatalf("stale alias: %v covered %v uncertain %v", err, r.Covered, r.Uncertain)
	}
}

func TestDockerHostListErrorIsUnknown(t *testing.T) {
	cfg := DockerConfig{Reader: labDocker(), Hosts: fakeHosts{err: errors.New("db")}}
	r, err := Docker(context.Background(), cfg)
	if !errors.Is(err, ErrSourceUnavailable) || r.Status != StatusUnknown || len(r.Nodes) != 0 {
		t.Fatalf("err %v result %+v", err, r)
	}
	if _, err := Docker(context.Background(), DockerConfig{Reader: labDocker()}); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("no host lister: %v", err)
	}
}

func TestDockerCapsContainersPerHost(t *testing.T) {
	h := DockerHost{HostID: "big", Complete: true}
	for i := range MaxContainersPerHost + 1 {
		id := strings.Repeat("0", 8) + hex4(i)
		h.Containers = append(h.Containers, dockerhost.Inspect{Phase: "done", ID: id})
	}
	r, err := Docker(context.Background(), dockerConfig(fakeDocker{hosts: []DockerHost{h}}, "big"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != MaxContainersPerHost+1 || !hasUncertainty(r.Uncertain, UncertainTruncated, "host:big") || r.Coverage.Covered != 0 {
		t.Fatalf("nodes %d uncertain %d coverage %+v", len(r.Nodes), len(r.Uncertain), r.Coverage)
	}
}

func hex4(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[i>>12&15], digits[i>>8&15], digits[i>>4&15], digits[i&15]})
}
