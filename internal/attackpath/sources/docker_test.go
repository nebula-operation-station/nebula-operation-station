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
	r, err := Docker(context.Background(), labDocker())
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
			{Phase: "done", ID: "dddddddddddd", Name: "/x⁦y"},
		}},
	}}
	r, err := Docker(context.Background(), f)
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
	r, err := Docker(context.Background(), fakeDocker{err: errors.New("x")})
	if !errors.Is(err, ErrSourceUnavailable) || r.Status != StatusUnknown || len(r.Nodes) != 0 {
		t.Fatalf("err %v result %+v", err, r)
	}
	if _, err := Docker(context.Background(), nil); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal(err)
	}
}

func TestDockerCapsContainersPerHost(t *testing.T) {
	h := DockerHost{HostID: "big", Complete: true}
	for i := range MaxContainersPerHost + 1 {
		id := strings.Repeat("0", 8) + hex4(i)
		h.Containers = append(h.Containers, dockerhost.Inspect{Phase: "done", ID: id})
	}
	r, err := Docker(context.Background(), fakeDocker{hosts: []DockerHost{h}})
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
