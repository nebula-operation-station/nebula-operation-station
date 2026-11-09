// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// fakeHosts is a fixture inventory.
type fakeHosts struct {
	hosts []inventory.Host
	err   error
}

func (f fakeHosts) List(context.Context) ([]inventory.Host, error) { return f.hosts, f.err }

func labHosts() fakeHosts {
	return fakeHosts{hosts: []inventory.Host{
		{ID: "exec", DisplayName: "executor"},
		{ID: "nas", DisplayName: "nas"},
		{ID: "web", DisplayName: "web" + string(rune(0x202e))}, // bidi control: label dropped
	}}
}

func TestCredentialsExecutorReachesEveryManagedHost(t *testing.T) {
	r, err := Credentials(context.Background(), CredentialConfig{Hosts: labHosts(), ExecutorHostID: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusComplete || len(r.Uncertain) != 0 {
		t.Fatalf("status %s uncertain %v", r.Status, r.Uncertain)
	}
	want := []attackpath.Edge{
		{From: "host:exec", To: "host:nas", Kind: attackpath.EdgeCredential},
		{From: "host:exec", To: "host:web", Kind: attackpath.EdgeCredential},
	}
	if !slices.Equal(r.Edges, want) {
		t.Fatalf("edges %v, want %v", r.Edges, want)
	}
	if r.Coverage != (Coverage{Covered: 3, Total: 3}) {
		t.Fatalf("coverage %+v", r.Coverage)
	}
	for _, n := range r.Nodes {
		if n.ID == "host:web" && n.Label != "" {
			t.Fatalf("unsafe label kept: %q", n.Label)
		}
	}
}

func TestCredentialsWithoutExecutorIsUnknownNotNoEdge(t *testing.T) {
	for _, id := range []string{"", "missing"} {
		r, err := Credentials(context.Background(), CredentialConfig{Hosts: labHosts(), ExecutorHostID: id})
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusUnknown || len(r.Edges) != 0 || r.Coverage.Covered != 0 {
			t.Fatalf("executor %q: status %s edges %d coverage %+v", id, r.Status, len(r.Edges), r.Coverage)
		}
		if !hasUncertainty(r.Uncertain, UncertainExecutorUnassigned, "") {
			t.Fatalf("executor %q: uncertainty %v", id, r.Uncertain)
		}
	}
}

func TestCredentialsReadErrorIsUnavailable(t *testing.T) {
	boom := errors.New("db locked")
	for name, cfg := range map[string]CredentialConfig{
		"error": {Hosts: fakeHosts{err: boom}, ExecutorHostID: "exec"},
		"nil":   {ExecutorHostID: "exec"},
	} {
		r, err := Credentials(context.Background(), cfg)
		if !errors.Is(err, ErrSourceUnavailable) {
			t.Fatalf("%s: err %v", name, err)
		}
		if r.Status != StatusUnknown || len(r.Nodes) != 0 || !hasUncertainty(r.Uncertain, UncertainSourceUnavailable, "") {
			t.Fatalf("%s: result %+v", name, r)
		}
	}
}

func TestCredentialsInvalidHostIDIsReported(t *testing.T) {
	h := labHosts()
	h.hosts = append(h.hosts, inventory.Host{ID: "bad id"})
	r, err := Credentials(context.Background(), CredentialConfig{Hosts: h, ExecutorHostID: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPartial || !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") {
		t.Fatalf("status %s uncertain %v", r.Status, r.Uncertain)
	}
}

func TestDeviceAdaptersAreUnknownStubs(t *testing.T) {
	for _, r := range []Result{FirewallPolicy(), VLANAdjacency()} {
		if r.Status != StatusUnknown || len(r.Nodes) != 0 || len(r.Edges) != 0 {
			t.Fatalf("%s: %+v", r.Source, r)
		}
		if !hasUncertainty(r.Uncertain, UncertainSourceMissing, "") {
			t.Fatalf("%s: uncertainty %v", r.Source, r.Uncertain)
		}
	}
	rep, err := Merge(attackpath.NewBuilder(), FirewallPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete() || rep.Coverage() != (Coverage{Covered: 0, Total: 1}) {
		t.Fatalf("missing source reads complete: %+v coverage %+v", rep, rep.Coverage())
	}
}

func hasUncertainty(us []Uncertainty, k UncertaintyKind, subject string) bool {
	for _, u := range us {
		if u.Kind == k && u.Subject == subject {
			return true
		}
	}
	return false
}
