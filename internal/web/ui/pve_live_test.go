// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// pveLiveHandler serves the PVE and lease pages with remote-a (active) and
// remote-b (blocked) registered and remote-a's inventory: nodes p1 and p2,
// the running QEMU guest 101 on p1, the stopped LXC guest 102 on p2 and the
// running QEMU guest 103 on p2, plus extra running guests on p1.
func pveLiveHandler(t *testing.T, f *fakeLeases, extra ...pvecontract.GuestObservation) http.Handler {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := pveinventory.New(db)
	metas := providerMetas()
	for _, m := range metas {
		seedRemote(t, store, pvecontract.Remote{
			RemoteID: m.RemoteID, Name: m.RemoteID, Kind: pvecontract.Kind(m.Kind),
			Endpoints: []pvecontract.Endpoint{{Host: m.RemoteID + ".lab", Port: 8006}},
			TrustPin:  m.TrustPin, TrustGeneration: m.TrustGeneration,
		})
	}
	obs := newPVEObs("remote-a", time.Now().Add(-time.Minute))
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{
		pveNodeObs("p1", pvecontract.NodeOnline), pveNodeObs("p2", pvecontract.NodeOnline)})
	guests := []pvecontract.GuestObservation{
		pveGuestObs(101, pvecontract.GuestQEMU, "p1", "web", pvecontract.GuestRunning),
		pveGuestObs(102, pvecontract.GuestLXC, "p2", "db", pvecontract.GuestStopped),
		pveGuestObs(103, pvecontract.GuestQEMU, "p2", "ci", pvecontract.GuestRunning),
	}
	obs.Guests = pvecontract.AvailableDataset(append(guests, extra...))
	seedObs(t, store, obs)
	o := ui.Options{
		PublicOrigin: pveOrigin,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PVE:          store,
		PVERemotes:   func(context.Context) ([]ui.PVERemoteMeta, error) { return metas, nil },
	}
	if f != nil {
		o.Leases = f
	}
	u, err := ui.New(o)
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return u.Handler()
}

// liveBox is the rendered checkbox of one target.
func liveBox(value string, checked bool) string {
	s := `<input type="checkbox" name="target" value="` + value + `" form="pve-live"`
	if checked {
		return s + " checked>"
	}
	return s + ">"
}

func TestPVEDetailOffersLiveValuesWithDefaults(t *testing.T) {
	f := &fakeLeases{}
	page := getBody(t, pveLiveHandler(t, f), "/pve/remote-a")
	for _, want := range []string{
		`<form id="pve-live" method="post" action="/leases/preview" class="form" data-fetch>`,
		`<input type="hidden" name="scope" value="provider_telemetry">`,
		`<input type="hidden" name="remote" value="remote-a">`,
		">Enable live values</button>",
		// Default: every node and every running guest. A guest posts the
		// incarnation generation the page shows (1 in the fixture).
		liveBox("p1/node/0", true), liveBox("p2/node/0", true),
		liveBox("p1/qemu/101/1", true), liveBox("p2/qemu/103/1", true),
		liveBox("p2/lxc/102/1", false),
		`<script src="/static/formpost.js`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if len(f.telemetryProposed) != 0 || len(f.providerProposed) != 0 || len(f.committed) != 0 {
		t.Error("viewing the page proposed or approved a lease")
	}
}

func TestPVEDetailLiveDefaultStopsAtTargetLimit(t *testing.T) {
	var extra []pvecontract.GuestObservation
	for i := range uint64(70) {
		extra = append(extra, pveGuestObs(200+i, pvecontract.GuestQEMU, "p1", "g", pvecontract.GuestRunning))
	}
	page := getBody(t, pveLiveHandler(t, &fakeLeases{}, extra...), "/pve/remote-a")
	if n := strings.Count(page, `form="pve-live" checked>`); n != permit.MaxProviderMetricsTargets {
		t.Fatalf("%d targets pre-selected, want %d", n, permit.MaxProviderMetricsTargets)
	}
	if !strings.Contains(page, "Only the first 64 nodes and guests are pre-selected.") {
		t.Error("page does not say the default selection was cut")
	}
	// The nodes come first in the default selection.
	if !strings.Contains(page, liveBox("p1/node/0", true)) || !strings.Contains(page, liveBox("p2/node/0", true)) {
		t.Error("nodes are not pre-selected")
	}
}

func TestPVEDetailHidesLiveValues(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		leases     *fakeLeases
	}{
		{"blocked remote", "/pve/remote-b", &fakeLeases{}},
		{"no lease service", "/pve/remote-a", nil},
		{"leases unavailable", "/pve/remote-a", &fakeLeases{err: errors.New("executor down")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := getBody(t, pveLiveHandler(t, tc.leases), tc.path)
			if strings.Contains(page, `id="pve-live"`) || strings.Contains(page, `name="target"`) {
				t.Error("page offers live values")
			}
		})
	}
}

// telemetryView is an approved telemetry lease of remote-a covering p1
// and guest 101 with generation gen.
func telemetryView(binding string, gen uint64) executions.ReadGrantView {
	return executions.ReadGrantView{
		ID: leaseID, Digest: leaseDigest, ScopeKind: executions.ScopeProvider, State: "active",
		RateProfile: permit.ProviderTelemetryProfile, Remotes: []string{"remote-a"},
		Providers: []executions.ReadGrantProviderView{{RemoteID: "remote-a", PinPrefix: "aaaaaaaaaaaaaaaa", TrustGeneration: 1,
			CredentialVersion: 2, Methods: []string{"metrics"}, Binding: binding,
			MetricsTargets: []permit.ProviderMetricsTarget{{Node: "p1", Kind: "node"}, {Node: "p1", Kind: "qemu", VMID: 101, Generation: gen}}}},
		ApprovedBy: "webauthn:ab", Created: time.Now().Add(-time.Hour), Expiry: time.Now().Add(6 * 24 * time.Hour),
	}
}

const (
	liveOn    = `form="pve-live" checked> live</label> <span class="badge badge--ok">on</span>`
	liveStale = `> live</label> <span class="badge badge--warning">lease stale, renew</span>`
)

func TestPVEDetailShowsLiveLeaseState(t *testing.T) {
	for _, tc := range []struct {
		name            string
		grant           executions.ReadGrantView
		wantOn, wantOld int
	}{
		{"current lease", telemetryView(executions.ProviderBindingCurrent, 1), 2, 0},
		{"guest recreated", telemetryView(executions.ProviderBindingCurrent, 2), 1, 1},
		{"stale binding", telemetryView(executions.ProviderBindingStale, 1), 0, 2},
		{"binding unknown", telemetryView("", 1), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := getBody(t, pveLiveHandler(t, &fakeLeases{grants: []executions.ReadGrantView{tc.grant}}), "/pve/remote-a")
			if n := strings.Count(page, liveOn); n != tc.wantOn {
				t.Errorf("%d targets on, want %d", n, tc.wantOn)
			}
			if n := strings.Count(page, liveStale); n != tc.wantOld {
				t.Errorf("%d targets stale, want %d", n, tc.wantOld)
			}
			if (tc.wantOld > 0) != strings.Contains(page, "Live values lease stale for") {
				t.Error("stale summary wrong")
			}
		})
	}
}

// TestPVEDetailReadLeaseStale is the #291 review case: an active read lease
// whose binding is stale no longer hides the request; the page says it is
// stale and offers the renewal. A telemetry lease never counts as a read
// lease.
func TestPVEDetailReadLeaseStale(t *testing.T) {
	stale := providerGrant("active")
	stale.Providers[0].Binding = executions.ProviderBindingStale
	current := providerGrant("active")
	current.Providers[0].Binding = executions.ProviderBindingCurrent
	otherStale := providerGrant("active")
	otherStale.Providers[0].Binding = executions.ProviderBindingStale
	for _, tc := range []struct {
		name      string
		grants    []executions.ReadGrantView
		wantStale bool
		wantLink  bool
	}{
		{"stale lease", []executions.ReadGrantView{stale}, true, true},
		{"stale and current lease", []executions.ReadGrantView{otherStale, current}, false, false},
		{"current lease", []executions.ReadGrantView{current}, false, false},
		{"telemetry lease only", []executions.ReadGrantView{telemetryView(executions.ProviderBindingCurrent, 1)}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{grants: tc.grants}
			page := getBody(t, pveLiveHandler(t, f), "/pve/remote-a")
			if got := strings.Contains(page, "Read lease stale"); got != tc.wantStale {
				t.Errorf("stale notice shown %v, want %v", got, tc.wantStale)
			}
			if got := strings.Contains(page, ">Renew read lease</a>"); got != tc.wantStale {
				t.Errorf("renew link shown %v, want %v", got, tc.wantStale)
			}
			if got := strings.Contains(page, pveLeaseLink); got != tc.wantLink {
				t.Errorf("lease form link shown %v, want %v", got, tc.wantLink)
			}
			if len(f.providerProposed) != 0 || len(f.telemetryProposed) != 0 {
				t.Error("viewing the page proposed a lease")
			}
		})
	}
}

// telemetryPreview is the executor's answer for a live-values proposal.
func telemetryPreview() executions.ReadGrantPreview {
	return executions.ReadGrantPreview{
		ID: leaseID, Digest: leaseDigest, ScopeKind: executions.ScopeProvider, Issuer: "nebula-server",
		Created: time.Unix(1_800_000_000, 0), Expiry: time.Unix(1_800_000_000+7*86400, 0),
		Trigger: permit.TriggerOnDemand, RateProfile: permit.ProviderTelemetryProfile, MinInterval: 10 * time.Second, RunBudget: 720,
		Providers: []executions.ReadGrantPreviewProvider{{RemoteID: "remote-a", TrustPin: pvePin(0), TrustGeneration: 1, CredentialVersion: 2,
			Methods: []string{"metrics"}, MetricsTargets: []permit.ProviderMetricsTarget{
				{Node: "p1", Kind: "node"}, {Node: "p1", Kind: "qemu", VMID: 101, Generation: 1}}}},
		Options: []byte(`{"publicKey":{"challenge":"abc"}}`), ChallengeExpiry: time.Now().Add(5 * time.Minute),
	}
}

const pveLiveForm = "scope=provider_telemetry&remote=remote-a&days=7&target=p1/node/0&target=p1/qemu/101/1"

func TestPVELivePreviewProposesChosenTargets(t *testing.T) {
	f := &fakeLeases{telemetryPreview: telemetryPreview()}
	h := pveLiveHandler(t, f)
	code, body := postLeaseForm(t, h, "/leases/preview", pveLiveForm)
	if code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", code, body)
	}
	if len(f.telemetryProposed) != 1 {
		t.Fatalf("%d proposals", len(f.telemetryProposed))
	}
	in := f.telemetryProposed[0]
	want := []executions.ProviderMetricsSelection{{Node: "p1", Kind: "node"}, {Node: "p1", Kind: "qemu", VMID: 101, Generation: 1}}
	if in.RemoteID != "remote-a" || in.Days != 7 || !slices.Equal(in.Targets, want) {
		t.Fatalf("request %+v", in)
	}
	// The service gets the stored inventory, which binds the guest's
	// current incarnation.
	if !f.telemetryInv[0] || !slices.Equal(f.telemetryResolved[0], []executions.TelemetryGuest{{VMID: 101, Generation: 1, Kind: "qemu", Node: "p1"}}) {
		t.Fatalf("inventory %v resolved %+v", f.telemetryInv, f.telemetryResolved)
	}
	page := getBody(t, h, "/leases/proposals/"+leaseDigest)
	for _, w := range []string{
		"2 nodes and guests (live values)",
		`<tr class="lease-metrics-target"><td class="mono">remote-a</td><td class="mono">p1</td><td>node</td><td class="mono">—</td><td class="mono">—</td></tr>`,
		`<tr class="lease-metrics-target"><td class="mono">remote-a</td><td class="mono">p1</td><td>qemu</td><td class="mono">101</td><td class="mono">1</td></tr>`,
		"at most 720 metrics requests per remote per hour, each node or guest at most every 10s",
		"trigger on_demand",
		"Approve with security key",
	} {
		if !strings.Contains(page, w) {
			t.Errorf("proposal page misses %q", w)
		}
	}
	if len(f.committed) != 0 {
		t.Error("the proposal was approved without the security key")
	}
}

// TestPVELiveFormCarriesPageGeneration is the #294 review case on the UI
// side: the checkbox carries the guest generation the page rendered, and a
// post is forwarded with exactly that generation, never the inventory's
// current one, so the service can refuse a guest recreated in between
// (executions TestProposeProviderTelemetryGrantRefusesRecreatedGuest).
func TestPVELiveFormCarriesPageGeneration(t *testing.T) {
	g := pveGuestObs(204, pvecontract.GuestLXC, "p1", "re", pvecontract.GuestRunning)
	g.Generation = 3
	f := &fakeLeases{telemetryPreview: telemetryPreview()}
	h := pveLiveHandler(t, f, g)
	if page := getBody(t, h, "/pve/remote-a"); !strings.Contains(page, liveBox("p1/lxc/204/3", true)) {
		t.Fatal("page does not post the stored generation 3 of guest 204")
	}
	// A page rendered before the guest was recreated posts its old
	// generation 2; the request keeps it while the inventory now has 3.
	code, body := postLeaseForm(t, h, "/leases/preview", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/lxc/204/2")
	if code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", code, body)
	}
	want := []executions.ProviderMetricsSelection{{Node: "p1", Kind: "lxc", VMID: 204, Generation: 2}}
	if len(f.telemetryProposed) != 1 || !slices.Equal(f.telemetryProposed[0].Targets, want) {
		t.Fatalf("request %+v, want the posted generation 2", f.telemetryProposed)
	}
	if !slices.Equal(f.telemetryResolved[0], []executions.TelemetryGuest{{VMID: 204, Generation: 3, Kind: "lxc", Node: "p1"}}) {
		t.Fatalf("inventory %+v", f.telemetryResolved[0])
	}
}

func TestPVELivePreviewRejections(t *testing.T) {
	var many strings.Builder
	for i := range 65 {
		fmt.Fprintf(&many, "&target=p1/qemu/%d/1", 200+i)
	}
	tooLargeGen := fmt.Sprintf("scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/%d", pvecontract.MaxGuestGeneration+1)
	for _, tc := range []struct{ name, form string }{
		{"bad days", "scope=provider_telemetry&remote=remote-a&days=9&target=p1/node/0"},
		{"no targets", "scope=provider_telemetry&remote=remote-a&days=7"},
		{"too many", "scope=provider_telemetry&remote=remote-a&days=7" + many.String()},
		{"node with vmid", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/node/5"},
		{"unknown kind", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/docker/101"},
		{"vmid not a number", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/abc/1"},
		{"vmid leading zero", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/0101/1"},
		{"vmid too small", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/99/1"},
		{"short key", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/node"},
		{"guest without generation", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101"},
		{"guest generation zero", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/0"},
		{"guest generation empty", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/"},
		{"guest generation not a number", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/x"},
		{"guest generation leading zero", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/01"},
		{"guest generation signed", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/%2B1"},
		{"guest generation too large", tooLargeGen},
		{"node with generation", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/node/0/1"},
		{"long key", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/1/1"},
		{"bad node", "scope=provider_telemetry&remote=remote-a&days=7&target=p%201/node/0"},
		{"duplicate", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/node/0&target=p1/node/0"},
		{"same guest two generations", "scope=provider_telemetry&remote=remote-a&days=7&target=p1/qemu/101/1&target=p1/qemu/101/2"},
		{"blocked remote", "scope=provider_telemetry&remote=remote-b&days=7&target=p1/node/0"},
		{"unknown remote", "scope=provider_telemetry&remote=remote-x&days=7&target=p1/node/0"},
		{"two remotes", "scope=provider_telemetry&remote=remote-a&remote=remote-c&days=7&target=p1/node/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{telemetryPreview: telemetryPreview()}
			code, body := postLeaseForm(t, pveLiveHandler(t, f), "/leases/preview", tc.form)
			if code != http.StatusBadRequest {
				t.Fatalf("status %d: %s", code, body)
			}
			if len(f.telemetryProposed) != 0 {
				t.Fatal("a refused form reached the service")
			}
		})
	}
}

func TestPVELivePreviewServiceErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"input", &executions.ReadGrantInputError{Reason: "guest 101 changed (kind, node or incarnation): reload the page"}, http.StatusBadRequest},
		{"mismatch", executions.ErrReadGrantProposalMismatch, http.StatusBadGateway},
		{"remotes", executions.ErrProviderRemotesUnavailable, http.StatusBadGateway},
		{"other", errors.New("database secret path"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLeases{telemetryErr: tc.err}
			code, body := postLeaseForm(t, pveLiveHandler(t, f), "/leases/preview", pveLiveForm)
			if code != tc.code || strings.Contains(body, "secret") {
				t.Fatalf("status %d body %q", code, body)
			}
		})
	}
}

func TestTelemetryLeaseDetailRendersMetricsTargets(t *testing.T) {
	g := telemetryView(executions.ProviderBindingStale, 4)
	page := getBody(t, pveLiveHandler(t, &fakeLeases{grants: []executions.ReadGrantView{g}}), "/leases/"+leaseID)
	for _, w := range []string{
		"2 nodes and guests of remote-a (live values)",
		`<tr class="lease-metrics-target"><td class="mono">p1</td><td>node</td><td class="mono">—</td><td class="mono">—</td></tr>`,
		`<tr class="lease-metrics-target"><td class="mono">p1</td><td>qemu</td><td class="mono">101</td><td class="mono">4</td></tr>`,
		"Lease stale for",
		`href="/pve/remote-a#live">Refresh</a>`,
	} {
		if !strings.Contains(page, w) {
			t.Errorf("detail misses %q", w)
		}
	}
}
