// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const (
	regCfg    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	regCredID = "0123456789abcdef0123456789abcdef"
)

// fakeRegistryReads stands in for the server's registry read caller.
type fakeRegistryReads struct {
	mu         sync.Mutex
	regs       []registrymeta.PrivateIdentity
	listErr    error
	proposal   registrymeta.LeaseProposal
	proposeErr error
	proposed   []registrymeta.LeaseRequest
	leases     []registrymeta.LeaseView
	resolved   int
	listed     int
}

func (f *fakeRegistryReads) PrivateRegistries(context.Context) ([]registrymeta.PrivateIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed++
	return f.regs, f.listErr
}

func (f *fakeRegistryReads) ProposeRegistryLease(_ context.Context, _ string, req registrymeta.LeaseRequest) (registrymeta.LeaseProposal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposed = append(f.proposed, req)
	return f.proposal, f.proposeErr
}

func (f *fakeRegistryReads) RegistryLeases(context.Context) ([]registrymeta.LeaseView, error) {
	return f.leases, nil
}

func (f *fakeRegistryReads) ResolveImageUpdates(_ context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved++
	for i := range u.Images {
		if strings.HasPrefix(u.Images[i].Image, "registry.corp.example/") {
			u.Images[i].Private, u.Images[i].Remote, u.Images[i].Note = true, "sha256:"+strings.Repeat("d", 64), "executor-read digest"
		}
	}
	return u
}

func regTarget() permit.RegistryTarget {
	return permit.RegistryTarget{RegistryID: "corp", ConfigDigest: regCfg, ConfigVersion: 1, CredentialID: regCredID,
		CredentialVersion: 2, Repositories: []string{"team/app", "team/db"}, Methods: []string{schedgrant.RegistryReadTagDigest}}
}

func newFakeRegistryReads() *fakeRegistryReads {
	now := time.Unix(1_800_000_000, 0).UTC()
	return &fakeRegistryReads{
		regs: []registrymeta.PrivateIdentity{{ID: "corp", Origin: "https://registry.corp.example", Repositories: []string{"team/app", "team/db"},
			ConfigDigest: regCfg, ConfigVersion: 1, CredentialID: regCredID, CredentialVersion: 2}},
		proposal: registrymeta.LeaseProposal{Digest: leaseDigest, Options: []byte(`{"publicKey":{"challenge":"abc"}}`),
			ChallengeExpiry: now.Add(5 * time.Minute), Doc: permit.ReadGrantDoc{
				Grant: permit.ReadGrantFormat, ID: leaseID, Issuer: registrymeta.LeaseIssuer, CreatedUnix: now.Unix(),
				ExpiryUnix: now.Add(7 * 24 * time.Hour).Unix(), Trigger: permit.TriggerOnDemand, MinIntervalS: 900,
				RunBudget: schedgrant.RegistryDefaultRunBudget, RateProfile: schedgrant.RegistryReadProfile,
				RegistryTargets: []permit.RegistryTarget{regTarget()}}},
	}
}

func registryLeaseHandler(t *testing.T, f *fakeLeases, r *fakeRegistryReads) http.Handler {
	t.Helper()
	o := ui.Options{PublicOrigin: leaseOrigin, Leases: f}
	if r != nil {
		o.RegistryReads = r
	}
	return newTestHandler(t, o).Handler()
}

func TestRegistryLeaseFormOffersExecutorRegistries(t *testing.T) {
	page := getBody(t, registryLeaseHandler(t, &fakeLeases{}, newFakeRegistryReads()), "/leases/new")
	for _, want := range []string{`name="scope" value="registry"`, `<select name="registry"`, `<option value="corp">`,
		"https://registry.corp.example: team/app, team/db", `name="registry_method" value="tag_digest" checked`,
		`name="registry_method" value="list_tags">`} {
		if !strings.Contains(page, want) {
			t.Errorf("form misses %q", want)
		}
	}
	if page := getBody(t, registryLeaseHandler(t, &fakeLeases{}, nil), "/leases/new"); strings.Contains(page, `value="registry"`) {
		t.Error("registry scope offered without registry reads")
	}
}

// TestRegistryLeasePreviewProposesAndShowsTheFrozenRegistries: the form
// proposes exactly the chosen registry and reads, and the proposal page
// shows every frozen registry target before approval.
func TestRegistryLeasePreviewProposesAndShowsTheFrozenRegistries(t *testing.T) {
	f, r := &fakeLeases{}, newFakeRegistryReads()
	h := registryLeaseHandler(t, f, r)
	code, body := postLeaseForm(t, h, "/leases/preview", "scope=registry&registry=corp&registry_method=tag_digest&days=7&action=core.facts")
	if code != http.StatusSeeOther {
		t.Fatalf("POST = %d (%s)", code, body)
	}
	if len(f.proposed)+len(f.providerProposed) != 0 || len(r.proposed) != 1 {
		t.Fatalf("proposals: host %d provider %d registry %d", len(f.proposed), len(f.providerProposed), len(r.proposed))
	}
	req := r.proposed[0]
	if req.Days != 7 || len(req.Registries) != 1 || req.Registries[0].RegistryID != "corp" ||
		!slices.Equal(req.Registries[0].Methods, []string{"tag_digest"}) || len(req.Registries[0].Repositories) != 0 {
		t.Fatalf("request = %+v", req)
	}
	page := getBody(t, h, "/leases/proposals/"+leaseDigest)
	for _, want := range []string{"1 private registries", `<tr class="lease-registry"><td class="mono">corp</td>`, regCfg, regCredID,
		"team/app, team/db", "registry, at most 24 reads per registry per hour", "Approve with security key", "The lease holds no credential"} {
		if !strings.Contains(page, want) {
			t.Errorf("proposal page misses %q", want)
		}
	}
	if strings.Contains(page, "0 hosts") {
		t.Error("registry proposal shows the host table")
	}
}

func TestRegistryLeasePreviewRejections(t *testing.T) {
	for _, tc := range []struct{ name, form string }{
		{"30 days", "scope=registry&registry=corp&registry_method=tag_digest&days=30"},
		{"no registry", "scope=registry&registry_method=tag_digest&days=7"},
		{"unknown registry", "scope=registry&registry=other&registry_method=tag_digest&days=7"},
		{"malformed registry", "scope=registry&registry=%3Cx%3E&registry_method=tag_digest&days=7"},
		{"registry twice", "scope=registry&registry=corp&registry=corp&registry_method=tag_digest&days=7"},
		{"no method", "scope=registry&registry=corp&days=7"},
		{"unknown method", "scope=registry&registry=corp&registry_method=pull&days=7"},
		{"method twice", "scope=registry&registry=corp&registry_method=tag_digest&registry_method=tag_digest&days=7"},
	} {
		r := newFakeRegistryReads()
		code, _ := postLeaseForm(t, registryLeaseHandler(t, &fakeLeases{}, r), "/leases/preview", tc.form)
		if code != http.StatusBadRequest || len(r.proposed) != 0 {
			t.Errorf("%s: %d, proposed %d", tc.name, code, len(r.proposed))
		}
	}
	r := newFakeRegistryReads()
	r.proposeErr = registrymeta.ErrLeaseProposalMismatch
	if code, _ := postLeaseForm(t, registryLeaseHandler(t, &fakeLeases{}, r), "/leases/preview",
		"scope=registry&registry=corp&registry_method=tag_digest&days=7"); code != http.StatusBadGateway {
		t.Errorf("mismatch = %d", code)
	}
	r = newFakeRegistryReads()
	r.listErr = errors.New("down")
	if code, _ := postLeaseForm(t, registryLeaseHandler(t, &fakeLeases{}, r), "/leases/preview",
		"scope=registry&registry=corp&registry_method=tag_digest&days=7"); code != http.StatusBadGateway || len(r.proposed) != 0 {
		t.Errorf("list failure = %d", code)
	}
	if code, _ := postLeaseForm(t, registryLeaseHandler(t, &fakeLeases{}, nil), "/leases/preview",
		"scope=registry&registry=corp&registry_method=tag_digest&days=7"); code != http.StatusBadRequest {
		t.Errorf("without registry reads = %d", code)
	}
}

// TestRegistryLeasePreviewThrottledBeforeExecutor: the per-user preview
// throttle applies before the executor's registries are listed, so
// repeated POSTs (valid or not) never reach the executor faster than the
// preview interval.
func TestRegistryLeasePreviewThrottledBeforeExecutor(t *testing.T) {
	r := newFakeRegistryReads()
	h := registryLeaseHandler(t, &fakeLeases{}, r)
	const form = "scope=registry&registry=corp&registry_method=tag_digest&days=7"
	if code, body := postLeaseForm(t, h, "/leases/preview", form); code != http.StatusSeeOther {
		t.Fatalf("first POST = %d (%s)", code, body)
	}
	for i, f := range []string{form, form, "scope=registry&registry=corp&registry_method=pull&days=7"} {
		if code, _ := postLeaseForm(t, h, "/leases/preview", f); code != http.StatusTooManyRequests {
			t.Fatalf("POST %d within the interval = %d", i, code)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listed != 1 || len(r.proposed) != 1 {
		t.Fatalf("executor reached by throttled previews: listed %d, proposed %d", r.listed, len(r.proposed))
	}
}

// TestRegistryLeaseListShowsRegistryLeasesAsValid: a registry lease the
// executions service shows as "invalid" is listed with its verified state
// and registries, and its detail page shows the frozen registries.
func TestRegistryLeaseListShowsRegistryLeasesAsValid(t *testing.T) {
	created := time.Unix(1_800_000_000, 0).UTC()
	f := &fakeLeases{grants: []executions.ReadGrantView{{ID: leaseID, State: "invalid", Hosts: []string{}, Actions: []string{}}}}
	r := newFakeRegistryReads()
	r.leases = []registrymeta.LeaseView{{ID: leaseID, Digest: leaseDigest, ApprovedBy: "webauthn:abcd", Created: created,
		Expiry: created.Add(7 * 24 * time.Hour), State: "active", Registries: []permit.RegistryTarget{regTarget()},
		RunBudget: 24, MinInterval: 15 * time.Minute}}
	h := registryLeaseHandler(t, f, r)
	page := getBody(t, h, "/leases")
	for _, want := range []string{"Private registries: corp", "1 registry reads", "1 registries", `badge--ok">active`, "scope=registry"} {
		if !strings.Contains(page, want) {
			t.Errorf("list misses %q", want)
		}
	}
	if strings.Contains(page, ">invalid<") {
		t.Error("registry lease listed as invalid")
	}
	detail := getBody(t, h, "/leases/"+leaseID)
	for _, want := range []string{"1 private registries", `<tr class="lease-registry"><td class="mono">corp</td>`, "team/app, team/db",
		leaseDigest, "webauthn:abcd", `action="/leases/revoke"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail misses %q", want)
		}
	}
	// Without registry reads the service's view stays as it was.
	if page := getBody(t, registryLeaseHandler(t, f, nil), "/leases"); !strings.Contains(page, ">invalid<") {
		t.Error("without registry reads the grant changed state")
	}
}

// TestCheckUpdatesResultShowsExecutorReadDigest: the operation page of a
// docker.check_updates result asks the registry reads for the private
// images' digests.
func TestCheckUpdatesResultShowsExecutorReadDigest(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	res := `{"format":"docker-updates-v1","phase":"done","images":1,"lines":"` +
		enc("registry.corp.example/team/app:1.0\tunknown\t\tauthentication required\n") + `"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.check_updates", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: []byte(res)}}}}
	r := newFakeRegistryReads()
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Operations: f, RegistryReads: r}).Handler()
	page := getBody(t, h, "/operations/"+opID)
	if r.resolved != 1 || !strings.Contains(page, "executor-read digest") || !strings.Contains(page, strings.Repeat("d", 64)) {
		t.Fatalf("resolved=%d page=%s", r.resolved, page)
	}
}
