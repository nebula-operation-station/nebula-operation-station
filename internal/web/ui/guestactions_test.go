// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Guest power controls (ADR 0006 P2-01 UI, job pu01): the chart offers
// Shutdown/Reboot/Stop (and Reset for QEMU) on running guests of active
// remotes; each button proposes the px01 action and the proposal page
// shows the exact guest and the executor's risk before approval.

const (
	gpOrigin = "https://nebula.example"
	gpRemote = "pve-lab"
)

var gpDigest = strings.Repeat("ab", 32)

// gpGuest is one stored guest of the fake PVE store.
type gpGuest struct {
	vmid       uint64
	kind, node string
	name       string
	status     string
	generation uint64
}

// fakeGPStore is an in-memory PVEStore for the power tests.
type fakeGPStore struct {
	mu        sync.Mutex
	guests    []gpGuest
	listCalls int
}

func (f *fakeGPStore) lists() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

func (f *fakeGPStore) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	return []pveinventory.Remote{{RemoteID: gpRemote, Name: "PVE lab"}}, nil
}

func (f *fakeGPStore) GetRemote(context.Context, string) (pveinventory.Remote, error) {
	return pveinventory.Remote{RemoteID: gpRemote, Name: "PVE lab"}, nil
}

func (f *fakeGPStore) ListNodes(context.Context, string, int) ([]pveinventory.Node, error) {
	return nil, nil
}

func (f *fakeGPStore) ListGuests(_ context.Context, remoteID string, flt pveinventory.GuestFilter, _ int) ([]pveinventory.Guest, error) {
	f.mu.Lock()
	f.listCalls++
	f.mu.Unlock()
	if remoteID != gpRemote {
		return nil, nil
	}
	var out []pveinventory.Guest
	for _, g := range f.guests {
		if flt.VMID != 0 && g.vmid != flt.VMID {
			continue
		}
		out = append(out, pveinventory.Guest{RemoteID: gpRemote, VMID: g.vmid, Generation: g.generation, Kind: g.kind,
			Node: g.node, Name: g.name, Status: g.status, State: pveinventory.StateAvailable, ObservedAt: time.Now()})
	}
	return out, nil
}

func (f *fakeGPStore) ListDatasetStatus(context.Context, string) ([]pveinventory.DatasetStatus, error) {
	return nil, nil
}

// gpPin is the PVE remote's trust pin in the fake registry.
var gpPin = strings.Repeat("c1", 32)

// gpArtifactSHA256 is the hash of the executor's fixed artifact of verb
// (internal/executor pveGuestPowerArtifact), written out independently of
// the UI's table.
func gpArtifactSHA256(verb string) string {
	text := map[string]string{
		"shutdown": "Graceful shutdown (ACPI, guest agent or LXC) of the exact running guest; never a force stop.",
		"reboot":   "Graceful reboot of the exact running guest; never a force stop.",
		"stop":     "Hard stop of the exact running guest (destructive: like pulling the power).",
		"reset":    "Hard reset of the exact running QEMU guest (destructive: like pressing reset).",
	}[verb]
	sum := sha256.Sum256([]byte("pve.guest.power 1.0.0\nverb: " + verb + "\n" + text + "\n"))
	return hex.EncodeToString(sum[:])
}

// gpCanonical builds the canonical request the executor binds for t
// (permit.ProviderMutationRequest): the target's host ID, its synthetic
// fingerprint under the trust pin, the verb's artifact and the risk.
func gpCanonical(t *pb.PVEGuestPowerTarget, risk string, execID string) canonical.Request {
	target, err := permit.ProviderMutationTarget{RemoteID: t.GetRemoteId(), TrustPin: gpPin, Kind: t.GetKind(), Node: t.GetNode(), VMID: t.GetVmid()}.RiskTarget()
	if err != nil {
		panic(err)
	}
	return canonical.Request{
		RequestVersion: 1, ExecutionID: execID, ActionID: "pve.guest.power", ModuleVersion: "1.0.0",
		ArtifactSHA256: gpArtifactSHA256(t.GetVerb()), ParametersHash: strings.Repeat("0d", 32),
		CredentialRefs: []string{"pve-lab-action"}, RiskClass: canonical.Risk(risk), StagePlanHash: strings.Repeat("5e", 32),
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(), ResolvedTargets: []canonical.Target{target},
	}
}

// fakeGuestPower records the executor calls.
type fakeGuestPower struct {
	mu          sync.Mutex
	proposed    []*pb.PVEGuestPowerTarget
	digests     []string
	risk        pb.RiskClass
	requirement pb.ApprovalRequirement
	proposeErr  error
	// mutate changes the canonical request before it is returned (an
	// executor binding something else); raw replaces it entirely.
	mutate     func(*canonical.Request)
	raw        []byte
	badDigest  bool // the digest is not the canonical request's hash
	assertions []*pb.SubmitAssertionRequest
	assertErr  error
	commits    []*pb.CommitPVEGuestPowerRequest
	commitErr  error
}

func (f *fakeGuestPower) ProposePVEGuestPower(_ context.Context, in *pb.ProposePVEGuestPowerRequest, _ ...grpc.CallOption) (*pb.ProposePVEGuestPowerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proposed = append(f.proposed, in.GetTarget())
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	rq := gpCanonical(in.GetTarget(), strings.TrimPrefix(f.risk.String(), "RISK_CLASS_"), "exec-"+strconv.Itoa(len(f.proposed)))
	if f.mutate != nil {
		f.mutate(&rq)
	}
	c, err := canonical.Encode(rq)
	if err != nil {
		return nil, err
	}
	if f.raw != nil {
		c = f.raw
	}
	sum := sha256.Sum256(c)
	if f.badDigest {
		sum = sha256.Sum256(append(c, ' '))
	}
	digest := hex.EncodeToString(sum[:])
	f.digests = append(f.digests, digest)
	return &pb.ProposePVEGuestPowerResponse{Permit: &pb.ProposeExecutionResponse{
		ExecutionDigest:     digest,
		CanonicalRequest:    c,
		ApprovalRequirement: f.requirement,
		RiskClass:           f.risk,
		ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		RequestOptionsJson:  []byte(`{"challenge":"Y2hhbA"}`),
	}}, nil
}

// lastDigest is the digest of the latest proposal.
func (f *fakeGuestPower) lastDigest() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.digests) == 0 {
		return gpDigest
	}
	return f.digests[len(f.digests)-1]
}

func (f *fakeGuestPower) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assertions = append(f.assertions, in)
	if f.assertErr != nil {
		return nil, f.assertErr
	}
	return &pb.SubmitAssertionResponse{}, nil
}

func (f *fakeGuestPower) CommitPVEGuestPower(_ context.Context, in *pb.CommitPVEGuestPowerRequest, _ ...grpc.CallOption) (*pb.CommitPVEGuestPowerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, in)
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitPVEGuestPowerResponse{ExecutionId: "exec-1", Steps: []*pb.PVEGuestPowerStep{
		{State: "succeeded", Upid: "UPID:pve1:0001:qmshutdown:100:root@pam:", TaskType: "qmshutdown"}}}, nil
}

func (f *fakeGuestPower) proposals() []*pb.PVEGuestPowerTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.PVEGuestPowerTarget(nil), f.proposed...)
}

func (f *fakeGuestPower) commitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.commits)
}

// gpGuests are the default stored guests: a running VM, a running
// container, a stopped VM.
func gpGuests() []gpGuest {
	return []gpGuest{
		{vmid: 100, kind: "qemu", node: "pve1", name: "web-vm", status: "running", generation: 1},
		{vmid: 101, kind: "lxc", node: "pve1", name: "dns-ct", status: "running", generation: 1},
		{vmid: 102, kind: "qemu", node: "pve1", name: "old-vm", status: "stopped", generation: 1},
	}
}

// gpTree builds the chart tree for guests.
func gpTree(t *testing.T, guests []gpGuest) pveinventory.Tree {
	t.Helper()
	now := time.Now()
	in := pveinventory.RemoteInput{RemoteID: gpRemote, Name: "PVE lab",
		Nodes: []pveinventory.NodeInput{{Node: "pve1", Status: "online", ObservedAt: now}}}
	for _, g := range guests {
		in.Guests = append(in.Guests, pveinventory.GuestInput{VMID: g.vmid, Generation: g.generation, Kind: g.kind,
			Node: g.node, Name: g.name, Status: g.status, ObservedAt: now})
	}
	tree, err := pveinventory.BuildTree(pveinventory.TreeInput{Now: now, Remotes: []pveinventory.RemoteInput{in}})
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	return tree
}

// gpEnv is a UI handler with the power controls wired.
type gpEnv struct {
	exec  *fakeGuestPower
	store *fakeGPStore
	state string // remote registry state
	h     *ui.Handler
}

func newGPEnv(t *testing.T, guests []gpGuest) *gpEnv {
	t.Helper()
	return newGPEnvClock(t, guests, nil)
}

// newGPEnvClock is newGPEnv with the UI clock now (nil: time.Now).
func newGPEnvClock(t *testing.T, guests []gpGuest, now func() time.Time) *gpEnv {
	t.Helper()
	e := &gpEnv{exec: &fakeGuestPower{risk: pb.RiskClass_RISK_CLASS_MEDIUM,
		requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED},
		store: &fakeGPStore{guests: guests}, state: "active"}
	tree := gpTree(t, guests)
	e.h = newTestHandler(t, ui.Options{
		PublicOrigin: gpOrigin,
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return tree, nil },
		PVE:          e.store,
		PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) {
			return []ui.PVERemoteMeta{{RemoteID: gpRemote, Name: "PVE lab", State: e.state, TrustPin: gpPin}}, nil
		},
		GuestPower: e.exec,
		Now:        now,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return e
}

var gpFormRe = regexp.MustCompile(`(?s)<form method="post" action="/pve/guests/power" class="chart__gpower-form"[^>]*>(.*?)</form>`)

// gpForms returns the power forms of the chart page: per form its hidden
// fields and button text.
func gpForms(t *testing.T, body string) []url.Values {
	t.Helper()
	var out []url.Values
	for _, m := range gpFormRe.FindAllStringSubmatch(body, -1) {
		v := url.Values{}
		for _, hm := range hiddenRe.FindAllStringSubmatch(m[1], -1) {
			v.Add(hm[1], html.UnescapeString(hm[2]))
		}
		out = append(out, v)
	}
	return out
}

// gpVerbs lists the offered verbs per VMID.
func gpVerbs(forms []url.Values) map[string][]string {
	out := map[string][]string{}
	for _, f := range forms {
		out[f.Get("vmid")] = append(out[f.Get("vmid")], f.Get("verb"))
	}
	return out
}

func TestChartPowerButtonsPerGuestKindAndState(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	body := getBody(t, e.h.Handler(), "/inventory/chart")
	got := gpVerbs(gpForms(t, body))
	if want := []string{"shutdown", "reboot", "stop", "reset"}; strings.Join(got["100"], ",") != strings.Join(want, ",") {
		t.Errorf("running VM verbs = %v, want %v", got["100"], want)
	}
	if want := []string{"shutdown", "reboot", "stop"}; strings.Join(got["101"], ",") != strings.Join(want, ",") {
		t.Errorf("running container verbs = %v, want %v (no reset for LXC)", got["101"], want)
	}
	if len(got["102"]) != 0 {
		t.Errorf("stopped VM offers %v, want none", got["102"])
	}
	if !strings.Contains(body, "formpost.js") {
		t.Error("power forms are posted with formpost.js, which the page does not load")
	}
	// Each form binds the exact guest the operator saw.
	for _, f := range gpForms(t, body) {
		if f.Get("vmid") == "100" {
			if f.Get("remote") != gpRemote || f.Get("node") != "pve1" || f.Get("kind") != "qemu" || f.Get("generation") != "1" {
				t.Errorf("form does not bind the exact guest: %v", f)
			}
		}
	}
}

func TestChartPowerResetAbsentForLXC(t *testing.T) {
	e := newGPEnv(t, []gpGuest{{vmid: 101, kind: "lxc", node: "pve1", name: "dns-ct", status: "running", generation: 1}})
	body := getBody(t, e.h.Handler(), "/inventory/chart")
	if strings.Contains(body, `name="verb" value="reset"`) || strings.Contains(body, ">Reset") {
		t.Error("an LXC guest offers Reset")
	}
}

func TestChartPowerLabelsDestructiveVerbs(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	body := getBody(t, e.h.Handler(), "/inventory/chart")
	for _, want := range []string{
		"Shutdown (MEDIUM)", "Reboot (MEDIUM)",
		"Stop — hard power off, HIGH", "Reset — hard reset, HIGH",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart lacks the button label %q", want)
		}
	}
}

func TestChartPowerHiddenUnlessRemoteActive(t *testing.T) {
	for _, state := range []string{"blocked", "—", ""} {
		e := newGPEnv(t, gpGuests())
		e.state = state
		body := getBody(t, e.h.Handler(), "/inventory/chart")
		if strings.Contains(body, "/pve/guests/power") {
			t.Errorf("remote state %q: power controls shown", state)
		}
	}
}

func TestChartPowerHiddenWithoutExecutor(t *testing.T) {
	tree := gpTree(t, gpGuests())
	h := newTestHandler(t, ui.Options{
		PublicOrigin: gpOrigin,
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return tree, nil },
		PVE:          &fakeGPStore{guests: gpGuests()},
		PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) {
			return []ui.PVERemoteMeta{{RemoteID: gpRemote, State: "active"}}, nil
		},
	})
	if body := getBody(t, h.Handler(), "/inventory/chart"); strings.Contains(body, "/pve/guests/power") {
		t.Error("power controls shown without Options.GuestPower")
	}
}

// gpPost posts a form directly to the handler (no middleware).
func gpPost(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gpForm(vmid, kind, verb string) url.Values {
	return url.Values{"remote": {gpRemote}, "vmid": {vmid}, "generation": {"1"}, "node": {"pve1"}, "kind": {kind}, "verb": {verb}}
}

func TestGuestPowerProposalPageShowsExactTargetAndRisk(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.risk = pb.RiskClass_RISK_CLASS_HIGH
	h := e.h.Handler()
	rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/pve/guests/power/"+e.exec.lastDigest() {
		t.Fatalf("redirect to %q", loc)
	}
	p := e.exec.proposals()
	if len(p) != 1 {
		t.Fatalf("%d proposals", len(p))
	}
	if p[0].GetRemoteId() != gpRemote || p[0].GetKind() != "qemu" || p[0].GetNode() != "pve1" || p[0].GetVmid() != 100 ||
		p[0].GetVerb() != "stop" || p[0].GetTimeoutSec() != 0 {
		t.Errorf("proposed target %v", p[0])
	}
	body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
	for _, want := range []string{
		"web-vm", ">100<", ">pve1<", "QEMU VM", ">stop<", gpRemote,
		`class="badge badge--critical">HIGH<`, e.exec.lastDigest(),
		"hard power off", // the destructive verb is spelled out
		`class="button schedule-approve button--danger"`, `data-commit="/pve/guests/power/commit"`,
		"webauthn.js", "schedules.js",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("proposal page lacks %q", want)
		}
	}
}

func TestGuestPowerProposalShowsExecutorRiskNotUIBase(t *testing.T) {
	// The executor raised a MEDIUM shutdown to CRITICAL (criticality
	// floor): the page shows CRITICAL, and browser approval (which cannot
	// send the typed count) gives way to the CLI.
	e := newGPEnv(t, gpGuests())
	e.exec.risk = pb.RiskClass_RISK_CLASS_CRITICAL
	e.exec.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED_TYPED_COUNT
	h := e.h.Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "shutdown")); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d", rec.Code)
	}
	body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
	if !strings.Contains(body, ">CRITICAL<") || strings.Contains(body, ">MEDIUM<") {
		t.Error("page does not show the executor's risk")
	}
	if strings.Contains(body, "schedule-approve") {
		t.Error("typed-count approval offered in the browser")
	}
	if !strings.Contains(body, "nebula approve "+e.exec.lastDigest()) {
		t.Error("no CLI approval command")
	}
}

func TestGuestPowerHardenedModeShowsCLI(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	h := e.h.Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "reboot")); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d", rec.Code)
	}
	body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
	if strings.Contains(body, "schedule-approve") || strings.Contains(body, "webauthn.js") {
		t.Error("hardened mode shows the browser approval")
	}
	if !strings.Contains(body, "hardened mode") || !strings.Contains(body, "nebula approve "+e.exec.lastDigest()) {
		t.Error("hardened mode lacks the CLI text")
	}
	if !strings.Contains(body, `action="/pve/guests/power/run"`) {
		t.Error("no run form after CLI approval")
	}
	// Run after CLI approval: commit without an assertion.
	rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {e.exec.lastDigest()}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("run = %d %q", rec.Code, rec.Body.String())
	}
	gpWaitCommit(t, e.exec)
	if len(e.exec.assertions) != 0 {
		t.Error("CLI run submitted an assertion")
	}
	if c := e.exec.commits[0]; c.GetExecutionDigest() != e.exec.lastDigest() || c.GetTarget().GetVerb() != "reboot" || c.GetTarget().GetVmid() != 100 {
		t.Errorf("commit %v", c)
	}
}

// gpWaitCommit waits for the background commit.
func gpWaitCommit(t *testing.T, f *fakeGuestPower) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.commitCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no commit")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func gpPostJSON(t *testing.T, h http.Handler, path string, v any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(v)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuestPowerCommitWithSecurityKey(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	h := e.h.Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("101", "lxc", "shutdown")); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d", rec.Code)
	}
	rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": e.exec.lastDigest(), "assertion": map[string]string{"id": "x"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit = %d %q", rec.Code, rec.Body.String())
	}
	gpWaitCommit(t, e.exec)
	if len(e.exec.assertions) != 1 || e.exec.assertions[0].GetExecutionDigest() != e.exec.lastDigest() {
		t.Errorf("assertions %v", e.exec.assertions)
	}
	c := e.exec.commits[0]
	if c.GetTarget().GetKind() != "lxc" || c.GetTarget().GetVmid() != 101 || c.GetTarget().GetVerb() != "shutdown" {
		t.Errorf("commit target %v", c.GetTarget())
	}
	// The page shows the result once the run is recorded.
	deadline := time.Now().Add(5 * time.Second)
	for {
		body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
		if strings.Contains(body, "succeeded") && strings.Contains(body, "exec-1") {
			if strings.Contains(body, "schedule-approve") {
				t.Error("committed proposal still offers approval")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("result not shown: %s", body)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A second approval of the same proposal is refused.
	if rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": e.exec.lastDigest(), "assertion": map[string]string{"id": "x"}}); rec.Code != http.StatusNotFound {
		t.Errorf("second commit = %d", rec.Code)
	}
}

func TestGuestPowerRejectedAssertionKeepsProposalPending(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.assertErr = status.Error(codes.PermissionDenied, "bad assertion")
	h := e.h.Handler()
	gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "shutdown"))
	rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": e.exec.lastDigest(), "assertion": map[string]string{"id": "x"}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("commit = %d", rec.Code)
	}
	if e.exec.commitCount() != 0 {
		t.Error("committed after a refused assertion")
	}
	if body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest()); !strings.Contains(body, "schedule-approve") {
		t.Error("refused approval lost the button")
	}
}

func TestGuestPowerProposeRefusals(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want int
	}{
		{"reset on LXC", gpForm("101", "lxc", "reset"), http.StatusBadRequest},
		{"unknown verb", gpForm("100", "qemu", "start"), http.StatusBadRequest},
		{"stopped guest", gpForm("102", "qemu", "shutdown"), http.StatusConflict},
		{"unknown guest", gpForm("999", "qemu", "shutdown"), http.StatusNotFound},
		{"wrong node", func() url.Values { v := gpForm("100", "qemu", "stop"); v.Set("node", "pve2"); return v }(), http.StatusConflict},
		{"wrong kind", gpForm("100", "lxc", "stop"), http.StatusConflict},
		{"wrong generation", func() url.Values { v := gpForm("100", "qemu", "stop"); v.Set("generation", "2"); return v }(), http.StatusConflict},
		{"bad vmid", gpForm("abc", "qemu", "stop"), http.StatusBadRequest},
		{"unknown remote", func() url.Values { v := gpForm("100", "qemu", "stop"); v.Set("remote", "other"); return v }(), http.StatusConflict},
		{"oversized remote", func() url.Values {
			v := gpForm("100", "qemu", "stop")
			v.Set("remote", strings.Repeat("r", 300))
			return v
		}(), http.StatusBadRequest},
		{"invalid UTF-8", func() url.Values { v := gpForm("100", "qemu", "stop"); v.Set("node", "\xff"); return v }(), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGPEnv(t, gpGuests())
			rec := gpPost(t, e.h.Handler(), "/pve/guests/power", tc.form)
			if rec.Code != tc.want {
				t.Errorf("status %d, want %d (%q)", rec.Code, tc.want, rec.Body.String())
			}
			if len(e.exec.proposals()) != 0 {
				t.Error("refused request reached the executor")
			}
		})
	}
}

func TestGuestPowerProposeRefusedOnBlockedRemote(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.state = "blocked"
	rec := gpPost(t, e.h.Handler(), "/pve/guests/power", gpForm("100", "qemu", "stop"))
	if rec.Code != http.StatusConflict {
		t.Errorf("status %d", rec.Code)
	}
	if len(e.exec.proposals()) != 0 {
		t.Error("blocked remote reached the executor")
	}
}

func TestGuestPowerExecutorRefusalIsText(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.proposeErr = status.Error(codes.FailedPrecondition, "guest <b>busy</b>")
	rec := gpPost(t, e.h.Handler(), "/pve/guests/power", gpForm("100", "qemu", "stop"))
	if rec.Code != http.StatusConflict {
		t.Errorf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type %q", ct)
	}
	e = newGPEnv(t, gpGuests()) // a fresh throttle
	e.exec.proposeErr = errors.New("connection refused")
	if rec := gpPost(t, e.h.Handler(), "/pve/guests/power", gpForm("100", "qemu", "stop")); rec.Code != http.StatusBadGateway ||
		strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("transport error = %d %q", rec.Code, rec.Body.String())
	}
}

func TestGuestPowerProposalOnlyForProposer(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	h := e.h.Handler()
	// Unknown digest and malformed digest.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pve/guests/power/"+gpDigest, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown proposal = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pve/guests/power/xyz", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("malformed digest = %d", rec.Code)
	}
	if rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": gpDigest}); rec.Code != http.StatusNotFound {
		t.Errorf("commit of unknown proposal = %d", rec.Code)
	}
	if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {gpDigest}}); rec.Code != http.StatusNotFound {
		t.Errorf("run of unknown proposal = %d", rec.Code)
	}
}

func TestGuestPowerRunRefusedForBrowserApproval(t *testing.T) {
	// A proposal that needs the security key cannot be run through the
	// CLI path without its assertion.
	e := newGPEnv(t, gpGuests())
	h := e.h.Handler()
	gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop"))
	if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {e.exec.lastDigest()}}); rec.Code != http.StatusNotFound {
		t.Errorf("run = %d", rec.Code)
	}
	time.Sleep(20 * time.Millisecond)
	if e.exec.commitCount() != 0 {
		t.Error("committed without approval")
	}
}

func TestGuestPowerEscapesGuestName(t *testing.T) {
	name := `<script>alert(1)</script>"x`
	guests := []gpGuest{{vmid: 100, kind: "qemu", node: "pve1", name: name, status: "running", generation: 1}}
	e := newGPEnv(t, guests)
	h := e.h.Handler()
	chart := getBody(t, h, "/inventory/chart")
	if strings.Contains(chart, "<script>alert(1)") {
		t.Error("chart renders the guest name as HTML")
	}
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop")); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d", rec.Code)
	}
	body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("proposal page renders the guest name as HTML")
	}
	if !strings.Contains(body, html.EscapeString("<script>alert(1)</script>")) {
		t.Error("proposal page lacks the escaped guest name")
	}
}

func TestGuestPowerRoutesNeedExecutor(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: gpOrigin, PVE: &fakeGPStore{guests: gpGuests()}}).Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop")); rec.Code != http.StatusNotFound {
		t.Errorf("propose without executor = %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pve/guests/power/"+gpDigest, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("proposal page without executor = %d", rec.Code)
	}
}

// TestGuestPowerProposeThroughMiddleware posts through the real middleware
// chain: a plain form navigation (Origin: null) and a foreign origin are
// refused before the executor is asked; the fetch post passes.
func TestGuestPowerProposeThroughMiddleware(t *testing.T) {
	for _, tc := range []struct {
		path, origin string
		body         string
		ct           string
		want         int
	}{
		{"/pve/guests/power", "null", gpForm("100", "qemu", "stop").Encode(), "application/x-www-form-urlencoded", http.StatusForbidden},
		{"/pve/guests/power", "", gpForm("100", "qemu", "stop").Encode(), "application/x-www-form-urlencoded", http.StatusForbidden},
		{"/pve/guests/power", "https://evil.example.org", gpForm("100", "qemu", "stop").Encode(), "application/x-www-form-urlencoded", http.StatusForbidden},
		{"/pve/guests/power/commit", "https://evil.example.org", `{"id":"` + gpDigest + `"}`, "application/json", http.StatusForbidden},
		{"/pve/guests/power/run", "null", url.Values{"digest": {gpDigest}}.Encode(), "application/x-www-form-urlencoded", http.StatusForbidden},
		{"/pve/guests/power", gpOrigin, gpForm("100", "qemu", "stop").Encode(), "application/x-www-form-urlencoded", http.StatusSeeOther},
	} {
		e := newGPEnv(t, gpGuests())
		srv, err := e.h.Server()
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv.Handler)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.ct)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if res.StatusCode != tc.want {
			t.Errorf("%s Origin %q = %d, want %d", tc.path, tc.origin, res.StatusCode, tc.want)
		}
		if tc.want == http.StatusForbidden && (len(e.exec.proposals()) != 0 || e.exec.commitCount() != 0) {
			t.Errorf("%s Origin %q reached the executor", tc.path, tc.origin)
		}
	}
}

func TestGuestPowerProposeIsPostOnly(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	rec := httptest.NewRecorder()
	e.h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pve/guests/power?"+gpForm("100", "qemu", "stop").Encode(), nil))
	if rec.Code == http.StatusSeeOther || len(e.exec.proposals()) != 0 {
		t.Errorf("GET proposed (status %d)", rec.Code)
	}
}
