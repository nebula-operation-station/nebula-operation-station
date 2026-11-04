// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Guest snapshot page (ADR 0006 P2-01 UI, job pu02): per guest, the stored
// snapshots (name, time, parent, RAM flag) with a create form and, per
// snapshot, Delete and Roll back. Each proposes the px02 action; the
// proposal page shows the exact snapshot identity and the executor's risk.

// gsSnapTime is the time of the stored snapshots.
var gsSnapTime = time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)

// fakeGSStore is the power tests' store plus stored snapshots.
type fakeGSStore struct {
	*fakeGPStore
	mu    sync.Mutex
	snaps map[uint64][]pveinventory.Snapshot
	calls int
}

func (f *fakeGSStore) ListSnapshots(_ context.Context, remoteID string, vmid, generation uint64, _ int) ([]pveinventory.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if remoteID != gpRemote {
		return nil, nil
	}
	var out []pveinventory.Snapshot
	for _, s := range f.snaps[vmid] {
		if s.Generation == generation {
			out = append(out, s)
		}
	}
	return out, nil
}

func gsSnap(vmid uint64, name, parent string, ram bool, at time.Time) pveinventory.Snapshot {
	return pveinventory.Snapshot{RemoteID: gpRemote, VMID: vmid, Generation: 1, Name: name, TimeUnix: at.Unix(),
		Parent: parent, HasRAM: ram, State: pveinventory.StateAvailable, ObservedAt: time.Now()}
}

// gsSnapArtifactSHA256 is the hash of the executor's fixed artifact of op
// (internal/executor pveSnapshotArtifact), written out independently of
// the UI's table.
func gsSnapArtifactSHA256(op string) string {
	text := map[string]string{
		"create":   "Create one snapshot with the exact name and RAM choice of the exact guest; every disk on verified snapshot-capable storage.",
		"delete":   "Delete the one exact snapshot (name, time and parent) of the exact guest; never by age, pattern or in bulk; no force.",
		"rollback": "Roll the exact guest back to the one exact snapshot (destructive: state since the snapshot is lost); explicit start flag and RAM side effect.",
	}[op]
	sum := sha256.Sum256([]byte("pve.guest.snapshot 1.0.0\nop: " + op + "\n" + text + "\n"))
	return hex.EncodeToString(sum[:])
}

// fakeGuestSnapshot records the executor's snapshot calls.
type fakeGuestSnapshot struct {
	mu          sync.Mutex
	proposed    []*pb.PVEGuestSnapshotTarget
	digests     []string
	risk        pb.RiskClass
	requirement pb.ApprovalRequirement
	// snapshot overrides the returned bound snapshot (nil: echo expect).
	snapshot  *pb.PVESnapshotIdentity
	runsAfter *bool // overrides GuestRunsAfter
	commits   []*pb.CommitPVEGuestSnapshotRequest
}

func (f *fakeGuestSnapshot) ProposePVEGuestSnapshot(_ context.Context, in *pb.ProposePVEGuestSnapshotRequest, _ ...grpc.CallOption) (*pb.ProposePVEGuestSnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := in.GetTarget()
	f.proposed = append(f.proposed, t)
	target, err := permit.ProviderMutationTarget{RemoteID: t.GetRemoteId(), TrustPin: gpPin, Kind: t.GetKind(), Node: t.GetNode(), VMID: t.GetVmid()}.RiskTarget()
	if err != nil {
		return nil, err
	}
	rq := canonical.Request{
		RequestVersion: 1, ExecutionID: "exec-s" + strconv.Itoa(len(f.proposed)), ActionID: "pve.guest.snapshot", ModuleVersion: "1.0.0",
		ArtifactSHA256: gsSnapArtifactSHA256(t.GetOp()), ParametersHash: strings.Repeat("0e", 32),
		CredentialRefs: []string{"pve-lab-action"}, RiskClass: canonical.Risk(strings.TrimPrefix(f.risk.String(), "RISK_CLASS_")),
		StagePlanHash: strings.Repeat("5f", 32), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{target},
	}
	c, err := canonical.Encode(rq)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	digest := hex.EncodeToString(sum[:])
	f.digests = append(f.digests, digest)
	resp := &pb.ProposePVEGuestSnapshotResponse{Permit: &pb.ProposeExecutionResponse{
		ExecutionDigest: digest, CanonicalRequest: c, ApprovalRequirement: f.requirement, RiskClass: f.risk,
		ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"Y2hhbA"}`),
	}}
	if t.GetOp() != "create" {
		resp.Snapshot = t.GetExpect()
		if f.snapshot != nil {
			resp.Snapshot = f.snapshot
		}
	}
	if t.GetOp() == "rollback" {
		resp.GuestRunsAfter = t.GetStart() || t.GetExpect().GetVmstate()
		if f.runsAfter != nil {
			resp.GuestRunsAfter = *f.runsAfter
		}
	}
	return resp, nil
}

func (f *fakeGuestSnapshot) SubmitAssertion(context.Context, *pb.SubmitAssertionRequest, ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	return &pb.SubmitAssertionResponse{}, nil
}

func (f *fakeGuestSnapshot) CommitPVEGuestSnapshot(_ context.Context, in *pb.CommitPVEGuestSnapshotRequest, _ ...grpc.CallOption) (*pb.CommitPVEGuestSnapshotResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, in)
	return &pb.CommitPVEGuestSnapshotResponse{ExecutionId: "exec-s1", Steps: []*pb.PVEGuestPowerStep{
		{State: "succeeded", Upid: "UPID:pve1:0001:qmdelsnapshot:100:root@pam:", TaskType: "qmdelsnapshot"}}}, nil
}

func (f *fakeGuestSnapshot) proposals() []*pb.PVEGuestSnapshotTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.PVEGuestSnapshotTarget(nil), f.proposed...)
}

func (f *fakeGuestSnapshot) lastDigest() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.digests) == 0 {
		return gpDigest
	}
	return f.digests[len(f.digests)-1]
}

func (f *fakeGuestSnapshot) commitList() []*pb.CommitPVEGuestSnapshotRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.CommitPVEGuestSnapshotRequest(nil), f.commits...)
}

// gsEnv is a UI handler with the snapshot actions wired.
type gsEnv struct {
	exec  *fakeGuestSnapshot
	store *fakeGSStore
	state string
	clock *gpClock
	h     http.Handler
}

func gsDefaultSnaps() map[uint64][]pveinventory.Snapshot {
	return map[uint64][]pveinventory.Snapshot{
		100: {
			gsSnap(100, "before-upgrade", "", false, gsSnapTime),
			gsSnap(100, "with-ram", "before-upgrade", true, gsSnapTime.Add(time.Hour)),
		},
		101: {gsSnap(101, "ct-base", "", false, gsSnapTime)},
	}
}

func newGSEnv(t *testing.T, snaps map[uint64][]pveinventory.Snapshot) *gsEnv {
	t.Helper()
	e := &gsEnv{
		exec: &fakeGuestSnapshot{risk: pb.RiskClass_RISK_CLASS_HIGH,
			requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED},
		store: &fakeGSStore{fakeGPStore: &fakeGPStore{guests: gpGuests()}, snaps: snaps},
		state: "active",
		clock: &gpClock{t: time.Now()},
	}
	tree := gpTree(t, gpGuests())
	e.h = newTestHandler(t, ui.Options{
		PublicOrigin: gpOrigin,
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return tree, nil },
		PVE:          e.store,
		PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) {
			return []ui.PVERemoteMeta{{RemoteID: gpRemote, Name: "PVE lab", State: e.state, TrustPin: gpPin}}, nil
		},
		GuestSnapshot: e.exec,
		Now:           e.clock.now,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler()
	return e
}

func gsListPath(vmid string) string {
	return "/pve/guests/snapshots?" + url.Values{"remote": {gpRemote}, "vmid": {vmid}}.Encode()
}

var gsFormRe = regexp.MustCompile(`(?s)<form method="post" action="/pve/guests/snapshots/propose"[^>]*>(.*?)</form>`)

// gsForms returns the snapshot forms of a page: per form its hidden fields
// and its whole HTML (under the key "_html").
func gsForms(body string) []url.Values {
	var out []url.Values
	for _, m := range gsFormRe.FindAllStringSubmatch(body, -1) {
		v := url.Values{"_html": {m[1]}}
		for _, hm := range hiddenRe.FindAllStringSubmatch(m[1], -1) {
			v.Add(hm[1], html.UnescapeString(hm[2]))
		}
		out = append(out, v)
	}
	return out
}

func gsFormsByOp(body, op string) []url.Values {
	var out []url.Values
	for _, f := range gsForms(body) {
		if f.Get("op") == op {
			out = append(out, f)
		}
	}
	return out
}

func TestGuestSnapshotListShowsNameTimeParentAndRAM(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	body := getBody(t, e.h, gsListPath("100"))
	for _, want := range []string{
		"web-vm", "QEMU VM", ">100<", ">pve1<", gpRemote,
		">before-upgrade<", ">with-ram<",
		gsSnapTime.UTC().Format(time.RFC3339), gsSnapTime.Add(time.Hour).UTC().Format(time.RFC3339),
		"RAM included", "disk only",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("snapshot list lacks %q", want)
		}
	}
	// with-ram's parent is before-upgrade; before-upgrade has none.
	if !regexp.MustCompile(`(?s)>with-ram<.*?parent[^<]*<[^>]*>before-upgrade<`).MatchString(body) &&
		!regexp.MustCompile(`(?s)>with-ram<.*?<td[^>]*>before-upgrade</td>`).MatchString(body) {
		t.Error("the list does not show with-ram's parent")
	}
	if !strings.Contains(body, "formpost.js") {
		t.Error("the snapshot forms are posted with formpost.js, which the page does not load")
	}
}

func TestGuestSnapshotListEscapesUntrustedValues(t *testing.T) {
	evil := `<img src=x onerror=alert(1)>`
	snaps := map[uint64][]pveinventory.Snapshot{100: {gsSnap(100, evil, `<b>p</b>`, false, gsSnapTime)}}
	e := newGSEnv(t, snaps)
	e.store.guests[0].name = `<script>alert(1)</script>`
	body := getBody(t, e.h, gsListPath("100"))
	for _, raw := range []string{evil, `<b>p</b>`, `<script>alert(1)</script>`} {
		if strings.Contains(body, raw) {
			t.Errorf("the page renders %q as HTML", raw)
		}
		if !strings.Contains(body, html.EscapeString(raw)) {
			t.Errorf("the page lacks the escaped %q", raw)
		}
	}
	// A name PVE could not have accepted from us gets no action buttons.
	if n := len(gsFormsByOp(body, "delete")) + len(gsFormsByOp(body, "rollback")); n != 0 {
		t.Errorf("%d actions offered on a snapshot whose name is not a valid snapshot name", n)
	}
}

func TestGuestSnapshotCreateFormValidatesNameClientSide(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	body := getBody(t, e.h, gsListPath("100"))
	create := gsFormsByOp(body, "create")
	if len(create) != 1 {
		t.Fatalf("%d create forms, want 1", len(create))
	}
	f := create[0]
	h := f.Get("_html")
	for _, want := range []string{`name="name"`, `required`, `maxlength="40"`, `pattern="`} {
		if !strings.Contains(h, want) {
			t.Errorf("create form lacks %q", want)
		}
	}
	if f.Get("remote") != gpRemote || f.Get("vmid") != "100" || f.Get("generation") != "1" || f.Get("node") != "pve1" || f.Get("kind") != "qemu" {
		t.Errorf("create form does not bind the exact guest: %v", f)
	}
	// The pattern the browser applies is the server's rule.
	m := regexp.MustCompile(`pattern="([^"]*)"`).FindStringSubmatch(h)
	if m == nil {
		t.Fatal("no pattern attribute")
	}
	re, err := regexp.Compile(`^(?:` + strings.ReplaceAll(html.UnescapeString(m[1]), `(?!current$)`, ``) + `)$`)
	if err != nil {
		t.Fatalf("pattern %q: %v", m[1], err)
	}
	for name, ok := range map[string]bool{"pre-upgrade_1": true, "1abc": false, "a b": false, "x" + strings.Repeat("y", 40): false, "": false} {
		if re.MatchString(name) != ok {
			t.Errorf("pattern accepts %q = %v, want %v", name, !ok, ok)
		}
	}
	if !strings.Contains(m[1], "(?!current$)") {
		t.Error("the pattern does not exclude the reserved name current")
	}
}

func TestGuestSnapshotRAMOptionOnlyForQEMU(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	vm := gsFormsByOp(getBody(t, e.h, gsListPath("100")), "create")
	if len(vm) != 1 || !strings.Contains(vm[0].Get("_html"), `name="vmstate"`) {
		t.Error("a running QEMU VM has no RAM option")
	}
	ct := getBody(t, e.h, gsListPath("101"))
	cf := gsFormsByOp(ct, "create")
	if len(cf) != 1 {
		t.Fatalf("container: %d create forms", len(cf))
	}
	if strings.Contains(cf[0].Get("_html"), `name="vmstate"`) || strings.Contains(ct, "Include RAM") {
		t.Error("an LXC container offers the RAM option")
	}
}

func TestGuestSnapshotDeleteAndRollbackCarryExactIdentity(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	body := getBody(t, e.h, gsListPath("100"))
	del := gsFormsByOp(body, "delete")
	rb := gsFormsByOp(body, "rollback")
	if len(del) != 2 || len(rb) != 2 {
		t.Fatalf("%d delete and %d rollback forms, want one each per snapshot", len(del), len(rb))
	}
	for _, f := range append(del, rb...) {
		if f.Get("name") == "with-ram" {
			if f.Get("snaptime") != strconv.FormatInt(gsSnapTime.Add(time.Hour).Unix(), 10) || f.Get("parent") != "before-upgrade" || f.Get("vmstate") != "1" {
				t.Errorf("%s form does not carry with-ram's identity: %v", f.Get("op"), f)
			}
			// The button names the exact snapshot and its time.
			if h := f.Get("_html"); !strings.Contains(h, "with-ram") || !strings.Contains(h, gsSnapTime.Add(time.Hour).UTC().Format(time.RFC3339)) {
				t.Errorf("%s button does not name the snapshot and its time", f.Get("op"))
			}
		}
	}
	// Rollback: the start choice is explicit (no default) and required.
	for _, f := range rb {
		h := f.Get("_html")
		if !strings.Contains(h, `name="start" value="yes"`) || !strings.Contains(h, `name="start" value="no"`) || !strings.Contains(h, "required") {
			t.Errorf("rollback form has no explicit start choice: %s", h)
		}
		if strings.Contains(h, "checked") {
			t.Error("rollback form preselects a start choice")
		}
	}
	// No bulk or age-based delete anywhere.
	low := strings.ToLower(body)
	for _, bad := range []string{"delete all", "older than", "bulk", `type="checkbox" name="snapshot`} {
		if strings.Contains(low, bad) {
			t.Errorf("the page offers %q", bad)
		}
	}

	// Rolling back posts the exact identity to the executor.
	f := rb[1]
	if f.Get("name") != "with-ram" {
		f = rb[0]
	}
	form := url.Values{}
	for k, v := range f {
		if k != "_html" {
			form[k] = v
		}
	}
	form.Set("start", "no")
	rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose rollback = %d %q", rec.Code, rec.Body.String())
	}
	p := e.exec.proposals()
	if len(p) != 1 {
		t.Fatalf("%d proposals", len(p))
	}
	x := p[0].GetExpect()
	if p[0].GetOp() != "rollback" || p[0].GetName() != "with-ram" || p[0].GetStart() || p[0].GetVmstate() ||
		x.GetName() != "with-ram" || x.GetSnaptimeUnix() != gsSnapTime.Add(time.Hour).Unix() || x.GetParent() != "before-upgrade" || !x.GetVmstate() ||
		p[0].GetRemoteId() != gpRemote || p[0].GetVmid() != 100 || p[0].GetNode() != "pve1" || p[0].GetKind() != "qemu" {
		t.Errorf("proposed target %v", p[0])
	}
	if loc := rec.Header().Get("Location"); loc != "/pve/guests/snapshots/proposals/"+e.exec.lastDigest() {
		t.Fatalf("redirect to %q", loc)
	}
	page := getBody(t, e.h, rec.Header().Get("Location"))
	for _, want := range []string{
		"Guest snapshot: rollback", "with-ram", gsSnapTime.Add(time.Hour).UTC().Format(time.RFC3339), "before-upgrade",
		`class="badge badge--critical">HIGH<`, e.exec.lastDigest(),
		"Start after rollback", "includes RAM", // explicit start and RAM side effect
		`data-commit="/pve/guests/snapshots/commit"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rollback proposal page lacks %q", want)
		}
	}
}

func TestGuestSnapshotDeleteProposalNamesSnapshotAndTime(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	form := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
		"op": {"delete"}, "name": {"before-upgrade"}, "snaptime": {strconv.FormatInt(gsSnapTime.Unix(), 10)}, "parent": {""}}
	rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose delete = %d %q", rec.Code, rec.Body.String())
	}
	page := getBody(t, e.h, rec.Header().Get("Location"))
	for _, want := range []string{"Guest snapshot: delete", "before-upgrade", gsSnapTime.UTC().Format(time.RFC3339),
		`class="badge badge--critical">HIGH<`, "Approve delete of snapshot before-upgrade"} {
		if !strings.Contains(page, want) {
			t.Errorf("delete proposal page lacks %q", want)
		}
	}
	// Approving commits the exact identity.
	rec = gpPostJSON(t, e.h, "/pve/guests/snapshots/commit", map[string]any{"id": e.exec.lastDigest(), "assertion": map[string]string{"id": "x"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit = %d %q", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.exec.commitList()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	c := e.exec.commitList()
	if len(c) != 1 {
		t.Fatalf("%d commits", len(c))
	}
	if x := c[0].GetTarget().GetExpect(); c[0].GetExecutionDigest() != e.exec.lastDigest() || x.GetName() != "before-upgrade" || x.GetSnaptimeUnix() != gsSnapTime.Unix() {
		t.Errorf("commit %v", c[0])
	}
}

func TestGuestSnapshotInvalidNameRefusedBeforeProposing(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	base := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"}, "op": {"create"}}
	for _, name := range []string{"", "current", "1abc", "a b", "a/b", "x" + strings.Repeat("y", 40), "<script>", "näme", "a\x00b"} {
		f := url.Values{}
		for k, v := range base {
			f[k] = v
		}
		f.Set("name", name)
		rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", f)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name %q: %d, want 400", name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<") {
			t.Errorf("name %q: refusal echoes markup: %q", name, rec.Body.String())
		}
	}
	if n := len(e.exec.proposals()); n != 0 {
		t.Errorf("%d proposals reached the executor", n)
	}
}

func TestGuestSnapshotProposeRefusals(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	ident := func(op string) url.Values {
		return url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
			"op": {op}, "name": {"before-upgrade"}, "snaptime": {strconv.FormatInt(gsSnapTime.Unix(), 10)}, "parent": {""}}
	}
	cases := []struct {
		name string
		mod  func(url.Values)
		code int
	}{
		{"unknown op", func(v url.Values) { v.Set("op", "delete-all") }, http.StatusBadRequest},
		{"rollback without start choice", func(v url.Values) { v.Set("op", "rollback") }, http.StatusBadRequest},
		{"rollback with bad start", func(v url.Values) { v.Set("op", "rollback"); v.Set("start", "on") }, http.StatusBadRequest},
		{"delete with start", func(v url.Values) { v.Set("start", "yes") }, http.StatusBadRequest},
		{"delete without time", func(v url.Values) { v.Del("snaptime") }, http.StatusBadRequest},
		{"delete of another time", func(v url.Values) { v.Set("snaptime", "12345") }, http.StatusConflict},
		{"delete of another parent", func(v url.Values) { v.Set("parent", "x") }, http.StatusConflict},
		{"delete of unknown snapshot", func(v url.Values) { v.Set("name", "nope") }, http.StatusConflict},
		{"RAM on LXC", func(v url.Values) {
			v.Set("vmid", "101")
			v.Set("kind", "lxc")
			v.Set("op", "create")
			v.Set("name", "new1")
			v.Del("snaptime")
			v.Del("parent")
			v.Set("vmstate", "1")
		}, http.StatusBadRequest},
		{"RAM on stopped VM", func(v url.Values) {
			v.Set("vmid", "102")
			v.Set("op", "create")
			v.Set("name", "new1")
			v.Del("snaptime")
			v.Del("parent")
			v.Set("vmstate", "1")
		}, http.StatusConflict},
		{"create with identity", func(v url.Values) { v.Set("op", "create"); v.Set("name", "new1") }, http.StatusBadRequest},
		{"re-created guest", func(v url.Values) { v.Set("generation", "2") }, http.StatusConflict},
		{"migrated guest", func(v url.Values) { v.Set("node", "pve2") }, http.StatusConflict},
	}
	for _, c := range cases {
		f := ident("delete")
		c.mod(f)
		rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", f)
		if rec.Code != c.code {
			t.Errorf("%s: %d %q, want %d", c.name, rec.Code, rec.Body.String(), c.code)
		}
		e.clock.add(3 * time.Second) // past the proposal throttle
	}
	if n := len(e.exec.proposals()); n != 0 {
		t.Errorf("%d refused proposals reached the executor", n)
	}
}

func TestGuestSnapshotExecutorBindingDifferenceWithholdsApproval(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	e.exec.snapshot = &pb.PVESnapshotIdentity{Name: "before-upgrade", SnaptimeUnix: gsSnapTime.Unix() + 1}
	form := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
		"op": {"delete"}, "name": {"before-upgrade"}, "snaptime": {strconv.FormatInt(gsSnapTime.Unix(), 10)}, "parent": {""}}
	rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
	}
	page := getBody(t, e.h, rec.Header().Get("Location"))
	if !strings.Contains(page, "approval withheld") || strings.Contains(page, "schedule-approve") {
		t.Error("a different bound snapshot does not withhold approval")
	}
}

func TestGuestSnapshotRollbackRunsAfterDifferenceWithholdsApproval(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	no := false
	e.exec.runsAfter = &no
	form := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
		"op": {"rollback"}, "name": {"before-upgrade"}, "snaptime": {strconv.FormatInt(gsSnapTime.Unix(), 10)}, "parent": {""}, "start": {"yes"}}
	rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
	}
	page := getBody(t, e.h, rec.Header().Get("Location"))
	if !strings.Contains(page, "approval withheld") || strings.Contains(page, "schedule-approve") {
		t.Error("a differing start side effect does not withhold approval")
	}
}

func TestGuestSnapshotCreateProposal(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	e.exec.risk = pb.RiskClass_RISK_CLASS_MEDIUM
	form := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
		"op": {"create"}, "name": {"pre-patch_1"}, "vmstate": {"1"}}
	rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
	}
	p := e.exec.proposals()
	if len(p) != 1 || p[0].GetOp() != "create" || p[0].GetName() != "pre-patch_1" || !p[0].GetVmstate() || p[0].GetExpect() != nil || p[0].GetStart() {
		t.Fatalf("proposed %v", p)
	}
	page := getBody(t, e.h, rec.Header().Get("Location"))
	for _, want := range []string{"Guest snapshot: create", "pre-patch_1", "RAM included", `class="badge badge--warning">MEDIUM<`} {
		if !strings.Contains(page, want) {
			t.Errorf("create proposal page lacks %q", want)
		}
	}
}

func TestGuestSnapshotRoutesNeedExecutor(t *testing.T) {
	store := &fakeGSStore{fakeGPStore: &fakeGPStore{guests: gpGuests()}, snaps: gsDefaultSnaps()}
	h := newTestHandler(t, ui.Options{PublicOrigin: gpOrigin, PVE: store, GuestPower: &fakeGuestPower{}}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, gsListPath("100"), nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("snapshot page without executor = %d", rec.Code)
	}
	if rec := gpPost(t, h, "/pve/guests/snapshots/propose", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("propose without executor = %d", rec.Code)
	}
}

func TestGuestSnapshotProposalNotServedAsPowerProposal(t *testing.T) {
	e := newGSEnv(t, gsDefaultSnaps())
	form := url.Values{"remote": {gpRemote}, "vmid": {"100"}, "generation": {"1"}, "node": {"pve1"}, "kind": {"qemu"},
		"op": {"create"}, "name": {"x1"}}
	if rec := gpPost(t, e.h, "/pve/guests/snapshots/propose", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pve/guests/power/"+e.exec.lastDigest(), nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("snapshot proposal under the power route = %d", rec.Code)
	}
}
