// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Guest power controls (ADR 0006 P2-01, UI of the px01 lifecycle
// baseline). The org chart shows a "Power" section on every running guest
// of an active PVE remote: Shutdown and Reboot (MEDIUM), Stop and Reset
// (HIGH, hard; Reset for QEMU only). Each button is a form that binds the
// exact guest the operator saw (remote, VMID, incarnation generation,
// node, kind) and the verb; POST /pve/guests/power re-reads the stored
// guest, refuses any difference, and asks the executor for a proposal.
// The executor binds the guest and decides the risk; GET
// /pve/guests/power/{digest} shows exactly that to the proposer before
// approval: the headline comes from the executor's canonical request
// (action, verb, bound target, risk), which must hash to the digest and
// match the requested guest; the UI's own inventory read is secondary. A
// canonical request that cannot be shown refuses the proposal; one that
// does not match the request is shown as a mismatch without approval.
// Approval reuses the schedule approval button (webauthn.js and
// schedules.js, posting to POST /pve/guests/power/commit); in hardened
// mode, or when the executor requires the typed target count, the page
// shows the `nebula approve` command and a form (POST
// /pve/guests/power/run) that runs the CLI-approved permit.
//
// The executor waits for the PVE task when committing (a graceful
// shutdown can take minutes, longer than the HTTP write timeout), so the
// commit runs in the background once the approval is accepted; the
// proposal page shows its state and result.
//
// Like the read lease preview, the forms are posted with fetch
// (formpost.js), because a browser form navigation sends "Origin: null"
// and the middleware refuses it.

// GuestPower proposes, approves and runs typed guest power actions on the
// executor (px01). executorclient.Client satisfies it.
type GuestPower interface {
	ProposePVEGuestPower(ctx context.Context, in *pb.ProposePVEGuestPowerRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestPowerResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
	CommitPVEGuestPower(ctx context.Context, in *pb.CommitPVEGuestPowerRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestPowerResponse, error)
}

// Limits of the guest power controls.
const (
	// guestPowerProposeInterval is the minimum time between two proposals
	// of one user: each one holds an executor binding.
	guestPowerProposeInterval = 2 * time.Second
	// guestPowerProposalTTL is how long a proposal page stays available
	// (the executor's approval challenge lasts five minutes; a running
	// commit keeps its page until it ends).
	guestPowerProposalTTL = 15 * time.Minute
	// maxGuestPowerProposals bounds the proposals kept in memory.
	maxGuestPowerProposals = 256
	// maxGuestPowerProposalsPerUser bounds one user's open (pending,
	// approving or running) proposals, well below maxGuestPowerProposals,
	// so one user cannot fill the table and lock others out.
	maxGuestPowerProposalsPerUser = 32
	// maxGuestPowerThrottleUsers bounds the throttle table.
	maxGuestPowerThrottleUsers = 1024
	// guestPowerCommitTimeout bounds one background commit; the executor
	// client adds its own (shorter) task wait.
	guestPowerCommitTimeout = 15 * time.Minute
	// maxGuestPowerField is the longest remote ID, node or kind value the
	// form accepts.
	maxGuestPowerField = 128
	// maxGuestPowerCanonical is the largest canonical request shown; a
	// larger one refuses the proposal.
	maxGuestPowerCanonical = 16 << 10
	// maxGuestPowerText is the longest executor text (step state, UPID,
	// refusal) shown.
	maxGuestPowerText = 300
	// maxGuestPowerSteps bounds the shown steps of one run.
	maxGuestPowerSteps = 16
	// guestPowerCLICommand is the CLI approval command; the full digest
	// follows it.
	guestPowerCLICommand = "nebula approve "
)

// Guest kinds the power controls know.
const (
	guestKindQEMU = "qemu"
	guestKindLXC  = "lxc"
)

// guestPowerVerb describes one power verb. The label names the base risk
// (MEDIUM or HIGH, as the executor's risk policy sets it); the executor
// decides the real one, which the proposal page shows.
type guestPowerVerb struct {
	Verb        string
	Label       string // button label
	Destructive bool   // hard power action, no guest cooperation
	Explain     string // spelled out on the proposal page
	QEMUOnly    bool
}

// guestPowerVerbs are the verbs in button order.
var guestPowerVerbs = []guestPowerVerb{
	{Verb: "shutdown", Label: "Shutdown (MEDIUM)",
		Explain: "graceful shutdown: the guest is asked to shut down; there is no forced stop if it does not"},
	{Verb: "reboot", Label: "Reboot (MEDIUM)",
		Explain: "graceful reboot: the guest is asked to reboot"},
	{Verb: "stop", Label: "Stop — hard power off, HIGH", Destructive: true,
		Explain: "hard power off: the guest is cut off immediately, like pulling the plug; unsaved data is lost"},
	{Verb: "reset", Label: "Reset — hard reset, HIGH", Destructive: true, QEMUOnly: true,
		Explain: "hard reset: the VM is restarted immediately, like pressing the reset button; unsaved data is lost"},
}

// lookupGuestPowerVerb returns the verb if kind supports it.
func lookupGuestPowerVerb(verb, kind string) (guestPowerVerb, bool) {
	for _, v := range guestPowerVerbs {
		if v.Verb == verb {
			if v.QEMUOnly && kind != guestKindQEMU {
				return guestPowerVerb{}, false
			}
			return v, true
		}
	}
	return guestPowerVerb{}, false
}

// guestKindLabel is the shown guest kind.
func guestKindLabel(kind string) string {
	switch kind {
	case guestKindQEMU:
		return "QEMU VM"
	case guestKindLXC:
		return "LXC container"
	default:
		return kind
	}
}

// guestPowerView is the Power section of one guest box on the chart.
type guestPowerView struct {
	RemoteID   string
	VMID       uint64
	Generation uint64
	Node       string
	Kind       string
	KindLabel  string
	// Verbs are the offered buttons; empty when Note says why none is.
	Verbs []guestPowerVerb
	Note  string
}

// guestPowerKey keys the chart's power sections.
func guestPowerKey(remoteID string, vmid uint64) string {
	return remoteID + "/" + strconv.FormatUint(vmid, 10)
}

// PowerFor returns the Power section of a guest on the chart, or nil when
// the guest gets none.
func (d pageData) PowerFor(remoteID string, vmid uint64) *guestPowerView {
	return d.GuestPower[guestPowerKey(remoteID, vmid)]
}

// RemoteID is the node's PVE remote, for the per-guest Power sections.
func (n pveNodeView) RemoteID() string { return n.remoteID }

// remoteAllowsMutations reports whether the registry marks the remote
// active. A blocked remote, or missing metadata, gets no controls (fail
// closed); the executor still decides whether the action is enabled.
func remoteAllowsMutations(meta map[string]PVERemoteMeta, remoteID string) bool {
	m, ok := meta[remoteID]
	return ok && m.State == "active"
}

// chartGuestPower builds the Power sections of the chart's guests from
// the stored guests (kind, node, status). Nil when the controls are off.
func (h *Handler) chartGuestPower(ctx context.Context, nodes []pveNodeView) map[string]*guestPowerView {
	if h.guestPower == nil || h.pve == nil {
		return nil
	}
	meta := h.pveMeta(ctx)
	out := map[string]*guestPowerView{}
	stored := map[string]map[uint64]pveinventory.Guest{}
	for _, n := range nodes {
		if !remoteAllowsMutations(meta, n.remoteID) {
			continue
		}
		byVMID, ok := stored[n.remoteID]
		if !ok {
			guests, err := h.pve.ListGuests(ctx, n.remoteID, pveinventory.GuestFilter{}, 0)
			if err != nil {
				h.log.Error("org chart: list PVE guests for power controls", "remote", n.remoteID, "error", err)
				guests = nil
			}
			byVMID = make(map[uint64]pveinventory.Guest, len(guests))
			for _, g := range guests {
				byVMID[g.VMID] = g
			}
			stored[n.remoteID] = byVMID
		}
		for _, gv := range n.Guests {
			g, ok := byVMID[gv.VMID]
			if !ok || g.Generation != gv.generation || g.Node != n.Name {
				continue // the stored guest is not the one shown
			}
			v := &guestPowerView{RemoteID: n.remoteID, VMID: g.VMID, Generation: g.Generation, Node: g.Node,
				Kind: g.Kind, KindLabel: guestKindLabel(g.Kind)}
			switch {
			case g.Kind != guestKindQEMU && g.Kind != guestKindLXC:
				continue
			case gv.Stale || g.State != pveinventory.StateAvailable:
				v.Note = "no power action: the guest status is not current"
			case g.Status != "running":
				v.Note = "no power action: the guest is not running"
			default:
				for _, verb := range guestPowerVerbs {
					if verb.QEMUOnly && g.Kind != guestKindQEMU {
						continue
					}
					v.Verbs = append(v.Verbs, verb)
				}
			}
			out[guestPowerKey(n.remoteID, g.VMID)] = v
		}
	}
	return out
}

// guestPowerAction is the executor's action ID of the power actions.
const guestPowerAction = "pve.guest.power"

// guestPowerArtifacts maps the SHA-256 (hex) of each verb's fixed executor
// artifact to the verb: the canonical request names the verb only through
// its artifact hash. The texts must equal the executor's
// (internal/executor, pveGuestPowerArtifact, module version 1.0.0); an
// artifact this table does not know is shown as a mismatch, never
// approved.
var guestPowerArtifacts = func() map[string]string {
	texts := map[string]string{
		"shutdown": "Graceful shutdown (ACPI, guest agent or LXC) of the exact running guest; never a force stop.",
		"reboot":   "Graceful reboot of the exact running guest; never a force stop.",
		"stop":     "Hard stop of the exact running guest (destructive: like pulling the power).",
		"reset":    "Hard reset of the exact running QEMU guest (destructive: like pressing reset).",
	}
	out := make(map[string]string, len(texts))
	for verb, text := range texts {
		sum := sha256.Sum256([]byte(guestPowerAction + " 1.0.0\nverb: " + verb + "\n" + text + "\n"))
		out[hex.EncodeToString(sum[:])] = verb
	}
	return out
}()

// guestPowerBinding is what the executor's canonical request binds, as
// shown in the headline of the proposal page.
type guestPowerBinding struct {
	ActionID       string
	Verb           string // from the artifact hash; empty when unknown
	ArtifactSHA256 string
	Risk           string
	TargetID       string
	Fingerprint    string
	ParametersHash string
	Expiry         time.Time
	Canonical      string // the exact canonical request, shown in full
}

// errGuestPowerCanonical is returned when the executor's canonical
// request cannot be shown; the proposal is refused.
var errGuestPowerCanonical = errors.New("the executor's bound request cannot be shown")

// parseGuestPowerCanonical checks that c is the canonical request the
// digest names, in canonical form (canonical.Encode of what it parses to,
// byte for byte: no duplicate keys, no other order, no trailing data), and
// reads what it binds.
func parseGuestPowerCanonical(c []byte, digest string) (guestPowerBinding, error) {
	switch {
	case len(c) == 0:
		return guestPowerBinding{}, errGuestPowerCanonical
	case len(c) > maxGuestPowerCanonical:
		return guestPowerBinding{}, errors.New("the executor's bound request is too large to show")
	case !utf8.Valid(c):
		return guestPowerBinding{}, errors.New("the executor's bound request is not valid UTF-8")
	}
	if sum := sha256.Sum256(c); hex.EncodeToString(sum[:]) != digest {
		return guestPowerBinding{}, errors.New("the executor's bound request does not match its digest")
	}
	var rq canonical.Request
	dec := json.NewDecoder(bytes.NewReader(c))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		return guestPowerBinding{}, errGuestPowerCanonical
	}
	if enc, err := canonical.Encode(rq); err != nil || !bytes.Equal(enc, c) {
		return guestPowerBinding{}, errors.New("the executor's bound request is not in canonical form")
	}
	b := guestPowerBinding{
		ActionID: rq.ActionID, Verb: guestPowerArtifacts[rq.ArtifactSHA256], ArtifactSHA256: rq.ArtifactSHA256, Risk: string(rq.RiskClass),
		ParametersHash: rq.ParametersHash, Canonical: string(c),
	}
	if rq.ExpiryUnix > 0 {
		b.Expiry = time.Unix(rq.ExpiryUnix, 0)
	}
	if len(rq.ResolvedTargets) == 1 {
		b.TargetID, b.Fingerprint = rq.ResolvedTargets[0].HostID, rq.ResolvedTargets[0].HostKeyFingerprint
	}
	return b, nil
}

// guestPowerMismatch lists every difference between what the executor
// bound and what was requested; any difference withholds approval.
// The bound target is compared with permit's own risk target of the
// requested guest (host ID and trust-pin fingerprint). The proposal names
// no execution ID (the executor picks it), so there is none to compare.
func guestPowerMismatch(b guestPowerBinding, t *pb.PVEGuestPowerTarget, risk, trustPin string, now time.Time) []string {
	var out []string
	if b.ActionID != guestPowerAction {
		out = append(out, "the executor bound a different action ("+cleanText(b.ActionID)+")")
	}
	switch {
	case b.Verb == "":
		out = append(out, "the executor bound an unknown power verb")
	case b.Verb != t.GetVerb():
		out = append(out, "the executor bound the verb "+b.Verb+", not "+t.GetVerb())
	}
	return append(out, guestTargetMismatch(b, guestRef{remote: t.GetRemoteId(), kind: t.GetKind(), node: t.GetNode(), vmid: t.GetVmid()}, risk, trustPin, now)...)
}

// guestRef is the exact guest a proposal names.
type guestRef struct {
	remote, kind, node string
	vmid               uint64
}

// guestTargetMismatch lists the differences of the bound risk, target and
// expiry from the requested guest; shared by the power and snapshot
// proposals.
func guestTargetMismatch(b guestPowerBinding, t guestRef, risk, trustPin string, now time.Time) []string {
	var out []string
	if b.Risk != risk {
		out = append(out, "the risk in the bound request ("+cleanText(b.Risk)+") differs from the executor's answer ("+risk+")")
	}
	want, err := permit.ProviderMutationTarget{RemoteID: t.remote, TrustPin: trustPin, Kind: t.kind,
		Node: t.node, VMID: t.vmid}.RiskTarget()
	switch {
	case b.TargetID == "":
		out = append(out, "the bound request does not name exactly one target")
	case err != nil:
		out = append(out, "the PVE remote's current trust pin is unknown: the bound target cannot be checked")
	case b.TargetID != want.HostID:
		out = append(out, "the executor bound a different guest ("+cleanText(b.TargetID)+", requested "+want.HostID+")")
	case b.Fingerprint != want.HostKeyFingerprint:
		out = append(out, "the bound target does not belong to the PVE remote's current trust pin")
	}
	switch {
	case b.Expiry.IsZero():
		out = append(out, "the bound request has no expiry")
	case !now.Before(b.Expiry):
		out = append(out, "the bound request has already expired")
	}
	return out
}

// guestPowerProposal is one proposal, visible to its proposer only.
type guestPowerProposal struct {
	user string
	// kind is guestActionPower or guestActionSnapshot; a proposal is shown,
	// approved and run only under the routes of its kind.
	kind string
	// target is the power target (power proposals only).
	target *pb.PVEGuestPowerTarget
	// snap is the snapshot proposal (snapshot proposals only).
	snap *guestSnapshotProposal
	// verb is the power verb, or the snapshot op (guestSnapshotOps).
	verb guestPowerVerb
	// bound is the executor's binding; mismatch lists its differences
	// from the request (approval is withheld when non-empty).
	bound    guestPowerBinding
	mismatch []string
	// uiName and uiGeneration are the UI's own inventory read at
	// proposal time: secondary information, not part of the approval.
	uiName       string
	uiGeneration uint64
	digest       string
	risk         string
	requirement  string // "key", "typed_count" or "cli"
	options      string
	challengeAt  time.Time
	expires      time.Time
	// state is "pending", "approving", "running", "done" (the executor
	// returned the run's steps) or "failed".
	state       string
	message     string
	executionID string
	steps       []guestPowerStepView
}

// Proposal kinds.
const (
	guestActionPower    = "power"
	guestActionSnapshot = "snapshot"
)

// ref is the guest the proposal names.
func (x *guestPowerProposal) ref() guestRef {
	if x.snap != nil {
		t := x.snap.target
		return guestRef{remote: t.GetRemoteId(), kind: t.GetKind(), node: t.GetNode(), vmid: t.GetVmid()}
	}
	t := x.target
	return guestRef{remote: t.GetRemoteId(), kind: t.GetKind(), node: t.GetNode(), vmid: t.GetVmid()}
}

// auditText names the proposal in the audit log.
func (x *guestPowerProposal) auditText() string {
	r := x.ref()
	s := guestPowerKey(r.remote, r.vmid) + " " + x.verb.Verb
	if x.snap != nil {
		s += " " + x.snap.target.GetName()
	}
	return s
}

// guestPowerStepView is one shown step of a run.
type guestPowerStepView struct {
	State, UPID, TaskType string
}

// guestPowerProposals keeps the throttle and the proposals.
type guestPowerProposals struct {
	mu    sync.Mutex
	last  map[string]time.Time
	props map[string]*guestPowerProposal // by digest
}

func newGuestPowerProposals() *guestPowerProposals {
	return &guestPowerProposals{last: map[string]time.Time{}, props: map[string]*guestPowerProposal{}}
}

// allow reports whether user may propose now, and records the attempt.
func (p *guestPowerProposals) allow(user string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.last[user]; ok && now.Sub(t) < guestPowerProposeInterval && !now.Before(t) {
		return false
	}
	if _, ok := p.last[user]; !ok && len(p.last) >= maxGuestPowerThrottleUsers {
		for u, t := range p.last {
			if now.Sub(t) >= guestPowerProposeInterval || now.Before(t) {
				delete(p.last, u)
			}
		}
		if len(p.last) >= maxGuestPowerThrottleUsers {
			return false
		}
	}
	p.last[user] = now
	return true
}

// Refusals of put.
var (
	// errGuestPowerUserCap: the user has maxGuestPowerProposalsPerUser
	// open proposals.
	errGuestPowerUserCap = errors.New("too many open power proposals of this user")
	// errGuestPowerFull: the table is full of open proposals.
	errGuestPowerFull = errors.New("too many power actions in progress")
	// errGuestPowerDigest: the digest is held by another user's proposal
	// or by a running one.
	errGuestPowerDigest = errors.New("the executor returned a digest already in use")
)

// approvable reports whether the proposal may be offered for approval or
// run: its binding matches the request and has not expired.
func (x *guestPowerProposal) approvable(now time.Time) bool {
	return len(x.mismatch) == 0 && now.Before(x.bound.Expiry)
}

// open reports whether a proposal still counts against its user's cap.
func (x *guestPowerProposal) open() bool {
	return x.state == "pending" || x.state == "approving" || x.state == "running"
}

// put stores a proposal, dropping expired ones and, when full, the
// settled one (done or failed) that expires first, else the proposer's own
// pending one that expires first. It never drops a running commit or
// another user's proposal of the same digest or a pending one, so one user
// cannot evict or take over the proposals others are about to approve;
// each user has at most maxGuestPowerProposalsPerUser open ones.
func (p *guestPowerProposals) put(x *guestPowerProposal, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for d, y := range p.props {
		if !now.Before(y.expires) && y.state != "running" && y.state != "approving" {
			delete(p.props, d)
		}
	}
	old, replaced := p.props[x.digest]
	if replaced && (old.user != x.user || old.state == "running" || old.state == "approving") {
		return errGuestPowerDigest
	}
	n := 0
	for d, y := range p.props {
		if y.user == x.user && y.open() && d != x.digest {
			n++
		}
	}
	if n >= maxGuestPowerProposalsPerUser {
		return errGuestPowerUserCap
	}
	if !replaced && len(p.props) >= maxGuestPowerProposals {
		oldest := func(ok func(*guestPowerProposal) bool) string {
			var d string
			for k, y := range p.props {
				if ok(y) && (d == "" || y.expires.Before(p.props[d].expires)) {
					d = k
				}
			}
			return d
		}
		d := oldest(func(y *guestPowerProposal) bool { return y.state == "done" || y.state == "failed" })
		if d == "" {
			d = oldest(func(y *guestPowerProposal) bool { return y.state == "pending" && y.user == x.user })
		}
		if d == "" {
			return errGuestPowerFull
		}
		delete(p.props, d)
	}
	p.props[x.digest] = x
	return nil
}

// get returns a copy of user's proposal with this digest.
func (p *guestPowerProposals) get(user, digest string, now time.Time) (guestPowerProposal, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.props[digest]
	if !ok || x.user != user {
		return guestPowerProposal{}, false
	}
	if !now.Before(x.expires) && x.state != "running" && x.state != "approving" {
		return guestPowerProposal{}, false
	}
	c := *x
	c.steps = append([]guestPowerStepView(nil), x.steps...)
	return c, true
}

// transition moves user's unexpired proposal from one state to another
// and returns a copy; false when it is not in state from.
func (p *guestPowerProposals) transition(user, digest, from, to string, now time.Time) (guestPowerProposal, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.props[digest]
	if !ok || x.user != user || x.state != from || (from == "pending" && !now.Before(x.expires)) {
		return guestPowerProposal{}, false
	}
	x.state = to
	if to == "running" {
		x.message = ""
	}
	return *x, true
}

// setResult records the outcome of a run or an approval refusal.
func (p *guestPowerProposals) setResult(digest, state, message, executionID string, steps []guestPowerStepView, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.props[digest]
	if !ok {
		return
	}
	x.state, x.message, x.executionID, x.steps = state, message, executionID, steps
	if state != "pending" {
		// Keep a finished run visible for a while after it ends.
		x.expires = now.Add(guestPowerProposalTTL)
	}
}

// guestPowerDigestRe is the executor's digest form.
var guestPowerDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// guestActionData is the data of the proposal page. The headline is the
// executor's binding (Bound, with the requested target it was checked
// against); UIName and UIGeneration are the UI's own inventory read.
type guestActionData struct {
	Remote, Node, KindLabel string
	VMID                    uint64
	Verb                    guestPowerVerb
	Bound                   guestPowerBinding
	Mismatch                []string
	Expired                 bool // the binding expired (no mismatch)
	UIName                  string
	UIGeneration            uint64
	Digest, Risk, RiskClass string
	ChallengeExpiry         time.Time
	// Approval: Options for the security key button, or CLICommand
	// (hardened mode, or a typed count the button cannot send).
	Options    string
	CLICommand string
	TypedCount bool
	// Run state.
	State       string
	Message     string
	ExecutionID string
	Steps       []guestPowerStepView
	// Snapshot is the snapshot the action names (snapshot proposals only).
	Snapshot *guestSnapshotShown
	// CommitURL and RunURL are the approval endpoints of the proposal's
	// kind; BackURL is where the operator proposes again.
	CommitURL, RunURL, BackURL string
}

// guestActionPathSet are the routes of one proposal kind.
type guestActionPathSet struct {
	page, commit, run, back string
}

// guestActionPaths are the routes per proposal kind (page is followed by
// the digest).
var guestActionPaths = map[string]guestActionPathSet{
	guestActionPower: {page: "/pve/guests/power/", commit: "/pve/guests/power/commit",
		run: "/pve/guests/power/run", back: "/inventory/chart"},
	guestActionSnapshot: {page: "/pve/guests/snapshots/proposals/", commit: "/pve/guests/snapshots/commit",
		run: "/pve/guests/snapshots/run"}, // back: the guest's snapshot page
}

// riskBadgeClass is the badge class of a risk text.
func riskBadgeClass(risk string) string {
	switch risk {
	case "LOW":
		return "badge--ok"
	case "MEDIUM":
		return "badge--warning"
	case "HIGH", "CRITICAL":
		return "badge--critical"
	default:
		return "badge--unknown"
	}
}

// cleanText caps executor text and drops it if it is not UTF-8.
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	if len(s) > maxGuestPowerText {
		s = s[:maxGuestPowerText]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// validFormField checks one bounded UTF-8 form value.
func validFormField(s string) bool {
	return s != "" && len(s) <= maxGuestPowerField && utf8.ValidString(s)
}

func (h *Handler) guestPowerEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.guestPower == nil || h.pve == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// handleGuestPowerPropose proposes one power action on the exact guest the
// chart showed, and redirects to the proposal page. Errors are plain text:
// formpost.js shows them with textContent.
func (h *Handler) handleGuestPowerPropose(w http.ResponseWriter, r *http.Request) {
	if !h.guestPowerEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	remote, node, kind, verbName := f.Get("remote"), f.Get("node"), f.Get("kind"), f.Get("verb")
	if !validFormField(remote) || !validFormField(node) || !validFormField(kind) || !validFormField(verbName) {
		http.Error(w, "the form names no valid guest", http.StatusBadRequest)
		return
	}
	vmid, err := strconv.ParseUint(f.Get("vmid"), 10, 64)
	if err != nil || vmid == 0 {
		http.Error(w, "invalid VMID", http.StatusBadRequest)
		return
	}
	generation, err := strconv.ParseUint(f.Get("generation"), 10, 64)
	if err != nil {
		http.Error(w, "invalid guest generation", http.StatusBadRequest)
		return
	}
	if kind != guestKindQEMU && kind != guestKindLXC {
		http.Error(w, "unknown guest kind", http.StatusBadRequest)
		return
	}
	verb, ok := lookupGuestPowerVerb(verbName, kind)
	if !ok {
		http.Error(w, "this power action is not available for a "+guestKindLabel(kind), http.StatusBadRequest)
		return
	}
	// Throttle before any store read, so repeated proposals cause no
	// unthrottled work.
	user := webUser(r)
	now := h.clockNow()
	if !h.guestPowerProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(guestPowerProposeInterval/time.Second)))
		http.Error(w, "too many power proposals: wait a moment and try again", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	meta := h.pveMeta(ctx)
	if !remoteAllowsMutations(meta, remote) {
		http.Error(w, "the PVE remote is not active: no power actions", http.StatusConflict)
		return
	}
	guests, err := h.pve.ListGuests(ctx, remote, pveinventory.GuestFilter{VMID: vmid}, 0)
	if err != nil {
		h.log.Error("guest power: read stored guest", "remote", remote, "vmid", vmid, "error", err)
		http.Error(w, "the stored guest could not be read", http.StatusInternalServerError)
		return
	}
	var g *pveinventory.Guest
	for i := range guests {
		if guests[i].VMID == vmid && !guests[i].Tombstoned {
			g = &guests[i]
			break
		}
	}
	switch {
	case g == nil:
		http.Error(w, "guest not found", http.StatusNotFound)
		return
	case g.Generation != generation || g.Node != node || g.Kind != kind:
		http.Error(w, "the guest changed since the chart was loaded (re-created, migrated or a different kind): reload the chart", http.StatusConflict)
		return
	case g.State != pveinventory.StateAvailable || g.Status != "running":
		http.Error(w, "the guest is not running: no power action", http.StatusConflict)
		return
	}
	target := &pb.PVEGuestPowerTarget{RemoteId: remote, Kind: kind, Node: node, Vmid: vmid, Verb: verb.Verb}
	resp, err := h.guestPower.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target})
	if err != nil {
		h.guestPowerRefusal(w, "propose guest power", err)
		return
	}
	p := &guestPowerProposal{user: user, kind: guestActionPower, target: target, verb: verb, uiName: g.Name, uiGeneration: g.Generation}
	mismatch := func(b guestPowerBinding, risk string) []string {
		return guestPowerMismatch(b, target, risk, meta[remote].TrustPin, now)
	}
	h.storeGuestProposal(w, r, p, resp.GetPermit(), mismatch, now)
}

// storeGuestProposal completes p from the executor's permit (digest, risk,
// the bound canonical request and its differences from the request, the
// approval requirement), stores it and redirects to its page; it answers a
// plain-text error instead when the permit is unusable or the table refuses
// it.
func (h *Handler) storeGuestProposal(w http.ResponseWriter, r *http.Request, p *guestPowerProposal, perm *pb.ProposeExecutionResponse,
	mismatch func(b guestPowerBinding, risk string) []string, now time.Time) {
	ref := p.ref()
	digest := perm.GetExecutionDigest()
	risk := strings.TrimPrefix(perm.GetRiskClass().String(), "RISK_CLASS_")
	if !guestPowerDigestRe.MatchString(digest) || perm.GetRiskClass() == pb.RiskClass_RISK_CLASS_UNSPECIFIED || strings.HasPrefix(risk, "RISK") {
		http.Error(w, "the executor returned no usable proposal", http.StatusBadGateway)
		return
	}
	// The operator approves what the executor bound: a canonical request
	// that cannot be shown in full refuses the proposal.
	bound, err := parseGuestPowerCanonical(perm.GetCanonicalRequest(), digest)
	if err != nil {
		h.log.Error("guest "+p.kind+": unusable canonical request", "remote", ref.remote, "vmid", ref.vmid, "error", err)
		http.Error(w, err.Error()+": the proposal is refused, nothing can be approved", http.StatusBadGateway)
		return
	}
	if p.kind == guestActionSnapshot {
		bound.Verb = guestSnapshotArtifacts[bound.ArtifactSHA256]
	}
	p.bound, p.mismatch = bound, mismatch(bound, risk)
	p.digest, p.risk, p.requirement = digest, risk, requirementText(perm.GetApprovalRequirement())
	p.state, p.expires = "pending", now.Add(guestPowerProposalTTL)
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		p.options = string(opts)
	}
	if e := perm.GetChallengeExpiryUnix(); e > 0 {
		p.challengeAt = time.Unix(e, 0)
	}
	if p.requirement == "key" && p.options == "" && len(p.mismatch) == 0 {
		http.Error(w, "the executor returned no approval challenge", http.StatusBadGateway)
		return
	}
	switch err := h.guestPowerProposals.put(p, now); {
	case errors.Is(err, errGuestPowerUserCap):
		http.Error(w, "too many open "+p.kind+" proposals: approve or wait for earlier ones to expire, then try again", http.StatusTooManyRequests)
		return
	case errors.Is(err, errGuestPowerDigest):
		h.log.Error("guest "+p.kind+": executor digest already in use", "remote", ref.remote, "vmid", ref.vmid)
		http.Error(w, "the executor returned a digest already in use: the proposal is refused", http.StatusBadGateway)
		return
	case err != nil:
		http.Error(w, "too many "+p.kind+" actions in progress", http.StatusServiceUnavailable)
		return
	}
	if len(p.mismatch) > 0 {
		h.log.Error("guest "+p.kind+": executor binding differs from the request", "remote", ref.remote, "vmid", ref.vmid, "mismatch", strings.Join(p.mismatch, "; "))
	}
	h.audit(r, "guest_"+p.kind+"_proposed", p.auditText())
	http.Redirect(w, r, guestActionPaths[p.kind].page+digest, http.StatusSeeOther)
}

// guestPowerRefusal answers an executor error as plain text: the
// executor's fixed refusal text for refusals, a generic text otherwise.
func (h *Handler) guestPowerRefusal(w http.ResponseWriter, op string, err error) {
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted,
		codes.AlreadyExists, codes.NotFound, codes.Aborted:
		http.Error(w, "the executor refused: "+cleanText(st.Message()), http.StatusConflict)
	default:
		h.log.Error(op, "error", err)
		http.Error(w, "executor unavailable", http.StatusBadGateway)
	}
}

// guestActionEnabled reports whether the actions of kind are wired, and
// answers 404 when not.
func (h *Handler) guestActionEnabled(w http.ResponseWriter, r *http.Request, kind string) bool {
	if kind == guestActionSnapshot {
		return h.guestSnapshotEnabled(w, r)
	}
	return h.guestPowerEnabled(w, r)
}

// getGuestProposal returns user's proposal of kind with this digest.
func (h *Handler) getGuestProposal(user, digest, kind string, now time.Time) (guestPowerProposal, bool) {
	if !guestPowerDigestRe.MatchString(digest) {
		return guestPowerProposal{}, false
	}
	p, ok := h.guestPowerProposals.get(user, digest, now)
	if !ok || p.kind != kind {
		return guestPowerProposal{}, false
	}
	return p, true
}

// handleGuestPowerProposal shows a power proposal to its proposer.
func (h *Handler) handleGuestPowerProposal(w http.ResponseWriter, r *http.Request) {
	h.showGuestProposal(w, r, guestActionPower)
}

// showGuestProposal shows a proposal of kind to its proposer.
func (h *Handler) showGuestProposal(w http.ResponseWriter, r *http.Request, kind string) {
	if !h.guestActionEnabled(w, r, kind) {
		return
	}
	p, ok := h.getGuestProposal(webUser(r), r.PathValue("digest"), kind, h.clockNow())
	if !ok {
		http.NotFound(w, r)
		return
	}
	t := p.ref()
	paths := guestActionPaths[kind]
	d := &guestActionData{
		Remote: t.remote, Node: t.node, KindLabel: guestKindLabel(t.kind),
		VMID: t.vmid, Verb: p.verb, Bound: p.bound, Mismatch: p.mismatch,
		UIName: p.uiName, UIGeneration: p.uiGeneration,
		Digest: p.digest, Risk: p.bound.Risk, RiskClass: riskBadgeClass(p.bound.Risk),
		ChallengeExpiry: p.challengeAt, State: p.state, Message: p.message, ExecutionID: p.executionID, Steps: p.steps,
		CommitURL: paths.commit, RunURL: paths.run, BackURL: paths.back,
	}
	title := "Guest power: " + p.verb.Verb
	if p.snap != nil {
		d.Snapshot = p.snap.shown()
		d.BackURL = guestSnapshotsURL(t.remote, t.vmid)
		title = "Guest snapshot: " + p.verb.Verb
	}
	data := pageData{Title: title, Active: "pve", Content: "guest_action", GuestAction: d}
	now := h.clockNow()
	d.Expired = len(p.mismatch) == 0 && !now.Before(p.bound.Expiry)
	if p.state == "pending" && p.approvable(now) {
		if p.requirement == "key" {
			d.Options = p.options
			data.Scripts = []string{"webauthn.js", "schedules.js"}
		} else {
			d.CLICommand = guestPowerCLICommand + p.digest
			d.TypedCount = p.requirement == "typed_count"
			data.Scripts = []string{"formpost.js"}
		}
	}
	h.render(w, r, data)
}

// handleGuestPowerCommit relays the security key assertion for a pending
// proposal of this user (the schedule approval button posts here) and
// starts the run.
func (h *Handler) handleGuestPowerCommit(w http.ResponseWriter, r *http.Request) {
	h.commitGuestProposal(w, r, guestActionPower)
}

// commitGuestProposal relays the assertion for a pending proposal of kind.
func (h *Handler) commitGuestProposal(w http.ResponseWriter, r *http.Request, kind string) {
	if !h.guestActionEnabled(w, r, kind) {
		return
	}
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	user := webUser(r)
	now := h.clockNow()
	notFound := kind + " proposal not found"
	cur, ok := h.getGuestProposal(user, in.ID, kind, now)
	if !ok || cur.requirement != "key" || !cur.approvable(now) || len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusNotFound, notFound)
		return
	}
	p, ok := h.guestPowerProposals.transition(user, in.ID, "pending", "approving", now)
	if !ok {
		writeJSONError(w, http.StatusNotFound, notFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	submit := func(ctx context.Context, in *pb.SubmitAssertionRequest) (*pb.SubmitAssertionResponse, error) {
		if kind == guestActionSnapshot {
			return h.guestSnapshot.SubmitAssertion(ctx, in)
		}
		return h.guestPower.SubmitAssertion(ctx, in)
	}
	if _, err := submit(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: p.digest, AssertionJson: in.Assertion}); err != nil {
		h.guestPowerProposals.setResult(p.digest, "pending", "", "", nil, now)
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			writeJSONError(w, http.StatusForbidden, "security key not accepted")
		case codes.InvalidArgument, codes.FailedPrecondition, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound, codes.Aborted:
			writeJSONError(w, http.StatusConflict, "the executor refused: "+cleanText(status.Convert(err).Message()))
		default:
			h.log.Error("approve guest "+kind, "error", err)
			writeJSONError(w, http.StatusBadGateway, "executor unavailable")
		}
		return
	}
	if _, ok := h.guestPowerProposals.transition(user, p.digest, "approving", "running", now); !ok {
		writeJSONError(w, http.StatusConflict, kind+" proposal changed")
		return
	}
	h.audit(r, "guest_"+kind+"_approved", p.auditText())
	h.startGuestPowerCommit(r, p)
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// handleGuestPowerRun runs a proposal approved with `nebula approve`
// (hardened mode, or a typed count). The executor refuses a permit that is
// not approved.
func (h *Handler) handleGuestPowerRun(w http.ResponseWriter, r *http.Request) {
	h.runGuestProposal(w, r, guestActionPower)
}

// runGuestProposal runs a CLI-approved proposal of kind.
func (h *Handler) runGuestProposal(w http.ResponseWriter, r *http.Request, kind string) {
	if !h.guestActionEnabled(w, r, kind) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	digest := r.PostForm.Get("digest")
	user := webUser(r)
	now := h.clockNow()
	cur, ok := h.getGuestProposal(user, digest, kind, now)
	if !ok || cur.requirement == "key" || !cur.approvable(now) {
		http.NotFound(w, r)
		return
	}
	p, ok := h.guestPowerProposals.transition(user, digest, "pending", "running", now)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.audit(r, "guest_"+kind+"_run", p.auditText())
	h.startGuestPowerCommit(r, p)
	http.Redirect(w, r, guestActionPaths[kind].page+digest, http.StatusSeeOther)
}

// startGuestPowerCommit commits the approved proposal in the background:
// the executor waits for the PVE task, longer than a request may take.
// A refusal before anything ran (the permit is not approved, the guest
// state changed) puts a CLI proposal back to pending with the reason.
func (h *Handler) startGuestPowerCommit(r *http.Request, p guestPowerProposal) {
	ctx := context.WithoutCancel(r.Context())
	commit := func(ctx context.Context) (string, []*pb.PVEGuestPowerStep, error) {
		resp, err := h.guestPower.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: p.target, ExecutionDigest: p.digest})
		return resp.GetExecutionId(), resp.GetSteps(), err
	}
	if p.snap != nil {
		// The same target that was proposed, with the exact snapshot the
		// executor bound (delete and rollback).
		commit = func(ctx context.Context) (string, []*pb.PVEGuestPowerStep, error) {
			resp, err := h.guestSnapshot.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{Target: p.snap.target, ExecutionDigest: p.digest})
			return resp.GetExecutionId(), resp.GetSteps(), err
		}
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, guestPowerCommitTimeout)
		defer cancel()
		executionID, respSteps, err := commit(ctx)
		now := h.clockNow()
		if err != nil {
			st, _ := status.FromError(err)
			switch st.Code() {
			// Unavailable is a transport error (its text names addresses):
			// shown generically like any other non-refusal.
			case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound, codes.Aborted:
				state := "failed"
				if p.requirement != "key" && (st.Code() == codes.PermissionDenied || st.Code() == codes.FailedPrecondition) {
					state = "pending" // approve with the CLI, then run again
				}
				h.guestPowerProposals.setResult(p.digest, state, "the executor refused: "+cleanText(st.Message()), "", nil, now)
			default:
				h.log.Error("commit guest "+p.kind, "error", err)
				h.guestPowerProposals.setResult(p.digest, "failed", "the run could not be confirmed (executor unavailable); check the executor's job list before trying again", "", nil, now)
			}
			return
		}
		var steps []guestPowerStepView
		for i, s := range respSteps {
			if i >= maxGuestPowerSteps {
				break
			}
			steps = append(steps, guestPowerStepView{State: cleanText(s.GetState()), UPID: cleanText(s.GetUpid()), TaskType: cleanText(s.GetTaskType())})
		}
		h.guestPowerProposals.setResult(p.digest, "done", "", cleanText(executionID), steps, now)
	}()
}

// Guest snapshots (ADR 0006 P2-01, UI of the px02 snapshot profile). GET
// /pve/guests/snapshots?remote=&vmid= lists one guest's stored snapshots
// (name, time, parent, RAM flag; the 5-minute read) with a create form
// (name, RAM for a running QEMU VM) and, per snapshot, Delete and Roll
// back. Every form binds the exact guest (remote, VMID, generation, node,
// kind); Delete and Roll back also bind the exact snapshot identity (name,
// time, parent, RAM flag), and Roll back needs an explicit start choice
// (no default). There is no bulk, pattern or age-based delete: one form
// names one snapshot. POST /pve/guests/snapshots/propose validates the
// name and the identity, re-reads the stored guest and snapshot, and asks
// the executor for a proposal with the identity as expect; the proposal
// page (guest_action.html) shows the snapshot the executor bound and its
// risk. Approval and the background commit are the power controls' own.
//
// The executor's snapshot target has no description field, so the create
// form offers none.

// GuestSnapshot proposes, approves and runs typed guest snapshot actions on
// the executor (px02). executorclient.Client satisfies it.
type GuestSnapshot interface {
	ProposePVEGuestSnapshot(ctx context.Context, in *pb.ProposePVEGuestSnapshotRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestSnapshotResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
	CommitPVEGuestSnapshot(ctx context.Context, in *pb.CommitPVEGuestSnapshotRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestSnapshotResponse, error)
}

// PVESnapshotStore is the snapshot read of the PVE store the snapshot page
// uses; Options.PVE must implement it for the page to exist.
// pveinventory.Store satisfies it.
type PVESnapshotStore interface {
	ListSnapshots(ctx context.Context, remoteID string, vmid, generation uint64, limit int) ([]pveinventory.Snapshot, error)
}

// Limits and fixed values of the snapshot page.
const (
	// guestSnapshotAction is the executor's action ID of the snapshot
	// actions.
	guestSnapshotAction = "pve.guest.snapshot"
	// maxGuestSnapshotName is the longest snapshot name (PVE rule, as the
	// executor enforces it).
	maxGuestSnapshotName = 40
	// guestSnapshotNamePattern is the name rule for the browser's pattern
	// attribute (implicitly anchored); validGuestSnapshotName is the
	// server's copy.
	guestSnapshotNamePattern = `(?!current$)[A-Za-z][A-Za-z0-9_\-]{0,39}`
	// maxGuestSnapshotParent is the longest parent name a delete or
	// rollback form may carry (the executor's bound).
	maxGuestSnapshotParent = 255
	// guestSnapshotListLimit bounds the snapshots read for one page.
	guestSnapshotListLimit = pveinventory.MaxSnapshotsQuery
)

// Snapshot ops.
const (
	guestSnapshotCreate   = "create"
	guestSnapshotDelete   = "delete"
	guestSnapshotRollback = "rollback"
)

// guestSnapshotNameRe is the snapshot name rule: a letter, then letters,
// digits, '_' or '-', at most maxGuestSnapshotName.
var guestSnapshotNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`)

// validGuestSnapshotName reports whether name may be created or addressed:
// the PVE rule, and never "current" (PVE's pointer to the running state).
func validGuestSnapshotName(name string) bool {
	return name != "current" && len(name) <= maxGuestSnapshotName && guestSnapshotNameRe.MatchString(name)
}

// guestSnapshotOps describe the ops; the label names the base risk, the
// executor decides the real one.
var guestSnapshotOps = map[string]guestPowerVerb{
	guestSnapshotCreate: {Verb: guestSnapshotCreate, Label: "Create snapshot (MEDIUM)",
		Explain: "creates one snapshot with exactly this name of every disk of the guest"},
	guestSnapshotDelete: {Verb: guestSnapshotDelete, Label: "Delete — HIGH", Destructive: true,
		Explain: "deletes exactly this one snapshot; it cannot be restored afterwards"},
	guestSnapshotRollback: {Verb: guestSnapshotRollback, Label: "Roll back — HIGH", Destructive: true,
		Explain: "rolls the guest back to exactly this snapshot: everything written since it was taken is lost, and a running guest is stopped"},
}

// guestSnapshotArtifacts maps the SHA-256 (hex) of each op's fixed executor
// artifact to the op. The texts must equal the executor's
// (internal/executor, pveSnapshotArtifact, module version 1.0.0); an
// artifact this table does not know is shown as a mismatch, never
// approved.
var guestSnapshotArtifacts = func() map[string]string {
	texts := map[string]string{
		guestSnapshotCreate:   "Create one snapshot with the exact name and RAM choice of the exact guest; every disk on verified snapshot-capable storage.",
		guestSnapshotDelete:   "Delete the one exact snapshot (name, time and parent) of the exact guest; never by age, pattern or in bulk; no force.",
		guestSnapshotRollback: "Roll the exact guest back to the one exact snapshot (destructive: state since the snapshot is lost); explicit start flag and RAM side effect.",
	}
	out := make(map[string]string, len(texts))
	for op, text := range texts {
		sum := sha256.Sum256([]byte(guestSnapshotAction + " 1.0.0\nop: " + op + "\n" + text + "\n"))
		out[hex.EncodeToString(sum[:])] = op
	}
	return out
}()

// guestSnapshotProposal is the snapshot part of a proposal.
type guestSnapshotProposal struct {
	// target is what was proposed and is committed (with expect for delete
	// and rollback).
	target *pb.PVEGuestSnapshotTarget
	// bound is the snapshot the executor bound (delete and rollback), and
	// runsAfter its rollback side effect; checked against target.
	bound     *pb.PVESnapshotIdentity
	runsAfter bool
}

// guestSnapshotShown is the snapshot section of the proposal page.
type guestSnapshotShown struct {
	Op   string
	Name string
	// HasIdentity: delete and rollback name an existing snapshot (Time,
	// Parent, RAM, as the executor bound it).
	HasIdentity bool
	Time        time.Time
	Parent      string
	RAM         bool
	// IncludeRAM is a create's RAM choice.
	IncludeRAM bool
	// Start is a rollback's explicit start choice; RunsAfter what the
	// executor bound as the result.
	Start     bool
	RunsAfter bool
}

// shown is the snapshot section of the proposal page: the executor's bound
// snapshot when there is one (any difference from the request is listed
// as a mismatch), else the requested one.
func (s *guestSnapshotProposal) shown() *guestSnapshotShown {
	t := s.target
	v := &guestSnapshotShown{Op: t.GetOp(), Name: t.GetName(), IncludeRAM: t.GetVmstate(), Start: t.GetStart(), RunsAfter: s.runsAfter}
	id := t.GetExpect()
	if s.bound != nil {
		id = s.bound
	}
	if t.GetOp() != guestSnapshotCreate && id != nil {
		v.HasIdentity = true
		v.Name, v.Parent, v.RAM = cleanText(id.GetName()), cleanText(id.GetParent()), id.GetVmstate()
		v.Time = time.Unix(id.GetSnaptimeUnix(), 0)
	}
	return v
}

// sameSnapshotIdentity reports whether a and b name the same snapshot.
func sameSnapshotIdentity(a, b *pb.PVESnapshotIdentity) bool {
	return a.GetName() == b.GetName() && a.GetSnaptimeUnix() == b.GetSnaptimeUnix() &&
		a.GetParent() == b.GetParent() && a.GetVmstate() == b.GetVmstate()
}

// guestSnapshotMismatch lists every difference between what the executor
// bound (canonical request, bound snapshot, rollback side effect) and what
// was requested; any difference withholds approval.
func guestSnapshotMismatch(b guestPowerBinding, s *guestSnapshotProposal, risk, trustPin string, now time.Time) []string {
	t := s.target
	var out []string
	if b.ActionID != guestSnapshotAction {
		out = append(out, "the executor bound a different action ("+cleanText(b.ActionID)+")")
	}
	switch op := guestSnapshotArtifacts[b.ArtifactSHA256]; {
	case op == "":
		out = append(out, "the executor bound an unknown snapshot operation")
	case op != t.GetOp():
		out = append(out, "the executor bound the operation "+op+", not "+t.GetOp())
	}
	switch {
	case t.GetOp() == guestSnapshotCreate && s.bound != nil:
		out = append(out, "the executor bound an existing snapshot for a create")
	case t.GetOp() != guestSnapshotCreate && s.bound == nil:
		out = append(out, "the executor did not name the snapshot it bound")
	case t.GetOp() != guestSnapshotCreate && !sameSnapshotIdentity(s.bound, t.GetExpect()):
		out = append(out, "the executor bound a different snapshot (name, time, parent or RAM flag) than the one shown")
	}
	wantRuns := t.GetOp() == guestSnapshotRollback && (t.GetStart() || t.GetExpect().GetVmstate())
	if s.runsAfter != wantRuns {
		out = append(out, "the executor bound a different power state after the rollback than the start choice and RAM flag give")
	}
	return append(out, guestTargetMismatch(b, guestRef{remote: t.GetRemoteId(), kind: t.GetKind(), node: t.GetNode(), vmid: t.GetVmid()}, risk, trustPin, now)...)
}

// guestSnapshotsURL is the snapshot page of one guest.
func guestSnapshotsURL(remote string, vmid uint64) string {
	return "/pve/guests/snapshots?" + url.Values{"remote": {remote}, "vmid": {strconv.FormatUint(vmid, 10)}}.Encode()
}

// guestSnapshotsData is the data of the snapshot page.
type guestSnapshotsData struct {
	Remote, Node, Kind, KindLabel string
	VMID, Generation              uint64
	// Name and Status are the stored guest's (untrusted, shown as text).
	Name, Status string
	// Actions shows the forms; Note says why there are none.
	Actions bool
	Note    string
	// RAMOption offers "include RAM" (QEMU only); RAMNote says why a QEMU
	// VM has none.
	RAMOption bool
	RAMNote   string
	// SnapshotNote says why delete and rollback are not offered.
	SnapshotNote string
	NamePattern  string
	NameMax      int
	Snapshots    []guestSnapshotRow
}

// guestSnapshotRow is one stored snapshot.
type guestSnapshotRow struct {
	Name, Parent string
	Time         time.Time
	TimeUnix     int64
	RAM          bool
	// Actionable: delete and rollback are offered (the name is a valid
	// snapshot name and the stored list is current).
	Actionable bool
}

func (h *Handler) guestSnapshotEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.guestSnapshot == nil || h.pve == nil {
		http.NotFound(w, r)
		return false
	}
	if _, ok := h.pve.(PVESnapshotStore); !ok {
		http.NotFound(w, r)
		return false
	}
	return true
}

// storedGuest returns the stored, not tombstoned guest vmid of remote, or
// nil.
func (h *Handler) storedGuest(ctx context.Context, remote string, vmid uint64) (*pveinventory.Guest, error) {
	guests, err := h.pve.ListGuests(ctx, remote, pveinventory.GuestFilter{VMID: vmid}, 0)
	if err != nil {
		return nil, err
	}
	for i := range guests {
		if guests[i].VMID == vmid && !guests[i].Tombstoned {
			return &guests[i], nil
		}
	}
	return nil, nil
}

// handleGuestSnapshots shows one guest's stored snapshots with the create,
// delete and rollback forms.
func (h *Handler) handleGuestSnapshots(w http.ResponseWriter, r *http.Request) {
	if !h.guestSnapshotEnabled(w, r) {
		return
	}
	q := r.URL.Query()
	remote := q.Get("remote")
	vmid, err := strconv.ParseUint(q.Get("vmid"), 10, 64)
	if !validFormField(remote) || err != nil || vmid == 0 {
		http.Error(w, "invalid guest", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	g, err := h.storedGuest(ctx, remote, vmid)
	if err != nil {
		h.log.Error("guest snapshots: read stored guest", "remote", remote, "vmid", vmid, "error", err)
		http.Error(w, "the stored guest could not be read", http.StatusInternalServerError)
		return
	}
	if g == nil || (g.Kind != guestKindQEMU && g.Kind != guestKindLXC) {
		http.NotFound(w, r)
		return
	}
	snaps, err := h.pve.(PVESnapshotStore).ListSnapshots(ctx, remote, vmid, g.Generation, guestSnapshotListLimit)
	if err != nil {
		h.log.Error("guest snapshots: read stored snapshots", "remote", remote, "vmid", vmid, "error", err)
		http.Error(w, "the stored snapshots could not be read", http.StatusInternalServerError)
		return
	}
	d := &guestSnapshotsData{
		Remote: remote, Node: g.Node, Kind: g.Kind, KindLabel: guestKindLabel(g.Kind), VMID: vmid, Generation: g.Generation,
		Name: g.Name, Status: g.Status, NamePattern: guestSnapshotNamePattern, NameMax: maxGuestSnapshotName,
	}
	switch {
	case !remoteAllowsMutations(h.pveMeta(ctx), remote):
		d.Note = "no snapshot actions: the PVE remote is not active"
	case g.State != pveinventory.StateAvailable:
		d.Note = "no snapshot actions: the guest status is not current"
	default:
		d.Actions = true
	}
	switch {
	case g.Kind != guestKindQEMU:
	case g.Status != "running":
		d.RAMNote = "RAM can only be included for a running VM"
	default:
		d.RAMOption = true
	}
	current := true
	for _, s := range snaps {
		if s.State != pveinventory.StateAvailable {
			current = false
		}
	}
	if !current {
		d.SnapshotNote = "the stored snapshot list is not current: delete and roll back are not offered until the next read"
	}
	for _, s := range snaps {
		row := guestSnapshotRow{Name: s.Name, Parent: s.Parent, TimeUnix: s.TimeUnix, RAM: s.HasRAM,
			Actionable: current && validGuestSnapshotName(s.Name) && s.TimeUnix >= 0 &&
				len(s.Parent) <= maxGuestSnapshotParent && utf8.ValidString(s.Parent)}
		if s.TimeUnix > 0 {
			row.Time = time.Unix(s.TimeUnix, 0)
		}
		d.Snapshots = append(d.Snapshots, row)
	}
	data := pageData{Title: "Snapshots: VMID " + strconv.FormatUint(vmid, 10), Active: "pve", Content: "guest_snapshots", GuestSnapshots: d}
	if d.Actions {
		data.Scripts = []string{"formpost.js"}
	}
	h.render(w, r, data)
}

// guestSnapshotForm is a validated snapshot form.
type guestSnapshotForm struct {
	target     *pb.PVEGuestSnapshotTarget
	generation uint64
}

// parseGuestSnapshotForm validates a snapshot form without I/O; the error
// text is shown to the operator.
func parseGuestSnapshotForm(f url.Values) (guestSnapshotForm, string) {
	remote, node, kind, op := f.Get("remote"), f.Get("node"), f.Get("kind"), f.Get("op")
	if !validFormField(remote) || !validFormField(node) || !validFormField(kind) || !validFormField(op) {
		return guestSnapshotForm{}, "the form names no valid guest"
	}
	vmid, err := strconv.ParseUint(f.Get("vmid"), 10, 64)
	if err != nil || vmid == 0 {
		return guestSnapshotForm{}, "invalid VMID"
	}
	generation, err := strconv.ParseUint(f.Get("generation"), 10, 64)
	if err != nil {
		return guestSnapshotForm{}, "invalid guest generation"
	}
	if kind != guestKindQEMU && kind != guestKindLXC {
		return guestSnapshotForm{}, "unknown guest kind"
	}
	if _, ok := guestSnapshotOps[op]; !ok {
		return guestSnapshotForm{}, "unknown snapshot operation"
	}
	name := f.Get("name")
	if !validGuestSnapshotName(name) {
		return guestSnapshotForm{}, "invalid snapshot name: it must start with a letter, contain only letters, digits, '_' and '-', be at most 40 characters long and not be \"current\""
	}
	ram := f.Get("vmstate")
	if ram != "" && ram != "1" {
		return guestSnapshotForm{}, "invalid RAM choice"
	}
	if ram == "1" && kind != guestKindQEMU {
		return guestSnapshotForm{}, "RAM snapshots exist only for a QEMU VM"
	}
	t := &pb.PVEGuestSnapshotTarget{RemoteId: remote, Kind: kind, Node: node, Vmid: vmid, Op: op, Name: name}
	if op == guestSnapshotCreate {
		if f.Has("start") || f.Has("snaptime") || f.Has("parent") {
			return guestSnapshotForm{}, "a create names no existing snapshot and has no start choice"
		}
		t.Vmstate = ram == "1"
		return guestSnapshotForm{target: t, generation: generation}, ""
	}
	// Delete and rollback: the exact snapshot as the list showed it.
	snaptime, err := strconv.ParseInt(f.Get("snaptime"), 10, 64)
	if err != nil || snaptime < 0 {
		return guestSnapshotForm{}, "the form does not name the snapshot's time"
	}
	parent := f.Get("parent")
	if len(parent) > maxGuestSnapshotParent || !utf8.ValidString(parent) {
		return guestSnapshotForm{}, "invalid snapshot parent"
	}
	t.Expect = &pb.PVESnapshotIdentity{Name: name, SnaptimeUnix: snaptime, Parent: parent, Vmstate: ram == "1"}
	switch start := f.Get("start"); {
	case op == guestSnapshotDelete && f.Has("start"):
		return guestSnapshotForm{}, "a delete has no start choice"
	case op == guestSnapshotRollback && start != "yes" && start != "no":
		return guestSnapshotForm{}, "choose whether the guest starts after the rollback"
	case op == guestSnapshotRollback:
		t.Start = start == "yes"
	}
	return guestSnapshotForm{target: t, generation: generation}, ""
}

// handleGuestSnapshotPropose proposes one snapshot action on the exact
// guest and snapshot the snapshot page showed, and redirects to the
// proposal page. Errors are plain text (formpost.js shows them with
// textContent).
func (h *Handler) handleGuestSnapshotPropose(w http.ResponseWriter, r *http.Request) {
	if !h.guestSnapshotEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	form, msg := parseGuestSnapshotForm(r.PostForm)
	if msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	t := form.target
	user := webUser(r)
	now := h.clockNow()
	if !h.guestPowerProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(guestPowerProposeInterval/time.Second)))
		http.Error(w, "too many proposals: wait a moment and try again", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	meta := h.pveMeta(ctx)
	if !remoteAllowsMutations(meta, t.GetRemoteId()) {
		http.Error(w, "the PVE remote is not active: no snapshot actions", http.StatusConflict)
		return
	}
	g, err := h.storedGuest(ctx, t.GetRemoteId(), t.GetVmid())
	if err != nil {
		h.log.Error("guest snapshot: read stored guest", "remote", t.GetRemoteId(), "vmid", t.GetVmid(), "error", err)
		http.Error(w, "the stored guest could not be read", http.StatusInternalServerError)
		return
	}
	switch {
	case g == nil:
		http.Error(w, "guest not found", http.StatusNotFound)
		return
	case g.Generation != form.generation || g.Node != t.GetNode() || g.Kind != t.GetKind():
		http.Error(w, "the guest changed since the snapshot list was loaded (re-created, migrated or a different kind): reload the list", http.StatusConflict)
		return
	case g.State != pveinventory.StateAvailable:
		http.Error(w, "the guest status is not current: no snapshot action", http.StatusConflict)
		return
	case t.GetVmstate() && g.Status != "running":
		http.Error(w, "RAM can only be included for a running VM", http.StatusConflict)
		return
	}
	if x := t.GetExpect(); x != nil {
		snaps, err := h.pve.(PVESnapshotStore).ListSnapshots(ctx, t.GetRemoteId(), t.GetVmid(), g.Generation, guestSnapshotListLimit)
		if err != nil {
			h.log.Error("guest snapshot: read stored snapshots", "remote", t.GetRemoteId(), "vmid", t.GetVmid(), "error", err)
			http.Error(w, "the stored snapshots could not be read", http.StatusInternalServerError)
			return
		}
		found := false
		for _, s := range snaps {
			if s.State == pveinventory.StateAvailable && sameSnapshotIdentity(x,
				&pb.PVESnapshotIdentity{Name: s.Name, SnaptimeUnix: s.TimeUnix, Parent: s.Parent, Vmstate: s.HasRAM}) {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "the snapshot changed since the list was loaded (deleted, re-created or another one of that name): reload the list", http.StatusConflict)
			return
		}
	}
	resp, err := h.guestSnapshot.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{Target: t})
	if err != nil {
		h.guestPowerRefusal(w, "propose guest snapshot", err)
		return
	}
	s := &guestSnapshotProposal{target: t, bound: resp.GetSnapshot(), runsAfter: resp.GetGuestRunsAfter()}
	p := &guestPowerProposal{user: user, kind: guestActionSnapshot, snap: s, verb: guestSnapshotOps[t.GetOp()],
		uiName: g.Name, uiGeneration: g.Generation}
	mismatch := func(b guestPowerBinding, risk string) []string {
		return guestSnapshotMismatch(b, s, risk, meta[t.GetRemoteId()].TrustPin, now)
	}
	h.storeGuestProposal(w, r, p, resp.GetPermit(), mismatch, now)
}

// handleGuestSnapshotProposal shows a snapshot proposal to its proposer.
func (h *Handler) handleGuestSnapshotProposal(w http.ResponseWriter, r *http.Request) {
	h.showGuestProposal(w, r, guestActionSnapshot)
}

// handleGuestSnapshotCommit relays the security key assertion of a
// snapshot proposal and starts the run.
func (h *Handler) handleGuestSnapshotCommit(w http.ResponseWriter, r *http.Request) {
	h.commitGuestProposal(w, r, guestActionSnapshot)
}

// handleGuestSnapshotRun runs a snapshot proposal approved with `nebula
// approve`.
func (h *Handler) handleGuestSnapshotRun(w http.ResponseWriter, r *http.Request) {
	h.runGuestProposal(w, r, guestActionSnapshot)
}
