// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
// approval. Approval reuses the schedule approval button (webauthn.js and
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
	// maxGuestPowerThrottleUsers bounds the throttle table.
	maxGuestPowerThrottleUsers = 1024
	// guestPowerCommitTimeout bounds one background commit; the executor
	// client adds its own (shorter) task wait.
	guestPowerCommitTimeout = 15 * time.Minute
	// maxGuestPowerField is the longest remote ID, node or kind value the
	// form accepts.
	maxGuestPowerField = 128
	// maxGuestPowerCanonical is the largest canonical request shown.
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

// guestPowerProposal is one proposal, visible to its proposer only.
type guestPowerProposal struct {
	user        string
	target      *pb.PVEGuestPowerTarget
	name        string
	generation  uint64
	verb        guestPowerVerb
	digest      string
	risk        string
	requirement string // "key", "typed_count" or "cli"
	options     string
	canonical   string
	challengeAt time.Time
	expires     time.Time
	// state is "pending", "approving", "running", "done" (the executor
	// returned the run's steps) or "failed".
	state       string
	message     string
	executionID string
	steps       []guestPowerStepView
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

// put stores a proposal, dropping expired ones and, when full, the
// settled or pending one that expires first (never a running commit).
func (p *guestPowerProposals) put(x *guestPowerProposal, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for d, y := range p.props {
		if !now.Before(y.expires) && y.state != "running" && y.state != "approving" {
			delete(p.props, d)
		}
	}
	if old, ok := p.props[x.digest]; ok && (old.state == "running" || old.state == "approving") {
		return false
	}
	if len(p.props) >= maxGuestPowerProposals {
		var oldest string
		for d, y := range p.props {
			if y.state == "running" || y.state == "approving" {
				continue
			}
			if oldest == "" || y.expires.Before(p.props[oldest].expires) {
				oldest = d
			}
		}
		if oldest == "" {
			return false
		}
		delete(p.props, oldest)
	}
	p.props[x.digest] = x
	return true
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

// guestActionData is the data of the proposal page.
type guestActionData struct {
	Name, Remote, Node, KindLabel string
	VMID, Generation              uint64
	Verb                          guestPowerVerb
	Digest, Risk, RiskClass       string
	Canonical                     string
	ChallengeExpiry               time.Time
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
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if !remoteAllowsMutations(h.pveMeta(ctx), remote) {
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
	user := webUser(r)
	now := h.clockNow()
	if !h.guestPowerProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(guestPowerProposeInterval/time.Second)))
		http.Error(w, "too many power proposals: wait a moment and try again", http.StatusTooManyRequests)
		return
	}
	target := &pb.PVEGuestPowerTarget{RemoteId: remote, Kind: kind, Node: node, Vmid: vmid, Verb: verb.Verb}
	resp, err := h.guestPower.ProposePVEGuestPower(ctx, &pb.ProposePVEGuestPowerRequest{Target: target})
	if err != nil {
		h.guestPowerRefusal(w, "propose guest power", err)
		return
	}
	perm := resp.GetPermit()
	digest := perm.GetExecutionDigest()
	risk := strings.TrimPrefix(perm.GetRiskClass().String(), "RISK_CLASS_")
	if !guestPowerDigestRe.MatchString(digest) || perm.GetRiskClass() == pb.RiskClass_RISK_CLASS_UNSPECIFIED || strings.HasPrefix(risk, "RISK") {
		http.Error(w, "the executor returned no usable proposal", http.StatusBadGateway)
		return
	}
	p := &guestPowerProposal{
		user: user, target: target, name: g.Name, generation: g.Generation, verb: verb,
		digest: digest, risk: risk, requirement: requirementText(perm.GetApprovalRequirement()),
		state: "pending", expires: now.Add(guestPowerProposalTTL),
	}
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		p.options = string(opts)
	}
	if c := perm.GetCanonicalRequest(); len(c) <= maxGuestPowerCanonical && utf8.Valid(c) {
		p.canonical = string(c)
	}
	if e := perm.GetChallengeExpiryUnix(); e > 0 {
		p.challengeAt = time.Unix(e, 0)
	}
	if p.requirement == "key" && p.options == "" {
		http.Error(w, "the executor returned no approval challenge", http.StatusBadGateway)
		return
	}
	if !h.guestPowerProposals.put(p, now) {
		http.Error(w, "too many power actions in progress", http.StatusServiceUnavailable)
		return
	}
	h.audit(r, "guest_power_proposed", guestPowerKey(remote, vmid)+" "+verb.Verb)
	http.Redirect(w, r, "/pve/guests/power/"+digest, http.StatusSeeOther)
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

// handleGuestPowerProposal shows a proposal to its proposer.
func (h *Handler) handleGuestPowerProposal(w http.ResponseWriter, r *http.Request) {
	if !h.guestPowerEnabled(w, r) {
		return
	}
	digest := r.PathValue("digest")
	if !guestPowerDigestRe.MatchString(digest) {
		http.NotFound(w, r)
		return
	}
	p, ok := h.guestPowerProposals.get(webUser(r), digest, h.clockNow())
	if !ok {
		http.NotFound(w, r)
		return
	}
	t := p.target
	d := &guestActionData{
		Name: p.name, Remote: t.GetRemoteId(), Node: t.GetNode(), KindLabel: guestKindLabel(t.GetKind()),
		VMID: t.GetVmid(), Generation: p.generation, Verb: p.verb,
		Digest: p.digest, Risk: p.risk, RiskClass: riskBadgeClass(p.risk), Canonical: p.canonical,
		ChallengeExpiry: p.challengeAt, State: p.state, Message: p.message, ExecutionID: p.executionID, Steps: p.steps,
	}
	data := pageData{Title: "Guest power: " + p.verb.Verb, Active: "pve", Content: "guest_action", GuestAction: d}
	if p.state == "pending" {
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
	if !h.guestPowerEnabled(w, r) {
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
	if !guestPowerDigestRe.MatchString(in.ID) {
		writeJSONError(w, http.StatusNotFound, "power proposal not found")
		return
	}
	cur, ok := h.guestPowerProposals.get(user, in.ID, now)
	if !ok || cur.requirement != "key" || len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusNotFound, "power proposal not found")
		return
	}
	p, ok := h.guestPowerProposals.transition(user, in.ID, "pending", "approving", now)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "power proposal not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if _, err := h.guestPower.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: p.digest, AssertionJson: in.Assertion}); err != nil {
		h.guestPowerProposals.setResult(p.digest, "pending", "", "", nil, now)
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			writeJSONError(w, http.StatusForbidden, "security key not accepted")
		default:
			h.executorRefusal(w, "approve guest power", err)
		}
		return
	}
	if _, ok := h.guestPowerProposals.transition(user, p.digest, "approving", "running", now); !ok {
		writeJSONError(w, http.StatusConflict, "power proposal changed")
		return
	}
	h.audit(r, "guest_power_approved", guestPowerKey(p.target.GetRemoteId(), p.target.GetVmid())+" "+p.verb.Verb)
	h.startGuestPowerCommit(r, p)
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// handleGuestPowerRun runs a proposal approved with `nebula approve`
// (hardened mode, or a typed count). The executor refuses a permit that is
// not approved.
func (h *Handler) handleGuestPowerRun(w http.ResponseWriter, r *http.Request) {
	if !h.guestPowerEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	digest := r.PostForm.Get("digest")
	user := webUser(r)
	now := h.clockNow()
	if !guestPowerDigestRe.MatchString(digest) {
		http.NotFound(w, r)
		return
	}
	cur, ok := h.guestPowerProposals.get(user, digest, now)
	if !ok || cur.requirement == "key" {
		http.NotFound(w, r)
		return
	}
	p, ok := h.guestPowerProposals.transition(user, digest, "pending", "running", now)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.audit(r, "guest_power_run", guestPowerKey(p.target.GetRemoteId(), p.target.GetVmid())+" "+p.verb.Verb)
	h.startGuestPowerCommit(r, p)
	http.Redirect(w, r, "/pve/guests/power/"+digest, http.StatusSeeOther)
}

// startGuestPowerCommit commits the approved proposal in the background:
// the executor waits for the PVE task, longer than a request may take.
// A refusal before anything ran (the permit is not approved, the guest
// state changed) puts a CLI proposal back to pending with the reason.
func (h *Handler) startGuestPowerCommit(r *http.Request, p guestPowerProposal) {
	ctx := context.WithoutCancel(r.Context())
	target := p.target
	go func() {
		ctx, cancel := context.WithTimeout(ctx, guestPowerCommitTimeout)
		defer cancel()
		resp, err := h.guestPower.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: p.digest})
		now := h.clockNow()
		if err != nil {
			st, _ := status.FromError(err)
			switch st.Code() {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound, codes.Aborted, codes.Unavailable:
				state := "failed"
				if p.requirement != "key" && (st.Code() == codes.PermissionDenied || st.Code() == codes.FailedPrecondition) {
					state = "pending" // approve with the CLI, then run again
				}
				h.guestPowerProposals.setResult(p.digest, state, "the executor refused: "+cleanText(st.Message()), "", nil, now)
			default:
				h.log.Error("commit guest power", "error", err)
				h.guestPowerProposals.setResult(p.digest, "failed", "the run could not be confirmed (executor unavailable); check the executor's job list before trying again", "", nil, now)
			}
			return
		}
		var steps []guestPowerStepView
		for i, s := range resp.GetSteps() {
			if i >= maxGuestPowerSteps {
				break
			}
			steps = append(steps, guestPowerStepView{State: cleanText(s.GetState()), UPID: cleanText(s.GetUpid()), TaskType: cleanText(s.GetTaskType())})
		}
		h.guestPowerProposals.setResult(p.digest, "done", "", cleanText(resp.GetExecutionId()), steps, now)
	}()
}
