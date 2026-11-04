// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
)

// Deployments (ADR 0008 section 6, PV-08). "Deploy" is one navigation
// entry with three pages: the deploy profiles (deployprofiles.go), the new
// deployment wizard (GET /deployments/new) and the deployment runs (GET
// /deployments, GET /deployments/{id}).
//
// The wizard has two steps. The first (a GET form, also the target of the
// org chart's "Deploy here" shortcut) picks the target remote and node, the
// profile and the IPAM network and pool, and shows the profile's values
// and a suggested free address. The second (POST /deployments/propose,
// posted with fetch like every state-changing form) reserves the address in
// the IPAM, freezes the bootstrap/runbook plan at exact versions and asks
// the executor to propose pve.guest.provision. The run page then shows the
// frozen plan with the risk the executor decided before approval.
//
// The run page follows the states of ADR 0008 section 6: proposed,
// approved, creating, booting, enrolling (fingerprint review), bootstrapping,
// done or failed, with the PVE task UPIDs and step outcomes. A server
// without a batch planner ends a run with a staged plan at "joined"
// (enrolled, plan not run) instead of leaving it in bootstrapping. An idle
// run that does not progress fails when its deadline passes (the
// proposal's request expiry, deployEnrollWindow, deployBootstrapWindow),
// so abandoned runs never hold the per-user or global run limit. Only a
// proposal the executor refused releases its IPAM reservation at once;
// once the executor may hold a permit for the execution, the reservation
// is kept: an admin may approve and commit that execution out of band
// (nebula approve, CommitPVEGuestProvision), and the executor cannot tell
// a consumed permit from an expired one. A kept address is cleared by the
// operator on the network page. Enrollment uses
// pveinventory.GuestJoinFlow (PV-06): propose on the executor, show the
// fingerprint the executor read, approve, commit; the inventory host and
// its guest link are created from the executor's committed binding only.
// After enrollment the staged plan (bootstrap modules, then runbooks, one
// member per stage, stop on the first failure) is proposed as one batch
// (ADR 0007) and approved once on the batch page.
//
// Runs are kept in memory and are visible to their proposer only, like the
// guest power proposals. Every string from the executor, PVE or a profile
// is untrusted and rendered as text only.

// DeployProvisioner proposes, approves and runs pve.guest.provision on the
// executor (server role). executorclient.Client satisfies it.
type DeployProvisioner interface {
	ProposePVEGuestProvision(ctx context.Context, in *pb.ProposePVEGuestProvisionRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error)
	CommitPVEGuestProvision(ctx context.Context, in *pb.CommitPVEGuestProvisionRequest, opts ...grpc.CallOption) (*pb.CommitPVEGuestProvisionResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
}

// DeployJoiner enrolls a provisioned guest (pveinventory.GuestJoinFlow).
type DeployJoiner interface {
	Propose(ctx context.Context, p pveinventory.GuestJoinProposal) (*pb.ProposeGuestJoinResponse, error)
	Commit(ctx context.Context, proposal *pb.ProposeGuestJoinResponse, host inventory.Host, actor string) (pveinventory.GuestJoinResult, error)
}

// DeployIPAM reserves the guest's address (ipam.Store).
type DeployIPAM interface {
	Reserve(ctx context.Context, user, networkID, pool string, ad netip.Addr, note string) (ipam.Reservation, error)
	ClearEntry(ctx context.Context, ad netip.Addr) error
}

// DeployBatches proposes and reads the staged post-enrollment plan as one
// batch (executions.Batches).
type DeployBatches interface {
	ProposeBatch(ctx context.Context, user string, req executions.BatchRequest) (executions.BatchCreated, error)
	Batch(ctx context.Context, id string) (executions.BatchView, error)
}

// Run states (ADR 0008 section 6).
const (
	deployProposed      = "proposed"
	deployApproved      = "approved"
	deployCreating      = "creating"
	deployBooting       = "booting"
	deployEnrolling     = "enrolling"
	deployBootstrapping = "bootstrapping"
	deployDone          = "done"
	deployFailed        = "failed"
	// deployJoined ends a run whose guest is enrolled but whose staged
	// plan cannot run because this server has no batch planner.
	deployJoined = "joined"
)

// deployStates are the states in the order the run page shows them.
var deployStates = []struct{ name, label string }{
	{deployProposed, "Proposed"},
	{deployApproved, "Approved"},
	{deployCreating, "Creating"},
	{deployBooting, "Booting"},
	{deployEnrolling, "Enrolling"},
	{deployBootstrapping, "Bootstrapping"},
	{deployDone, "Done"},
}

// Limits of the deployment pages.
const (
	// maxDeployRuns bounds the runs kept in memory.
	maxDeployRuns = 128
	// maxDeployRunsPerUser bounds one user's unfinished runs.
	maxDeployRunsPerUser = 16
	// deployRunTTL is how long a finished or expired run stays visible.
	deployRunTTL = 24 * time.Hour
	// deployProposalWindow bounds a proposal whose bound request carries
	// no expiry; normally the executor's request expiry (at most
	// deployRunTTL away) ends a proposal.
	deployProposalWindow = time.Hour
	// deployEnrollWindow bounds booting and enrolling: from the end of
	// provisioning until the enrollment is committed.
	deployEnrollWindow = 6 * time.Hour
	// deployBootstrapWindow bounds bootstrapping: from the enrollment
	// until the staged plan's batch has ended.
	deployBootstrapWindow = 24 * time.Hour
	// deployBatchGrace is how long after its approval or run expiry a
	// batch the server still records as pending or approved is taken as
	// ended (the executor's state may arrive late).
	deployBatchGrace = 5 * time.Minute
	// deployCommitTimeout bounds the background provisioning commit; the
	// executor client adds its own task wait.
	deployCommitTimeout = 35 * time.Minute
	// deployReleaseTimeout bounds the one ClearEntry of a refused
	// proposal.
	deployReleaseTimeout = 10 * time.Second
	// deployJoinTimeout bounds the enrollment commit (an SSH probe and the
	// inventory transaction).
	deployJoinTimeout = 2 * time.Minute
	// maxDeployNameLen is the longest guest name; it is also the inventory
	// host ID, which allows 63 characters.
	maxDeployNameLen = 63
	// maxDeployNameservers bounds the nameservers of one guest.
	maxDeployNameservers = deployprofile.MaxNameservers
	// maxDeploySuggestions is how many free addresses the wizard offers.
	maxDeploySuggestions = 5
	// maxDeployField is the longest free-text form value.
	maxDeployField = 253
	// deployDefaultCredential is the keyring reference of the NOS
	// automation key cloud-init installs and the join uses.
	deployDefaultCredential = "nebula-default"
	// deployDefaultCIUser is the default cloud-init user.
	deployDefaultCIUser = "nebula"
	// deployDisk is the disk slot provisioning resizes.
	deployDisk = "scsi0"
	// deploySSHPort is the port of the guest's SSH endpoint.
	deploySSHPort = 22
	// deployCLICommand is the CLI approval command.
	deployCLICommand = "nebula approve "
)

var (
	deployNameRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	deployFieldRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	deployRemoteRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	deployDomainRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	deploySHA256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	deployRunIDRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	deployRunbookRe = regexp.MustCompile(`^([a-z0-9][a-z0-9_]{0,39})@([1-9][0-9]{0,5})$`)
)

// deployForm is the validated wizard input.
type deployForm struct {
	Remote, Node, Storage string
	ProfileSlug           string
	ProfileVersion        int
	Image                 string
	TemplateVMID          uint64
	TemplateSHA256        string
	Size                  deployprofile.Size
	Name                  string
	Environment           string
	Bridge                string
	VLAN                  int
	DHCP                  bool
	Network, Pool         string
	Address               netip.Addr
	Nameservers           []string
	SearchDomain          string
	CIUser                string
	PasswordID            string
	Bootstrap             []string
	Runbooks              []deployprofile.RunbookRef
	SaveAs                string
	moduleParams          map[string]map[string]string
	runbookParams         map[string]map[string]string
}

// deployPlanStep is one step of the frozen post-enrollment plan.
type deployPlanStep struct {
	// Stage is the batch stage (1-based); 0 for a step outside the batch.
	Stage    int
	Kind     string // "bootstrap module" or "runbook"
	ActionID string
	Version  string
	Title    string
	Risk     string
	Params   map[string]string
	// Separate says why the step cannot be part of the batch (it must be
	// run as its own operation after the batch).
	Separate string
}

// ParamText is the step's parameters as sorted name=value pairs.
func (s deployPlanStep) ParamText() string {
	keys := make([]string, 0, len(s.Params))
	for k := range s.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+s.Params[k])
	}
	return strings.Join(out, " ")
}

// deployJoin is the enrollment proposal of a run.
type deployJoin struct {
	resp        *pb.ProposeGuestJoinResponse
	bound       guestPowerBinding
	mismatch    []string
	digest      string
	risk        string
	requirement string
	options     string
	generation  uint64
	endpoint    string
	approving   bool
}

// deployRun is one deployment.
type deployRun struct {
	id      string
	user    string
	created time.Time
	form    deployForm
	spec    *pb.PVEGuestProvisionSpec
	ipam    *pb.PVEIPAMBinding

	executionID string
	vmid        uint64
	digest      string
	risk        string
	requirement string
	options     string
	challengeAt time.Time
	bound       guestPowerBinding
	mismatch    []string
	warnings    []string

	state string
	// failedIn is the state a failed run failed in.
	failedIn  string
	approving bool
	message   string
	steps     []guestPowerStepView
	guestKept bool
	expires   time.Time
	// deadline ends an idle unfinished run (proposed, booting, enrolling,
	// bootstrapping): settle marks it failed once it has passed.
	deadline time.Time
	// address is what happens to the IPAM reservation (ipamHeld etc.).
	address string

	join   *deployJoin
	joined *pveinventory.GuestJoinResult

	plan     []deployPlanStep
	batchID  string
	batchErr string
}

// What happens to a run's IPAM reservation. A run never releases its
// reservation: from the proposal on, the executor may hold a permit an
// admin can commit out of band, so the address may be in use.
const (
	// ipamHeld: the reservation is held for the live run (or there is none).
	ipamHeld = ""
	// ipamKept: the run ended and a guest may use the address; it stays
	// reserved until the operator clears it.
	ipamKept = "kept"
)

// final reports whether the run ended.
func (x *deployRun) final() bool {
	return x.state == deployDone || x.state == deployFailed || x.state == deployJoined
}

// busy reports whether a background call holds the run.
func (x *deployRun) busy() bool {
	return x.approving || x.state == deployApproved || x.state == deployCreating || (x.join != nil && x.join.approving)
}

// approvable reports whether the provisioning proposal may be approved.
func (x *deployRun) approvable(now time.Time) bool {
	return x.state == deployProposed && !x.approving && len(x.mismatch) == 0 && now.Before(x.bound.Expiry)
}

// deployRuns keeps the runs and the propose throttle.
type deployRuns struct {
	mu   sync.Mutex
	last map[string]time.Time
	runs map[string]*deployRun
	log  *slog.Logger // audit entries of settling; nil discards them
}

func newDeployRuns(log *slog.Logger) *deployRuns {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &deployRuns{last: map[string]time.Time{}, runs: map[string]*deployRun{}, log: log}
}

var (
	errDeployUserCap = errors.New("too many unfinished deployments of this user")
	errDeployFull    = errors.New("too many deployments in progress")
)

// allow throttles proposals per user (each one holds a VMID and an
// address reservation).
func (p *deployRuns) allow(user string, now time.Time) bool {
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

// room checks, before anything is reserved, that user may start another
// run.
func (p *deployRuns) room(user string, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	n := 0
	for _, x := range p.runs {
		if x.user == user && !x.final() {
			n++
		}
	}
	if n >= maxDeployRunsPerUser {
		return errDeployUserCap
	}
	if len(p.runs) >= maxDeployRuns && p.oldestFinal() == "" {
		return errDeployFull
	}
	return nil
}

// prune settles idle unfinished runs past their deadline and drops
// finished runs past their TTL that no background call holds. Unfinished
// runs are never dropped; dropping a run leaves its reservation in place.
func (p *deployRuns) prune(now time.Time) {
	p.expire(now)
	for id, x := range p.runs {
		if x.final() && !now.Before(x.expires) && !x.busy() {
			delete(p.runs, id)
		}
	}
}

// expire ends every idle unfinished run whose deadline has passed: it
// fails in the state it was in with a visible reason, stops counting
// against the caps and is pruned after deployRunTTL. No expiry releases an
// address. An expired proposal was not run from this page, but an admin may
// have approved and committed the same execution out of band; the
// executor's only read (GetPermitState) reports "no live permit" for a
// consumed and an expired permit alike, so whether a guest exists cannot be
// told and the address is kept as "may be in use".
func (p *deployRuns) expire(now time.Time) {
	for _, x := range p.runs {
		if x.final() || x.busy() || x.deadline.IsZero() || now.Before(x.deadline) {
			continue
		}
		switch x.state {
		case deployProposed:
			vmid := "VMID " + strconv.FormatUint(x.vmid, 10) + " on " + x.form.Remote
			x.message = "the proposal expired without a run from this page"
			switch {
			case x.address == ipamKept:
				// A refused run left it ambiguous whether an earlier run
				// of the execution created the guest.
				x.message = "the proposal expired; the address stays reserved because an earlier run of this execution may have created the guest"
			case x.ipam != nil:
				x.address = ipamKept
				x.message += "; the address " + x.ipam.GetAddress() + " stays reserved and may be in use, because the execution may have been approved and committed outside this page (nebula approve). Clear the reservation on the network page once no guest with " +
					vmid + " exists"
				// The run's message is pruned with the run; the audit log
				// keeps which execution and VMID the reservation belongs to.
				p.log.Warn("audit", "kind", "deployment_address_kept", "reason", "proposal_expired", "address", x.ipam.GetAddress(),
					"run", x.id, "execution", x.executionID, "remote", x.form.Remote, "vmid", x.vmid, "user", x.user)
			default:
				x.message += "; it may have been approved and committed outside this page (nebula approve): check for a guest with " + vmid
			}
		case deployBooting, deployEnrolling:
			x.message = "expired: the guest was not enrolled within " + deployEnrollWindow.String() +
				"; the guest is left in PVE and keeps its address, deleting it is a separate action"
		case deployBootstrapping:
			x.message = "expired: the staged plan did not finish within " + deployBootstrapWindow.String() +
				"; the guest stays enrolled, a batch keeps its own outcome on the batch page"
		default:
			continue
		}
		x.failedIn, x.state, x.expires = x.state, deployFailed, now.Add(deployRunTTL)
	}
}

// settleDeployRuns expires idle runs past their deadline and prunes
// finished runs past their TTL; it returns the time it used. Settling is
// lazy (every deployment page and form calls it, there is no background
// sweep) and only touches memory: it never calls the IPAM store, so no
// page request waits on the store or retries a failing one.
func (h *Handler) settleDeployRuns() time.Time {
	now := h.clockNow()
	h.deployRuns.mu.Lock()
	h.deployRuns.prune(now)
	h.deployRuns.mu.Unlock()
	return now
}

// oldestFinal returns the finished run that expires first.
func (p *deployRuns) oldestFinal() string {
	var id string
	for k, x := range p.runs {
		if x.final() && (id == "" || x.expires.Before(p.runs[id].expires)) {
			id = k
		}
	}
	return id
}

// put stores a new run, evicting the finished run that expires first when
// full; an unfinished run is never evicted.
func (p *deployRuns) put(x *deployRun, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	if len(p.runs) >= maxDeployRuns {
		id := p.oldestFinal()
		if id == "" {
			return errDeployFull
		}
		delete(p.runs, id)
	}
	p.runs[x.id] = x
	return nil
}

// get returns a copy of user's run.
func (p *deployRuns) get(user, id string) (deployRun, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.runs[id]
	if !ok || x.user != user {
		return deployRun{}, false
	}
	return x.copy(), true
}

func (x *deployRun) copy() deployRun {
	c := *x
	c.steps = slices.Clone(x.steps)
	c.plan = slices.Clone(x.plan)
	if x.join != nil {
		j := *x.join
		c.join = &j
	}
	return c
}

// list returns copies of user's runs, newest first.
func (p *deployRuns) list(user string, now time.Time) []deployRun {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)
	var out []deployRun
	for _, x := range p.runs {
		if x.user == user {
			out = append(out, x.copy())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].created.After(out[j].created) })
	return out
}

// update applies f to user's run under the lock if ok(run) holds, and
// returns a copy of the result.
func (p *deployRuns) update(user, id string, ok func(*deployRun) bool, f func(*deployRun)) (deployRun, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, found := p.runs[id]
	if !found || x.user != user || !ok(x) {
		return deployRun{}, false
	}
	f(x)
	return x.copy(), true
}

// set applies f to the run (background calls).
func (p *deployRuns) set(id string, f func(*deployRun)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x, ok := p.runs[id]; ok {
		f(x)
	}
}

func newDeployRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// deployEnabled answers 404 when provisioning is not wired.
func (h *Handler) deployEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.deploy == nil || h.pve == nil || h.pveRemotes == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// ---- Wizard ---------------------------------------------------------------

// deployOption is one choice of a wizard select.
type deployOption struct {
	Value, Label string
	Selected     bool
}

// deployWizardData is the data of the wizard page.
type deployWizardData struct {
	Remotes  []deployOption
	Nodes    []deployOption
	Profiles []deployOption
	Networks []deployOption
	Pools    []deployOption
	Envs     []deployOption
	Sizes    []deployOption
	Modules  []deployOption
	Runbooks []deployOption
	// Templates are the stored QEMU guests of the node a template may be.
	Templates []deployOption

	Remote, Node, Profile, Network, Pool string
	// Profile values (prefill of the second step).
	ProfileVersion int
	Image          string
	Storage        string
	Bridge         string
	VLAN           int
	DHCP           bool
	Nameservers    string
	SearchDomain   string
	VCPU, RAMGiB   int
	DiskGiB        int
	// Suggestions are free IPAM addresses; Suggested is the first.
	Suggestions []string
	Suggested   string
	// Notes explain why parts of the wizard are not available.
	Notes []string
	// Ready is set when a remote and node are chosen (the second step is
	// shown).
	Ready bool
	// CIUserDefault prefills the cloud-init user.
	CIUserDefault string
}

// handleDeployWizard renders the wizard. The query preselects the target
// (the chart's "Deploy here" passes remote and node), the profile and the
// IPAM network and pool.
func (h *Handler) handleDeployWizard(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	// Settle expired runs before the suggestion; expiry keeps addresses.
	h.settleDeployRuns()
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	q := r.URL.Query()
	d := &deployWizardData{Remote: q.Get("remote"), Node: q.Get("node"), Profile: q.Get("profile"),
		Network: q.Get("network"), Pool: q.Get("pool"), CIUserDefault: deployDefaultCIUser}
	meta := h.pveMeta(ctx)
	var remotes []string
	for id := range meta {
		// Read-only or blocked remotes are hidden (ADR 0008 consequences);
		// the executor still refuses a remote without an action token.
		if remoteAllowsMutations(meta, id) {
			remotes = append(remotes, id)
		}
	}
	sort.Strings(remotes)
	if !slices.Contains(remotes, d.Remote) {
		d.Remote, d.Node = "", ""
	}
	for _, id := range remotes {
		label := id
		if n := meta[id].Name; n != "" && n != id {
			label = n + " (" + id + ")"
		}
		d.Remotes = append(d.Remotes, deployOption{Value: id, Label: label, Selected: id == d.Remote})
	}
	if len(remotes) == 0 {
		d.Notes = append(d.Notes, "No active PVE remote: provisioning needs a remote with an action token in the executor registry.")
	}
	if d.Remote != "" {
		nodes, err := h.pve.ListNodes(ctx, d.Remote, 0)
		if err != nil {
			h.log.Error("deploy wizard: list nodes", "remote", d.Remote, "error", err)
		}
		found := false
		for _, n := range nodes {
			d.Nodes = append(d.Nodes, deployOption{Value: n.Node, Label: n.Node, Selected: n.Node == d.Node})
			found = found || n.Node == d.Node
		}
		if !found {
			d.Node = ""
		}
	}
	d.Ready = d.Remote != "" && d.Node != ""
	if d.Ready {
		guests, err := h.pve.ListGuests(ctx, d.Remote, pveinventory.GuestFilter{}, 0)
		if err != nil {
			h.log.Error("deploy wizard: list guests", "remote", d.Remote, "error", err)
		}
		for _, g := range guests {
			if g.Node == d.Node && g.Kind == guestKindQEMU && !g.Tombstoned && g.Status != "running" {
				d.Templates = append(d.Templates, deployOption{Value: strconv.FormatUint(g.VMID, 10), Label: strconv.FormatUint(g.VMID, 10) + " " + g.Name})
			}
		}
	}
	d.Envs = []deployOption{{Value: "DEV", Label: "DEV", Selected: true}, {Value: "QA", Label: "QA"}, {Value: "PROD", Label: "PROD"}}
	for _, s := range []string{"S", "M", "L", "XL"} {
		p := deployprofile.Presets[s]
		d.Sizes = append(d.Sizes, deployOption{Value: s, Label: s + " (" + sizeLabel(deployprofile.Size{VCPU: p.VCPU, RAMGiB: p.RAMGiB, DiskGiB: p.DiskGiB}) + ")"})
	}
	var prof *deployprofile.Version
	if h.deployProfiles != nil {
		list, err := h.deployProfiles.Latest(ctx)
		if err != nil {
			h.log.Error("deploy wizard: list profiles", "error", err)
		}
		for i := range list {
			v := list[i]
			sel := v.Profile.Slug == d.Profile
			if sel {
				prof = &v
			}
			d.Profiles = append(d.Profiles, deployOption{Value: v.Profile.Slug, Label: v.Profile.Title + " (" + v.Profile.Slug + " v" + strconv.Itoa(v.Version) + ")", Selected: sel})
		}
	}
	if prof == nil {
		d.Profile = ""
	}
	selectedModules := map[string]bool{}
	selectedRunbooks := map[string]bool{}
	if prof != nil {
		p := prof.Profile
		d.ProfileVersion, d.Image, d.Storage = prof.Version, p.Image, p.StorageClass
		d.Bridge, d.VLAN, d.DHCP = p.Network.Bridge, p.Network.VLAN, p.Network.DHCP
		d.Nameservers, d.SearchDomain = strings.Join(p.DNS.Nameservers, ", "), p.DNS.SearchDomain
		if size, err := p.Size.Resolve(); err == nil {
			d.VCPU, d.RAMGiB, d.DiskGiB = size.VCPU, size.RAMGiB, size.DiskGiB
			for i := range d.Sizes {
				d.Sizes[i].Selected = d.Sizes[i].Value == size.Preset
			}
		}
		for _, m := range p.Bootstrap {
			selectedModules[m.Name] = true
		}
		for _, rb := range p.Runbooks {
			selectedRunbooks[rb.Slug+"@"+strconv.Itoa(rb.Version)] = true
		}
		if d.Pool == "" && !p.Network.DHCP {
			d.Pool = p.Network.IPAMPool
		}
	}
	for _, m := range deployprofile.BootstrapModules {
		d.Modules = append(d.Modules, deployOption{Value: m, Label: m, Selected: selectedModules[m]})
	}
	if h.runbooks != nil {
		list, err := h.runbooks.Latest(ctx)
		if err != nil {
			h.log.Error("deploy wizard: list runbooks", "error", err)
		}
		for _, v := range list {
			key := v.Slug + "@" + strconv.Itoa(v.Version)
			d.Runbooks = append(d.Runbooks, deployOption{Value: key, Label: v.Title + " (" + key + ")", Selected: selectedRunbooks[key]})
			delete(selectedRunbooks, key)
		}
	}
	// A profile may pin an older runbook version than the latest.
	for key := range selectedRunbooks {
		d.Runbooks = append(d.Runbooks, deployOption{Value: key, Label: key, Selected: true})
	}
	h.wizardIPAM(ctx, d)
	h.render(w, r, pageData{Title: "New deployment", Active: "deploy", Content: "deploy_wizard",
		Scripts: []string{"formpost.js"}, DeployWizard: d})
}

// wizardIPAM fills the networks, pools and suggested free addresses. A
// pool name alone (from a profile) selects the first network that has it.
func (h *Handler) wizardIPAM(ctx context.Context, d *deployWizardData) {
	if h.network == nil {
		d.Notes = append(d.Notes, "IPAM is not available: use DHCP.")
		return
	}
	nets, err := h.network.Networks(ctx)
	if err != nil {
		h.log.Error("deploy wizard: list networks", "error", err)
		d.Notes = append(d.Notes, "IPAM networks could not be read: use DHCP or try again.")
		return
	}
	var cur *ipam.Network
	for i := range nets {
		n := &nets[i]
		if d.Network == "" && d.Pool != "" {
			for _, p := range n.Pools {
				if p.Name == d.Pool {
					d.Network = n.ID
				}
			}
		}
		if n.ID == d.Network {
			cur = n
		}
	}
	for _, n := range nets {
		d.Networks = append(d.Networks, deployOption{Value: n.ID, Label: n.Name + " (" + n.Prefix.String() + ")", Selected: n.ID == d.Network})
	}
	if cur == nil {
		d.Network, d.Pool = "", ""
		return
	}
	poolFound := false
	for _, p := range cur.Pools {
		d.Pools = append(d.Pools, deployOption{Value: p.Name, Label: p.Name + " (" + p.First.String() + " – " + p.Last.String() + ")", Selected: p.Name == d.Pool})
		poolFound = poolFound || p.Name == d.Pool
	}
	if !poolFound {
		d.Pool = ""
	}
	if d.Bridge == "" && cur.VLAN != 0 {
		d.VLAN = cur.VLAN
	}
	addrs, err := h.network.Suggest(ctx, cur.ID, d.Pool, maxDeploySuggestions)
	if err != nil {
		h.log.Error("deploy wizard: suggest address", "network", cur.ID, "error", err)
		d.Notes = append(d.Notes, "No free address could be suggested for this network.")
		return
	}
	for _, a := range addrs {
		d.Suggestions = append(d.Suggestions, a.String())
	}
	if len(d.Suggestions) > 0 {
		d.Suggested = d.Suggestions[0]
	} else {
		d.Notes = append(d.Notes, "The network (or pool) has no free address left.")
	}
}

// formError is a wizard input error shown to the user.
type formError string

func (e formError) Error() string { return string(e) }

// parseDeployForm validates the second wizard step. Values are bounded and
// checked here; the executor validates the spec again.
func parseDeployForm(f url.Values) (deployForm, error) {
	var d deployForm
	get := func(k string) string { return strings.TrimSpace(f.Get(k)) }
	for k, vs := range f {
		for _, v := range vs {
			if len(v) > 4*maxDeployField {
				return d, formError("the field " + k + " is too long")
			}
		}
	}
	d.Remote, d.Node, d.Storage = get("remote"), get("node"), get("storage")
	switch {
	case !deployRemoteRe.MatchString(d.Remote):
		return d, formError("choose a PVE remote")
	case !deployRemoteRe.MatchString(d.Node):
		return d, formError("choose a node")
	case !deployFieldRe.MatchString(d.Storage):
		return d, formError("name the storage for the guest's disks")
	}
	if s := get("profile"); s != "" {
		d.ProfileSlug = s
		v, err := strconv.Atoi(get("profile_version"))
		if err != nil || v < 1 {
			return d, formError("the profile version is missing; reload the wizard")
		}
		d.ProfileVersion = v
	}
	d.Image = get("image")
	if !deployFieldRe.MatchString(d.Image) {
		return d, formError("choose the OS image")
	}
	vmid, err := strconv.ParseUint(get("template_vmid"), 10, 64)
	if err != nil || vmid < 100 || vmid > 999999999 {
		return d, formError("choose the prepared template (its VMID)")
	}
	d.TemplateVMID = vmid
	d.TemplateSHA256 = strings.ToLower(get("template_sha256"))
	if !deploySHA256Re.MatchString(d.TemplateSHA256) {
		return d, formError("the template's image SHA-256 is 64 hex characters (the image catalog digest the template was prepared from)")
	}
	switch preset := get("size"); preset {
	case "S", "M", "L", "XL":
		d.Size = deployprofile.Presets[preset]
	case "custom":
		atoi := func(k string) int { n, _ := strconv.Atoi(get(k)); return n }
		d.Size = deployprofile.Size{VCPU: atoi("vcpu"), RAMGiB: atoi("ram_gib"), DiskGiB: atoi("disk_gib")}
		if d.Size.VCPU < deployprofile.MinVCPUs || d.Size.VCPU > deployprofile.MaxVCPUs ||
			d.Size.RAMGiB < deployprofile.MinRAMGiB || d.Size.RAMGiB > deployprofile.MaxRAMGiB ||
			d.Size.DiskGiB < deployprofile.MinDiskGiB || d.Size.DiskGiB > deployprofile.MaxDiskGiB {
			return d, formError("the custom size is out of range")
		}
	default:
		return d, formError("choose a size")
	}
	d.Name = get("name")
	if !deployNameRe.MatchString(d.Name) || len(d.Name) > maxDeployNameLen {
		return d, formError("the hostname is one lowercase DNS label of 1 to 63 letters, digits or hyphens")
	}
	d.Environment = get("environment")
	if d.Environment != "DEV" && d.Environment != "QA" && d.Environment != "PROD" {
		return d, formError("choose the environment")
	}
	d.Bridge = get("bridge")
	if !deployFieldRe.MatchString(d.Bridge) {
		return d, formError("name the bridge")
	}
	if s := get("vlan"); s != "" && s != "0" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > deployprofile.MaxVLAN {
			return d, formError("the VLAN tag is 1 to 4094, or empty")
		}
		d.VLAN = v
	}
	switch get("ip_mode") {
	case "dhcp":
		d.DHCP = true
	case "ipam":
		d.Network, d.Pool = get("network"), get("pool")
		if !deployRemoteRe.MatchString(d.Network) || (d.Pool != "" && !deployRemoteRe.MatchString(d.Pool)) {
			return d, formError("choose the IPAM network")
		}
		a, err := netip.ParseAddr(get("address"))
		if err != nil || !a.Is4() {
			return d, formError("enter the IPv4 address (the wizard suggests a free one)")
		}
		d.Address = a
	default:
		return d, formError("choose a static IPAM address or DHCP")
	}
	for _, s := range strings.FieldsFunc(get("nameservers"), func(r rune) bool { return r == ',' || r == ' ' }) {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return d, formError("nameservers are IP addresses, separated by commas")
		}
		d.Nameservers = append(d.Nameservers, a.String())
	}
	if len(d.Nameservers) > maxDeployNameservers {
		return d, formError("at most " + strconv.Itoa(maxDeployNameservers) + " nameservers")
	}
	d.SearchDomain = get("search_domain")
	if d.SearchDomain != "" && (!deployDomainRe.MatchString(d.SearchDomain) || len(d.SearchDomain) > deployprofile.MaxSearchDomain) {
		return d, formError("the search domain is a lowercase DNS name")
	}
	d.CIUser = get("ci_user")
	if d.CIUser == "" {
		d.CIUser = deployDefaultCIUser
	}
	if !deployNameRe.MatchString(d.CIUser) || len(d.CIUser) > 32 {
		return d, formError("the cloud-init user is a lowercase login name")
	}
	if get("password") == "executor" {
		d.PasswordID = get("password_id")
		if !deployFieldRe.MatchString(d.PasswordID) {
			return d, formError("name the guest password entered on the executor (nebula pve guest-password set)")
		}
	}
	known := map[string]bool{}
	for _, m := range deployprofile.BootstrapModules {
		known[m] = true
	}
	chosen := map[string]bool{}
	for _, m := range f["bootstrap"] {
		if !known[m] {
			return d, formError("unknown bootstrap module")
		}
		chosen[m] = true
	}
	// The documented execution order (ADR 0008 section 5), whatever the
	// form's order.
	for _, m := range deployprofile.BootstrapModules {
		if chosen[m] {
			d.Bootstrap = append(d.Bootstrap, m)
		}
	}
	seen := map[string]bool{}
	for _, s := range f["runbook"] {
		m := deployRunbookRe.FindStringSubmatch(s)
		if m == nil || seen[m[1]] {
			return d, formError("runbooks are chosen once each, at one version")
		}
		seen[m[1]] = true
		v, _ := strconv.Atoi(m[2])
		d.Runbooks = append(d.Runbooks, deployprofile.RunbookRef{Slug: m[1], Version: v})
	}
	if len(d.Runbooks) > deployprofile.MaxRunbookRefs {
		return d, formError("at most " + strconv.Itoa(deployprofile.MaxRunbookRefs) + " runbooks")
	}
	d.SaveAs = get("save_as")
	if d.SaveAs != "" && d.ProfileSlug != "" {
		return d, formError("only an ad-hoc deployment (no profile) can be saved as a new profile")
	}
	return d, nil
}

// adHocProfile is the profile an ad-hoc deployment saves.
func (d deployForm) adHocProfile() deployprofile.Profile {
	p := deployprofile.Profile{
		Slug: d.SaveAs, Title: d.SaveAs, Image: d.Image, Size: d.Size, StorageClass: d.Storage,
		Network:   deployprofile.Network{Bridge: d.Bridge, VLAN: d.VLAN, DHCP: d.DHCP, IPAMPool: d.Pool},
		DNS:       deployprofile.DNS{Nameservers: append([]string{}, d.Nameservers...), SearchDomain: d.SearchDomain},
		Bootstrap: []deployprofile.BootstrapModule{}, Runbooks: append([]deployprofile.RunbookRef{}, d.Runbooks...),
		VaultRefs: []deployprofile.VaultRef{},
	}
	if d.DHCP {
		p.Network.IPAMPool = ""
	}
	for _, m := range d.Bootstrap {
		p.Bootstrap = append(p.Bootstrap, deployprofile.BootstrapModule{Name: m})
	}
	return p
}

// applyProfile loads the chosen profile version and takes its module and
// runbook parameters for the selected modules and runbooks.
func (h *Handler) applyProfile(ctx context.Context, d *deployForm) error {
	d.moduleParams, d.runbookParams = map[string]map[string]string{}, map[string]map[string]string{}
	if d.ProfileSlug == "" {
		return nil
	}
	if h.deployProfiles == nil {
		return formError("deploy profiles are not available")
	}
	v, err := h.deployProfiles.Get(ctx, d.ProfileSlug, d.ProfileVersion)
	if errors.Is(err, deployprofile.ErrNotFound) {
		return formError("the profile version no longer exists; reload the wizard")
	}
	if err != nil {
		return err
	}
	for _, m := range v.Profile.Bootstrap {
		d.moduleParams[m.Name] = m.Params
	}
	for _, rb := range v.Profile.Runbooks {
		d.runbookParams[rb.Slug+"@"+strconv.Itoa(rb.Version)] = rb.Params
	}
	return nil
}

// freezePlan resolves the post-enrollment plan at exact versions:
// bootstrap modules (latest imported version) in the documented order,
// then the runbooks at the chosen versions, one member per stage. A step
// that declares secret slots cannot be a batch member (the batch contract
// binds no vault reference); it is listed as a separate step instead.
func (h *Handler) freezePlan(ctx context.Context, d deployForm) ([]deployPlanStep, error) {
	var out []deployPlanStep
	if len(d.Bootstrap) > 0 {
		if h.modules == nil {
			return nil, formError("bootstrap modules are not available on this server")
		}
		latest, err := h.modules.Latest(ctx)
		if err != nil {
			return nil, err
		}
		byName := map[string]int{}
		for i, v := range latest {
			byName[v.Lock.Name] = i
		}
		for _, m := range d.Bootstrap {
			i, ok := byName[m]
			if !ok {
				return nil, formError("the bootstrap module " + m + " is not imported; import it on the modules page first")
			}
			a, ok := latest[i].Action(m + ".install")
			if !ok {
				return nil, formError("the bootstrap module " + m + " has no install action")
			}
			out = append(out, deployPlanStep{Kind: "bootstrap module", ActionID: a.ID, Version: a.Version, Title: a.Title,
				Risk: riskWord(a.Risk), Params: d.moduleParams[m], Separate: separateReason(a.Secrets)})
		}
	}
	if len(d.Runbooks) > 0 {
		if h.runbooks == nil {
			return nil, formError("runbooks are not available on this server")
		}
		for _, ref := range d.Runbooks {
			v, err := h.runbooks.Get(ctx, ref.Slug, ref.Version)
			if errors.Is(err, runbooks.ErrNotFound) {
				return nil, formError("the runbook " + ref.Slug + " version " + strconv.Itoa(ref.Version) + " does not exist")
			}
			if err != nil {
				return nil, fmt.Errorf("read runbook %s version %d: %w", ref.Slug, ref.Version, err)
			}
			a := v.Action()
			out = append(out, deployPlanStep{Kind: "runbook", ActionID: a.ID, Version: a.Version, Title: a.Title,
				Risk: riskWord(a.Risk), Params: d.runbookParams[ref.Slug+"@"+strconv.Itoa(ref.Version)], Separate: separateReason(a.Secrets)})
		}
	}
	stage := 0
	for i := range out {
		if out[i].Separate == "" {
			stage++
			out[i].Stage = stage
		}
	}
	return out, nil
}

func separateReason(secrets []string) string {
	if len(secrets) == 0 {
		return ""
	}
	return "needs the secret slot(s) " + strings.Join(secrets, ", ") + ": a batch binds no vault reference, so run it as its own operation after the batch"
}

func riskWord(r pb.RiskClass) string {
	return strings.TrimPrefix(r.String(), "RISK_CLASS_")
}

// handleDeployPropose reserves the address, freezes the plan, proposes the
// provisioning and redirects to the run page. Errors are plain text
// (formpost.js shows them as text).
func (h *Handler) handleDeployPropose(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	form, err := parseDeployForm(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user := webUser(r)
	now := h.settleDeployRuns()
	if !h.deployRuns.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(guestPowerProposeInterval/time.Second)))
		http.Error(w, "too many deployment proposals: wait a moment and try again", http.StatusTooManyRequests)
		return
	}
	if err := h.deployRuns.room(user, now); err != nil {
		http.Error(w, err.Error()+": finish or wait for earlier deployments", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	meta := h.pveMeta(ctx)
	if !remoteAllowsMutations(meta, form.Remote) {
		http.Error(w, "the PVE remote is not active: no provisioning", http.StatusConflict)
		return
	}
	if err := h.applyProfile(ctx, &form); err != nil {
		h.deployInputError(w, "deploy: profile", err)
		return
	}
	plan, err := h.freezePlan(ctx, form)
	if err != nil {
		h.deployInputError(w, "deploy: freeze plan", err)
		return
	}
	tplGen, err := h.templateGeneration(ctx, form)
	if err != nil {
		h.deployInputError(w, "deploy: template", err)
		return
	}
	id, err := newDeployRunID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// "Save as profile" is checked now and stored only once the executor
	// has proposed the deployment, so a refusal leaves no profile behind.
	if form.SaveAs != "" {
		if h.deployProfiles == nil {
			http.Error(w, "deploy profiles are not available", http.StatusConflict)
			return
		}
		if err := deployprofile.Validate(form.adHocProfile()); err != nil {
			http.Error(w, "the profile could not be saved: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	spec := &pb.PVEGuestProvisionSpec{
		RemoteId: form.Remote, Node: form.Node, Storage: form.Storage,
		Template: &pb.PVETemplateRef{RemoteId: form.Remote, Node: form.Node, Storage: form.Storage, ImageId: form.Image,
			Vmid: form.TemplateVMID, Generation: tplGen, SourceSha256: form.TemplateSHA256},
		Name: form.Name, Cores: uint32(form.Size.VCPU), MemoryMib: uint32(form.Size.RAMGiB) * 1024,
		Disk: deployDisk, DiskGib: uint64(form.Size.DiskGiB),
		Nic:    &pb.PVEProvisionNIC{Bridge: form.Bridge, Vlan: uint32(form.VLAN)},
		CiUser: form.CIUser, Nameservers: form.Nameservers, PasswordId: form.PasswordID, Start: true,
		AutomationCredentialRef: deployDefaultCredential,
	}
	if form.SearchDomain != "" {
		spec.SearchDomains = []string{form.SearchDomain}
	}
	var reserved netip.Addr
	if !form.DHCP {
		if h.deployIPAM == nil {
			http.Error(w, "IPAM reservations are not available: use DHCP", http.StatusConflict)
			return
		}
		res, err := h.deployIPAM.Reserve(ctx, user, form.Network, form.Pool, form.Address, "deployment "+form.Name+" ("+id[:8]+")")
		if errors.Is(err, ipam.ErrAddressTaken) {
			http.Error(w, "the address "+form.Address.String()+" is no longer free: reload the wizard for a new suggestion", http.StatusConflict)
			return
		}
		if err != nil {
			h.log.Error("deploy: reserve address", "network", form.Network, "error", err)
			http.Error(w, "the address could not be reserved", http.StatusConflict)
			return
		}
		reserved = res.Address
		b := &pb.PVEIPAMBinding{NetworkId: res.NetworkID, Pool: res.Pool, Prefix: res.Prefix.String(), Vlan: uint32(res.VLAN),
			Address: res.Address.String(), ReservedBy: res.By, ReservedAtUnix: res.At.Unix()}
		if res.Gateway.IsValid() {
			b.Gateway = res.Gateway.String()
		}
		spec.Ipam = b
	}
	// release clears the reservation once, bounded, when the executor
	// refused the proposal before registering a permit (proposeRefused),
	// so no guest can be created with the address.
	release := func() {
		if !reserved.IsValid() {
			return
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deployReleaseTimeout)
		defer cancel()
		if err := h.deployIPAM.ClearEntry(rctx, reserved); err != nil {
			h.log.Error("deploy: release address", "address", reserved.String(), "error", err)
		}
	}
	// keep leaves the reservation in place when the executor may hold a
	// permit for the execution (the outcome of the call is unknown, or it
	// answered with a proposal this page refuses): an admin may approve
	// and commit it out of band, and the guest would use the address. It
	// returns the note for the user.
	keep := func(execution string) string {
		if !reserved.IsValid() {
			return ""
		}
		h.log.Warn("audit", "kind", "deployment_address_kept", "address", reserved.String(), "execution", execution, "user", user)
		return "; the address " + reserved.String() + " stays reserved because the executor may hold a permit for this deployment: clear it on the network page once no guest uses it"
	}
	resp, err := h.deploy.ProposePVEGuestProvision(ctx, &pb.ProposePVEGuestProvisionRequest{Spec: spec})
	if err != nil {
		if proposeRefused(err) {
			release()
			h.guestPowerRefusal(w, "propose guest provision", err)
			return
		}
		h.log.Error("propose guest provision", "error", err)
		// Any other answer keeps the address; a refusal is still shown as
		// such.
		st, _ := status.FromError(err)
		switch st.Code() {
		case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted,
			codes.AlreadyExists, codes.NotFound, codes.Aborted:
			http.Error(w, "the executor refused: "+cleanText(st.Message())+keep(""), http.StatusConflict)
		default:
			http.Error(w, "the executor did not confirm the proposal (unavailable or busy); its outcome is unknown"+keep(""), http.StatusBadGateway)
		}
		return
	}
	run := &deployRun{id: id, user: user, created: now, form: form, spec: spec, ipam: spec.GetIpam(), plan: plan,
		executionID: cleanText(resp.GetExecutionId()), vmid: resp.GetVmid(), state: deployProposed, expires: now.Add(deployRunTTL)}
	for i, s := range resp.GetCapacityWarnings() {
		if i >= maxGuestPowerSteps {
			break
		}
		run.warnings = append(run.warnings, cleanText(s))
	}
	perm := resp.GetPermit()
	digest := perm.GetExecutionDigest()
	risk := riskWord(perm.GetRiskClass())
	if !guestPowerDigestRe.MatchString(digest) || perm.GetRiskClass() == pb.RiskClass_RISK_CLASS_UNSPECIFIED || strings.HasPrefix(risk, "RISK") ||
		run.vmid == 0 || run.executionID == "" {
		http.Error(w, "the executor returned no usable proposal"+keep(run.executionID), http.StatusBadGateway)
		return
	}
	bound, err := parseGuestPowerCanonical(perm.GetCanonicalRequest(), digest)
	if err != nil {
		h.log.Error("deploy: unusable canonical request", "remote", form.Remote, "error", err)
		http.Error(w, err.Error()+": the proposal is refused, nothing can be approved here"+keep(run.executionID), http.StatusBadGateway)
		return
	}
	run.bound, run.digest, run.risk = bound, digest, risk
	run.mismatch = deployMismatch(bound, form, risk, meta[form.Remote].TrustPin, run.executionID, now)
	run.requirement = requirementText(perm.GetApprovalRequirement())
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		run.options = string(opts)
	}
	if e := perm.GetChallengeExpiryUnix(); e > 0 {
		run.challengeAt = time.Unix(e, 0)
	}
	if run.requirement == "key" && run.options == "" && len(run.mismatch) == 0 {
		http.Error(w, "the executor returned no approval challenge"+keep(run.executionID), http.StatusBadGateway)
		return
	}
	// Commit presents the proposed spec with the reserved VMID; the
	// proposal request itself stays as sent.
	run.spec = proto.Clone(spec).(*pb.PVEGuestProvisionSpec)
	run.spec.Vmid = run.vmid
	// The proposal ends with the executor's bound request; one without an
	// expiry (never approvable) ends after deployProposalWindow.
	run.deadline = bound.Expiry
	if run.deadline.IsZero() {
		run.deadline = now.Add(deployProposalWindow)
	} else if run.deadline.After(now.Add(deployRunTTL)) {
		run.deadline = now.Add(deployRunTTL)
	}
	if form.SaveAs != "" {
		saved, err := h.deployProfiles.Save(ctx, user, form.adHocProfile())
		var ie *deployprofile.InvalidError
		switch {
		case errors.As(err, &ie):
			http.Error(w, "the profile could not be saved: "+ie.Error()+keep(run.executionID), http.StatusBadRequest)
			return
		case err != nil:
			h.log.Error("deploy: save ad-hoc profile", "error", err)
			http.Error(w, "the profile could not be saved"+keep(run.executionID), http.StatusInternalServerError)
			return
		}
		run.form.ProfileSlug, run.form.ProfileVersion = saved.Profile.Slug, saved.Version
		h.log.Info("audit", "kind", "deploy_profile_saved", "profile", saved.Profile.Slug, "version", saved.Version, "user", user)
	}
	if err := h.deployRuns.put(run, now); err != nil {
		http.Error(w, err.Error()+keep(run.executionID), http.StatusServiceUnavailable)
		return
	}
	if len(run.mismatch) > 0 {
		h.log.Error("deploy: executor binding differs from the request", "remote", form.Remote, "mismatch", strings.Join(run.mismatch, "; "))
	}
	h.log.Info("audit", "kind", "deployment_proposed", "run", id, "remote", form.Remote, "node", form.Node,
		"name", form.Name, "vmid", run.vmid, "risk", risk, "user", user)
	http.Redirect(w, r, "/deployments/"+id, http.StatusSeeOther)
}

// proposeSpecRefusal is the status message of the executor's one
// propose refusal this page releases an address for: InvalidArgument from
// pveGuestProvisionRPCError (internal/executor/pve_rpc.go). The executor
// returns it only from the request decoding and the provisioner's proposal
// request, both before the authority registers a permit; the step after
// the registration (the permit response) fails with Internal only.
const proposeSpecRefusal = "pve guest provision: invalid or unsupported spec, template, network, key or password id"

// proposeRefused reports whether a ProposePVEGuestProvision error proves
// that the executor holds no permit for the proposal, so the address can
// be released. It is an allowlist of exactly one answer: the executor's
// spec refusal (proposeSpecRefusal), sent as such or mapped by
// executorclient as invalid_request. Everything else keeps the address:
// any other code (a lost response, a timeout, a permit or authority
// refusal, an executor-defined code), a refusal the client reports as a
// deadline, an error wrapped with other text and a non-status error. The
// response step after the registration in particular (Internal) may leave
// an approvable permit whose VMID release failed. Leaking a reservation is
// acceptable; releasing an address a guest may use is not.
func proposeRefused(err error) bool {
	var ce *executorclient.Error
	if errors.As(err, &ce) {
		if !errors.Is(ce, executorclient.ErrInvalidRequest) || ce.Detail != proposeSpecRefusal {
			return false
		}
		err = ce.Unwrap()
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.InvalidArgument && st.Message() == proposeSpecRefusal
}

// deployInputError answers a form error as 400 and anything else as 500.
func (h *Handler) deployInputError(w http.ResponseWriter, op string, err error) {
	var fe formError
	if errors.As(err, &fe) {
		http.Error(w, fe.Error(), http.StatusBadRequest)
		return
	}
	h.log.Error(op, "error", err)
	http.Error(w, "the deployment could not be prepared", http.StatusInternalServerError)
}

// templateGeneration is the stored incarnation of the chosen template on
// the target node; the executor checks it against its template record.
func (h *Handler) templateGeneration(ctx context.Context, d deployForm) (uint64, error) {
	guests, err := h.pve.ListGuests(ctx, d.Remote, pveinventory.GuestFilter{VMID: d.TemplateVMID}, 0)
	if err != nil {
		return 0, err
	}
	for _, g := range guests {
		if g.VMID == d.TemplateVMID && !g.Tombstoned {
			if g.Node != d.Node || g.Kind != guestKindQEMU {
				return 0, formError("the template is not a QEMU guest on node " + d.Node)
			}
			return g.Generation, nil
		}
	}
	return 0, formError("the template VMID is not in the PVE inventory of this remote")
}

// deployMismatch lists every difference between what the executor bound
// and what was requested: the action, the node target under the remote's
// current trust pin, the risk, the execution and the expiry.
func deployMismatch(b guestPowerBinding, d deployForm, risk, trustPin, executionID string, now time.Time) []string {
	var out []string
	if b.ActionID != "pve.guest.provision" {
		out = append(out, "the executor bound a different action ("+cleanText(b.ActionID)+")")
	}
	if rq, ok := canonicalExecution(b); ok && rq != executionID {
		out = append(out, "the executor bound a different execution than it reported")
	}
	return append(out, guestTargetMismatch(b, guestRef{remote: d.Remote, kind: "node", node: d.Node}, risk, trustPin, now)...)
}

// canonicalExecution reads the execution ID of a shown canonical request.
func canonicalExecution(b guestPowerBinding) (string, bool) {
	var rq struct {
		ExecutionID string `json:"execution_id"`
	}
	if err := json.Unmarshal([]byte(b.Canonical), &rq); err != nil || rq.ExecutionID == "" {
		return "", false
	}
	return rq.ExecutionID, true
}

// ---- Approval and provisioning --------------------------------------------

// handleDeployApprove relays the security key assertion for the
// provisioning (schedules.js posts {id, assertion}) and starts the run.
func (h *Handler) handleDeployApprove(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
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
	now := h.settleDeployRuns()
	if !deployRunIDRe.MatchString(in.ID) || len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusNotFound, "deployment not found")
		return
	}
	run, ok := h.deployRuns.update(user, in.ID, func(x *deployRun) bool { return x.requirement == "key" && x.approvable(now) },
		func(x *deployRun) { x.approving, x.message = true, "" })
	if !ok {
		writeJSONError(w, http.StatusNotFound, "deployment not found or not waiting for approval")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if _, err := h.deploy.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: run.digest, AssertionJson: in.Assertion}); err != nil {
		h.deployRuns.set(run.id, func(x *deployRun) { x.approving = false })
		h.assertionRefusal(w, "approve deployment", err)
		return
	}
	h.deployRuns.set(run.id, func(x *deployRun) { x.approving, x.state = false, deployApproved })
	h.log.Info("audit", "kind", "deployment_approved", "run", run.id, "user", user)
	h.startDeployCommit(r, run)
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// assertionRefusal answers a SubmitAssertion error as JSON.
func (h *Handler) assertionRefusal(w http.ResponseWriter, op string, err error) {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		writeJSONError(w, http.StatusForbidden, "security key not accepted")
	case codes.InvalidArgument, codes.FailedPrecondition, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound, codes.Aborted:
		writeJSONError(w, http.StatusConflict, "the executor refused: "+cleanText(status.Convert(err).Message()))
	default:
		h.log.Error(op, "error", err)
		writeJSONError(w, http.StatusBadGateway, "executor unavailable")
	}
}

// handleDeployRun runs a provisioning approved with `nebula approve`
// (hardened mode or a typed count); the executor refuses an unapproved
// permit.
func (h *Handler) handleDeployRun(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("id")
	user := webUser(r)
	now := h.settleDeployRuns()
	run, ok := h.deployRuns.update(user, id, func(x *deployRun) bool { return x.requirement != "key" && x.approvable(now) },
		func(x *deployRun) { x.state, x.message = deployApproved, "" })
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.log.Info("audit", "kind", "deployment_run", "run", run.id, "user", user)
	h.startDeployCommit(r, run)
	http.Redirect(w, r, "/deployments/"+id, http.StatusSeeOther)
}

// startDeployCommit runs the approved provisioning in the background: the
// executor waits for the clone, config, resize and start tasks.
func (h *Handler) startDeployCommit(r *http.Request, run deployRun) {
	ctx := context.WithoutCancel(r.Context())
	h.deployRuns.set(run.id, func(x *deployRun) { x.state = deployCreating })
	go func() {
		ctx, cancel := context.WithTimeout(ctx, deployCommitTimeout)
		defer cancel()
		resp, err := h.deploy.CommitPVEGuestProvision(ctx, &pb.CommitPVEGuestProvisionRequest{Spec: run.spec,
			ExecutionId: run.executionID, ExecutionDigest: run.digest})
		now := h.clockNow()
		if err != nil {
			st, _ := status.FromError(err)
			switch st.Code() {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound, codes.Aborted:
				// A refusal: this call sent no PVE step. No refusal
				// rules out that an earlier run of the same execution
				// (another commit, for example by an admin with the CLI)
				// created the guest: InvalidArgument is not only request
				// validation (the executor also wraps automation key
				// lookup errors in it and answers one fixed text for every
				// cause), PermissionDenied also means the permit was
				// already used or is final, FailedPrecondition also means
				// the VMID now exists, NotFound a remote or key removed
				// after a run, Aborted a concurrent change. So the address
				// always stays reserved (a leaked reservation is safe, a
				// released address in use is not).
				msg := "the executor refused: " + cleanText(st.Message())
				h.deployRuns.set(run.id, func(x *deployRun) {
					x.message = msg
					if x.ipam != nil {
						x.address = ipamKept
						x.message += "; the address " + x.ipam.GetAddress() + " stays reserved because an earlier run of this execution may have created the guest"
					}
					if run.requirement != "key" && (st.Code() == codes.PermissionDenied || st.Code() == codes.FailedPrecondition) {
						// Approve with the CLI, then run again. The address
						// is kept (above), so an expiry does not release it.
						x.state = deployProposed
						return
					}
					x.state, x.failedIn, x.expires = deployFailed, deployCreating, now.Add(deployRunTTL)
				})
			default:
				// Outcome unknown: a guest may exist and use the address.
				h.log.Error("commit guest provision", "run", run.id, "error", err)
				h.deployRuns.set(run.id, func(x *deployRun) {
					x.state, x.failedIn, x.expires = deployFailed, deployCreating, now.Add(deployRunTTL)
					x.message = "the run could not be confirmed (executor unavailable); check the executor's job list before deploying again"
					if x.ipam != nil {
						x.address = ipamKept
						x.message += "; the address " + x.ipam.GetAddress() + " stays reserved because the guest may exist"
					}
				})
			}
			return
		}
		var steps []guestPowerStepView
		failed := false
		for i, s := range resp.GetSteps() {
			if i >= maxGuestPowerSteps {
				break
			}
			v := guestPowerStepView{State: cleanText(s.GetState()), UPID: cleanText(s.GetUpid()), TaskType: cleanText(s.GetTaskType())}
			failed = failed || v.State != "succeeded"
			steps = append(steps, v)
		}
		h.deployRuns.set(run.id, func(x *deployRun) {
			x.steps, x.guestKept = steps, resp.GetGuestKept()
			if failed || resp.GetGuestKept() || len(steps) == 0 {
				x.state, x.failedIn, x.expires = deployFailed, deployCreating, now.Add(deployRunTTL)
				x.message = "provisioning did not complete; the guest (if created) is left in PVE for inspection, deleting it is a separate action"
				if x.ipam != nil {
					x.address = ipamKept
					x.message += "; its address " + x.ipam.GetAddress() + " stays reserved"
				}
				return
			}
			x.state, x.deadline = deployBooting, now.Add(deployEnrollWindow)
		})
		h.log.Info("audit", "kind", "deployment_provisioned", "run", run.id, "vmid", run.vmid, "failed", failed)
	}()
}

// ---- Enrollment -----------------------------------------------------------

// handleDeployJoin proposes the enrollment of the provisioned guest once
// the PVE inventory has observed it (form: id, and endpoint for a DHCP
// guest). The run page then shows the fingerprint for review.
func (h *Handler) handleDeployJoin(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if h.deployJoin == nil {
		http.Error(w, "enrollment is not available on this server", http.StatusConflict)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	h.settleDeployRuns()
	id := r.PostForm.Get("id")
	user := webUser(r)
	run, ok := h.deployRuns.get(user, id)
	if !ok || (run.state != deployBooting && run.state != deployEnrolling) || (run.join != nil && run.join.approving) {
		http.NotFound(w, r)
		return
	}
	endpoint := ""
	if run.ipam != nil {
		endpoint = run.ipam.GetAddress()
	} else {
		a, err := netip.ParseAddr(strings.TrimSpace(r.PostForm.Get("endpoint")))
		a = a.Unmap()
		// Only a usable unicast guest address: no loopback, unspecified,
		// multicast, link-local or broadcast address reaches the probe.
		if err != nil || a.Zone() != "" || !a.IsGlobalUnicast() {
			http.Error(w, "enter the guest's IP address (its DHCP lease, a unicast address) for the SSH enrollment", http.StatusBadRequest)
			return
		}
		endpoint = a.String()
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	g, err := h.provisionedGuest(ctx, run)
	if err != nil {
		h.deployInputError(w, "deploy: read provisioned guest", err)
		return
	}
	resp, err := h.deployJoin.Propose(ctx, pveinventory.GuestJoinProposal{
		RemoteID: run.form.Remote, Node: run.form.Node, VMID: run.vmid, Generation: g.Generation, GuestName: run.form.Name,
		HostID: run.form.Name, Endpoint: endpoint, SSHUser: run.form.CIUser, CredentialRef: deployDefaultCredential,
	})
	if err != nil {
		if _, isStatus := status.FromError(err); isStatus && status.Code(err) != codes.Unknown {
			h.guestPowerRefusal(w, "propose guest join", err)
			return
		}
		if errors.Is(err, inventory.ErrHostExists) {
			http.Error(w, "a host named "+run.form.Name+" already exists in the inventory: the guest cannot be enrolled under that ID", http.StatusConflict)
			return
		}
		h.log.Error("deploy: propose guest join", "run", run.id, "error", err)
		http.Error(w, "the enrollment could not be proposed: the guest or host changed (reload and check the inventory)", http.StatusConflict)
		return
	}
	j, err := h.checkJoin(resp, run, endpoint, g.Generation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if _, ok := h.deployRuns.update(user, id, func(x *deployRun) bool {
		return (x.state == deployBooting || x.state == deployEnrolling) && (x.join == nil || !x.join.approving)
	}, func(x *deployRun) { x.state, x.join, x.message = deployEnrolling, j, "" }); !ok {
		http.Error(w, "the deployment changed", http.StatusConflict)
		return
	}
	h.log.Info("audit", "kind", "deployment_join_proposed", "run", run.id, "host", run.form.Name, "method", j.resp.GetJoinMethod(), "user", user)
	http.Redirect(w, r, "/deployments/"+id, http.StatusSeeOther)
}

// provisionedGuest is the stored incarnation of the run's new guest: the
// VMID the executor reserved, on the run's node, with its name.
func (h *Handler) provisionedGuest(ctx context.Context, run deployRun) (pveinventory.Guest, error) {
	guests, err := h.pve.ListGuests(ctx, run.form.Remote, pveinventory.GuestFilter{VMID: run.vmid}, 0)
	if err != nil {
		return pveinventory.Guest{}, err
	}
	for _, g := range guests {
		if g.VMID != run.vmid || g.Tombstoned {
			continue
		}
		if g.Node != run.form.Node || g.Name != run.form.Name || g.Kind != guestKindQEMU {
			return pveinventory.Guest{}, formError("the guest with VMID " + strconv.FormatUint(run.vmid, 10) + " is not the provisioned guest (another node, name or kind)")
		}
		return g, nil
	}
	return pveinventory.Guest{}, formError("the new guest is not in the PVE inventory yet: wait for the next PVE collection, then try again")
}

// checkJoin checks the executor's enrollment proposal against what was
// requested and shows its binding: the host, the endpoint, the guest and
// the reviewed fingerprint must be exactly the run's.
func (h *Handler) checkJoin(resp *pb.ProposeGuestJoinResponse, run deployRun, endpoint string, generation uint64) (*deployJoin, error) {
	perm := resp.GetPermit()
	digest := perm.GetExecutionDigest()
	risk := riskWord(perm.GetRiskClass())
	if !guestPowerDigestRe.MatchString(digest) || perm.GetRiskClass() == pb.RiskClass_RISK_CLASS_UNSPECIFIED || strings.HasPrefix(risk, "RISK") {
		return nil, errors.New("the executor returned no usable enrollment proposal")
	}
	bound, err := parseGuestPowerCanonical(perm.GetCanonicalRequest(), digest)
	if err != nil {
		return nil, errors.New(err.Error() + ": the enrollment is refused, nothing can be approved")
	}
	j := &deployJoin{resp: resp, bound: bound, digest: digest, risk: risk, requirement: requirementText(perm.GetApprovalRequirement()),
		generation: generation, endpoint: endpoint}
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		j.options = string(opts)
	}
	host, guest := resp.GetHost(), resp.GetGuest()
	switch m := resp.GetJoinMethod(); {
	case m != pveinventory.JoinMethodAgent && m != pveinventory.JoinMethodReview:
		j.mismatch = append(j.mismatch, "the executor named an unknown join method")
	}
	if host.GetHostId() != run.form.Name || bound.TargetID != run.form.Name {
		j.mismatch = append(j.mismatch, "the executor bound another host than "+run.form.Name)
	}
	if fp := host.GetFingerprint(); fp == "" || bound.Fingerprint != fp {
		j.mismatch = append(j.mismatch, "the bound host key is not the fingerprint shown for review")
	}
	if ep := host.GetEndpoint(); ep != endpoint && ep != net.JoinHostPort(endpoint, strconv.Itoa(deploySSHPort)) {
		j.mismatch = append(j.mismatch, "the executor bound another endpoint than "+endpoint)
	}
	if guest.GetRemoteId() != run.form.Remote || guest.GetNode() != run.form.Node || guest.GetVmid() != run.vmid ||
		guest.GetGeneration() != generation || guest.GetGuestName() != run.form.Name {
		j.mismatch = append(j.mismatch, "the executor bound another guest than the provisioned one")
	}
	if host.GetCredentialRef() != deployDefaultCredential {
		j.mismatch = append(j.mismatch, "the executor bound another credential than the automation key")
	}
	if bound.Risk != risk {
		j.mismatch = append(j.mismatch, "the risk in the bound request differs from the executor's answer")
	}
	if bound.Expiry.IsZero() || !h.clockNow().Before(bound.Expiry) {
		j.mismatch = append(j.mismatch, "the bound enrollment request has no expiry or has expired")
	}
	if j.requirement == "key" && j.options == "" && len(j.mismatch) == 0 {
		return nil, errors.New("the executor returned no approval challenge for the enrollment")
	}
	return j, nil
}

// handleDeployJoinApprove relays the assertion for the enrollment and
// commits it: the executor pins the reviewed key, then the inventory host
// and its guest link are created from the committed binding.
func (h *Handler) handleDeployJoinApprove(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if h.deployJoin == nil {
		http.NotFound(w, r)
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
	if !deployRunIDRe.MatchString(in.ID) || len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusNotFound, "deployment not found")
		return
	}
	h.settleDeployRuns()
	run, ok := h.deployRuns.update(user, in.ID, joinApprovable("key"), func(x *deployRun) { x.join.approving, x.message = true, "" })
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no enrollment waiting for approval")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if _, err := h.deploy.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: run.join.digest, AssertionJson: in.Assertion}); err != nil {
		h.deployRuns.set(run.id, func(x *deployRun) { x.join.approving = false })
		h.assertionRefusal(w, "approve guest join", err)
		return
	}
	h.log.Info("audit", "kind", "deployment_join_approved", "run", run.id, "host", run.form.Name, "user", user)
	if err := h.commitDeployJoin(r, run, user); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// handleDeployJoinRun commits a CLI-approved enrollment.
func (h *Handler) handleDeployJoinRun(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if h.deployJoin == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("id")
	user := webUser(r)
	h.settleDeployRuns()
	run, ok := h.deployRuns.update(user, id, joinApprovable("cli"), func(x *deployRun) { x.join.approving, x.message = true, "" })
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := h.commitDeployJoin(r, run, user); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/deployments/"+id, http.StatusSeeOther)
}

// joinApprovable selects a run whose enrollment waits for approval of the
// given kind ("key", or "cli" for the CLI and typed-count requirements).
func joinApprovable(kind string) func(*deployRun) bool {
	return func(x *deployRun) bool {
		j := x.join
		if x.state != deployEnrolling || j == nil || j.approving || len(j.mismatch) > 0 {
			return false
		}
		if kind == "key" {
			return j.requirement == "key"
		}
		return j.requirement != "key"
	}
}

// commitDeployJoin commits the approved enrollment and moves the run on.
// A refusal leaves the enrollment proposal for another attempt.
func (h *Handler) commitDeployJoin(r *http.Request, run deployRun, user string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), deployJoinTimeout)
	defer cancel()
	host := inventory.Host{ID: run.form.Name, DisplayName: run.form.Name, Environment: inventory.Environment(run.form.Environment),
		Endpoints: []inventory.Endpoint{{Address: run.join.endpoint, Port: deploySSHPort}}, CredentialRef: deployDefaultCredential}
	res, err := h.deployJoin.Commit(ctx, run.join.resp, host, user)
	now := h.clockNow()
	if err != nil {
		msg := "the enrollment was not committed: "
		switch {
		case errors.Is(err, pveinventory.ErrJoinNotPinned):
			msg += "the executor did not pin the reviewed host key; nothing was created"
		case status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.FailedPrecondition:
			msg += "the executor refused: " + cleanText(status.Convert(err).Message())
		default:
			h.log.Error("deploy: commit guest join", "run", run.id, "error", err)
			msg += "the guest, host or binding changed; check the inventory, then propose the enrollment again"
		}
		h.deployRuns.set(run.id, func(x *deployRun) {
			if x.join != nil {
				x.join.approving = false
			}
			x.message = msg
		})
		return errors.New(msg)
	}
	batches := h.deployBatches != nil
	h.deployRuns.set(run.id, func(x *deployRun) {
		x.joined, x.join.approving, x.message = &res, false, ""
		switch {
		case !hasBatchSteps(x.plan):
			x.state, x.expires = deployDone, now.Add(deployRunTTL)
		case !batches:
			// No batch planner on this server: the run ends enrolled
			// instead of waiting in bootstrapping for a plan that can
			// never be proposed.
			x.state, x.expires = deployJoined, now.Add(deployRunTTL)
			x.message = deployNoBatchesMessage
		default:
			x.state, x.deadline = deployBootstrapping, now.Add(deployBootstrapWindow)
		}
	})
	h.log.Info("audit", "kind", "deployment_joined", "run", run.id, "host", res.Host.ID, "fingerprint", res.Fingerprint,
		"method", res.JoinMethod, "user", user)
	return nil
}

// deployNoBatchesMessage explains a run that ended at "joined".
const deployNoBatchesMessage = "bootstrap steps not available: this server has no batch planner, so the staged plan was not run; " +
	"the guest is enrolled, run the plan's steps as separate operations on the host"

func hasBatchSteps(plan []deployPlanStep) bool {
	for _, s := range plan {
		if s.Stage > 0 {
			return true
		}
	}
	return false
}

// ---- Staged plan ----------------------------------------------------------

// batchRequest is the frozen plan as one batch: one member per stage,
// automatic gates, zero thresholds (stop on the first failure).
func (x *deployRun) batchRequest() executions.BatchRequest {
	var req executions.BatchRequest
	for _, s := range x.plan {
		if s.Stage == 0 {
			continue
		}
		req.Stages = append(req.Stages, executions.BatchStageSpec{Gate: "automatic", Members: []executions.BatchMemberSpec{
			{ActionID: s.ActionID, Version: s.Version, HostID: x.form.Name, Params: s.Params}}})
	}
	return req
}

// handleDeployPlan proposes the staged bootstrap/runbook plan as one
// batch and redirects to the batch page for its single approval.
func (h *Handler) handleDeployPlan(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	if h.deployBatches == nil {
		http.Error(w, "batches are not available on this server", http.StatusConflict)
		return
	}
	h.settleDeployRuns()
	id := r.PostForm.Get("id")
	user := webUser(r)
	run, ok := h.deployRuns.update(user, id, func(x *deployRun) bool {
		return x.state == deployBootstrapping && x.batchID == "" && x.joined != nil && !x.approving
	}, func(x *deployRun) { x.approving = true })
	if !ok {
		http.NotFound(w, r)
		return
	}
	defer h.deployRuns.set(run.id, func(x *deployRun) { x.approving = false })
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	c, err := h.deployBatches.ProposeBatch(ctx, user, run.batchRequest())
	if err != nil {
		var ie *executions.BatchInputError
		var he *executions.HostError
		msg := "the staged plan could not be proposed"
		switch {
		case errors.As(err, &ie):
			msg += ": " + cleanText(ie.Reason)
		case errors.As(err, &he):
			msg += ": " + cleanText(he.Error())
		case errors.Is(err, executions.ErrBatchCritical):
			msg += ": " + cleanText(err.Error())
		default:
			h.log.Error("deploy: propose staged plan", "run", run.id, "error", err)
		}
		h.deployRuns.set(run.id, func(x *deployRun) { x.batchErr = msg })
		http.Error(w, msg, http.StatusConflict)
		return
	}
	h.deployRuns.set(run.id, func(x *deployRun) { x.batchID, x.batchErr = c.ID, "" })
	h.log.Info("audit", "kind", "deployment_plan_proposed", "run", run.id, "batch", c.ID, "user", user)
	http.Redirect(w, r, "/batches/"+url.PathEscape(c.ID), http.StatusSeeOther)
}

// followBatch moves a bootstrapping run on from its batch:
//
//   - every member succeeded: done;
//   - no member is open any more and at least one was started (ran,
//     failed, is unknown or was skipped): failed;
//   - the batch ended (refused, expired, or past its approval or run
//     expiry plus deployBatchGrace) before any member was dispatched:
//     nothing ran, so the batch is detached and the frozen plan may be
//     proposed again for a fresh approval (ADR 0007: a retry is a new
//     batch); the bootstrapping deadline still bounds the run;
//   - the batch ended after some members ran while others never will:
//     failed, the remaining steps were not executed.
//
// A batch with a dispatched member is never decided here: its outcome
// is still open.
func (h *Handler) followBatch(ctx context.Context, run *deployRun) *executions.BatchView {
	if run.batchID == "" || h.deployBatches == nil {
		return nil
	}
	v, err := h.deployBatches.Batch(ctx, run.batchID)
	if err != nil {
		h.log.Error("deploy: read staged plan batch", "batch", run.batchID, "error", err)
		return nil
	}
	if run.state != deployBootstrapping {
		return &v
	}
	now := h.clockNow()
	c := v.Counts
	open := c.Planned + c.Dispatched
	started := c.Dispatched + c.Success + c.Failed + c.Unknown + c.Skipped
	ended := (v.State != "pending" && v.State != "approved") ||
		(!v.Expiry.IsZero() && !now.Before(v.Expiry.Add(deployBatchGrace))) ||
		(v.State == "pending" && !v.ApprovalExpiry.IsZero() && !now.Before(v.ApprovalExpiry.Add(deployBatchGrace)))
	state, msg, detach := "", "", false
	switch {
	case c.Total > 0 && c.Success == c.Total:
		state = deployDone
	case c.Total == 0 || c.Dispatched > 0:
	case started == 0 && (ended || open == 0):
		detach = true
		msg = "the batch " + run.batchID + " ended (" + cleanText(v.State) + ") before any step ran: nothing was executed; propose the staged plan again for a fresh approval"
	case open == 0:
		state = deployFailed
	case ended:
		state = deployFailed
		msg = "the batch " + run.batchID + " ended (" + cleanText(v.State) + ") after some steps ran; the remaining steps were not executed"
	}
	if state == "" && !detach {
		return &v
	}
	id := run.batchID
	h.deployRuns.set(run.id, func(x *deployRun) {
		if x.state != deployBootstrapping || x.batchID != id {
			return
		}
		if detach {
			x.batchID, x.batchErr = "", msg
			return
		}
		x.state, x.expires = state, now.Add(deployRunTTL)
		if state == deployFailed {
			x.failedIn = deployBootstrapping
			if msg != "" {
				x.message = msg
			}
		}
	})
	if detach {
		run.batchID, run.batchErr = "", msg
		return nil
	}
	run.state = state
	if state == deployFailed {
		run.failedIn = deployBootstrapping
		if msg != "" {
			run.message = msg
		}
	}
	return &v
}

// ---- Pages ----------------------------------------------------------------

// DeployHere reports whether the chart offers "Deploy here" on the nodes
// of remoteID.
func (d pageData) DeployHere(remoteID string) bool { return d.DeployRemotes[remoteID] }

// DeployURL is the wizard link with the node's remote and node
// preselected ("Deploy here").
func (n pveNodeView) DeployURL() string {
	return "/deployments/new?" + url.Values{"remote": {n.remoteID}, "node": {n.Name}}.Encode()
}

// deployRunRow is one row of the run list.
type deployRunRow struct {
	ID, Name, Remote, Node, State, StateClass, Risk string
	VMID                                            uint64
	Created                                         time.Time
}

// deployStateView is one step of the state line.
type deployStateView struct {
	Label, Class string
}

// deployRunData is the data of the run page.
type deployRunData struct {
	ID, State, StateClass, Message string
	States                         []deployStateView
	Form                           deployForm
	Size                           string
	IP                             string
	Gateway                        string
	VMID                           uint64
	ExecutionID                    string
	Plan                           []deployPlanStep
	Separate                       []deployPlanStep
	Warnings                       []string

	// Review: the executor's binding and risk.
	Bound           guestPowerBinding
	Mismatch        []string
	Expired         bool
	Digest          string
	Risk, RiskClass string
	Approving       bool
	Options         string
	CLICommand      string
	TypedCount      bool
	ChallengeExpiry time.Time

	// Provisioning outcome.
	Steps     []guestPowerStepView
	GuestKept bool
	TaskLink  string
	GuestLink string

	// Enrollment.
	NeedEndpoint bool
	Join         *deployJoinView
	Joined       *pveinventory.GuestJoinResult

	// Staged plan.
	BatchID    string
	BatchError string
	Batch      *executions.BatchView
}

// deployJoinView is the fingerprint review of the enrollment.
type deployJoinView struct {
	Method, AgentDetail, HostID, Endpoint, SSHUser, CredentialRef string
	Fingerprint, KeyType, Digest, Risk, RiskClass                 string
	Generation                                                    uint64
	Bound                                                         guestPowerBinding
	Mismatch                                                      []string
	Options, CLICommand                                           string
	Approving                                                     bool
}

func deployStateClass(state string) string {
	switch state {
	case deployDone:
		return "badge--ok"
	case deployFailed:
		return "badge--critical"
	case deployProposed, deployEnrolling, deployJoined:
		return "badge--warning"
	default:
		return "badge--unknown"
	}
}

// handleDeployRuns lists the user's deployment runs.
func (h *Handler) handleDeployRuns(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	var rows []deployRunRow
	for _, x := range h.deployRuns.list(webUser(r), h.settleDeployRuns()) {
		rows = append(rows, deployRunRow{ID: x.id, Name: x.form.Name, Remote: x.form.Remote, Node: x.form.Node,
			State: x.state, StateClass: deployStateClass(x.state), Risk: x.risk, VMID: x.vmid, Created: x.created.UTC()})
	}
	h.render(w, r, pageData{Title: "Deployment runs", Active: "deploy", Content: "deploy_runs", DeployRuns: rows})
}

// handleDeployRunPage shows one run to its proposer.
func (h *Handler) handleDeployRunPage(w http.ResponseWriter, r *http.Request) {
	if !h.deployEnabled(w, r) {
		return
	}
	id := r.PathValue("id")
	if !deployRunIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	now := h.settleDeployRuns()
	run, ok := h.deployRuns.get(webUser(r), id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	batch := h.followBatch(ctx, &run)
	d := &deployRunData{ID: run.id, State: run.state, StateClass: deployStateClass(run.state), Message: run.message,
		Form: run.form, Size: sizeLabel(run.form.Size), VMID: run.vmid, ExecutionID: run.executionID, Warnings: run.warnings,
		Bound: run.bound, Mismatch: run.mismatch, Digest: run.digest, Risk: run.risk, RiskClass: riskBadgeClass(run.risk),
		Approving: run.approving, ChallengeExpiry: run.challengeAt, Steps: run.steps, GuestKept: run.guestKept,
		Joined: run.joined, BatchID: run.batchID, BatchError: run.batchErr, Batch: batch,
		NeedEndpoint: run.ipam == nil}
	if run.form.Size.Preset != "" {
		d.Size = run.form.Size.Preset + " (" + sizeLabel(deployprofile.Size{VCPU: run.form.Size.VCPU, RAMGiB: run.form.Size.RAMGiB, DiskGiB: run.form.Size.DiskGiB}) + ")"
	}
	if b := run.ipam; b != nil {
		d.IP = b.GetAddress() + " in " + b.GetPrefix() + " (IPAM network " + b.GetNetworkId()
		if b.GetPool() != "" {
			d.IP += ", pool " + b.GetPool()
		}
		d.IP += ", reserved)"
		d.Gateway = b.GetGateway()
	} else {
		d.IP = "DHCP"
	}
	for _, s := range run.plan {
		if s.Stage == 0 {
			d.Separate = append(d.Separate, s)
		} else {
			d.Plan = append(d.Plan, s)
		}
	}
	d.States = deployStateLine(run.state, run.failedIn)
	d.Expired = run.state == deployProposed && len(run.mismatch) == 0 && !now.Before(run.bound.Expiry)
	data := pageData{Title: "Deployment " + run.form.Name, Active: "deploy", Content: "deploy_run", DeployRun: d}
	if run.approvable(now) {
		if run.requirement == "key" {
			d.Options = run.options
			data.Scripts = []string{"webauthn.js", "schedules.js"}
		} else {
			d.CLICommand = deployCLICommand + run.digest
			d.TypedCount = run.requirement == "typed_count"
			data.Scripts = []string{"formpost.js"}
		}
	}
	meta := h.pveMeta(ctx)
	if m, ok := meta[run.form.Remote]; ok {
		d.TaskLink = pveDeepLink(m.Kind, m.Endpoints, run.form.Node)
		if run.vmid != 0 && run.state != deployProposed {
			d.GuestLink = pveDeepLink(m.Kind, m.Endpoints, run.form.Node, "qemu", strconv.FormatUint(run.vmid, 10))
		}
	}
	if j := run.join; j != nil && run.state == deployEnrolling {
		host := j.resp.GetHost()
		jv := &deployJoinView{Method: cleanText(j.resp.GetJoinMethod()), AgentDetail: cleanText(j.resp.GetAgentDetail()),
			HostID: cleanText(host.GetHostId()), Endpoint: cleanText(host.GetEndpoint()), SSHUser: cleanText(host.GetSshUser()),
			CredentialRef: cleanText(host.GetCredentialRef()), Fingerprint: cleanText(host.GetFingerprint()), KeyType: cleanText(host.GetKeyType()),
			Digest: j.digest, Risk: j.risk, RiskClass: riskBadgeClass(j.risk), Generation: j.generation, Bound: j.bound,
			Mismatch: j.mismatch, Approving: j.approving}
		if !j.approving && len(j.mismatch) == 0 {
			if j.requirement == "key" {
				jv.Options = j.options
				data.Scripts = []string{"webauthn.js", "schedules.js", "formpost.js"}
			} else {
				jv.CLICommand = deployCLICommand + j.digest
			}
		}
		d.Join = jv
	}
	if len(data.Scripts) == 0 {
		data.Scripts = []string{"formpost.js"}
	}
	h.render(w, r, data)
}

// deployStateLine marks the states before the current one done and the
// current one active; a failed run marks the state it failed in.
func deployStateLine(state, failedIn string) []deployStateView {
	at := state
	switch state {
	case deployFailed:
		at = failedIn
	case deployJoined:
		at = deployDone
	}
	cur := -1
	for i, s := range deployStates {
		if s.name == at {
			cur = i
		}
	}
	out := make([]deployStateView, 0, len(deployStates))
	for i, s := range deployStates {
		v := deployStateView{Label: s.label}
		switch {
		case state == deployFailed && i == cur:
			v.Class, v.Label = "failed", s.label+" (failed)"
		case state == deployFailed && s.name == deployDone:
			v.Class, v.Label = "todo", "Failed"
		case state == deployJoined && s.name == deployBootstrapping:
			v.Class, v.Label = "todo", s.label+" (not available)"
		case state == deployJoined && s.name == deployDone:
			v.Class, v.Label = "current", "Joined"
		case i < cur, state == deployDone:
			v.Class = "done"
		case i == cur:
			v.Class = "current"
		default:
			v.Class = "todo"
		}
		out = append(out, v)
	}
	return out
}
