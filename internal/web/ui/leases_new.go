// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Read lease proposals (ADR 0007 E06, part 3). GET /leases/new shows the
// form (scope all/tag/environment, read-only actions, 7 or 30 days);
// POST /leases/preview proposes the grant to the executor and redirects
// to GET /leases/proposals/{digest}, which shows the complete canonical
// scope the executor returned: every frozen host with its host key and
// credential version, every action, the expiry and the digest. Browser
// approval reuses the schedule approval button (webauthn.js and
// schedules.js), posting to POST /leases/commit; in hardened mode the page
// shows the CLI command instead of the button. "Refresh" on an active or
// expired lease pre-fills the form with its scope: the result is a new
// grant, and the old one stays until it expires or is revoked.
//
// The preview is posted with fetch (formpost.js, like the revoke form),
// which follows a redirect but does not render a POST answer; the frozen
// proposal is therefore kept in memory for its proposer and shown by a
// GET page.

// Limits of lease proposals.
const (
	// leasePreviewInterval is the minimum time between two previews of one
	// user: each preview resolves the inventory and asks the executor.
	leasePreviewInterval = 10 * time.Second
	// leaseProposalTTL is how long a preview page stays available (the
	// executor's approval challenge lasts five minutes).
	leaseProposalTTL = 10 * time.Minute
	// maxLeaseProposals bounds the proposals kept in memory.
	maxLeaseProposals = 256
	// maxLeaseThrottleUsers bounds the throttle table.
	maxLeaseThrottleUsers = 1024
	// maxLeaseScopeOptions bounds the tag/environment suggestions.
	maxLeaseScopeOptions = 200
	// leaseCLICommand is the hardened-mode approval command; the digest
	// follows it.
	leaseCLICommand = "nebula lease approve "
)

// Leases lists, proposes, approves and revokes read grants.
// executions.Service satisfies it.
type Leases interface {
	ReadGrants(ctx context.Context) ([]executions.ReadGrantView, error)
	RevokeReadGrant(ctx context.Context, user, id string) error
	ProposeReadGrant(ctx context.Context, user string, in executions.ReadGrantRequest) (executions.ReadGrantPreview, error)
	CommitReadGrant(ctx context.Context, user, digest string, assertion []byte) error
}

// leaseProposal is one previewed proposal, visible to its proposer only.
type leaseProposal struct {
	user      string
	preview   executions.ReadGrantPreview
	expires   time.Time
	committed bool
}

// leaseProposals keeps the preview throttle and the previewed proposals.
type leaseProposals struct {
	mu    sync.Mutex
	last  map[string]time.Time
	props map[string]*leaseProposal // by digest
}

func newLeaseProposals() *leaseProposals {
	return &leaseProposals{last: map[string]time.Time{}, props: map[string]*leaseProposal{}}
}

// allow reports whether user may preview now, and records the attempt.
// When the table is full of users within the interval, it refuses.
func (p *leaseProposals) allow(user string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.last[user]; ok && now.Sub(t) < leasePreviewInterval && !now.Before(t) {
		return false
	}
	if _, ok := p.last[user]; !ok && len(p.last) >= maxLeaseThrottleUsers {
		for u, t := range p.last {
			if now.Sub(t) >= leasePreviewInterval || now.Before(t) {
				delete(p.last, u)
			}
		}
		if len(p.last) >= maxLeaseThrottleUsers {
			return false
		}
	}
	p.last[user] = now
	return true
}

// put stores a proposal, dropping expired ones and, when full, the one
// that expires first.
func (p *leaseProposals) put(user string, v executions.ReadGrantPreview, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for d, x := range p.props {
		if !now.Before(x.expires) {
			delete(p.props, d)
		}
	}
	if len(p.props) >= maxLeaseProposals {
		var oldest string
		for d, x := range p.props {
			if oldest == "" || x.expires.Before(p.props[oldest].expires) {
				oldest = d
			}
		}
		delete(p.props, oldest)
	}
	p.props[v.Digest] = &leaseProposal{user: user, preview: v, expires: now.Add(leaseProposalTTL)}
}

// get returns a copy of user's unexpired proposal with this digest.
func (p *leaseProposals) get(user, digest string, now time.Time) (leaseProposal, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.props[digest]
	if !ok || x.user != user || !now.Before(x.expires) {
		return leaseProposal{}, false
	}
	return *x, true
}

// markCommitted records that the proposal was approved.
func (p *leaseProposals) markCommitted(digest string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x, ok := p.props[digest]; ok {
		x.committed = true
	}
}

// leaseDigestRe is the executor's digest form.
var leaseDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// leaseActionOption is one action checkbox of the form.
type leaseActionOption struct {
	ID, Title, Description string
	Checked                bool
}

// leaseNewData is the data of the lease form and the preview page.
type leaseNewData struct {
	// Form.
	Kind, Value  string
	Days         int
	DayOptions   []int
	Actions      []leaseActionOption
	ScopeOptions []string
	Refresh      string // short id of the lease being refreshed
	// Preview (set on the proposal page).
	Preview     *executions.ReadGrantPreview
	Options     string // WebAuthn request options JSON
	CLICommand  string
	MinInterval string
	HostCount   int
	ActionCount int
}

// leaseRefreshURL is the form URL pre-filled with a grant's scope, or ""
// when the grant cannot be refreshed (not active or expired, or a scope
// that is not all/tag/environment).
func leaseRefreshURL(v executions.ReadGrantView) string {
	if v.State != "active" && v.State != "expired" {
		return ""
	}
	switch v.ScopeKind {
	case executions.ScopeAll, executions.ScopeTag, executions.ScopeEnvironment:
	default:
		return ""
	}
	q := url.Values{}
	q.Set("scope", v.ScopeKind)
	if v.ScopeValue != "" {
		q.Set("value", v.ScopeValue)
	}
	for _, a := range v.Actions {
		q.Add("action", a)
	}
	days := executions.ReadGrantShortDays
	if !v.Created.IsZero() && v.Expiry.Sub(v.Created) > time.Duration(executions.ReadGrantShortDays)*24*time.Hour+time.Hour {
		days = executions.ReadGrantLongDays
	}
	q.Set("days", strconv.Itoa(days))
	if v.ID != "" {
		q.Set("refresh", v.ID)
	}
	return "/leases/new?" + q.Encode()
}

// leaseFormFromQuery reads the pre-fill (Refresh) from the query. Only
// values the form can hold are kept; everything else is ignored.
func leaseFormFromQuery(q url.Values) *leaseNewData {
	d := &leaseNewData{Kind: executions.ScopeAll, Days: executions.ReadGrantShortDays,
		DayOptions: []int{executions.ReadGrantShortDays, executions.ReadGrantLongDays}}
	switch k := q.Get("scope"); k {
	case executions.ScopeTag, executions.ScopeEnvironment:
		if v := q.Get("value"); v != "" && len(v) <= 200 && utf8.ValidString(v) {
			d.Kind, d.Value = k, v
		}
	}
	if n, err := strconv.Atoi(q.Get("days")); err == nil && (n == executions.ReadGrantShortDays || n == executions.ReadGrantLongDays) {
		d.Days = n
	}
	if id := q.Get("refresh"); leaseIDRe.MatchString(id) {
		d.Refresh = leaseShort(id)
	}
	checked := map[string]bool{}
	for _, a := range q["action"] {
		checked[a] = true
	}
	known := map[string]leaseActionOption{}
	for _, a := range executions.SortedActions() {
		known[a.ID] = leaseActionOption{ID: a.ID, Title: a.Title, Description: a.Description}
	}
	for _, id := range executions.ReadGrantActionIDs() {
		o, ok := known[id]
		if !ok {
			o = leaseActionOption{ID: id}
		}
		o.Checked = checked[id]
		d.Actions = append(d.Actions, o)
	}
	return d
}

// leaseScopeOptions lists the tags ("key=value") and environments of the
// inventory as suggestions for the value field.
func (h *Handler) leaseScopeOptions(ctx context.Context) []string {
	if h.hosts == nil {
		return nil
	}
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("list hosts", "error", err)
		return nil
	}
	set := map[string]bool{}
	for _, x := range hosts {
		if x.Environment != "" {
			set[string(x.Environment)] = true
		}
		for k, v := range x.Tags {
			set[k+"="+v] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > maxLeaseScopeOptions {
		out = out[:maxLeaseScopeOptions]
	}
	return out
}

func (h *Handler) handleLeaseNew(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	d := leaseFormFromQuery(r.URL.Query())
	d.ScopeOptions = h.leaseScopeOptions(ctx)
	h.render(w, r, pageData{Title: "New read lease", Active: "operations", Content: "lease_new", LeaseNew: d,
		Scripts: []string{"formpost.js"}})
}

// handleLeasePreview proposes the grant and redirects to its preview page.
// Errors are plain text: formpost.js shows them with textContent.
func (h *Handler) handleLeasePreview(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
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
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil {
		days = 0 // the service names the allowed values
	}
	in := executions.ReadGrantRequest{
		ScopeKind:  r.PostFormValue("scope"),
		ScopeValue: r.PostFormValue("value"),
		Actions:    r.PostForm["action"],
		Days:       days,
	}
	if in.ScopeKind == executions.ScopeAll {
		in.ScopeValue = "" // the value field may still hold a tag
	}
	user := webUser(r)
	now := h.clockNow()
	if !h.leaseProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(leasePreviewInterval/time.Second)))
		http.Error(w, "at most one read lease preview every 10 seconds: wait and try again", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.leases.ProposeReadGrant(ctx, user, in)
	if err != nil {
		var ie *executions.ReadGrantInputError
		switch {
		case errors.As(err, &ie):
			http.Error(w, ie.Reason, http.StatusBadRequest)
		case errors.Is(err, executions.ErrReadGrantProposeFailed), errors.Is(err, executions.ErrReadGrantCredentials),
			errors.Is(err, executions.ErrReadGrantProposalMismatch), errors.Is(err, executions.ErrReadGrantProposeUnsupported):
			h.log.Error("propose read grant", "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		default:
			h.log.Error("propose read grant", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	if !leaseDigestRe.MatchString(v.Digest) {
		http.Error(w, "the executor returned no usable digest", http.StatusBadGateway)
		return
	}
	h.leaseProposals.put(user, v, now)
	http.Redirect(w, r, "/leases/proposals/"+v.Digest, http.StatusSeeOther)
}

// handleLeaseProposal shows a previewed proposal to its proposer.
func (h *Handler) handleLeaseProposal(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	digest := r.PathValue("digest")
	if !leaseDigestRe.MatchString(digest) {
		http.NotFound(w, r)
		return
	}
	p, ok := h.leaseProposals.get(webUser(r), digest, h.clockNow())
	if !ok {
		http.NotFound(w, r)
		return
	}
	if p.committed {
		http.Redirect(w, r, "/leases", http.StatusSeeOther)
		return
	}
	v := p.preview
	d := &leaseNewData{Preview: &v, HostCount: len(v.Targets), ActionCount: len(v.Actions),
		MinInterval: formatScheduleInterval(v.MinInterval)}
	data := pageData{Title: "Approve read lease", Active: "operations", Content: "lease_new", LeaseNew: d}
	if v.CLI {
		d.CLICommand = leaseCLICommand + v.Digest
	} else {
		d.Options = string(v.Options)
		data.Scripts = []string{"webauthn.js", "schedules.js"}
	}
	h.render(w, r, data)
}

// handleLeaseCommit relays the security key assertion for a previewed
// proposal of this user (the schedule approval button posts here).
func (h *Handler) handleLeaseCommit(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
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
	if !leaseDigestRe.MatchString(in.ID) {
		writeJSONError(w, http.StatusNotFound, "read lease proposal not found")
		return
	}
	p, ok := h.leaseProposals.get(user, in.ID, h.clockNow())
	if !ok || p.committed || p.preview.CLI {
		writeJSONError(w, http.StatusNotFound, "read lease proposal not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.leases.CommitReadGrant(ctx, user, in.ID, in.Assertion); err != nil {
		var ie *executions.ReadGrantInputError
		switch {
		case errors.As(err, &ie):
			writeJSONError(w, http.StatusBadRequest, ie.Reason)
		case errors.Is(err, executions.ErrReadGrantProposalNotFound):
			writeJSONError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, executions.ErrReadGrantApprovalRefused):
			writeJSONError(w, http.StatusForbidden, err.Error())
		default:
			h.log.Error("commit read grant", "error", err)
			writeJSONError(w, http.StatusBadGateway, "the read lease could not be approved")
		}
		return
	}
	h.leaseProposals.markCommitted(in.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}
