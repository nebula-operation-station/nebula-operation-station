// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

// Read lease pages (ADR 0007 E06, part 2): the list and detail of the
// read grants the executor holds, and the revoke of a grant.
// The executor is the source of truth for the grant documents; the pages
// render them as text only (host names and approved-by are untrusted
// input). Active and legacy read-schedule-v1 grants can be revoked.

// leaseDetailOpenMax is the number of hosts up to which the detail page
// shows the frozen host list open by default.
const leaseDetailOpenMax = 20

// leaseRow is one row of the lease list table.
type leaseRow struct {
	ID, Short, State, StateClass, Scope string
	ActionCount, HostCount              int
	Expiry                              time.Time
	ExpirySet                           bool
	// RefreshURL is the form pre-filled with this grant's scope (a new
	// grant); empty when the grant cannot be refreshed.
	RefreshURL string
	// Provider marks a provider lease: the row counts remotes and
	// methods instead of hosts and actions.
	Provider                 bool
	RemoteCount, MethodCount int
	// Registry marks a private registry read lease: the row counts
	// registries and methods.
	Registry      bool
	RegistryCount int
}

// leaseDetail is the data of one lease detail page.
type leaseDetail struct {
	ID, Short, State, StateClass, Scope string
	Actions                             []string
	Remotes                             []string
	Hosts                               []string
	HostsOpen                           bool // frozen host list open by default
	Digest, ApprovedBy                  string
	Created, Expiry, Revoked            time.Time
	CreatedSet, ExpirySet, RevokedSet   bool
	Legacy                              bool
	Revocable                           bool // show the Revoke form
	RefreshURL                          string
	// Provider marks a provider lease with its frozen remotes.
	Provider    bool
	Providers   []leaseProviderRow
	RateProfile string
	// Registry marks a private registry read lease with its frozen
	// registries.
	Registry   bool
	Registries []leaseRegistryRow
}

// leasesData is the data of the lease list page.
type leasesData struct {
	Rows        []leaseRow
	Unavailable bool
}

// leaseStateClass maps a read-grant state to its badge class.
func leaseStateClass(state string) string {
	switch state {
	case "active":
		return "badge--ok"
	case "expired":
		return "badge--expired"
	case "revoked":
		return "badge--warning"
	case "legacy":
		return "badge--unknown"
	default:
		return "badge--critical"
	}
}

// leaseIDRe is the executor's grant id form: a lowercase UUIDv4, the same
// form internal/executions checks (readGrantIDRe). The revoke handler
// checks the posted id against it before any lookup or log line.
var leaseIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// leaseRevocable reports whether a grant in this state can be revoked:
// active grants, legacy read-schedule-v1 grants (ADR 0007: "offer revoke
// or explicitly approved replacement" for legacy grants) and grants the
// server cannot decode ("invalid", e.g. a newer format during version
// skew). Revoke only reduces authority and needs just the validated id,
// so an undecodable grant that may still be live stays revocable.
func leaseRevocable(state string) bool {
	return state == "active" || state == "legacy" || state == "invalid"
}

// leaseShort bounds the id shown in the UI and the page title. Invalid
// UTF-8 in a malformed executor-supplied id is replaced first, and the
// cut is made after the eighth rune, so the result is always valid UTF-8.
func leaseShort(id string) string {
	if !utf8.ValidString(id) {
		id = strings.ToValidUTF8(id, "\uFFFD")
	}
	n := 0
	for i := range id {
		if n == 8 {
			return id[:i]
		}
		n++
	}
	return id
}

// leaseScope renders the scope of a grant as "kind: value" or "kind".
func leaseScope(v executions.ReadGrantView) string {
	if v.ScopeKind == executions.ScopeProvider {
		return "Proxmox remotes: " + strings.Join(v.Remotes, ", ")
	}
	if v.ScopeKind == ScopeRegistry {
		return "Private registries: " + v.ScopeValue
	}
	if v.ScopeValue != "" {
		return v.ScopeKind + ": " + v.ScopeValue
	}
	return v.ScopeKind
}

func (h *Handler) leasesEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.leases == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) handleLeases(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	ld := &leasesData{}
	list, err := h.leases.ReadGrants(ctx)
	if err != nil {
		h.log.Error("list read grants", "error", err)
		ld.Unavailable = true
	}
	var regs map[string]registrymeta.LeaseView
	if err == nil {
		regs = h.registryLeaseViews(ctx)
	}
	for _, v := range list {
		rl, isRegistry := regs[v.ID]
		if isRegistry {
			applyRegistryLease(&v, rl)
		}
		row := leaseRow{
			ID: v.ID, Short: leaseShort(v.ID), State: v.State,
			StateClass: leaseStateClass(v.State), Scope: leaseScope(v),
			ActionCount: len(v.Actions), HostCount: len(v.Hosts),
			Expiry: v.Expiry.UTC(), RefreshURL: leaseRefreshURL(v),
			Provider:    v.ScopeKind == executions.ScopeProvider,
			RemoteCount: len(v.Remotes), MethodCount: leaseProviderMethodCount(v),
		}
		if !v.Expiry.IsZero() {
			row.ExpirySet = true
		}
		if isRegistry {
			row.Registry, row.RegistryCount, row.MethodCount = true, len(rl.Registries), registryMethodCount(rl)
			row.RefreshURL = registryRefreshURL(rl)
		}
		ld.Rows = append(ld.Rows, row)
	}
	h.render(w, r, pageData{Title: "Read leases", Active: "operations", Content: "leases", Leases: ld})
}

// findLease returns the grant with the given id from the current list. A
// private registry read lease (which the executions service shows as
// "invalid") comes back with its verified state, and its registry view.
func (h *Handler) findLease(ctx context.Context, id string) (*executions.ReadGrantView, *registrymeta.LeaseView, error) {
	list, err := h.leases.ReadGrants(ctx)
	if err != nil {
		return nil, nil, err
	}
	for i := range list {
		if list[i].ID == id {
			v := list[i] // a copy: the overlay never writes into the caller's list
			if rl, ok := h.registryLeaseViews(ctx)[id]; ok {
				applyRegistryLease(&v, rl)
				return &v, &rl, nil
			}
			return &v, nil, nil
		}
	}
	return nil, nil, nil
}

func (h *Handler) handleLease(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, rl, err := h.findLease(ctx, r.PathValue("id"))
	if err != nil {
		h.log.Error("list read grants", "error", err)
		http.Error(w, "the read leases could not be listed", http.StatusBadGateway)
		return
	}
	if v == nil {
		http.NotFound(w, r)
		return
	}
	d := &leaseDetail{
		ID: v.ID, Short: leaseShort(v.ID), State: v.State,
		StateClass: leaseStateClass(v.State), Scope: leaseScope(*v),
		Actions: v.Actions, Remotes: v.Remotes, Hosts: v.Hosts,
		HostsOpen: len(v.Hosts) > 0 && len(v.Hosts) <= leaseDetailOpenMax,
		Digest:    v.Digest, ApprovedBy: v.ApprovedBy, Legacy: v.Legacy,
		Revocable: leaseRevocable(v.State), RefreshURL: leaseRefreshURL(*v),
		Provider: v.ScopeKind == executions.ScopeProvider, Providers: leaseProviderRows(*v),
		RateProfile: v.RateProfile,
	}
	if rl != nil {
		d.Registry, d.Registries, d.RefreshURL = true, registryRows(rl.Registries), registryRefreshURL(*rl)
	}
	if !v.Created.IsZero() {
		d.Created, d.CreatedSet = v.Created.UTC(), true
	}
	if !v.Expiry.IsZero() {
		d.Expiry, d.ExpirySet = v.Expiry.UTC(), true
	}
	if !v.Revoked.IsZero() {
		d.Revoked, d.RevokedSet = v.Revoked.UTC(), true
	}
	h.render(w, r, pageData{Title: "Read lease " + d.Short, Active: "operations", Content: "lease", Lease: d,
		Scripts: []string{"formpost.js"}})
}

// handleLeaseRevoke revokes an active, legacy or undecodable read grant. The page
// submits the form with fetch (data-fetch, formpost.js), which sends the
// real Origin; the security middleware rejects cross-origin posts and
// plain form posts (Origin: null under Referrer-Policy: no-referrer). The
// executions service writes the audit line.
func (h *Handler) handleLeaseRevoke(w http.ResponseWriter, r *http.Request) {
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
	id := r.PostFormValue("id")
	if !leaseIDRe.MatchString(id) {
		http.Error(w, "invalid lease id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, _, err := h.findLease(ctx, id)
	if err != nil {
		h.log.Error("find read grant", "grant", id, "error", err)
		http.Error(w, "the read lease could not be found", http.StatusBadGateway)
		return
	}
	if v == nil {
		http.NotFound(w, r)
		return
	}
	if !leaseRevocable(v.State) {
		http.Error(w, "an expired or revoked lease cannot be revoked", http.StatusConflict)
		return
	}
	if err := h.leases.RevokeReadGrant(ctx, webUser(r), id); err != nil {
		switch {
		case errors.Is(err, executions.ErrReadGrantNotFound):
			http.NotFound(w, r)
		case errors.Is(err, executions.ErrReadGrantRevokeFailed):
			h.log.Error("revoke read grant", "grant", id, "error", err)
			http.Error(w, "the read lease could not be revoked", http.StatusBadGateway)
		default:
			h.log.Error("revoke read grant", "grant", id, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/leases/"+id, http.StatusSeeOther)
}
