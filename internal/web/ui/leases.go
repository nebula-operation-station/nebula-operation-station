// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Read lease pages (ADR 0007 E06, part 2): the list and detail of the
// read grants the executor holds, and the revoke of an active grant.
// The executor is the source of truth for the grant documents; the pages
// render them as text only (host names and approved-by are untrusted
// input).

// leaseDetailOpenMax is the number of hosts up to which the detail page
// shows the frozen host list open by default.
const leaseDetailOpenMax = 20

// Leases lists and revokes read grants. executions.Service satisfies it.
type Leases interface {
	ReadGrants(ctx context.Context) ([]executions.ReadGrantView, error)
	RevokeReadGrant(ctx context.Context, user, id string) error
}

// leaseRow is one row of the lease list table.
type leaseRow struct {
	ID, Short, State, StateClass, Scope string
	ActionCount, HostCount              int
	Expiry                              time.Time
	ExpirySet                           bool
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

// leaseShort bounds the id shown in the UI and the page title.
func leaseShort(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

// leaseScope renders the scope of a grant as "kind: value" or "kind".
func leaseScope(v executions.ReadGrantView) string {
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
	for _, v := range list {
		row := leaseRow{
			ID: v.ID, Short: leaseShort(v.ID), State: v.State,
			StateClass: leaseStateClass(v.State), Scope: leaseScope(v),
			ActionCount: len(v.Actions), HostCount: len(v.Hosts),
			Expiry: v.Expiry.UTC(),
		}
		if !v.Expiry.IsZero() {
			row.ExpirySet = true
		}
		ld.Rows = append(ld.Rows, row)
	}
	h.render(w, r, pageData{Title: "Read leases", Active: "operations", Content: "leases", Leases: ld})
}

// findLease returns the grant with the given id from the current list.
func (h *Handler) findLease(ctx context.Context, id string) (*executions.ReadGrantView, error) {
	list, err := h.leases.ReadGrants(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (h *Handler) handleLease(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.findLease(ctx, r.PathValue("id"))
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
	h.render(w, r, pageData{Title: "Read lease " + d.Short, Active: "operations", Content: "lease", Lease: d})
}

// handleLeaseRevoke revokes an active read grant. It uses the same
// origin-checked POST pattern and audit handling as handleScheduleRevoke:
// the middleware rejects cross-origin posts, and the executions service
// writes the audit line. Only active grants can be revoked.
func (h *Handler) handleLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.leasesEnabled(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	id := r.PostFormValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.findLease(ctx, id)
	if err != nil {
		h.log.Error("find read grant", "grant", id, "error", err)
		http.Error(w, "the read lease could not be found", http.StatusBadGateway)
		return
	}
	if v == nil {
		http.NotFound(w, r)
		return
	}
	if v.State != "active" {
		http.Error(w, "only an active lease can be revoked", http.StatusConflict)
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
