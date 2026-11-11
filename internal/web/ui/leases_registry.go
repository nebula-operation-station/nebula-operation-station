// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Private registry read leases (ADR 0006, cu06 part 1, G13): the
// "Private registry" scope of the lease form. The form offers the
// executor's private registries (ListPrivateRegistries, metadata only)
// and the typed registry reads; POST /leases/preview with scope=registry
// builds the lease from the executor's listed record and credential
// identity (registrymeta.ProposeRegistryReadLease) and redirects to the
// same proposal page as every other lease, where the user approves the
// digest with the security key (or the hardened-mode CLI). The lease pages
// show registry leases with their frozen registries; the executions
// service cannot decode them, so they are decoded here with
// registrymeta.DecodeRegistryLease. No page, form or log line ever holds a
// registry credential: the server has none.

// ScopeRegistry is the lease form scope of a private registry read lease.
const ScopeRegistry = "registry"

// RegistryReads is the server's caller of executor private registry
// reads. cmd/nebula-server implements it over the executor client.
type RegistryReads interface {
	// PrivateRegistries lists the executor's private registries
	// (validated metadata, no credential).
	PrivateRegistries(ctx context.Context) ([]registrymeta.PrivateIdentity, error)
	// ProposeRegistryLease builds a registry read lease for req (the
	// implementation sets req.ID) and proposes it to the executor.
	ProposeRegistryLease(ctx context.Context, user string, req registrymeta.LeaseRequest) (registrymeta.LeaseProposal, error)
	// RegistryLeases lists the executor-held registry read leases.
	RegistryLeases(ctx context.Context) ([]registrymeta.LeaseView, error)
	// ResolveImageUpdates fills executor-read digests into a
	// docker.check_updates result (dockerhost.ResolvePrivateDigestsWith);
	// on any failure it returns u unchanged.
	ResolveImageUpdates(ctx context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates
}

// leaseRegistryOption is one registry of the form's registry select.
type leaseRegistryOption struct {
	ID, Origin, Repositories string
	Selected                 bool
}

// leaseRegistryRow is one frozen registry target of a registry lease, as
// the proposal and detail pages show it.
type leaseRegistryRow struct {
	ID, ConfigDigest, CredentialID   string
	ConfigVersion, CredentialVersion int64
	Repositories, Methods            string
}

// registryMethodOptions are the typed registry reads the form offers.
var registryMethodOptions = []struct {
	ID, Description string
	Default         bool
}{
	{schedgrant.RegistryReadTagDigest, "the current manifest digest of a running image's tag (docker.check_updates)", true},
	{schedgrant.RegistryReadListTags, "a bounded tag list of each repository", false},
}

func registryRows(ts []permit.RegistryTarget) []leaseRegistryRow {
	out := make([]leaseRegistryRow, 0, len(ts))
	for _, t := range ts {
		out = append(out, leaseRegistryRow{ID: t.RegistryID, ConfigDigest: t.ConfigDigest, CredentialID: t.CredentialID,
			ConfigVersion: t.ConfigVersion, CredentialVersion: t.CredentialVersion,
			Repositories: strings.Join(t.Repositories, ", "), Methods: strings.Join(t.Methods, ", ")})
	}
	return out
}

func registryIDs(ts []permit.RegistryTarget) []string {
	ids := make([]string, 0, len(ts))
	for _, t := range ts {
		ids = append(ids, t.RegistryID)
	}
	return ids
}

// registryLeaseForm adds the registry scope to the form, pre-filled from
// the query (Refresh of a registry lease).
func (h *Handler) registryLeaseForm(ctx context.Context, d *leaseNewData, q url.Values) {
	if h.registryReads == nil {
		return
	}
	regs, err := h.registryReads.PrivateRegistries(ctx)
	if err != nil {
		h.log.Error("list private registries", "error", err)
		return
	}
	d.RegistryOffered = true
	isRegistry := q.Get("scope") == ScopeRegistry
	if isRegistry {
		d.Kind, d.Value, d.Days = ScopeRegistry, "", executions.ReadGrantShortDays
	}
	for _, r := range regs {
		d.PrivateRegistries = append(d.PrivateRegistries, leaseRegistryOption{ID: r.ID, Origin: r.Origin,
			Repositories: strings.Join(r.Repositories, ", "), Selected: isRegistry && slices.Contains(q["registry"], r.ID)})
	}
	checked := map[string]bool{}
	if isRegistry {
		for _, m := range q["registry_method"] {
			if schedgrant.IsRegistryReadMethod(m) {
				checked[m] = true
			}
		}
	}
	useDefaults := len(checked) == 0
	for _, o := range registryMethodOptions {
		c := checked[o.ID]
		if useDefaults {
			c = o.Default
		}
		d.RegistryMethods = append(d.RegistryMethods, leaseMethodOption{ID: o.ID, Description: o.Description, Checked: c})
	}
}

// checkRegistryLeaseForm turns the posted registry form into a request, or
// returns the reason it is refused. known are the executor's registries.
func checkRegistryLeaseForm(form url.Values, known []registrymeta.PrivateIdentity) (registrymeta.LeaseRequest, string) {
	days, err := strconv.Atoi(form.Get("days"))
	if err != nil || days < 1 || days > registrymeta.MaxLeaseDays {
		return registrymeta.LeaseRequest{}, fmt.Sprintf("a private registry read lease lasts at most %d days", registrymeta.MaxLeaseDays)
	}
	ids := form["registry"]
	if len(ids) == 0 || len(ids) > permit.MaxRegistryTargets {
		return registrymeta.LeaseRequest{}, fmt.Sprintf("choose 1 to %d private registries", permit.MaxRegistryTargets)
	}
	methods := form["registry_method"]
	if len(methods) == 0 {
		return registrymeta.LeaseRequest{}, "choose at least one registry read"
	}
	seen := map[string]bool{}
	for _, m := range methods {
		if !schedgrant.IsRegistryReadMethod(m) || seen[m] {
			return registrymeta.LeaseRequest{}, "a registry read is unknown or chosen twice"
		}
		seen[m] = true
	}
	req := registrymeta.LeaseRequest{Days: days}
	seen = map[string]bool{}
	for _, id := range ids {
		if !schedgrant.ValidRegistryID(id) || seen[id] {
			return registrymeta.LeaseRequest{}, "a private registry is malformed or chosen twice"
		}
		if !slices.ContainsFunc(known, func(r registrymeta.PrivateIdentity) bool { return r.ID == id }) {
			return registrymeta.LeaseRequest{}, "a chosen private registry is not known to the executor"
		}
		seen[id] = true
		// The whole approved scope of the record; the proposal page lists
		// every repository before anything is approved.
		req.Registries = append(req.Registries, registrymeta.LeaseSelection{RegistryID: id, Methods: slices.Clone(methods)})
	}
	return req, ""
}

// handleRegistryLeasePreview proposes a registry read lease (scope=registry
// of POST /leases/preview; the form is already parsed) and redirects to its
// proposal page. Errors are plain text for formpost.js.
func (h *Handler) handleRegistryLeasePreview(w http.ResponseWriter, r *http.Request) {
	if h.registryReads == nil {
		http.Error(w, "private registry leases are not available", http.StatusBadRequest)
		return
	}
	// The per-user throttle comes first: every later step calls the
	// executor, so repeated POSTs never reach it faster than the interval.
	user := webUser(r)
	now := h.clockNow()
	if !h.leaseProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(leasePreviewInterval/time.Second)))
		http.Error(w, "at most one read lease preview every 10 seconds: wait and try again", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	known, err := h.registryReads.PrivateRegistries(ctx)
	if err != nil {
		h.log.Error("list private registries", "error", err)
		http.Error(w, "the executor's private registries could not be listed", http.StatusBadGateway)
		return
	}
	req, reason := checkRegistryLeaseForm(r.PostForm, known)
	if reason != "" {
		http.Error(w, reason, http.StatusBadRequest)
		return
	}
	p, err := h.registryReads.ProposeRegistryLease(ctx, user, req)
	if err != nil {
		switch {
		case errors.Is(err, registrymeta.ErrLeaseRequest), errors.Is(err, registrymeta.ErrLeaseUnknownRegistry),
			errors.Is(err, registrymeta.ErrOutOfScope):
			http.Error(w, "the private registry lease request is not valid for the executor's current registries", http.StatusBadRequest)
		case errors.Is(err, registrymeta.ErrPrivateListFailed), errors.Is(err, registrymeta.ErrLeaseProposeFailed),
			errors.Is(err, registrymeta.ErrLeaseProposalMismatch):
			h.log.Error("propose registry read lease", "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		default:
			h.log.Error("propose registry read lease", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	if !leaseDigestRe.MatchString(p.Digest) || len(p.Doc.RegistryTargets) == 0 {
		http.Error(w, "the executor returned no usable digest", http.StatusBadGateway)
		return
	}
	d := p.Doc
	v := executions.ReadGrantPreview{
		ID: d.ID, Digest: p.Digest, ScopeKind: ScopeRegistry, ScopeValue: strings.Join(registryIDs(d.RegistryTargets), ", "),
		Issuer: d.Issuer, Created: time.Unix(d.CreatedUnix, 0).UTC(), Expiry: time.Unix(d.ExpiryUnix, 0).UTC(),
		Trigger: d.Trigger, RateProfile: d.RateProfile, MinInterval: time.Duration(d.MinIntervalS) * time.Second,
		RunBudget: d.RunBudget, CLI: p.CLI, Options: p.Options, ChallengeExpiry: p.ChallengeExpiry,
	}
	h.leaseProposals.putWith(user, v, registryRows(d.RegistryTargets), now)
	h.log.Info("audit", "kind", "registry_read_lease_proposed", "digest", p.Digest, "user", user,
		"registries", strings.Join(registryIDs(d.RegistryTargets), ","))
	http.Redirect(w, r, "/leases/proposals/"+p.Digest, http.StatusSeeOther)
}

// registryLeaseViews returns the executor's registry read leases by id;
// nil when there are none or they cannot be listed.
func (h *Handler) registryLeaseViews(ctx context.Context) map[string]registrymeta.LeaseView {
	if h.registryReads == nil {
		return nil
	}
	list, err := h.registryReads.RegistryLeases(ctx)
	if err != nil {
		h.log.Error("list registry read leases", "error", err)
		return nil
	}
	out := make(map[string]registrymeta.LeaseView, len(list))
	for _, v := range list {
		out[v.ID] = v
	}
	return out
}

// applyRegistryLease replaces the view of a grant the executions service
// could not decode ("invalid") with its verified registry lease view.
func applyRegistryLease(v *executions.ReadGrantView, rl registrymeta.LeaseView) {
	v.State, v.RateProfile = rl.State, schedgrant.RegistryReadProfile
	v.ScopeKind, v.ScopeValue = ScopeRegistry, strings.Join(registryIDs(rl.Registries), ", ")
	v.Digest, v.ApprovedBy = rl.Digest, rl.ApprovedBy
	v.Created, v.Expiry, v.Revoked = rl.Created, rl.Expiry, rl.Revoked
	v.Hosts, v.Actions, v.Remotes, v.Providers = nil, nil, nil, nil
}

// registryMethodCount counts the distinct methods of a registry lease.
func registryMethodCount(rl registrymeta.LeaseView) int {
	seen := map[string]bool{}
	for _, t := range rl.Registries {
		for _, m := range t.Methods {
			seen[m] = true
		}
	}
	return len(seen)
}

// registryRefreshURL pre-fills the form with a registry lease's scope.
func registryRefreshURL(rl registrymeta.LeaseView) string {
	if rl.State != "active" && rl.State != "expired" {
		return ""
	}
	q := url.Values{"scope": {ScopeRegistry}}
	seen := map[string]bool{}
	for _, t := range rl.Registries {
		q.Add("registry", t.RegistryID)
		for _, m := range t.Methods {
			if !seen[m] {
				seen[m] = true
				q.Add("registry_method", m)
			}
		}
	}
	return "/leases/new?" + q.Encode()
}

// resolveImageUpdates fills executor-read private digests into a parsed
// docker.check_updates result when the registry reads are wired.
func (h *Handler) resolveImageUpdates(ctx context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates {
	if h.registryReads == nil || u.Phase != "done" {
		return u
	}
	return h.registryReads.ResolveImageUpdates(ctx, u)
}
