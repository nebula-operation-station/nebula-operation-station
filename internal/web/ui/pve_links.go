// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// Links between PVE guests and managed hosts on the PVE detail page (ADR
// 0006 "explicit reviewed link", P1-12). The page shows, per guest, the
// active link or the candidates pveinventory.SuggestHosts computes; MAC
// matches (via IPAM assets) are "MAC", IP matches are "POSSIBLE MATCH",
// and conflicts (cloned MAC, one IP on several hosts) are shown. Nothing
// is linked by rendering: a link is created or released only by a POST
// from the page (fetch-posted form, Origin checked by the middleware like
// every state change), by a logged-in user while a privileged session is
// open, and every change is written as an audit line with that user. A
// link is display and drift information only, never an SSH identity.
//
// Suggestions are help, not a whitelist: the link POST accepts any
// inventory host ID, so an admin may link a guest to a host that was not
// suggested (for example a guest without guest agent or IPAM asset). The
// conflict confirmation is still enforced for the guest's own conflicts
// and for a suggested candidate flagged as conflicting.
//
// Known gap (review of PR #346): the privileged session is executor-wide
// and the executor does not report which user opened it, so the gate is
// not bound to the requesting web user. Closing it needs a change outside
// this package (see docs/operator/proxmox.md).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveSuggestGuestLimit caps the unlinked guests a detail page computes
// suggestions for; each suggestion reads the inventory and IPAM assets.
const pveSuggestGuestLimit = 100

// pveLinkStateTimeout bounds all link reads of one detail page. It is a
// context of its own, so the link cells can never expire the context of
// the other page reads.
const pveLinkStateTimeout = 4 * time.Second

// pveSuggestBudget bounds the suggestion computation of one detail page
// (inside pveLinkStateTimeout, so the active links and names still load).
// Guests not reached within it show pveSuggestSkippedNote.
const pveSuggestBudget = 2 * time.Second

// pveSuggestSkippedNote is shown for guests whose suggestions were not
// computed because the page budget was used up.
const pveSuggestSkippedNote = "Suggestions skipped: the time budget of this page was used up. Reload the page to try again."

// pveLinkFormMax bounds the link and unlink form bodies.
const pveLinkFormMax = 4 << 10

// pveLinkActorRe is the user name pveinventory accepts as link actor.
var pveLinkActorRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// pveLinkHostIDRe is the inventory host ID syntax.
var pveLinkHostIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Match kind labels shown on the page: a MAC match suggests a link, an IP
// match is only a possible match (ADR 0006).
const (
	pveMatchMACLabel      = "MAC"
	pveMatchPossibleLabel = "POSSIBLE MATCH"
)

// PVELinkStore is the guest/host link part of pveinventory.Store. When the
// PVEStore passed in Options also implements it (pveinventory.Store
// does), the PVE detail page shows links and suggestions and accepts the
// link and unlink POSTs.
type PVELinkStore interface {
	ListLinks(ctx context.Context, remoteID string, limit int) ([]pveinventory.Link, error)
	LinksForHost(ctx context.Context, hostID string) ([]pveinventory.Link, error)
	SuggestHosts(ctx context.Context, remoteID string, vmid, generation uint64) ([]pveinventory.Candidate, error)
	GuestConflicts(ctx context.Context, remoteID string, vmid, generation uint64) ([]string, error)
	CreateLink(ctx context.Context, remoteID string, vmid, generation uint64, hostID, actor string) (pveinventory.Link, error)
	Unlink(ctx context.Context, remoteID string, vmid, generation uint64, actor, reason string) (pveinventory.Link, error)
}

// pveLinkStore returns the link store, or nil when the PVE store has none.
func (h *Handler) pveLinkStore() PVELinkStore {
	if h.pve == nil {
		return nil
	}
	ls, _ := h.pve.(PVELinkStore)
	return ls
}

// pveGuestLinkView is the "Managed host" cell of one guest row.
type pveGuestLinkView struct {
	// LinkAction and UnlinkAction are the form targets.
	LinkAction   string
	UnlinkAction string
	// VMIDText and GenerationText identify the guest incarnation.
	VMIDText       string
	GenerationText string
	// Linked is set when an active link exists for this incarnation.
	Linked bool
	// HostID, HostName and HostURL describe the linked host.
	HostID   string
	HostName string
	HostURL  string
	// Since and By are when and by whom the link was created.
	Since time.Time
	By    string
	// Candidates are the suggestions for an unlinked guest.
	Candidates []pveLinkCandidate
	// Conflicts are the guest's MAC/IP conflicts (untrusted values were
	// validated by the store; rendered as text).
	Conflicts []string
	// NeedsConfirm is set when a link from this guest needs the explicit
	// conflict review confirmation.
	NeedsConfirm bool
	// Reused lists active links of older incarnations of this VMID.
	Reused []pveReusedLink
	// SuggestNote explains missing suggestions ("" when computed).
	SuggestNote string
}

// pveLinkCandidate is one suggested host of an unlinked guest.
type pveLinkCandidate struct {
	// HostID and HostName identify the suggested managed host.
	HostID   string
	HostName string
	// Kind is pveMatchMACLabel or pveMatchPossibleLabel.
	Kind string
	// Details explain the matches.
	Details []string
	// Conflict is set when a matching value points to more than one host
	// or guest.
	Conflict bool
	// LinkedElsewhere names the guest the host is already linked to; the
	// candidate then gets no button.
	LinkedElsewhere string
}

// pveReusedLink is an active link of an older incarnation of a reused
// VMID: it does not apply to the current guest.
type pveReusedLink struct {
	// HostID and HostName identify the host of the old link.
	HostID   string
	HostName string
	// GenerationText is the old incarnation (for the "Lösen" form).
	GenerationText string
	// Notice is the visible explanation.
	Notice string
}

// pveHostNames resolves display names of inventory hosts. The managed
// host list is read once per page; a host missing from it (or a failed
// list) falls back to one Get per host, memoized.
type pveHostNames struct {
	h     *Handler
	ctx   context.Context
	names map[string]string
}

// newPVEHostNames preloads the display names of all managed hosts.
func (h *Handler) newPVEHostNames(ctx context.Context) *pveHostNames {
	n := &pveHostNames{h: h, ctx: ctx, names: map[string]string{}}
	if h.hosts == nil {
		return n
	}
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("list managed hosts for PVE links", "error", err)
		return n
	}
	for _, host := range hosts {
		if host.DisplayName != "" {
			n.names[host.ID] = host.DisplayName
		} else {
			n.names[host.ID] = host.ID
		}
	}
	return n
}

func (n *pveHostNames) name(id string) string {
	if v, ok := n.names[id]; ok {
		return v
	}
	name := id
	if n.h.inventory != nil {
		if host, err := n.h.inventory.Get(n.ctx, id); err == nil && host.DisplayName != "" {
			name = host.DisplayName
		}
	}
	n.names[id] = name
	return name
}

// pveHostLinks memoizes LinksForHost per host for one page: a host that
// is a candidate of several guests is read once.
type pveHostLinks struct {
	ls   PVELinkStore
	seen map[string]string
}

// elsewhere returns the guest the host is already linked to ("" when
// none).
func (p *pveHostLinks) elsewhere(ctx context.Context, hostID string) (string, error) {
	if v, ok := p.seen[hostID]; ok {
		return v, nil
	}
	other, err := p.ls.LinksForHost(ctx, hostID)
	if err != nil {
		return "", err
	}
	v := ""
	if len(other) > 0 {
		v = fmt.Sprintf("%s VMID %d (incarnation %d)", other[0].RemoteID, other[0].VMID, other[0].Generation)
	}
	p.seen[hostID] = v
	return v, nil
}

// pveHostURL is the host page of a managed host.
func pveHostURL(id string) string { return "/hosts/" + url.PathEscape(id) }

// pveLinkState fills the "Managed host" cells of the guest rows. Store
// errors are logged and shown as "unavailable"; nothing is written.
//
// ctx should be the request context, not the page's read context: the
// link reads get their own pveLinkStateTimeout, and the suggestions their
// own pveSuggestBudget inside it, so a slow store or a large lab leaves
// later guests with pveSuggestSkippedNote instead of expiring the rest of
// the page. Active links, host names and host links are read once per
// page; suggestions are computed only for unlinked guests (at most
// pveSuggestGuestLimit).
func (h *Handler) pveLinkState(ctx context.Context, id string, d *pveDetailData) {
	ls := h.pveLinkStore()
	if ls == nil || len(d.Guests) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, pveLinkStateTimeout)
	defer cancel()
	d.Links = true
	d.LinkAdmin = h.pvePrivileged(ctx)
	links, err := ls.ListLinks(ctx, id, pveinventory.MaxLinksQuery)
	if err != nil {
		h.log.Error("list PVE guest links", "remote", id, "error", err)
		d.LinksUnavailable = true
		return
	}
	byVMID := map[uint64][]pveinventory.Link{}
	for _, l := range links {
		byVMID[l.VMID] = append(byVMID[l.VMID], l)
	}
	names := h.newPVEHostNames(ctx)
	hostLinks := &pveHostLinks{ls: ls, seen: map[string]string{}}
	sctx, scancel := context.WithTimeout(ctx, pveSuggestBudget)
	defer scancel()
	base := "/pve/" + url.PathEscape(id) + "/links"
	suggested := 0
	for i := range d.Guests {
		g := &d.Guests[i]
		vmid, err := strconv.ParseUint(g.VMIDText, 10, 64)
		if err != nil {
			continue
		}
		v := &pveGuestLinkView{
			LinkAction: base, UnlinkAction: base + "/remove",
			VMIDText: g.VMIDText, GenerationText: strconv.FormatUint(g.generation, 10),
		}
		g.HostLink = v
		for _, l := range byVMID[vmid] {
			if l.Generation == g.generation {
				v.Linked, v.HostID, v.HostName, v.HostURL = true, l.HostID, names.name(l.HostID), pveHostURL(l.HostID)
				v.Since, v.By = l.CreatedAt, l.CreatedBy
				continue
			}
			v.Reused = append(v.Reused, pveReusedLink{
				HostID: l.HostID, HostName: names.name(l.HostID),
				GenerationText: strconv.FormatUint(l.Generation, 10),
				Notice: fmt.Sprintf("VMID %d was reused: the link to host %s (incarnation %d) does not apply to this guest (incarnation %d). Release it; link this guest only if it really is the same machine.",
					vmid, l.HostID, l.Generation, g.generation),
			})
		}
		if v.Linked || len(v.Reused) > 0 {
			d.LinkForms = true
		}
		if v.Linked {
			continue
		}
		if suggested >= pveSuggestGuestLimit {
			v.SuggestNote = fmt.Sprintf("Suggestions are computed for the first %d unlinked guests only.", pveSuggestGuestLimit)
			continue
		}
		if sctx.Err() != nil {
			v.SuggestNote = pveSuggestSkippedNote
			continue
		}
		suggested++
		if err := h.pveSuggest(sctx, ls, id, vmid, g.generation, names, hostLinks, v); err != nil {
			v.Candidates, v.Conflicts, v.NeedsConfirm = nil, nil, false
			if sctx.Err() != nil {
				v.SuggestNote = pveSuggestSkippedNote
				continue
			}
			h.log.Error("suggest PVE guest links", "remote", id, "vmid", vmid, "error", err)
			v.SuggestNote = "Suggestions unavailable."
		}
		for _, c := range v.Candidates {
			if c.LinkedElsewhere == "" {
				d.LinkForms = true
			}
		}
	}
}

// pveSuggest fills the candidates and conflicts of one unlinked guest.
// The guest conflicts are read only when there is a candidate: they decide
// whether a suggested link needs the review confirmation, and the link
// POST checks them again in any case.
func (h *Handler) pveSuggest(ctx context.Context, ls PVELinkStore, id string, vmid, gen uint64, names *pveHostNames, hostLinks *pveHostLinks, v *pveGuestLinkView) error {
	cands, err := ls.SuggestHosts(ctx, id, vmid, gen)
	if err != nil {
		return err
	}
	if len(cands) == 0 {
		return nil
	}
	conflicts, err := ls.GuestConflicts(ctx, id, vmid, gen)
	if err != nil {
		return err
	}
	v.Conflicts = conflicts
	v.NeedsConfirm = len(conflicts) > 0
	byHost := map[string]*pveLinkCandidate{}
	var order []string
	for _, c := range cands {
		pc, ok := byHost[c.HostID]
		if !ok {
			pc = &pveLinkCandidate{HostID: c.HostID, HostName: names.name(c.HostID), Kind: pveMatchPossibleLabel}
			byHost[c.HostID] = pc
			order = append(order, c.HostID)
		}
		if c.Match == pveinventory.MatchMAC {
			pc.Kind = pveMatchMACLabel
		}
		pc.Details = append(pc.Details, c.Detail)
		pc.Conflict = pc.Conflict || c.Conflict
	}
	sort.Strings(order)
	for _, hostID := range order {
		pc := byHost[hostID]
		if pc.Conflict {
			v.NeedsConfirm = true
		}
		other, err := hostLinks.elsewhere(ctx, hostID)
		if err != nil {
			return err
		}
		pc.LinkedElsewhere = other
		v.Candidates = append(v.Candidates, *pc)
	}
	return nil
}

// addPVELinks sets HostID on the chart guest boxes from the active links
// when the tree did not carry them (the stored chart tree is built without
// managed hosts). Only links of the exact incarnation to a host the chart
// knows are used; a guest the tree already linked is left alone. Display
// only: the link is never an SSH identity. A read error leaves the boxes
// unlinked (logged).
func (h *Handler) addPVELinks(ctx context.Context, nodes []pveNodeView, hosts []inventory.Host) {
	ls := h.pveLinkStore()
	if ls == nil || len(nodes) == 0 {
		return
	}
	known := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		known[host.ID] = true
	}
	type key struct {
		vmid, gen uint64
	}
	byRemote := map[string]map[key]string{}
	for i := range nodes {
		n := &nodes[i]
		links, ok := byRemote[n.remoteID]
		if !ok {
			links = map[key]string{}
			list, err := ls.ListLinks(ctx, n.remoteID, pveinventory.MaxLinksQuery)
			if err != nil {
				h.log.Error("org chart: PVE links failed", "remote", n.remoteID, "error", err)
			}
			for _, l := range list {
				links[key{l.VMID, l.Generation}] = l.HostID
			}
			byRemote[n.remoteID] = links
		}
		for j := range n.Guests {
			g := &n.Guests[j]
			if hostID := links[key{g.VMID, g.generation}]; g.HostID == "" && known[hostID] {
				g.HostID = hostID
			}
		}
	}
}

// pvePrivileged reports whether a privileged session is open on the
// executor. An unreadable status counts as not open (fail closed).
func (h *Handler) pvePrivileged(ctx context.Context) bool {
	if h.status == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, statusCallTimeout)
	defer cancel()
	st, err := h.status.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		h.log.Error("privileged session check for PVE link", "error", err)
		return false
	}
	return st.GetPrivilegedSessionActive()
}

// pveLinkRequest holds the checked common fields of a link or unlink POST.
type pveLinkRequest struct {
	store      PVELinkStore
	remoteID   string
	user       string
	vmid       uint64
	generation uint64
}

// pveLinkPrecheck answers the request itself unless it is a POST from a
// logged-in user with an open privileged session, for a known remote, with
// a readable form naming a guest incarnation.
func (h *Handler) pveLinkPrecheck(ctx context.Context, w http.ResponseWriter, r *http.Request) (pveLinkRequest, bool) {
	ls := h.pveLinkStore()
	if ls == nil {
		http.NotFound(w, r)
		return pveLinkRequest{}, false
	}
	id := r.PathValue("id")
	if !pvecontract.ValidRemoteID(id) {
		http.NotFound(w, r)
		return pveLinkRequest{}, false
	}
	user := webUser(r)
	if !pveLinkActorRe.MatchString(user) || user == "unknown" {
		http.Error(w, "linking needs a logged-in user whose name can be recorded", http.StatusForbidden)
		return pveLinkRequest{}, false
	}
	if !h.pvePrivileged(ctx) {
		http.Error(w, "linking guests to hosts needs an open privileged session: open one on the dashboard and try again", http.StatusForbidden)
		return pveLinkRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, pveLinkFormMax)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return pveLinkRequest{}, false
		}
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return pveLinkRequest{}, false
	}
	if _, err := h.pve.GetRemote(ctx, id); err != nil {
		if errors.Is(err, pveinventory.ErrRemoteNotFound) {
			http.NotFound(w, r)
			return pveLinkRequest{}, false
		}
		h.log.Error("get PVE remote for link", "remote", id, "error", err)
		http.Error(w, "inventory unavailable", http.StatusInternalServerError)
		return pveLinkRequest{}, false
	}
	vmid, err1 := strconv.ParseUint(r.PostFormValue("vmid"), 10, 64)
	gen, err2 := strconv.ParseUint(r.PostFormValue("generation"), 10, 64)
	if err1 != nil || err2 != nil {
		http.Error(w, "vmid and generation must be numbers", http.StatusBadRequest)
		return pveLinkRequest{}, false
	}
	return pveLinkRequest{store: ls, remoteID: id, user: user, vmid: vmid, generation: gen}, true
}

// pveLinkError answers a store error of a link or unlink.
func (h *Handler) pveLinkError(w http.ResponseWriter, op string, in pveLinkRequest, err error) {
	switch {
	case errors.Is(err, pveinventory.ErrGuestNotFound):
		http.Error(w, "guest not found: it may have been recreated, reload the page", http.StatusNotFound)
	case errors.Is(err, pveinventory.ErrManagedHostNotFound), errors.Is(err, inventory.ErrHostNotFound):
		http.Error(w, "managed host not found", http.StatusNotFound)
	case errors.Is(err, pveinventory.ErrLinkNotFound):
		http.Error(w, "this guest is not linked", http.StatusNotFound)
	case errors.Is(err, pveinventory.ErrLinkExists):
		http.Error(w, "this guest is already linked: release the link first", http.StatusConflict)
	case errors.Is(err, pveinventory.ErrHostAlreadyLinked):
		http.Error(w, "this host is already linked to another guest: release that link first", http.StatusConflict)
	default:
		h.log.Error(op, "remote", in.remoteID, "vmid", in.vmid, "generation", in.generation, "error", err)
		http.Error(w, "inventory unavailable", http.StatusInternalServerError)
	}
}

// pveLinkRedirect sends the browser back to the guest row.
func pveLinkRedirect(w http.ResponseWriter, r *http.Request, in pveLinkRequest) {
	http.Redirect(w, r, "/pve/"+url.PathEscape(in.remoteID)+"#guest-"+strconv.FormatUint(in.vmid, 10), http.StatusSeeOther)
}

// handlePVELink creates one explicit link (POST /pve/{id}/links: vmid,
// generation, host, confirm_conflict). A guest or candidate with a MAC/IP
// conflict needs confirm_conflict=1, the reviewed confirmation. host may
// be any inventory host, not only a suggested one: the admin decides,
// suggestions are help (the store still refuses unknown hosts and a host
// already linked to another guest).
func (h *Handler) handlePVELink(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), pveCallTimeout)
	defer cancel()
	in, ok := h.pveLinkPrecheck(ctx, w, r)
	if !ok {
		return
	}
	host := r.PostFormValue("host")
	if !pveLinkHostIDRe.MatchString(host) {
		http.Error(w, "host must be an inventory host ID", http.StatusBadRequest)
		return
	}
	conflict, err := pveLinkConflict(ctx, in, host)
	if err != nil {
		h.pveLinkError(w, "check PVE link conflicts", in, err)
		return
	}
	if conflict && r.PostFormValue("confirm_conflict") != "1" {
		http.Error(w, "this guest has a MAC or IP conflict: review it and tick the confirmation before linking", http.StatusConflict)
		return
	}
	if _, err := in.store.CreateLink(ctx, in.remoteID, in.vmid, in.generation, host, in.user); err != nil {
		h.pveLinkError(w, "create PVE link", in, err)
		return
	}
	h.log.Info("audit", "kind", "pve_guest_linked", "remote", in.remoteID, "vmid", in.vmid,
		"generation", in.generation, "host", host, "user", in.user, "conflict_confirmed", conflict)
	pveLinkRedirect(w, r, in)
}

// pveLinkConflict reports whether linking host to the guest needs the
// conflict confirmation: the guest has a MAC/IP conflict, or a match of
// this host is flagged as one.
func pveLinkConflict(ctx context.Context, in pveLinkRequest, host string) (bool, error) {
	conflicts, err := in.store.GuestConflicts(ctx, in.remoteID, in.vmid, in.generation)
	if err != nil {
		return false, err
	}
	if len(conflicts) > 0 {
		return true, nil
	}
	cands, err := in.store.SuggestHosts(ctx, in.remoteID, in.vmid, in.generation)
	if err != nil {
		return false, err
	}
	for _, c := range cands {
		if c.HostID == host && c.Conflict {
			return true, nil
		}
	}
	return false, nil
}

// handlePVEUnlink releases one link (POST /pve/{id}/links/remove: vmid,
// generation, reason). The link is kept in the history with the reason.
func (h *Handler) handlePVEUnlink(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), pveCallTimeout)
	defer cancel()
	in, ok := h.pveLinkPrecheck(ctx, w, r)
	if !ok {
		return
	}
	reason, ok := pveUnlinkReason(r.PostFormValue("reason"))
	if !ok {
		http.Error(w, fmt.Sprintf("a reason of 1 to %d bytes (UTF-8) without control characters is required: an ASCII character is one byte, umlauts and other non-ASCII characters are two or more",
			pveinventory.MaxUnlinkReasonLen), http.StatusBadRequest)
		return
	}
	l, err := in.store.Unlink(ctx, in.remoteID, in.vmid, in.generation, in.user, reason)
	if err != nil {
		h.pveLinkError(w, "unlink PVE guest", in, err)
		return
	}
	h.log.Info("audit", "kind", "pve_guest_unlinked", "remote", in.remoteID, "vmid", in.vmid,
		"generation", in.generation, "host", l.HostID, "user", in.user, "reason", reason)
	pveLinkRedirect(w, r, in)
}

// pveUnlinkReason trims and checks an unlink reason: valid UTF-8, not
// empty, at most pveinventory.MaxUnlinkReasonLen bytes (the store's limit,
// so a valid reason never fails in the store; the only limit, since a
// character limit of the same size could never apply first), no control
// characters. The form's maxlength only stops ASCII text early.
func pveUnlinkReason(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || len(s) > pveinventory.MaxUnlinkReasonLen {
		return "", false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return "", false
		}
	}
	return s, true
}
