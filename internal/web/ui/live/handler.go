// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// maxTargetsBodyBytes bounds the visible-box update body.
const maxTargetsBodyBytes = 16 * 1024

// Options configure the live endpoints.
type Options struct {
	// Hub is the fan-out hub. Required.
	Hub *Hub
	// Log receives resolution errors (the client only sees a denied
	// list). Nil means slog.Default().
	Log *slog.Logger
	// Session returns the key of the authenticated session of a
	// request. Required: the live endpoints are logged-in only.
	Session func(r *http.Request) (string, bool)
	// Leases returns the current telemetry leases (P1-26). Nil means
	// no live targets are ever resolved.
	Leases func(ctx context.Context) ([]pvecollect.TelemetryLease, error)
	// Tree returns the org-chart tree; it binds a guest box to its
	// incarnation generation so a box can never be answered from
	// another generation's samples. Nil means guest boxes are not
	// resolved.
	Tree func(ctx context.Context) (pveinventory.Tree, error)
}

// Handler serves the live chart endpoints.
type Handler struct {
	hub     *Hub
	log     *slog.Logger
	session func(r *http.Request) (string, bool)
	leases  func(ctx context.Context) ([]pvecollect.TelemetryLease, error)
	tree    func(ctx context.Context) (pveinventory.Tree, error)
}

// New returns a Handler. Hub and Session are required.
func New(o Options) (*Handler, error) {
	if o.Hub == nil {
		return nil, errors.New("live: hub is required")
	}
	if o.Session == nil {
		return nil, errors.New("live: session is required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Handler{hub: o.Hub, log: o.Log, session: o.Session, leases: o.Leases, tree: o.Tree}, nil
}

// Events is the SSE stream of one viewer. It requires a session (the
// server wraps it; the check here is the testable backstop). On connect
// it sends a "hello" event carrying the viewer ID; the client then posts
// its visible boxes to Targets with that ID.
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := h.session(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	viewerID, err := newViewerID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ch, err := h.hub.Add(viewerID, sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer h.hub.Remove(viewerID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	writeEvent(w, flusher, Event{Name: "hello", Data: helloData(viewerID)})

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeEvent(w, flusher, ev)
		}
	}
}

// boxRef is one visible box as the client describes it. The fields are
// validated; the box ID is built server-side.
type boxRef struct {
	Kind string  `json:"kind"`
	Name string  `json:"name"` // node name (kind "node")
	Node string  `json:"node"` // node name (kind "guest")
	VMID *uint64 `json:"vmid"` // guest VMID (kind "guest")
	ID   string  `json:"id"`   // host ID (kind "host")
}

// Targets sets the viewer's visible boxes. The body is JSON:
//
//	{"viewer": "<id>", "boxes": [{"kind":"node","name":"pve1"},
//	                               {"kind":"guest","node":"pve1","vmid":101},
//	                               {"kind":"host","id":"host-1"}]}
//
// It answers {"granted": [...], "denied": [...]} with box IDs. A box is
// granted when at least one of its exact targets is still covered by an
// on-demand lease (P1-26); everything else is denied and the client
// keeps the server-rendered value with its age.
func (h *Handler) Targets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := h.session(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTargetsBodyBytes+1))
	if err != nil || len(body) > maxTargetsBodyBytes {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Viewer string   `json:"viewer"`
		Boxes  []boxRef `json:"boxes"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !validViewerID(req.Viewer) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Boxes) > maxViewerBoxes {
		http.Error(w, "too many boxes", http.StatusBadRequest)
		return
	}
	boxes, denied := h.resolve(r.Context(), req.Boxes)
	granted, err := h.hub.SetBoxes(req.Viewer, sess, boxes)
	if err != nil {
		// Unknown viewer or session mismatch: the stream is gone or
		// belongs to someone else; the client must reopen it.
		http.Error(w, "viewer expired", http.StatusGone)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Granted []string `json:"granted"`
		Denied  []string `json:"denied"`
	}{granted, denied})
}

// resolve maps the refs to the exact leased targets. A ref matches every
// lease target with the same identity fields (a node name can exist on
// several remotes; a guest is bound to its tree generation; a host
// matches both of its telemetry actions). Nothing is ever added that a
// lease does not list — the live endpoints widen no scope.
func (h *Handler) resolve(ctx context.Context, refs []boxRef) (map[string][]pvecollect.TelemetryTarget, []string) {
	boxes := map[string][]pvecollect.TelemetryTarget{}
	denied := []string{}
	if len(refs) == 0 {
		return boxes, denied
	}
	var targets []pvecollect.TelemetryTarget
	if h.leases != nil {
		ls, err := h.leases(ctx)
		if err != nil {
			h.log.Error("live: list leases", "err", err)
		} else {
			for _, l := range ls {
				targets = append(targets, l.Targets...)
			}
		}
	}
	var tree pveinventory.Tree
	if h.tree != nil {
		t, err := h.tree(ctx)
		if err != nil {
			h.log.Error("live: chart tree", "err", err)
		} else {
			tree = t
		}
	}
	for _, ref := range refs {
		box, ok := ref.boxID()
		if !ok {
			continue
		}
		var match []pvecollect.TelemetryTarget
		for _, t := range targets {
			if ref.matches(t, tree) {
				match = append(match, t)
			}
		}
		if len(match) == 0 {
			denied = append(denied, box)
			continue
		}
		if len(match) > maxTargetsPerBox {
			match = match[:maxTargetsPerBox]
		}
		boxes[box] = match
	}
	return boxes, denied
}

// boxID validates the ref's fields and builds the box ID from them.
func (ref boxRef) boxID() (string, bool) {
	switch ref.Kind {
	case "node":
		if !pvecontract.ValidNodeName(ref.Name) {
			return "", false
		}
		return "node:" + ref.Name, true
	case "guest":
		if !pvecontract.ValidNodeName(ref.Node) {
			return "", false
		}
		if ref.VMID == nil || *ref.VMID < pvecontract.MinVMID || *ref.VMID > pvecontract.MaxVMID {
			return "", false
		}
		return "guest:" + ref.Node + ":" + strconv.FormatUint(*ref.VMID, 10), true
	case "host":
		if !canonical.ValidHostID(ref.ID) {
			return "", false
		}
		return "host:" + ref.ID, true
	}
	return "", false
}

// matches reports whether the lease target is one of the ref's exact
// targets.
func (ref boxRef) matches(t pvecollect.TelemetryTarget, tree pveinventory.Tree) bool {
	switch ref.Kind {
	case "node":
		return t.Source == pvecollect.TelemetryProvider &&
			t.Kind == pvecollect.TelemetryKindNode && t.Node == ref.Name
	case "guest":
		if t.Source == pvecollect.TelemetryProvider {
			if t.Kind != pvecollect.TelemetryKindQEMU && t.Kind != pvecollect.TelemetryKindLXC {
				return false
			}
			if t.Node != ref.Node || t.VMID != *ref.VMID {
				return false
			}
			// Bind the box to the incarnation the chart shows; without
			// the tree the generation is unknown and the guest is not
			// resolved (no scope widening through a stale DOM).
			return t.Generation == guestGeneration(tree, ref.Node, *ref.VMID)
		}
		// A guest box linked to a managed host shows that host's
		// observations; the link is display-only and the target stays
		// the exact leased host target.
		return t.Source == pvecollect.TelemetrySSH && t.HostID == guestHostID(tree, ref.Node, *ref.VMID)
	case "host":
		return t.Source == pvecollect.TelemetrySSH && t.HostID == ref.ID
	}
	return false
}

// guestGeneration returns the generation of the guest box in the tree,
// or 0 when the tree does not contain that guest (no match).
func guestGeneration(tree pveinventory.Tree, node string, vmid uint64) uint64 {
	for _, root := range tree.Roots {
		if root.Kind != pveinventory.KindPVENode || root.Name != node {
			continue
		}
		for _, g := range root.Children {
			if g.Kind == pveinventory.KindGuest && g.VMID == vmid {
				return g.Generation
			}
		}
	}
	return 0
}

// guestHostID returns the managed host linked to the guest box, or ""
// when the tree does not contain that guest or it is not linked (no
// SSH target matches, since lease targets always carry a host ID).
func guestHostID(tree pveinventory.Tree, node string, vmid uint64) string {
	for _, root := range tree.Roots {
		if root.Kind != pveinventory.KindPVENode || root.Name != node {
			continue
		}
		for _, g := range root.Children {
			if g.Kind == pveinventory.KindGuest && g.VMID == vmid {
				return g.HostID
			}
		}
	}
	return ""
}

func writeEvent(w http.ResponseWriter, f http.Flusher, ev Event) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Name, ev.Data)
	f.Flush()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
