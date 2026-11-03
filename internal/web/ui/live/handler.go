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
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// Routes of the live endpoints (served behind the login wrapper).
const (
	// EventsPath is the SSE stream of one viewer.
	EventsPath = "/chart/live/events"
	// TargetsPath receives the viewer's visible boxes.
	TargetsPath = "/chart/live/targets"
)

const (
	// maxTargetsBodyBytes bounds the visible-box update body.
	maxTargetsBodyBytes = 16 * 1024
	// keepAliveInterval is the cadence of SSE comment lines on an idle
	// stream; each write extends the write deadline by writeWindow.
	keepAliveInterval = 15 * time.Second
	writeWindow       = 2 * keepAliveInterval
)

// Options configure the live endpoints.
type Options struct {
	// Hub is the fan-out hub. Required.
	Hub *Hub
	// Log receives resolution errors (the client only sees a denied
	// list). Nil means slog.Default().
	Log *slog.Logger
	// Session returns a stable, non-secret key of the authenticated
	// session of a request. Nil means the web session set by the login
	// wrapper (auth.SessionFrom). The live endpoints are logged-in only.
	Session func(r *http.Request) (string, bool)
	// Leases returns the current telemetry leases (P1-26). Nil means no
	// box is ever resolved.
	Leases func(ctx context.Context) ([]pvecollect.TelemetryLease, error)
	// Tree returns the org-chart tree; it binds a node box to its remote
	// and a guest box to the incarnation generation (and managed-host
	// link) the chart shows. Nil means node and guest boxes are not
	// resolved (host boxes still are).
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

// New returns a Handler. Hub is required.
func New(o Options) (*Handler, error) {
	if o.Hub == nil {
		return nil, errors.New("live: hub is required")
	}
	if o.Session == nil {
		o.Session = webSession
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Handler{hub: o.Hub, log: o.Log, session: o.Session, leases: o.Leases, tree: o.Tree}, nil
}

// webSession keys a request by its web session: the credential and the
// session's creation time (never the session token).
func webSession(r *http.Request) (string, bool) {
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.CredentialID == "" {
		return "", false
	}
	return s.CredentialID + "\x00" + strconv.FormatInt(s.CreatedAt.UnixNano(), 10), true
}

// Register adds the live routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc(EventsPath, h.Events)
	mux.HandleFunc(TargetsPath, h.Targets)
}

// Events is the SSE stream of one viewer. It requires a session (the
// server wraps it in the login check; this check is the backstop). On
// connect it sends a "hello" event carrying the viewer ID; the client
// then posts its visible boxes to Targets with that ID. Disconnecting
// releases every target of the viewer.
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
	viewerID, err := newViewerID()
	if err != nil {
		h.log.Error("live: viewer id", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ch, err := h.hub.Add(viewerID, sess)
	if errors.Is(err, ErrTooManyViewers) {
		http.Error(w, "too many live views", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		http.Error(w, "live values unavailable", http.StatusServiceUnavailable)
		return
	}
	defer h.hub.Remove(viewerID)

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if writeEvent(w, rc, Event{Name: "hello", Data: helloData(viewerID)}) != nil {
		return
	}
	keep := time.NewTicker(keepAliveInterval)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			if writeRaw(w, rc, ": keepalive\n\n") != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if writeEvent(w, rc, ev) != nil {
				return
			}
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

// Targets sets the viewer's visible boxes and renews its 30-s lease.
// The body is JSON:
//
//	{"viewer": "<id>", "boxes": [{"kind":"node","name":"pve1"},
//	                               {"kind":"guest","node":"pve1","vmid":101},
//	                               {"kind":"host","id":"web01"}]}
//
// An empty box list (hidden page) releases every target. It answers
// {"granted": [...], "denied": [...]} with box IDs. A box is granted when
// at least one of its exact targets is covered by an on-demand lease
// (P1-26); a denied box keeps its server-rendered value.
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
		// Unknown viewer or another session's: the client must reopen
		// its own stream.
		http.Error(w, "viewer expired", http.StatusGone)
		return
	}
	writeJSON(w, struct {
		Granted []string `json:"granted"`
		Denied  []string `json:"denied"`
	}{granted, denied})
}

// resolve maps the refs to the exact leased targets. A ref matches every
// on-demand lease target with the same identity (a node is bound to its
// remote in the tree; a guest to its remote and tree generation; a host
// matches each of its telemetry actions). Nothing is added that a lease
// does not list — the live endpoints widen no scope — and the scheduler
// re-checks every target on Request.
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
			h.log.Error("live: list leases", "error", err)
		}
		for _, l := range ls {
			if l.OnDemand {
				targets = append(targets, l.Targets...)
			}
		}
	}
	var tree pveinventory.Tree
	if h.tree != nil {
		t, err := h.tree(ctx)
		if err != nil {
			h.log.Error("live: chart tree", "error", err)
		} else {
			tree = t
		}
	}
	for _, ref := range refs {
		box, ok := ref.boxID()
		if !ok {
			continue
		}
		if _, dup := boxes[box]; dup {
			continue
		}
		var match []pvecollect.TelemetryTarget
		seen := map[pvecollect.TelemetryTarget]bool{}
		for _, t := range targets {
			if !seen[t] && ref.matches(t, tree) {
				seen[t] = true
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
		remote, ok := treeNodeRemote(tree, ref.Name)
		if !ok {
			// Not in the chart, or the name is ambiguous across
			// remotes: not resolved.
			return false
		}
		return t.Source == pvecollect.TelemetryProvider &&
			t.Kind == pvecollect.TelemetryKindNode && t.Node == ref.Name && t.RemoteID == remote
	case "guest":
		g, ok := treeGuest(tree, ref.Node, *ref.VMID)
		if !ok {
			// Without the guest in the tree its incarnation is unknown:
			// not resolved (no scope widening through a stale page).
			return false
		}
		if t.Source == pvecollect.TelemetryProvider {
			return (t.Kind == pvecollect.TelemetryKindQEMU || t.Kind == pvecollect.TelemetryKindLXC) &&
				t.Node == ref.Node && t.VMID == *ref.VMID && t.RemoteID == g.RemoteID &&
				g.Generation != 0 && t.Generation == g.Generation
		}
		// A guest linked to a managed host shows that host's
		// observations; the target stays the exact leased host target.
		return t.Source == pvecollect.TelemetrySSH && g.HostID != "" && t.HostID == g.HostID
	case "host":
		return t.Source == pvecollect.TelemetrySSH && t.HostID == ref.ID
	}
	return false
}

// treeNodeRemote returns the remote of the single PVE node box named
// node. A name shown under several remotes is ambiguous (the page cannot
// tell the boxes apart) and resolves to nothing.
func treeNodeRemote(tree pveinventory.Tree, node string) (string, bool) {
	remote, n := "", 0
	for _, root := range tree.Roots {
		if root.Kind == pveinventory.KindPVENode && root.Name == node {
			remote = root.RemoteID
			n++
		}
	}
	return remote, n == 1 && remote != ""
}

// treeGuest returns the guest box with vmid under the single PVE node
// box named node; its RemoteID is the node's remote.
func treeGuest(tree pveinventory.Tree, node string, vmid uint64) (pveinventory.Box, bool) {
	remote, ok := treeNodeRemote(tree, node)
	if !ok {
		return pveinventory.Box{}, false
	}
	for _, root := range tree.Roots {
		if root.Kind != pveinventory.KindPVENode || root.Name != node {
			continue
		}
		for _, g := range root.Children {
			if g.Kind == pveinventory.KindGuest && g.VMID == vmid {
				g.RemoteID = remote
				return g, true
			}
		}
	}
	return pveinventory.Box{}, false
}

func writeEvent(w io.Writer, rc *http.ResponseController, ev Event) error {
	return writeRaw(w, rc, fmt.Sprintf("event: %s\ndata: %s\n\n", ev.Name, ev.Data))
}

// writeRaw writes and flushes one SSE chunk, extending the server's
// write deadline first (the stream outlives the per-request timeout).
func writeRaw(w io.Writer, rc *http.ResponseController, s string) error {
	_ = rc.SetWriteDeadline(time.Now().Add(writeWindow))
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	return rc.Flush()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
