// SPDX-License-Identifier: AGPL-3.0-or-later

// Package live delivers sanitized 10-s telemetry values to the logged-in
// chart viewers over server-sent events (ADR 0006 P1-37). It fans out the
// live samples the pvecollect scheduler records to the viewers that
// requested the exact target; the scheduler keeps every read within the
// approved leases (P1-26), and this package adds no authority of its own.
package live

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

// Limits of the live delivery.
const (
	// maxViewerBoxes bounds the visible boxes of one viewer.
	maxViewerBoxes = 32
	// maxTargetsPerBox bounds the exact targets one box may resolve to
	// (a node name can exist on several remotes, a host carries several
	// telemetry actions).
	maxTargetsPerBox = 8
	// maxViewers bounds the open streams of the whole server.
	maxViewers = 256
	// maxViewersPerSession bounds the open streams of one session (tabs).
	maxViewersPerSession = 8
	// maxSessionRequests bounds the (viewer, target) requests all viewers
	// of one session hold together: a quarter of the scheduler's
	// MaxTelemetryViewers, so one session cannot starve the others.
	// Targets past it are not requested (their boxes stay deferred).
	maxSessionRequests = pvecollect.MaxTelemetryViewers / 4
	// viewerEventQueue bounds the per-viewer event queue; a viewer whose
	// queue is full misses events until it catches up.
	viewerEventQueue = 64
	// viewerLease is how long a viewer's visible boxes stay requested
	// without a renewal (ADR 0006 P1-37: 30-s target leases). It equals
	// the scheduler's own renewal window.
	viewerLease = pvecollect.TelemetryViewerRenewal
	// clientRenewal is the cadence the client re-posts its visible boxes
	// (well inside viewerLease, so one lost update does not expire it).
	clientRenewal = 10 * time.Second
	// tickInterval is the cadence of expiry and deferred-box age labels.
	tickInterval = 5 * time.Second
	// staleAfter: a box whose newest observation is older than this is
	// labelled with the age of its last observation (the 10-s live
	// interval plus slack).
	staleAfter = 15 * time.Second
	// maxAgeSeconds bounds the age a label reports.
	maxAgeSeconds = 24 * 3600
)

// Errors of the hub.
var (
	// ErrUnknownViewer is returned for a viewer ID the hub does not hold
	// for the calling session (expired stream, or another session's).
	ErrUnknownViewer = errors.New("live: unknown viewer")
	// ErrTooManyViewers is returned when a stream limit is reached.
	ErrTooManyViewers = errors.New("live: too many viewers")
	// ErrInvalid is returned for malformed input.
	ErrInvalid = errors.New("live: invalid input")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("live: hub closed")
)

// Scheduler is the P1-26 telemetry scheduler surface the hub uses.
// *pvecollect.TelemetryScheduler implements it.
type Scheduler interface {
	Request(viewerID string, t pvecollect.TelemetryTarget) (time.Time, error)
	Release(viewerID string, t pvecollect.TelemetryTarget)
	LastObserved(t pvecollect.TelemetryTarget) (time.Time, bool)
}

// Event is one server-sent event. Name is a fixed token ("hello",
// "value", "age"); Data is a sanitized JSON payload.
type Event struct {
	Name string
	Data []byte
}

type viewer struct {
	session string
	ch      chan Event
	// setMu serializes SetBoxes of this viewer, so two overlapping
	// updates cannot leave a target requested that neither keeps.
	setMu sync.Mutex
	boxes map[string][]pvecollect.TelemetryTarget // guarded by Hub.mu
	// reserved is the number of distinct targets this viewer holds or
	// is requesting; it counts against maxSessionRequests. Guarded by
	// Hub.mu.
	reserved int
	renewed  time.Time // guarded by Hub.mu
	gone     bool      // guarded by Hub.mu
}

// Hub fans out recorded live samples to the viewers that requested the
// exact target. It is safe for concurrent use.
type Hub struct {
	sched Scheduler
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	viewers map[string]*viewer
	closed  bool
}

// NewHub returns a hub over sched. log may be nil (slog.Default); now
// may be nil (time.Now).
func NewHub(sched Scheduler, log *slog.Logger, now func() time.Time) (*Hub, error) {
	if sched == nil {
		return nil, errors.New("live: scheduler is required")
	}
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Hub{sched: sched, log: log, now: now, viewers: map[string]*viewer{}}, nil
}

// Add registers a new viewer and returns its event channel. sessionKey
// binds the viewer to the authenticated session that opened the stream;
// SetBoxes only accepts that session.
func (h *Hub) Add(viewerID, sessionKey string) (<-chan Event, error) {
	if !validViewerID(viewerID) || sessionKey == "" {
		return nil, ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	if _, ok := h.viewers[viewerID]; ok {
		return nil, ErrInvalid
	}
	if len(h.viewers) >= maxViewers {
		return nil, ErrTooManyViewers
	}
	n := 0
	for _, v := range h.viewers {
		if v.session == sessionKey {
			n++
		}
	}
	if n >= maxViewersPerSession {
		return nil, ErrTooManyViewers
	}
	v := &viewer{
		session: sessionKey,
		ch:      make(chan Event, viewerEventQueue),
		boxes:   map[string][]pvecollect.TelemetryTarget{},
		renewed: h.now(),
	}
	h.viewers[viewerID] = v
	return v.ch, nil
}

// Remove ends the viewer (disconnect): all of its target requests are
// released and its channel is closed.
func (h *Hub) Remove(viewerID string) {
	h.mu.Lock()
	v, ok := h.viewers[viewerID]
	if !ok {
		h.mu.Unlock()
		return
	}
	delete(h.viewers, viewerID)
	v.gone = true
	old := v.boxes
	v.boxes = nil
	h.mu.Unlock()
	h.releaseAll(viewerID, old)
	close(v.ch)
}

func (h *Hub) releaseAll(viewerID string, boxes map[string][]pvecollect.TelemetryTarget) {
	for _, targets := range boxes {
		for _, t := range targets {
			h.sched.Release(viewerID, t)
		}
	}
}

// SetBoxes replaces the viewer's visible boxes and renews its 30-s
// lease: targets that are no longer visible are released (hidden box),
// the visible ones are requested from the scheduler, which accepts only
// targets an active on-demand lease lists. sessionKey must be the
// session that opened the viewer. It returns the box IDs with at least
// one requested target.
func (h *Hub) SetBoxes(viewerID, sessionKey string, boxes map[string][]pvecollect.TelemetryTarget) ([]string, error) {
	if !validViewerID(viewerID) || sessionKey == "" || len(boxes) > maxViewerBoxes {
		return nil, ErrInvalid
	}
	for box, targets := range boxes {
		if !validBoxID(box) || len(targets) > maxTargetsPerBox {
			return nil, ErrInvalid
		}
	}
	h.mu.Lock()
	v, ok := h.viewers[viewerID]
	if !ok || v.session != sessionKey {
		h.mu.Unlock()
		return nil, ErrUnknownViewer
	}
	h.mu.Unlock()

	v.setMu.Lock()
	defer v.setMu.Unlock()

	h.mu.Lock()
	if v.gone {
		h.mu.Unlock()
		return nil, ErrUnknownViewer
	}
	old := v.boxes
	// Reserve this viewer's share of the session budget in the same
	// critical section that reads the other viewers' reservations, so
	// two viewers of one session cannot both overrun it.
	boxes = h.withinSessionBudget(v, boxes)
	v.reserved = distinctTargets(old, boxes)
	h.mu.Unlock()

	// Request the visible targets. Only the targets the scheduler
	// accepted are kept, so a target without a live request never
	// reaches this viewer.
	granted := make([]string, 0, len(boxes))
	next := make(map[string][]pvecollect.TelemetryTarget, len(boxes))
	requested := map[pvecollect.TelemetryTarget]bool{}
	for _, box := range slices.Sorted(maps.Keys(boxes)) {
		targets := boxes[box]
		var ok []pvecollect.TelemetryTarget
		for _, t := range targets {
			if _, err := h.sched.Request(viewerID, t); err == nil {
				ok = append(ok, t)
				requested[t] = true
			}
		}
		if len(ok) > 0 {
			next[box] = ok
			granted = append(granted, box)
		}
	}
	// Release every old target that is no longer requested.
	for _, targets := range old {
		for _, t := range targets {
			if !requested[t] {
				h.sched.Release(viewerID, t)
			}
		}
	}

	h.mu.Lock()
	if v.gone {
		// Removed (disconnect) while requesting: release what this call
		// requested, so nothing outlives the stream.
		h.mu.Unlock()
		h.releaseAll(viewerID, next)
		return nil, ErrUnknownViewer
	}
	v.boxes = next
	v.reserved = distinctTargets(next)
	v.renewed = h.now()
	h.mu.Unlock()
	slices.Sort(granted)
	return granted, nil
}

// withinSessionBudget returns boxes trimmed so that v's distinct targets
// plus those every other viewer of v's session reserved stay within
// maxSessionRequests. Boxes are taken in box-ID order; a target past the
// budget is dropped (its box is not granted if nothing remains). The
// caller holds h.mu.
func (h *Hub) withinSessionBudget(v *viewer, boxes map[string][]pvecollect.TelemetryTarget) map[string][]pvecollect.TelemetryTarget {
	budget := maxSessionRequests
	for _, o := range h.viewers {
		if o != v && o.session == v.session {
			budget -= o.reserved
		}
	}
	out := make(map[string][]pvecollect.TelemetryTarget, len(boxes))
	kept := map[pvecollect.TelemetryTarget]bool{}
	for _, box := range slices.Sorted(maps.Keys(boxes)) {
		var ts []pvecollect.TelemetryTarget
		for _, t := range boxes[box] {
			if !kept[t] {
				if len(kept) >= budget {
					continue
				}
				kept[t] = true
			}
			ts = append(ts, t)
		}
		if len(ts) > 0 {
			out[box] = ts
		}
	}
	return out
}

// distinctTargets counts the distinct targets of the box sets (the
// scheduler counts one request per (viewer, target)).
func distinctTargets(sets ...map[string][]pvecollect.TelemetryTarget) int {
	seen := map[pvecollect.TelemetryTarget]bool{}
	for _, boxes := range sets {
		for _, targets := range boxes {
			for _, t := range targets {
				seen[t] = true
			}
		}
	}
	return len(seen)
}

// RecordTelemetry implements pvecollect.TelemetrySink: the scheduler
// records every accepted sample through it. It never fails — a viewer
// whose queue is full simply misses the event.
func (h *Hub) RecordTelemetry(_ context.Context, s pvecollect.TelemetrySample) error {
	h.Record(s)
	return nil
}

// Record fans out one recorded live sample to the unexpired viewers that
// requested its exact target. History samples and samples of targets no
// viewer requested reach no viewer.
func (h *Hub) Record(s pvecollect.TelemetrySample) {
	if !s.Live {
		return
	}
	now := h.now()
	type fanout struct {
		v   *viewer
		box string
	}
	var out []fanout
	h.mu.Lock()
	for _, v := range h.viewers {
		if expired(v, now) {
			continue
		}
		for box, targets := range v.boxes {
			for _, t := range targets {
				if t == s.Target {
					out = append(out, fanout{v, box})
					break
				}
			}
		}
	}
	// Send under the lock: Remove marks the viewer gone under the lock
	// and closes the channel only after unlocking; trySend checks
	// v.gone under the lock, so a send never hits a closed channel.
	// Sends never block.
	built := map[string]Event{}
	for _, f := range out {
		ev, ok := built[f.box]
		if !ok {
			if ev, ok = valueEvent(f.box, s); !ok {
				continue
			}
			built[f.box] = ev
		}
		trySend(f.v, ev)
	}
	h.mu.Unlock()
}

// trySend queues ev without blocking unless v is gone (its channel may
// be closed); the caller holds Hub.mu.
func trySend(v *viewer, ev Event) {
	if v.gone {
		return
	}
	select {
	case v.ch <- ev:
	default:
	}
}

func expired(v *viewer, now time.Time) bool {
	return now.Sub(v.renewed) > viewerLease
}

// Start runs expiry and the deferred-box age labels until ctx is done.
func (h *Hub) Start(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Tick()
		}
	}
}

// Tick expires viewers whose 30-s lease was not renewed (hidden page,
// suspended tab): their requests are released and their boxes cleared;
// the stream stays open and the next renewal requests them again. Then
// every box whose newest observation is stale is labelled with the age
// of its last observation (ADR 0006 P1-37: deferred boxes show the age,
// never a fresh-looking value).
func (h *Hub) Tick() {
	now := h.now()
	var exp []*viewer
	var expIDs []string
	h.mu.Lock()
	for id, v := range h.viewers {
		if expired(v, now) && len(v.boxes) > 0 {
			exp = append(exp, v)
			expIDs = append(expIDs, id)
		}
	}
	h.mu.Unlock()
	for i, v := range exp {
		h.expire(expIDs[i], v, now)
	}

	// Snapshot the boxes; LastObserved takes the scheduler's lock, which
	// must not nest inside the hub's.
	h.mu.Lock()
	type boxRef struct {
		id      string
		box     string
		targets []pvecollect.TelemetryTarget
	}
	var boxes []boxRef
	for id, v := range h.viewers {
		for box, targets := range v.boxes {
			boxes = append(boxes, boxRef{id, box, targets})
		}
	}
	h.mu.Unlock()

	type label struct {
		id string
		ev Event
	}
	var labels []label
	for _, b := range boxes {
		var newest time.Time
		for _, t := range b.targets {
			if ts, ok := h.sched.LastObserved(t); ok && ts.After(newest) {
				newest = ts
			}
		}
		if newest.IsZero() || now.Sub(newest) <= staleAfter {
			continue
		}
		if ev, ok := ageEvent(b.box, now.Sub(newest)); ok {
			labels = append(labels, label{b.id, ev})
		}
	}
	if len(labels) == 0 {
		return
	}
	h.mu.Lock()
	for _, l := range labels {
		if v, ok := h.viewers[l.id]; ok {
			trySend(v, l.ev)
		}
	}
	h.mu.Unlock()
}

// expire releases the targets of a viewer whose lease ran out. It takes
// the same lock order as SetBoxes (setMu, then Hub.mu) and re-checks the
// expiry under both, so a renewal that ran in between is never undone.
func (h *Hub) expire(id string, v *viewer, now time.Time) {
	v.setMu.Lock()
	defer v.setMu.Unlock()
	h.mu.Lock()
	if v.gone || !expired(v, now) || len(v.boxes) == 0 {
		h.mu.Unlock()
		return
	}
	old := v.boxes
	v.boxes = map[string][]pvecollect.TelemetryTarget{}
	v.reserved = 0
	h.mu.Unlock()
	h.releaseAll(id, old)
}

// Close ends all viewers (server shutdown).
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	ids := make([]string, 0, len(h.viewers))
	for id := range h.viewers {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	for _, id := range ids {
		h.Remove(id)
	}
}

func validViewerID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
