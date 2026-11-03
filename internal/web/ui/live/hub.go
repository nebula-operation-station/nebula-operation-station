// SPDX-License-Identifier: AGPL-3.0-or-later

// Package live delivers sanitized 10-s telemetry values to the logged-in
// chart viewers over server-sent events (ADR 0006 P1-37). It fans out the
// samples the pvecollect scheduler records to the viewers that requested
// the exact target; the scheduler keeps every read within the approved
// leases (P1-26), and this package adds no authority of its own.
package live

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

// Limits of the live delivery.
const (
	// maxViewerBoxes bounds the visible boxes of one viewer.
	maxViewerBoxes = 32
	// maxTargetsPerBox bounds the exact targets one box may resolve to
	// (a node name can exist on several remotes, a host carries two
	// telemetry actions).
	maxTargetsPerBox = 8
	// viewerEventQueue bounds the per-viewer event queue; a viewer whose
	// queue stays full simply misses events until it catches up or the
	// connection drops.
	viewerEventQueue = 64
	// ageTick is the cadence of the deferred-box age labels.
	ageTick = 5 * time.Second
	// staleAfter: a box whose newest observation is older than this is
	// labelled with the age of its last observation (the 10-s live
	// interval plus slack).
	staleAfter = 15 * time.Second
	// maxAgeSeconds bounds the age a label reports; a sample older than
	// this is reported at the bound.
	maxAgeSeconds = 24 * 3600
)

// Event is one server-sent event. Name is a fixed token ("hello",
// "value", "age"); Data is a sanitized JSON payload.
type Event struct {
	Name string
	Data []byte
}

type viewer struct {
	session string
	ch      chan Event
	boxes   map[string][]pvecollect.TelemetryTarget
}

// Hub fans out recorded telemetry samples to the viewers that requested
// the exact target. It is safe for concurrent use.
type Hub struct {
	sched *pvecollect.TelemetryScheduler
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	viewers map[string]*viewer
	closed  bool
}

// NewHub returns a hub over sched. log may be nil (slog.Default); now
// may be nil (time.Now).
func NewHub(sched *pvecollect.TelemetryScheduler, log *slog.Logger, now func() time.Time) *Hub {
	if sched == nil {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Hub{sched: sched, log: log, now: now, viewers: map[string]*viewer{}}
}

// Add registers a new viewer and returns its event channel. sessionKey
// binds the viewer to the authenticated session that opened the stream;
// SetBoxes only accepts that session.
func (h *Hub) Add(viewerID, sessionKey string) (<-chan Event, error) {
	if !validViewerID(viewerID) || sessionKey == "" {
		return nil, fmt.Errorf("live: invalid viewer or session")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, fmt.Errorf("live: hub closed")
	}
	if _, ok := h.viewers[viewerID]; ok {
		return nil, fmt.Errorf("live: viewer exists")
	}
	h.viewers[viewerID] = &viewer{
		session: sessionKey,
		ch:      make(chan Event, viewerEventQueue),
		boxes:   map[string][]pvecollect.TelemetryTarget{},
	}
	return h.viewers[viewerID].ch, nil
}

// Remove ends the viewer: all of its target requests are released and
// its channel is closed.
func (h *Hub) Remove(viewerID string) {
	h.mu.Lock()
	v, ok := h.viewers[viewerID]
	if ok {
		delete(h.viewers, viewerID)
	}
	h.mu.Unlock()
	if !ok {
		return
	}
	for _, targets := range v.boxes {
		for _, t := range targets {
			h.sched.Release(viewerID, t)
		}
	}
	close(v.ch)
}

// SetBoxes replaces the viewer's visible boxes: targets that are no
// longer visible are released, the visible ones are requested (renewing
// the 30-s viewer lease). sessionKey must be the session that opened the
// viewer. It returns the box IDs with at least one requested target.
func (h *Hub) SetBoxes(viewerID, sessionKey string, boxes map[string][]pvecollect.TelemetryTarget) ([]string, error) {
	if !validViewerID(viewerID) || sessionKey == "" {
		return nil, fmt.Errorf("live: invalid viewer or session")
	}
	if len(boxes) > maxViewerBoxes {
		return nil, fmt.Errorf("live: more than %d boxes", maxViewerBoxes)
	}
	for _, targets := range boxes {
		if len(targets) > maxTargetsPerBox {
			return nil, fmt.Errorf("live: more than %d targets per box", maxTargetsPerBox)
		}
	}
	h.mu.Lock()
	v, ok := h.viewers[viewerID]
	if !ok {
		h.mu.Unlock()
		return nil, fmt.Errorf("live: unknown viewer")
	}
	if v.session != sessionKey {
		h.mu.Unlock()
		return nil, fmt.Errorf("live: session mismatch")
	}
	old := v.boxes
	h.mu.Unlock()

	// Request the visible targets; a box is granted when at least one
	// of its targets is still covered by an on-demand lease. Only the
	// requested targets are kept: a target without a live request
	// records no live sample, and its history samples must not reach
	// the viewer through this stream.
	granted := make([]string, 0, len(boxes))
	next := map[string][]pvecollect.TelemetryTarget{}
	requested := map[pvecollect.TelemetryTarget]bool{}
	for box, targets := range boxes {
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

	// Release every old target that is no longer requested (hidden
	// box, or its lease no longer covers it).
	for _, targets := range old {
		for _, t := range targets {
			if !requested[t] {
				h.sched.Release(viewerID, t)
			}
		}
	}

	h.mu.Lock()
	if v, ok := h.viewers[viewerID]; ok {
		v.boxes = next
	}
	h.mu.Unlock()
	return granted, nil
}

// RecordTelemetry implements pvecollect.TelemetrySink: the scheduler
// records every accepted sample through it. It never fails — a viewer
// whose queue is full simply misses the event.
func (h *Hub) RecordTelemetry(_ context.Context, s pvecollect.TelemetrySample) error {
	h.Record(s)
	return nil
}

// Record fans out one recorded sample to the viewers that requested its
// exact target. It is the sink hook of the scheduler; samples of
// unrequested targets reach no viewer.
func (h *Hub) Record(s pvecollect.TelemetrySample) {
	h.mu.Lock()
	type fanout struct {
		v   *viewer
		box string
	}
	var out []fanout
	for _, v := range h.viewers {
		for box, targets := range v.boxes {
			for _, t := range targets {
				if t == s.Target {
					out = append(out, fanout{v, box})
					break
				}
			}
		}
	}
	h.mu.Unlock()
	if len(out) == 0 {
		return
	}
	// The same target can be visible under different box IDs in
	// different viewers (a host box and a guest box linked to that
	// host); the payload carries the viewer's own box ID.
	byBox := map[string]Event{}
	for _, f := range out {
		ev, cached := byBox[f.box]
		if !cached {
			built, ok := valueEvent(f.box, s)
			if !ok {
				continue
			}
			ev = built
			byBox[f.box] = ev
		}
		select {
		case f.v.ch <- ev:
		default:
			h.log.Warn("live: dropping event for full viewer queue", "box", f.box)
		}
	}
}

// Start sends the deferred-box age labels until ctx is done.
func (h *Hub) Start(ctx context.Context) {
	t := time.NewTicker(ageTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.tickAges()
		}
	}
}

// tickAges labels every box whose newest observation is stale with the
// age of its last observation (ADR 0006 P1-37: deferred boxes show the
// age, never a fresh-looking value).
func (h *Hub) tickAges() {
	now := h.now()
	h.mu.Lock()
	type boxAge struct {
		v    *viewer
		box  string
		age  time.Duration
	}
	var out []boxAge
	for _, v := range h.viewers {
		for box, targets := range v.boxes {
			var newest time.Time
			for _, t := range targets {
				if ts, ok := h.sched.LastObserved(t); ok && ts.After(newest) {
					newest = ts
				}
			}
			if newest.IsZero() || now.Sub(newest) <= staleAfter {
				continue
			}
			out = append(out, boxAge{v, box, now.Sub(newest)})
		}
	}
	h.mu.Unlock()
	for _, b := range out {
		ev, ok := ageEvent(b.box, b.age)
		if !ok {
			continue
		}
		select {
		case b.v.ch <- ev:
		default:
		}
	}
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
	return id != "" && len(id) <= pvecollect.MaxViewerIDBytes
}
