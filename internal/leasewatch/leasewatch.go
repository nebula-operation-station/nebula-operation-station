// SPDX-License-Identifier: AGPL-3.0-or-later

// Package leasewatch decides which deterministic lease events are due.
//
// It implements the server-side events lease.expiring and lease.run_failed of
// ADR 0016 D10. The package is a pure library: the caller passes grants and run
// results in as values and gets due events and the next State back. It does not
// read a database, call the executor, or send notifications. Times are passed
// in, never read from the clock.
package leasewatch

import (
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"
)

// ExpiryWarnLong is the first expiry threshold: a grant with at most this much
// time left is reported once.
const ExpiryWarnLong = 7 * 24 * time.Hour

// ExpiryWarnShort is the second expiry threshold: a grant with at most this much
// time left is reported once more.
const ExpiryWarnShort = 24 * time.Hour

// Limits enforced by this package. They bound the State that is persisted.
const (
	// MaxIDLen is the maximum length in bytes of a grant ID or a grant name.
	MaxIDLen = 128
	// MaxLabelLen is the maximum length in bytes of a host label or grant name.
	MaxLabelLen = 128
	// MaxActionLen is the maximum length in bytes of an action name.
	MaxActionLen = 64
	// MaxTrackedGrants is the maximum number of grants in one snapshot and the
	// maximum number of grants with stored expiry marks.
	MaxTrackedGrants = 2048
	// MaxOpenEpisodes is the maximum number of open run-failure episodes. The
	// oldest episodes are dropped first.
	MaxOpenEpisodes = 1024
)

// Sentinel errors. Callers check them with errors.Is.
var (
	// ErrInvalidGrant reports a grant that is malformed or duplicated.
	ErrInvalidGrant = errors.New("leasewatch: invalid grant")
	// ErrInvalidResult reports a run result that is malformed.
	ErrInvalidResult = errors.New("leasewatch: invalid run result")
	// ErrTooManyGrants reports more grants than MaxTrackedGrants.
	ErrTooManyGrants = errors.New("leasewatch: too many grants")
)

// GrantKind tells a read lease apart from a schedule grant.
type GrantKind string

const (
	// KindReadLease is a read lease.
	KindReadLease GrantKind = "read_lease"
	// KindScheduleGrant is a schedule grant.
	KindScheduleGrant GrantKind = "schedule_grant"
)

// Grant is the value of one read lease or schedule grant as seen by the watcher.
type Grant struct {
	// ID identifies the grant.
	ID string
	// Name is the display name.
	Name string
	// Kind is the grant type.
	Kind GrantKind
	// ExpiresAt is the end of the grant's validity.
	ExpiresAt time.Time
	// Revoked reports whether the grant was revoked. Revoked grants report nothing.
	Revoked bool
}

// RunResult is the outcome of one run of a leased action on one host.
type RunResult struct {
	// GrantID is the grant the run used.
	GrantID string
	// Action is the action name.
	Action string
	// HostLabel is the host label shown to the admin.
	HostLabel string
	// Success reports whether the run succeeded.
	Success bool
	// At is when the run finished.
	At time.Time
}

// EventType names a deterministic lease event.
type EventType string

const (
	// EventExpiring is the lease.expiring event.
	EventExpiring EventType = "lease.expiring"
	// EventRunFailed is the lease.run_failed event.
	EventRunFailed EventType = "lease.run_failed"
)

// Event is a due lease event. The caller turns it into a notification.
type Event struct {
	// Type is the event name.
	Type EventType
	// GrantID is the grant the event is about.
	GrantID string
	// GrantName is the grant's display name at decision time.
	GrantName string
	// Kind is the grant type. Set for lease.expiring.
	Kind GrantKind
	// Threshold is the expiry threshold that was crossed. Set for lease.expiring.
	Threshold time.Duration
	// ExpiresAt is the grant's expiry. Set for lease.expiring.
	ExpiresAt time.Time
	// Action is the failed action. Set for lease.run_failed.
	Action string
	// HostLabel is the host of the failed run. Set for lease.run_failed.
	HostLabel string
	// At is the time of the decision (lease.expiring) or of the failed run (lease.run_failed).
	At time.Time
}

// Expiring returns the lease.expiring events due at now and the next state.
//
// A grant that is not revoked and has not expired is reported once at
// ExpiryWarnLong and once more at ExpiryWarnShort. A grant first seen inside the
// short window reports only the short threshold. The input state is not changed.
//
// grants must be a complete snapshot. Expiry marks of grants that are not in
// the snapshot are dropped, so a grant that comes back is treated as new. Run
// failure episodes are kept: they are keyed by grant, action and host, not by
// the snapshot, and RunFailed bounds them. Events are ordered by grant ID.
func Expiring(grants []Grant, st State, now time.Time) ([]Event, State, error) {
	if len(grants) > MaxTrackedGrants {
		return nil, State{}, fmt.Errorf("%w: %d > %d", ErrTooManyGrants, len(grants), MaxTrackedGrants)
	}
	live := make(map[string]struct{}, len(grants))
	sorted := make([]Grant, len(grants))
	copy(sorted, grants)
	for _, g := range sorted {
		if err := validateGrant(g); err != nil {
			return nil, State{}, err
		}
		if _, dup := live[g.ID]; dup {
			return nil, State{}, fmt.Errorf("%w: duplicate id %q", ErrInvalidGrant, g.ID)
		}
		live[g.ID] = struct{}{}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	next := State{Seq: st.Seq, Episodes: append([]Episode(nil), st.Episodes...)}
	for id, marks := range st.Expiry {
		if _, ok := live[id]; ok {
			if next.Expiry == nil {
				next.Expiry = make(map[string]ExpiryMarks)
			}
			next.Expiry[id] = marks
		}
	}

	var events []Event
	for _, g := range sorted {
		if g.Revoked || !g.ExpiresAt.After(now) {
			continue
		}
		remaining := g.ExpiresAt.Sub(now)
		marks := next.Expiry[g.ID]
		switch {
		case remaining <= ExpiryWarnShort:
			if !marks.Short {
				events = append(events, expiringEvent(g, ExpiryWarnShort, now))
				marks.Short = true
			}
			// A grant inside the short window has also passed the long threshold.
			marks.Long = true
		case remaining <= ExpiryWarnLong:
			if !marks.Long {
				events = append(events, expiringEvent(g, ExpiryWarnLong, now))
				marks.Long = true
			}
		default:
			continue
		}
		if next.Expiry == nil {
			next.Expiry = make(map[string]ExpiryMarks)
		}
		next.Expiry[g.ID] = marks
	}
	return events, next, nil
}

func expiringEvent(g Grant, threshold time.Duration, now time.Time) Event {
	return Event{
		Type:      EventExpiring,
		GrantID:   g.ID,
		GrantName: g.Name,
		Kind:      g.Kind,
		Threshold: threshold,
		ExpiresAt: g.ExpiresAt,
		At:        now,
	}
}

// RunFailed returns the lease.run_failed events for results and the next state.
//
// Results are processed in order of At; results with equal At keep their input
// order. A failed run opens an episode for its grant, action and host and
// emits one event when it opens. Further failures of that episode are silent.
// A successful run closes the episode. A success without an open episode emits
// nothing. At most MaxOpenEpisodes episodes are kept; the oldest are dropped.
// The input state is not changed.
func RunFailed(results []RunResult, st State) ([]Event, State, error) {
	for _, r := range results {
		if err := validateResult(r); err != nil {
			return nil, State{}, err
		}
	}
	order := make([]int, len(results))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return results[order[a]].At.Before(results[order[b]].At)
	})

	next := State{Seq: st.Seq, Episodes: append([]Episode(nil), st.Episodes...)}
	var events []Event
	for _, i := range order {
		r := results[i]
		pos := findEpisode(next.Episodes, r)
		if r.Success {
			if pos >= 0 {
				next.Episodes = append(next.Episodes[:pos], next.Episodes[pos+1:]...)
			}
			continue
		}
		if pos >= 0 {
			continue
		}
		next.Seq++
		next.Episodes = append(next.Episodes, Episode{
			GrantID:   r.GrantID,
			Action:    r.Action,
			HostLabel: r.HostLabel,
			Seq:       next.Seq,
		})
		if len(next.Episodes) > MaxOpenEpisodes {
			next.Episodes = dropOldest(next.Episodes)
		}
		events = append(events, Event{
			Type:      EventRunFailed,
			GrantID:   r.GrantID,
			Action:    r.Action,
			HostLabel: r.HostLabel,
			At:        r.At,
		})
	}
	return events, next, nil
}

// findEpisode returns the index of the open episode for r, or -1.
func findEpisode(eps []Episode, r RunResult) int {
	for i, ep := range eps {
		if ep.GrantID == r.GrantID && ep.Action == r.Action && ep.HostLabel == r.HostLabel {
			return i
		}
	}
	return -1
}

// dropOldest removes the episode with the smallest Seq.
func dropOldest(eps []Episode) []Episode {
	oldest := 0
	for i := range eps {
		if eps[i].Seq < eps[oldest].Seq {
			oldest = i
		}
	}
	return append(eps[:oldest], eps[oldest+1:]...)
}

func validateGrant(g Grant) error {
	if err := checkText(g.ID, MaxIDLen); err != nil {
		return fmt.Errorf("%w: id: %v", ErrInvalidGrant, err)
	}
	if !utf8.ValidString(g.Name) || len(g.Name) > MaxLabelLen {
		return fmt.Errorf("%w: grant %q: name is not valid UTF-8 or longer than %d bytes", ErrInvalidGrant, g.ID, MaxLabelLen)
	}
	switch g.Kind {
	case KindReadLease, KindScheduleGrant:
	default:
		return fmt.Errorf("%w: grant %q has unknown kind %q", ErrInvalidGrant, g.ID, g.Kind)
	}
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: grant %q has no expiry", ErrInvalidGrant, g.ID)
	}
	return nil
}

func validateResult(r RunResult) error {
	if err := checkText(r.GrantID, MaxIDLen); err != nil {
		return fmt.Errorf("%w: grant id: %v", ErrInvalidResult, err)
	}
	if err := checkText(r.Action, MaxActionLen); err != nil {
		return fmt.Errorf("%w: action: %v", ErrInvalidResult, err)
	}
	if err := checkText(r.HostLabel, MaxLabelLen); err != nil {
		return fmt.Errorf("%w: host label: %v", ErrInvalidResult, err)
	}
	if r.At.IsZero() {
		return fmt.Errorf("%w: run of grant %q has no time", ErrInvalidResult, r.GrantID)
	}
	return nil
}

// checkText requires a non-empty, valid UTF-8 string of at most max bytes.
func checkText(s string, max int) error {
	switch {
	case s == "":
		return errors.New("empty")
	case len(s) > max:
		return fmt.Errorf("longer than %d bytes", max)
	case !utf8.ValidString(s):
		return errors.New("not valid UTF-8")
	}
	return nil
}
