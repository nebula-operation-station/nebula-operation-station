// SPDX-License-Identifier: AGPL-3.0-or-later

package leasewatch

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func run(grant, action, host string, ok bool, at time.Duration) RunResult {
	return RunResult{GrantID: grant, Action: action, HostLabel: host, Success: ok, At: testBase.Add(at)}
}

func mustRunFailed(t *testing.T, results []RunResult, st State) ([]Event, State) {
	t.Helper()
	events, next, err := RunFailed(results, st)
	if err != nil {
		t.Fatalf("RunFailed: unexpected error: %v", err)
	}
	return events, next
}

func TestRunFailedEpisodeLifecycle(t *testing.T) {
	tests := []struct {
		name    string
		steps   [][]RunResult
		wantPer []int // number of events per step
	}{
		{
			name:    "first failure emits, repeat failures stay silent until success",
			steps:   [][]RunResult{{run("g1", "apt.upgrade", "web-1", false, 0)}, {run("g1", "apt.upgrade", "web-1", false, time.Hour)}, {run("g1", "apt.upgrade", "web-1", false, 2*time.Hour)}},
			wantPer: []int{1, 0, 0},
		},
		{
			name: "success ends the episode, next failure is a new episode",
			steps: [][]RunResult{
				{run("g1", "apt.upgrade", "web-1", false, 0)},
				{run("g1", "apt.upgrade", "web-1", true, time.Hour)},
				{run("g1", "apt.upgrade", "web-1", false, 2*time.Hour)},
			},
			wantPer: []int{1, 0, 1},
		},
		{
			name:    "success without open episode emits nothing",
			steps:   [][]RunResult{{run("g1", "apt.upgrade", "web-1", true, 0)}},
			wantPer: []int{0},
		},
		{
			name: "distinct grant, action and host are separate episodes",
			steps: [][]RunResult{{
				run("g1", "apt.upgrade", "web-1", false, 0),
				run("g1", "apt.upgrade", "web-2", false, 0),
				run("g1", "reboot", "web-1", false, 0),
				run("g2", "apt.upgrade", "web-1", false, 0),
			}},
			wantPer: []int{4},
		},
		{
			name: "success on one host does not close another host's episode",
			steps: [][]RunResult{
				{run("g1", "apt.upgrade", "web-1", false, 0), run("g1", "apt.upgrade", "web-2", false, 0)},
				{run("g1", "apt.upgrade", "web-1", true, time.Hour)},
				{run("g1", "apt.upgrade", "web-2", false, 2*time.Hour)},
			},
			wantPer: []int{2, 0, 0},
		},
		{
			name: "fail then success in one batch, ordered by time, emits once per episode",
			steps: [][]RunResult{{
				run("g1", "apt.upgrade", "web-1", true, 2*time.Hour),
				run("g1", "apt.upgrade", "web-1", false, time.Hour),
			}},
			wantPer: []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st State
			for i, step := range tt.steps {
				var events []Event
				events, st = mustRunFailed(t, step, st)
				if len(events) != tt.wantPer[i] {
					t.Fatalf("step %d: %d events, want %d", i, len(events), tt.wantPer[i])
				}
			}
		})
	}
}

func TestRunFailedEventFields(t *testing.T) {
	events, _ := mustRunFailed(t, []RunResult{run("g1", "reboot", "db-1", false, time.Hour)}, State{})
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if e.Type != EventRunFailed || e.GrantID != "g1" || e.Action != "reboot" || e.HostLabel != "db-1" {
		t.Errorf("event = %+v", e)
	}
	if !e.At.Equal(testBase.Add(time.Hour)) {
		t.Errorf("At = %s, want %s", e.At, testBase.Add(time.Hour))
	}
}

func TestRunFailedClockRewindDoesNotRepeat(t *testing.T) {
	// The episode opened at t+5h; a later-recorded result carrying an earlier
	// timestamp must not open a second episode.
	events, st := mustRunFailed(t, []RunResult{run("g1", "a", "h", false, 5*time.Hour)}, State{})
	if len(events) != 1 {
		t.Fatalf("first failure: %d events", len(events))
	}
	events, _ = mustRunFailed(t, []RunResult{run("g1", "a", "h", false, time.Hour)}, st)
	if len(events) != 0 {
		t.Fatalf("earlier timestamp emitted %d events", len(events))
	}
}

func TestRunFailedDoesNotMutateInputState(t *testing.T) {
	_, st := mustRunFailed(t, []RunResult{run("g1", "a", "h", false, 0)}, State{})
	before := len(st.Episodes)
	_, _ = mustRunFailed(t, []RunResult{run("g2", "a", "h", false, 0)}, st)
	if len(st.Episodes) != before {
		t.Fatalf("input state mutated: %d -> %d episodes", before, len(st.Episodes))
	}
}

func TestRunFailedBoundsOpenEpisodes(t *testing.T) {
	var st State
	var results []RunResult
	for i := 0; i < MaxOpenEpisodes+3; i++ {
		results = append(results, run("g"+strconv.Itoa(i), "a", "h", false, time.Duration(i)*time.Second))
	}
	events, st := mustRunFailed(t, results, st)
	if len(events) != MaxOpenEpisodes+3 {
		t.Fatalf("got %d events, want %d", len(events), MaxOpenEpisodes+3)
	}
	if len(st.Episodes) != MaxOpenEpisodes {
		t.Fatalf("open episodes = %d, want %d", len(st.Episodes), MaxOpenEpisodes)
	}
	// The three oldest episodes (g0..g2) fell out. The oldest tracked one, g3,
	// stays silent; g0 is no longer tracked, so its next failure is reported again.
	events, _ = mustRunFailed(t, []RunResult{run("g3", "a", "h", false, time.Hour)}, st)
	if len(events) != 0 {
		t.Fatalf("tracked episode g3 emitted %d events", len(events))
	}
	events, _ = mustRunFailed(t, []RunResult{run("g0", "a", "h", false, time.Hour)}, st)
	if len(events) != 1 {
		t.Fatalf("evicted episode g0: %d events, want 1", len(events))
	}
}

func TestRunFailedRejectsInvalidResults(t *testing.T) {
	long := make([]byte, MaxLabelLen+1)
	for i := range long {
		long[i] = 'h'
	}
	tests := []struct {
		name string
		r    RunResult
	}{
		{"empty grant", run("", "a", "h", false, 0)},
		{"empty action", run("g", "", "h", false, 0)},
		{"empty host", run("g", "a", "", false, 0)},
		{"overlong host", run("g", "a", string(long), false, 0)},
		{"zero time", RunResult{GrantID: "g", Action: "a", HostLabel: "h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := RunFailed([]RunResult{tt.r}, State{})
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v, want ErrInvalidResult", err)
			}
		})
	}
}

// TestExpiringKeepsEpisodesOfGrantsOutsideSnapshot: an episode is keyed by
// grant, action and host, not by the snapshot. A grant that is missing from the
// snapshot (inactive, over the limit, invalid) must not lose its open episode,
// or each further failure of that run would be reported again.
func TestExpiringKeepsEpisodesOfGrantsOutsideSnapshot(t *testing.T) {
	_, st := mustRunFailed(t, []RunResult{run("g1", "a", "h", false, 0)}, State{})
	_, st, err := Expiring([]Grant{lease("g2", testBase.Add(time.Hour*24*30))}, st, testBase)
	if err != nil {
		t.Fatalf("Expiring: %v", err)
	}
	if len(st.Episodes) != 1 {
		t.Fatalf("episode of grant outside the snapshot dropped: %+v", st.Episodes)
	}
	events, st := mustRunFailed(t, []RunResult{run("g1", "a", "h", false, time.Hour)}, st)
	if len(events) != 0 {
		t.Fatalf("repeated failure of an open episode: %d events, want 0", len(events))
	}
	_, st = mustRunFailed(t, []RunResult{run("g1", "a", "h", true, 2*time.Hour)}, st)
	if len(st.Episodes) != 0 {
		t.Fatalf("success did not close the episode: %+v", st.Episodes)
	}
	events, _ = mustRunFailed(t, []RunResult{run("g1", "a", "h", false, 3*time.Hour)}, st)
	if len(events) != 1 {
		t.Fatalf("failure after the success: %d events, want 1", len(events))
	}
}
