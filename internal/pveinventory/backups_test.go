// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the per-guest backup freshness model (ADR 0006, ticket P1-29).
//
// They cover the acceptance criteria: the five freshness states (ok, overdue,
// failed, stale-data, expected-off) plus unknown; the injected clock; exact
// guest association by (remote, vmid, incarnation); task/catalog/verification
// confidence kept separate; and unknown never rendered as safe.

package pveinventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// nowUnix is the Unix seconds of the shared test base, used to build evidence
// timestamps relative to the injected clock.
var nowUnix = testBase.Unix()

// guestWithBackups builds a guest observation with an explicit backups dataset.
func guestWithBackups(vmid, gen uint64, name string, status pvecontract.GuestStatus, backups pvecontract.Dataset[[]pvecontract.BackupEvidence]) pvecontract.GuestObservation {
	return pvecontract.GuestObservation{
		VMID:       vmid,
		Kind:       pvecontract.GuestQEMU,
		Node:       "p1",
		Name:       name,
		Status:     status,
		Generation: gen,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    backups,
	}
}

// taskEvidence builds a vzdump task evidence row.
func taskEvidence(name, status string, started, finished int64) pvecontract.BackupEvidence {
	return pvecontract.BackupEvidence{
		Source:       pvecontract.BackupVZDump,
		Kind:         pvecontract.BackupKindTask,
		Name:         name,
		Status:       status,
		StartedUnix:  started,
		FinishedUnix: finished,
		Verified:     pvecontract.Unknown,
	}
}

// catalogEvidence builds an affirmative PBS catalog evidence row.
func catalogEvidence(name string, ctime int64, verified pvecontract.TriState) pvecontract.BackupEvidence {
	return pvecontract.BackupEvidence{
		Source:       pvecontract.BackupPBS,
		Kind:         pvecontract.BackupKindCatalog,
		Name:         name,
		Status:       "present",
		FinishedUnix: ctime,
		Verified:     verified,
	}
}

func TestEvaluateFreshness(t *testing.T) {
	tests := []struct {
		name  string
		in    FreshnessInput
		want  FreshnessState
		check func(t *testing.T, f Freshness)
	}{
		{
			name: "ok: recent task success",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100)},
			},
			want: FreshnessOK,
			check: func(t *testing.T, f Freshness) {
				if f.Task.LastSuccessUnix != nowUnix-7100 {
					t.Fatalf("task last success = %d, want %d", f.Task.LastSuccessUnix, nowUnix-7100)
				}
				if f.LastSuccessUnix != nowUnix-7100 {
					t.Fatalf("last success = %d, want %d", f.LastSuccessUnix, nowUnix-7100)
				}
			},
		},
		{
			name: "overdue: old task success",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "success", nowUnix-108000, nowUnix-107900)},
			},
			want: FreshnessOverdue,
		},
		{
			name: "overdue: complete enumeration found no backup",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
			},
			want: FreshnessOverdue,
		},
		{
			name: "failed: failure after last success",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{
					taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100),
					taskEvidence("b2", "failed", nowUnix-3600, nowUnix-3500),
				},
			},
			want: FreshnessFailed,
		},
		{
			name: "failed: only a failure",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "failed", nowUnix-3600, nowUnix-3500)},
			},
			want: FreshnessFailed,
		},
		{
			name: "ok: success newer than a prior failure",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{
					taskEvidence("b1", "failed", nowUnix-7200, nowUnix-7100),
					taskEvidence("b2", "success", nowUnix-3600, nowUnix-3500),
				},
			},
			want: FreshnessOK,
		},
		{
			name: "stale-data: observation older than the stale limit",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase.Add(-20 * time.Minute),
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100)},
			},
			want: FreshnessStaleData,
		},
		{
			name: "expected-off: explicitly exempt stopped guest",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestStopped),
				ExpectedOff:  true,
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
			},
			want: FreshnessExpectedOff,
		},
		{
			name: "unknown: unavailable dataset",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateUnavailable, DatasetReason: "denied", DatasetObservedAt: testBase,
			},
			want: FreshnessUnknown,
		},
		{
			name: "unknown: partial and empty",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StatePartial, DatasetReason: "incomplete", DatasetObservedAt: testBase,
			},
			want: FreshnessUnknown,
		},
		{
			name: "ok: catalog present backup",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{catalogEvidence("vol1", nowUnix-3600, pvecontract.Unknown)},
			},
			want: FreshnessOK,
			check: func(t *testing.T, f Freshness) {
				if !f.Catalog.Present {
					t.Fatalf("catalog present = false, want true")
				}
				if f.Task.Count != 0 {
					t.Fatalf("task count = %d, want 0", f.Task.Count)
				}
			},
		},
		{
			name: "overdue: operator-configured max age",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, MaxAge: time.Hour,
				GuestStatus:  string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100)},
			},
			want: FreshnessOverdue,
		},
		{
			name: "verification: verified catalog entry",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{catalogEvidence("vol1", nowUnix-3600, pvecontract.Yes)},
			},
			want: FreshnessOK,
			check: func(t *testing.T, f Freshness) {
				if f.Verification.State != pvecontract.Yes {
					t.Fatalf("verification = %q, want yes", f.Verification.State)
				}
			},
		},
		{
			name: "model requires affirmative catalog status",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{{
					Source: pvecontract.BackupPBS, Kind: pvecontract.BackupKindCatalog,
					Name: "vol1", Status: "present", FinishedUnix: nowUnix - 3600, Verified: pvecontract.Unknown,
				}},
			},
			want: FreshnessOK,
		},
		{
			name: "channels separate: task success but no catalog",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				Evidence: []pvecontract.BackupEvidence{taskEvidence("b1", "success", nowUnix-3600, nowUnix-3500)},
			},
			want: FreshnessOK,
			check: func(t *testing.T, f Freshness) {
				if f.Task.LastSuccessUnix == 0 {
					t.Fatalf("task last success = 0, want nonzero")
				}
				if f.Catalog.Present {
					t.Fatalf("catalog present = true, want false")
				}
				if f.Verification.State != pvecontract.Unknown {
					t.Fatalf("verification = %q, want unknown", f.Verification.State)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := EvaluateFreshness(tc.in)
			if f.State != tc.want {
				t.Fatalf("state = %q, want %q (reason %q)", f.State, tc.want, f.Reason)
			}
			if tc.check != nil {
				tc.check(t, f)
			}
		})
	}
}

func TestGuestBackupFreshnessUnknownCatalogIsNotPresent(t *testing.T) {
	s, _, _ := newTestStore(t)
	e := catalogEvidence("unknown-volume", nowUnix-60, pvecontract.Yes)
	e.Status = "unknown"
	ingestOK(t, s, newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
		pvecontract.AvailableDataset([]pvecontract.BackupEvidence{e}))).build())
	f, err := s.GuestBackupFreshness(context.Background(), "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.State != FreshnessUnknown || f.Catalog.Present || f.LastSuccessUnix != 0 || f.Verification.State != pvecontract.Unknown || f.Verification.Count != 0 {
		t.Fatalf("unknown catalog became affirmative evidence: %+v", f)
	}
}

func TestGuestBackupFreshnessCatalogDeletionBetweenPolls(t *testing.T) {
	for _, sameTime := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-time=%t", sameTime), func(t *testing.T) {
			s, _, now := newTestStore(t)
			ctx := context.Background()
			obs := newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
				pvecontract.AvailableDataset([]pvecontract.BackupEvidence{catalogEvidence("deleted", nowUnix-60, pvecontract.Yes)}))).build()
			ingestOK(t, s, obs)
			before, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
			if err != nil || before.State != FreshnessOK || !before.Catalog.Present || before.Verification.State != pvecontract.Yes {
				t.Fatalf("before deletion: %+v, %v", before, err)
			}
			obs.CollectionGeneration++
			if !sameTime {
				obs.ObservedAt = obs.ObservedAt.Add(5 * time.Minute)
			}
			*now = obs.ObservedAt
			obs.Guests.Value[0].Backups.Value = nil
			ingestOK(t, s, obs)
			after, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
			if err != nil || after.State != FreshnessOverdue || after.Catalog.Present || after.Catalog.Count != 0 || after.LastSuccessUnix != 0 || after.Verification.State != pvecontract.Unknown || after.Verification.Count != 0 {
				t.Fatalf("deleted catalog still current: %+v, %v", after, err)
			}
			retained, err := s.ListBackups(ctx, "remote-a", 100, 1, 0)
			if err != nil || len(retained) != 1 || !retained[0].ObservedAt.Equal(testBase) {
				t.Fatalf("historical evidence was not retained with its age: %+v, %v", retained, err)
			}
		})
	}
}

func TestStoppedGuestRequiresExpectedOffPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    DatasetState
		observed time.Time
		evidence []pvecontract.BackupEvidence
		want     FreshnessState
	}{
		{"unavailable", StateUnavailable, testBase, nil, FreshnessUnknown},
		{"partial", StatePartial, testBase, nil, FreshnessUnknown},
		{"stale", StateAvailable, testBase.Add(-time.Hour), nil, FreshnessStaleData},
		{"failed", StateAvailable, testBase, []pvecontract.BackupEvidence{taskEvidence("failed", "failed", nowUnix-60, nowUnix-30)}, FreshnessFailed},
		{"empty", StateAvailable, testBase, nil, FreshnessOverdue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := FreshnessInput{Now: testBase, GuestStatus: string(pvecontract.GuestStopped),
				DatasetState: tc.state, DatasetObservedAt: tc.observed, Evidence: tc.evidence}
			f := EvaluateFreshness(in)
			if f.State != tc.want {
				t.Fatalf("stopped guest without policy: %+v, want %s", f, tc.want)
			}
			if tc.want != FreshnessOverdue {
				in.ExpectedOff = true
				if f := EvaluateFreshness(in); f.State != tc.want {
					t.Fatalf("policy suppressed visibility or failure: %+v, want %s", f, tc.want)
				}
			}
		})
	}
}

func TestEvaluateFreshnessClockToleranceBoundary(t *testing.T) {
	for _, kind := range []string{pvecontract.BackupKindTask, pvecontract.BackupKindCatalog} {
		for _, offset := range []time.Duration{0, BackupClockTolerance, BackupClockTolerance + time.Second} {
			t.Run(fmt.Sprintf("%s/%s", kind, offset), func(t *testing.T) {
				timestamp := testBase.Add(offset).Unix()
				e := taskEvidence("clock", "success", nowUnix-60, timestamp)
				if kind == pvecontract.BackupKindCatalog {
					e = catalogEvidence("clock", timestamp, pvecontract.Yes)
				}
				in := FreshnessInput{Now: testBase, DatasetState: StateAvailable, DatasetObservedAt: testBase,
					Evidence: []pvecontract.BackupEvidence{e}}
				want := FreshnessOK
				if offset > BackupClockTolerance {
					want = FreshnessUnknown
				}
				if f := EvaluateFreshness(in); f.State != want {
					t.Fatalf("clock tolerance: %+v, want %s", f, want)
				}
				// Exercise the indexed range boundary through the store too.
				s, _, _ := newTestStore(t)
				ingestOK(t, s, newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
					pvecontract.AvailableDataset(in.Evidence))).build())
				if f, err := s.GuestBackupFreshness(context.Background(), "remote-a", 100, 1, 0); err != nil || f.State != want {
					t.Fatalf("stored clock tolerance: %+v, %v, want %s", f, err, want)
				}
			})
		}
	}
}

func TestEvaluateFreshnessRejectsFutureEvidence(t *testing.T) {
	for _, timestamp := range []int64{nowUnix + 121, nowUnix + 10*365*24*60*60, math.MaxInt64} {
		for _, kind := range []string{pvecontract.BackupKindTask, pvecontract.BackupKindCatalog} {
			for _, startedOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/started-only=%t", kind, timestamp, startedOnly), func(t *testing.T) {
					e := taskEvidence("future", "success", 0, timestamp)
					if kind == pvecontract.BackupKindCatalog {
						e = catalogEvidence("future", timestamp, pvecontract.Yes)
					}
					if startedOnly {
						e.StartedUnix, e.FinishedUnix = timestamp, 0
					}
					f := EvaluateFreshness(FreshnessInput{Now: testBase, DatasetState: StateAvailable,
						DatasetObservedAt: testBase, Evidence: []pvecontract.BackupEvidence{e}})
					if f.State != FreshnessUnknown || f.LastSuccessUnix != 0 || f.LastRunUnix != 0 || f.Task.LastSuccessUnix != 0 || f.Catalog.Present || f.Verification.State != pvecontract.Unknown {
						t.Fatalf("future timestamp trusted: %+v", f)
					}
				})
			}
		}
	}
}

func TestGuestBackupFreshnessChannelsSurviveCutoff(t *testing.T) {
	for _, flood := range []string{"catalog", "task", "failure", "future"} {
		t.Run(flood, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			ctx := context.Background()
			evidence := []pvecontract.BackupEvidence{
				taskEvidence("success", "success", nowUnix-7200, nowUnix-7100),
				taskEvidence("failure", "failed", nowUnix-7300, nowUnix-7200),
				catalogEvidence("verified", nowUnix-8000, pvecontract.Yes),
			}
			for i := 0; i < 1025; i++ {
				name := fmt.Sprintf("flood-%04d", i)
				switch flood {
				case "catalog":
					evidence = append(evidence, catalogEvidence(name, nowUnix-3600+int64(i), pvecontract.No))
				case "task":
					evidence = append(evidence, taskEvidence(name, "running", nowUnix-3600+int64(i), 0))
				case "failure":
					evidence = append(evidence, taskEvidence(name, "failed", nowUnix-10000+int64(i), nowUnix-3500+int64(i)))
				case "future":
					evidence = append(evidence, taskEvidence(name, "success", nowUnix-60, nowUnix+3600+int64(i)))
				}
			}
			for start := 0; start < len(evidence); start += pvecontract.MaxBackupsPerGuest {
				end := min(start+pvecontract.MaxBackupsPerGuest, len(evidence))
				ingestOK(t, s, newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
					pvecontract.AvailableDataset(evidence[start:end]))).build())
			}
			f, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := FreshnessOK
			if flood == "failure" {
				want = FreshnessFailed
			}
			if f.State != want || f.Task.LastSuccessUnix != nowUnix-7100 || !f.Catalog.Present || f.Verification.State != pvecontract.Yes {
				t.Fatalf("confidence channel lost behind cutoff: %+v, want %s", f, want)
			}
			if flood != "failure" && flood != "task" && (f.Task.LastRunUnix != nowUnix-7100 || f.Task.LastRunStatus != "success") {
				t.Fatalf("task summary lost: %+v", f.Task)
			}
			if flood == "task" && (f.Task.LastRunUnix != nowUnix-3600+1024 || f.Task.LastRunStatus != "running") {
				t.Fatalf("unfinished tasks not ordered by effective time: %+v", f.Task)
			}
			switch flood {
			case "catalog":
				if f.Catalog.Count != MaxFreshnessEvidence+1 || f.Verification.Count != MaxFreshnessEvidence+1 {
					t.Fatalf("catalog bucket read was not bounded: %+v", f)
				}
			case "task", "failure":
				wantCount := MaxFreshnessEvidence + 1 // capped failures plus one success
				if flood == "task" {
					wantCount++ // capped running tasks plus one failure and one success
				}
				if f.Task.Count != wantCount {
					t.Fatalf("task bucket read was not bounded: %+v", f.Task)
				}
			}
		})
	}
}

func TestFreshnessEvidenceUsesBoundedIndexedRanges(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		query string
		args  []any
		index string
	}{
		{"tasks", backupTaskEvidenceQuery, []any{"remote-a", 100, 1, "success", 0, nowUnix, MaxFreshnessEvidence}, "idx_pve_backup_task_freshness"},
		{"catalog", backupCatalogEvidenceQuery, []any{"remote-a", 100, 1, s.formatTime(testBase), 1, "present", "yes", 0, nowUnix, MaxFreshnessEvidence}, "idx_pve_backup_catalog_freshness"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+tc.query, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan += detail + "\n"
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan, "SEARCH pve_backup_observations USING INDEX "+tc.index) ||
				!strings.Contains(plan, "<expr>>? AND <expr><?") || strings.Contains(plan, "TEMP B-TREE") || strings.Contains(plan, "SCAN ") {
				t.Fatalf("freshness query scans or sorts unbounded history:\n%s", plan)
			}
		})
	}
}

// TestEvaluateFreshnessUnknownNeverSafe pins the security property: no input
// with missing visibility may be reported as ok.
func TestEvaluateFreshnessUnknownNeverSafe(t *testing.T) {
	cases := []FreshnessInput{
		{RemoteID: "r", VMID: 1, Generation: 1, Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
			DatasetState: StateUnavailable, DatasetReason: "denied", DatasetObservedAt: testBase},
		{RemoteID: "r", VMID: 1, Generation: 1, Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
			DatasetState: StateUnavailable, DatasetReason: "filtered", DatasetObservedAt: testBase},
		{RemoteID: "r", VMID: 1, Generation: 1, Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
			DatasetState: StatePartial, DatasetReason: "incomplete", DatasetObservedAt: testBase},
		{RemoteID: "r", VMID: 1, Generation: 1, Now: testBase, GuestStatus: string(pvecontract.GuestUnknown),
			DatasetState: StateUnavailable, DatasetReason: "no backup dataset recorded"},
	}
	for i, in := range cases {
		f := EvaluateFreshness(in)
		if f.State == FreshnessOK {
			t.Fatalf("case %d: unknown visibility reported as ok", i)
		}
		if f.State != FreshnessUnknown {
			t.Fatalf("case %d: state = %q, want unknown", i, f.State)
		}
	}
}

// TestGuestBackupFreshness verifies the store path end to end with the
// injected clock: a running guest with a recent evidenced backup is ok, and
// the channel metrics are populated.
func TestGuestBackupFreshness(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	obs := newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
		pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
			taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100),
		}))).build()
	if _, err := s.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	f, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("GuestBackupFreshness: %v", err)
	}
	if f.State != FreshnessOK {
		t.Fatalf("state = %q, want ok (reason %q)", f.State, f.Reason)
	}
	if f.LastSuccessUnix != nowUnix-7100 {
		t.Fatalf("last success = %d, want %d", f.LastSuccessUnix, nowUnix-7100)
	}
	if f.Task.LastSuccessUnix == 0 || f.Catalog.Present || f.Verification.State != pvecontract.Unknown {
		t.Fatalf("channels wrong: %+v", f)
	}
}

// TestGuestBackupFreshnessExactAssociation pins that freshness is scoped to the
// exact (remote, vmid, incarnation): the same VMID on two remotes keeps
// independent verdicts, and a missing incarnation is an error, not a verdict.
func TestGuestBackupFreshnessExactAssociation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote A: %v", err)
	}
	if err := s.UpsertRemote(ctx, remoteB()); err != nil {
		t.Fatalf("UpsertRemote B: %v", err)
	}

	// Both remotes host VMID 100, generation 1, with different backup ages.
	recent := pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
		taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100),
	})
	old := pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
		taskEvidence("b1", "success", nowUnix-108000, nowUnix-107900),
	})
	if _, err := s.IngestObservation(ctx, newObsA().guests(guestWithBackups(100, 1, "vm-a", pvecontract.GuestRunning, recent)).build()); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsB().guests(guestWithBackups(100, 1, "vm-b", pvecontract.GuestRunning, old)).build()); err != nil {
		t.Fatalf("ingest B: %v", err)
	}

	fa, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("freshness A: %v", err)
	}
	fb, err := s.GuestBackupFreshness(ctx, "remote-b", 100, 1, 0)
	if err != nil {
		t.Fatalf("freshness B: %v", err)
	}
	if fa.State != FreshnessOK || fb.State != FreshnessOverdue {
		t.Fatalf("states: A=%q B=%q, want ok/overdue", fa.State, fb.State)
	}

	// A generation that was never observed is an error, not a verdict.
	if _, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 99, 0); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("missing generation: err = %v, want ErrGuestNotFound", err)
	}
}

// TestGuestBackupFreshnessUnknownNeverSafe verifies the store path for a
// denied backup dataset: the verdict is unknown, never ok.
func TestGuestBackupFreshnessUnknownNeverSafe(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	obs := newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
		pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("denied"))).build()
	if _, err := s.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	f, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("GuestBackupFreshness: %v", err)
	}
	if f.State == FreshnessOK {
		t.Fatalf("denied dataset reported as ok")
	}
	if f.State != FreshnessUnknown {
		t.Fatalf("state = %q, want unknown (reason %q)", f.State, f.Reason)
	}
}

// TestGuestBackupFreshnessStaleDataWithClock verifies the injected clock drives
// the stale-data verdict: a fresh observation is ok, and advancing the clock
// past the stale limit flips it to stale-data without any new ingest.
func TestGuestBackupFreshnessStaleDataWithClock(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	obs := newObsA().guests(guestWithBackups(100, 1, "vm", pvecontract.GuestRunning,
		pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
			taskEvidence("b1", "success", nowUnix-7200, nowUnix-7100),
		}))).build()
	if _, err := s.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if f, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0); err != nil || f.State != FreshnessOK {
		t.Fatalf("before clock advance: state=%q err=%v, want ok", f.State, err)
	}

	// Advance the injected clock past the stale limit (15 min). The stored
	// observation stays at testBase, so the data becomes stale.
	*now = testBase.Add(20 * time.Minute)
	f, err := s.GuestBackupFreshness(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("GuestBackupFreshness: %v", err)
	}
	if f.State != FreshnessStaleData {
		t.Fatalf("after clock advance: state = %q, want stale-data (reason %q)", f.State, f.Reason)
	}
}
