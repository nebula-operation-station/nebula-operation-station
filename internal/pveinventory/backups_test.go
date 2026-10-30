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

// catalogEvidence builds a PBS catalog evidence row. The status "present" is
// the pvecontract-valid value; the model must not depend on the exact string.
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
			name: "expected-off: stopped guest",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestStopped),
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
			name: "model ignores catalog status string",
			in: FreshnessInput{
				RemoteID: "r", VMID: 1, Generation: 1,
				Now: testBase, GuestStatus: string(pvecontract.GuestRunning),
				DatasetState: StateAvailable, DatasetObservedAt: testBase,
				// "catalog" is the pveapi-emitted status; the model must treat
				// any catalog-kind entry as a present backup.
				Evidence: []pvecontract.BackupEvidence{{
					Source: pvecontract.BackupPBS, Kind: pvecontract.BackupKindCatalog,
					Name: "vol1", Status: "catalog", FinishedUnix: nowUnix - 3600, Verified: pvecontract.Unknown,
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
