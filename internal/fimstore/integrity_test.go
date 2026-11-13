// SPDX-License-Identifier: AGPL-3.0-or-later

package fimstore

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// mount returns a mount entry of a scan.
func mount(p, fstype string) fimscan.Mount {
	return fimscan.Mount{Path: []byte(p), FSType: fstype}
}

// scanWithMounts wraps records and mounts in a complete scan result.
func scanWithMounts(ms []fimscan.Mount, recs ...fimscan.Record) *fimscan.Result {
	r := scan(recs...)
	r.Mounts = ms
	return r
}

// rebuildFromStore rebuilds the approved baseline of host from the stored
// rows only (entries and mounts) and returns its digest.
func rebuildFromStore(t *testing.T, s *Store, host HostID) fimbaseline.Digest {
	t.Helper()
	ctx := context.Background()
	a, err := s.GetApproved(ctx, host)
	if err != nil {
		t.Fatalf("GetApproved: %v", err)
	}
	var recs []fimscan.Record
	if err := s.ForEachApproved(ctx, host, func(r fimscan.Record) error {
		recs = append(recs, r)
		return nil
	}); err != nil {
		t.Fatalf("ForEachApproved: %v", err)
	}
	mounts, err := s.ApprovedMounts(ctx, host)
	if err != nil {
		t.Fatalf("ApprovedMounts: %v", err)
	}
	b, err := fimbaseline.NewBaseline(&fimscan.Result{
		ProfileID: a.ProfileID, Mode: fimscan.ModeFull, Records: recs, Mounts: mounts,
		SSHConfigState: fimscan.SSHConfigValid,
	})
	if err != nil {
		t.Fatalf("rebuild NewBaseline: %v", err)
	}
	return b.Digest()
}

func TestApprovedBaselineRebuildsItsDigestFromStoredRows(t *testing.T) {
	s, _, host := newTestStore(t, "efi-1")
	res := scanWithMounts([]fimscan.Mount{mount("/var", "ext4"), mount("/boot/efi", "vfat")},
		file("/etc/hosts", 1), file("/etc/passwd", 2))
	a := proposeAndApprove(t, s, host, nil, res)
	if got := rebuildFromStore(t, s, host); got != a.Digest {
		t.Errorf("rebuilt digest %s, approved digest %s", got, a.Digest)
	}
	if got := rebuildFromStore(t, s, host); got != digestOf(t, res) {
		t.Errorf("rebuilt digest %s, scan digest %s", got, digestOf(t, res))
	}
}

func TestMountFSTypeIsPartOfTheDigest(t *testing.T) {
	recs := []fimscan.Record{file("/etc/hosts", 1)}
	vfat := digestOf(t, scanWithMounts([]fimscan.Mount{mount("/boot/efi", "vfat")}, recs...))
	ext4 := digestOf(t, scanWithMounts([]fimscan.Mount{mount("/boot/efi", "ext4")}, recs...))
	if vfat == ext4 {
		t.Fatal("digest does not change with the mount file-system type")
	}
}

func TestApprovedMountsAreTheProposedOnes(t *testing.T) {
	s, _, host := newTestStore(t, "efi-2")
	// Stored and returned in raw path byte order: /boot/efi sorts before /var.
	want := []fimscan.Mount{mount("/boot/efi", "vfat"), mount("/var", "ext4")}
	proposeAndApprove(t, s, host, nil, scanWithMounts(want, file("/etc/hosts", 1)))
	got, err := s.ApprovedMounts(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("approved mounts %d, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i].Path) != string(want[i].Path) || got[i].FSType != want[i].FSType {
			t.Errorf("mount %d: got %q %q, want %q %q", i, got[i].Path, got[i].FSType, want[i].Path, want[i].FSType)
		}
	}
}

func TestReproposalReplacesTheStoredMounts(t *testing.T) {
	s, db, host := newTestStore(t, "efi-3")
	ctx := context.Background()
	if _, err := s.Propose(ctx, host, scanWithMounts([]fimscan.Mount{mount("/var", "ext4"), mount("/boot/efi", "vfat")}, file("/etc/hosts", 1))); err != nil {
		t.Fatal(err)
	}
	p, err := s.Propose(ctx, host, scanWithMounts([]fimscan.Mount{mount("/var", "ext4")}, file("/etc/hosts", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposal_mounts WHERE host_id = ?`, host); n != 1 {
		t.Errorf("proposal mounts after re-proposal = %d, want 1", n)
	}
	if _, err := s.Approve(ctx, host, Approval{Digest: p.Digest}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_mounts WHERE host_id = ?`, host); n != 1 {
		t.Errorf("approved mounts = %d, want 1", n)
	}
}

func TestMountLimitRefusesWithReason(t *testing.T) {
	s, db, host := newTestStore(t, "efi-4")
	ms := make([]fimscan.Mount, fimscan.MaxMounts+1)
	for i := range ms {
		ms[i] = mount(fmt.Sprintf("/m%d", i), "ext4")
	}
	_, err := s.Propose(context.Background(), host, scanWithMounts(ms, file("/etc/hosts", 1)))
	if !errors.Is(err, fimbaseline.ErrLimit) {
		t.Fatalf("Propose with %d mounts: %v, want ErrLimit", len(ms), err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposals`); n != 0 {
		t.Errorf("refused proposal left %d rows", n)
	}
}

func TestApprovalRefusesEntriesThatDivergedFromTheDigest(t *testing.T) {
	s, db, host := newTestStore(t, "tamper-1")
	ctx := context.Background()
	p, err := s.Propose(ctx, host, scan(file("/etc/hosts", 1), file("/etc/passwd", 2)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE fim_baseline_proposal_entries SET size = size + 1 WHERE host_id = ? AND path = ?`,
		host, []byte("/etc/passwd")); err != nil {
		t.Fatal(err)
	}
	_, err = s.Approve(ctx, host, Approval{Digest: p.Digest})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Approve over diverged entries: %v, want ErrDigestMismatch", err)
	}
	if _, err := s.GetApproved(ctx, host); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("refused approval left a baseline: %v", err)
	}
	if _, err := s.GetProposal(ctx, host); err != nil {
		t.Errorf("refused approval removed the proposal: %v", err)
	}
}

func TestApprovalRefusesMountsThatDivergedFromTheDigest(t *testing.T) {
	s, db, host := newTestStore(t, "tamper-2")
	ctx := context.Background()
	p, err := s.Propose(ctx, host, scanWithMounts([]fimscan.Mount{mount("/boot/efi", "vfat")}, file("/etc/hosts", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE fim_baseline_proposal_mounts SET fstype = 'ext4' WHERE host_id = ?`, host); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, host, Approval{Digest: p.Digest}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Approve over diverged mounts: %v, want ErrDigestMismatch", err)
	}
	if _, err := s.GetApproved(ctx, host); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("refused approval left a baseline: %v", err)
	}
}

func TestStaleProposalIsRefusedAndChangesNothing(t *testing.T) {
	s, db, host := newTestStore(t, "stale-1")
	ctx := context.Background()
	p, err := s.Propose(ctx, host, scan(file("/etc/hosts", 1)))
	if err != nil {
		t.Fatal(err)
	}
	// The proposal claims to be built on an approved version that does not
	// exist: the approval must refuse it as stale, not as a digest error.
	if _, err := db.Exec(`UPDATE fim_baseline_proposals SET base_version = 3, base_digest = ? WHERE host_id = ?`,
		make([]byte, 32), host); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, host, Approval{Digest: p.Digest}); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("Approve of stale proposal: %v, want ErrStaleProposal", err)
	}
	if _, err := s.GetApproved(ctx, host); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("stale approval left a baseline: %v", err)
	}
	if _, err := s.GetProposal(ctx, host); err != nil {
		t.Errorf("stale approval removed the proposal: %v", err)
	}
}
