// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the pvecollect spool (ADR 0006, P1-10). They cover the
// acceptance criteria for the spool: atomic writes (temp file + rename,
// mode 0640), size limits, symlink refusal, strict decoding, and
// replay/oversize rejection on the reading side.

package pvecollect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// mkObs builds a minimal valid observation: every dataset is unavailable
// with a reason, which is the smallest document the contract accepts.
func mkObs(remoteID string, gen uint64, at time.Time) pvecontract.Observation {
	r := "not read in this collection"
	return pvecontract.Observation{
		RemoteID:             remoteID,
		ObservedAt:           at,
		Source:               "pve-collector",
		CollectionGeneration: gen,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation](r),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation](r),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation](r),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation](r),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation](r),
	}
}

func newTestSpool(t *testing.T) *Spool {
	t.Helper()
	s, err := NewSpool(filepath.Join(t.TempDir(), "spool"))
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSpoolWriteIsAtomicAndReadable(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)

	path, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o640 {
		t.Errorf("written file mode = %o, want 0640", perm)
	}
	// The results directory must let the server group list and traverse
	// so it can read the 0640 files.
	di, err := os.Stat(s.ResultsDir())
	if err != nil {
		t.Fatalf("stat results dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o770 {
		t.Errorf("results dir mode = %o, want 0770", perm)
	}
	if filepath.Dir(path) != s.ResultsDir() {
		t.Errorf("file written to %s, want %s", filepath.Dir(path), s.ResultsDir())
	}
	// No temp files may be left behind.
	entries, err := os.ReadDir(s.ResultsDir())
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("results dir has %d entries, want 1: %v", len(entries), entries)
	}

	got, err := s.ReadFile(ctx, filepath.Base(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got.RemoteID != obs.RemoteID || got.CollectionGeneration != obs.CollectionGeneration || !got.ObservedAt.Equal(obs.ObservedAt) {
		t.Errorf("read back %+v, want remote %s gen %d at %s", got, obs.RemoteID, obs.CollectionGeneration, obs.ObservedAt)
	}
}

// TestSpoolWriteRejectsOversize verifies the 1 MiB spool page limit on the
// writing side. A valid observation whose marshalled form exceeds the limit
// (here: long dataset reasons) must be refused.
func TestSpoolWriteRejectsOversize(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	reason := strings.Repeat("x", pvecontract.MaxResponseBytes)
	obs.Nodes = pvecontract.UnavailableDataset[[]pvecontract.NodeObservation](reason)
	obs.Guests = pvecontract.UnavailableDataset[[]pvecontract.GuestObservation](reason)
	raw, err := pvecontract.MarshalObservation(obs)
	if err != nil {
		t.Fatalf("MarshalObservation: %v", err)
	}
	if len(raw) <= pvecontract.MaxResponseBytes {
		t.Fatalf("test setup: observation is %d bytes, want > %d", len(raw), pvecontract.MaxResponseBytes)
	}
	if _, err := s.WriteFile(ctx, obs); !errors.Is(err, ErrOversize) {
		t.Fatalf("WriteFile error = %v, want ErrOversize", err)
	}
}

// TestSpoolWriteRefusesSymlinkTarget verifies a pre-planted symlink at the
// final file name is never followed or replaced silently.
func TestSpoolWriteRefusesSymlinkTarget(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)

	target := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	final, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.ResultsDir(), final)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteFile(ctx, obs); !errors.Is(err, ErrSymlink) {
		t.Fatalf("WriteFile error = %v, want ErrSymlink", err)
	}
	// The symlink target must be untouched.
	if b, err := os.ReadFile(target); err != nil || string(b) != "secret" {
		t.Fatalf("symlink target modified: %q %v", b, err)
	}
}

// TestSpoolWriteIdempotentRetry verifies that rewriting the same payload is
// accepted, but a different payload under the same name is refused.
func TestSpoolWriteIdempotentRetry(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)

	path, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	path2, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	if path2 != path {
		t.Errorf("retry path %s != %s", path2, path)
	}
	// Same name (same remote+generation) but different content.
	other := mkObs("remote-a", 1, testNow.Add(time.Minute))
	if _, err := s.WriteFile(ctx, other); err == nil {
		t.Fatal("WriteFile accepted different content under the same name")
	}
}

// TestSpoolReadRejectsSymlink verifies the reading side never follows a
// symlink.
func TestSpoolReadRejectsSymlink(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	path, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	name := filepath.Base(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(s.ResultsDir(), name)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile(ctx, name); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadFile error = %v, want ErrSymlink", err)
	}
}

// TestSpoolReadRejectsOversize verifies the reading side refuses files above
// the size limit, even if they were not written by the collector.
func TestSpoolReadRejectsOversize(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	name, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, pvecontract.MaxResponseBytes+1)
	if err := os.WriteFile(filepath.Join(s.ResultsDir(), name), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile(ctx, name); !errors.Is(err, ErrOversize) {
		t.Fatalf("ReadFile error = %v, want ErrOversize", err)
	}
}

// TestSpoolReadRejectsMalformed verifies strict decoding on the reading side.
func TestSpoolReadRejectsMalformed(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	name, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.ResultsDir(), name), []byte(`{"remote_id":`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile(ctx, name); err == nil {
		t.Fatal("ReadFile accepted a truncated document")
	}
	// Unknown fields must be rejected by the strict decoder.
	valid, err := pvecontract.MarshalObservation(obs)
	if err != nil {
		t.Fatal(err)
	}
	hostile := append(append([]byte{}, `{"bogus_field":true,`...), valid[1:]...)
	if err := os.WriteFile(filepath.Join(s.ResultsDir(), name), hostile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile(ctx, name); err == nil {
		t.Fatal("ReadFile accepted a document with unknown fields")
	}
}

// TestSpoolReadRejectsBadName verifies file names cannot traverse the
// results directory.
func TestSpoolReadRejectsBadName(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	for _, name := range []string{
		"", ".", "..", "../remote-a.json", "a/b.json",
		"remote-a.tmp-123", "REMOTE-a.gen-00000000000000000001.json",
		"remote-a.gen-1.json", "remote-a.gen-00000000000000000001.jsonx",
	} {
		if _, err := s.ReadFile(ctx, name); err == nil {
			t.Errorf("ReadFile(%q) succeeded, want error", name)
		}
	}
}

// TestSpoolReadRejectsRenamedGeneration verifies the reading side checks the
// file name against the document: a file renamed to claim a newer
// generation is refused.
func TestSpoolReadRejectsRenamedGeneration(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	path, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	forged, err := spoolFileName("remote-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(s.ResultsDir(), forged)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile(ctx, forged); err == nil {
		t.Fatal("ReadFile accepted a document whose generation does not match its name")
	}
}

// TestSpoolListRejectsSymlink verifies listing refuses a symlinked entry
// instead of skipping it.
func TestSpoolListRejectsSymlink(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	if _, err := s.WriteFile(ctx, obs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(s.ResultsDir(), "remote-b.gen-00000000000000000001.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ctx); !errors.Is(err, ErrSymlink) {
		t.Fatalf("List error = %v, want ErrSymlink", err)
	}
}

// TestSpoolListReturnsRegularFiles verifies List returns only regular files,
// sorted, and ignores leftover temp files.
func TestSpoolListReturnsRegularFiles(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	for _, gen := range []uint64{2, 1} {
		if _, err := s.WriteFile(ctx, mkObs("remote-a", gen, testNow)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.ResultsDir(), "remote-a.gen-00000000000000000003.json.tmp-1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 || names[0] != "remote-a.gen-00000000000000000001.json" || names[1] != "remote-a.gen-00000000000000000002.json" {
		t.Fatalf("List = %v", names)
	}
}

// TestSpoolReplayRejection verifies the reading-side replay guard: an
// observation is accepted only if it advances (generation, observedAt) for
// its remote.
func TestSpoolReplayRejection(t *testing.T) {
	s := newTestSpool(t)

	first := mkObs("remote-a", 1, testNow)
	if err := s.CheckReplay(first); err != nil {
		t.Fatalf("first observation rejected: %v", err)
	}
	s.MarkIngested(first)

	// Same generation, same timestamp: accepted (idempotent retry).
	if err := s.CheckReplay(mkObs("remote-a", 1, testNow)); err != nil {
		t.Fatalf("idempotent retry rejected: %v", err)
	}
	// Same generation, earlier timestamp: replay.
	if err := s.CheckReplay(mkObs("remote-a", 1, testNow.Add(-time.Second))); !errors.Is(err, ErrReplayed) {
		t.Fatalf("earlier observedAt at same generation: error = %v, want ErrReplayed", err)
	}
	// Same generation, later timestamp: accepted and advances the watermark.
	second := mkObs("remote-a", 1, testNow.Add(time.Second))
	if err := s.CheckReplay(second); err != nil {
		t.Fatalf("later observedAt at same generation rejected: %v", err)
	}
	s.MarkIngested(second)
	if err := s.CheckReplay(first); !errors.Is(err, ErrReplayed) {
		t.Fatalf("observation before the watermark accepted: %v", err)
	}
	// Newer generation: accepted.
	third := mkObs("remote-a", 2, testNow.Add(time.Hour))
	if err := s.CheckReplay(third); err != nil {
		t.Fatalf("newer generation rejected: %v", err)
	}
	s.MarkIngested(third)
	// Older generation: replay, even with a newer timestamp.
	if err := s.CheckReplay(mkObs("remote-a", 1, testNow.Add(2*time.Hour))); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older generation: error = %v, want ErrReplayed", err)
	}
	// Other remotes are tracked independently.
	if err := s.CheckReplay(mkObs("remote-b", 1, testNow)); err != nil {
		t.Fatalf("other remote rejected: %v", err)
	}
}

// TestSpoolRemoveDeletesAndRefusesSymlink verifies Remove deletes regular
// files and refuses symlinks.
func TestSpoolRemoveDeletesAndRefusesSymlink(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	obs := mkObs("remote-a", 1, testNow)
	path, err := s.WriteFile(ctx, obs)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, name); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Remove error = %v, want ErrSymlink", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteFile(ctx, obs); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still present after Remove: %v", err)
	}
	if err := s.Remove(ctx, "../x.json"); err == nil {
		t.Fatal("Remove accepted a traversal name")
	}
}

// TestNewSpoolRefusesSymlinkRoot verifies the spool refuses a symlinked
// root or results directory.
func TestNewSpoolRefusesSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpool(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("NewSpool(symlink root) error = %v, want ErrSymlink", err)
	}
	// Symlinked results directory.
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, resultsDirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSpool(root); !errors.Is(err, ErrSymlink) {
		t.Fatalf("NewSpool(symlink results) error = %v, want ErrSymlink", err)
	}
	if _, err := NewSpool("relative/path"); err == nil {
		t.Fatal("NewSpool accepted a relative root")
	}
}

// TestSpoolFileNameIsFlat verifies the derived file name is a flat, safe
// name and rejects malformed inputs.
func TestSpoolFileNameIsFlat(t *testing.T) {
	name, err := spoolFileName("remote-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(name, "/\\") || name != "remote-a.gen-00000000000000000001.json" {
		t.Fatalf("spoolFileName = %q", name)
	}
	for _, id := range []string{"", "Remote", "a..b", "a/b", strings.Repeat("a", 65)} {
		if _, err := spoolFileName(id, 1); err == nil {
			t.Errorf("spoolFileName(%q) succeeded, want error", id)
		}
	}
	if _, err := spoolFileName("remote-a", 0); err == nil {
		t.Error("spoolFileName accepted generation 0")
	}
}
