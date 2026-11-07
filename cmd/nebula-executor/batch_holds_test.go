// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

const (
	testHeldExec  = "00000000-0000-4000-8000-000000000001"
	testOtherExec = "00000000-0000-4000-8000-000000000002"
)

// writeTestHeld writes a held-target file with an expired hold of web-1
// and a rechecked hold of web-2, in the executor's format.
func writeTestHeld(t *testing.T, dir string) string {
	t.Helper()
	doc := map[string]any{"version": 1, "targets": []map[string]any{
		{"host_id": "web-1", "fingerprint": "SHA256:a", "execution_id": testHeldExec, "endpoints": []string{"192.0.2.1:22"},
			"held_at_unix": 1_700_000_000, "expired": true},
		{"host_id": "web-2", "fingerprint": "SHA256:b", "execution_id": testOtherExec, "endpoints": []string{"192.0.2.2:22"},
			"held_at_unix": 1_700_000_100},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "batch-held-targets.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runHolds(t *testing.T, now time.Time, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := runBatchHolds(args, &out, &errOut, func() time.Time { return now })
	return out.String(), errOut.String(), err
}

// list shows every held target with its state; nothing is changed.
func TestBatchHoldsList(t *testing.T) {
	dir := privateTempDir(t)
	path := writeTestHeld(t, dir)
	before, _ := os.ReadFile(path)
	out, _, err := runHolds(t, time.Now(), "list", "-data-dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "web-1") || !strings.Contains(lines[1], testHeldExec) || !strings.Contains(lines[1], "expired") ||
		!strings.Contains(lines[2], "web-2") || !strings.Contains(lines[2], "held (rechecked)") {
		t.Fatalf("list:\n%s", out)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("list changed the file")
	}
	empty := privateTempDir(t)
	if out, _, err := runHolds(t, time.Now(), "list", "-data-dir", empty); err != nil || !strings.Contains(out, "no held batch targets") {
		t.Fatalf("empty list: %q %v", out, err)
	}
}

// A hold of a durable container job is listed as such, and a rearm keeps
// the mark: only its reconciled run ends it.
func TestBatchHoldsListMarksDurableJob(t *testing.T) {
	dir := privateTempDir(t)
	doc := map[string]any{"version": 1, "targets": []map[string]any{
		{"host_id": "web-1", "fingerprint": "SHA256:a", "execution_id": testHeldExec, "endpoints": []string{"192.0.2.1:22"},
			"held_at_unix": 1_700_000_000, "expired": true, "durable": true},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "batch-held-targets.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runHolds(t, time.Now(), "list", "-data-dir", dir)
	if err != nil || !strings.Contains(out, "durable job") {
		t.Fatalf("list: %q %v", out, err)
	}
	if _, _, err := runHolds(t, time.Now(), "rearm", "-data-dir", dir, "-execution", testHeldExec,
		"-by", "alice", "-reason", "host back", "web-1"); err != nil {
		t.Fatalf("rearm: %v", err)
	}
	out, _, err = runHolds(t, time.Now(), "list", "-data-dir", dir)
	if err != nil || !strings.Contains(out, "held (rechecked), durable job") {
		t.Fatalf("list after rearm: %q %v", out, err)
	}
}

// rearm returns exactly the named expired hold to automatic rechecks,
// counted from now, keeps the target held, writes the file atomically in
// the executor's format and audits the change in the signed event chain.
func TestBatchHoldsRearm(t *testing.T) {
	dir := privateTempDir(t)
	path := writeTestHeld(t, dir)
	now := time.Unix(1_800_000_000, 0)
	out, _, err := runHolds(t, now, "rearm", "-data-dir", dir, "-execution", testHeldExec, "-by", "alice",
		"-reason", "host checked on the console", "web-1")
	if err != nil || !strings.Contains(out, "rechecked again") {
		t.Fatalf("rearm: %q %v", out, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi, err)
	}
	db := openDB(t, dir)
	held, err := executor.OfflineHeldBatchTargets(db, dir)
	if err != nil || len(held) != 2 {
		t.Fatalf("after rearm: %+v %v", held, err)
	}
	if h := held[0]; h.HostID != "web-1" || h.ExecutionID != testHeldExec || h.Expired || !h.HeldAt.Equal(now) {
		t.Fatalf("rearmed hold %+v", h)
	}
	if h := held[1]; h.HostID != "web-2" || h.Expired || h.HeldAt.Unix() != 1_700_000_100 {
		t.Fatalf("other hold changed: %+v", h)
	}
	recs, err := db.Events(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, r := range recs {
		if b := string(r.Body); strings.Contains(b, "batch_target_hold_rearmed_by_operator") && strings.Contains(b, "alice") &&
			strings.Contains(b, testHeldExec) {
			audited = true
		}
	}
	if !audited {
		t.Fatal("rearm not in the signed event chain")
	}
}

// rearm refuses everything but the exact expired hold, a running executor
// (the data directory is locked) and root; the file stays as it was.
func TestBatchHoldsRearmRefusals(t *testing.T) {
	dir := privateTempDir(t)
	path := writeTestHeld(t, dir)
	before, _ := os.ReadFile(path)
	rearm := func(host, exec, by, reason string) error {
		_, _, err := runHolds(t, time.Now(), "rearm", "-data-dir", dir, "-execution", exec, "-by", by, "-reason", reason, host)
		return err
	}
	for name, tc := range map[string]struct {
		host, exec, by, reason string
		want                   error
	}{
		"other execution": {"web-1", testOtherExec, "alice", "r", executor.ErrBatchTargetNotHeld},
		"unknown host":    {"web-9", testHeldExec, "alice", "r", executor.ErrBatchTargetNotHeld},
		"not expired":     {"web-2", testOtherExec, "alice", "r", executor.ErrBatchHoldNotExpired},
		"no operator":     {"web-1", testHeldExec, "", "r", executor.ErrBatchHoldReason},
		"no reason":       {"web-1", testHeldExec, "alice", "", executor.ErrBatchHoldReason},
	} {
		if err := rearm(tc.host, tc.exec, tc.by, tc.reason); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, _, err := runHolds(t, time.Now(), "rearm", "-data-dir", dir, "-execution", testHeldExec, "-by", "a", "-reason", "r"); err == nil {
		t.Error("rearm without a host accepted")
	}
	if _, _, err := runHolds(t, time.Now(), "release", "-data-dir", dir); err == nil {
		t.Error("unknown subcommand accepted")
	}
	// A running executor holds the data directory.
	db := openDB(t, dir)
	if err := rearm("web-1", testHeldExec, "alice", "r"); err == nil || !strings.Contains(err.Error(), "stop nebula-executor first") {
		t.Errorf("with the directory in use: %v", err)
	}
	if _, _, err := runHolds(t, time.Now(), "list", "-data-dir", dir); err == nil {
		t.Error("list with the directory in use accepted")
	}
	_ = db.Close()
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("a refused rearm changed the file")
	}
	// A malformed file is reported, never rewritten.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rearm("web-1", testHeldExec, "alice", "r"); !errors.Is(err, executor.ErrBatchHoldStore) {
		t.Errorf("malformed file: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != "{" {
		t.Fatal("malformed file rewritten")
	}
}
