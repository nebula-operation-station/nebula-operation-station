// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestBulkAdmitDryRunScansNewAction checks that a dry run returns the
// review and the scanner findings for a new action without committing.
func TestBulkAdmitDryRunScansNewAction(t *testing.T) {
	e := newEnv(t)
	c := e.candidate("1.0.0", mod{name: "core", version: "1.0.0", actions: map[string]string{"reboot": "echo hi"}})
	out, err := e.s.BulkAdmit(c, BulkAdmitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Committed {
		t.Fatal("dry run must not commit")
	}
	if out.ManifestDigest == "" {
		t.Fatal("missing manifest digest")
	}
	if len(out.Scans) != 1 {
		t.Fatalf("want 1 scan, got %d", len(out.Scans))
	}
	if out.Scans[0].Module != "core" || out.Scans[0].ActionID != "core.reboot" {
		t.Fatalf("unexpected scan %v", out.Scans[0])
	}
	if len(out.OldVersions) != 0 {
		t.Fatalf("a new module has no old versions, got %v", out.OldVersions)
	}
}

// TestBulkAdmitCommitBindsDigest checks that a commit requires the
// confirmed digest to match the reviewed manifest digest, and records the
// retirement audit.
func TestBulkAdmitCommitBindsDigest(t *testing.T) {
	e := newEnv(t)
	c := e.candidate("1.0.0", mod{name: "core", version: "1.0.0", actions: map[string]string{"reboot": "echo hi"}})
	// A wrong digest is rejected before any change.
	if _, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: "deadbeef", AdminUID: 1000}); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale for a wrong digest, got %v", err)
	}
	out, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest, AdminUID: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Committed {
		t.Fatal("want committed")
	}
	if out.AdminUID != 1000 {
		t.Fatalf("want admin uid 1000, got %d", out.AdminUID)
	}
	if len(out.Tuples) != 1 || out.Tuples[0].Module != "core" || out.Tuples[0].Status != string(StatusNew) {
		t.Fatalf("unexpected tuples %v", out.Tuples)
	}
}

// TestBulkAdmitRequiresExplicitRetirement checks that a changed module's
// old version must be explicitly retained or retired, and that the
// decisions cover exactly the old versions.
func TestBulkAdmitRequiresExplicitRetirement(t *testing.T) {
	e := newEnv(t)
	e.admit(e.candidate("1.0.0", mod{name: "core", version: "1.0.0", actions: map[string]string{"reboot": "echo hi"}}))
	c := e.candidate("1.1.0", mod{name: "core", version: "1.1.0", actions: map[string]string{"reboot": "echo v2"}})
	// Undecided: the old version (core@1.0.0) is neither retained nor retired.
	if _, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest}); err == nil {
		t.Fatal("want an error for an undecided old version")
	}
	// Retired: the old version is retired, the commit succeeds.
	out, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest, Retired: []string{"core@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Committed {
		t.Fatal("want committed")
	}
	if len(out.Retired) != 1 || out.Retired[0] != "core@1.0.0" {
		t.Fatalf("unexpected retired %v", out.Retired)
	}
	// Retained: the old version (core@1.1.0) is pinned, the commit succeeds.
	c2 := e.candidate("1.2.0", mod{name: "core", version: "1.2.0", actions: map[string]string{"reboot": "echo v3"}})
	out2, err := e.s.BulkAdmit(c2, BulkAdmitOpts{ConfirmedDigest: c2.Manifest.Digest, Pins: map[string]bool{"core@1.1.0": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Pinned) != 1 || out2.Pinned[0] != "core@1.1.0" {
		t.Fatalf("unexpected pinned %v", out2.Pinned)
	}
	// Both retained and retired is rejected.
	c3 := e.candidate("1.3.0", mod{name: "core", version: "1.3.0", actions: map[string]string{"reboot": "echo v4"}})
	if _, err := e.s.BulkAdmit(c3, BulkAdmitOpts{ConfirmedDigest: c3.Manifest.Digest,
		Pins: map[string]bool{"core@1.2.0": true}, Retired: []string{"core@1.2.0"}}); err == nil {
		t.Fatal("want an error for a version both retained and retired")
	}
	// A decision that names a version that is not an old version is rejected.
	if _, err := e.s.BulkAdmit(c3, BulkAdmitOpts{ConfirmedDigest: c3.Manifest.Digest, Retired: []string{"core@1.0.0"}}); err == nil {
		t.Fatal("want an error for a decision on a non-old version")
	}
}

// TestBulkAdmitRetirementAuditRecordsCleanup checks that the audit records
// Result.Collected and Result.CleanupFailures without script contents.
func TestBulkAdmitRetirementAuditRecordsCleanup(t *testing.T) {
	e := newEnv(t)
	// Build up history so an old version ends up beyond the two most
	// recent predecessors and past its 90-day floor.
	e.admit(e.candidate("1.0.0", mod{name: "core", version: "1.0.0", actions: map[string]string{"reboot": "echo hi"}}))
	e.admit(e.candidate("1.1.0", mod{name: "core", version: "1.1.0", actions: map[string]string{"reboot": "echo v2"}}))
	e.admit(e.candidate("1.2.0", mod{name: "core", version: "1.2.0", actions: map[string]string{"reboot": "echo v3"}}))
	// Advance the clock past the 90-day floor of the oldest superseded
	// version (core@1.0.0), well inside the implausible-jump bound.
	e.now = e.now.Add(91 * 24 * time.Hour)
	c := e.candidate("1.3.0", mod{name: "core", version: "1.3.0", actions: map[string]string{"reboot": "echo v4"}})
	out, err := e.s.BulkAdmit(c, BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest, Retired: []string{"core@1.2.0"}})
	if err != nil {
		t.Fatal(err)
	}
	// The oldest superseded version beyond the floor is collected by GC;
	// the two most recent predecessors are kept.
	if !inCollected(out.Collected, "core@1.0.0") {
		t.Fatalf("want core@1.0.0 collected, got %v", out.Collected)
	}
	if inCollected(out.Collected, "core@1.2.0") {
		t.Fatalf("the two most recent predecessors must not be collected, got %v", out.Collected)
	}
	for _, s := range out.Collected {
		if strings.Contains(s, "echo") {
			t.Fatalf("audit must not carry script contents: %q", s)
		}
	}
}

// inCollected reports whether s is in the collected list.
func inCollected(collected []string, s string) bool {
	for _, c := range collected {
		if c == s {
			return true
		}
	}
	return false
}
