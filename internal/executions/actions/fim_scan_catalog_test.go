// SPDX-License-Identifier: AGPL-3.0-or-later

package actions_test

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// fim.scan is a durable, read-only action whose timeout fits the durable
// maximum, and its version and script hash are the ones the read lease
// pins (permit.validateFimScanAction).
func TestFimScanIsDurableReadOnlyWithinDurableLimit(t *testing.T) {
	a := fimscan.Action()
	if !a.Durable || !a.ReadOnly {
		t.Fatalf("%s: durable=%v read-only=%v, want both true", a.ID, a.Durable, a.ReadOnly)
	}
	if a.Timeout <= 0 || a.Timeout > hostrun.MaxDurableTimeout {
		t.Fatalf("%s timeout %s, durable maximum %s", a.ID, a.Timeout, hostrun.MaxDurableTimeout)
	}
	if a.Version != permit.FimScanModuleVersion || a.SHA256() != permit.FimScanArtifactSHA256 {
		t.Fatalf("%s@%s sha %s, lease pins %s@%s", a.ID, a.Version, a.SHA256(), permit.FimScanModuleVersion, permit.FimScanArtifactSHA256)
	}
	if !permit.InReadOnlyAllowlist(fimscan.ActionID) {
		t.Fatalf("%s is not in the read-only allowlist", fimscan.ActionID)
	}
}

// actions.FimScan is the one fim.scan contract: it has exactly the
// version, script hash and flags the read lease pins, and fimscan.Action
// is the same contract (one source for script, version and parameters).
func TestFimScanContractHasOneSource(t *testing.T) {
	a := actions.FimScan()
	if a.ID != permit.FimScanActionID || a.Version != permit.FimScanModuleVersion || a.SHA256() != permit.FimScanArtifactSHA256 {
		t.Fatalf("contract %s@%s sha %s, lease pins %s@%s", a.ID, a.Version, a.SHA256(), permit.FimScanModuleVersion, permit.FimScanArtifactSHA256)
	}
	if !a.ReadOnly || !a.Durable {
		t.Fatalf("contract %s: read-only=%v durable=%v, want both true", a.ID, a.ReadOnly, a.Durable)
	}
	if !reflect.DeepEqual(a, fimscan.Action()) {
		t.Fatal("actions.FimScan and fimscan.Action differ")
	}
}

// The embedded script is the pinned one, and fimscan.Script is the same
// bytes (no second copy).
func TestFimScanEmbeddedScriptHashIsPinned(t *testing.T) {
	sum := sha256.Sum256(actions.FimScanScript)
	if got := hex.EncodeToString(sum[:]); got != permit.FimScanArtifactSHA256 {
		t.Fatalf("actions.FimScanScript sha %s, pinned %s", got, permit.FimScanArtifactSHA256)
	}
	if len(fimscan.Script) == 0 || &fimscan.Script[0] != &actions.FimScanScript[0] {
		t.Fatal("fimscan.Script is not actions.FimScanScript")
	}
}
