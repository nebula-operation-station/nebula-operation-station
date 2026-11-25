// SPDX-License-Identifier: AGPL-3.0-or-later

package actions_test

import (
	"testing"

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
