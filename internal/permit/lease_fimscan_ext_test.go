// SPDX-License-Identifier: AGPL-3.0-or-later

package permit_test

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// The executor's pins equal the embedded fimscan contract: script bytes,
// version, action ID and the canonical parameters of both modes.
func TestFimScanPinsMatchFimscanContract(t *testing.T) {
	a := fimscan.Action()
	if a.ID != permit.FimScanActionID || a.Version != permit.FimScanModuleVersion || a.SHA256() != permit.FimScanArtifactSHA256 {
		t.Fatalf("contract %s@%s %s, pinned %s@%s %s", a.ID, a.Version, a.SHA256(),
			permit.FimScanActionID, permit.FimScanModuleVersion, permit.FimScanArtifactSHA256)
	}
	for mode, want := range map[fimscan.Mode]string{
		fimscan.ModeIncremental: permit.FimScanIncrementalParametersHash,
		fimscan.ModeFull:        permit.FimScanFullParametersHash,
	} {
		raw, err := a.ParametersJSON(map[string]string{"mode": string(mode), "profile": fimscan.DefaultProfileID}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := canonical.HashParameters(raw)
		if err != nil || got != want {
			t.Errorf("%s: %s (%v), pinned %s", mode, got, err, want)
		}
	}
}
