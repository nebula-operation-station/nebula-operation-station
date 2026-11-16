// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
)

// fim.scan read-only contract (ADR 0015 D5, spec 07 "Integrity scan read",
// spec 10 v26-10-02). The executor pins the exact script and the only two
// parameter documents a read lease may bind, independently of the server's
// catalog: a lease names fim.scan 1.0.0 with exactly this script hash and
// the canonical parameters of one mode of profile fim-default-v1. There is
// no path parameter and no look-back parameter; the roots, excludes and
// the 26-hour look-back window are fixed in the script, so the script hash
// covers them. internal/fimscan depends on this package, so the values are
// pinned here and lease_fimscan_ext_test.go checks them against
// fimscan.Action and fimscan.Script.
const (
	// FimScanActionID is the integrity scan action.
	FimScanActionID = "fim.scan"
	// FimScanModuleVersion is the only leasable version.
	FimScanModuleVersion = "1.0.0"
	// FimScanArtifactSHA256 is the SHA-256 of fimscan.Script 1.0.0. A
	// change of the script needs a reviewed update of this pin.
	FimScanArtifactSHA256 = "c5fc8501d0c533ca3a344d260fec97784fe4ab16ec16d9d49648bfc75a227332"
	// FimScanIncrementalParametersHash is the canonical parameters hash of
	// {"mode":"incremental","profile":"fim-default-v1"}.
	FimScanIncrementalParametersHash = "c24a2d60fe75484a39d573ae08c8efc3547870b086fc43a297ffda6fbbf82c2a"
	// FimScanFullParametersHash is the canonical parameters hash of
	// {"mode":"full","profile":"fim-default-v1"}.
	FimScanFullParametersHash = "22e57c0d26980311a492f4e99987cf5beaaab8b2cda89779277617777a8e6a18"

	// FimScanIncrementalMinInterval is the per-host floor between two
	// incremental runs (spec 07 Q2): hourly on crown-jewel hosts is the
	// fastest approved schedule; the default 6 hours is the lease's or the
	// scheduler's choice above it.
	FimScanIncrementalMinInterval = time.Hour
	// FimScanFullMinInterval is the per-host floor between two full runs
	// (spec 07 Q2: full weekly). It lies FimScanFullScheduleSlack below one
	// week (schedgrant.MaxInterval, the longest interval the read store
	// retains), so a weekly schedule that fires slightly early is not
	// denied and pushed to the slot after, while two full runs in one week
	// still are.
	FimScanFullMinInterval = 7*24*time.Hour - FimScanFullScheduleSlack
	// FimScanFullScheduleSlack is the scheduler jitter by which a weekly
	// full run may fire early.
	FimScanFullScheduleSlack = 6 * time.Hour

	// fimScanFullIntervalKey keys the floor of full runs apart from
	// incremental ones, so neither mode blocks the other. It contains '#',
	// which no action ID can, so it never shares a key with an action.
	fimScanFullIntervalKey = "fim.scan#full"
)

// fimScanReviewedScannerVersion is the Safety Scanner pattern list under
// which fimScanReviewedFindings were reviewed.
const fimScanReviewedScannerVersion = "scanner-v1"

// fimScanReviewedFindings is the complete, reviewed Safety Scanner result
// for the pinned script FimScanArtifactSHA256 under scanner-v1. Both
// findings are data, not commands: line 84 is the HOME_MAX_MATCHES limit
// whose comment names .ssh/authorized_keys*, line 124 the HOME_FILES list
// of files the scan reads (hashed only through a holder dropped to the
// file's owner). The script never writes them (ADR 0015 D5: it only
// reads). The scanner rates any mention of authorized_keys MEDIUM, which
// would raise every fim.scan run above the LOW of a read lease, so exactly
// this result for exactly these bytes does not raise the floor. Any other
// finding, another scanner version, another action or other bytes keep
// the scanner's full verdict. A change of the script or of the scanner
// needs a reviewed update of this list (TestFimScanRealScriptPassesFloor
// fails until then, and runs fail closed at MEDIUM).
var fimScanReviewedFindings = []scanner.Finding{
	{Category: scanner.UsersGroups, Risk: canonical.RiskMedium, Line: 84, Excerpt: "authorized_keys"},
	{Category: scanner.UsersGroups, Risk: canonical.RiskMedium, Line: 124, Excerpt: "authorized_keys"},
}

// fimScanReviewedScan reports whether the scanner result s for request r
// is the reviewed result of the pinned fim.scan script, so it does not
// raise r's floor. It holds only for the pinned action, version and script
// hash, under the reviewed scanner version, with exactly the reviewed
// findings (fewer than scanner.MaxFindings, so none were cut off).
func fimScanReviewedScan(r canonical.Request, s scanResult) bool {
	return r.ActionID == FimScanActionID &&
		r.ModuleVersion == FimScanModuleVersion &&
		r.ArtifactSHA256 == FimScanArtifactSHA256 &&
		scanner.Version == fimScanReviewedScannerVersion &&
		len(s.findings) < scanner.MaxFindings &&
		slices.Equal(s.findings, fimScanReviewedFindings)
}

// validateFimScanAction checks a lease entry for fim.scan against the
// pinned contract.
func validateFimScanAction(a ReadGrantAction) error {
	switch {
	case a.ModuleVersion != FimScanModuleVersion:
		return fmt.Errorf("fim.scan: only version %s is leasable", FimScanModuleVersion)
	case a.ArtifactSHA256 != FimScanArtifactSHA256:
		return fmt.Errorf("fim.scan: the artifact is not the reviewed script")
	case a.ParametersHash != FimScanIncrementalParametersHash && a.ParametersHash != FimScanFullParametersHash:
		return fmt.Errorf("fim.scan: parameters must be profile fim-default-v1 with mode incremental or full")
	}
	return nil
}

// readRunInterval returns the interval key and the action's own floor for
// one authorized run. canonicalParams are the run's canonical parameters,
// already checked against the lease. ok is false for a fim.scan run whose
// parameters are not one of the pinned modes.
func readRunInterval(actionID string, canonicalParams []byte) (key string, floor time.Duration, ok bool) {
	if actionID != FimScanActionID {
		return actionID, ReadActionMinInterval(actionID), true
	}
	sum := sha256.Sum256(canonicalParams)
	switch hex.EncodeToString(sum[:]) {
	case FimScanIncrementalParametersHash:
		return actionID, FimScanIncrementalMinInterval, true
	case FimScanFullParametersHash:
		return fimScanFullIntervalKey, FimScanFullMinInterval, true
	}
	return "", 0, false
}
