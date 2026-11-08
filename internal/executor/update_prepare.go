// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// docker.update_prepare (ADR 0006 P2-03, container update plan cu02, Q5).
//
// Prepare creates the root-only per-host salt that keys the configuration
// and source digests of the preview and the update. It changes the host,
// so it is at least MEDIUM, and the salt it writes decides which digests
// the host produces, so the executor, not the server, decides how it runs:
//
//   - never below MEDIUM: a proposal that declares a lower risk class is
//     refused, whatever risk an operator registered for the artifact;
//   - only as a durable job on the classic path (root, like the preview
//     that reads the salt), with the fixed updatePrepareTimeout: never
//     attached and never as a batch member;
//   - only with the pinned module version and the exact artifact digest
//     (updatePrepareArtifactSHA256), so no other artifact trusted for the
//     action ID can write, replace or print a salt;
//   - its runs row records the action ID, like the preview's.
//
// Its result (docker-update-prepare-v1) is "created" or "present" and never
// the salt, so ReleaseRun releases it like any run: unlike the preview's,
// it is no evidence Resolve reads.

// updatePrepareAction is prepare's action ID.
const updatePrepareAction = "docker.update_prepare"

const (
	// updatePrepareVersion is the pinned module version (result format
	// docker-update-prepare-v1).
	updatePrepareVersion = "1.0.0"
	// updatePrepareArtifactSHA256 is the lowercase hex SHA-256 of
	// internal/executions/actions/scripts/docker_update_prepare.sh as
	// embedded in the server's catalog (checked by
	// TestShippedUpdatePreparePinMatchesEmbeddedScript). Changing it is a
	// reviewed change of this protected package.
	updatePrepareArtifactSHA256 = "5d8eb7ef4115bdd7b79abceb667c930556691aad58012cc4f200d0ca01d2e74d"
	// updatePrepareTimeout bounds one prepare job on the host; the
	// request cannot change it.
	updatePrepareTimeout = 2 * time.Minute
	// updatePrepareMinRisk is the lowest risk class a prepare permit may
	// carry.
	updatePrepareMinRisk = canonical.RiskMedium
)

var (
	// errPrepareArtifact: a prepare run that does not name the pinned
	// module version, or whose artifact does not hash to the pinned digest.
	errPrepareArtifact = errors.New("docker.update_prepare runs only with the pinned 1.0.0 artifact")
	// errPrepareTransport: a prepare run requested attached or as a batch
	// member.
	errPrepareTransport = errors.New("docker.update_prepare runs only as a durable job on the classic path")
	// errPrepareRisk: a prepare proposal below MEDIUM.
	errPrepareRisk = errors.New("docker.update_prepare is at least MEDIUM")
)

// isUpdatePrepare reports whether actionID is prepare.
func isUpdatePrepare(actionID string) bool { return actionID == updatePrepareAction }

// checkPreparePin checks prepare's module version and artifact digest
// against the pin (at proposal, where the request declares the digest).
func checkPreparePin(moduleVersion, artifactSHA256 string) error {
	if moduleVersion != updatePrepareVersion || artifactSHA256 != updatePrepareArtifactSHA256 {
		return errPrepareArtifact
	}
	return nil
}

// checkPrepareArtifact checks a prepare run's module version and the
// artifact bytes it would put on the host against the pin.
func checkPrepareArtifact(moduleVersion string, artifact []byte) error {
	sum := sha256.Sum256(artifact)
	return checkPreparePin(moduleVersion, hex.EncodeToString(sum[:]))
}

// checkPrepareProposal checks a prepare proposal: the pinned artifact and
// a declared risk class of at least MEDIUM. The permit binds the declared
// class, and approval never lowers it, so every prepare permit is at
// least MEDIUM.
func checkPrepareProposal(r canonical.Request) error {
	if err := checkPreparePin(r.ModuleVersion, r.ArtifactSHA256); err != nil {
		return err
	}
	if r.RiskClass.Rank() < updatePrepareMinRisk.Rank() {
		return errPrepareRisk
	}
	return nil
}

func prepareStatus(err error) error {
	return status.Error(codes.FailedPrecondition, "update_prepare_refused: "+err.Error())
}
