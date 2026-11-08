// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// docker.update_preview (ADR 0006 P2-03, container update plan cu02, Q19).
//
// The preview is the only source of the keyed configuration and source
// digests a container update binding holds, and its result is the evidence
// that resolves an uncertain recreation (cu03). So the executor, not the
// server, decides how it runs:
//
//   - only as a durable job on the classic path, with the fixed
//     updatePreviewTimeout: never attached (an attached run has no runs row
//     that Resolve could read) and never as a batch member;
//   - only with the pinned module version and the exact artifact digest
//     (updatePreviewArtifactSHA256), so no other artifact the operator
//     happens to trust for the action ID produces "preview" evidence;
//   - its runs row records the action ID, so Resolve can prove which action
//     produced a result (runs.action_id);
//   - ReleaseRun keeps the result while the host has an uncertain
//     recreation row, so the evidence is still there to read.

// updatePreviewAction is the preview's action ID.
const updatePreviewAction = "docker.update_preview"

const (
	// updatePreviewVersion is the pinned module version (result format
	// docker-update-preview-v1).
	updatePreviewVersion = "1.0.0"
	// updatePreviewArtifactSHA256 is the lowercase hex SHA-256 of
	// internal/executions/actions/scripts/docker_update_preview.sh as
	// embedded in the server's catalog (checked by
	// TestShippedUpdatePreviewPinMatchesEmbeddedScript). Changing it is a
	// reviewed change of this protected package.
	updatePreviewArtifactSHA256 = "ab543a795187aaa1db1e5396034cbf14dd7b5487a5e0fe42345bd8488af09813"
	// updatePreviewTimeout bounds one preview job on the host; the request
	// cannot change it. The script stops its own work a minute earlier.
	updatePreviewTimeout = 5 * time.Minute
)

var (
	// errPreviewArtifact: a preview run that does not name the pinned
	// module version, or whose artifact does not hash to the pinned digest.
	errPreviewArtifact = errors.New("docker.update_preview runs only with the pinned 1.0.0 artifact")
	// errPreviewTransport: a preview run requested attached or as a batch
	// member.
	errPreviewTransport = errors.New("docker.update_preview runs only as a durable job on the classic path")
)

// isUpdatePreview reports whether actionID is the preview.
func isUpdatePreview(actionID string) bool { return actionID == updatePreviewAction }

// checkPreviewPin checks a preview's module version and artifact digest
// against the pin (at proposal, where the request declares the digest).
func checkPreviewPin(moduleVersion, artifactSHA256 string) error {
	if moduleVersion != updatePreviewVersion || artifactSHA256 != updatePreviewArtifactSHA256 {
		return errPreviewArtifact
	}
	return nil
}

// checkPreviewArtifact checks a preview run's module version and the
// artifact bytes it would put on the host against the pin.
func checkPreviewArtifact(moduleVersion string, artifact []byte) error {
	sum := sha256.Sum256(artifact)
	return checkPreviewPin(moduleVersion, hex.EncodeToString(sum[:]))
}

func previewStatus(err error) error {
	return status.Error(codes.FailedPrecondition, "update_preview_refused: "+err.Error())
}

// retainPreviewResult reports whether ReleaseRun must keep the result of a
// finished run: a preview run of a host that has an uncertain recreation
// row keeps it for Resolve. The store cannot tell which preview is the
// newest one of a host, so every such preview is kept until no row of the
// host is uncertain; a later release request then drops it. A store error
// keeps the result (the evidence is not thrown away on a guess).
func (s *Service) retainPreviewResult(run executordb.Run) bool {
	if !isUpdatePreview(run.ActionID) || run.MemberID != "" {
		return false
	}
	uncertain, err := s.db.HostHasUncertainRecreation(run.HostID)
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "host_uncertain_recreation", "host", run.HostID, "detail", err.Error())
		return true
	}
	if uncertain {
		s.log.Info("audit", "kind", "preview_result_retained", "execution", run.ExecutionID, "host", run.HostID)
	}
	return uncertain
}
