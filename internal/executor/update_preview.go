// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
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
//   - ReleaseRun keeps the result of the newest preview while the host has
//     an uncertain recreation row, so the evidence is still there to read.

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
	updatePreviewArtifactSHA256 = "7775738be3dab225799482aaea60da5ad4f0911fe2ae1593b01af627cf70a640"
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

// previewRetention remembers, per host, the preview run whose result
// ReleaseRun keeps (Q19: only the newest preview of a host). It lives in
// memory: the executor store has no query for a host's previews, so a
// result retained before a restart is not superseded by a later one.
type previewRetention struct {
	mu   sync.Mutex
	kept map[string]keptPreview // by host ID
}

// keptPreview is one retained preview run.
type keptPreview struct {
	executionID string
	created     time.Time
}

// newerThan orders preview runs of one host by start (runs.created_at),
// then by execution ID, so two runs of the same second have one order.
func (k keptPreview) newerThan(o keptPreview) bool {
	if !k.created.Equal(o.created) {
		return k.created.After(o.created)
	}
	return k.executionID > o.executionID
}

// retainPreviewResult reports whether ReleaseRun must keep the result of a
// finished run: only the newest preview run of a host that has an
// uncertain recreation row keeps it, for Resolve (Q19). Keeping a newer
// preview releases the one kept before; an older preview is released like
// any run. Once the host has no uncertain row, the kept preview is
// released too. A store error keeps the result (the evidence is not
// thrown away on a guess).
func (s *Service) retainPreviewResult(run executordb.Run) bool {
	if !isUpdatePreview(run.ActionID) || run.MemberID != "" {
		return false
	}
	uncertain, err := s.db.HostHasUncertainRecreation(run.HostID)
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "host_uncertain_recreation", "host", run.HostID, "detail", err.Error())
		return true
	}
	this := keptPreview{executionID: run.ExecutionID, created: run.CreatedAt}
	k := &s.previewKeep
	k.mu.Lock()
	defer k.mu.Unlock()
	prev, had := k.kept[run.HostID]
	switch {
	case had && prev.executionID == run.ExecutionID:
		if uncertain {
			return true
		}
		delete(k.kept, run.HostID)
		return false
	case had && !uncertain:
		s.releaseKeptPreview(run.HostID, prev)
		delete(k.kept, run.HostID)
		return false
	case !uncertain:
		return false
	case had && !this.newerThan(prev):
		// A newer preview of the host is kept already.
		return false
	case had:
		s.releaseKeptPreview(run.HostID, prev)
	}
	if k.kept == nil {
		k.kept = map[string]keptPreview{}
	}
	k.kept[run.HostID] = this
	s.log.Info("audit", "kind", "preview_result_retained", "execution", run.ExecutionID, "host", run.HostID)
	return true
}

// releaseKeptPreview drops the result of a preview kept before; a store
// error leaves it kept and is audited.
func (s *Service) releaseKeptPreview(hostID string, k keptPreview) {
	if err := s.db.ReleaseRun(k.executionID, hostID); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "release_run", "execution", k.executionID, "host", hostID, "detail", err.Error())
		return
	}
	s.log.Info("audit", "kind", "preview_result_released", "execution", k.executionID, "host", hostID)
}
