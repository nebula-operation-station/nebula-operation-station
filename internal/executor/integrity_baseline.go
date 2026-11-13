// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// BaselineComparison is the result of comparing a caller's I2 baseline
// digest with the executor-held approved digest (ADR 0015 D7 item 2).
type BaselineComparison string

// Comparison results.
const (
	// BaselineMatch: the caller's digest equals the approved digest.
	BaselineMatch BaselineComparison = "match"
	// BaselineTamper: the caller's digest differs from the approved
	// digest (`integrity.baseline_tamper`). The stored digest is kept.
	BaselineTamper BaselineComparison = "baseline_tamper"
	// BaselineNone: the executor holds no approved digest for the host.
	BaselineNone BaselineComparison = "none"
)

// ErrBaselineCompareInvalid is a malformed host ID or digest.
var ErrBaselineCompareInvalid = errors.New("executor: compare baseline digest: malformed host_id or digest")

// CompareBaselineDigestLocal compares digest, the digest of the baseline
// list a caller holds for hostID, with the executor's approved digest. It
// only reads: a mismatch is audited and reported as BaselineTamper, and
// the stored digest is never replaced by the caller's (no silent
// correction). by is the caller from peer credentials, for the audit.
func (s *Service) CompareBaselineDigestLocal(hostID, digest, by string) (BaselineComparison, error) {
	if !canonical.ValidHostID(hostID) || !executordb.ValidBaselineDigest(digest) {
		return "", ErrBaselineCompareInvalid
	}
	if s.db == nil {
		return "", fmt.Errorf("compare baseline digest for %s: executor database not configured", hostID)
	}
	approved, err := s.db.ApprovedBaselineDigest(hostID)
	switch {
	case errors.Is(err, executordb.ErrNoBaselineDigest):
		return BaselineNone, nil
	case err != nil:
		s.auditLog(slog.LevelError, "integrity_baseline_digest_unreadable", slog.String("by", by),
			slog.String("host", hostID), slog.String("detail", err.Error()))
		return "", fmt.Errorf("compare baseline digest for %s: %w", hostID, err)
	}
	if approved.Digest == digest {
		return BaselineMatch, nil
	}
	s.auditLog(slog.LevelWarn, "integrity_baseline_tamper",
		slog.String("finding", string(notify.IntegrityBaselineTamper)),
		slog.String("by", by), slog.String("host", hostID),
		slog.String("presented_digest", digest), slog.String("approved_digest", approved.Digest),
		slog.String("approval_kind", string(approved.Kind)), slog.Int64("approved_unix", approved.ApprovedAt.Unix()))
	return BaselineTamper, nil
}

// CompareBaselineDigest is the RPC form of CompareBaselineDigestLocal; the
// method table allows server and admin. It never writes.
func (s *Service) CompareBaselineDigest(ctx context.Context, req *pb.CompareBaselineDigestRequest) (*pb.CompareBaselineDigestResponse, error) {
	res, err := s.CompareBaselineDigestLocal(req.GetHostId(), req.GetDigest(), callerName(ctx))
	switch {
	case errors.Is(err, ErrBaselineCompareInvalid):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, "compare baseline digest: the approved digest could not be read")
	}
	out := &pb.CompareBaselineDigestResponse{}
	switch res {
	case BaselineMatch:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MATCH
	case BaselineTamper:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MISMATCH
		out.FindingKind = string(notify.IntegrityBaselineTamper)
	case BaselineNone:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_NONE
	}
	return out, nil
}
