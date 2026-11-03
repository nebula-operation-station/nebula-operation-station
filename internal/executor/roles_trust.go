// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

const (
	// maxBuiltinTrustDecisions bounds the retain and the retire list of a
	// CommitBuiltinTrust request each.
	maxBuiltinTrustDecisions = 1024
	// maxBuiltinVersionRefBytes bounds one name@version entry.
	maxBuiltinVersionRefBytes = 256
)

// ErrBuiltinTrustUnavailable is returned when no verified local release
// bundle is present in the executor-configured directory.
var ErrBuiltinTrustUnavailable = errors.New("built-in trust: no local release bundle available")

// errBuiltinTrustUnconfigured is returned while no trust transaction is wired.
var errBuiltinTrustUnconfigured = status.Error(codes.Unimplemented, "built-in trust: not configured")

// BuiltinTrust is the executor-local built-in trust transaction (ADR 0007
// E16/E19c). Implementations read the bundle only from an executor-local,
// configured location; callers never pass a path or bundle bytes.
type BuiltinTrust interface {
	// Review returns the dry-run review and scanner findings of the local
	// release bundle against the trust store. It commits nothing.
	Review(ctx context.Context) (trust.BulkAdmitResult, error)
	// Commit reviews again and commits atomically when digest matches the
	// reviewed manifest digest; pins are retained and retired retired old
	// versions. It returns the result and the new store generation.
	Commit(ctx context.Context, digest string, pins map[string]bool, retired []string, adminUID int) (trust.BulkAdmitResult, int64, error)
}

// SetBuiltinTrust wires the built-in trust transaction. It must be called
// before the server starts serving. A nil transaction leaves review and
// commit Unimplemented and status UNAVAILABLE.
func (s *Service) SetBuiltinTrust(t BuiltinTrust) { s.builtinTrust = t }

// dirBuiltinTrust is the directory-backed BuiltinTrust: the store and the
// bundle directory are fixed at construction from executor-local
// configuration. Calls are serialized and every call reopens the store, so a
// review always reflects the durable index and generation.
type dirBuiltinTrust struct {
	storeDir, bundleDir string
	anchors             []release.Anchor
	now                 func() time.Time
	mu                  sync.Mutex
}

// NewDirBuiltinTrust returns a BuiltinTrust over the trust store in storeDir
// and the locally verified release bundle in bundleDir. Both must be
// absolute executor-local paths; anchors are the compiled release anchors
// (release.Anchors) and now is the injected clock (nil means time.Now).
func NewDirBuiltinTrust(storeDir, bundleDir string, anchors []release.Anchor, now func() time.Time) (BuiltinTrust, error) {
	if storeDir == "" || !filepath.IsAbs(storeDir) {
		return nil, fmt.Errorf("built-in trust: store directory %q must be absolute", storeDir)
	}
	if bundleDir == "" || !filepath.IsAbs(bundleDir) {
		return nil, fmt.Errorf("built-in trust: bundle directory %q must be absolute", bundleDir)
	}
	if now == nil {
		now = time.Now
	}
	return &dirBuiltinTrust{storeDir: filepath.Clean(storeDir), bundleDir: filepath.Clean(bundleDir), anchors: anchors, now: now}, nil
}

// open checks for the bundle, opens the store and reads the bundle against
// the store's current durable roots.
func (d *dirBuiltinTrust) open() (*trust.Store, release.Candidate, error) {
	if _, err := os.Stat(d.bundleDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, release.Candidate{}, ErrBuiltinTrustUnavailable
		}
		return nil, release.Candidate{}, fmt.Errorf("built-in trust: stat bundle: %w", err)
	}
	st, err := trust.Open(d.storeDir, d.anchors, d.now)
	if err != nil {
		return nil, release.Candidate{}, fmt.Errorf("built-in trust: open store: %w", err)
	}
	c, err := release.ReadBundleDir(d.bundleDir, st.Roots())
	if err != nil {
		return nil, release.Candidate{}, fmt.Errorf("built-in trust: read bundle: %w", err)
	}
	return st, c, nil
}

// Review implements BuiltinTrust.
func (d *dirBuiltinTrust) Review(_ context.Context) (trust.BulkAdmitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, c, err := d.open()
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	return st.BulkAdmit(c, trust.BulkAdmitOpts{})
}

// Commit implements BuiltinTrust.
func (d *dirBuiltinTrust) Commit(_ context.Context, digest string, pins map[string]bool, retired []string, adminUID int) (trust.BulkAdmitResult, int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, c, err := d.open()
	if err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	res, err := st.BulkAdmit(c, trust.BulkAdmitOpts{ConfirmedDigest: digest, Pins: pins, Retired: retired, AdminUID: adminUID})
	if err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	return res, st.Generation(), nil
}

// builtinTrustAdmin returns the local admin caller's UID from peer
// credentials. It is defense in depth behind the role table: the handler
// itself refuses any caller that is not the admin role.
func builtinTrustAdmin(ctx context.Context) (uint32, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "built-in trust: no authenticated caller")
	}
	if c.Role != peercred.RoleAdmin {
		return 0, status.Error(codes.PermissionDenied, "built-in trust: local admin only")
	}
	return c.UID, nil
}

// validateBuiltinTrustMessage enforces the executor-wide request bound.
func validateBuiltinTrustMessage(m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() || proto.Size(m) > MaxMessageSize {
		return status.Error(codes.InvalidArgument, "built-in trust: missing or oversize request")
	}
	return nil
}

// validBuiltinVersionRef reports whether s is a bounded UTF-8 name@version.
// The trust store checks every entry against the reviewed old versions.
func validBuiltinVersionRef(s string) bool {
	if len(s) > maxBuiltinVersionRefBytes || !utf8.ValidString(s) {
		return false
	}
	name, version, ok := strings.Cut(s, "@")
	return ok && name != "" && version != ""
}

// validateCommitBuiltinTrust rejects malformed or oversize commits before
// the trust transaction is touched.
func validateCommitBuiltinTrust(req *pb.CommitBuiltinTrustRequest) error {
	if err := validateBuiltinTrustMessage(req); err != nil {
		return err
	}
	if !canonical.ValidSHA256Hex(req.GetManifestDigest()) {
		return status.Error(codes.InvalidArgument, "built-in trust: invalid manifest digest")
	}
	if len(req.GetRetain()) > maxBuiltinTrustDecisions || len(req.GetRetire()) > maxBuiltinTrustDecisions {
		return status.Errorf(codes.InvalidArgument, "built-in trust: at most %d retained and %d retired versions", maxBuiltinTrustDecisions, maxBuiltinTrustDecisions)
	}
	seen := make(map[string]bool, len(req.GetRetain())+len(req.GetRetire()))
	for _, list := range [][]string{req.GetRetain(), req.GetRetire()} {
		for _, v := range list {
			if !validBuiltinVersionRef(v) {
				return status.Error(codes.InvalidArgument, "built-in trust: malformed name@version")
			}
			if seen[v] {
				return status.Error(codes.InvalidArgument, "built-in trust: version listed twice")
			}
			seen[v] = true
		}
	}
	return nil
}

// builtinTrustStatus maps trust transaction errors to gRPC codes. Only the
// local admin sees these messages; they carry versions, never secrets.
func builtinTrustStatus(err error) error {
	switch {
	case errors.Is(err, trust.ErrStale):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, trust.ErrQuota):
		return status.Error(codes.ResourceExhausted, err.Error())
	default:
		// Unavailable bundle, substitution, invalid provenance, corrupt or
		// missing state and rejected retain/retire decisions.
		return status.Error(codes.FailedPrecondition, err.Error())
	}
}

// builtinChangeToProto maps a review status.
func builtinChangeToProto(s trust.Status) pb.BuiltinTrustChange {
	switch s {
	case trust.StatusNew:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_NEW
	case trust.StatusChanged:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED
	case trust.StatusUnchanged:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_UNCHANGED
	case trust.StatusReactivated:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REACTIVATED
	case trust.StatusRemoved:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED
	default:
		return pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_UNSPECIFIED
	}
}

// builtinDiffLine renders one diff line. A line that is not valid UTF-8 is
// sent in Go-quoted ASCII form with escaped set: exact, never repaired.
func builtinDiffLine(l textdiff.Line) *pb.BuiltinDiffLine {
	out := &pb.BuiltinDiffLine{Text: l.Text}
	switch l.Op {
	case textdiff.Equal:
		out.Op = pb.BuiltinDiffOp_BUILTIN_DIFF_OP_EQUAL
	case textdiff.Insert:
		out.Op = pb.BuiltinDiffOp_BUILTIN_DIFF_OP_INSERT
	case textdiff.Delete:
		out.Op = pb.BuiltinDiffOp_BUILTIN_DIFF_OP_DELETE
	}
	if !utf8.ValidString(l.Text) {
		out.Text, out.Escaped = strconv.QuoteToASCII(l.Text), true
	}
	return out
}

// builtinActionToProto renders one action review with its scanner result.
func builtinActionToProto(module string, a trust.ActionReview, scans []trust.ScanFinding) *pb.BuiltinActionReview {
	out := &pb.BuiltinActionReview{
		ActionId:          a.ActionID,
		Change:            builtinChangeToProto(a.Status),
		OldRisk:           a.OldRisk,
		NewRisk:           a.NewRisk,
		OldScriptSha256:   a.OldScriptSHA256,
		NewScriptSha256:   a.NewScriptSHA256,
		OldArtifactSha256: a.OldArtifactSHA256,
		NewArtifactSha256: a.NewArtifactSHA256,
		Diff:              make([]*pb.BuiltinDiffLine, 0, len(a.Diff)),
	}
	for _, l := range a.Diff {
		out.Diff = append(out.Diff, builtinDiffLine(l))
	}
	for _, sc := range scans {
		if sc.Module != module || sc.ActionID != a.ActionID {
			continue
		}
		out.ScannerFloor = riskToProto(canonical.Risk(sc.Floor))
		for _, f := range sc.Findings {
			out.Findings = append(out.Findings, &pb.BuiltinScanFinding{
				Category: f.Category, Risk: riskToProto(f.Risk), Line: int32(f.Line), Excerpt: f.Excerpt,
			})
		}
	}
	return out
}

// ReviewBuiltinTrust returns the complete review of the executor's local
// release bundle for the local admin: every module and action with old/new
// versions, hashes, risks, the full script diff and scanner findings. It
// commits nothing and is never truncated.
func (s *Service) ReviewBuiltinTrust(ctx context.Context, req *pb.ReviewBuiltinTrustRequest) (*pb.ReviewBuiltinTrustResponse, error) {
	if err := validateBuiltinTrustMessage(req); err != nil {
		return nil, err
	}
	if _, err := builtinTrustAdmin(ctx); err != nil {
		return nil, err
	}
	if s.builtinTrust == nil {
		return nil, errBuiltinTrustUnconfigured
	}
	res, err := s.builtinTrust.Review(ctx)
	if err != nil {
		return nil, builtinTrustStatus(err)
	}
	r := res.Review
	out := &pb.ReviewBuiltinTrustResponse{
		ManifestDigest:    r.ManifestDigest,
		ReleaseVersion:    r.ReleaseVersion,
		RootId:            r.RootID,
		RootFingerprint:   r.RootFingerprint,
		Generation:        r.Generation,
		NeedsConfirmation: res.NeedsConfirmation,
		Modules:           make([]*pb.BuiltinModuleReview, 0, len(r.Modules)),
		OldVersions:       append([]string(nil), res.OldVersions...),
	}
	for _, m := range r.Modules {
		mr := &pb.BuiltinModuleReview{
			Name:             m.Name,
			Change:           builtinChangeToProto(m.Status),
			OldVersion:       m.OldVersion,
			OldSha256:        m.OldSHA256,
			NewVersion:       m.NewVersion,
			NewSha256:        m.NewSHA256,
			FullReview:       m.FullReview,
			FullReviewReason: m.Reason,
			Actions:          make([]*pb.BuiltinActionReview, 0, len(m.Actions)),
		}
		for _, a := range m.Actions {
			mr.Actions = append(mr.Actions, builtinActionToProto(m.Name, a, res.Scans))
		}
		out.Modules = append(out.Modules, mr)
	}
	if proto.Size(out) > MaxResponseSize {
		return nil, status.Error(codes.ResourceExhausted, "built-in trust: review exceeds response limit")
	}
	return out, nil
}

// CommitBuiltinTrust commits the locally reviewed additions/changes
// atomically, bound to the confirmed manifest digest, with every old version
// explicitly retained or retired (local admin only). The trust store
// reviews again and rejects a changed bundle or store generation. The admin
// UID is taken from peer credentials, never from the request.
func (s *Service) CommitBuiltinTrust(ctx context.Context, req *pb.CommitBuiltinTrustRequest) (*pb.CommitBuiltinTrustResponse, error) {
	if err := validateCommitBuiltinTrust(req); err != nil {
		return nil, err
	}
	uid, err := builtinTrustAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.builtinTrust == nil {
		return nil, errBuiltinTrustUnconfigured
	}
	pins := make(map[string]bool, len(req.GetRetain()))
	for _, v := range req.GetRetain() {
		pins[v] = true
	}
	retired := append([]string(nil), req.GetRetire()...)
	res, gen, err := s.builtinTrust.Commit(ctx, req.GetManifestDigest(), pins, retired, int(uid))
	if err != nil {
		return nil, builtinTrustStatus(err)
	}
	if s.log != nil {
		s.log.Info("built-in trust committed", "manifest_digest", res.ManifestDigest, "generation", gen,
			"admin_uid", uid, "retained", res.Pinned, "retired", res.Retired, "cleanup_failures", res.CleanupFailures)
	}
	out := &pb.CommitBuiltinTrustResponse{
		ManifestDigest:  res.ManifestDigest,
		Generation:      gen,
		AdminUid:        uid,
		Retained:        append([]string(nil), res.Pinned...),
		Retired:         append([]string(nil), res.Retired...),
		Collected:       append([]string(nil), res.Collected...),
		CleanupFailures: int32(res.CleanupFailures),
		Tuples:          make([]*pb.BuiltinTrustTuple, 0, len(res.Tuples)),
	}
	for _, tu := range res.Tuples {
		out.Tuples = append(out.Tuples, &pb.BuiltinTrustTuple{
			Module: tu.Module, OldVersion: tu.OldVersion, OldSha256: tu.OldSHA256,
			NewVersion: tu.NewVersion, NewSha256: tu.NewSHA256, Change: builtinChangeToProto(trust.Status(tu.Status)),
		})
	}
	return out, nil
}

// GetBuiltinTrustStatus reports which built-in versions are trusted and which
// are not (server and admin roles). It is a dry-run review reduced to
// per-module versions and hashes: no diffs, scripts, scanner excerpts or
// paths, and it never commits or grants anything. Any failure is reported as
// UNAVAILABLE without detail; the detail is logged locally.
func (s *Service) GetBuiltinTrustStatus(ctx context.Context, req *pb.GetBuiltinTrustStatusRequest) (*pb.GetBuiltinTrustStatusResponse, error) {
	if err := validateBuiltinTrustMessage(req); err != nil {
		return nil, err
	}
	unavailable := &pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE}
	if s.builtinTrust == nil {
		return unavailable, nil
	}
	res, err := s.builtinTrust.Review(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn("built-in trust status unavailable", "err", err)
		}
		return unavailable, nil
	}
	out := &pb.GetBuiltinTrustStatusResponse{
		State:          pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED,
		ManifestDigest: res.Review.ManifestDigest,
		ReleaseVersion: res.Review.ReleaseVersion,
		Generation:     res.Review.Generation,
		Modules:        make([]*pb.BuiltinTrustEntry, 0, len(res.Review.Modules)),
	}
	if res.NeedsConfirmation {
		out.State = pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED
	}
	for _, m := range res.Review.Modules {
		out.Modules = append(out.Modules, &pb.BuiltinTrustEntry{
			Name: m.Name, Change: builtinChangeToProto(m.Status),
			TrustedVersion: m.OldVersion, TrustedSha256: m.OldSHA256,
			ReleaseVersion: m.NewVersion, ReleaseSha256: m.NewSHA256,
		})
	}
	return out, nil
}
