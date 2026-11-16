// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Release root rotation files (spec 10, root rotation and revocation). The
// executor reads them only from RootRotationDirName next to its configured
// local release directory (/usr/share/nebula/release-rotation for the
// default /usr/share/nebula/release). They cannot live in the release
// directory itself: spec 10 requires that directory to hold exactly the
// manifest, its signature and builtins.tar, and to apply rotations
// separately first.
const (
	// RootRotationDirName is the rotation directory, a sibling of the
	// release bundle directory.
	RootRotationDirName = "release-rotation"
	// RootRotationFile is the signed rotation document.
	RootRotationFile = "root-rotation.json"
	// RootRotationSignatureFile is its detached SSHSIG signature.
	RootRotationSignatureFile = "root-rotation.json.sig"
)

// ErrRootRotationUnavailable is returned when the local rotation directory
// holds no rotation document and signature.
var ErrRootRotationUnavailable = errors.New("root rotation: no " + RootRotationFile + " and " + RootRotationSignatureFile + " in the local rotation directory")

// rotationDir is the executor-local rotation directory for bundleDir.
func rotationDir(bundleDir string) string {
	return filepath.Join(filepath.Dir(bundleDir), RootRotationDirName)
}

// ErrRootRotationApplied is a rotation whose exact bytes are the last one
// already applied to the durable root state (a replay); nothing to commit.
var ErrRootRotationApplied = errors.New("root rotation: this rotation is already applied")

// errRootRotationUnconfigured is returned while no release directory is
// wired.
var errRootRotationUnconfigured = status.Error(codes.Unimplemented, "root rotation: not configured")

// RootRotationReview is a rotation verified against the durable root
// state, before (Old) and after (New) applying it.
type RootRotationReview struct {
	// Rotation is the verified document: digest, sequence, signer,
	// added roots and revoked IDs.
	Rotation release.Rotation
	// Old is the durable root state the rotation was verified against;
	// New is the state it produces.
	Old, New release.RootState
	// Generation is the trust store generation the review saw.
	Generation int64
}

// RootRotation is the executor-local root rotation admission. The rotation
// is read only from the executor-configured release directory; callers
// never pass a path or bytes. Only a delivered review becomes committable,
// and a commit applies exactly the reviewed bytes at the reviewed store
// generation.
type RootRotation interface {
	// ReviewRotation verifies the local rotation against the durable root
	// state and returns the old and new roots. It commits nothing.
	ReviewRotation(ctx context.Context) (RootRotationReview, error)
	// ConfirmRotationReview is called after the last review was delivered
	// in full; it binds the next commit to that digest and generation.
	ConfirmRotationReview(ctx context.Context, digest string, generation int64)
	// CommitRotation applies the reviewed rotation when digest is the
	// confirmed rotation digest, the bytes on disk still have it and the
	// store generation is unchanged. Every call consumes the confirmed
	// review.
	CommitRotation(ctx context.Context, digest string) (RootRotationReview, int64, error)
}

// readRotationFile reads one rotation file from the release directory as a
// regular file of at most max bytes, without following symlinks.
func readRotationFile(r *os.Root, name string, max int64) ([]byte, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w (missing %s)", ErrRootRotationUnavailable, name)
		}
		return nil, fmt.Errorf("root rotation: stat %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("root rotation: %s is not a regular file", name)
	}
	// O_NONBLOCK: a FIFO swapped in after Lstat must not hang the open.
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("root rotation: open %s: %w", name, err)
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("root rotation: %s is not a regular file of at most %d bytes", name, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("root rotation: read %s: at most %d bytes", name, max)
	}
	return b, nil
}

// readRotation reads the rotation document and its signature.
func (d *dirBuiltinTrust) readRotation() (doc, sig []byte, err error) {
	dir := rotationDir(d.bundleDir)
	r, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w (%s does not exist)", ErrRootRotationUnavailable, dir)
		}
		return nil, nil, fmt.Errorf("root rotation: open rotation directory %s: %w", dir, err)
	}
	defer r.Close()
	if doc, err = readRotationFile(r, RootRotationFile, release.MaxRotation); err != nil {
		return nil, nil, err
	}
	if sig, err = readRotationFile(r, RootRotationSignatureFile, release.MaxSignature); err != nil {
		return nil, nil, err
	}
	return doc, sig, nil
}

// reviewRotation verifies the local rotation against st's durable roots.
func (d *dirBuiltinTrust) reviewRotation(st *trust.Store) (RootRotationReview, []byte, []byte, error) {
	doc, sig, err := d.readRotation()
	if err != nil {
		return RootRotationReview{}, nil, nil, err
	}
	old := st.RootState()
	sum := sha256.Sum256(doc)
	if old.Sequence > 0 && hex.EncodeToString(sum[:]) == old.Digest {
		return RootRotationReview{}, nil, nil, fmt.Errorf("%w (sequence %d)", ErrRootRotationApplied, old.Sequence)
	}
	next, rot, err := old.ApplyRotation(doc, sig)
	if err != nil {
		return RootRotationReview{}, nil, nil, fmt.Errorf("root rotation: %w", err)
	}
	return RootRotationReview{Rotation: rot, Old: old, New: next, Generation: st.Generation()}, doc, sig, nil
}

// ReviewRotation implements RootRotation.
func (d *dirBuiltinTrust) ReviewRotation(_ context.Context) (RootRotationReview, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rotationPending, d.rotationReviewed = nil, nil
	st, err := trust.OpenExisting(d.storeDir, d.now)
	if err != nil {
		return RootRotationReview{}, fmt.Errorf("root rotation: open store: %w", err)
	}
	rev, _, _, err := d.reviewRotation(st)
	if err != nil {
		return RootRotationReview{}, err
	}
	d.rotationPending = &builtinReviewBinding{digest: rev.Rotation.Digest, generation: rev.Generation}
	return rev, nil
}

// ConfirmRotationReview implements RootRotation.
func (d *dirBuiltinTrust) ConfirmRotationReview(_ context.Context, digest string, generation int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.rotationPending
	d.rotationPending = nil
	if p != nil && p.digest == digest && p.generation == generation {
		d.rotationReviewed = p
	}
}

// CommitRotation implements RootRotation.
func (d *dirBuiltinTrust) CommitRotation(_ context.Context, digest string) (RootRotationReview, int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rb := d.rotationReviewed
	d.rotationPending, d.rotationReviewed = nil, nil
	if rb == nil {
		return RootRotationReview{}, 0, fmt.Errorf("%w: no reviewed root rotation to commit", trust.ErrStale)
	}
	if rb.digest != digest {
		return RootRotationReview{}, 0, fmt.Errorf("%w: confirmed digest %s is not the reviewed rotation digest %s", trust.ErrStale, digest, rb.digest)
	}
	st, err := trust.OpenExisting(d.storeDir, d.now)
	if err != nil {
		return RootRotationReview{}, 0, fmt.Errorf("root rotation: open store: %w", err)
	}
	if g := st.Generation(); g != rb.generation {
		return RootRotationReview{}, 0, fmt.Errorf("%w: the store changed since the review (generation %d, now %d)", trust.ErrStale, rb.generation, g)
	}
	// An interrupted built-in trust commit is resolved by its store
	// generation; a rotation must not move the generation under it.
	if _, err := trust.ReadPending(d.storeDir); !errors.Is(err, os.ErrNotExist) {
		return RootRotationReview{}, 0, fmt.Errorf("%w: an interrupted built-in trust commit is pending (%v); run `nebula artifact trust-builtins` first", trust.ErrStale, err)
	}
	rev, doc, sig, err := d.reviewRotation(st)
	if err != nil {
		return RootRotationReview{}, 0, err
	}
	if rev.Rotation.Digest != digest {
		return RootRotationReview{}, 0, fmt.Errorf("%w: %s changed since the review", trust.ErrStale, RootRotationFile)
	}
	// The store verifies again against its durable state and persists the
	// new roots, the record and the document atomically; a competing
	// writer makes it ErrStale.
	if _, err := st.ApplyRotation(doc, sig); err != nil {
		return RootRotationReview{}, 0, fmt.Errorf("root rotation: %w", err)
	}
	return rev, st.Generation(), nil
}

// rootRotationAdmin returns the local admin caller's UID from peer
// credentials, defense in depth behind the role table.
func rootRotationAdmin(ctx context.Context) (uint32, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "root rotation: no authenticated caller")
	}
	if c.Role != peercred.RoleAdmin {
		return 0, status.Error(codes.PermissionDenied, "root rotation: local admin only")
	}
	return c.UID, nil
}

// rootRotationStatus maps rotation errors to gRPC codes. Messages carry
// root IDs, sequences and digests, never key or signature bytes.
func rootRotationStatus(err error) error {
	switch {
	case errors.Is(err, trust.ErrStale):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, trust.ErrQuota):
		return status.Error(codes.ResourceExhausted, err.Error())
	default:
		// Missing or malformed files, bad or untrusted signatures, a
		// replay, a wrong predecessor, root limits and missing state.
		return status.Error(codes.FailedPrecondition, err.Error())
	}
}

// releaseRootToProto renders one root record: ID, fingerprint, lifecycle.
func releaseRootToProto(r release.RootRecord) *pb.ReleaseRoot {
	out := &pb.ReleaseRoot{Id: r.ID, AddedSequence: r.AddedSequence, RevokedSequence: r.RevokedSequence}
	if k, err := release.ParseRootKey(r.PublicKey); err == nil {
		out.Fingerprint = release.Root{ID: r.ID, Key: k}.Fingerprint()
	}
	return out
}

func releaseRootsToProto(rs []release.RootRecord) []*pb.ReleaseRoot {
	out := make([]*pb.ReleaseRoot, 0, len(rs))
	for _, r := range rs {
		out = append(out, releaseRootToProto(r))
	}
	return out
}

// rootAudit lists roots as "id fingerprint" for the audit record.
func rootAudit(rs []*pb.ReleaseRoot) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		s := r.GetId() + " " + r.GetFingerprint()
		if r.GetRevokedSequence() != 0 {
			s += fmt.Sprintf(" revoked@%d", r.GetRevokedSequence())
		}
		out = append(out, s)
	}
	return out
}

// rotationProto renders the parts of a review the responses share.
func rotationProto(rev RootRotationReview) (signedBy *pb.ReleaseRoot, added []*pb.ReleaseRoot) {
	rot := rev.Rotation
	signedBy = &pb.ReleaseRoot{Id: rot.SignedBy.ID, Fingerprint: rot.SignedBy.Fingerprint()}
	for _, r := range rev.Old.Roots {
		if r.ID == rot.SignedBy.ID {
			signedBy = releaseRootToProto(r)
		}
	}
	for _, a := range rot.Added {
		added = append(added, &pb.ReleaseRoot{Id: a.ID, Fingerprint: a.Fingerprint(), AddedSequence: rot.Sequence})
	}
	return signedBy, added
}

// ReviewRootRotation verifies the executor's local root-rotation.json
// against the durable root state for the local admin and returns the old
// and resulting roots with fingerprints. It commits nothing; only a review
// delivered in full becomes committable.
func (s *Service) ReviewRootRotation(ctx context.Context, req *pb.ReviewRootRotationRequest) (*pb.ReviewRootRotationResponse, error) {
	if err := validateBuiltinTrustMessage(req); err != nil {
		return nil, err
	}
	if _, err := rootRotationAdmin(ctx); err != nil {
		return nil, err
	}
	if s.rootRotation == nil {
		return nil, errRootRotationUnconfigured
	}
	rev, err := s.rootRotation.ReviewRotation(ctx)
	if err != nil {
		return nil, rootRotationStatus(err)
	}
	signedBy, added := rotationProto(rev)
	out := &pb.ReviewRootRotationResponse{
		RotationDigest:  rev.Rotation.Digest,
		Sequence:        rev.Rotation.Sequence,
		CurrentSequence: rev.Old.Sequence,
		SignedBy:        signedBy,
		OldRoots:        releaseRootsToProto(rev.Old.Roots),
		NewRoots:        releaseRootsToProto(rev.New.Roots),
		Added:           added,
		Revoked:         append([]string(nil), rev.Rotation.Revoked...),
		Generation:      rev.Generation,
	}
	if proto.Size(out) > MaxResponseSize {
		return nil, status.Error(codes.ResourceExhausted, "root rotation: review exceeds response limit")
	}
	s.rootRotation.ConfirmRotationReview(ctx, rev.Rotation.Digest, rev.Generation)
	return out, nil
}

// CommitRootRotation applies the locally reviewed rotation to the durable
// root state, bound to the confirmed rotation digest and the reviewed store
// generation (local admin only). The admin UID comes from peer
// credentials. Applied and rejected commits are audited with digests,
// sequences and fingerprints, never with key or signature bytes.
func (s *Service) CommitRootRotation(ctx context.Context, req *pb.CommitRootRotationRequest) (*pb.CommitRootRotationResponse, error) {
	if err := validateBuiltinTrustMessage(req); err != nil {
		return nil, err
	}
	if !canonical.ValidSHA256Hex(req.GetRotationDigest()) {
		return nil, status.Error(codes.InvalidArgument, "root rotation: invalid rotation digest")
	}
	uid, err := rootRotationAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.rootRotation == nil {
		return nil, errRootRotationUnconfigured
	}
	rev, gen, err := s.rootRotation.CommitRotation(ctx, req.GetRotationDigest())
	if err != nil {
		s.auditLog(slog.LevelWarn, "root_rotation_rejected", slog.String("by", callerName(ctx)), slog.Any("admin_uid", uid),
			slog.String("rotation_digest", req.GetRotationDigest()), slog.String("err", err.Error()))
		return nil, rootRotationStatus(err)
	}
	signedBy, added := rotationProto(rev)
	roots := releaseRootsToProto(rev.New.Roots)
	s.auditLog(slog.LevelInfo, "root_rotation_applied", slog.String("by", callerName(ctx)), slog.Any("admin_uid", uid),
		slog.String("rotation_digest", rev.Rotation.Digest), slog.Int64("sequence", rev.Rotation.Sequence),
		slog.Int64("previous_sequence", rev.Old.Sequence), slog.String("previous_digest", rev.Old.Digest),
		slog.Int64("generation", gen), slog.Any("signed_by", rootAudit([]*pb.ReleaseRoot{signedBy})),
		slog.Any("added", rootAudit(added)), slog.Any("revoked", rev.Rotation.Revoked),
		slog.Any("old_roots", rootAudit(releaseRootsToProto(rev.Old.Roots))), slog.Any("roots", rootAudit(roots)))
	return &pb.CommitRootRotationResponse{
		RotationDigest: rev.Rotation.Digest,
		Sequence:       rev.Rotation.Sequence,
		Generation:     gen,
		AdminUid:       uid,
		SignedBy:       signedBy,
		Roots:          roots,
	}, nil
}
