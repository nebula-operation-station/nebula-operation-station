// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
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

// ErrBuiltinArtifactTrust is a built-in trust commit whose store commit
// succeeded but whose new artifact trust could not be recorded: the new
// built-in versions stay untrusted for risk (fail closed) until the admin
// trusts them individually. The retired versions' trust was already
// revoked before the store committed. Errors carrying it are
// *BuiltinArtifactTrustError.
var ErrBuiltinArtifactTrust = errors.New("built-in trust: store committed, but the artifact trust was not recorded")

// BuiltinArtifactTrustError is the ErrBuiltinArtifactTrust failure with the
// exact state it left: the store is committed at Generation, every entry
// in Revoked (the retired versions' trust) is gone, and none of Untrusted
// (the new versions' entries) was recorded.
type BuiltinArtifactTrustError struct {
	// Generation is the committed store generation.
	Generation int64
	// Retired are the retired versions (name@version), revoked before the
	// store committed.
	Retired []string
	// Revoked are the entries revoked for Retired.
	Revoked []trust.ArtifactTuple
	// Untrusted are the entries the commit meant to record; none was.
	Untrusted []trust.ArtifactTuple
	// Err is the cause.
	Err error
}

// Error tells the admin the state and what to do.
func (e *BuiltinArtifactTrustError) Error() string {
	return fmt.Sprintf("%v (store generation %d): %v; the retired versions %v were revoked before the store commit and are untrusted; "+
		"none of the %d new action entries was recorded, so they stay untrusted (at least HIGH) and a re-run of trust-builtins does not add them: "+
		"trust each one with `nebula artifact trust --action ID --version X.Y.Z --risk LEVEL FILE` "+
		"(the entries are listed in the builtin_trust_artifacts_failed audit record)",
		ErrBuiltinArtifactTrust, e.Generation, e.Err, e.Retired, len(e.Untrusted))
}

// Unwrap returns ErrBuiltinArtifactTrust and the cause.
func (e *BuiltinArtifactTrustError) Unwrap() []error { return []error{ErrBuiltinArtifactTrust, e.Err} }

// BuiltinArtifactTrust records the execution authority of a built-in trust
// commit in the executor's artifact trust, the only trust the risk policy
// reads (internal/riskpolicy, ArtifactRisk). *executordb.DB implements it.
type BuiltinArtifactTrust interface {
	// CheckBuiltinTrust validates a change without writing.
	CheckBuiltinTrust(executordb.BuiltinTrustChange) error
	// ApplyBuiltinTrust records a change atomically and returns the
	// revoked entries.
	ApplyBuiltinTrust(executordb.BuiltinTrustChange) ([]executordb.TrustedArtifact, error)
}

// errBuiltinTrustUnconfigured is returned while no trust transaction is wired.
var errBuiltinTrustUnconfigured = status.Error(codes.Unimplemented, "built-in trust: not configured")

// BuiltinTrust is the executor-local built-in trust transaction (ADR 0007
// E16/E19c). Implementations read the bundle only from an executor-local,
// configured location; callers never pass a path or bundle bytes.
type BuiltinTrust interface {
	// Review returns the dry-run review and scanner findings of the local
	// release bundle against the trust store for the local admin. It
	// commits nothing; the review only becomes committable once
	// ConfirmReview reports it delivered.
	Review(ctx context.Context) (trust.BulkAdmitResult, error)
	// ConfirmReview is called after the last Review was delivered to the
	// admin in full. It binds the next Commit to that review's manifest
	// digest and store generation; a mismatch binds nothing.
	ConfirmReview(ctx context.Context, digest string, generation int64)
	// Status returns the same dry run for the read-only trust status. It
	// never writes state and never binds a commit; implementations may
	// cache it while the store and the bundle are unchanged.
	Status(ctx context.Context) (trust.BulkAdmitResult, error)
	// Commit reviews again and commits atomically when digest matches the
	// reviewed manifest digest and the store generation is still the one
	// the last confirmed Review saw; pins are retained and retired are the
	// retired old versions. It returns the result and the new store generation. Every
	// call consumes the confirmed review, whether it commits or fails.
	Commit(ctx context.Context, digest string, pins map[string]bool, retired []string, adminUID int) (trust.BulkAdmitResult, int64, error)
}

// SetBuiltinTrust wires the built-in trust transaction. It must be called
// before the server starts serving. A nil transaction leaves review and
// commit Unimplemented and status UNAVAILABLE.
func (s *Service) SetBuiltinTrust(t BuiltinTrust) { s.builtinTrust = t }

// dirBuiltinTrust is the directory-backed BuiltinTrust: the store and the
// bundle directory are fixed at construction from executor-local
// configuration. Calls are serialized and every call reopens the existing
// store read-only, so a review always reflects the durable index and
// generation and never initializes or resets state.
type dirBuiltinTrust struct {
	storeDir, bundleDir string
	now                 func() time.Time
	// artifacts receives the exact artifact trust of every commit.
	artifacts BuiltinArtifactTrust

	mu sync.Mutex
	// pending is the last admin Review, not yet confirmed delivered.
	pending *builtinReviewBinding
	// reviewed binds Commit to the last confirmed admin Review.
	reviewed *builtinReviewBinding
	// status caches the last status dry run under statusKey.
	status    *trust.BulkAdmitResult
	statusKey string
	// statusRuns counts uncached status dry runs.
	statusRuns int
}

// builtinReviewBinding is what an admin Review saw.
type builtinReviewBinding struct {
	digest     string
	generation int64
}

// NewDirBuiltinTrust returns a BuiltinTrust over the trust store in storeDir
// and the locally verified release bundle in bundleDir. Both must be
// absolute executor-local paths; anchors are the compiled release anchors
// (release.Anchors) and now is the injected clock (nil means time.Now).
// artifacts is required: every commit records the exact (action, version,
// sha256) trust of the committed versions there and revokes the retired
// ones, so committed built-ins count for risk exactly like
// `nebula artifact trust`.
//
// The store is opened once here, at executor startup, so a fresh store is
// bootstrapped by the executor itself; later calls (including the server's
// status read) only open an existing index read-only and never initialize
// or persist state. A store whose index disappears later stays unavailable
// until local recovery.
func NewDirBuiltinTrust(storeDir, bundleDir string, anchors []release.Anchor, now func() time.Time, artifacts BuiltinArtifactTrust) (BuiltinTrust, error) {
	if storeDir == "" || !filepath.IsAbs(storeDir) {
		return nil, fmt.Errorf("built-in trust: store directory %q must be absolute", storeDir)
	}
	if bundleDir == "" || !filepath.IsAbs(bundleDir) {
		return nil, fmt.Errorf("built-in trust: bundle directory %q must be absolute", bundleDir)
	}
	if artifacts == nil {
		return nil, errors.New("built-in trust: an artifact trust store is required")
	}
	if now == nil {
		now = time.Now
	}
	d := &dirBuiltinTrust{storeDir: filepath.Clean(storeDir), bundleDir: filepath.Clean(bundleDir), now: now, artifacts: artifacts}
	if _, err := trust.Open(d.storeDir, anchors, d.now); err != nil {
		return nil, fmt.Errorf("built-in trust: open store %s: %w", d.storeDir, err)
	}
	return d, nil
}

// openStore checks for the bundle and opens the existing store read-only.
func (d *dirBuiltinTrust) openStore() (*trust.Store, error) {
	if _, err := os.Stat(d.bundleDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBuiltinTrustUnavailable
		}
		return nil, fmt.Errorf("built-in trust: stat bundle: %w", err)
	}
	st, err := trust.OpenExisting(d.storeDir, d.now)
	if err != nil {
		return nil, fmt.Errorf("built-in trust: open store: %w", err)
	}
	return st, nil
}

// readBundle reads the bundle against the store's current durable roots.
func (d *dirBuiltinTrust) readBundle(st *trust.Store) (release.Candidate, error) {
	c, err := release.ReadBundleDir(d.bundleDir, st.Roots())
	if err != nil {
		return release.Candidate{}, fmt.Errorf("built-in trust: read bundle: %w", err)
	}
	return c, nil
}

// open opens the store and reads the bundle.
func (d *dirBuiltinTrust) open() (*trust.Store, release.Candidate, error) {
	st, err := d.openStore()
	if err != nil {
		return nil, release.Candidate{}, err
	}
	c, err := d.readBundle(st)
	if err != nil {
		return nil, release.Candidate{}, err
	}
	return st, c, nil
}

// Review implements BuiltinTrust.
func (d *dirBuiltinTrust) Review(_ context.Context) (trust.BulkAdmitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending, d.reviewed = nil, nil
	st, c, err := d.open()
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	res, err := st.BulkAdmit(c, trust.BulkAdmitOpts{})
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	d.pending = &builtinReviewBinding{digest: res.ManifestDigest, generation: res.Review.Generation}
	return res, nil
}

// ConfirmReview implements BuiltinTrust.
func (d *dirBuiltinTrust) ConfirmReview(_ context.Context, digest string, generation int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p := d.pending; p != nil && p.digest == digest && p.generation == generation {
		d.reviewed = p
	}
	d.pending = nil
}

// Status implements BuiltinTrust. The dry run is cached under the store
// generation and the bundle files' identity, size and times, so polling
// does not repeat it while nothing changed; Commit drops the cache.
func (d *dirBuiltinTrust) Status(_ context.Context) (trust.BulkAdmitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := d.openStore()
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	key, err := d.statusCacheKey(st.Generation())
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	if d.status != nil && d.statusKey == key {
		return *d.status, nil
	}
	d.status = nil
	d.statusRuns++
	c, err := d.readBundle(st)
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	res, err := st.BulkAdmit(c, trust.BulkAdmitOpts{})
	if err != nil {
		return trust.BulkAdmitResult{}, err
	}
	d.status, d.statusKey = &res, key
	return res, nil
}

// statusKeyDirEntries bounds the bundle directory listing read for the
// status cache key: the three bundle files plus one, so any extra entry
// (which ReadBundleDir rejects) changes the key.
const statusKeyDirEntries = 4

// bundleDirNames returns up to statusKeyDirEntries entry names of the
// bundle directory, sorted.
func (d *dirBuiltinTrust) bundleDirNames() ([]string, error) {
	f, err := os.Open(d.bundleDir)
	if err != nil {
		return nil, fmt.Errorf("built-in trust: open bundle directory: %w", err)
	}
	defer f.Close()
	names, err := f.Readdirnames(statusKeyDirEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("built-in trust: list bundle directory: %w", err)
	}
	sort.Strings(names)
	return names, nil
}

// statusCacheKey identifies the store generation, the bundle directory
// listing and the bundle files by device, inode, size, mtime and ctime. A
// replaced or rewritten bundle file changes its ctime and an added or
// removed entry changes the listing, so the key changes with any
// substitution.
func (d *dirBuiltinTrust) statusCacheKey(generation int64) (string, error) {
	var b strings.Builder
	b.WriteString(strconv.FormatInt(generation, 10))
	names, err := d.bundleDirNames()
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "|dir %d", len(names))
	for _, n := range names {
		b.WriteString(" " + strconv.QuoteToASCII(n))
	}
	for _, name := range []string{release.ManifestFile, release.SignatureFile, release.BundleArtifact} {
		fi, err := os.Lstat(filepath.Join(d.bundleDir, name))
		if err != nil {
			return "", fmt.Errorf("built-in trust: stat bundle file %s: %w", name, err)
		}
		fmt.Fprintf(&b, "|%s %o %d %d", name, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			fmt.Fprintf(&b, " %d %d %d.%d", sys.Dev, sys.Ino, sys.Ctim.Sec, sys.Ctim.Nsec)
		}
	}
	return b.String(), nil
}

// Commit implements BuiltinTrust. It requires a prior admin Review of the
// same manifest digest at the store's current generation; a store that
// changed since that review rejects the commit as stale. Every attempt
// consumes the review, also one that fails, so a retry needs a new review.
func (d *dirBuiltinTrust) Commit(_ context.Context, digest string, pins map[string]bool, retired []string, adminUID int) (trust.BulkAdmitResult, int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rb := d.reviewed
	d.pending, d.reviewed = nil, nil
	st, c, err := d.open()
	if err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	switch {
	case rb == nil:
		return trust.BulkAdmitResult{}, 0, fmt.Errorf("%w: no review to commit", trust.ErrStale)
	case rb.digest != digest:
		return trust.BulkAdmitResult{}, 0, fmt.Errorf("%w: confirmed digest %s is not the reviewed manifest digest %s", trust.ErrStale, digest, rb.digest)
	case rb.generation != st.Generation():
		return trust.BulkAdmitResult{}, 0, fmt.Errorf("%w: the store changed since the review (generation %d, now %d)", trust.ErrStale, rb.generation, st.Generation())
	}
	// Check the artifact trust the commit implies before the store
	// commits, so a malformed tuple cannot leave committed built-ins
	// without their recorded trust.
	dry, err := st.BulkAdmit(c, trust.BulkAdmitOpts{})
	if err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	// Reject a changed bundle and invalid decisions before anything is
	// revoked below.
	if dry.ManifestDigest != digest {
		return trust.BulkAdmitResult{}, 0, fmt.Errorf("%w: confirmed digest %s does not match the reviewed manifest digest %s", trust.ErrStale, digest, dry.ManifestDigest)
	}
	if err := trust.CheckDecisions(dry.OldVersions, pins, retired); err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	change, err := builtinTrustChange(dry.Review, retired, adminUID)
	if err != nil {
		return trust.BulkAdmitResult{}, 0, err
	}
	if err := d.artifacts.CheckBuiltinTrust(change); err != nil {
		return trust.BulkAdmitResult{}, 0, fmt.Errorf("built-in trust: %w", err)
	}
	// Revoke the retired versions' trust before the store commits (fail
	// closed): if anything later fails, no retired version stays trusted
	// for risk while the store no longer lists it. A failure here commits
	// nothing.
	var revoked []executordb.TrustedArtifact
	if len(change.Retire) > 0 {
		if revoked, err = d.artifacts.ApplyBuiltinTrust(executordb.BuiltinTrustChange{Retire: change.Retire}); err != nil {
			return trust.BulkAdmitResult{}, 0, fmt.Errorf("built-in trust: revoke the retired versions %v (nothing committed, the store and the artifact trust are unchanged; review and commit again): %w", retired, err)
		}
	}
	res, err := st.BulkAdmit(c, trust.BulkAdmitOpts{ConfirmedDigest: digest, Pins: pins, Retired: retired, AdminUID: adminUID})
	d.status = nil
	if err != nil {
		if len(revoked) > 0 {
			return trust.BulkAdmitResult{}, 0, fmt.Errorf("%w (the store was not committed, but the trust of the retired versions %v was already revoked: %s; "+
				"to keep using them, trust them again with `nebula artifact trust`)", err, retired, strings.Join(artifactAudit(tuples(revoked)), ", "))
		}
		return trust.BulkAdmitResult{}, 0, err
	}
	// Record the committed review's authority (ADR 0007 E16). The retired
	// versions are revoked again in the same transaction, so an entry
	// added for them meanwhile cannot survive the retirement.
	change, err = builtinTrustChange(res.Review, res.Retired, adminUID)
	if err != nil {
		return trust.BulkAdmitResult{}, 0, &BuiltinArtifactTrustError{Generation: st.Generation(), Retired: retired, Revoked: tuples(revoked), Err: err}
	}
	again, err := d.artifacts.ApplyBuiltinTrust(change)
	if err != nil {
		return trust.BulkAdmitResult{}, 0, &BuiltinArtifactTrustError{Generation: st.Generation(), Retired: res.Retired,
			Revoked: tuples(revoked), Untrusted: tuples(change.Trust), Err: err}
	}
	res.ArtifactsTrusted = append(res.ArtifactsTrusted, tuples(change.Trust)...)
	res.ArtifactsRevoked = append(res.ArtifactsRevoked, tuples(revoked)...)
	res.ArtifactsRevoked = append(res.ArtifactsRevoked, tuples(again)...)
	return res, st.Generation(), nil
}

// builtinTrustChange maps the artifact trust a review implies, committed
// with the retired old versions, to trust entries: exact tuples recorded
// for the admin as `nebula artifact trust` records them.
func builtinTrustChange(r trust.Review, retired []string, adminUID int) (executordb.BuiltinTrustChange, error) {
	at, err := trust.ArtifactTrustFor(r, retired)
	if err != nil {
		return executordb.BuiltinTrustChange{}, err
	}
	var out executordb.BuiltinTrustChange
	by := string(peercred.RoleAdmin) + ":uid" + strconv.Itoa(adminUID)
	for _, t := range at.Trust {
		out.Trust = append(out.Trust, executordb.TrustedArtifact{SHA256: t.SHA256, ActionID: t.ActionID,
			ModuleVersion: t.ModuleVersion, Risk: canonical.Risk(t.Risk), Label: "built-in release " + r.ReleaseVersion, TrustedBy: by})
	}
	for _, v := range at.Retire {
		out.Retire = append(out.Retire, executordb.BuiltinVersion{Module: v.Module, Version: v.Version})
	}
	return out, nil
}

// tuples is the audit form of trust entries.
func tuples(as []executordb.TrustedArtifact) []trust.ArtifactTuple {
	out := make([]trust.ArtifactTuple, 0, len(as))
	for _, a := range as {
		out = append(out, artifactTuple(a))
	}
	return out
}

// artifactTuple is the audit form of a trust entry.
func artifactTuple(a executordb.TrustedArtifact) trust.ArtifactTuple {
	return trust.ArtifactTuple{ActionID: a.ActionID, ModuleVersion: a.ModuleVersion, SHA256: a.SHA256, Risk: string(a.Risk)}
}

// builtinTupleAudit renders the module-level old/new trust tuples for the
// audit log: names, versions, hashes and statuses only.
func builtinTupleAudit(ts []trust.TrustTuple) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, fmt.Sprintf("%s %s:%s -> %s:%s (%s)", t.Module, t.OldVersion, t.OldSHA256, t.NewVersion, t.NewSHA256, t.Status))
	}
	return out
}

// artifactAudit renders exact artifact trust tuples for the audit log.
func artifactAudit(ts []trust.ArtifactTuple) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ActionID+"@"+t.ModuleVersion+" "+t.SHA256+" "+t.Risk)
	}
	return out
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
	// Only a review the admin receives in full becomes committable.
	s.builtinTrust.ConfirmReview(ctx, r.ManifestDigest, r.Generation)
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
		var ae *BuiltinArtifactTrustError
		if errors.As(err, &ae) && s.log != nil {
			s.log.Error("audit", "kind", "builtin_trust_artifacts_failed", "by", callerName(ctx), "admin_uid", uid,
				"manifest_digest", req.GetManifestDigest(), "generation", ae.Generation, "retired", ae.Retired,
				"revoked", artifactAudit(ae.Revoked), "untrusted", artifactAudit(ae.Untrusted), "err", ae.Err.Error())
		}
		return nil, builtinTrustStatus(err)
	}
	if s.log != nil {
		s.log.Info("audit", "kind", "builtin_trust_committed", "by", callerName(ctx), "admin_uid", uid,
			"manifest_digest", res.ManifestDigest, "release", res.Review.ReleaseVersion, "generation", gen,
			"tuples", builtinTupleAudit(res.Tuples), "trusted", artifactAudit(res.ArtifactsTrusted),
			"revoked", artifactAudit(res.ArtifactsRevoked), "retained", res.Pinned, "retired", res.Retired,
			"collected", res.Collected, "cleanup_failures", res.CleanupFailures)
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
	res, err := s.builtinTrust.Status(ctx)
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
