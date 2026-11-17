// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ADR 0015 D7 "Server compromise": the executor recomputes the digest of
// the server's I2 baseline list itself and compares it with the digest it
// holds. The server sends the list, never a digest, so a server that
// rewrote the list cannot present the old approved digest. A mismatch is
// an executor-held finding (executordb.RecordBaselineTamper), shown by
// GetIntegrityStatus, and never changes the stored digest.

// maxBaselineListBytes bounds the summed path, link and fstype bytes of one
// streamed list: the fim-scan-v1 document limit, which every approved list
// came through.
const maxBaselineListBytes = fimscan.MaxDocumentBytes

// BaselineComparison is the result of comparing the recomputed digest of a
// caller's I2 baseline list with the executor-held approved digest.
type BaselineComparison string

// Comparison results.
const (
	// BaselineMatch: the recomputed digest equals the approved digest.
	BaselineMatch BaselineComparison = "match"
	// BaselineTamper: the recomputed digest differs from the approved
	// digest (`integrity.baseline_tamper`). The stored digest is kept and
	// an executor-held finding is opened or updated.
	BaselineTamper BaselineComparison = "baseline_tamper"
	// BaselineNone: the executor holds no approved digest for the host.
	BaselineNone BaselineComparison = "none"
)

// ErrBaselineListInvalid is a malformed or oversize baseline list stream.
var ErrBaselineListInvalid = errors.New("executor: compare baseline list: malformed list")

// baselineResult is the outcome of one comparison.
type baselineResult struct {
	Result BaselineComparison
	// Computed is the digest the executor computed; empty for
	// BaselineNone.
	Computed string
}

// baselineListAcc collects one streamed list within its limits.
type baselineListAcc struct {
	header      *pb.CompareBaselineListHeader
	res         fimscan.Result
	bytes, max  int
	gotEntries  int
	gotMounts   int
	wantEntries int
	wantMounts  int
}

func newBaselineListAcc(h *pb.CompareBaselineListHeader, maxBytes int) *baselineListAcc {
	return &baselineListAcc{
		header: h, max: maxBytes,
		res:         fimscan.Result{ProfileID: h.GetProfileId(), Mode: fimscan.ModeFull},
		wantEntries: int(h.GetEntryCount()), wantMounts: int(h.GetMountCount()),
	}
}

func invalidList(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrBaselineListInvalid}, a...)...)
}

// checkHeader validates the header before anything else is read.
func (a *baselineListAcc) checkHeader() error {
	h := a.header
	switch {
	case !canonical.ValidHostID(h.GetHostId()):
		return invalidList("host_id is malformed")
	case h.GetProfileId() == "" || len(h.GetProfileId()) > fimbaseline.MaxProfileIDBytes:
		return invalidList("profile_id is empty or too long")
	case h.GetEntryCount() > fimbaseline.MaxEntries:
		return invalidList("entry_count above %d", fimbaseline.MaxEntries)
	case h.GetMountCount() > fimbaseline.MaxMounts:
		return invalidList("mount_count above %d", fimbaseline.MaxMounts)
	}
	return nil
}

func (a *baselineListAcc) spend(n int) error {
	if n > a.max-a.bytes {
		return invalidList("list above %d bytes", a.max)
	}
	a.bytes += n
	return nil
}

// add takes one body chunk.
func (a *baselineListAcc) add(c *pb.CompareBaselineListRequest) error {
	if c.GetHeader() != nil {
		return invalidList("header after the first message")
	}
	if len(c.GetEntries()) == 0 && len(c.GetMounts()) == 0 {
		return invalidList("empty message")
	}
	if len(c.GetEntries()) > a.wantEntries-a.gotEntries {
		return invalidList("more entries than entry_count")
	}
	if len(c.GetMounts()) > a.wantMounts-a.gotMounts {
		return invalidList("more mounts than mount_count")
	}
	for _, e := range c.GetEntries() {
		if err := a.spend(len(e.GetPath()) + len(e.GetLink())); err != nil {
			return err
		}
		r, err := baselineRecord(e)
		if err != nil {
			return err
		}
		a.res.Records = append(a.res.Records, r)
		a.gotEntries++
	}
	for _, m := range c.GetMounts() {
		if err := a.spend(len(m.GetPath()) + len(m.GetFsType())); err != nil {
			return err
		}
		a.res.Mounts = append(a.res.Mounts, fimscan.Mount{Path: m.GetPath(), FSType: m.GetFsType()})
		a.gotMounts++
	}
	return nil
}

// recomputeDigest checks the counts and computes the digest the same way
// an approval does (fimbaseline.NewBaseline), which also enforces the
// path, link, uniqueness and hash rules.
func (a *baselineListAcc) recomputeDigest() (string, error) {
	if a.gotEntries != a.wantEntries || a.gotMounts != a.wantMounts {
		return "", invalidList("fewer entries or mounts than declared")
	}
	b, err := fimbaseline.NewBaseline(&a.res)
	if err != nil {
		return "", invalidList("%v", err)
	}
	return b.Digest().String(), nil
}

// baselineRecord converts one entry; enum values outside the known set,
// hash sums of the wrong size and secret flags on unkeyed hashes are
// refused.
func baselineRecord(e *pb.BaselineListEntry) (fimscan.Record, error) {
	r := fimscan.Record{
		Path: e.GetPath(), Size: e.GetSize(), Mode: e.GetMode(), UID: e.GetUid(), GID: e.GetGid(),
		Inode: e.GetInode(), Mtime: e.GetMtime(), Ctime: e.GetCtime(),
	}
	switch e.GetType() {
	case pb.BaselineEntryType_BASELINE_ENTRY_TYPE_FILE:
		r.Type = fimscan.TypeFile
	case pb.BaselineEntryType_BASELINE_ENTRY_TYPE_DIR:
		r.Type = fimscan.TypeDir
	case pb.BaselineEntryType_BASELINE_ENTRY_TYPE_SYMLINK:
		r.Type = fimscan.TypeSymlink
	case pb.BaselineEntryType_BASELINE_ENTRY_TYPE_OTHER:
		r.Type = fimscan.TypeOther
	default:
		return fimscan.Record{}, invalidList("unknown entry type")
	}
	switch e.GetHashKind() {
	case pb.BaselineHashKind_BASELINE_HASH_KIND_NONE:
		r.Hash.Kind = fimscan.HashNone
	case pb.BaselineHashKind_BASELINE_HASH_KIND_PLAIN:
		r.Hash.Kind = fimscan.HashPlain
	case pb.BaselineHashKind_BASELINE_HASH_KIND_KEYED:
		r.Hash.Kind = fimscan.HashKeyed
	default:
		return fimscan.Record{}, invalidList("unknown hash kind")
	}
	if r.Hash.Kind == fimscan.HashNone {
		if len(e.GetHashSum()) != 0 || e.GetHashSecret() {
			return fimscan.Record{}, invalidList("hash value on an entry without hash")
		}
	} else if len(e.GetHashSum()) != len(r.Hash.Sum) {
		return fimscan.Record{}, invalidList("hash sum must be %d bytes", len(r.Hash.Sum))
	}
	if e.GetHashSecret() && r.Hash.Kind != fimscan.HashKeyed {
		return fimscan.Record{}, invalidList("secret-bearing entry without keyed hash")
	}
	r.Hash.Secret = e.GetHashSecret()
	copy(r.Hash.Sum[:], e.GetHashSum())
	if len(e.GetLink()) > 0 {
		r.Link = e.GetLink()
	}
	return r, nil
}

// compareBaselineList rebuilds the list of header and body, recomputes its
// digest and compares it with the executor's approved digest for the
// host. It never writes the approved digest. On a mismatch it records the
// executor-held finding and audits it (on opening, then at most once per
// executordb.BaselineTamperAuditInterval). by is the caller from peer
// credentials, for the audit.
func (s *Service) compareBaselineList(header *pb.CompareBaselineListHeader, body []*pb.CompareBaselineListRequest, by string) (baselineResult, error) {
	acc := newBaselineListAcc(header, maxBaselineListBytes)
	if err := acc.checkHeader(); err != nil {
		return baselineResult{}, err
	}
	for _, c := range body {
		if err := acc.add(c); err != nil {
			return baselineResult{}, err
		}
	}
	return s.finishBaselineCompare(acc, by)
}

func (s *Service) approvedBaselineDigest(hostID, by string) (executordb.BaselineDigest, bool, error) {
	if s.db == nil {
		return executordb.BaselineDigest{}, false, fmt.Errorf("compare baseline list for %s: executor database not configured", hostID)
	}
	approved, err := s.db.ApprovedBaselineDigest(hostID)
	switch {
	case errors.Is(err, executordb.ErrNoBaselineDigest):
		return executordb.BaselineDigest{}, false, nil
	case err != nil:
		s.auditLog(slog.LevelError, "integrity_baseline_digest_unreadable", slog.String("by", by),
			slog.String("host", hostID), slog.String("detail", err.Error()))
		return executordb.BaselineDigest{}, false, fmt.Errorf("compare baseline list for %s: %w", hostID, err)
	}
	return approved, true, nil
}

func (s *Service) finishBaselineCompare(acc *baselineListAcc, by string) (baselineResult, error) {
	host := acc.header.GetHostId()
	computed, err := acc.recomputeDigest()
	if err != nil {
		return baselineResult{}, err
	}
	approved, ok, err := s.approvedBaselineDigest(host, by)
	if err != nil {
		return baselineResult{}, err
	}
	if !ok {
		return baselineResult{Result: BaselineNone, Computed: computed}, nil
	}
	if approved.Digest == computed {
		return baselineResult{Result: BaselineMatch, Computed: computed}, nil
	}
	f, audit, err := s.db.RecordBaselineTamper(host, approved.Digest, computed)
	if err != nil {
		// The mismatch is still reported and audited; only its storage
		// failed.
		s.auditLog(slog.LevelError, "integrity_baseline_tamper_unrecorded",
			slog.String("finding", string(notify.IntegrityBaselineTamper)), slog.String("by", by),
			slog.String("host", host), slog.String("computed_digest", computed),
			slog.String("approved_digest", approved.Digest), slog.String("detail", err.Error()))
		return baselineResult{Result: BaselineTamper, Computed: computed}, nil
	}
	if audit {
		s.auditLog(slog.LevelWarn, "integrity_baseline_tamper",
			slog.String("finding", string(notify.IntegrityBaselineTamper)),
			slog.String("by", by), slog.String("host", host),
			slog.String("computed_digest", computed), slog.String("approved_digest", approved.Digest),
			slog.String("approval_kind", string(approved.Kind)), slog.Int64("approved_unix", approved.ApprovedAt.Unix()),
			slog.Bool("opened", f.Opened), slog.Int64("count", f.Count), slog.Int64("first_seen_unix", f.FirstSeen.Unix()))
	}
	return baselineResult{Result: BaselineTamper, Computed: computed}, nil
}

// baselineCompareTimeout is the executor's own deadline for one
// CompareBaselineList call, from the opened stream to the answer. A caller
// that stalls or never closes its stream is cut off here, so it holds
// baselineCompareMu at most this long (MEDIUM 2 of PR #579). A full list
// (fimscan.MaxDocumentBytes) over the local socket takes seconds. A
// variable only so tests can shorten it.
var baselineCompareTimeout = 2 * time.Minute

// errBaselineCompareDeadline ends a comparison the caller did not finish
// within baselineCompareTimeout.
var errBaselineCompareDeadline = status.Error(codes.DeadlineExceeded,
	"compare baseline list: the list was not complete within the executor deadline")

// recvResult is one stream.Recv outcome handed from the receiving
// goroutine.
type recvResult struct {
	msg *pb.CompareBaselineListRequest
	err error
}

// baselineReceiver reads the stream in its own goroutine so the handler
// can stop waiting at the executor deadline: grpc's Recv does not return
// before the stream ends, and the stream ends only when the handler
// returns. After the deadline the goroutine sees the cancelled stream,
// stops and drops what it read; it touches nothing but the stream.
type baselineReceiver struct {
	ctx    context.Context
	stream grpc.ClientStreamingServer[pb.CompareBaselineListRequest, pb.CompareBaselineListResponse]
	out    chan recvResult
	ask    chan struct{}
}

func newBaselineReceiver(ctx context.Context, stream grpc.ClientStreamingServer[pb.CompareBaselineListRequest, pb.CompareBaselineListResponse]) *baselineReceiver {
	r := &baselineReceiver{ctx: ctx, stream: stream, out: make(chan recvResult, 1), ask: make(chan struct{})}
	go r.loop()
	return r
}

func (r *baselineReceiver) loop() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.ask:
		}
		m, err := r.stream.Recv()
		r.out <- recvResult{msg: m, err: err}
		if err != nil {
			return
		}
	}
}

// recv is stream.Recv bounded by the receiver's deadline.
func (r *baselineReceiver) recv() (*pb.CompareBaselineListRequest, error) {
	select {
	case r.ask <- struct{}{}:
	case <-r.ctx.Done():
		return nil, errBaselineCompareDeadline
	}
	select {
	case res := <-r.out:
		return res.msg, res.err
	case <-r.ctx.Done():
		return nil, errBaselineCompareDeadline
	}
}

// CompareBaselineList is the RPC form of compareBaselineList; the method
// table allows server and admin. The first message is the header; the
// executor stops reading early when it holds no approved digest for the
// host. One comparison runs at a time: baselineCompareMu is taken only
// once a valid header arrived and is held while the bounded list is read
// and compared, never longer than baselineCompareTimeout. It never writes
// the approved digest.
func (s *Service) CompareBaselineList(stream grpc.ClientStreamingServer[pb.CompareBaselineListRequest, pb.CompareBaselineListResponse]) error {
	ctx, cancel := context.WithTimeout(stream.Context(), baselineCompareTimeout)
	defer cancel()
	by := callerName(stream.Context())
	res, err := s.receiveBaselineList(newBaselineReceiver(ctx, stream), by)
	switch {
	case errors.Is(err, ErrBaselineListInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Error(codes.Internal, "compare baseline list: the approved digest could not be read")
	}
	// The answer is the result enum only; the computed digest stays in the
	// executor (finding and audit).
	out := &pb.CompareBaselineListResponse{}
	switch res.Result {
	case BaselineMatch:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MATCH
	case BaselineTamper:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MISMATCH
	case BaselineNone:
		out.Result = pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_NONE
	}
	return stream.SendAndClose(out)
}

func (s *Service) receiveBaselineList(stream *baselineReceiver, by string) (baselineResult, error) {
	// The header is read without the lock: a caller that opens the stream
	// and sends nothing blocks no other comparison.
	first, err := stream.recv()
	if errors.Is(err, io.EOF) {
		return baselineResult{}, invalidList("no header")
	}
	if err != nil {
		return baselineResult{}, err
	}
	if first.GetHeader() == nil || len(first.GetEntries()) != 0 || len(first.GetMounts()) != 0 {
		return baselineResult{}, invalidList("the first message must carry the header only")
	}
	acc := newBaselineListAcc(first.GetHeader(), maxBaselineListBytes)
	if err := acc.checkHeader(); err != nil {
		return baselineResult{}, err
	}
	// From here one list is buffered: one at a time, so the lists of
	// concurrent callers cannot add up; bounded in time by the deadline.
	if !s.baselineCompareMu.TryLock() {
		return baselineResult{}, status.Error(codes.Unavailable, "compare baseline list: another comparison is running")
	}
	defer s.baselineCompareMu.Unlock()
	if _, ok, err := s.approvedBaselineDigest(acc.header.GetHostId(), by); err != nil {
		return baselineResult{}, err
	} else if !ok {
		return baselineResult{Result: BaselineNone}, nil
	}
	for {
		c, err := stream.recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return baselineResult{}, err
		}
		if err := acc.add(c); err != nil {
			return baselineResult{}, err
		}
	}
	return s.finishBaselineCompare(acc, by)
}

func baselineTamperToProto(f executordb.BaselineTamperFinding) *pb.BaselineTamperFinding {
	return &pb.BaselineTamperFinding{
		// No approved digest: GetIntegrityStatus serves the server role.
		HostId: f.HostID, PresentedDigest: f.PresentedDigest,
		FirstSeenUnix: f.FirstSeen.Unix(), LastSeenUnix: f.LastSeen.Unix(), Count: f.Count,
	}
}
