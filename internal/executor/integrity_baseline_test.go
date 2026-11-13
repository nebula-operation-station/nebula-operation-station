// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const testProfile = "fim-default-v1"

// approvedList is the baseline list the executor approved for web-1.
func approvedList() (*pb.CompareBaselineListRequest, []*pb.CompareBaselineListRequest) {
	header := &pb.CompareBaselineListRequest{Header: &pb.CompareBaselineListHeader{
		HostId: "web-1", ProfileId: testProfile, EntryCount: 4, MountCount: 1,
	}}
	sum := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	entries := []*pb.BaselineListEntry{
		{Path: []byte("/etc"), Type: pb.BaselineEntryType_BASELINE_ENTRY_TYPE_DIR, Mode: 0o755, Inode: 2,
			HashKind: pb.BaselineHashKind_BASELINE_HASH_KIND_NONE},
		{Path: []byte("/etc/passwd"), Type: pb.BaselineEntryType_BASELINE_ENTRY_TYPE_FILE, Size: 1200, Mode: 0o644,
			Inode: 3, Mtime: 1700000000, Ctime: 1700000000,
			HashKind: pb.BaselineHashKind_BASELINE_HASH_KIND_KEYED, HashSum: sum("passwd")},
		{Path: []byte("/etc/shadow"), Type: pb.BaselineEntryType_BASELINE_ENTRY_TYPE_FILE, Size: 900, Mode: 0o640,
			Gid: 42, Inode: 4, HashKind: pb.BaselineHashKind_BASELINE_HASH_KIND_KEYED, HashSecret: true, HashSum: sum("shadow")},
		{Path: []byte("/etc/localtime"), Type: pb.BaselineEntryType_BASELINE_ENTRY_TYPE_SYMLINK, Mode: 0o777, Inode: 5,
			HashKind: pb.BaselineHashKind_BASELINE_HASH_KIND_NONE, Link: []byte("/usr/share/zoneinfo/UTC")},
	}
	body := []*pb.CompareBaselineListRequest{
		{Entries: entries[:2]},
		{Entries: entries[2:], Mounts: []*pb.BaselineListMount{{Path: []byte("/boot/efi"), FsType: "vfat"}}},
	}
	return header, body
}

func cloneChunks(cs []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
	out := make([]*pb.CompareBaselineListRequest, len(cs))
	for i, c := range cs {
		out[i] = proto.Clone(c).(*pb.CompareBaselineListRequest)
	}
	return out
}

// digestOfChunks computes the digest of a list independently of the code
// under test, from fimscan records through fimbaseline.
func digestOfChunks(t *testing.T, header *pb.CompareBaselineListRequest, body []*pb.CompareBaselineListRequest) string {
	t.Helper()
	res := &fimscan.Result{ProfileID: header.GetHeader().GetProfileId(), Mode: fimscan.ModeFull}
	for _, c := range body {
		for _, e := range c.GetEntries() {
			r := fimscan.Record{Path: e.GetPath(), Type: fimscan.Type(e.GetType()), Size: e.GetSize(), Mode: e.GetMode(),
				UID: e.GetUid(), GID: e.GetGid(), Inode: e.GetInode(), Mtime: e.GetMtime(), Ctime: e.GetCtime()}
			r.Hash.Kind = fimscan.HashKind(e.GetHashKind() - 1)
			r.Hash.Secret = e.GetHashSecret()
			copy(r.Hash.Sum[:], e.GetHashSum())
			if len(e.GetLink()) > 0 {
				r.Link = e.GetLink()
			}
			res.Records = append(res.Records, r)
		}
		for _, m := range c.GetMounts() {
			res.Mounts = append(res.Mounts, fimscan.Mount{Path: m.GetPath(), FSType: m.GetFsType()})
		}
	}
	b, err := fimbaseline.NewBaseline(res)
	if err != nil {
		t.Fatalf("test list: %v", err)
	}
	return b.Digest().String()
}

// baselineEnv is a service on a fresh executor database whose approved
// digest for web-1 is the digest of approvedList.
type baselineEnv struct {
	dir      string
	db       *executordb.DB
	svc      *Service
	log      *recordingHandler
	approved string
}

func newBaselineEnv(t *testing.T) *baselineEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, dir)
	h, b := approvedList()
	approved := digestOfChunks(t, h, b)
	if _, err := db.StoreApprovedBaselineDigest(executordb.BaselineDigest{
		HostID: "web-1", Digest: approved, Kind: executordb.BaselineApprovalInitial,
	}); err != nil {
		t.Fatal(err)
	}
	rh := &recordingHandler{}
	return &baselineEnv{dir: dir, db: db, svc: &Service{db: db, log: slog.New(rh)}, log: rh, approved: approved}
}

func (e *baselineEnv) stream(t *testing.T, roles []peercred.Role, chunks ...*pb.CompareBaselineListRequest) (*pb.CompareBaselineListResponse, error) {
	t.Helper()
	conn := integrityRPCConn(t, e.svc, roles...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := pb.NewExecutorServiceClient(conn).CompareBaselineList(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range chunks {
		if err := st.Send(c); err != nil {
			break // the server ended the stream; CloseAndRecv has its status
		}
	}
	return st.CloseAndRecv()
}

func (e *baselineEnv) requireApproved(t *testing.T) {
	t.Helper()
	got, err := e.db.ApprovedBaselineDigest("web-1")
	if err != nil || got.Digest != e.approved {
		t.Fatalf("approved digest = %q, %v; want %q", got.Digest, err, e.approved)
	}
}

func (e *baselineEnv) tamperFindings(t *testing.T) []executordb.BaselineTamperFinding {
	t.Helper()
	fs, err := e.db.BaselineTamperFindings()
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

var serverRole = []peercred.Role{peercred.RoleServer}

func TestBaselineListMatchesWhenUnchanged(t *testing.T) {
	e := newBaselineEnv(t)
	h, b := approvedList()
	// Reversed order: the executor sorts like the approval did.
	resp, err := e.stream(t, serverRole, h, b[1], b[0])
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetResult() != pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MATCH || resp.GetFindingKind() != "" {
		t.Fatalf("result = %v %q", resp.GetResult(), resp.GetFindingKind())
	}
	if resp.GetComputedDigest() != e.approved {
		t.Fatalf("computed = %s, want %s", resp.GetComputedDigest(), e.approved)
	}
	if fs := e.tamperFindings(t); len(fs) != 0 || containsKind(e.log.kinds(), "integrity_baseline_tamper") {
		t.Fatalf("match opened a finding: %v %v", fs, e.log.kinds())
	}
	e.requireApproved(t)
}

// TestRewrittenBaselineListIsTamper is the review's HIGH case: a server
// that rewrote its list cannot get MATCH, because it never sends a digest;
// the executor recomputes it from the list. Every field of an entry and
// every mount counts.
func TestRewrittenBaselineListIsTamper(t *testing.T) {
	rewrites := map[string]func(b []*pb.CompareBaselineListRequest){
		"content hash": func(b []*pb.CompareBaselineListRequest) { b[0].Entries[1].HashSum[0] ^= 1 },
		"mode":         func(b []*pb.CompareBaselineListRequest) { b[0].Entries[1].Mode = 0o4755 },
		"owner":        func(b []*pb.CompareBaselineListRequest) { b[1].Entries[0].Uid = 1000 },
		"link target":  func(b []*pb.CompareBaselineListRequest) { b[1].Entries[1].Link = []byte("/tmp/evil") },
		"secret flag":  func(b []*pb.CompareBaselineListRequest) { b[1].Entries[0].HashSecret = false },
		"mount fstype": func(b []*pb.CompareBaselineListRequest) { b[1].Mounts[0].FsType = "ext4" },
		"entry removed": func(b []*pb.CompareBaselineListRequest) {
			b[0].Entries = b[0].Entries[:1]
		},
	}
	for name, rewrite := range rewrites {
		t.Run(name, func(t *testing.T) {
			e := newBaselineEnv(t)
			h, b := approvedList()
			b = cloneChunks(b)
			rewrite(b)
			n := 0
			for _, c := range b {
				n += len(c.GetEntries())
			}
			h.Header.EntryCount = uint32(n)
			resp, err := e.stream(t, serverRole, append([]*pb.CompareBaselineListRequest{h}, b...)...)
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetResult() != pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MISMATCH ||
				resp.GetFindingKind() != "integrity.baseline_tamper" {
				t.Fatalf("result = %v %q", resp.GetResult(), resp.GetFindingKind())
			}
			if resp.GetComputedDigest() == e.approved || resp.GetComputedDigest() != digestOfChunks(t, h, b) {
				t.Fatalf("computed digest = %s", resp.GetComputedDigest())
			}
			fs := e.tamperFindings(t)
			if len(fs) != 1 || fs[0].HostID != "web-1" || fs[0].ApprovedDigest != e.approved ||
				fs[0].PresentedDigest != resp.GetComputedDigest() || fs[0].Count != 1 {
				t.Fatalf("findings = %+v", fs)
			}
			// No silent correction: the stored digest stays.
			e.requireApproved(t)
		})
	}
}

// TestBaselineTamperIsHeldAndShownByExecutor is the review's MEDIUM case:
// the finding lives in the executor, survives a restart, and the
// executor-local status shows it whatever the server does with the
// response.
func TestBaselineTamperIsHeldAndShownByExecutor(t *testing.T) {
	e := newBaselineEnv(t)
	h, b := approvedList()
	b = cloneChunks(b)
	b[0].Entries[1].Size++
	if _, err := e.stream(t, serverRole, append([]*pb.CompareBaselineListRequest{h}, b...)...); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, e.dir)
	svc := &Service{db: db, log: slog.New(&recordingHandler{})}
	st, err := svc.GetIntegrityStatus(context.Background(), &pb.GetIntegrityStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	fs := st.GetBaselineTamperFindings()
	if len(fs) != 1 || fs[0].GetHostId() != "web-1" || fs[0].GetApprovedDigest() != e.approved ||
		fs[0].GetPresentedDigest() != digestOfChunks(t, h, b) || fs[0].GetCount() != 1 || fs[0].GetFirstSeenUnix() == 0 {
		t.Fatalf("status findings = %v", fs)
	}
}

// TestBaselineTamperAuditIsRateLimited is the review's LOW case: repeated
// mismatches count in the finding but are audited once per interval.
func TestBaselineTamperAuditIsRateLimited(t *testing.T) {
	e := newBaselineEnv(t)
	h, b := approvedList()
	for i := 0; i < 5; i++ {
		bb := cloneChunks(b)
		bb[0].Entries[1].Mtime += int64(i + 1) // a new digest every time
		res, err := e.svc.compareBaselineList(h.GetHeader(), bb, "server:uid7")
		if err != nil || res.Result != BaselineTamper {
			t.Fatalf("compare %d = %+v, %v", i, res, err)
		}
	}
	e.log.mu.Lock()
	var tamper []slog.Record
	for _, r := range e.log.recs {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
		if attrs["kind"] == "integrity_baseline_tamper" {
			tamper = append(tamper, r)
			want := map[string]string{"finding": "integrity.baseline_tamper", "by": "server:uid7", "host": "web-1",
				"approved_digest": e.approved, "approval_kind": "initial", "count": "1"}
			for k, v := range want {
				if attrs[k] != v {
					t.Errorf("audit %s = %q, want %q", k, attrs[k], v)
				}
			}
			if !executordb.ValidBaselineDigest(attrs["computed_digest"]) || attrs["computed_digest"] == e.approved {
				t.Errorf("audit computed_digest = %q", attrs["computed_digest"])
			}
			if r.Level != slog.LevelWarn {
				t.Errorf("audit level = %v, want WARN", r.Level)
			}
		}
	}
	e.log.mu.Unlock()
	if len(tamper) != 1 {
		t.Fatalf("tamper audit records = %d, want 1", len(tamper))
	}
	if fs := e.tamperFindings(t); len(fs) != 1 || fs[0].Count != 5 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestBaselineListWithoutApprovedDigestIsNone(t *testing.T) {
	e := newBaselineEnv(t)
	h, b := approvedList()
	h.Header.HostId = "web-2"
	resp, err := e.stream(t, serverRole, append([]*pb.CompareBaselineListRequest{h}, b...)...)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetResult() != pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_NONE {
		t.Fatalf("result = %v", resp.GetResult())
	}
	if fs := e.tamperFindings(t); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
	if _, err := e.db.ApprovedBaselineDigest("web-2"); err != executordb.ErrNoBaselineDigest {
		t.Fatalf("web-2 gained a digest: %v", err)
	}
}

func TestBaselineListRejectsMalformedInput(t *testing.T) {
	type mut func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest
	all := func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
		return append([]*pb.CompareBaselineListRequest{h}, b...)
	}
	cases := map[string]mut{
		"no header": func(_ *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			return b
		},
		"empty stream": func(*pb.CompareBaselineListRequest, []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			return nil
		},
		"header twice": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[1].Header = h.Header
			return all(h, b)
		},
		"header with entries": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Entries = b[0].Entries
			h.Header.EntryCount += 2
			return all(h, b)
		},
		"empty chunk": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			return all(h, append(b, &pb.CompareBaselineListRequest{}))
		},
		"malformed host": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.HostId = "web-1\x1b[2J"
			return all(h, b)
		},
		"empty profile": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.ProfileId = ""
			return all(h, b)
		},
		"fewer entries than declared": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.EntryCount++
			return all(h, b)
		},
		"more entries than declared": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.EntryCount--
			return all(h, b)
		},
		"more mounts than declared": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.MountCount = 0
			return all(h, b)
		},
		"entry count above limit": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.EntryCount = fimbaseline.MaxEntries + 1
			return all(h, b)
		},
		"mount count above limit": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			h.Header.MountCount = fimbaseline.MaxMounts + 1
			return all(h, b)
		},
		"unspecified type": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].Type = pb.BaselineEntryType_BASELINE_ENTRY_TYPE_UNSPECIFIED
			return all(h, b)
		},
		"unknown type": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].Type = 99
			return all(h, b)
		},
		"unspecified hash kind": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].HashKind = pb.BaselineHashKind_BASELINE_HASH_KIND_UNSPECIFIED
			return all(h, b)
		},
		"short hash": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[1].HashSum = b[0].Entries[1].HashSum[:31]
			return all(h, b)
		},
		"hash on no-hash entry": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].HashSum = bytes.Repeat([]byte{1}, 32)
			return all(h, b)
		},
		"secret not keyed": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[1].Entries[0].HashKind = pb.BaselineHashKind_BASELINE_HASH_KIND_PLAIN
			return all(h, b)
		},
		"unhashed file": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[1].HashKind = pb.BaselineHashKind_BASELINE_HASH_KIND_NONE
			b[0].Entries[1].HashSum = nil
			return all(h, b)
		},
		"duplicate path": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[1].Path = []byte("/etc")
			b[0].Entries[1].Type = pb.BaselineEntryType_BASELINE_ENTRY_TYPE_DIR
			b[0].Entries[1].HashKind = pb.BaselineHashKind_BASELINE_HASH_KIND_NONE
			b[0].Entries[1].HashSum = nil
			return all(h, b)
		},
		"relative path": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].Path = []byte("etc")
			return all(h, b)
		},
		"path too long": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[0].Path = append([]byte("/"), bytes.Repeat([]byte("a"), fimscan.MaxPathBytes)...)
			return all(h, b)
		},
		"link on file": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[0].Entries[1].Link = []byte("/x")
			return all(h, b)
		},
		"empty fstype": func(h *pb.CompareBaselineListRequest, b []*pb.CompareBaselineListRequest) []*pb.CompareBaselineListRequest {
			b[1].Mounts[0].FsType = ""
			return all(h, b)
		},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			e := newBaselineEnv(t)
			h, b := approvedList()
			chunks := m(h, cloneChunks(b))
			_, err := e.stream(t, serverRole, chunks...)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if fs := e.tamperFindings(t); len(fs) != 0 {
				t.Fatalf("malformed list opened a finding: %+v", fs)
			}
			e.requireApproved(t)
		})
	}
}

// TestBaselineListByteBudget: the summed path, link and fstype bytes of
// one list are bounded, so a caller cannot make the executor buffer more
// than the document limit.
func TestBaselineListByteBudget(t *testing.T) {
	acc := newBaselineListAcc(&pb.CompareBaselineListHeader{HostId: "web-1", ProfileId: testProfile, EntryCount: 3}, 10)
	e := &pb.BaselineListEntry{Path: []byte("/abcd"), Type: pb.BaselineEntryType_BASELINE_ENTRY_TYPE_DIR,
		HashKind: pb.BaselineHashKind_BASELINE_HASH_KIND_NONE}
	if err := acc.add(&pb.CompareBaselineListRequest{Entries: []*pb.BaselineListEntry{e, e}}); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	if err := acc.add(&pb.CompareBaselineListRequest{Entries: []*pb.BaselineListEntry{e}}); err == nil {
		t.Fatal("budget exceeded without error")
	}
	if maxBaselineListBytes != fimscan.MaxDocumentBytes {
		t.Fatalf("maxBaselineListBytes = %d", maxBaselineListBytes)
	}
}

// TestBaselineListOneAtATime: a second comparison while one runs is
// refused instead of buffering a second list.
func TestBaselineListOneAtATime(t *testing.T) {
	e := newBaselineEnv(t)
	e.svc.baselineCompareMu.Lock()
	defer e.svc.baselineCompareMu.Unlock()
	h, b := approvedList()
	_, err := e.stream(t, serverRole, append([]*pb.CompareBaselineListRequest{h}, b...)...)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// TestBaselineDigestServerCannotWrite pins ADR 0015 D7: the server role
// may compare, and no executor method lets it set or approve a baseline
// digest or supply one.
func TestBaselineDigestServerCannotWrite(t *testing.T) {
	const serverUID, adminUID uint32 = 40001, 40002
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
	}, MethodRoles())
	cmp := pb.ExecutorService_CompareBaselineList_FullMethodName
	if _, ok := policy.Allowed(serverUID, cmp); !ok {
		t.Fatal("server may not compare baseline lists")
	}
	if _, ok := policy.Allowed(adminUID, cmp); !ok {
		t.Fatal("admin may not compare baseline lists")
	}
	for _, r := range []peercred.Role{peercred.RolePVECollector, peercred.RoleNetDevCollector} {
		if slicesContainsRole(MethodRoles()[cmp], r) {
			t.Errorf("%s may compare baseline lists", r)
		}
	}
	// The only baseline method on the service is the list comparison, and
	// its request has no digest field.
	for _, m := range allServiceMethods(t) {
		if strings.Contains(strings.ToLower(m), "baseline") && m != cmp {
			t.Errorf("unexpected baseline method %s", m)
		}
	}
	fields := (&pb.CompareBaselineListHeader{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		if strings.Contains(string(fields.Get(i).Name()), "digest") {
			t.Errorf("the comparison header takes a digest field %s", fields.Get(i).Name())
		}
	}

	e := newBaselineEnv(t)
	conn := integrityRPCConn(t, e.svc, peercred.RoleServer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, name := range []string{"SetBaselineDigest", "ApproveBaselineDigest", "StoreApprovedBaselineDigest", "ApproveIntegrityBaseline", "CompareBaselineDigest"} {
		method := "/" + pb.ExecutorService_ServiceDesc.ServiceName + "/" + name
		if _, ok := policy.Allowed(serverUID, method); ok {
			t.Errorf("policy lets the server call %s", name)
		}
		err := invokeEmpty(ctx, conn, method)
		if c := status.Code(err); c != codes.Unimplemented && c != codes.PermissionDenied {
			t.Errorf("server %s: err = %v, want Unimplemented or PermissionDenied", name, err)
		}
	}
	e.requireApproved(t)
}

func slicesContainsRole(rs []peercred.Role, r peercred.Role) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// TestBaselineListCompareIsNotLocked: the comparison is tamper evidence and
// stays available while the I1 lock is open.
func TestBaselineListCompareIsNotLocked(t *testing.T) {
	locked, known := integrityLockedMethods[pb.ExecutorService_CompareBaselineList_FullMethodName]
	if !known || locked {
		t.Fatalf("CompareBaselineList lock classification = %v, %v; want known and not locked", locked, known)
	}
}
