// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func baselineDigestOf(c byte) string { return strings.Repeat(string(c), 64) }

// baselineEnv is a service on a fresh executor database with an approved
// initial digest "a…" for host web-1.
type baselineEnv struct {
	dir string
	db  *executordb.DB
	svc *Service
	log *recordingHandler
}

func newBaselineEnv(t *testing.T) *baselineEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, dir)
	if _, err := db.StoreApprovedBaselineDigest(executordb.BaselineDigest{
		HostID: "web-1", Digest: baselineDigestOf('a'), Kind: executordb.BaselineApprovalInitial,
	}); err != nil {
		t.Fatal(err)
	}
	h := &recordingHandler{}
	return &baselineEnv{dir: dir, db: db, svc: &Service{db: db, log: slog.New(h)}, log: h}
}

func (e *baselineEnv) compare(t *testing.T, roles []peercred.Role, host, digest string) (*pb.CompareBaselineDigestResponse, error) {
	t.Helper()
	conn := integrityRPCConn(t, e.svc, roles...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pb.NewExecutorServiceClient(conn).CompareBaselineDigest(ctx, &pb.CompareBaselineDigestRequest{HostId: host, Digest: digest})
}

func (e *baselineEnv) requireApproved(t *testing.T, want string) {
	t.Helper()
	got, err := e.db.ApprovedBaselineDigest("web-1")
	if err != nil || got.Digest != want {
		t.Fatalf("approved digest = %q, %v; want %q", got.Digest, err, want)
	}
}

func TestBaselineDigestCompareResults(t *testing.T) {
	server := []peercred.Role{peercred.RoleServer}
	for _, tc := range []struct {
		name, host, digest string
		want               pb.BaselineDigestComparison
		finding            string
		audited            bool
	}{
		{"equal", "web-1", baselineDigestOf('a'), pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MATCH, "", false},
		{"different", "web-1", baselineDigestOf('b'), pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_MISMATCH, "integrity.baseline_tamper", true},
		{"no digest", "web-2", baselineDigestOf('a'), pb.BaselineDigestComparison_BASELINE_DIGEST_COMPARISON_NONE, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newBaselineEnv(t)
			resp, err := e.compare(t, server, tc.host, tc.digest)
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetResult() != tc.want || resp.GetFindingKind() != tc.finding {
				t.Fatalf("result = %v %q; want %v %q", resp.GetResult(), resp.GetFindingKind(), tc.want, tc.finding)
			}
			if got := containsKind(e.log.kinds(), "integrity_baseline_tamper"); got != tc.audited {
				t.Fatalf("tamper audited = %v, want %v (log %v)", got, tc.audited, e.log.kinds())
			}
			// A comparison never writes: the stored digest is unchanged,
			// in particular not replaced by a mismatching one.
			e.requireApproved(t, baselineDigestOf('a'))
			if _, err := e.db.ApprovedBaselineDigest("web-2"); err != executordb.ErrNoBaselineDigest {
				t.Fatalf("web-2 gained a digest: %v", err)
			}
		})
	}
}

// TestBaselineTamperIsAuditedWithBothDigests pins the audit record: who
// presented which digest for which host, against which approved digest.
func TestBaselineTamperIsAuditedWithBothDigests(t *testing.T) {
	e := newBaselineEnv(t)
	res, err := e.svc.CompareBaselineDigestLocal("web-1", baselineDigestOf('c'), "server:uid7")
	if err != nil || res != BaselineTamper {
		t.Fatalf("compare = %v, %v", res, err)
	}
	e.log.mu.Lock()
	defer e.log.mu.Unlock()
	if len(e.log.recs) != 1 {
		t.Fatalf("records = %d, want 1", len(e.log.recs))
	}
	attrs := map[string]string{}
	e.log.recs[0].Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
	want := map[string]string{
		"kind": "integrity_baseline_tamper", "finding": "integrity.baseline_tamper", "by": "server:uid7",
		"host": "web-1", "presented_digest": baselineDigestOf('c'), "approved_digest": baselineDigestOf('a'),
		"approval_kind": "initial",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("audit %s = %q, want %q", k, attrs[k], v)
		}
	}
	if e.log.recs[0].Level != slog.LevelWarn {
		t.Errorf("audit level = %v, want WARN", e.log.recs[0].Level)
	}
}

func TestBaselineDigestCompareRejectsMalformedInput(t *testing.T) {
	e := newBaselineEnv(t)
	for name, req := range map[string][2]string{
		"empty host":       {"", baselineDigestOf('a')},
		"host with escape": {"web-1\x1b[2J", baselineDigestOf('a')},
		"empty digest":     {"web-1", ""},
		"uppercase digest": {"web-1", baselineDigestOf('A')},
		"short digest":     {"web-1", "abcd"},
		"long digest":      {"web-1", baselineDigestOf('a') + "a"},
		"non-hex digest":   {"web-1", baselineDigestOf('g')},
	} {
		_, err := e.compare(t, []peercred.Role{peercred.RoleServer}, req[0], req[1])
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
	if containsKind(e.log.kinds(), "integrity_baseline_tamper") {
		t.Fatal("malformed input was audited as tamper")
	}
	e.requireApproved(t, baselineDigestOf('a'))
}

// TestBaselineDigestServerCannotWrite pins ADR 0015 D7 item 2: the
// server role may compare, and no executor method lets it set or approve
// a baseline digest. A call to a write method name is refused by the
// peer-credential policy and leaves the stored digest unchanged.
func TestBaselineDigestServerCannotWrite(t *testing.T) {
	const serverUID, adminUID uint32 = 40001, 40002
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
	}, MethodRoles())
	cmp := pb.ExecutorService_CompareBaselineDigest_FullMethodName
	if _, ok := policy.Allowed(serverUID, cmp); !ok {
		t.Fatal("server may not compare baseline digests")
	}
	if _, ok := policy.Allowed(adminUID, cmp); !ok {
		t.Fatal("admin may not compare baseline digests")
	}
	for _, r := range []peercred.Role{peercred.RolePVECollector, peercred.RoleNetDevCollector} {
		if slicesContainsRole(MethodRoles()[cmp], r) {
			t.Errorf("%s may compare baseline digests", r)
		}
	}
	// The only baseline-digest method on the service is the comparison.
	for _, m := range pb.ExecutorService_ServiceDesc.Methods {
		if strings.Contains(m.MethodName, "BaselineDigest") && m.MethodName != "CompareBaselineDigest" {
			t.Errorf("unexpected baseline digest method %s", m.MethodName)
		}
	}

	e := newBaselineEnv(t)
	conn := integrityRPCConn(t, e.svc, peercred.RoleServer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, name := range []string{"SetBaselineDigest", "ApproveBaselineDigest", "StoreApprovedBaselineDigest", "ApproveIntegrityBaseline"} {
		method := "/" + pb.ExecutorService_ServiceDesc.ServiceName + "/" + name
		if _, ok := policy.Allowed(serverUID, method); ok {
			t.Errorf("policy lets the server call %s", name)
		}
		// gRPC refuses a method the service does not have before any
		// interceptor runs (Unimplemented); the policy would refuse it
		// otherwise (PermissionDenied). Either way nothing is written.
		err := invokeEmpty(ctx, conn, method)
		if c := status.Code(err); c != codes.Unimplemented && c != codes.PermissionDenied {
			t.Errorf("server %s: err = %v, want Unimplemented or PermissionDenied", name, err)
		}
	}
	e.requireApproved(t, baselineDigestOf('a'))
}

func slicesContainsRole(rs []peercred.Role, r peercred.Role) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// TestBaselineDigestSurvivesExecutorRestart: a restarted executor still
// holds the approved digest and still reports a rewritten list.
func TestBaselineDigestSurvivesExecutorRestart(t *testing.T) {
	e := newBaselineEnv(t)
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, e.dir)
	h := &recordingHandler{}
	svc := &Service{db: db, log: slog.New(h)}
	for digest, want := range map[string]BaselineComparison{
		baselineDigestOf('a'): BaselineMatch,
		baselineDigestOf('d'): BaselineTamper,
	} {
		got, err := svc.CompareBaselineDigestLocal("web-1", digest, "server:uid1")
		if err != nil || got != want {
			t.Fatalf("after restart compare %c… = %v, %v; want %v", digest[0], got, err, want)
		}
	}
	if !containsKind(h.kinds(), "integrity_baseline_tamper") {
		t.Fatal("tamper after restart not audited")
	}
}

// TestBaselineDigestCompareIsNotLocked: the comparison is tamper
// evidence and stays available while the I1 lock is open.
func TestBaselineDigestCompareIsNotLocked(t *testing.T) {
	locked, known := integrityLockedMethods[pb.ExecutorService_CompareBaselineDigest_FullMethodName]
	if !known || locked {
		t.Fatalf("CompareBaselineDigest lock classification = %v, %v; want known and not locked", locked, known)
	}
}
