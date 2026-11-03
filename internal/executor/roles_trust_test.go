// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

const (
	trustTestServerUID = 101
	trustTestAdminUID  = 0
	trustTestDigest    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// fakeBuiltinTrust records calls and returns canned results.
type fakeBuiltinTrust struct {
	review    trust.BulkAdmitResult
	reviewErr error
	commit    trust.BulkAdmitResult
	commitGen int64
	commitErr error

	reviews  int
	statuses int
	commits  []fakeCommit
}

type fakeCommit struct {
	digest  string
	pins    map[string]bool
	retired []string
	uid     int
}

func (f *fakeBuiltinTrust) Review(context.Context) (trust.BulkAdmitResult, error) {
	f.reviews++
	return f.review, f.reviewErr
}

func (f *fakeBuiltinTrust) Status(context.Context) (trust.BulkAdmitResult, error) {
	f.statuses++
	return f.review, f.reviewErr
}

func (f *fakeBuiltinTrust) Commit(_ context.Context, digest string, pins map[string]bool, retired []string, uid int) (trust.BulkAdmitResult, int64, error) {
	f.commits = append(f.commits, fakeCommit{digest: digest, pins: pins, retired: retired, uid: uid})
	return f.commit, f.commitGen, f.commitErr
}

// trustPolicy maps one UID to each role.
func trustPolicy() *peercred.Policy {
	return peercred.NewPolicy(map[uint32][]peercred.Role{
		trustTestServerUID: {peercred.RoleServer},
		trustTestAdminUID:  {peercred.RoleAdmin},
		102:                {peercred.RolePVECollector},
	}, MethodRoles())
}

// callAs runs h through the real peercred interceptor as uid, so the
// handler sees exactly the caller a socket peer would produce.
func callAs[Req, Resp any](t *testing.T, uid uint32, method string, req Req, h func(context.Context, Req) (Resp, error)) (Resp, error) {
	t.Helper()
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
	var zero Resp
	out, err := trustPolicy().UnaryInterceptor(nil)(ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, r any) (any, error) { return h(ctx, r.(Req)) })
	if err != nil {
		return zero, err
	}
	return out.(Resp), nil
}

func sampleReview() trust.BulkAdmitResult {
	return trust.BulkAdmitResult{
		Review: trust.Review{
			ManifestDigest: trustTestDigest, ReleaseVersion: "2026.11.0", RootID: "root-1", RootFingerprint: "SHA256:x", Generation: 7,
			Modules: []trust.ModuleReview{
				{Name: "core", Status: trust.StatusUnchanged, OldVersion: "1.0.0", OldSHA256: "o1", NewVersion: "1.0.0", NewSHA256: "o1"},
				{Name: "docker", Status: trust.StatusChanged, OldVersion: "1.0.0", OldSHA256: "d1", NewVersion: "1.1.0", NewSHA256: "d2",
					Actions: []trust.ActionReview{{
						ActionID: "docker.restart", Status: trust.StatusChanged, OldRisk: "LOW", NewRisk: "MEDIUM",
						OldScriptSHA256: "s1", NewScriptSHA256: "s2",
						Diff: []textdiff.Line{{Op: textdiff.Equal, Text: "#!/bin/sh"}, {Op: textdiff.Delete, Text: "echo old"}, {Op: textdiff.Insert, Text: "echo \xff new"}},
					}}},
				{Name: "gone", Status: trust.StatusRemoved, OldVersion: "0.9.0", OldSHA256: "g1"},
			},
		},
		Scans: []trust.ScanFinding{{Module: "docker", ActionID: "docker.restart", Floor: "HIGH",
			Findings: []scanner.Finding{{Category: "network", Risk: canonical.RiskHigh, Line: 3, Excerpt: `"curl"`}}}},
		ManifestDigest:    trustTestDigest,
		NeedsConfirmation: true,
		OldVersions:       []string{"docker@1.0.0", "gone@0.9.0"},
	}
}

// Review and commit are local-admin only; the server may only read status.
// No other role reaches the built-in trust surface.
func TestBuiltinTrustMethodRoles(t *testing.T) {
	methods := map[string][]peercred.Role{
		pb.ExecutorService_ReviewBuiltinTrust_FullMethodName:    {peercred.RoleAdmin},
		pb.ExecutorService_CommitBuiltinTrust_FullMethodName:    {peercred.RoleAdmin},
		pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName: {peercred.RoleServer, peercred.RoleAdmin},
	}
	roles := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector, peercred.Role("discovery")}
	uids := map[uint32][]peercred.Role{}
	for i, r := range roles {
		uids[uint32(i+1)] = []peercred.Role{r}
	}
	policy := peercred.NewPolicy(uids, MethodRoles())
	for method, want := range methods {
		t.Run(method, func(t *testing.T) {
			if got := MethodRoles()[method]; len(got) != len(want) {
				t.Errorf("roles = %v, want %v", got, want)
			}
			for i, role := range roles {
				allowed := false
				for _, r := range want {
					allowed = allowed || r == role
				}
				if _, ok := policy.Allowed(uint32(i+1), method); ok != allowed {
					t.Errorf("role %s allowed=%v, want %v", role, ok, allowed)
				}
			}
			if _, ok := policy.Allowed(999, method); ok {
				t.Error("unknown UID allowed")
			}
		})
	}
}

// The server reaches no built-in trust method other than the read-only
// status: no server bulk trust, whatever a future method is called.
func TestServerHasNoBuiltinTrustMutation(t *testing.T) {
	for method, roles := range MethodRoles() {
		if !strings.Contains(method, "Builtin") {
			continue
		}
		for _, r := range roles {
			if r == peercred.RoleServer && method != pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName {
				t.Errorf("server may call %s", method)
			}
		}
	}
}

// Through the real interceptor, the server is denied review and commit and
// the trust transaction is never touched.
func TestServerCannotReviewOrCommitBuiltinTrust(t *testing.T) {
	f := &fakeBuiltinTrust{review: sampleReview()}
	s := &Service{}
	s.SetBuiltinTrust(f)
	_, err := callAs(t, trustTestServerUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server review: %v, want PermissionDenied", err)
	}
	_, err = callAs(t, trustTestServerUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName,
		&pb.CommitBuiltinTrustRequest{ManifestDigest: trustTestDigest, Retire: []string{"docker@1.0.0"}}, s.CommitBuiltinTrust)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server commit: %v, want PermissionDenied", err)
	}
	if f.reviews != 0 || f.statuses != 0 || len(f.commits) != 0 {
		t.Fatalf("trust transaction touched: reviews=%d statuses=%d commits=%d", f.reviews, f.statuses, len(f.commits))
	}
}

// Defense in depth: even if the role table were widened, the handlers
// themselves refuse a caller that is not the local admin, and a call
// without peer credentials.
func TestBuiltinTrustHandlersRequireAdminCaller(t *testing.T) {
	f := &fakeBuiltinTrust{review: sampleReview()}
	s := &Service{}
	s.SetBuiltinTrust(f)
	if _, err := s.ReviewBuiltinTrust(context.Background(), &pb.ReviewBuiltinTrustRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("review without caller: %v, want Unauthenticated", err)
	}
	req := &pb.CommitBuiltinTrustRequest{ManifestDigest: trustTestDigest}
	if _, err := s.CommitBuiltinTrust(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("commit without caller: %v, want Unauthenticated", err)
	}
	// A widened table: the server role is admitted by the interceptor.
	wide := MethodRoles()
	wide[pb.ExecutorService_CommitBuiltinTrust_FullMethodName] = []peercred.Role{peercred.RoleServer}
	wide[pb.ExecutorService_ReviewBuiltinTrust_FullMethodName] = []peercred.Role{peercred.RoleServer}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{trustTestServerUID: {peercred.RoleServer}}, wide)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: trustTestServerUID}})
	for _, m := range []string{pb.ExecutorService_CommitBuiltinTrust_FullMethodName, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName} {
		_, err := policy.UnaryInterceptor(nil)(ctx, req, &grpc.UnaryServerInfo{FullMethod: m}, func(ctx context.Context, _ any) (any, error) {
			if m == pb.ExecutorService_CommitBuiltinTrust_FullMethodName {
				return s.CommitBuiltinTrust(ctx, req)
			}
			return s.ReviewBuiltinTrust(ctx, &pb.ReviewBuiltinTrustRequest{})
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s as server: %v, want PermissionDenied", m, err)
		}
	}
	if f.reviews != 0 || f.statuses != 0 || len(f.commits) != 0 {
		t.Fatalf("trust transaction touched: reviews=%d statuses=%d commits=%d", f.reviews, f.statuses, len(f.commits))
	}
}

// Without a configured trust transaction, review and commit are
// Unimplemented and status reports UNAVAILABLE (distinct from untrusted).
func TestBuiltinTrustUnconfigured(t *testing.T) {
	s := &Service{}
	_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("review: %v, want Unimplemented", err)
	}
	_, err = callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName,
		&pb.CommitBuiltinTrustRequest{ManifestDigest: trustTestDigest}, s.CommitBuiltinTrust)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("commit: %v, want Unimplemented", err)
	}
	st, err := callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName, &pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE {
		t.Fatalf("state = %v, want UNAVAILABLE", st.State)
	}
}

// The admin review carries the complete review: versions, hashes, risks, the
// full diff (invalid UTF-8 escaped losslessly), scanner findings and the old
// versions to decide.
func TestAdminReviewBuiltinTrustIsComplete(t *testing.T) {
	f := &fakeBuiltinTrust{review: sampleReview()}
	s := &Service{}
	s.SetBuiltinTrust(f)
	out, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if err != nil {
		t.Fatal(err)
	}
	if out.ManifestDigest != trustTestDigest || out.Generation != 7 || !out.NeedsConfirmation || out.RootId != "root-1" || out.ReleaseVersion != "2026.11.0" {
		t.Fatalf("header = %+v", out)
	}
	if len(out.Modules) != 3 || len(out.OldVersions) != 2 {
		t.Fatalf("modules=%d old=%v", len(out.Modules), out.OldVersions)
	}
	d := out.Modules[1]
	if d.Change != pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED || d.OldVersion != "1.0.0" || d.NewVersion != "1.1.0" {
		t.Fatalf("docker module = %+v", d)
	}
	if out.Modules[2].Change != pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED {
		t.Fatalf("removed module = %+v", out.Modules[2])
	}
	a := d.Actions[0]
	if a.NewRisk != "MEDIUM" || a.ScannerFloor != pb.RiskClass_RISK_CLASS_HIGH || len(a.Findings) != 1 || a.Findings[0].Category != "network" {
		t.Fatalf("action = %+v", a)
	}
	if len(a.Diff) != 3 || a.Diff[1].Op != pb.BuiltinDiffOp_BUILTIN_DIFF_OP_DELETE || a.Diff[2].Op != pb.BuiltinDiffOp_BUILTIN_DIFF_OP_INSERT {
		t.Fatalf("diff = %+v", a.Diff)
	}
	if a.Diff[0].Escaped || !a.Diff[2].Escaped || a.Diff[2].Text != `"echo \xff new"` {
		t.Fatalf("escaping: %+v", a.Diff)
	}
	if _, err := proto.Marshal(out); err != nil {
		t.Fatalf("response does not marshal: %v", err)
	}
}

// The commit is bound to the confirmed digest and the retain/retire
// decisions, and the admin UID comes from peer credentials only.
func TestAdminCommitBuiltinTrustUsesPeerUID(t *testing.T) {
	f := &fakeBuiltinTrust{commitGen: 8, commit: trust.BulkAdmitResult{
		ManifestDigest: trustTestDigest, Committed: true, AdminUID: trustTestAdminUID,
		Pinned: []string{"docker@1.0.0"}, Retired: []string{"gone@0.9.0"}, Collected: []string{"old@0.1.0"}, CleanupFailures: 1,
		Tuples: []trust.TrustTuple{{Module: "docker", OldVersion: "1.0.0", OldSHA256: "d1", NewVersion: "1.1.0", NewSHA256: "d2", Status: string(trust.StatusChanged)}},
	}}
	s := &Service{}
	s.SetBuiltinTrust(f)
	req := &pb.CommitBuiltinTrustRequest{ManifestDigest: trustTestDigest, Retain: []string{"docker@1.0.0"}, Retire: []string{"gone@0.9.0"}}
	out, err := callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName, req, s.CommitBuiltinTrust)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commits) != 1 {
		t.Fatalf("commits = %d", len(f.commits))
	}
	c := f.commits[0]
	if c.digest != trustTestDigest || !c.pins["docker@1.0.0"] || len(c.pins) != 1 || len(c.retired) != 1 || c.retired[0] != "gone@0.9.0" || c.uid != trustTestAdminUID {
		t.Fatalf("commit call = %+v", c)
	}
	if out.Generation != 8 || out.AdminUid != trustTestAdminUID || out.CleanupFailures != 1 || len(out.Tuples) != 1 ||
		out.Tuples[0].Change != pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED || out.Retained[0] != "docker@1.0.0" || out.Retired[0] != "gone@0.9.0" {
		t.Fatalf("commit response = %+v", out)
	}
}

// Malformed and oversize commit requests are rejected before the trust
// transaction is touched.
func TestCommitBuiltinTrustRejectsMalformedRequests(t *testing.T) {
	many := make([]string, maxBuiltinTrustDecisions+1)
	for i := range many {
		many[i] = fmt.Sprintf("m%d@1.0.0", i)
	}
	cases := map[string]*pb.CommitBuiltinTrustRequest{
		"empty digest":       {},
		"short digest":       {ManifestDigest: "abc"},
		"uppercase digest":   {ManifestDigest: strings.ToUpper(trustTestDigest)},
		"too many retained":  {ManifestDigest: trustTestDigest, Retain: many},
		"too many retired":   {ManifestDigest: trustTestDigest, Retire: many},
		"no at sign":         {ManifestDigest: trustTestDigest, Retain: []string{"docker"}},
		"empty name":         {ManifestDigest: trustTestDigest, Retain: []string{"@1.0.0"}},
		"empty version":      {ManifestDigest: trustTestDigest, Retire: []string{"docker@"}},
		"invalid utf8":       {ManifestDigest: trustTestDigest, Retire: []string{"dock\xffer@1.0.0"}},
		"oversize entry":     {ManifestDigest: trustTestDigest, Retire: []string{strings.Repeat("a", maxBuiltinVersionRefBytes) + "@1"}},
		"duplicate retained": {ManifestDigest: trustTestDigest, Retain: []string{"docker@1.0.0", "docker@1.0.0"}},
		"retained+retired":   {ManifestDigest: trustTestDigest, Retain: []string{"docker@1.0.0"}, Retire: []string{"docker@1.0.0"}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeBuiltinTrust{}
			s := &Service{}
			s.SetBuiltinTrust(f)
			_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName, req, s.CommitBuiltinTrust)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if len(f.commits) != 0 {
				t.Fatal("trust transaction touched")
			}
		})
	}
}

// Trust store errors map to stable codes; a stale review or substituted
// bytes never commit.
func TestBuiltinTrustErrorMapping(t *testing.T) {
	cases := map[string]struct {
		err  error
		code codes.Code
	}{
		"stale":        {fmt.Errorf("x: %w", trust.ErrStale), codes.Aborted},
		"substitution": {fmt.Errorf("x: %w", trust.ErrSubstitution), codes.FailedPrecondition},
		"quota":        {fmt.Errorf("x: %w", trust.ErrQuota), codes.ResourceExhausted},
		"corrupt":      {fmt.Errorf("x: %w", trust.ErrCorrupt), codes.FailedPrecondition},
		"missing":      {trust.ErrStateMissing, codes.FailedPrecondition},
		"unavailable":  {fmt.Errorf("x: %w", ErrBuiltinTrustUnavailable), codes.FailedPrecondition},
		"decision":     {errors.New("old version docker@1.0.0 is neither retained nor retired"), codes.FailedPrecondition},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeBuiltinTrust{reviewErr: tc.err, commitErr: tc.err}
			s := &Service{}
			s.SetBuiltinTrust(f)
			_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
			if status.Code(err) != tc.code {
				t.Fatalf("review err = %v, want %v", err, tc.code)
			}
			_, err = callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName,
				&pb.CommitBuiltinTrustRequest{ManifestDigest: trustTestDigest}, s.CommitBuiltinTrust)
			if status.Code(err) != tc.code {
				t.Fatalf("commit err = %v, want %v", err, tc.code)
			}
		})
	}
}

// The server's status is metadata only: versions and hashes per module, no
// diffs, scripts, scanner excerpts or old-version decisions; it never
// commits.
func TestServerBuiltinTrustStatusIsReadOnlyMetadata(t *testing.T) {
	f := &fakeBuiltinTrust{review: sampleReview()}
	s := &Service{}
	s.SetBuiltinTrust(f)
	out, err := callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName, &pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commits) != 0 {
		t.Fatal("status committed")
	}
	if out.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED || out.ManifestDigest != trustTestDigest || out.Generation != 7 || out.ReleaseVersion != "2026.11.0" {
		t.Fatalf("status = %+v", out)
	}
	if len(out.Modules) != 3 {
		t.Fatalf("modules = %+v", out.Modules)
	}
	d := out.Modules[1]
	if d.Name != "docker" || d.Change != pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED || d.TrustedVersion != "1.0.0" || d.TrustedSha256 != "d1" || d.ReleaseVersion != "1.1.0" || d.ReleaseSha256 != "d2" {
		t.Fatalf("docker entry = %+v", d)
	}
	raw, err := proto.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"echo old", "curl", "docker.restart", "network"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("status leaks %q", leak)
		}
	}

	// All unchanged: TRUSTED.
	r := sampleReview()
	r.NeedsConfirmation = false
	f.review = r
	out, err = callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName, &pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil || out.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED {
		t.Fatalf("status = %+v, %v; want TRUSTED", out, err)
	}
}

// A failing review gives the server UNAVAILABLE without error details: no
// paths or store internals reach the server.
func TestServerBuiltinTrustStatusHidesErrors(t *testing.T) {
	f := &fakeBuiltinTrust{reviewErr: fmt.Errorf("read bundle /secret/path: %w", ErrBuiltinTrustUnavailable)}
	s := &Service{}
	s.SetBuiltinTrust(f)
	out, err := callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName, &pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE || len(out.Modules) != 0 || out.ManifestDigest != "" {
		t.Fatalf("status = %+v", out)
	}
	raw, _ := proto.Marshal(out)
	if strings.Contains(string(raw), "/secret/path") {
		t.Fatal("status leaks the error")
	}
}

// An oversize review is refused rather than truncated.
func TestReviewBuiltinTrustRefusesOversizeResponse(t *testing.T) {
	r := sampleReview()
	big := strings.Repeat("x", 1<<20)
	lines := make([]textdiff.Line, MaxResponseSize/(1<<20)+1)
	for i := range lines {
		lines[i] = textdiff.Line{Op: textdiff.Insert, Text: big}
	}
	r.Review.Modules[1].Actions[0].Diff = lines
	f := &fakeBuiltinTrust{review: r}
	s := &Service{}
	s.SetBuiltinTrust(f)
	_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
}

// The directory-backed transaction reports a missing local release bundle
// as unavailable and never bootstraps from a server-supplied path.
func TestDirBuiltinTrustMissingBundleIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	anchors, err := release.Anchors()
	if err != nil {
		t.Fatal(err)
	}
	bt, err := NewDirBuiltinTrust(filepath.Join(dir, "trust"), filepath.Join(dir, "no-such-bundle"), anchors, func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	// The executor bootstrapped the store at construction.
	if _, err := os.Stat(filepath.Join(dir, "trust", "index.json")); err != nil {
		t.Fatalf("store not bootstrapped at construction: %v", err)
	}
	if _, err := bt.Review(context.Background()); !errors.Is(err, ErrBuiltinTrustUnavailable) {
		t.Fatalf("review err = %v, want ErrBuiltinTrustUnavailable", err)
	}
	if _, _, err := bt.Commit(context.Background(), trustTestDigest, nil, nil, 0); !errors.Is(err, ErrBuiltinTrustUnavailable) {
		t.Fatalf("commit err = %v, want ErrBuiltinTrustUnavailable", err)
	}
	// Nothing was created for the missing bundle beyond the private store.
	if _, err := os.Stat(filepath.Join(dir, "no-such-bundle")); !os.IsNotExist(err) {
		t.Fatalf("bundle dir created: %v", err)
	}
}

// Relative or empty directories are refused at construction.
func TestNewDirBuiltinTrustRejectsBadDirs(t *testing.T) {
	abs := t.TempDir()
	for name, dirs := range map[string][2]string{
		"empty store":     {"", abs},
		"empty bundle":    {abs, ""},
		"relative store":  {"trust", abs},
		"relative bundle": {abs, "bundle"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDirBuiltinTrust(dirs[0], dirs[1], nil, nil); err == nil {
				t.Fatal("want error")
			}
		})
	}
}
