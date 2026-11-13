// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

var (
	testRawDigestA = strings.Repeat("a1", 32)
	testRawDigestB = strings.Repeat("b2", 32)
)

// netDevBaselineEnv is an approval-capable service over a netdev test env
// with the audit log captured.
type netDevBaselineEnv struct {
	e    *netDevTestEnv
	svc  *Service
	logs *syncBuffer
	dev  executordb.NetDevice
}

// testRawDigestUnverified is a raw_digest the test verifier never
// confirms as executor-computed.
var testRawDigestUnverified = strings.Repeat("c3", 32)

// testBaselineVerifier stands in for the ND-14 executor-computed digest
// check: it confirms every digest except testRawDigestUnverified.
func testBaselineVerifier(_ context.Context, _ string, _ int64, raw string) error {
	if raw == testRawDigestUnverified {
		return errors.New("digest not computed by the executor")
	}
	return nil
}

func newNetDevBaselineEnv(t *testing.T) *netDevBaselineEnv {
	t.Helper()
	return newNetDevBaselineEnvFor(t, "core-sw")
}

func newNetDevBaselineEnvFor(t *testing.T, deviceID string) *netDevBaselineEnv {
	t.Helper()
	e := newNetDevTestEnv(t)
	svc := newReconcileEnv(t).svc
	logs := &syncBuffer{}
	svc.db, svc.vault, svc.log = e.db, e.vault, slog.New(slog.NewJSONHandler(logs, nil))
	svc.netDevBaselineDigest = testBaselineVerifier
	dev := registerTestNetDev(t, e, deviceID, "10.20.0.2", testNetDevPin)
	return &netDevBaselineEnv{e: e, svc: svc, logs: logs, dev: dev}
}

// auditEvents returns the netdev_admin audit records of the given action.
func (b *netDevBaselineEnv) auditEvents(action string) []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(b.logs.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec["msg"] != "audit" || rec["kind"] != "netdev_admin" {
			continue
		}
		if rec["action"] == action {
			out = append(out, rec)
		}
	}
	return out
}

// propose proposes a baseline and returns the permit digest.
func (b *netDevBaselineEnv) propose(t *testing.T, version int64, raw string) *pb.ProposeExecutionResponse {
	t.Helper()
	p, err := b.svc.ProposeNetDeviceBaseline(context.Background(), b.dev.ID, version, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (b *netDevBaselineEnv) approve(t *testing.T, digest string) {
	t.Helper()
	d, err := canonical.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.svc.auth.ApproveCLI(d, 0, "personal-admin"); err != nil {
		t.Fatal(err)
	}
}

// commitApproved proposes, approves and commits a baseline.
func (b *netDevBaselineEnv) commitApproved(t *testing.T, version int64, raw string) NetDevBaseline {
	t.Helper()
	p := b.propose(t, version, raw)
	b.approve(t, p.ExecutionDigest)
	out, err := b.svc.CommitNetDeviceBaseline(context.Background(), b.dev.ID, version, raw, p.ExecutionDigest)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireNoBaseline(t *testing.T, svc *Service, id string) {
	t.Helper()
	if b, ok, err := svc.GetNetDeviceBaseline(context.Background(), id); err != nil || ok {
		t.Fatalf("baseline present without approval: %v %v %v", b, ok, err)
	}
}

func TestNetDevBaselineRequiresExactSingleUseApproval(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	svc, ctx, id := env.svc, context.Background(), env.dev.ID

	// The server cannot set a baseline without a permit, with a made-up
	// digest or with a malformed one.
	for name, digest := range map[string]string{"empty": "", "unknown": strings.Repeat("0", 64), "malformed": "XYZ"} {
		if _, err := svc.CommitNetDeviceBaseline(ctx, id, 7, testRawDigestA, digest); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s permit: approval bypass: %v", name, err)
		}
	}
	requireNoBaseline(t, svc, id)

	p := env.propose(t, 7, testRawDigestA)
	if p.RiskClass != pb.RiskClass_RISK_CLASS_MEDIUM && p.RiskClass != pb.RiskClass_RISK_CLASS_HIGH && p.RiskClass != pb.RiskClass_RISK_CLASS_CRITICAL {
		t.Fatalf("baseline permit risk %v, want at least MEDIUM", p.RiskClass)
	}
	requireNoBaseline(t, svc, id)
	if _, err := svc.CommitNetDeviceBaseline(ctx, id, 7, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pending permit accepted: %v", err)
	}
	env.approve(t, p.ExecutionDigest)

	// The approved permit covers exactly the proposed version and digest.
	if _, err := svc.CommitNetDeviceBaseline(ctx, id, 8, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("other version accepted: %v", err)
	}
	if _, err := svc.CommitNetDeviceBaseline(ctx, id, 7, testRawDigestB, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("other digest accepted: %v", err)
	}
	b, err := svc.netDevAdmin().BaselineBinding(ctx, id, 7, testRawDigestA)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*NetDevBaselineBinding){
		"device":            func(b *NetDevBaselineBinding) { b.DeviceID = "other-sw" },
		"pin":               func(b *NetDevBaselineBinding) { b.Pin = testNetDevPin2 },
		"generation":        func(b *NetDevBaselineBinding) { b.TrustGeneration++ },
		"previous digest":   func(b *NetDevBaselineBinding) { b.PreviousRawDigest = testRawDigestB },
		"previous revision": func(b *NetDevBaselineBinding) { b.PreviousRevision++ },
	} {
		c := b
		change(&c)
		if err := svc.authorizeNetDevBaseline(ctx, c, p.ExecutionDigest); err == nil {
			t.Errorf("%s: approval accepted a changed binding", name)
		}
	}
	requireNoBaseline(t, svc, id)

	got, err := svc.CommitNetDeviceBaseline(ctx, id, 7, testRawDigestA, p.ExecutionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if got.VersionID != 7 || got.RawDigest != testRawDigestA || got.Revision != 1 || got.ExecutionDigest != p.ExecutionDigest || got.TrustGeneration != env.dev.TrustGeneration {
		t.Fatalf("committed baseline %+v", got)
	}
	if _, err := svc.CommitNetDeviceBaseline(ctx, id, 7, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("approval replay accepted: %v", err)
	}
	read, ok, err := svc.GetNetDeviceBaseline(ctx, id)
	if err != nil || !ok || read != got {
		t.Fatalf("read baseline %+v %v %v, want %+v", read, ok, err, got)
	}
}

func TestNetDevBaselineGenericProposalCannotCreatePermit(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	b, err := env.svc.netDevAdmin().BaselineBinding(context.Background(), env.dev.ID, 7, testRawDigestA)
	if err != nil {
		t.Fatal(err)
	}
	params, target, err := b.params()
	if err != nil {
		t.Fatal(err)
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	rq := canonical.Request{ExecutionID: id, ActionID: netDevBaselineAction, ModuleVersion: netDevBaselineVersion,
		ArtifactSHA256: sha256Hex(netDevBaselineArtifact), ParametersHash: ph, CredentialRefs: []string{netDevBaselineRef(b.DeviceID)},
		RiskClass: canonical.RiskMedium, StagePlanHash: stagePlanNetDevBaseline,
		ExpiryUnix: env.svc.clock().Add(netDevBaselineLifetime).Unix(), ResolvedTargets: []canonical.Target{target}}
	if _, err := env.svc.ProposeExecution(context.Background(), &pb.ProposeExecutionRequest{Request: toProto(rq), ParametersJson: params}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("server proposed a baseline permit through ProposeExecution: %v", err)
	}
}

func TestNetDevBaselineApprovalIsAudited(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	ctx := context.Background()
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, strings.Repeat("0", 64)); err == nil {
		t.Fatal("approval bypass")
	}
	got := env.commitApproved(t, 7, testRawDigestA)

	var approved, refused int
	for line := range strings.SplitSeq(strings.TrimSpace(env.logs.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec["msg"] != "audit" || rec["kind"] != "netdev_admin" {
			continue
		}
		switch rec["action"] {
		case "baseline_refused":
			refused++
			if rec["device"] != env.dev.ID {
				t.Errorf("refusal event %v", rec)
			}
		case "baseline_approved":
			approved++
			if rec["device"] != env.dev.ID || rec["version_id"] != float64(7) || rec["raw_digest"] != testRawDigestA ||
				rec["execution_digest"] != got.ExecutionDigest || rec["previous_raw_digest"] != "" || rec["revision"] != float64(1) || rec["by"] == "" {
				t.Errorf("approval event %v", rec)
			}
		}
	}
	if approved != 1 || refused != 1 {
		t.Fatalf("audit events: %d approved, %d refused; log:\n%s", approved, refused, env.logs.String())
	}
}

func TestNetDevBaselineSurvivesRestart(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	want := env.commitApproved(t, 7, testRawDigestA)

	// A fresh process: the old one is gone (vault locked, database
	// closed); new database handle, new vault, unlocked again.
	env.e.vault.Lock()
	if err := env.e.db.Close(); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, env.e.dir)
	v := vault.New(db)
	v.SetMinParams(testVaultParams)
	if err := v.Unlock([]byte(strings.Repeat("correct-horse-battery-staple-", 4))); err != nil {
		t.Fatal(err)
	}
	restarted := &Service{db: db, vault: v}
	got, ok, err := restarted.GetNetDeviceBaseline(context.Background(), env.dev.ID)
	if err != nil || !ok || got != want {
		t.Fatalf("after restart %+v %v %v, want %+v", got, ok, err, want)
	}
	// Without a permit authority the restarted executor still refuses.
	if _, err := restarted.CommitNetDeviceBaseline(context.Background(), env.dev.ID, 8, testRawDigestB, want.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restarted executor set a baseline without approval: %v", err)
	}
}

func TestNetDevBaselineStalePermitCannotReplaceNewer(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	ctx := context.Background()
	stale := env.propose(t, 7, testRawDigestA)
	env.approve(t, stale.ExecutionDigest)
	newer := env.commitApproved(t, 8, testRawDigestB)

	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, stale.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale permit replaced the newer baseline: %v", err)
	}
	got, _, err := env.svc.GetNetDeviceBaseline(ctx, env.dev.ID)
	if err != nil || got != newer {
		t.Fatalf("baseline %+v %v, want %+v", got, err, newer)
	}
	// A replacement binds the baseline it replaces.
	next := env.commitApproved(t, 9, testRawDigestA)
	if next.Revision != newer.Revision+1 || next.VersionID != 9 {
		t.Fatalf("replacement %+v", next)
	}
	if !strings.Contains(env.logs.String(), `"previous_raw_digest":"`+testRawDigestB+`"`) {
		t.Fatal("replacement event does not name the previous baseline")
	}
}

func TestNetDevBaselineConcurrentTrustChangeRefused(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	ctx := context.Background()
	p := env.propose(t, 7, testRawDigestA)
	env.approve(t, p.ExecutionDigest)
	if _, err := env.e.db.BumpTrustGeneration(env.dev.ID, testNetDevPin2); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("baseline committed across a re-pin: %v", err)
	}
	requireNoBaseline(t, env.svc, env.dev.ID)
}

func TestNetDevBaselineRequestRefusals(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		id      string
		version int64
		raw     string
		code    codes.Code
	}{
		"zero version":     {env.dev.ID, 0, testRawDigestA, codes.InvalidArgument},
		"negative version": {env.dev.ID, -1, testRawDigestA, codes.InvalidArgument},
		"upper hex":        {env.dev.ID, 1, strings.ToUpper(testRawDigestA), codes.InvalidArgument},
		"short digest":     {env.dev.ID, 1, testRawDigestA[:63], codes.InvalidArgument},
		"empty digest":     {env.dev.ID, 1, "", codes.InvalidArgument},
		"unknown device":   {"no-such-sw", 1, testRawDigestA, codes.NotFound},
	} {
		if _, err := env.svc.ProposeNetDeviceBaseline(ctx, tc.id, tc.version, tc.raw); status.Code(err) != tc.code {
			t.Errorf("%s: propose %v, want %v", name, err, tc.code)
		}
		if _, err := env.svc.CommitNetDeviceBaseline(ctx, tc.id, tc.version, tc.raw, strings.Repeat("0", 64)); status.Code(err) != tc.code {
			t.Errorf("%s: commit %v, want %v", name, err, tc.code)
		}
	}
	if _, _, err := env.svc.GetNetDeviceBaseline(ctx, "../x"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("malformed device id read: %v", err)
	}

	// A blocked device gets no baseline, even under a permit approved
	// before it was blocked.
	blockedPermit := env.propose(t, 7, testRawDigestA)
	env.approve(t, blockedPermit.ExecutionDigest)
	if _, err := env.e.db.BlockNetDevice(env.dev.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.ProposeNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("blocked device propose: %v", err)
	}
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, blockedPermit.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("blocked device commit: %v", err)
	}
	if _, err := env.e.db.UnblockNetDevice(env.dev.ID); err != nil {
		t.Fatal(err)
	}
	requireNoBaseline(t, env.svc, env.dev.ID)

	// A locked vault refuses reads and writes, even under an approved
	// permit.
	lockedPermit := env.propose(t, 8, testRawDigestB)
	env.approve(t, lockedPermit.ExecutionDigest)
	env.e.vault.Lock()
	if _, _, err := env.svc.GetNetDeviceBaseline(ctx, env.dev.ID); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("locked vault read: %v", err)
	}
	if _, err := env.svc.ProposeNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("locked vault propose: %v", err)
	}
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 8, testRawDigestB, lockedPermit.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("locked vault commit: %v", err)
	}
	if _, _, err := env.e.vault.OpenVersion(netDevBaselineRef(env.dev.ID)); err == nil {
		t.Error("locked vault opened")
	}
	if err := env.e.vault.Unlock([]byte(strings.Repeat("correct-horse-battery-staple-", 4))); err != nil {
		t.Fatal(err)
	}
	requireNoBaseline(t, env.svc, env.dev.ID)
}

// TestNetDevBaselineCommitChecksRaceAfterAuthorization drives a change in
// between the permit check (AuthorizeBaseline) and the vault commit: the
// checks inside the PutWithCommit callback must refuse it, store nothing
// and audit the refused commit of the consumed permit.
func TestNetDevBaselineCommitChecksRaceAfterAuthorization(t *testing.T) {
	for name, race := range map[string]func(t *testing.T, env *netDevBaselineEnv){
		"re-pin": func(t *testing.T, env *netDevBaselineEnv) {
			if _, err := env.e.db.BumpTrustGeneration(env.dev.ID, testNetDevPin2); err != nil {
				t.Fatal(err)
			}
		},
		"block": func(t *testing.T, env *netDevBaselineEnv) {
			if _, err := env.e.db.BlockNetDevice(env.dev.ID, "test"); err != nil {
				t.Fatal(err)
			}
		},
		"concurrent baseline": func(t *testing.T, env *netDevBaselineEnv) {
			v, err := encodeNetDevBaseline(NetDevBaseline{DeviceID: env.dev.ID, VersionID: 9, RawDigest: testRawDigestB, TrustGeneration: env.dev.TrustGeneration,
				ExecutionDigest: strings.Repeat("d4", 32), CommittedBy: "other", ApprovedAtUnix: 1700000000})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := env.e.vault.Put(netDevBaselineRef(env.dev.ID), v, "other"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := newNetDevBaselineEnv(t)
			ctx := context.Background()
			p := env.propose(t, 7, testRawDigestA)
			env.approve(t, p.ExecutionDigest)
			a := env.svc.netDevAdmin()
			authorize := a.AuthorizeBaseline
			raced := false
			a.AuthorizeBaseline = func(ctx context.Context, b NetDevBaselineBinding, digest string) error {
				if err := authorize(ctx, b, digest); err != nil {
					return err
				}
				race(t, env)
				raced = true
				return nil
			}
			if _, err := a.ApproveBaseline(ctx, env.dev.ID, 7, testRawDigestA, p.ExecutionDigest, "admin:uid1000"); !errors.Is(err, ErrNetDevBaselineConcurrent) {
				t.Fatalf("raced commit: %v, want ErrNetDevBaselineConcurrent", err)
			}
			if !raced {
				t.Fatal("permit was not consumed before the race")
			}
			got, rev, err := env.e.vault.OpenVersion(netDevBaselineRef(env.dev.ID))
			if name == "concurrent baseline" {
				b, derr := decodeNetDevBaseline(env.dev.ID, got)
				if err != nil || rev != 1 || derr != nil || b.VersionID != 9 {
					t.Fatalf("concurrent baseline overwritten: %+v rev %d %v %v", b, rev, err, derr)
				}
			} else if !errors.Is(err, vault.ErrNotFound) {
				t.Fatalf("baseline stored across the race: %v", err)
			}
			refused := env.auditEvents("baseline_commit_refused")
			if len(refused) != 1 || refused[0]["device"] != env.dev.ID || refused[0]["execution_digest"] != p.ExecutionDigest || refused[0]["reason"] != "concurrent_change" {
				t.Fatalf("refused commit audit %v", refused)
			}
			if n := len(env.auditEvents("baseline_approved")); n != 0 {
				t.Fatalf("%d approval events for a refused commit", n)
			}
		})
	}
}

// TestNetDevBaselineRequiresExecutorComputedDigest: without the
// executor-side digest check (production until ND-14) no baseline can be
// proposed or committed, and a digest the executor did not compute is
// refused at propose and at commit (ADR 0010 D4).
func TestNetDevBaselineRequiresExecutorComputedDigest(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	ctx := context.Background()
	p := env.propose(t, 7, testRawDigestA)
	env.approve(t, p.ExecutionDigest)

	// Production wiring: no verifier.
	env.svc.netDevBaselineDigest = nil
	if a := env.svc.netDevAdmin(); a.VerifyBaselineDigest != nil {
		t.Fatal("production netDevAdmin has a baseline digest verifier")
	}
	if _, err := env.svc.ProposeNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("propose without executor-computed digest: %v", err)
	}
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit without executor-computed digest: %v", err)
	}
	if _, err := env.svc.netDevAdmin().BaselineBinding(ctx, env.dev.ID, 7, testRawDigestA); !errors.Is(err, ErrNetDevBaselineUnverified) {
		t.Fatalf("binding without verifier: %v", err)
	}
	requireNoBaseline(t, env.svc, env.dev.ID)

	// With a verifier, a server-chosen digest it does not confirm is
	// refused before any permit exists.
	env.svc.netDevBaselineDigest = testBaselineVerifier
	if _, err := env.svc.ProposeNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestUnverified); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("propose of unverified digest: %v", err)
	}
	// Commit checks again: the verifier withdraws the digest after approval.
	env.svc.netDevBaselineDigest = func(context.Context, string, int64, string) error { return errors.New("withdrawn") }
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, p.ExecutionDigest); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit of withdrawn digest: %v", err)
	}
	requireNoBaseline(t, env.svc, env.dev.ID)
	// The permit was not consumed by the refused commits.
	env.svc.netDevBaselineDigest = testBaselineVerifier
	if _, err := env.svc.CommitNetDeviceBaseline(ctx, env.dev.ID, 7, testRawDigestA, p.ExecutionDigest); err != nil {
		t.Fatalf("verified commit: %v", err)
	}
}

// TestNetDevBaselineRPCNotWired pins that the baseline handlers have no
// gRPC method and no role entry: they may only be wired together with the
// executor-computed digest check of ND-14 (see netdev_baseline.go).
//
// The one exempt method is the read-only I2 host baseline digest
// comparison (ADR 0015 D7 item 2, IG-06), which is not a network device
// baseline and writes nothing; integrity_baseline_test.go pins it.
func TestNetDevBaselineRPCNotWired(t *testing.T) {
	const i2Compare = pb.ExecutorService_CompareBaselineList_FullMethodName
	for _, m := range allServiceMethods(t) {
		if m != i2Compare && strings.Contains(strings.ToLower(m), "baseline") {
			t.Errorf("baseline RPC %s is wired before ND-14", m)
		}
	}
	for m := range MethodRoles() {
		if m != i2Compare && strings.Contains(strings.ToLower(m), "baseline") {
			t.Errorf("baseline method %s has a role before ND-14", m)
		}
	}
}

// TestNetDevBaselineTargetIsCanonical: every valid device id, up to the
// maximum length, yields a permit host id canonical accepts, distinct per
// device.
func TestNetDevBaselineTargetIsCanonical(t *testing.T) {
	seen := map[string]string{}
	for n := 1; n <= netdevcontract.MaxDeviceIDBytes; n++ {
		for _, id := range []string{strings.Repeat("a", n), "b" + strings.Repeat("-c", (n-1)/2) + strings.Repeat("d", (n-1)%2)} {
			if !netdevcontract.ValidDeviceID(id) {
				t.Fatalf("test id %q invalid", id)
			}
			target := netDevBaselineTarget(id)
			if !canonical.ValidHostID(target) {
				t.Errorf("device id of %d bytes: target %q (%d chars) rejected by canonical", len(id), target, len(target))
			}
			if prev, ok := seen[target]; ok && prev != id {
				t.Errorf("target %q shared by %q and %q", target, prev, id)
			}
			seen[target] = id
		}
	}
}

// TestNetDevBaselineMaxLengthDeviceID approves a baseline end to end for
// device ids at the boundaries of the target and vault ref scoping.
func TestNetDevBaselineMaxLengthDeviceID(t *testing.T) {
	for _, n := range []int{47, 48, 54, 55, netdevcontract.MaxDeviceIDBytes} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			env := newNetDevBaselineEnvFor(t, strings.Repeat("s", n))
			got := env.commitApproved(t, 7, testRawDigestA)
			if got.DeviceID != env.dev.ID || got.Revision != 1 {
				t.Fatalf("baseline %+v", got)
			}
		})
	}
}

func TestNetDevBaselineRecordFormat(t *testing.T) {
	good := NetDevBaseline{DeviceID: "core-sw", VersionID: 7, RawDigest: testRawDigestA, TrustGeneration: 1,
		ExecutionDigest: strings.Repeat("c3", 32), CommittedBy: "admin:uid1000", ApprovedAtUnix: 1700000000}
	enc, err := encodeNetDevBaseline(good)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeNetDevBaseline("core-sw", enc); err != nil || got != good {
		t.Fatalf("round trip %+v %v", got, err)
	}
	bad := map[string][]byte{
		"other device": enc,
		"no magic":     enc[len(netDevBaselineMagic):],
		"trailing":     append(append([]byte{}, enc...), []byte(`{}`)...),
		"unknown field": func() []byte {
			return []byte(netDevBaselineMagic + `{"device_id":"core-sw","version_id":7,"raw_digest":"` + testRawDigestA + `","x":1}`)
		}(),
		"too large": append([]byte(netDevBaselineMagic), make([]byte, maxNetDevBaselineRecord)...),
	}
	for name, v := range bad {
		id := "core-sw"
		if name == "other device" {
			id = "edge-sw"
		}
		if _, err := decodeNetDevBaseline(id, v); !errors.Is(err, ErrNetDevBaselineFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, change := range map[string]func(*NetDevBaseline){
		"version":   func(b *NetDevBaseline) { b.VersionID = 0 },
		"digest":    func(b *NetDevBaseline) { b.RawDigest = "zz" },
		"execution": func(b *NetDevBaseline) { b.ExecutionDigest = "" },
		"actor":     func(b *NetDevBaseline) { b.CommittedBy = "" },
		"time":      func(b *NetDevBaseline) { b.ApprovedAtUnix = 0 },
	} {
		c := good
		change(&c)
		v, err := encodeNetDevBaseline(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeNetDevBaseline("core-sw", v); !errors.Is(err, ErrNetDevBaselineFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNetDevBaselineDrift(t *testing.T) {
	b := NetDevBaseline{RawDigest: testRawDigestA}
	if drift, err := NetDevBaselineDrift(b, testRawDigestA); err != nil || drift {
		t.Fatalf("same digest: %v %v", drift, err)
	}
	if drift, err := NetDevBaselineDrift(b, testRawDigestB); err != nil || !drift {
		t.Fatalf("other digest: %v %v", drift, err)
	}
	if _, err := NetDevBaselineDrift(NetDevBaseline{}, testRawDigestA); !errors.Is(err, ErrNetDevNoBaseline) {
		t.Fatalf("no baseline: %v", err)
	}
	if _, err := NetDevBaselineDrift(b, "nope"); !errors.Is(err, ErrNetDevBaselineRequest) {
		t.Fatalf("malformed current: %v", err)
	}
}

func TestRemoveNetDeviceDeletesBaseline(t *testing.T) {
	env := newNetDevBaselineEnv(t)
	env.commitApproved(t, 7, testRawDigestA)
	if _, err := env.svc.RemoveNetDevice(context.Background(), &pb.RemoveNetDeviceRequest{DeviceId: env.dev.ID, Confirm: "yes"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.e.vault.Open(netDevBaselineRef(env.dev.ID)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("baseline vault entry after remove: %v", err)
	}
}

func TestNetDevBaselineRefIsDeviceScoped(t *testing.T) {
	long := strings.Repeat("s", 60)
	for _, id := range []string{"core-sw", long} {
		ref := netDevBaselineRef(id)
		dk, fk := netDevKeyRefs(id)
		if ref == dk || ref == fk || ref == netDevReadCredRef(executordb.NetDevice{ID: id}) || !strings.HasSuffix(ref, "-bl") || len(ref) > maxNetDevVaultRef {
			t.Errorf("%s: baseline ref %q collides or is too long", id, ref)
		}
	}
	if netDevBaselineRef("core-sw") == netDevBaselineRef("edge-sw") {
		t.Fatal("baseline refs are not device scoped")
	}
}
