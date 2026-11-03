// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// openTrustTestDB opens an executor.db in a private temporary directory.
func openTrustTestDB(t *testing.T) *executordb.DB {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

const (
	riskTestHost = "web-1"
	riskTestFP   = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// recordLowHost records riskTestHost as LOW so the action's own trust
// decides the floor.
func recordLowHost(t *testing.T, db *executordb.DB) {
	t.Helper()
	if _, err := db.SetHostCriticality(riskTestHost, riskTestFP, canonical.RiskLow, "admin:uid0"); err != nil {
		t.Fatal(err)
	}
}

// minimumRisk is the executor's risk floor for running action@version
// with the artifact sum on riskTestHost.
func minimumRisk(t *testing.T, db *executordb.DB, action, version, sum string) canonical.Risk {
	t.Helper()
	p, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := p.MinimumRisk(canonical.Request{ActionID: action, ModuleVersion: version, ArtifactSHA256: sum},
		[]canonical.Target{{HostID: riskTestHost, HostKeyFingerprint: riskTestFP}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// restartArtifact returns the reviewed artifact hash of docker.restart.
func restartArtifact(t *testing.T, rev *pb.ReviewBuiltinTrustResponse) string {
	t.Helper()
	for _, m := range rev.GetModules() {
		for _, a := range m.GetActions() {
			if a.GetActionId() == "docker.restart" {
				return a.GetNewArtifactSha256()
			}
		}
	}
	t.Fatalf("docker.restart not in review %+v", rev)
	return ""
}

// reviewAndCommit reviews the bundle as the admin and commits it.
func reviewAndCommit(t *testing.T, s *Service, retain, retire []string) (*pb.ReviewBuiltinTrustResponse, *pb.CommitBuiltinTrustResponse) {
	t.Helper()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest, Retain: retain, Retire: retire})
	if err != nil {
		t.Fatal(err)
	}
	return rev, out
}

// After trust-builtins (CommitBuiltinTrust) the committed built-in version
// is trusted for risk exactly like `nebula artifact trust` of the same
// bytes, action, version and declared risk: HIGH before, the declared
// LOW after, and the same floor as the individual path.
func TestCommittedBuiltinTrustCountsForRisk(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	sum := restartArtifact(t, rev)
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", sum); got != riskpolicy.UntrustedFloor {
		t.Fatalf("before commit: floor %s, want %s", got, riskpolicy.UntrustedFloor)
	}
	if _, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest}); err != nil {
		t.Fatal(err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", sum); got != canonical.RiskLow {
		t.Fatalf("after commit: floor %s, want LOW", got)
	}
	// Exact binding only: other bytes, versions or actions stay HIGH.
	other := strings.Repeat("f", 64)
	for _, c := range [][3]string{{"docker.restart", "1.0.0", other}, {"docker.restart", "1.0.1", sum}, {"docker.stop", "1.0.0", sum}} {
		if got := minimumRisk(t, e.db, c[0], c[1], c[2]); got != riskpolicy.UntrustedFloor {
			t.Errorf("%v: floor %s, want %s", c, got, riskpolicy.UntrustedFloor)
		}
	}
	// The individual path gives the same floor and the same trust entry.
	ind := openTrustTestDB(t)
	recordLowHost(t, ind)
	if err := ind.TrustArtifact(executordb.TrustedArtifact{SHA256: sum, ActionID: "docker.restart", ModuleVersion: "1.0.0",
		Risk: canonical.RiskLow, TrustedBy: "admin:uid0"}); err != nil {
		t.Fatal(err)
	}
	if a, b := minimumRisk(t, ind, "docker.restart", "1.0.0", sum), minimumRisk(t, e.db, "docker.restart", "1.0.0", sum); a != b {
		t.Fatalf("individual trust floor %s, built-in trust floor %s", a, b)
	}
	list, err := e.db.ListTrustedArtifacts()
	if err != nil || len(list) != 1 {
		t.Fatalf("trusted artifacts = %+v, %v", list, err)
	}
	if a := list[0]; a.SHA256 != sum || a.ActionID != "docker.restart" || a.ModuleVersion != "1.0.0" ||
		a.Risk != canonical.RiskLow || a.TrustedBy != "admin:uid0" || a.Label != "built-in release 2026.11.0" {
		t.Fatalf("trust entry = %+v", a)
	}
	// Individual revocation removes the built-in trust like any other.
	if removed, err := e.db.UntrustArtifact(sum, "docker.restart", "1.0.0"); err != nil || !removed {
		t.Fatalf("untrust = %v, %v", removed, err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", sum); got != riskpolicy.UntrustedFloor {
		t.Fatalf("after untrust: floor %s, want %s", got, riskpolicy.UntrustedFloor)
	}
}

// Retiring the old version on upgrade revokes its trust; the new version
// is trusted; retaining the old version keeps it trusted. Trust is never
// retargeted from the old bytes to the new ones.
func TestBuiltinTrustUpgradeRetireRevokesRetainKeeps(t *testing.T) {
	for _, retire := range []bool{true, false} {
		name := map[bool]string{true: "retire", false: "retain"}[retire]
		t.Run(name, func(t *testing.T) {
			e := newBundleEnv(t)
			recordLowHost(t, e.db)
			s := e.service()
			rev1, _ := reviewAndCommit(t, s, nil, nil)
			oldSum := restartArtifact(t, rev1)

			writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
			var retain, retired []string
			if retire {
				retired = []string{"docker@1.0.0"}
			} else {
				retain = []string{"docker@1.0.0"}
			}
			rev2, _ := reviewAndCommit(t, s, retain, retired)
			newSum := restartArtifact(t, rev2)
			if newSum == oldSum {
				t.Fatal("test bundle did not change the artifact")
			}
			if got := minimumRisk(t, e.db, "docker.restart", "1.1.0", newSum); got != canonical.RiskLow {
				t.Fatalf("new version floor %s, want LOW", got)
			}
			wantOld := canonical.RiskLow
			if retire {
				wantOld = riskpolicy.UntrustedFloor
			}
			if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != wantOld {
				t.Fatalf("old version floor %s, want %s", got, wantOld)
			}
			// No retargeting: the old version with the new bytes and the
			// new version with the old bytes are untrusted.
			if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", newSum); got != riskpolicy.UntrustedFloor {
				t.Fatalf("old version with new bytes: floor %s", got)
			}
			if got := minimumRisk(t, e.db, "docker.restart", "1.1.0", oldSum); got != riskpolicy.UntrustedFloor {
				t.Fatalf("new version with old bytes: floor %s", got)
			}
		})
	}
}

// auditLines returns the JSON audit records of kind.
func auditLines(t *testing.T, buf *bytes.Buffer, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["msg"] == "audit" && m["kind"] == kind {
			out = append(out, m)
		}
	}
	return out
}

func auditStrings(t *testing.T, m map[string]any, key string) []string {
	t.Helper()
	raw, ok := m[key].([]any)
	if !ok {
		if m[key] == nil {
			return nil
		}
		t.Fatalf("%s = %#v, want a list", key, m[key])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

// A commit writes one audit record with the admin UID (from peer
// credentials), the old/new module tuples, the exact trusted and revoked
// artifact tuples and the retain/retire decisions. It carries no script
// content.
func TestBuiltinTrustCommitIsAudited(t *testing.T) {
	e := newBundleEnv(t)
	var buf bytes.Buffer
	s := e.service()
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)
	recs := auditLines(t, &buf, "builtin_trust_committed")
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1: %s", len(recs), buf.String())
	}
	r := recs[0]
	if r["admin_uid"] != float64(trustTestAdminUID) || r["manifest_digest"] != rev1.ManifestDigest || r["release"] != "2026.11.0" {
		t.Fatalf("audit = %v", r)
	}
	if got := auditStrings(t, r, "tuples"); len(got) != 1 || !strings.HasPrefix(got[0], "docker :") || !strings.HasSuffix(got[0], "(new)") {
		t.Fatalf("tuples = %v", got)
	}
	if got := auditStrings(t, r, "trusted"); len(got) != 1 || got[0] != "docker.restart@1.0.0 "+oldSum+" LOW" {
		t.Fatalf("trusted = %v", got)
	}

	buf.Reset()
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	rev2, _ := reviewAndCommit(t, s, nil, []string{"docker@1.0.0"})
	newSum := restartArtifact(t, rev2)
	recs = auditLines(t, &buf, "builtin_trust_committed")
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(recs))
	}
	r = recs[0]
	if got := auditStrings(t, r, "tuples"); len(got) != 1 || !strings.HasPrefix(got[0], "docker 1.0.0:") || !strings.Contains(got[0], "-> 1.1.0:") {
		t.Fatalf("tuples = %v", got)
	}
	if got := auditStrings(t, r, "trusted"); len(got) != 1 || got[0] != "docker.restart@1.1.0 "+newSum+" LOW" {
		t.Fatalf("trusted = %v", got)
	}
	if got := auditStrings(t, r, "revoked"); len(got) != 1 || got[0] != "docker.restart@1.0.0 "+oldSum+" LOW" {
		t.Fatalf("revoked = %v", got)
	}
	if got := auditStrings(t, r, "retired"); len(got) != 1 || got[0] != "docker@1.0.0" {
		t.Fatalf("retired = %v", got)
	}
	if strings.Contains(buf.String(), "echo restart") {
		t.Fatal("audit carries script content")
	}
}

// failingArtifacts fails the check or the apply step.
type failingArtifacts struct {
	*executordb.DB
	failCheck, failApply bool
	// failTrustApply fails only an apply that records trust entries.
	failTrustApply bool
	// failRestore fails only an apply that records entries and retires
	// nothing (a restore of revoked entries).
	failRestore bool
	applied     int
}

func (f *failingArtifacts) CheckBuiltinTrust(c executordb.BuiltinTrustChange) error {
	if f.failCheck {
		return errors.New("check refused")
	}
	return f.DB.CheckBuiltinTrust(c)
}

func (f *failingArtifacts) ApplyBuiltinTrust(c executordb.BuiltinTrustChange) ([]executordb.TrustedArtifact, error) {
	f.applied++
	if f.failApply || (f.failTrustApply && len(c.Trust) > 0) || (f.failRestore && len(c.Trust) > 0 && len(c.Retire) == 0) {
		return nil, errors.New("disk full")
	}
	return f.DB.ApplyBuiltinTrust(c)
}

// Artifact trust that does not validate stops the commit before the store
// changes; nothing is trusted.
func TestBuiltinTrustArtifactCheckFailureCommitsNothing(t *testing.T) {
	e := newBundleEnv(t)
	fa := &failingArtifacts{DB: e.db, failCheck: true}
	e.bt.artifacts = fa
	s := e.service()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit err = %v, want FailedPrecondition", err)
	}
	if g := e.storeGeneration(t); g != 0 {
		t.Fatalf("store generation %d, want 0 (nothing committed)", g)
	}
	if fa.applied != 0 {
		t.Fatalf("apply called %d times", fa.applied)
	}
}

// A failure to record the artifact trust after the store committed is
// reported and audited; the built-ins stay untrusted for risk.
func TestBuiltinTrustArtifactApplyFailureFailsClosed(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	e.bt.artifacts = &failingArtifacts{DB: e.db, failApply: true}
	var buf bytes.Buffer
	s := e.service()
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "artifact trust was not recorded") {
		t.Fatalf("commit err = %v", err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", restartArtifact(t, rev)); got != riskpolicy.UntrustedFloor {
		t.Fatalf("floor %s, want %s", got, riskpolicy.UntrustedFloor)
	}
	if recs := auditLines(t, &buf, "builtin_trust_artifacts_failed"); len(recs) != 1 || recs[0]["admin_uid"] != float64(trustTestAdminUID) {
		t.Fatalf("failure audit = %v (%s)", recs, buf.String())
	}
	if recs := auditLines(t, &buf, "builtin_trust_committed"); len(recs) != 0 {
		t.Fatalf("success audited on failure: %v", recs)
	}
}

// A failure to record the new trust after a store commit that retired an
// old version leaves no retired version trusted (fail closed): its trust
// was revoked before the store committed. The error and the audit record
// name the state.
func TestBuiltinTrustApplyFailureAfterRetireLeavesRetiredUntrusted(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != canonical.RiskLow {
		t.Fatalf("old version floor %s, want LOW", got)
	}
	gen := e.storeGeneration(t)

	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	e.bt.artifacts = &failingArtifacts{DB: e.db, failTrustApply: true}
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	rev2, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev2.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	commitErr := err
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit err = %v", err)
	}
	if g := e.storeGeneration(t); g == gen {
		t.Fatal("store did not commit")
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != riskpolicy.UntrustedFloor {
		t.Fatalf("retired version floor %s, want %s (fail closed)", got, riskpolicy.UntrustedFloor)
	}
	if msg := err.Error(); !strings.Contains(msg, "artifact trust was not recorded") || !strings.Contains(msg, "docker@1.0.0") ||
		!strings.Contains(msg, "nebula artifact trust") {
		t.Fatalf("commit err = %v", err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.1.0", restartArtifact(t, rev2)); got != riskpolicy.UntrustedFloor {
		t.Fatalf("new version floor %s, want %s", got, riskpolicy.UntrustedFloor)
	}
	list, err := e.db.ListTrustedArtifacts()
	if err != nil || len(list) != 0 {
		t.Fatalf("trusted artifacts = %+v, %v", list, err)
	}
	recs := auditLines(t, &buf, "builtin_trust_artifacts_failed")
	if len(recs) != 1 {
		t.Fatalf("failure audit = %v (%s)", recs, buf.String())
	}
	if r := auditStrings(t, recs[0], "retired"); len(r) != 1 || r[0] != "docker@1.0.0" {
		t.Fatalf("audit retired = %v", r)
	}
	if r := auditStrings(t, recs[0], "revoked"); len(r) == 0 || !strings.Contains(strings.Join(r, " "), oldSum) {
		t.Fatalf("audit revoked = %v", r)
	}
	if r := auditStrings(t, recs[0], "untrusted"); len(r) == 0 || !strings.Contains(strings.Join(r, " "), "docker.restart@1.1.0") {
		t.Fatalf("audit untrusted = %v", r)
	}
	if !strings.Contains(commitErr.Error(), "docker.restart@1.1.0 "+restartArtifact(t, rev2)) {
		t.Fatalf("error does not name the unrecorded entry: %v", commitErr)
	}

	// The next review completes the pending trust: the new version is
	// trusted, the retired one stays revoked.
	e.bt.artifacts = e.db
	if _, err := adminReview(t, s); err != nil {
		t.Fatal(err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.1.0", restartArtifact(t, rev2)); got != canonical.RiskLow {
		t.Fatalf("after recovery: new version floor %s, want LOW", got)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != riskpolicy.UntrustedFloor {
		t.Fatalf("after recovery: retired version floor %s", got)
	}
	rec := auditLines(t, &buf, "builtin_trust_pending_recovered")
	if len(rec) != 1 || rec[0]["outcome"] != "completed" {
		t.Fatalf("recovery audit = %v", rec)
	}
	assertNoPending(t, e)
}

// A corrupt pending record blocks the review instead of being guessed at.
func TestBuiltinTrustCorruptPendingBlocksReview(t *testing.T) {
	e := newBundleEnv(t)
	s := e.service()
	if err := trust.WritePending(e.storeDir, []byte(`{"format":9}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := adminReview(t, s); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("review err = %v", err)
	}
}

// assertNoPending checks that no pending record is left.
func assertNoPending(t *testing.T, e *bundleEnv) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(e.storeDir, trust.PendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending record left: %v", err)
	}
}

// failStoreCommit makes the committing store BulkAdmit fail with a quota
// error after the retired versions' trust was revoked.
func failStoreCommit(e *bundleEnv) {
	e.bt.commitStore = func(*trust.Store, release.Candidate, trust.BulkAdmitOpts) (trust.BulkAdmitResult, error) {
		return trust.BulkAdmitResult{}, fmt.Errorf("%w: disk quota", trust.ErrQuota)
	}
}

// A store commit that fails after the retired versions' trust was revoked
// restores the revoked entries, reports the state and audits it.
func TestBuiltinTrustStoreCommitFailureRestoresRevoked(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)
	gen := e.storeGeneration(t)

	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	failStoreCommit(e)
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	rev2, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev2.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("commit err = %v", err)
	}
	if g := e.storeGeneration(t); g != gen {
		t.Fatalf("store generation %d, want %d", g, gen)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != canonical.RiskLow {
		t.Fatalf("old version floor %s, want LOW (restored)", got)
	}
	recs := auditLines(t, &buf, "builtin_trust_store_failed")
	if len(recs) != 1 || recs[0]["restored"] != true || recs[0]["store_committed"] != false {
		t.Fatalf("store failure audit = %v (%s)", recs, buf.String())
	}
	if r := auditStrings(t, recs[0], "revoked"); len(r) == 0 || !strings.Contains(strings.Join(r, " "), oldSum) {
		t.Fatalf("audit revoked = %v", r)
	}
	if !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("commit err = %v", err)
	}
	assertNoPending(t, e)
}

// If the revoked entries cannot be restored after a failed store commit,
// the error says so and the next review restores them.
func TestBuiltinTrustStoreCommitFailureReviewRestores(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)

	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	failStoreCommit(e)
	e.bt.artifacts = &failingArtifacts{DB: e.db, failRestore: true}
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	rev2, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev2.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "could not be restored") ||
		!strings.Contains(err.Error(), "nebula artifact trust-builtins") || !strings.Contains(err.Error(), oldSum) {
		t.Fatalf("commit err = %v", err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != riskpolicy.UntrustedFloor {
		t.Fatalf("old version floor %s, want %s (revoked, not restored)", got, riskpolicy.UntrustedFloor)
	}
	if recs := auditLines(t, &buf, "builtin_trust_store_failed"); len(recs) != 1 || recs[0]["restored"] != false {
		t.Fatalf("store failure audit = %v", recs)
	}

	e.bt.artifacts, e.bt.commitStore = e.db, nil
	if _, err := adminReview(t, s); err != nil {
		t.Fatal(err)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != canonical.RiskLow {
		t.Fatalf("after recovery: old version floor %s, want LOW", got)
	}
	if rec := auditLines(t, &buf, "builtin_trust_pending_recovered"); len(rec) != 1 || rec[0]["outcome"] != "restored" {
		t.Fatalf("recovery audit = %v", rec)
	}
	assertNoPending(t, e)
}

// A failure to revoke the retired versions commits nothing: the store and
// the artifact trust are unchanged.
func TestBuiltinTrustRevokeFailureCommitsNothing(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)
	gen := e.storeGeneration(t)

	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	e.bt.artifacts = &failingArtifacts{DB: e.db, failApply: true}
	rev2, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev2.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "nothing committed") {
		t.Fatalf("commit err = %v", err)
	}
	if g := e.storeGeneration(t); g != gen {
		t.Fatalf("store generation %d, want %d", g, gen)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != canonical.RiskLow {
		t.Fatalf("old version floor %s, want LOW", got)
	}
}

// Invalid retirement decisions are rejected before any trust is revoked.
func TestBuiltinTrustInvalidRetireRevokesNothing(t *testing.T) {
	e := newBundleEnv(t)
	recordLowHost(t, e.db)
	s := e.service()
	rev1, _ := reviewAndCommit(t, s, nil, nil)
	oldSum := restartArtifact(t, rev1)

	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	fa := &failingArtifacts{DB: e.db}
	e.bt.artifacts = fa
	rev2, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	// docker@1.0.0 retired, but docker@9.9.9 is no old version: invalid.
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev2.ManifestDigest,
		Retire: []string{"docker@1.0.0", "docker@9.9.9"}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not an old version") {
		t.Fatalf("commit err = %v", err)
	}
	if fa.applied != 0 {
		t.Fatalf("apply called %d times", fa.applied)
	}
	if got := minimumRisk(t, e.db, "docker.restart", "1.0.0", oldSum); got != canonical.RiskLow {
		t.Fatalf("old version floor %s, want LOW", got)
	}
}

// The directory-backed transaction refuses to exist without an artifact
// trust store, so a commit can never skip recording the trust.
func TestNewDirBuiltinTrustRequiresArtifactTrust(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewDirBuiltinTrust(dir+"/trust", dir+"/bundle", nil, nil, nil); err == nil {
		t.Fatal("want error without artifact trust")
	}
	if _, err := os.Stat(dir + "/trust"); !os.IsNotExist(err) {
		t.Fatalf("store created without artifact trust: %v", err)
	}
	var _ BuiltinArtifactTrust = (*executordb.DB)(nil)
}
