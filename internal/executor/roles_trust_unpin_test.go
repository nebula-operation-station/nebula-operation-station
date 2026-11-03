// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// adminUnpin runs the UnpinBuiltinVersion handler as uid.
func adminUnpin(t *testing.T, s *Service, uid uint32, version string) (*pb.UnpinBuiltinVersionResponse, error) {
	t.Helper()
	return callAs(t, uid, pb.ExecutorService_UnpinBuiltinVersion_FullMethodName,
		&pb.UnpinBuiltinVersionRequest{Version: version}, s.UnpinBuiltinVersion)
}

// pinnedBundleEnv commits docker 1.0.0, then 1.1.0 retaining (pinning)
// docker@1.0.0, then 1.2.0 and 1.3.0 retiring their predecessors, and moves
// the clock past every 90-day floor: docker@1.0.0 is only kept by its pin.
// It returns the environment, the service and a clock advancer.
func pinnedBundleEnv(t *testing.T) (*bundleEnv, *Service, func(time.Duration)) {
	t.Helper()
	e := newBundleEnv(t)
	cur := e.now()
	e.bt.now = func() time.Time { return cur }
	advance := func(d time.Duration) { cur = cur.Add(d) }
	s := e.service()
	reviewAndCommit(t, s, nil, nil)
	steps := []struct{ release, version, old string }{
		{"2026.12.0", "1.1.0", "docker@1.0.0"},
		{"2027.1.0", "1.2.0", "docker@1.1.0"},
		{"2027.2.0", "1.3.0", "docker@1.2.0"},
	}
	for i, st := range steps {
		advance(24 * time.Hour)
		writeDockerBundle(t, e.k, e.bundleDir, st.release, st.version, "echo restart "+st.version+"\n")
		if i == 0 {
			reviewAndCommit(t, s, []string{st.old}, nil)
		} else {
			reviewAndCommit(t, s, nil, []string{st.old})
		}
	}
	advance(200 * 24 * time.Hour)
	return e, s, advance
}

// The local admin unpins a saved pin through the RPC: it commits a new
// generation, is audited with the admin UID, deletes nothing, and the next
// commit collects the version again. Without the unpin the version is kept.
func TestUnpinBuiltinVersionMakesVersionCollectable(t *testing.T) {
	e, s, advance := pinnedBundleEnv(t)
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	st, err := trust.OpenExisting(e.storeDir, e.bt.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Pins(); !slices.Equal(got, []string{"docker@1.0.0"}) {
		t.Fatalf("pins before unpin = %v", got)
	}
	gen := st.Generation()

	out, err := adminUnpin(t, s, trustTestAdminUID, "docker@1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != "docker@1.0.0" || out.Generation != gen+1 || out.AdminUid != trustTestAdminUID || len(out.RemainingPins) != 0 {
		t.Fatalf("unpin = %+v", out)
	}
	recs := auditLines(t, &buf, "builtin_trust_unpinned")
	if len(recs) != 1 || recs[0]["admin_uid"] != float64(trustTestAdminUID) || recs[0]["version"] != "docker@1.0.0" ||
		recs[0]["generation"] != float64(gen+1) {
		t.Fatalf("audit = %v (%s)", recs, buf.String())
	}
	st, err = trust.OpenExisting(e.storeDir, e.bt.now)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := st.Module("docker")
	if len(st.Pins()) != 0 || !slices.ContainsFunc(m.History, func(h trust.VersionRecord) bool { return h.Version == "1.0.0" }) {
		t.Fatalf("after unpin: pins %v, history %+v (unpin must not delete)", st.Pins(), m.History)
	}

	advance(24 * time.Hour)
	writeDockerBundle(t, e.k, e.bundleDir, "2027.3.0", "1.4.0", "echo restart 1.4.0\n")
	_, res := reviewAndCommit(t, s, nil, []string{"docker@1.3.0"})
	if !slices.Contains(res.Collected, "docker@1.0.0") {
		t.Fatalf("collected = %v, want docker@1.0.0 after the unpin", res.Collected)
	}
}

// A pinned version stays kept by later commits while it is not unpinned
// (control for the test above).
func TestPinnedBuiltinVersionKeptWithoutUnpin(t *testing.T) {
	e, s, advance := pinnedBundleEnv(t)
	advance(24 * time.Hour)
	writeDockerBundle(t, e.k, e.bundleDir, "2027.3.0", "1.4.0", "echo restart 1.4.0\n")
	_, res := reviewAndCommit(t, s, nil, []string{"docker@1.3.0"})
	if slices.Contains(res.Collected, "docker@1.0.0") {
		t.Fatalf("collected = %v: the pinned docker@1.0.0 was collected", res.Collected)
	}
}

// An unpin of an unknown or not pinned version is NotFound, a malformed one
// InvalidArgument, a server caller PermissionDenied; none changes the store
// or writes an audit record.
func TestUnpinBuiltinVersionRejections(t *testing.T) {
	e, s, _ := pinnedBundleEnv(t)
	var buf bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&buf, nil))
	st, err := trust.OpenExisting(e.storeDir, e.bt.now)
	if err != nil {
		t.Fatal(err)
	}
	gen := st.Generation()
	cases := []struct {
		uid     uint32
		version string
		code    codes.Code
	}{
		{trustTestAdminUID, "docker@9.9.9", codes.NotFound},
		{trustTestAdminUID, "nosuch@1.0.0", codes.NotFound},
		{trustTestAdminUID, "docker@1.3.0", codes.NotFound}, // the active, unpinned version
		{trustTestAdminUID, "docker", codes.InvalidArgument},
		{trustTestAdminUID, "", codes.InvalidArgument},
		{trustTestAdminUID, string(bytes.Repeat([]byte("a"), maxBuiltinVersionRefBytes)) + "@1", codes.InvalidArgument},
		{trustTestServerUID, "docker@1.0.0", codes.PermissionDenied},
	}
	for _, c := range cases {
		if _, err := adminUnpin(t, s, c.uid, c.version); status.Code(err) != c.code {
			t.Fatalf("unpin %q as %d: %v, want %v", c.version, c.uid, err, c.code)
		}
	}
	st, err = trust.OpenExisting(e.storeDir, e.bt.now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation() != gen || !slices.Equal(st.Pins(), []string{"docker@1.0.0"}) {
		t.Fatalf("rejected unpins changed the store: generation %d (was %d), pins %v", st.Generation(), gen, st.Pins())
	}
	if recs := auditLines(t, &buf, "builtin_trust_unpinned"); len(recs) != 0 {
		t.Fatalf("rejected unpins were audited: %v", recs)
	}
	// A second unpin of the same version is refused once it is unpinned.
	if _, err := adminUnpin(t, s, trustTestAdminUID, "docker@1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminUnpin(t, s, trustTestAdminUID, "docker@1.0.0"); status.Code(err) != codes.NotFound {
		t.Fatalf("second unpin: %v, want NotFound", err)
	}
}

// An unpin consumes a confirmed review (the generation changes) and is
// refused while an interrupted commit's pending record exists.
func TestUnpinBuiltinVersionConsumesReviewAndRespectsPending(t *testing.T) {
	e, s, advance := pinnedBundleEnv(t)
	advance(24 * time.Hour)
	writeDockerBundle(t, e.k, e.bundleDir, "2027.3.0", "1.4.0", "echo restart 1.4.0\n")
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminUnpin(t, s, trustTestAdminUID, "docker@1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest,
		Retire: []string{"docker@1.3.0"}}); status.Code(err) != codes.Aborted {
		t.Fatalf("commit of a review made before the unpin: %v, want Aborted", err)
	}

	e2, s2, _ := pinnedBundleEnv(t)
	if err := trust.WritePending(e2.storeDir, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := adminUnpin(t, s2, trustTestAdminUID, "docker@1.0.0"); status.Code(err) != codes.Aborted {
		t.Fatalf("unpin with a pending record: %v, want Aborted", err)
	}
}
