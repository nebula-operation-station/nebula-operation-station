// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// End-to-end test of the image inventory chain (ADR 0011 D3, amendment of
// 2026-11-23 for image read leases):
//
//	read-grant-v2 lease (approved by the executor, fake in process)
//	  -> executions.RunDueReadGrants: docker.inspect, then image.packages with
//	     the parameters the grant binds (read_grant_params, parameter hashes)
//	  -> the executions service stores the runs and calls the image observer
//	  -> vuln_image_reads: one read of the image digest
//	  -> runServer over loopback HTTP with the vuln token and the real middleware
//	  -> GET inventory (nosclient and raw) shows the image subject
//	  -> a findings run with the snapshot ID: one finding, rejection of a
//	     digest outside the snapshot, complete, finding readable from the store.
//
// The results of image.packages and docker.inspect are real script output
// (testdata, produced by running the scripts against fake docker and trivy).
// The executor is an in-process fake: the lease and the runs are the real
// executions service, nothing else is mocked between the lease and the store.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

const (
	// imgE2EHex is the platform digest of the Debian 12 image of the fixtures.
	imgE2EHex    = "9d2e7b4a1f6c8e035a7d9b2c4e1f8a6d0c3b5e7f2a9d1c8b6f4e0a3d7b5c2e91"
	imgE2EDigest = "sha256:" + imgE2EHex
	imgE2ERepo   = "registry.example/app/web"
	imgE2ERef    = imgE2ERepo + "@" + imgE2EDigest
	// imgE2EOther is a digest the host does not run; a finding for it is
	// outside the snapshot.
	imgE2EOther = "sha256:" + "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
	// imgE2EContainer is the container the docker.inspect fixture names.
	imgE2EContainer = "web-app"
	// imgE2EVersion is the openssl version of the fixture (the older reads of
	// the fourth-read case carry one version back, see imgE2EOlderRead).
	imgE2EVersion = "3.0.14-1~deb12u1"
	imgE2EFixed   = "3.0.15-1~deb12u1"
	imgE2ECVE     = "CVE-2026-2001"
	// Key and credential fingerprints in the executor's real form.
	imgE2EKey  = "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	imgE2ECred = "SHA256:" + "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	imgE2EFix  = "testdata/image_packages_debian12_result.json"
	imgE2EInsp = "testdata/docker_inspect_web_result.json"
)

// imgE2EFiles returns the two fixture results: the image.packages result and
// the docker.inspect result that names the digest.
func imgE2EFiles(t *testing.T) (imgResult, inspectResult []byte) {
	t.Helper()
	img, err := os.ReadFile(imgE2EFix)
	if err != nil {
		t.Fatalf("read image.packages fixture: %v", err)
	}
	insp, err := os.ReadFile(imgE2EInsp)
	if err != nil {
		t.Fatalf("read docker.inspect fixture: %v", err)
	}
	return img, insp
}

// imgE2EOlderRead is the fixture with the older openssl version of the
// fourth-read case: the same complete read, one version back.
func imgE2EOlderRead(img []byte) []byte {
	return []byte(strings.ReplaceAll(string(img), "3.0.14", "3.0.13"))
}

// imgE2EExec is the executor of the lease test: it proposes and approves
// read grants, lists them, and runs their actions. Embedding the executor
// interface makes every other call panic, so the test fails loudly if the
// executions service asks for more.
type imgE2EExec struct {
	executions.Executor
	img, insp []byte
	grants    []*pb.ReadGrant
	// pending holds the proposed grants by digest until their approval.
	pending map[string]*pb.ReadGrant
	// runs records every RunReadGrant request, in order.
	runs []*pb.RunReadGrantRequest
	// refuse answers an action with an error instead of a result.
	refuse map[string]error
}

// ListHostKeys pins the one host of the test with the test key.
func (f *imgE2EExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: []*pb.HostKeyPin{{HostId: ivcHost, Fingerprint: imgE2EKey, CredentialRef: "nebula-default"}}}, nil
}

// GetSSHPublicKey answers the credential version with the test fingerprint.
func (f *imgE2EExec) GetSSHPublicKey(context.Context, *pb.GetSSHPublicKeyRequest, ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error) {
	return &pb.GetSSHPublicKeyResponse{Fingerprint: imgE2ECred}, nil
}

// ProposeReadGrant answers the proposal as the executor does: the digest it
// computes, and a user approval (WebAuthn) still to come. The grant is held
// as pending until CommitReadGrant.
func (f *imgE2EExec) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	raw := in.GetGrantJson()
	doc, _, digest, err := permit.ParseReadGrant(raw, time.Now())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "grant: %v", err)
	}
	f.pending[digest] = &pb.ReadGrant{GrantId: doc.ID, GrantDigest: digest, CanonicalGrant: raw,
		ApprovedBy: "alice", CreatedUnix: doc.CreatedUnix, ExpiryUnix: doc.ExpiryUnix}
	return &pb.ProposeReadGrantResponse{GrantDigest: digest, CanonicalGrant: raw,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		RequestOptionsJson:  []byte(`{"publicKey":{"challenge":"abc"}}`),
		ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}, nil
}

// CommitReadGrant approves the pending grant of the digest (the assertion is
// not checked here: the executor verifies it, and the test only needs the
// approved grant in its registry).
func (f *imgE2EExec) CommitReadGrant(_ context.Context, in *pb.CommitReadGrantRequest, _ ...grpc.CallOption) (*pb.CommitReadGrantResponse, error) {
	g, ok := f.pending[in.GetGrantDigest()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no pending read grant")
	}
	delete(f.pending, in.GetGrantDigest())
	f.grants = append(f.grants, g)
	return &pb.CommitReadGrantResponse{}, nil
}

// ListReadGrants returns the approved grants.
func (f *imgE2EExec) ListReadGrants(context.Context, *pb.ListReadGrantsRequest, ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	return &pb.ListReadGrantsResponse{Grants: f.grants}, nil
}

// RunReadGrant records the run and answers it with the fixture of its action
// (or with the refusal set for it).
func (f *imgE2EExec) RunReadGrant(_ context.Context, in *pb.RunReadGrantRequest, _ ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	f.runs = append(f.runs, in)
	action := in.GetRun().GetActionId()
	if err := f.refuse[action]; err != nil {
		return nil, err
	}
	var result []byte
	switch action {
	case inspectActionID:
		result = f.insp
	case imageActionID:
		result = f.img
	default:
		return nil, status.Errorf(codes.Unimplemented, "action %s is not an image lease action", action)
	}
	return &pb.RunReadGrantResponse{ExecutionId: fmt.Sprintf("00000000-0000-4000-9000-%012d", len(f.runs)),
		Result: &pb.RunAttachedResponse{Class: "success", Result: result}}, nil
}

// imgE2EHosts answers the one host of the test with its endpoint.
type imgE2EHosts struct{}

// Get returns the test host; other IDs are unknown.
func (imgE2EHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	if id != ivcHost {
		return inventory.Host{}, inventory.ErrHostNotFound
	}
	return inventory.Host{ID: ivcHost, Endpoints: []inventory.Endpoint{{Address: "192.0.2.10", Port: 22}}}, nil
}

// imgE2EEnv is the executions service with the image observer on one server
// database, the executor fake and the store.
type imgE2EEnv struct {
	db     *sql.DB
	ops    *executions.Service
	img    *vulnImageService
	st     *vulninventory.Store
	exec   *imgE2EExec
	cancel context.CancelFunc
	now    time.Time
}

// newImgE2EEnv opens the server database at path, creates the host of the
// test with the given inventory and starts the executions service the way
// main wires it (the image observer set). The lease is not proposed yet.
func newImgE2EEnv(t *testing.T, path string) *imgE2EEnv {
	t.Helper()
	img, insp := imgE2EFiles(t)
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := inventory.New(db).Create(context.Background(), inventory.Host{ID: ivcHost, DisplayName: "web-e2e.lab",
		Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
		Endpoints: []inventory.Endpoint{{Address: "192.0.2.10", Port: 22}}, CredentialRef: "lab"}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	obs, err := newVulnImageService(db, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulninventory.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	exec := &imgE2EExec{img: img, insp: insp, refuse: map[string]error{}, pending: map[string]*pb.ReadGrant{}}
	ops := executions.New(ctx, exec, db, imgE2EHosts{}, log)
	ops.SetImageObserver(obs)
	e := &imgE2EEnv{db: db, ops: ops, img: obs, st: st, exec: exec, cancel: cancel,
		now: time.Now().UTC().Truncate(time.Second)}
	t.Cleanup(e.close)
	return e
}

// close stops the executions service and closes the database. It is safe to
// call twice.
func (e *imgE2EEnv) close() {
	if e.db == nil {
		return
	}
	e.cancel()
	e.ops.Wait()
	_ = e.db.Close()
	e.db = nil
}

// seedInspect stores the docker.inspect result of the container that names
// the image, finished at at (the earlier one of the lease's read).
func (e *imgE2EEnv) seedInspect(t *testing.T, at time.Time) {
	t.Helper()
	inspectRun(t, e.db, 1, ivcHost, at, e.exec.insp)
}

// propose proposes the image read lease through the executions service and
// approves it with a security-key assertion, as the lease page does. It
// returns the preview of the approved grant.
func (e *imgE2EEnv) propose(t *testing.T) executions.ReadGrantPreview {
	t.Helper()
	ctx := context.Background()
	v, err := e.ops.ProposeImageReadGrant(ctx, "alice", executions.ImageReadGrantRequest{
		HostID: ivcHost, Container: imgE2EContainer, Image: imgE2ERef, Days: executions.ReadGrantShortDays})
	if err != nil {
		t.Fatalf("propose image read lease: %v", err)
	}
	if err := e.ops.CommitReadGrant(ctx, "alice", v.Digest, []byte(`{"id":"assertion"}`)); err != nil {
		t.Fatalf("approve image read lease: %v", err)
	}
	return v
}

// reads returns the number of stored image reads of the host.
func (e *imgE2EEnv) reads(t *testing.T, host string) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT count(*) FROM vuln_image_reads WHERE host_id = ?`, host).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// runActions lists the action IDs the executor was asked to run, in order.
func (e *imgE2EEnv) runActions() []string {
	var out []string
	for _, r := range e.exec.runs {
		out = append(out, r.GetRun().GetActionId())
	}
	return out
}

// imgE2EPage is the part of the export page the test reads.
type imgE2EPage struct {
	Subjects []struct {
		SubjectKind string `json:"subject_kind"`
		SubjectRef  struct {
			ID          string `json:"id"`
			ImageDigest string `json:"image_digest"`
		} `json:"subject_ref"`
		Ecosystem  string `json:"ecosystem"`
		Complete   bool   `json:"complete"`
		Components []struct {
			SourcePackage string `json:"source_package"`
			SourceVersion string `json:"source_version"`
			Binaries      []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"binaries"`
		} `json:"components"`
	} `json:"subjects"`
}

// imgE2ERecord is a finding record for component openssl of the subject with
// the given digest.
func imgE2ERecord(digest string) map[string]any {
	return map[string]any{
		"subject_kind":  "image",
		"subject_ref":   map[string]any{"id": ivcHost, "image_digest": digest},
		"ecosystem":     "debian:bookworm",
		"component":     map[string]any{"source_package": "openssl", "source_version": imgE2EVersion},
		"vuln":          map[string]any{"id": imgE2ECVE},
		"fix":           map[string]any{"state": "fixed", "version": imgE2EFixed},
		"tracker_state": "fixed",
		"match_basis":   "distro_tracker",
		"evidence": map[string]any{"matcher_version": "1.4.0",
			"basis_sources": []any{map[string]any{"source_id": "debian-tracker", "snapshot_id": "snap-debian-tracker", "integrity": "none"}}},
		"assessment": map[string]any{"text": "openssl of the image is below the fixed version"},
	}
}

// imgE2ESources are the feed snapshots of the run (as the agent's run names
// them: the basis of the record is debian-tracker).
func imgE2ESources(now time.Time) []nosclient.SourceSnapshot {
	var out []nosclient.SourceSnapshot
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		out = append(out, nosclient.SourceSnapshot{SourceID: id, SnapshotID: "snap-" + id,
			Integrity: vulnfinding.IntegrityNone, DateKind: nosclient.DateKindData, ContentDate: now.Add(-time.Hour)})
	}
	return out
}

// TestImagePackagesLeaseFindingReachesServerOverHTTP is the chain of the
// image test: an approved lease runs docker.inspect and image.packages with
// the bound parameters, the executions service stores the image read, the
// server exports the image subject over HTTP, and a findings run on the
// snapshot stores one finding that the store lists.
func TestImagePackagesLeaseFindingReachesServerOverHTTP(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := vrConfig(t, dir, serveVTExecutor(t), map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})

	// The lease: one docker.inspect result names the digest, the executor
	// approves a 24 h grant for the container and the image.
	env := newImgE2EEnv(t, filepath.Join(dir, "server.db"))
	env.seedInspect(t, env.now.Add(-10*time.Minute))
	v := env.propose(t)
	if v.ID == "" || len(v.Targets) != 1 || v.Targets[0].HostID != ivcHost || len(v.Actions) != 2 {
		t.Fatalf("preview = id %q targets %v actions %v, want one host and two actions", v.ID, v.Targets, v.Actions)
	}
	if got := v.Expiry.Sub(v.Created); got != executions.ReadGrantShortDays*24*time.Hour {
		t.Fatalf("lease lasts %s, want %d days", got, executions.ReadGrantShortDays)
	}
	if v.MinInterval != executions.ImageLeaseInterval {
		t.Fatalf("minimum interval %s, want the image lease's %s", v.MinInterval, executions.ImageLeaseInterval)
	}

	// One due tick: docker.inspect, then image.packages, each with the
	// parameters the grant binds.
	env.ops.RunDueReadGrants(ctx)
	if got := env.runActions(); len(got) != 2 || got[0] != inspectActionID || got[1] != imageActionID {
		t.Fatalf("runs = %v, want docker.inspect then image.packages", got)
	}
	wantParams := []string{`{"container":"web-app"}`, `{"image":"` + imgE2ERef + `"}`}
	for i, want := range wantParams {
		canon, _, err := canonical.CanonicalParameters([]byte(want))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(env.exec.runs[i].GetRun().GetParametersJson()); got != string(canon) {
			t.Fatalf("run %d sent parameters %s, want the bound %s", i, got, canon)
		}
	}
	var imageParams string
	if err := env.db.QueryRow(`SELECT params FROM executions WHERE schedule_id = ? AND action_id = ?`,
		v.ID, imageActionID).Scan(&imageParams); err != nil {
		t.Fatalf("image.packages execution of the lease: %v", err)
	}
	if !strings.Contains(imageParams, imgE2ERef) {
		t.Fatalf("executions.params of image.packages = %s, want the image", imageParams)
	}

	// Exactly one stored read of the digest, complete.
	var rows int
	var host, digest string
	var complete bool
	if err := env.db.QueryRow(`SELECT count(*), min(host_id), min(digest), min(complete) FROM vuln_image_reads`).Scan(&rows, &host, &digest, &complete); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || host != ivcHost || digest != imgE2EDigest || !complete {
		t.Fatalf("vuln_image_reads: %d rows, host %q digest %q complete %v; want one complete read of %s on %s",
			rows, host, digest, complete, imgE2EDigest, ivcHost)
	}
	env.close()

	// The server over loopback HTTP, with the vuln token through the TLS
	// terminator. The export is the snapshot of the findings run.
	w := &e2eWiring{}
	s := startE2E(t, dir, cfg, nil, w)
	front := e2eFront(t, s.base)
	ca := e2eCAFile(t, dir, front)
	client := e2eClient(t, front.URL, e2eTokenFile(t, dir, "token", vrToken), ca)

	snap, err := client.Export(ctx, func(nosclient.Page) error { return nil })
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	cov, ok := snap.Subject(vulnfinding.SubjectImage, vulnfinding.SubjectRef{ID: ivcHost, ImageDigest: imgE2EDigest})
	if !ok || cov.Parts != 1 {
		t.Fatalf("snapshot has no image subject of %s on %s (parts %d)", imgE2EDigest, ivcHost, cov.Parts)
	}
	imgE2EAssertExport(t, front)

	// The findings run on the snapshot: one finding for an openssl component
	// of the image, accepted; a finding for another digest refused by the API.
	run, err := client.StartRun(ctx, snap, nosclient.StartRequest{MatcherVersion: "1.4.0", Sources: imgE2ESources(time.Now())})
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	if run.InventorySnapshotID != snap.ID {
		t.Fatalf("run bound to %q, want %q", run.InventorySnapshotID, snap.ID)
	}
	// The batch covers the image subject. Its two findings: the one for the
	// image's openssl (stored), and one for a digest outside the snapshot,
	// which the server re-checks against the snapshot and refuses (not stored).
	inRec, err := json.Marshal(imgE2ERecord(imgE2EDigest))
	if err != nil {
		t.Fatal(err)
	}
	outRec, err := json.Marshal(imgE2ERecord(imgE2EOther))
	if err != nil {
		t.Fatal(err)
	}
	sub := nosclient.BatchSubject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: ivcHost, ImageDigest: imgE2EDigest}, Part: 1, LastPart: true}
	res, err := run.Submit(ctx, nosclient.Batch{Seq: 1, Subjects: []nosclient.BatchSubject{sub},
		Findings: []json.RawMessage{inRec, outRec}})
	if err != nil {
		t.Fatalf("findings batch: %v", err)
	}
	if res.Opened != 1 || res.Rejected != 1 || len(res.Rejections) != 1 || res.Rejections[0].Index != 1 ||
		res.Rejections[0].Reason != "subject not in the run's inventory snapshot" {
		t.Fatalf("batch result %+v, want the image finding opened and the outside digest refused with the snapshot reason", res)
	}
	done, err := run.Complete(ctx)
	if err != nil {
		t.Fatalf("complete run: %v", err)
	}
	if done.Completion == nil {
		t.Fatal("complete answered without a completion")
	}
	s.stop()

	// The finding is stored, open, on the image subject, and listed by the
	// store the findings page reads.
	s2 := startE2E(t, dir, cfg, nil, w)
	w.mu.Lock()
	vuln := w.vuln
	w.mu.Unlock()
	if vuln == nil {
		t.Fatal("runServer did not hand out its vulnerability service")
	}
	fs, _, err := vuln.store.List(ctx, vulnstore.ListQuery{
		Subject: &vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: ivcHost, ImageDigest: imgE2EDigest}, Limit: 50})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("%d findings on the image, want exactly one", len(fs))
	}
	f := fs[0]
	if f.State != vulnstore.StateOpen || f.Subject.ImageDigest != imgE2EDigest || f.Record.Vuln.ID != imgE2ECVE ||
		f.Record.Component.SourcePackage != "openssl" {
		t.Fatalf("finding = state %s subject %+v vuln %q source %q", f.State, f.Subject, f.Record.Vuln.ID, f.Record.Component.SourcePackage)
	}
	s2.stop()
}

// imgE2EAssertExport GETs the inventory over the agent API with the vuln
// token and checks the image subject: kind, host ID, digest, ecosystem and
// its three OS components, the openssl one with its two binaries.
func imgE2EAssertExport(t *testing.T, front *httptest.Server) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, front.URL+api.VulnPrefix+"inventory", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+vrToken)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var page imgE2EPage
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&page) != nil {
		t.Fatalf("GET inventory = %d, want a decodable page", resp.StatusCode)
	}
	var sub *struct {
		SubjectKind string `json:"subject_kind"`
		SubjectRef  struct {
			ID          string `json:"id"`
			ImageDigest string `json:"image_digest"`
		} `json:"subject_ref"`
		Ecosystem  string `json:"ecosystem"`
		Complete   bool   `json:"complete"`
		Components []struct {
			SourcePackage string `json:"source_package"`
			SourceVersion string `json:"source_version"`
			Binaries      []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"binaries"`
		} `json:"components"`
	}
	for i := range page.Subjects {
		if page.Subjects[i].SubjectKind == "image" && page.Subjects[i].SubjectRef.ImageDigest == imgE2EDigest {
			sub = &page.Subjects[i]
		}
	}
	if sub == nil {
		t.Fatalf("export has no image subject of %s: %+v", imgE2EDigest, page.Subjects)
	}
	if sub.SubjectRef.ID != ivcHost || sub.Ecosystem != "debian:bookworm" || !sub.Complete {
		t.Fatalf("image subject = host %q ecosystem %q complete %v, want %s debian:bookworm complete",
			sub.SubjectRef.ID, sub.Ecosystem, sub.Complete, ivcHost)
	}
	want := map[string][]string{"base-files": {"base-files"}, "glibc": {"libc6"}, "openssl": {"libssl3", "openssl"}}
	if len(sub.Components) != len(want) {
		t.Fatalf("image components = %d, want %d: %+v", len(sub.Components), len(want), sub.Components)
	}
	for _, c := range sub.Components {
		bins, ok := want[c.SourcePackage]
		if !ok {
			t.Fatalf("unexpected component %q", c.SourcePackage)
		}
		var names []string
		for _, b := range c.Binaries {
			names = append(names, b.Name)
		}
		if strings.Join(names, ",") != strings.Join(bins, ",") {
			t.Fatalf("component %s binaries = %v, want %v", c.SourcePackage, names, bins)
		}
		if c.SourcePackage == "openssl" && c.SourceVersion != imgE2EVersion {
			t.Fatalf("openssl source version = %q, want %q", c.SourceVersion, imgE2EVersion)
		}
	}
}

// TestImagePackagesLeaseNegativeCases is the table of the lease cases that
// store no image read, and of the case in which a fourth read keeps three.
// Each case has its own server database and executor.
func TestImagePackagesLeaseNegativeCases(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		run  func(t *testing.T, e *imgE2EEnv)
	}{
		{
			// The executions service has no docker.inspect that names the
			// digest: the observer refuses the stored read, nothing is stored or
			// exported (the export is built from vuln_image_reads).
			name: "no inspect names the digest",
			run: func(t *testing.T, e *imgE2EEnv) {
				grantRun(t, e.db, 1, ivcHost, imgE2ERef, e.now, e.exec.img)
				e.img.ObserveImage(ctx, ivcHost, execN(1))
				if n := e.reads(t, ivcHost); n != 0 {
					t.Fatalf("%d reads stored without an inspect naming the digest, want 0", n)
				}
				reads, err := e.st.ImageReads(ctx, ivcHost, imgE2EDigest)
				if err != nil {
					t.Fatal(err)
				}
				if subs := imageSubjects(reads); len(subs) != 0 {
					t.Fatalf("export has %d image subjects, want none", len(subs))
				}
			},
		},
		{
			// The executor refuses docker.inspect because the action is not LOW
			// on the host: nothing is stored, and image.packages is not asked in
			// this tick, since it needs the inspect of the same tick.
			name: "executor refuses the action as not LOW",
			run: func(t *testing.T, e *imgE2EEnv) {
				e.seedInspect(t, e.now.Add(-10*time.Minute))
				e.propose(t)
				e.exec.refuse[inspectActionID] = status.Error(codes.PermissionDenied, "the action is not LOW on this host")
				e.ops.RunDueReadGrants(ctx)
				if got := e.runActions(); len(got) != 1 || got[0] != inspectActionID {
					t.Fatalf("runs = %v, want docker.inspect only", got)
				}
				if n := e.reads(t, ivcHost); n != 0 {
					t.Fatalf("%d reads stored after a refused run, want 0", n)
				}
				var n int
				if err := e.db.QueryRow(`SELECT count(*) FROM executions WHERE action_id = ?`, imageActionID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("image.packages executions = %d (%v), want none", n, err)
				}
			},
		},
		{
			// The stored parameters of image.packages do not hash to the grant's
			// ParametersHash: the action is not sent, the inspect still runs.
			name: "stored parameters do not match the grant",
			run: func(t *testing.T, e *imgE2EEnv) {
				e.seedInspect(t, e.now.Add(-10*time.Minute))
				e.propose(t)
				other := `{"image":"registry.example/app/web@sha256:` + strings.Repeat("e", 64) + `"}`
				if _, err := e.db.Exec(`UPDATE read_grant_params SET params = ? WHERE action_id = ?`, other, imageActionID); err != nil {
					t.Fatal(err)
				}
				e.ops.RunDueReadGrants(ctx)
				if got := e.runActions(); len(got) != 1 || got[0] != inspectActionID {
					t.Fatalf("runs = %v, want docker.inspect only", got)
				}
				if n := e.reads(t, ivcHost); n != 0 {
					t.Fatalf("%d reads stored for a mismatched grant, want 0", n)
				}
			},
		},
		{
			// A fourth read keeps three: the lease read is the newest, the
			// observer stores three older reads, and the oldest of the four is
			// pushed out. The export (its subject built from the newest read)
			// shows the lease's read.
			name: "fourth read keeps three and the newest is exported",
			run: func(t *testing.T, e *imgE2EEnv) {
				e.seedInspect(t, e.now.Add(-10*time.Minute))
				e.propose(t)
				e.ops.RunDueReadGrants(ctx)
				if n := e.reads(t, ivcHost); n != 1 {
					t.Fatalf("%d reads after the lease run, want 1", n)
				}
				older := imgE2EOlderRead(e.exec.img)
				for i, back := range []time.Duration{5 * time.Minute, 4 * time.Minute, 3 * time.Minute} {
					grantRun(t, e.db, 10+i, ivcHost, imgE2ERef, e.now.Add(-back), older)
					e.img.ObserveImage(ctx, ivcHost, execN(10+i))
				}
				reads, err := e.st.ImageReads(ctx, ivcHost, imgE2EDigest)
				if err != nil {
					t.Fatal(err)
				}
				if len(reads) != vulninventory.ImageReadsKept {
					t.Fatalf("kept %d reads, want %d", len(reads), vulninventory.ImageReadsKept)
				}
				subs := imageSubjects(reads)
				if len(subs) != 1 {
					t.Fatalf("export has %d image subjects, want 1", len(subs))
				}
				for _, c := range subs[0].Components {
					if c.Source == "openssl" && c.SourceVersion != imgE2EVersion {
						t.Fatalf("export shows openssl %s, want the newest read's %s", c.SourceVersion, imgE2EVersion)
					}
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newImgE2EEnv(t, filepath.Join(t.TempDir(), "server.db"))
			tt.run(t, e)
		})
	}
}
