// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func cuHex(c string) string    { return strings.Repeat(c, 64) }
func cuDigest(c string) string { return "sha256:" + cuHex(c) }

const (
	cuPreviewID  = "00000000-0000-4000-8000-0000000000a1"
	cuPreview2ID = "00000000-0000-4000-8000-0000000000a2"
	cuUpdateID   = "00000000-0000-4000-8000-0000000000b1"
)

// cuPreviewDoc is a valid docker-update-preview-v1 result. Project "site"
// has db, web (depends on db), worker (depends on web with restart) and
// side; project "big" was truncated.
func cuPreviewDoc() map[string]any {
	img := func(id, ref, repo, tag string, old []any, res ...any) map[string]any {
		return map[string]any{"image_id": id, "running_reference": ref, "repository": repo, "tag": tag, "platform": "linux/amd64",
			"old_digests": old, "resolved": res, "reason": ""}
	}
	tgt := func(svc, id, name, image, ref, cfg string) map[string]any {
		return map[string]any{"service": svc, "container_id": id, "container_name": name, "state": "running", "image_id": image,
			"running_reference": ref, "configuration_digest": cfg}
	}
	svc := func(name string, depends ...any) map[string]any {
		if depends == nil {
			depends = []any{}
		}
		return map[string]any{"service": name, "replicas": 1, "scale": 1, "depends": depends, "shares": []any{}, "reasons": []any{}}
	}
	res := func(tag, idx, plat, reason string) map[string]any {
		return map[string]any{"tag": tag, "index_digest": idx, "platform_digest": plat, "reason": reason}
	}
	return map[string]any{
		"format": "docker-update-preview-v1", "status": "ok",
		"units": []any{
			map[string]any{"form": "compose", "project": "big", "container_id": "", "reason": "truncated"},
			map[string]any{"form": "compose", "project": "site", "container_id": "", "reason": "",
				"working_dir_hash": cuHex("1"), "config_files_hash": cuHex("2"), "source_digest": cuHex("3"),
				"services": []any{
					svc("db"),
					svc("side"),
					svc("web", map[string]any{"service": "db", "restart": false}),
					svc("worker", map[string]any{"service": "web", "restart": true}),
				},
				"targets": []any{
					tgt("db", cuHex("3"), "site-db-1", cuDigest("e"), "postgres:16", cuHex("c")),
					tgt("side", cuHex("6"), "site-side-1", cuDigest("f"), "redis:7", cuHex("c")),
					tgt("web", cuHex("1"), "site-web-1", cuDigest("d"), "nginx:1.27", cuHex("c")),
					tgt("worker", cuHex("4"), "site-worker-1", cuDigest("d"), "nginx:1.27", cuHex("b")),
				},
				"images": []any{
					img(cuDigest("d"), "nginx:1.27", "docker.io/library/nginx", "1.27", []any{cuDigest("a")},
						res("1.27", cuDigest("8"), cuDigest("9"), ""),
						res("1.28", cuDigest("6"), cuDigest("5"), ""),
						res("2.0", "", "", "tag_unresolved")),
					img(cuDigest("e"), "postgres:16", "docker.io/library/postgres", "16", []any{cuDigest("7")},
						res("16", "", cuDigest("7"), "")),
					img(cuDigest("f"), "redis:7", "docker.io/library/redis", "7", []any{cuDigest("a")},
						res("7", "", cuDigest("b"), "")),
				}},
		},
	}
}

// cuSite returns the "site" unit of a preview document.
func cuSite(doc map[string]any) map[string]any { return doc["units"].([]any)[1].(map[string]any) }

// cuService returns service i of the "site" unit.
func cuService(doc map[string]any, i int) map[string]any {
	return cuSite(doc)["services"].([]any)[i].(map[string]any)
}

func cuMarshal(t *testing.T, doc any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedPreview stores one docker.update_preview run of host, started and
// finished at the given times, with the shipped preview artifact unless
// sha is set.
func seedPreview(t *testing.T, db *sql.DB, id, host, class string, result []byte, started, finished time.Time, sha string) {
	t.Helper()
	pa, ok := actions.Lookup("docker.update_preview")
	if !ok {
		t.Fatal("docker.update_preview is not in the catalog")
	}
	if sha == "" {
		sha = pa.SHA256()
	}
	if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at)
		VALUES (?, 'docker.update_preview', ?, ?, 'LOW', 'finished', 1, 300, 'axel', ?, ?)`, id, pa.Version, sha, started.Unix(), finished.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:x', 'nebula-default', '[]', 'finished', ?, ?, ?, ?)`, id, host, class, result, started.Unix(), finished.Unix()); err != nil {
		t.Fatal(err)
	}
}

// freshPreviewAt seeds the standard preview of h01, started at age before
// batchNow and finished a minute later.
func freshPreviewAt(t *testing.T, db *sql.DB, age time.Duration) {
	t.Helper()
	seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-age), batchNow.Add(-age+time.Minute), "")
}

func updateMember(services ...ContainerServiceSpec) BatchMemberSpec {
	return BatchMemberSpec{ActionID: "docker.compose_update", HostID: "h01",
		Update: &ContainerUpdateSpec{PreviewExecutionID: cuPreviewID, Project: "site", Services: services}}
}

func oneStage(ms ...BatchMemberSpec) BatchRequest {
	return BatchRequest{Stages: []BatchStageSpec{{Gate: canonical.BatchGateManual, Members: ms}}}
}

func TestComposeUpdateMemberBindsFreshPreview(t *testing.T) {
	f := &fakeBatchExec{}
	b, db := batchSetup(t, f, nil)
	freshPreviewAt(t, db, 10*time.Minute)
	ctx := context.Background()
	c, err := b.ProposeBatch(ctx, "axel", oneStage(updateMember(ContainerServiceSpec{Service: "web"})))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.frozen.Members) != 1 {
		t.Fatalf("frozen %d members", len(f.frozen.Members))
	}
	m := f.frozen.Members[0]
	u := m.ContainerUpdate
	if u == nil || m.Container != nil {
		t.Fatalf("member without its update binding: %+v", m)
	}
	if m.Request.ActionID != "docker.compose_update" || m.Request.ModuleVersion != "2.0.0" || m.Request.RiskClass != canonical.RiskMedium {
		t.Errorf("request %+v", m.Request)
	}
	if u.Kind != "update" || u.Form != "compose" || u.Project != "site" || u.SourceDigest != cuHex("3") ||
		u.WorkingDirHash != cuHex("1") || u.ConfigFilesHash != cuHex("2") || u.RollbackOf != "" || u.Registry != nil {
		t.Errorf("unit identity %+v", u)
	}
	wantImg := canonical.ContainerUpdateImage{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64", OldTag: "1.27", NewTag: "1.27",
		OldDigests: []string{cuDigest("a")}, NewIndexDigest: cuDigest("8"), NewPlatformDigest: cuDigest("9"), OldImageID: cuDigest("d")}
	if len(u.Images) != 1 || !sameJSON(u.Images[0], wantImg) {
		t.Errorf("images %+v", u.Images)
	}
	wantTgt := canonical.ContainerUpdateTarget{Service: "web", ContainerID: cuHex("1"), ContainerName: "site-web-1", ImageID: cuDigest("d"),
		RunningReference: "nginx:1.27", ConfigurationDigest: cuHex("c")}
	if len(u.Targets) != 1 || u.Targets[0] != wantTgt {
		t.Errorf("targets %+v", u.Targets)
	}
	// The dependency closure is the script's: db is required, worker
	// requires web and restarts on it; side is unrelated.
	wantDeps := []canonical.ContainerUpdateDependency{
		{Service: "db", Relation: "requires", Containers: []canonical.ContainerDependencyMember{{ContainerID: cuHex("3"), ContainerName: "site-db-1", ConfigurationDigest: cuHex("c")}}},
		{Service: "worker", Relation: "required_by", RestartOnUpdate: true, Containers: []canonical.ContainerDependencyMember{{ContainerID: cuHex("4"), ContainerName: "site-worker-1", ConfigurationDigest: cuHex("b")}}},
	}
	if !sameJSON(u.Dependencies, wantDeps) {
		t.Errorf("dependencies %+v", u.Dependencies)
	}
	// The parameters are exactly the rendering of the binding.
	want, hash, err := canonical.ContainerUpdateParameters(*u)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.proposed[0].GetMembers()[0].GetParametersJson(); string(got) != string(want) || m.Request.ParametersHash != hash {
		t.Errorf("parameters %s, want %s", got, want)
	}
	v, err := b.Batch(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Members) != 1 || v.Members[0].Params != string(want) || v.Members[0].ActionID != "docker.compose_update" {
		t.Errorf("stored member %+v", v.Members)
	}
}

func TestComposeUpdateTagChangeIsLabelledHigh(t *testing.T) {
	f := &fakeBatchExec{}
	b, db := batchSetup(t, f, nil)
	freshPreviewAt(t, db, maxPreviewBindingAge) // exactly at the bound
	_, err := b.ProposeBatch(context.Background(), "axel", oneStage(updateMember(
		ContainerServiceSpec{Service: "web", NewTag: "1.28", PolicyVersion: "stable-v1", PolicyDigest: cuHex("9")})))
	if err != nil {
		t.Fatal(err)
	}
	m := f.frozen.Members[0]
	img := m.ContainerUpdate.Images[0]
	if m.Request.RiskClass != canonical.RiskHigh || img.NewTag != "1.28" || img.NewPlatformDigest != cuDigest("5") ||
		img.NewIndexDigest != cuDigest("6") || img.PolicyVersion != "stable-v1" || img.PolicyDigest != cuHex("9") || img.MajorChange {
		t.Fatalf("risk %s image %+v", m.Request.RiskClass, img)
	}
}

func TestComposeUpdateRefusals(t *testing.T) {
	policy := func(svc, tag string) ContainerServiceSpec {
		return ContainerServiceSpec{Service: svc, NewTag: tag, PolicyVersion: "stable-v1", PolicyDigest: cuHex("9")}
	}
	web := ContainerServiceSpec{Service: "web"}
	cases := []struct {
		name string
		// seed stores the previews; nil stores the fresh standard one.
		seed func(t *testing.T, db *sql.DB)
		req  BatchRequest
		want error // nil: a BatchInputError without a sentinel
	}{
		{name: "no selection", req: oneStage(BatchMemberSpec{ActionID: "docker.compose_update", HostID: "h01"}), want: ErrBatchPreviewUnit},
		{name: "both selections", req: oneStage(BatchMemberSpec{ActionID: "docker.compose_update", HostID: "h01",
			Update: updateMember(web).Update, Rollback: &ContainerRollbackSpec{PreviewExecutionID: cuPreviewID, RollbackOf: cuUpdateID}}), want: ErrBatchPreviewUnit},
		{name: "selection on another action", req: oneStage(BatchMemberSpec{ActionID: "docker.restart", HostID: "h01",
			Params: map[string]string{"container": cuHex("1")}, Update: updateMember(web).Update})},
		{name: "parameters", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Params = map[string]string{"project": "site"}
			return m
		}()), want: ErrBatchPreviewUnit},
		{name: "other version", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Version = "1.0.0"
			return m
		}())},
		{name: "no preview named", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Update.PreviewExecutionID = ""
			return m
		}()), want: ErrBatchPreviewMissing},
		{name: "unknown preview", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Update.PreviewExecutionID = cuPreview2ID
			return m
		}()), want: ErrBatchPreviewMissing},
		{name: "preview of another host", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h02", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewMissing},
		{name: "failed preview", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h01", "failed", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewMissing},
		{name: "preview of another artifact", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-time.Minute), batchNow, cuHex("0"))
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewMissing},
		{name: "malformed preview result", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h01", "success", []byte(`{"format":"docker-update-preview-v1"}`), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewMissing},
		{name: "stale preview", seed: func(t *testing.T, db *sql.DB) {
			freshPreviewAt(t, db, maxPreviewBindingAge+time.Second)
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewStale},
		{name: "preview from the future", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(time.Minute), batchNow.Add(2*time.Minute), "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewStale},
		{name: "newer preview exists", seed: func(t *testing.T, db *sql.DB) {
			freshPreviewAt(t, db, 20*time.Minute)
			seedPreview(t, db, cuPreview2ID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-5*time.Minute), batchNow.Add(-4*time.Minute), "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewStale},
		{name: "host not prepared", seed: func(t *testing.T, db *sql.DB) {
			seedPreview(t, db, cuPreviewID, "h01", "success", []byte(`{"format":"docker-update-preview-v1","status":"prepare_required","units":[]}`),
				batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewUnit},
		{name: "unknown project", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Update.Project = "shop"
			return m
		}()), want: ErrBatchPreviewUnit},
		{name: "truncated project", req: oneStage(func() BatchMemberSpec {
			m := updateMember(web)
			m.Update.Project = "big"
			return m
		}()), want: ErrBatchPreviewUnit},
		{name: "override drift", seed: func(t *testing.T, db *sql.DB) {
			doc := cuPreviewDoc()
			cuSite(doc)["reason"] = "override_drift"
			seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, doc), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewUnit},
		{name: "service unavailable", seed: func(t *testing.T, db *sql.DB) {
			doc := cuPreviewDoc()
			cuService(doc, 2)["reasons"] = []any{"digest_pinned"}
			seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, doc), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewUnit},
		{name: "namespace sharer not selected", seed: func(t *testing.T, db *sql.DB) {
			doc := cuPreviewDoc()
			cuService(doc, 1)["shares"] = []any{"web"}
			seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, doc), batchNow.Add(-time.Minute), batchNow, "")
		}, req: oneStage(updateMember(web)), want: ErrBatchPreviewUnit},
		{name: "unknown service", req: oneStage(updateMember(ContainerServiceSpec{Service: "mail"})), want: ErrBatchPreviewUnit},
		{name: "no services", req: oneStage(updateMember()), want: ErrBatchPreviewUnit},
		{name: "service twice", req: oneStage(updateMember(web, web)), want: ErrBatchPreviewUnit},
		{name: "tag not previewed", req: oneStage(updateMember(policy("web", "1.29"))), want: ErrBatchPreviewUnit},
		{name: "tag unresolved", req: oneStage(updateMember(policy("web", "2.0"))), want: ErrBatchPreviewUnit},
		{name: "tag change without policy", req: oneStage(updateMember(ContainerServiceSpec{Service: "web", NewTag: "1.28"})), want: ErrBatchPreviewUnit},
		{name: "policy on a same-tag refresh", req: oneStage(updateMember(policy("web", "1.27"))), want: ErrBatchPreviewUnit},
		{name: "service already current", req: oneStage(updateMember(ContainerServiceSpec{Service: "db"})), want: ErrBatchPreviewUnit},
		{name: "same unit twice", req: oneStage(updateMember(web), updateMember(ContainerServiceSpec{Service: "side"})), want: ErrBatchPreviewUnit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchExec{}
			b, db := batchSetup(t, f, nil)
			if tc.seed != nil {
				tc.seed(t, db)
			} else {
				freshPreviewAt(t, db, time.Minute)
			}
			_, err := b.ProposeBatch(context.Background(), "axel", tc.req)
			var ie *BatchInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err = %v, want a BatchInputError", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(f.proposed) != 0 {
				t.Fatal("a refused plan reached the executor")
			}
		})
	}
}

// fakeRecreations answers ListContainerRecreations with rows.
type fakeRecreations struct {
	rows  []*pb.ContainerRecreationInfo
	err   error
	asked []string
}

func (f *fakeRecreations) ListContainerRecreations(_ context.Context, in *pb.ListContainerRecreationsRequest, _ ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error) {
	f.asked = append(f.asked, in.GetHostId())
	if f.err != nil {
		return nil, f.err
	}
	return &pb.ListContainerRecreationsResponse{Recreations: f.rows}, nil
}

// updateRow is the recorded update of web from 1.26 to 1.27 on h01 that
// the standard preview shows as its result.
func updateRow() *pb.ContainerRecreationInfo {
	return &pb.ContainerRecreationInfo{ExecutionId: cuUpdateID, MemberId: "m-001", Kind: "update", HostId: "h01", Form: "compose", Unit: "site",
		State: "recreated", WindowExpiresAtUnix: batchNow.Add(time.Hour).Unix(), HasBaseline: true,
		SourceDigest: cuHex("3"), WorkingDirHash: cuHex("1"), ConfigFilesHash: cuHex("2"),
		Images: []*pb.ContainerRecreationImage{{Service: "web", Repository: "docker.io/library/nginx", OldTag: "1.26", NewTag: "1.27",
			NewPlatformDigest: cuDigest("9"), Platform: "linux/amd64", PolicyVersion: "stable-v1", PolicyDigest: cuHex("9"),
			PriorImageId: cuDigest("2"), RetainedTag: "u-b1-web", RetainedReference: "docker.io/library/nginx:1.26"}},
		Targets: []*pb.ContainerRecreationTarget{{Service: "web", Replica: "1", ContainerName: "site-web-1", Status: "recreated",
			ContainerId: cuHex("1"), ImageId: cuDigest("d"), RunningReference: "nginx:1.27", ConfigurationDigest: cuHex("c")}},
		Dependencies: []*pb.ContainerRecreationDependency{
			{Service: "db", Relation: "requires", Containers: []*pb.ContainerRecreationDependencyMember{{ContainerId: cuHex("3"), ContainerName: "site-db-1", ConfigurationDigest: cuHex("c")}}},
			{Service: "worker", Relation: "required_by", RestartOnUpdate: true, Containers: []*pb.ContainerRecreationDependencyMember{{ContainerId: cuHex("4"), ContainerName: "site-worker-1", ConfigurationDigest: cuHex("b")}}},
		},
		RecoveryPlan: &pb.ContainerRecoveryPlanInfo{HostId: "h01", Unit: "site", Digest: cuHex("5")}}
}

func rollbackMember() BatchMemberSpec {
	return BatchMemberSpec{ActionID: "docker.compose_rollback", HostID: "h01",
		Rollback: &ContainerRollbackSpec{PreviewExecutionID: cuPreviewID, RollbackOf: cuUpdateID}}
}

func TestComposeRollbackMemberBindsRecordedUpdate(t *testing.T) {
	f := &fakeBatchExec{}
	rec := &fakeRecreations{rows: []*pb.ContainerRecreationInfo{updateRow()}}
	b, db := batchSetup(t, f, func(o *BatchOptions) { o.Recreations = rec })
	freshPreviewAt(t, db, 5*time.Minute)
	if _, err := b.ProposeBatch(context.Background(), "axel", oneStage(rollbackMember())); err != nil {
		t.Fatal(err)
	}
	if len(rec.asked) != 1 || rec.asked[0] != "h01" {
		t.Errorf("recreations asked for %v", rec.asked)
	}
	m := f.frozen.Members[0]
	u := m.ContainerUpdate
	if m.Request.ActionID != "docker.compose_rollback" || m.Request.ModuleVersion != "1.0.0" || m.Request.RiskClass != canonical.RiskHigh || u == nil {
		t.Fatalf("member %+v", m)
	}
	if u.Kind != "rollback" || u.RollbackOf != cuUpdateID || u.RecoveryPlanDigest != cuHex("5") || u.Project != "site" || u.SourceDigest != cuHex("3") {
		t.Errorf("binding %+v", u)
	}
	wantImg := canonical.ContainerUpdateImage{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64", OldTag: "1.27", NewTag: "1.26",
		OldDigests: []string{cuDigest("9")}, PolicyVersion: "stable-v1", PolicyDigest: cuHex("9"),
		Rollback: &canonical.ContainerRollbackImage{PriorImageID: cuDigest("2"), RetainedTag: "u-b1-web", RetainedReference: "docker.io/library/nginx:1.26"}}
	if len(u.Images) != 1 || !sameJSON(u.Images[0], wantImg) {
		t.Errorf("images %+v", u.Images)
	}
	if len(u.Targets) != 1 || u.Targets[0].ContainerID != cuHex("1") || len(u.Dependencies) != 2 || !u.Dependencies[1].RestartOnUpdate {
		t.Errorf("targets %+v dependencies %+v", u.Targets, u.Dependencies)
	}
}

func TestComposeRollbackRefusals(t *testing.T) {
	row := func(mod func(*pb.ContainerRecreationInfo)) []*pb.ContainerRecreationInfo {
		r := updateRow()
		mod(r)
		return []*pb.ContainerRecreationInfo{r}
	}
	cases := []struct {
		name string
		rec  RecreationLister
		seed func(t *testing.T, db *sql.DB)
		want error
	}{
		{name: "no recreation list", rec: nil, want: ErrBatchRollbackSource},
		{name: "no such update", rec: &fakeRecreations{}, want: ErrBatchRollbackSource},
		{name: "other host", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.HostId = "h02" })}, want: ErrBatchRollbackSource},
		{name: "rollback of a rollback", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.Kind = "rollback" })}, want: ErrBatchRollbackSource},
		{name: "uncertain update", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.State = "uncertain" })}, want: ErrBatchRollbackSource},
		{name: "no baseline", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.HasBaseline = false })}, want: ErrBatchRollbackSource},
		{name: "window over", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.WindowExpiresAtUnix = batchNow.Unix() })}, want: ErrBatchRollbackSource},
		{name: "no recovery plan", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.RecoveryPlan = nil })}, want: ErrBatchRollbackSource},
		{name: "files changed", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.SourceDigest = cuHex("4") })}, want: ErrBatchRollbackSource},
		{name: "container changed", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) { r.Targets[0].ConfigurationDigest = cuHex("d") })}, want: ErrBatchRollbackSource},
		{name: "dependency changed", rec: &fakeRecreations{rows: row(func(r *pb.ContainerRecreationInfo) {
			r.Dependencies[0].Containers[0].ConfigurationDigest = cuHex("d")
		})}, want: ErrBatchRollbackSource},
		{name: "stale preview", rec: &fakeRecreations{rows: []*pb.ContainerRecreationInfo{updateRow()}}, seed: func(t *testing.T, db *sql.DB) {
			freshPreviewAt(t, db, 2*time.Hour)
		}, want: ErrBatchPreviewStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchExec{}
			b, db := batchSetup(t, f, func(o *BatchOptions) { o.Recreations = tc.rec })
			if tc.seed != nil {
				tc.seed(t, db)
			} else {
				freshPreviewAt(t, db, time.Minute)
			}
			_, err := b.ProposeBatch(context.Background(), "axel", oneStage(rollbackMember()))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(f.proposed) != 0 {
				t.Fatal("a refused plan reached the executor")
			}
		})
	}
}

// TestCriticalContainerMemberHasNoSeparateApproval: the executor's CRITICAL
// refusal of a container member maps to a BatchCriticalError whose text
// says no separate approval exists; other CRITICAL members keep the batch
// default text.
func TestCriticalContainerMemberHasNoSeparateApproval(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"container refusal", status.Error(codes.Internal, "batch member m-001: "+containerCriticalText)},
		{"batch refusal of a container member", status.Error(codes.InvalidArgument, "CRITICAL members cannot be approved in a batch: [m-001]")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchExec{proposeErr: tc.err}
			b, db := batchSetup(t, f, nil)
			freshPreviewAt(t, db, time.Minute)
			_, err := b.ProposeBatch(context.Background(), "axel", oneStage(updateMember(ContainerServiceSpec{Service: "web"})))
			var ce *BatchCriticalError
			if !errors.As(err, &ce) || !errors.Is(err, ErrBatchCritical) {
				t.Fatalf("err = %v, want a BatchCriticalError", err)
			}
			if !ce.Container || len(ce.Members) != 1 || ce.Members[0].MemberID != "m-001" || ce.Advice() != BatchCriticalContainerAdvice {
				t.Fatalf("critical error %+v advice %q", ce, ce.Advice())
			}
			if !strings.Contains(err.Error(), "no separate approval") || strings.Contains(err.Error(), "approve each separately") {
				t.Fatalf("text %q", err.Error())
			}
		})
	}
	f := &fakeBatchExec{critical: []string{"m-001"}}
	b, _ := batchSetup(t, f, nil)
	_, err := b.ProposeBatch(context.Background(), "axel", oneStage(BatchMemberSpec{ActionID: "package.install_all", HostID: "h01"}))
	var ce *BatchCriticalError
	if !errors.As(err, &ce) || ce.Container || ce.Advice() != BatchCriticalAdvice || strings.Contains(err.Error(), "no separate approval") {
		t.Fatalf("non-container critical: %v", err)
	}
}

// TestBatchAnswerWithChangedContainerBindingIsRefused: the executor's
// frozen binding must equal the proposed one field for field.
func TestBatchAnswerWithChangedContainerBindingIsRefused(t *testing.T) {
	f := &fakeBatchExec{tamper: func(p *canonical.Batch) {
		u := p.Members[0].ContainerUpdate.Clone()
		u.Targets[0].ConfigurationDigest = cuHex("d")
		raw, hash, err := canonical.ContainerUpdateParameters(u)
		if err != nil || raw == nil {
			panic(err)
		}
		p.Members[0].ContainerUpdate = &u
		p.Members[0].Request.ParametersHash = hash
	}}
	b, db := batchSetup(t, f, nil)
	freshPreviewAt(t, db, time.Minute)
	if _, err := b.ProposeBatch(context.Background(), "axel", oneStage(updateMember(ContainerServiceSpec{Service: "web"}))); !errors.Is(err, ErrBatchAnswer) {
		t.Fatalf("err = %v, want ErrBatchAnswer", err)
	}
	u := canonical.BatchContainerUpdate{Kind: "update", Project: "site"}
	v := u
	v.Project = "shop"
	if !sameContainerUpdate(nil, nil) || sameContainerUpdate(&u, nil) || sameContainerUpdate(&u, &v) || !sameContainerUpdate(&u, &u) {
		t.Fatal("sameContainerUpdate")
	}
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
