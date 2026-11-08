// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Through the real interceptor and role table: the recovery plan RPCs are
// admin only; the list and the resolve are server and admin. Every other
// role and an unknown UID are denied before the handler runs.
func TestRecreationRPCRolesThroughInterceptor(t *testing.T) {
	const (
		serverUID uint32 = 40001
		adminUID  uint32 = 40002
		collUID   uint32 = 40003
		discUID   uint32 = 40004
		otherUID  uint32 = 40999
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		collUID:   {peercred.RolePVECollector},
		discUID:   {peercred.Role("discovery")},
	}, MethodRoles())
	adminOnly := []peercred.Role{peercred.RoleAdmin}
	serverAdmin := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin}
	want := map[string][]peercred.Role{
		pb.ExecutorService_SetContainerRecoveryPlan_FullMethodName:   adminOnly,
		pb.ExecutorService_ClearContainerRecoveryPlan_FullMethodName: adminOnly,
		pb.ExecutorService_ListContainerRecreations_FullMethodName:   serverAdmin,
		pb.ExecutorService_ResolveContainerRecreation_FullMethodName: serverAdmin,
	}
	roles := MethodRoles()
	for method, allowed := range want {
		if !slices.Equal(roles[method], allowed) {
			t.Errorf("%s roles %v, want %v", method, roles[method], allowed)
		}
		ok := map[uint32]bool{adminUID: true, serverUID: slices.Contains(allowed, peercred.RoleServer)}
		for _, uid := range []uint32{serverUID, adminUID, collUID, discUID, otherUID} {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
			reached := false
			_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
				func(context.Context, any) (any, error) { reached = true; return nil, nil })
			if ok[uid] {
				if err != nil || !reached {
					t.Errorf("%s uid %d: err %v reached %v, want allowed", method, uid, err, reached)
				}
			} else if status.Code(err) != codes.PermissionDenied || reached {
				t.Errorf("%s uid %d: err %v reached %v, want PermissionDenied", method, uid, err, reached)
			}
		}
	}
}

// The recovery plan is set and cleared only by the local admin, as
// exactly one of a reference or the explicit no_persistent_data
// declaration; the reference is never logged.
func TestRecoveryPlanRPCsAdminOnlyAndExplicit(t *testing.T) {
	e := newReconcileEnv(t)
	const ref = "restic snapshot planted-ref-4c1d of /srv/site"
	set := pb.ExecutorService_SetContainerRecoveryPlan_FullMethodName
	clear := pb.ExecutorService_ClearContainerRecoveryPlan_FullMethodName

	// The server is denied by the role table.
	_, err := callAs(t, trustTestServerUID, set, &pb.SetContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site",
		Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}}, e.svc.SetContainerRecoveryPlan)
	wantCode(t, err, codes.PermissionDenied)
	_, err = callAs(t, trustTestServerUID, clear, &pb.ClearContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site"}, e.svc.ClearContainerRecoveryPlan)
	wantCode(t, err, codes.PermissionDenied)

	// The handlers refuse a non-admin caller even behind a widened table.
	wide := peercred.NewPolicy(map[uint32][]peercred.Role{7: {peercred.RoleServer}},
		map[string][]peercred.Role{set: {peercred.RoleServer}, clear: {peercred.RoleServer}})
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: 7}})
	_, err = wide.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: set}, func(ctx context.Context, _ any) (any, error) {
		return e.svc.SetContainerRecoveryPlan(ctx, &pb.SetContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site",
			Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}})
	})
	wantCode(t, err, codes.PermissionDenied)
	_, err = wide.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: clear}, func(ctx context.Context, _ any) (any, error) {
		return e.svc.ClearContainerRecoveryPlan(ctx, &pb.ClearContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site"})
	})
	wantCode(t, err, codes.PermissionDenied)

	for name, req := range map[string]*pb.SetContainerRecoveryPlanRequest{
		"neither":             {HostId: "web-1", Unit: "site"},
		"no data false":       {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{}},
		"empty reference":     {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_Reference{}},
		"blank reference":     {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_Reference{Reference: "  "}},
		"control characters":  {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_Reference{Reference: "x\x1b[2J"}},
		"oversize reference":  {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_Reference{Reference: strings.Repeat("a", maxRecoveryReferenceBytes+1)}},
		"invalid UTF-8":       {HostId: "web-1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_Reference{Reference: "a\xffb"}},
		"bad host":            {HostId: "Web 1", Unit: "site", Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}},
		"blank unit":          {HostId: "web-1", Unit: "", Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}},
		"oversize unit":       {HostId: "web-1", Unit: strings.Repeat("u", maxRecoveryUnitBytes+1), Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}},
		"unit with a newline": {HostId: "web-1", Unit: "si\nte", Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}},
	} {
		if _, err := callAs(t, trustTestAdminUID, set, req, e.svc.SetContainerRecoveryPlan); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := e.db.ContainerRecoveryPlan("web-1", "site"); err == nil {
		t.Fatal("a refused set recorded a plan")
	}

	got, err := callAs(t, trustTestAdminUID, set, &pb.SetContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site",
		Plan: &pb.SetContainerRecoveryPlanRequest_Reference{Reference: ref}}, e.svc.SetContainerRecoveryPlan)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := e.db.ContainerRecoveryPlan("web-1", "site")
	if err != nil {
		t.Fatal(err)
	}
	p := got.GetPlan()
	if p.GetKind() != executordb.RecoveryPlanReference || p.GetReference() != ref || p.GetVersion() != 1 ||
		p.GetDigest() != stored.Digest() || !strings.HasPrefix(p.GetActor(), "admin:") || p.GetRecordedAtUnix() == 0 {
		t.Fatalf("plan %+v, stored %+v", p, stored)
	}
	got, err = callAs(t, trustTestAdminUID, set, &pb.SetContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site",
		Plan: &pb.SetContainerRecoveryPlanRequest_NoPersistentData{NoPersistentData: true}}, e.svc.SetContainerRecoveryPlan)
	if err != nil || got.GetPlan().GetVersion() != 2 || got.GetPlan().GetKind() != executordb.RecoveryNoData || got.GetPlan().GetDigest() == p.GetDigest() {
		t.Fatalf("second set %+v %v", got, err)
	}
	if _, err := callAs(t, trustTestAdminUID, clear, &pb.ClearContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site"}, e.svc.ClearContainerRecoveryPlan); err != nil {
		t.Fatal(err)
	}
	_, err = callAs(t, trustTestAdminUID, clear, &pb.ClearContainerRecoveryPlanRequest{HostId: "web-1", Unit: "site"}, e.svc.ClearContainerRecoveryPlan)
	wantCode(t, err, codes.NotFound)
	if len(e.logs.find("container_recovery_plan_set", "")) != 2 || len(e.logs.find("container_recovery_plan_cleared", "")) != 1 {
		t.Fatal("recovery plan changes not audited")
	}
	noLeak(t, e, "planted-ref-4c1d")
}

// The list carries metadata only: no recreation definition, no baseline,
// no host key, no batch digest. Yet it carries every value a rollback
// binding must equal: a binding built from the list alone passes the
// executor's rollback source check.
func TestListContainerRecreationsMetadataOnly(t *testing.T) {
	e := newReconcileEnv(t)
	row, _, want := rollbackFixture(t, time.Now())
	// A batch digest no fixture value shares, so its absence is meaningful.
	row.BatchDigest = hexOf("0")
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	if err := e.db.CompleteContainerRecreation(row.ExecutionID, executordb.RecreationCompletion{State: row.State, Baseline: row.Baseline,
		Containers: row.Containers, Images: row.Images, Verdict: row.Verdict}, time.Now(), DefaultRollbackWindow); err != nil {
		t.Fatal(err)
	}
	plan, err := e.db.SetContainerRecoveryPlan("web-1", "site", executordb.RecoveryNoData, "", "admin:uid0")
	if err != nil {
		t.Fatal(err)
	}
	list := pb.ExecutorService_ListContainerRecreations_FullMethodName
	resp, err := callAs(t, trustTestServerUID, list, &pb.ListContainerRecreationsRequest{HostId: "web-1"}, e.svc.ListContainerRecreations)
	if err != nil || len(resp.GetRecreations()) != 1 {
		t.Fatalf("list %+v %v", resp, err)
	}
	if other, err := callAs(t, trustTestAdminUID, list, &pb.ListContainerRecreationsRequest{HostId: "db-1"}, e.svc.ListContainerRecreations); err != nil || len(other.GetRecreations()) != 0 {
		t.Fatalf("other host %+v %v", other, err)
	}
	_, err = callAs(t, trustTestAdminUID, list, &pb.ListContainerRecreationsRequest{HostId: "Web 1"}, e.svc.ListContainerRecreations)
	wantCode(t, err, codes.InvalidArgument)

	info := resp.GetRecreations()[0]
	if info.GetExecutionId() != row.ExecutionID || info.GetState() != executordb.RecreationRecreated || !info.GetHasBaseline() ||
		info.GetKind() != canonical.ContainerUpdateKindUpdate || info.GetUnit() != "site" || info.GetWindowExpiresAtUnix() == 0 ||
		!info.GetVerdict().GetJudged() || !info.GetVerdict().GetPassed() || info.GetRecoveryPlan().GetDigest() != plan.Digest() {
		t.Fatalf("info %+v", info)
	}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	// Definition-only, baseline-only and row-internal values.
	var baseline []snapshotEntry
	if err := json.Unmarshal(row.Baseline, &baseline); err != nil || len(baseline) == 0 {
		t.Fatalf("fixture baseline %v", err)
	}
	for _, needle := range []string{"prior_override_entry", "priorOverrideEntry", "replicas_before", "replicasBefore",
		"prior_references", "priorReferences", baseline[0].StartedAt, baseline[0].Mounts[0].Source, "site_default",
		"80/tcp->0.0.0.0:8080", row.HostKey, row.BatchDigest} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("list carries %q", needle)
		}
	}

	// Rebuild the rollback binding from the list alone.
	rb := canonical.BatchContainerUpdate{Kind: canonical.ContainerUpdateKindRollback, Form: info.GetForm(), Project: info.GetUnit(),
		SourceDigest: info.GetSourceDigest(), WorkingDirHash: info.GetWorkingDirHash(), ConfigFilesHash: info.GetConfigFilesHash(),
		RollbackOf: info.GetExecutionId(), RecoveryPlanDigest: info.GetRecoveryPlan().GetDigest()}
	for _, img := range info.GetImages() {
		rb.Images = append(rb.Images, canonical.ContainerUpdateImage{Service: img.GetService(), Repository: img.GetRepository(),
			Platform: img.GetPlatform(), OldTag: img.GetNewTag(), NewTag: img.GetOldTag(), OldDigests: []string{img.GetNewPlatformDigest()},
			PolicyVersion: img.GetPolicyVersion(), PolicyDigest: img.GetPolicyDigest(), MajorChange: img.GetMajorChange(),
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: img.GetPriorImageId(), RetainedTag: img.GetRetainedTag(),
				RetainedReference: img.GetRetainedReference()}})
	}
	for _, tg := range info.GetTargets() {
		if tg.GetStatus() == executordb.ContainerMissing || !slices.ContainsFunc(info.GetImages(), func(i *pb.ContainerRecreationImage) bool { return i.GetService() == tg.GetService() }) {
			continue
		}
		rb.Targets = append(rb.Targets, canonical.ContainerUpdateTarget{Service: tg.GetService(), ContainerID: tg.GetContainerId(),
			ContainerName: tg.GetContainerName(), ImageID: tg.GetImageId(), RunningReference: tg.GetRunningReference(),
			ConfigurationDigest: tg.GetConfigurationDigest()})
	}
	for _, d := range info.GetDependencies() {
		cd := canonical.ContainerUpdateDependency{Service: d.GetService(), Relation: d.GetRelation(), RestartOnUpdate: d.GetRestartOnUpdate()}
		for _, m := range d.GetContainers() {
			cd.Containers = append(cd.Containers, canonical.ContainerDependencyMember{ContainerID: m.GetContainerId(),
				ContainerName: m.GetContainerName(), ConfigurationDigest: m.GetConfigurationDigest()})
		}
		rb.Dependencies = append(rb.Dependencies, cd)
	}
	stored, err := e.db.GetContainerRecreation(row.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRollbackSource(rb, stored, &plan, "web-1", time.Now()); err != nil {
		t.Fatalf("binding from the list: %v", err)
	}
	if !jsonEqual(rb.Targets, want.Targets) || !jsonEqual(rb.Images[0].Rollback, want.Images[0].Rollback) {
		t.Fatalf("binding from the list %+v, fixture %+v", rb, want)
	}
}

// --- resolve ------------------------------------------------------------

// pvTarget is one container a test preview reports.
type pvTarget struct{ svc, id, name, image, ref, cfg string }

// frozenTargets are the containers of testComposeUpdate as they were
// before the update: web (recreated) and db (dependency).
func frozenTargets() []pvTarget {
	u := testComposeUpdate()
	w, d := u.Targets[0], u.Dependencies[0].Containers[0]
	return []pvTarget{
		{w.Service, w.ContainerID, w.ContainerName, w.ImageID, w.RunningReference, w.ConfigurationDigest},
		{"db", d.ContainerID, d.ContainerName, digestOf("e"), "postgres:16", d.ConfigurationDigest},
	}
}

// previewResult renders a docker-update-preview-v1 result with project
// "site" holding targets (reason "" or override_drift).
func previewResult(t *testing.T, reason string, targets []pvTarget) []byte {
	t.Helper()
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].svc != targets[j].svc {
			return targets[i].svc < targets[j].svc
		}
		return targets[i].id < targets[j].id
	})
	count := map[string]int{}
	var tgts []any
	images := map[[2]string]bool{}
	for _, x := range targets {
		count[x.svc]++
		tgts = append(tgts, map[string]any{"service": x.svc, "container_id": x.id, "container_name": x.name, "state": "running",
			"image_id": x.image, "running_reference": x.ref, "configuration_digest": x.cfg})
		images[[2]string{x.image, x.ref}] = true
	}
	var keys [][2]string
	for k := range images {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var imgs []any
	for _, k := range keys {
		ref, err := canonical.ParseImageReference(k[1])
		if err != nil {
			t.Fatal(err)
		}
		imgs = append(imgs, map[string]any{"image_id": k[0], "running_reference": k[1], "repository": ref.Repository, "tag": ref.Tag,
			"platform": "", "old_digests": []any{}, "resolved": []any{}, "reason": "platform_unknown"})
	}
	var svcs []any
	var names []string
	for s := range count {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		svcs = append(svcs, map[string]any{"service": s, "replicas": count[s], "scale": count[s], "depends": []any{}, "shares": []any{}, "reasons": []any{}})
	}
	b, err := json.Marshal(map[string]any{"format": "docker-update-preview-v1", "status": "ok", "units": []any{
		map[string]any{"form": "compose", "project": "site", "container_id": "", "reason": reason,
			"working_dir_hash": hexOf("6"), "config_files_hash": hexOf("7"), "source_digest": hexOf("5"),
			"services": svcs, "targets": tgts, "images": imgs},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resolveRow writes an uncertain update row of e.host whose run finished
// now and returns its execution ID. With open, the row's run is left
// unfinished.
func resolveRow(t *testing.T, e *reconcileEnv, state string, open bool) string {
	t.Helper()
	run := testDispatchRun(t, testComposeUpdate())
	run.ExecutionID = newTestUUID()
	row, err := recreationIntent(run, e.host, "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreateRun(executordb.Run{ExecutionID: run.ExecutionID, HostID: e.host, Digest: hexOf("b"),
		Endpoints: []string{"127.0.0.1:22"}, Fingerprint: e.fp, Timeout: time.Hour, ActionID: composeUpdateAction, MemberID: "member-0"}); err != nil {
		t.Fatal(err)
	}
	if !open {
		if err := e.db.FinishRun(executordb.Run{ExecutionID: run.ExecutionID, HostID: e.host, Class: "unknown"}); err != nil {
			t.Fatal(err)
		}
	}
	if state != executordb.RecreationIntent {
		if err := e.db.CompleteContainerRecreation(run.ExecutionID, executordb.RecreationCompletion{State: state,
			Verdict: executordb.RecreationVerdict{Findings: []string{"the run closed without a result (unknown)"}}},
			time.Now(), DefaultRollbackWindow); err != nil {
			t.Fatal(err)
		}
	}
	return run.ExecutionID
}

// previewRunOn stores a finished classic run of actionID on host with
// result and class; memberID "" is a classic run.
func previewRunOn(t *testing.T, e *reconcileEnv, host, actionID, memberID, class string, result []byte) string {
	t.Helper()
	id := newTestUUID()
	if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: host, Digest: hexOf("b"), Endpoints: []string{"127.0.0.1:22"},
		Fingerprint: e.fp, Timeout: updatePreviewTimeout, ActionID: actionID, MemberID: memberID}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.FinishRun(executordb.Run{ExecutionID: id, HostID: host, Class: class, Result: result}); err != nil {
		t.Fatal(err)
	}
	return id
}

// nextSecond waits until the store's second-resolution clock has moved
// past every run finished so far.
func nextSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 20*time.Millisecond).Sub(now))
}

func resolveAs(t *testing.T, e *reconcileEnv, uid uint32, exec, preview string) (*pb.ResolveContainerRecreationResponse, error) {
	t.Helper()
	return callAs(t, uid, pb.ExecutorService_ResolveContainerRecreation_FullMethodName,
		&pb.ResolveContainerRecreationRequest{ExecutionId: exec, PreviewExecutionId: preview}, e.svc.ResolveContainerRecreation)
}

func openPrivilegedSession(t *testing.T, e *reconcileEnv, sign func([]byte) []byte) {
	t.Helper()
	b, err := e.svc.BeginPrivilegedSession(context.Background(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CompletePrivilegedSession(context.Background(), &pb.CompletePrivilegedSessionRequest{AssertionJson: sign(b.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
}

func requireState(t *testing.T, e *reconcileEnv, exec, state string) executordb.ContainerRecreation {
	t.Helper()
	row, err := e.db.GetContainerRecreation(exec)
	if err != nil || row.State != state {
		t.Fatalf("row %s state %q %v, want %s", exec, row.State, err, state)
	}
	return row
}

// A server resolve needs the executor's privileged session; the local
// admin resolves through its peer credentials.
func TestResolveRequiresPrivilegedSession(t *testing.T) {
	e, sign := sessionRPCEnv(t, 30*time.Minute)
	serverRow := resolveRow(t, e, executordb.RecreationUncertain, false)
	adminRow := resolveRow(t, e, executordb.RecreationUncertain, false)
	nextSecond()
	preview := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", previewResult(t, "", frozenTargets()))

	_, err := resolveAs(t, e, trustTestServerUID, serverRow, preview)
	if !strings.Contains(status.Convert(err).Message(), "privileged session") {
		t.Fatalf("server without session: %v", err)
	}
	wantCode(t, err, codes.FailedPrecondition)
	requireState(t, e, serverRow, executordb.RecreationUncertain)

	if _, err := resolveAs(t, e, trustTestAdminUID, adminRow, preview); err != nil {
		t.Fatalf("admin: %v", err)
	}
	requireState(t, e, adminRow, executordb.RecreationNotRecreated)

	openPrivilegedSession(t, e, sign)
	if _, err := resolveAs(t, e, trustTestServerUID, serverRow, preview); err != nil {
		t.Fatalf("server with session: %v", err)
	}
	requireState(t, e, serverRow, executordb.RecreationNotRecreated)
}

// Only an uncertain row is resolved; every other state is refused and
// left as it is.
func TestResolveOnlyUncertainRows(t *testing.T) {
	e := newReconcileEnv(t)
	rows := map[string]string{}
	for _, st := range []string{executordb.RecreationIntent, executordb.RecreationNotRecreated, executordb.RecreationRecreated,
		executordb.RecreationPartial} {
		rows[resolveRow(t, e, st, false)] = st
	}
	rb := resolveRow(t, e, executordb.RecreationPartial, false)
	if err := e.db.MarkContainerRecreationRolledBack(rb); err != nil {
		t.Fatal(err)
	}
	rows[rb] = executordb.RecreationRolledBack
	nextSecond()
	preview := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", previewResult(t, "", frozenTargets()))
	for exec, st := range rows {
		_, err := resolveAs(t, e, trustTestAdminUID, exec, preview)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "only an uncertain row") {
			t.Errorf("%s row: %v", st, err)
		}
		requireState(t, e, exec, st)
	}
	_, err := resolveAs(t, e, trustTestAdminUID, newTestUUID(), preview)
	wantCode(t, err, codes.NotFound)
}

// The evidence is a finished, retained, classic docker.update_preview run
// of the row's host that started after the row's run finished, with a
// readable result holding the unit with complete facts. Anything else is
// refused and the row stays uncertain.
func TestResolveRefusesWrongEvidence(t *testing.T) {
	e := newReconcileEnv(t)
	good := previewResult(t, "", frozenTargets())
	early := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", good)
	row := resolveRow(t, e, executordb.RecreationUncertain, false)
	openRow := resolveRow(t, e, executordb.RecreationUncertain, true)
	nextSecond()
	released := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", good)
	if err := e.db.ReleaseRun(released, e.host); err != nil {
		t.Fatal(err)
	}
	truncated, err := json.Marshal(map[string]any{"format": "docker-update-preview-v1", "status": "ok", "units": []any{
		map[string]any{"form": "compose", "project": "site", "container_id": "", "reason": "truncated"}}})
	if err != nil {
		t.Fatal(err)
	}
	otherProject := strings.Replace(string(good), `"project":"site"`, `"project":"shop"`, 1)
	cases := map[string]struct {
		preview string
		code    codes.Code
	}{
		"before the row's run finished": {early, codes.FailedPrecondition},
		"another action":                {previewRunOn(t, e, e.host, composeUpdateAction, "", "success", good), codes.FailedPrecondition},
		"a batch member":                {previewRunOn(t, e, e.host, updatePreviewAction, "member-0", "success", good), codes.FailedPrecondition},
		"another host":                  {previewRunOn(t, e, "other-host", updatePreviewAction, "", "success", good), codes.FailedPrecondition},
		"failed run":                    {previewRunOn(t, e, e.host, updatePreviewAction, "", "failed", good), codes.FailedPrecondition},
		"released result":               {released, codes.FailedPrecondition},
		"unknown run":                   {newTestUUID(), codes.FailedPrecondition},
		"not a preview result":          {previewRunOn(t, e, e.host, updatePreviewAction, "", "success", []byte(`{"format":"x"}`)), codes.FailedPrecondition},
		"prepare required": {previewRunOn(t, e, e.host, updatePreviewAction, "", "success",
			[]byte(`{"format":"docker-update-preview-v1","status":"prepare_required","units":[]}`)), codes.FailedPrecondition},
		"truncated unit":  {previewRunOn(t, e, e.host, updatePreviewAction, "", "success", truncated), codes.FailedPrecondition},
		"project missing": {previewRunOn(t, e, e.host, updatePreviewAction, "", "success", []byte(otherProject)), codes.FailedPrecondition},
		"malformed ID":    {"not-an-id", codes.InvalidArgument},
		"the row itself":  {row, codes.InvalidArgument},
	}
	for name, c := range cases {
		_, err := resolveAs(t, e, trustTestAdminUID, row, c.preview)
		if status.Code(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
		requireState(t, e, row, executordb.RecreationUncertain)
	}
	// The row's own run is still open.
	fresh := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", good)
	_, err = resolveAs(t, e, trustTestAdminUID, openRow, fresh)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not finished") {
		t.Fatalf("open run: %v", err)
	}
	requireState(t, e, openRow, executordb.RecreationUncertain)
	if ok, err := e.db.HostHasUncertainRecreation(e.host); err != nil || !ok {
		t.Fatal("refusals changed the uncertain rows")
	}
	if len(e.logs.find("container_recreation_resolved", "")) != 0 {
		t.Fatal("a refused resolve was audited as resolved")
	}
}

// Every frozen container unchanged gives not_recreated (also beside
// override_drift); a recreated, changed or missing container gives
// partial with the preview's incarnations; never recreated. The window is
// not extended, the resolve is audited, and the list shows the result.
func TestResolveMatchesPreview(t *testing.T) {
	e := newReconcileEnv(t)
	u := testComposeUpdate()
	frozen := frozenTargets()
	recreatedWeb := frozen[0]
	recreatedWeb.id, recreatedWeb.image, recreatedWeb.cfg = hexOf("8"), digestOf("9"), hexOf("a")
	changedCfg := frozen[0]
	changedCfg.cfg = hexOf("b")
	extra := pvTarget{"web", hexOf("c"), "site-web-2", digestOf("9"), "nginx:1.27", hexOf("a")}
	cases := []struct {
		name    string
		reason  string
		targets []pvTarget
		state   string
		web     string // status of the frozen web container
	}{
		{"unchanged", "", frozen, executordb.RecreationNotRecreated, executordb.ContainerUnchanged},
		{"unchanged beside override drift", "override_drift", frozen, executordb.RecreationNotRecreated, executordb.ContainerUnchanged},
		{"recreated", "", []pvTarget{recreatedWeb, frozen[1]}, executordb.RecreationPartial, executordb.ContainerRecreated},
		{"same container, other facts", "", []pvTarget{changedCfg, frozen[1]}, executordb.RecreationPartial, executordb.ContainerUnchanged},
		{"missing", "", []pvTarget{frozen[1]}, executordb.RecreationPartial, executordb.ContainerMissing},
		{"new replica", "", []pvTarget{frozen[0], extra, frozen[1]}, executordb.RecreationPartial, executordb.ContainerUnchanged},
	}
	rows := make([]string, len(cases))
	for i := range cases {
		rows[i] = resolveRow(t, e, executordb.RecreationUncertain, false)
	}
	nextSecond()
	for i, c := range cases {
		before := requireState(t, e, rows[i], executordb.RecreationUncertain)
		preview := previewRunOn(t, e, e.host, updatePreviewAction, "", "success", previewResult(t, c.reason, c.targets))
		resp, err := resolveAs(t, e, trustTestAdminUID, rows[i], preview)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := requireState(t, e, rows[i], c.state)
		if !got.WindowExpiresAt.Equal(before.WindowExpiresAt) || got.Verdict.Judged || got.Verdict.Passed ||
			!strings.Contains(got.Verdict.Findings[len(got.Verdict.Findings)-1], preview) {
			t.Fatalf("%s: row %+v", c.name, got)
		}
		web := got.Containers[0]
		if web.Service != "web" || web.IDBefore != u.Targets[0].ContainerID || web.Status != c.web {
			t.Fatalf("%s: web %+v", c.name, web)
		}
		if c.web != executordb.ContainerMissing {
			want := c.targets[slices.IndexFunc(c.targets, func(p pvTarget) bool { return p.svc == "web" && p.name == "site-web-1" })]
			if web.IDAfter != want.id || web.ImageAfter != want.image || web.ConfigAfter != want.cfg || web.ReferenceAfter != want.ref {
				t.Fatalf("%s: web after %+v, want %+v", c.name, web, want)
			}
		}
		if c.name == "new replica" && (len(got.Containers) != 2 || got.Containers[1].IDAfter != extra.id || got.Containers[1].Status != executordb.ContainerRecreated) {
			t.Fatalf("new replica not recorded: %+v", got.Containers)
		}
		info := resp.GetRecreation()
		if info.GetState() != c.state || len(info.GetTargets()) != len(got.Containers) || info.GetTargets()[0].GetStatus() != c.web {
			t.Fatalf("%s: response %+v", c.name, info)
		}
		if len(e.logs.find("container_recreation_resolved", rows[i])) != 1 {
			t.Fatalf("%s: resolve not audited", c.name)
		}
		// Resolved once: the row is no longer uncertain.
		_, err = resolveAs(t, e, trustTestAdminUID, rows[i], preview)
		wantCode(t, err, codes.FailedPrecondition)
	}
}
