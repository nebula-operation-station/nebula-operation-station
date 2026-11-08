// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestLatestContainerPreviewIsTheNewestFreshRun(t *testing.T) {
	b, db := batchSetup(t, &fakeBatchExec{}, nil)
	ctx := context.Background()
	p, err := b.LatestContainerPreview(ctx, "h01")
	if err != nil || p.ID != "" {
		t.Fatalf("no preview = %+v, %v; want an empty view", p, err)
	}
	seedPreview(t, db, cuPreview2ID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-30*time.Minute), batchNow.Add(-29*time.Minute), "")
	freshPreviewAt(t, db, 10*time.Minute)
	p, err = b.LatestContainerPreview(ctx, "h01")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != cuPreviewID || p.Stale != "" || p.Status != "ok" || len(p.Units) != 2 || !p.StartedAt.Equal(batchNow.Add(-10*time.Minute).Truncate(time.Second)) {
		t.Fatalf("latest = %+v", p)
	}
}

func TestLatestContainerPreviewReportsStaleAndStatus(t *testing.T) {
	ctx := context.Background()
	t.Run("stale", func(t *testing.T) {
		b, db := batchSetup(t, &fakeBatchExec{}, nil)
		freshPreviewAt(t, db, 2*time.Hour)
		p, err := b.LatestContainerPreview(ctx, "h01")
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != cuPreviewID || p.Stale == "" || len(p.Units) != 0 {
			t.Fatalf("stale preview = %+v; want a reason and no units", p)
		}
	})
	t.Run("prepare required", func(t *testing.T) {
		b, db := batchSetup(t, &fakeBatchExec{}, nil)
		doc := map[string]any{"format": "docker-update-preview-v1", "status": "prepare_required", "units": []any{}}
		seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, doc), batchNow.Add(-time.Minute), batchNow, "")
		p, err := b.LatestContainerPreview(ctx, "h01")
		if err != nil {
			t.Fatal(err)
		}
		if p.Status != "prepare_required" || p.Stale != "" || len(p.Units) != 0 {
			t.Fatalf("prepare_required preview = %+v", p)
		}
	})
	t.Run("foreign artifact", func(t *testing.T) {
		b, db := batchSetup(t, &fakeBatchExec{}, nil)
		seedPreview(t, db, cuPreviewID, "h01", "success", cuMarshal(t, cuPreviewDoc()), batchNow.Add(-time.Minute), batchNow, cuHex("0"))
		p, err := b.LatestContainerPreview(ctx, "h01")
		if err != nil {
			t.Fatal(err)
		}
		if p.Stale == "" || len(p.Units) != 0 {
			t.Fatalf("foreign preview = %+v; want it unusable", p)
		}
	})
}

func TestPlanContainerUpdateMatchesTheProposedBinding(t *testing.T) {
	f := &fakeBatchExec{}
	b, db := batchSetup(t, f, nil)
	freshPreviewAt(t, db, 10*time.Minute)
	ctx := context.Background()
	spec := ContainerUpdateSpec{PreviewExecutionID: cuPreviewID, Project: "site", Services: []ContainerServiceSpec{{Service: "web"}}}
	shown, err := b.PlanContainerUpdate(ctx, "h01", spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ProposeBatch(ctx, "axel", oneStage(updateMember(ContainerServiceSpec{Service: "web"}))); err != nil {
		t.Fatal(err)
	}
	if !sameContainerUpdate(&shown, f.frozen.Members[0].ContainerUpdate) {
		t.Fatalf("shown binding %+v differs from the proposed %+v", shown, f.frozen.Members[0].ContainerUpdate)
	}
	if _, err := b.PlanContainerUpdate(ctx, "h01", ContainerUpdateSpec{PreviewExecutionID: cuPreviewID, Project: "big",
		Services: []ContainerServiceSpec{{Service: "web"}}}); !errors.Is(err, ErrBatchPreviewUnit) {
		t.Fatalf("truncated unit = %v, want ErrBatchPreviewUnit", err)
	}
}

func TestPlanContainerRollbackAndRecreations(t *testing.T) {
	rec := &fakeRecreations{rows: []*pb.ContainerRecreationInfo{updateRow()}}
	b, db := batchSetup(t, &fakeBatchExec{}, func(o *BatchOptions) { o.Recreations = rec })
	freshPreviewAt(t, db, 5*time.Minute)
	ctx := context.Background()
	rows, err := b.ContainerRecreations(ctx, "h01")
	if err != nil || len(rows) != 1 || rows[0].GetExecutionId() != cuUpdateID {
		t.Fatalf("recreations = %v, %v", rows, err)
	}
	u, err := b.PlanContainerRollback(ctx, "h01", ContainerRollbackSpec{PreviewExecutionID: cuPreviewID, RollbackOf: cuUpdateID})
	if err != nil {
		t.Fatal(err)
	}
	if u.Kind != "rollback" || u.RollbackOf != cuUpdateID || len(u.Targets) != 1 || u.Targets[0].ContainerID != cuHex("1") {
		t.Fatalf("rollback binding %+v", u)
	}

	none, _ := batchSetup(t, &fakeBatchExec{}, nil)
	if _, err := none.ContainerRecreations(ctx, "h01"); !errors.Is(err, ErrRecreationsUnavailable) {
		t.Fatalf("no recreation source = %v, want ErrRecreationsUnavailable", err)
	}
}
