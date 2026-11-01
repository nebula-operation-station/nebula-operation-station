// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func newBucketStore(t *testing.T, clk *fakeClock) *pveinventory.Store {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatalf("serverdb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return pveinventory.NewWithNow(db, clk.Now)
}

// TestTelemetryFeedsMetricBuckets runs the scheduler with the provider
// reader into the real P1-25 store: one history sample per five-minute
// bucket, live samples sharing the current bucket, no zero filling.
func TestTelemetryFeedsMetricBuckets(t *testing.T) {
	clk := &fakeClock{t: telT0}
	store := newBucketStore(t, clk)
	tg := provTarget("remote-a", 101, 2)
	cpu := 0.2
	fr := &fakeReader{readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		p := req.GetMetrics()
		return metricsResp(req.GetRemoteId(), p.GetNode(), p.GetKind(), p.GetVmid(),
			&pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: cpu},
			&pb.PVEMetric{Name: "mem_used", Unit: "bytes", Value: 1},
			&pb.PVEMetric{Name: "mem_total", Unit: "bytes", Value: 4}), nil
	}}
	s, err := NewTelemetryScheduler(ProviderTelemetryReader{Reader: fr}, BucketSink{Store: store}, TelemetryConfig{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLeases([]TelemetryLease{lease("g1", true, true, telT0.Add(2*time.Hour), 4096, tg)}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Three history buckets.
	for range 3 {
		s.RunOnce(ctx)
		clk.Add(TelemetryHistoryInterval)
	}
	// A viewer opens the page: live samples land in the current bucket.
	if _, err := s.Request("v", tg); err != nil {
		t.Fatal(err)
	}
	cpu = 0.6
	for range 3 {
		s.RunOnce(ctx)
		clk.Add(TelemetryLiveInterval)
	}
	mt := pveinventory.MetricTarget{RemoteID: "remote-a", Kind: pveinventory.MetricTargetGuest, VMID: 101, Generation: 2}
	sum, err := store.GetMetricSummary(ctx, mt, pveinventory.MetricCPU)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Valid || sum.BucketsValid != 4 || sum.Samples != 6 || sum.Current != 0.6 {
		t.Fatalf("summary = %+v", sum)
	}
	ram, err := store.GetMetricSummary(ctx, mt, pveinventory.MetricRAM)
	if err != nil || !ram.Valid || ram.Current != 0.25 {
		t.Fatalf("ram = %+v %v", ram, err)
	}
	// The node series was never leased: nothing, not zero.
	node := pveinventory.MetricTarget{RemoteID: "remote-a", Kind: pveinventory.MetricTargetNode, Node: "pve1"}
	if ns, err := store.GetMetricSummary(ctx, node, pveinventory.MetricCPU); err != nil || ns.Valid {
		t.Fatalf("node = %+v %v", ns, err)
	}
}

func TestBucketSinkSSHNeedsLinkedTarget(t *testing.T) {
	clk := &fakeClock{t: telT0}
	store := newBucketStore(t, clk)
	smp := TelemetrySample{Target: sshTarget("host-1", "filesystem.list"), Metric: TelemetryMetricDisk, Value: 0.7}
	if err := (BucketSink{Store: store}).RecordTelemetry(context.Background(), smp); !errors.Is(err, ErrNoMetricTarget) {
		t.Fatalf("unlinked host: %v", err)
	}
	guest := pveinventory.MetricTarget{RemoteID: "remote-a", Kind: pveinventory.MetricTargetGuest, VMID: 101, Generation: 2}
	link := func(_ context.Context, host string) (pveinventory.MetricTarget, bool) { return guest, host == "host-1" }
	if err := (BucketSink{Store: store, SSHTarget: link}).RecordTelemetry(context.Background(), smp); err != nil {
		t.Fatal(err)
	}
	sum, err := store.GetMetricSummary(context.Background(), guest, pveinventory.MetricDisk)
	if err != nil || !sum.Valid || sum.Current != 0.7 {
		t.Fatalf("disk = %+v %v", sum, err)
	}
	// Provider samples never become filesystem disk usage.
	pd := TelemetrySample{Target: provTarget("remote-a", 101, 2), Metric: TelemetryMetricDisk, Value: 0.5}
	if err := (BucketSink{Store: store}).RecordTelemetry(context.Background(), pd); !errors.Is(err, ErrNoMetricTarget) {
		t.Fatalf("provider disk: %v", err)
	}
}
