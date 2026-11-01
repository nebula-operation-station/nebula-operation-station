// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect_test

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

var telKey = "SHA256:" + strings.Repeat("k", 43)

type telExec struct {
	mu    sync.Mutex
	pins  []*pb.HostKeyPin
	runs  []*pb.RunReadGrantRequest
	reply *pb.RunAttachedResponse
	err   error
}

func (e *telExec) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: e.pins}, nil
}

func (e *telExec) RunReadGrant(_ context.Context, in *pb.RunReadGrantRequest, _ ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runs = append(e.runs, in)
	if e.err != nil {
		return nil, e.err
	}
	return &pb.RunReadGrantResponse{ExecutionId: "x1", Result: e.reply}, nil
}

type telHosts map[string]inventory.Host

func (h telHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	if x, ok := h[id]; ok {
		return x, nil
	}
	return inventory.Host{}, inventory.ErrHostNotFound
}

func telB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func telMetricsDoc(cpu, mem, disk string) []byte {
	return []byte(`{"format":"host-metrics-v1","phase":"done","cpu":"` + telB64(cpu) + `","mem":"` + telB64(mem) + `","disk":"` + telB64(disk) + `"}`)
}

func telSetup(reply *pb.RunAttachedResponse) (*telExec, pvecollect.SSHTelemetryReader) {
	e := &telExec{
		pins:  []*pb.HostKeyPin{{HostId: "host-1", Fingerprint: telKey, CredentialRef: "ssh-default"}},
		reply: reply,
	}
	hosts := telHosts{"host-1": {ID: "host-1", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5"}, {Address: "host1.lan", Port: 2222}}}}
	return e, pvecollect.SSHTelemetryReader{Exec: e, Hosts: hosts}
}

func telTarget(action string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{Source: pvecollect.TelemetrySSH, HostID: "host-1", HostKey: telKey, ActionID: action}
}

func telApprox(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestSSHTelemetryRunsUnderNamedGrantWithExactBinding(t *testing.T) {
	e, r := telSetup(&pb.RunAttachedResponse{Class: "success", Result: telMetricsDoc("25.0", "1024 4096", "/\t30\t100")})
	tg := telTarget("host.metrics")
	out, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: tg, Live: true, GrantID: "g-tel"})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.runs) != 1 {
		t.Fatalf("runs = %d", len(e.runs))
	}
	req := e.runs[0]
	a, _ := actions.Lookup("host.metrics")
	run := req.GetRun()
	if req.GetGrantId() != "g-tel" || req.GetTrigger() != pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND ||
		run.GetHostId() != "host-1" || run.GetHostKeyFingerprint() != telKey || run.GetActionId() != "host.metrics" ||
		run.GetModuleVersion() != a.Version || string(run.GetArtifact()) != string(a.Script) || string(run.GetParametersJson()) != "{}" ||
		run.GetCredentialRef() != "ssh-default" || run.GetExecutionDigest() != "" {
		t.Fatalf("request = %v", req)
	}
	if len(req.GetEndpoints()) != 2 || req.GetEndpoints()[0] != "10.0.0.5:22" || req.GetEndpoints()[1] != "host1.lan:2222" {
		t.Fatalf("endpoints = %v", req.GetEndpoints())
	}
	if req.GetTimeoutSeconds() == 0 || time.Duration(req.GetTimeoutSeconds())*time.Second > 20*time.Second {
		t.Fatalf("timeout = %d", req.GetTimeoutSeconds())
	}
	want := map[string]float64{pvecollect.TelemetryMetricCPU: 0.25, pvecollect.TelemetryMetricRAM: 0.25, pvecollect.TelemetryMetricDisk: 0.3}
	if len(out) != 3 {
		t.Fatalf("samples = %+v", out)
	}
	for _, s := range out {
		if s.Target != tg || !telApprox(s.Value, want[s.Metric]) {
			t.Fatalf("sample = %+v", s)
		}
	}

	// History reads use the scheduled trigger.
	if _, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: tg, GrantID: "g-tel"}); err != nil {
		t.Fatal(err)
	}
	if e.runs[1].GetTrigger() != pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED {
		t.Fatalf("history trigger = %v", e.runs[1].GetTrigger())
	}
}

func TestSSHTelemetryFilesystemFullestIsDisk(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "executions", "hostmetrics", "testdata", "proxmox-fs.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, r := telSetup(&pb.RunAttachedResponse{Class: "success", Result: raw})
	out, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: telTarget("filesystem.list"), GrantID: "g"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Metric != pvecollect.TelemetryMetricDisk || !telApprox(out[0].Value, 644245094400.0/1099511627776.0) {
		t.Fatalf("samples = %+v", out)
	}
}

func TestSSHTelemetryUnavailableIsMissingNotZero(t *testing.T) {
	for name, reply := range map[string]*pb.RunAttachedResponse{
		"precheck":       {Class: "success", Result: []byte(`{"format":"host-metrics-v1","phase":"precheck","reason":"` + telB64("no /proc/stat") + `"}`)},
		"empty values":   {Class: "success", Result: []byte(`{"format":"host-metrics-v1","phase":"done"}`)},
		"failed run":     {Class: "script_failed", Result: telMetricsDoc("25", "1 2", "/\t1\t2")},
		"unreachable":    {Class: "network_unreachable"},
		"key mismatch":   {Class: "host_key_mismatch"},
		"precheck class": {Class: "precheck_failed"},
	} {
		_, r := telSetup(reply)
		out, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: telTarget("host.metrics"), GrantID: "g"})
		if err != nil || len(out) != 0 {
			t.Errorf("%s: out=%+v err=%v", name, out, err)
		}
	}
}

func TestSSHTelemetryRejectsMalformedResult(t *testing.T) {
	for name, res := range map[string][]byte{
		"not json":       []byte("{"),
		"unknown format": []byte(`{"format":"other","phase":"done"}`),
		"oversized":      []byte(`{"format":"host-metrics-v1","phase":"done","cpu":"` + strings.Repeat("A", 2<<20) + `"}`),
	} {
		_, r := telSetup(&pb.RunAttachedResponse{Class: "success", Result: res})
		if out, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: telTarget("host.metrics"), GrantID: "g"}); err == nil {
			t.Errorf("%s: accepted %+v", name, out)
		}
	}
}

func TestSSHTelemetryStaleOrBlockedHostKeyNeverRuns(t *testing.T) {
	for name, pin := range map[string]*pb.HostKeyPin{
		"replaced key": {HostId: "host-1", Fingerprint: "SHA256:" + strings.Repeat("z", 43)},
		"blocked":      {HostId: "host-1", Fingerprint: telKey, Blocked: true},
		"no pin":       {HostId: "host-2", Fingerprint: telKey},
	} {
		e, r := telSetup(&pb.RunAttachedResponse{Class: "success"})
		e.pins = []*pb.HostKeyPin{pin}
		if _, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: telTarget("host.metrics"), GrantID: "g"}); !errors.Is(err, pvecollect.ErrTelemetryHostKey) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(e.runs) != 0 {
			t.Errorf("%s: ran anyway", name)
		}
	}
}

func TestSSHTelemetryRefusesUnsupportedOrMalformedReads(t *testing.T) {
	e, r := telSetup(&pb.RunAttachedResponse{Class: "success"})
	cases := map[string]pvecollect.TelemetryRead{
		"gpu action (no box metric)": {Target: telTarget("gpu.status"), GrantID: "g"},
		"non-telemetry action":       {Target: telTarget("package.list_updates"), GrantID: "g"},
		"provider target":            {Target: pvecollect.TelemetryTarget{Source: pvecollect.TelemetryProvider, RemoteID: "remote-a"}, GrantID: "g"},
		"no grant":                   {Target: telTarget("host.metrics")},
	}
	for name, rd := range cases {
		if _, err := r.ReadTelemetry(context.Background(), rd); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	unknown := telTarget("host.metrics")
	unknown.HostID = "ghost"
	if _, err := r.ReadTelemetry(context.Background(), pvecollect.TelemetryRead{Target: unknown, GrantID: "g"}); !errors.Is(err, inventory.ErrHostNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if len(e.runs) != 0 {
		t.Fatalf("refused reads reached the executor: %d", len(e.runs))
	}
}

func TestTelemetryHostKeysSkipsBlockedHosts(t *testing.T) {
	e := &telExec{pins: []*pb.HostKeyPin{
		{HostId: "host-1", Fingerprint: telKey},
		{HostId: "host-2", Fingerprint: telKey, Blocked: true},
		{HostId: "host-3"},
	}}
	keys, err := pvecollect.TelemetryHostKeys(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys["host-1"] != telKey {
		t.Fatalf("keys = %v", keys)
	}
}

// TestSSHTelemetrySchedulerLeaseFlow drives the scheduler with the SSH
// reader: history every five minutes, one run per host at a time, and a
// lock stops runs.
func TestSSHTelemetrySchedulerLeaseFlow(t *testing.T) {
	e, r := telSetup(&pb.RunAttachedResponse{Class: "success", Result: telMetricsDoc("10", "1 2", "/\t1\t4")})
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	sink := &telSinkExec{}
	s, err := pvecollect.NewTelemetryScheduler(r, sink, pvecollect.TelemetryConfig{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLeases([]pvecollect.TelemetryLease{{
		GrantID: "g-tel", GrantDigest: "d", Scheduled: true, ExpiresAt: now.Add(time.Hour),
		MinInterval: 10 * time.Second, RunBudget: 100,
		Targets: []pvecollect.TelemetryTarget{telTarget("host.metrics"), telTarget("filesystem.list")},
	}}); err != nil {
		t.Fatal(err)
	}
	rep := s.RunOnce(context.Background())
	if rep.Issued != 1 || len(e.runs) != 1 || rep.Recorded != 3 {
		t.Fatalf("first pass: %+v runs=%d", rep, len(e.runs))
	}
	now = now.Add(time.Second)
	s.RunOnce(context.Background())
	if len(e.runs) != 2 {
		t.Fatalf("second action not run: %d", len(e.runs))
	}
	s.Lock()
	now = now.Add(10 * time.Minute)
	if rep := s.RunOnce(context.Background()); rep.Issued != 0 || len(e.runs) != 2 {
		t.Fatalf("ran while locked: %+v", rep)
	}
}

type telSinkExec struct {
	mu sync.Mutex
	n  int
}

func (s *telSinkExec) RecordTelemetry(context.Context, pvecollect.TelemetrySample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return nil
}
