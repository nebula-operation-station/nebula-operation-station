// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const pveMetricsGrantID = "00000000-0000-4000-8000-0000000000e9"

var (
	pveNodeTarget  = permit.ProviderMetricsTarget{Node: "pve1", Kind: permit.MetricsKindNode}
	pveGuestTarget = permit.ProviderMetricsTarget{Node: "pve1", Kind: permit.MetricsKindQEMU, VMID: 100, Generation: 3}
)

func (e *pveReadEnv) setMetricsBodies() {
	e.pve.set("/api2/json/nodes/pve1/status", `{"data":{"cpu":0.25,"memory":{"used":400,"total":1000},"netin":10,"netout":20}}`)
	e.pve.set("/api2/json/nodes/pve1/qemu/100/status/current", `{"data":{"status":"running","cpu":0.5,"mem":100,"maxmem":200,"maxdisk":5000,"netin":7}}`)
	for vmid := range 6 {
		e.pve.set("/api2/json/nodes/pve1/qemu/"+strconv.Itoa(101+vmid)+"/status/current", `{"data":{"status":"running","cpu":0.1}}`)
	}
}

func (e *pveReadEnv) telemetryDoc(id string, budget int64, trigger string, targets ...permit.ProviderMetricsTarget) []byte {
	e.t.Helper()
	rm := e.remote()
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: id, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(permit.DefaultReadGrantLifetime).Unix(), Trigger: trigger,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 10, RunBudget: budget, RateProfile: permit.ProviderTelemetryProfile,
		ProviderTargets: []permit.ProviderTarget{{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
			CredentialVersion: rm.Credentials.ReadVersion, Methods: []string{permit.ProviderMethodMetrics}, MetricsTargets: targets}},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *pveReadEnv) readMetrics(t permit.ProviderMetricsTarget, live bool) (*pb.ReadPVEResponse, error) {
	return e.svc.ReadPVE(context.Background(), &pb.ReadPVERequest{RemoteId: pveReadRemote, Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS,
		Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{Node: t.Node, Kind: t.Kind, Vmid: t.VMID, Generation: t.Generation, Live: live}}})
}

func metricValue(m *pb.PVEMetrics, name string) (float64, bool) {
	for _, x := range m.GetMetrics() {
		if x.GetName() == name {
			return x.GetValue(), true
		}
	}
	return 0, false
}

func TestReadPVEMetricsReturnsFixedMetricsUnderTelemetryGrant(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.setMetricsBodies()
	e.approve(e.telemetryDoc(pveMetricsGrantID, 100, permit.TriggerBoth, pveNodeTarget, pveGuestTarget))

	got, err := e.readMetrics(pveNodeTarget, false)
	if err != nil {
		t.Fatal(err)
	}
	m := got.GetMetrics()
	if m.GetState() != pveAvailable || m.GetNode() != "pve1" || m.GetKind() != "node" || m.GetVmid() != 0 {
		t.Fatalf("node metrics = %v", m)
	}
	if v, ok := metricValue(m, pveMetricCPU); !ok || v != 0.25 {
		t.Fatalf("cpu = %v %v", v, ok)
	}
	if _, ok := metricValue(m, pveMetricDiskRead); ok {
		t.Fatal("a metric PVE did not report is present")
	}
	e.clock.Add(2 * time.Second)
	got, err = e.readMetrics(pveGuestTarget, true)
	if err != nil {
		t.Fatal(err)
	}
	m = got.GetMetrics()
	if m.GetState() != pveAvailable || m.GetStatus() != "running" || m.GetVmid() != 100 {
		t.Fatalf("guest metrics = %v", m)
	}
	if v, ok := metricValue(m, pveMetricDiskAllocated); !ok || v != 5000 {
		t.Fatalf("disk_allocated = %v %v", v, ok)
	}
	if e.pve.badAuth.Load() != 0 {
		t.Fatal("a request carried the wrong credential")
	}
}

// Metrics need the telemetry profile and the exact target; an inventory
// grant, another target or a different guest generation authorizes nothing.
func TestReadPVEMetricsDeniedWithoutExactTelemetryGrant(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.setMetricsBodies()
	_, err := e.readMetrics(pveNodeTarget, false)
	wantPveCode(t, err, codes.PermissionDenied)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
	e.clock.Add(2 * time.Second)
	_, err = e.readMetrics(pveNodeTarget, false)
	wantPveCode(t, err, codes.PermissionDenied)

	e.approve(e.telemetryDoc(pveMetricsGrantID, 100, permit.TriggerScheduled, pveGuestTarget))
	recreated := pveGuestTarget
	recreated.Generation++
	for name, tc := range map[string]struct {
		target permit.ProviderMetricsTarget
		live   bool
	}{
		"other target":         {pveNodeTarget, false},
		"recreated guest":      {recreated, false},
		"live under scheduled": {pveGuestTarget, true},
		"other kind":           {permit.ProviderMetricsTarget{Node: "pve1", Kind: permit.MetricsKindLXC, VMID: 100, Generation: 3}, false},
	} {
		e.clock.Add(2 * time.Second)
		_, err = e.readMetrics(tc.target, tc.live)
		if err == nil {
			t.Fatalf("%s: read authorized", name)
		}
		wantPveCode(t, err, codes.PermissionDenied)
	}
	if e.pve.requests.Load() != 0 {
		t.Fatalf("%d requests reached PVE without authority", e.pve.requests.Load())
	}
	// A denied request holds no live slot and no rate slot.
	e.pve.set("/api2/json/nodes/pve1/qemu/100/status/current", `{"data":{"status":"running"}}`)
	if _, err := e.readMetrics(pveGuestTarget, false); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReadPVERequestMetricsShape(t *testing.T) {
	req := func(p *pb.PVEReadMetricsParams) *pb.ReadPVERequest {
		r := &pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS}
		if p != nil {
			r.Params = &pb.ReadPVERequest_Metrics{Metrics: p}
		}
		return r
	}
	for name, tc := range map[string]struct {
		r  *pb.ReadPVERequest
		ok bool
	}{
		"node":                {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "node"}), true},
		"guest":               {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "lxc", Vmid: 200, Generation: 1, Live: true}), true},
		"no params":           {req(nil), false},
		"guest param":         {&pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_METRICS, Params: &pb.ReadPVERequest_Guest{Guest: &pb.PVEReadGuestParams{Vmid: 100}}}, false},
		"node with vmid":      {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "node", Vmid: 100}), false},
		"guest without gen":   {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "qemu", Vmid: 100}), false},
		"guest vmid 0":        {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "qemu", Generation: 1}), false},
		"bad kind":            {req(&pb.PVEReadMetricsParams{Node: "pve1", Kind: "vm", Vmid: 100, Generation: 1}), false},
		"bad node":            {req(&pb.PVEReadMetricsParams{Node: "../x", Kind: "node"}), false},
		"tasks with metrics":  {&pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_TASKS, Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{Node: "pve1", Kind: "node"}}}, false},
		"nodes with metrics":  {&pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_NODES, Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{Node: "pve1", Kind: "node"}}}, false},
		"config with metrics": {&pb.ReadPVERequest{RemoteId: "pve-1", Method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{Node: "pve1", Kind: "node"}}}, false},
	} {
		if err := ValidateReadPVERequest(tc.r); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

// One metrics request per second and four live targets per remote; a live
// target frees its slot 30 s after its last renewal.
func TestReadPVEMetricsPerRemoteCaps(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.setMetricsBodies()
	targets := []permit.ProviderMetricsTarget{pveNodeTarget}
	for i := range 6 {
		targets = append(targets, permit.ProviderMetricsTarget{Node: "pve1", Kind: permit.MetricsKindQEMU, VMID: uint64(101 + i), Generation: 1})
	}
	e.approve(e.telemetryDoc(pveMetricsGrantID, 1000, permit.TriggerBoth, targets...))

	if _, err := e.readMetrics(targets[0], true); err != nil {
		t.Fatal(err)
	}
	_, err := e.readMetrics(targets[1], true)
	wantPveCode(t, err, codes.ResourceExhausted)
	for _, tg := range targets[1:4] {
		e.clock.Add(time.Second)
		if _, err := e.readMetrics(tg, true); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.Add(time.Second)
	_, err = e.readMetrics(targets[4], true)
	wantPveCode(t, err, codes.ResourceExhausted)
	// History reads are not live targets.
	e.clock.Add(time.Second)
	if _, err := e.readMetrics(targets[5], false); err != nil {
		t.Fatal(err)
	}
	// The first live target stopped renewing 30 s ago; its slot is free.
	e.clock.Add(26 * time.Second)
	if _, err := e.readMetrics(targets[4], true); err != nil {
		t.Fatal(err)
	}
}

// Live reads keep the 10-s floor per exact target and spend the remote's
// separate telemetry budget.
func TestReadPVEMetricsIntervalAndBudget(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.setMetricsBodies()
	e.approve(e.telemetryDoc(pveMetricsGrantID, 2, permit.TriggerBoth, pveNodeTarget))
	if _, err := e.readMetrics(pveNodeTarget, true); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(5 * time.Second)
	_, err := e.readMetrics(pveNodeTarget, true)
	wantPveCode(t, err, codes.ResourceExhausted)
	e.clock.Add(10 * time.Second)
	if _, err := e.readMetrics(pveNodeTarget, true); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(10 * time.Second)
	_, err = e.readMetrics(pveNodeTarget, true)
	wantPveCode(t, err, codes.ResourceExhausted)
}

func TestReadPVEMetricsTrustChangeBlocksRemote(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	e.setMetricsBodies()
	e.approve(e.telemetryDoc(pveMetricsGrantID, 100, permit.TriggerBoth, pveNodeTarget))
	impostor := makeTestChain(t)
	e.pve.srv.TLS.Certificates = []tls.Certificate{impostor.tls}
	e.pve.srv.CloseClientConnections()
	_, err := e.readMetrics(pveNodeTarget, false)
	wantPveCode(t, err, codes.FailedPrecondition)
	if e.pve.requests.Load() != 0 || e.pve.badAuth.Load() != 0 {
		t.Fatal("a request reached the impostor")
	}
	grants, err := e.svc.auth.ReadGrants()
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatalf("telemetry grant not revoked: %v %v", grants, err)
	}
}

func TestReadPVEMetricsHostileValuesUnavailable(t *testing.T) {
	for name, body := range map[string]string{
		"cpu above one":     `{"data":{"cpu":7,"memory":{"used":1,"total":2}}}`,
		"negative memory":   `{"data":{"cpu":0.1,"memory":{"used":-1,"total":2}}}`,
		"used above total":  `{"data":{"cpu":0.1,"memory":{"used":5,"total":2}}}`,
		"not an object":     `{"data":"<script>"}`,
		"status hostile":    `{"data":{"cpu":0.1,"status":"<script>alert(1)</script>"}}`,
		"oversized garbage": `{"data":{"cpu":0.1,"x":"` + strings.Repeat("A", 2<<20) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindStandalone)
			e.approve(e.telemetryDoc(pveMetricsGrantID, 100, permit.TriggerBoth, pveNodeTarget))
			e.pve.set("/api2/json/nodes/pve1/status", body)
			got, err := e.readMetrics(pveNodeTarget, false)
			if err != nil {
				t.Fatal(err)
			}
			m := got.GetMetrics()
			if text := got.String(); strings.Contains(text, "<script>") || strings.Contains(text, "s3cr3t") {
				t.Fatalf("hostile value passed: %.200s", text)
			}
			if name == "status hostile" {
				if m.GetState() == pveAvailable && m.GetStatus() != "unknown" {
					t.Fatalf("status = %q", m.GetStatus())
				}
				return
			}
			if m.GetState() != pveUnavailable || len(m.GetMetrics()) != 0 {
				t.Fatalf("metrics = %v", m)
			}
			if r := m.GetReason(); r != pveReasonRead && r != pveReasonInvalid {
				t.Fatalf("reason %q is not fixed", r)
			}
		})
	}
}
