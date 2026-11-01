// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

func metricsResp(remote, node, kind string, vmid uint64, ms ...*pb.PVEMetric) *pb.ReadPVEResponse {
	return &pb.ReadPVEResponse{RemoteId: remote, Payload: &pb.ReadPVEResponse_Metrics{Metrics: &pb.PVEMetrics{
		State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE, Node: node, Kind: kind, Vmid: vmid, Metrics: ms,
	}}}
}

func TestProviderTelemetryReaderBuildsExactTypedRequest(t *testing.T) {
	tg := provTarget("remote-a", 101, 7)
	var got *pb.ReadPVERequest
	fr := &fakeReader{readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		got = req
		return metricsResp("remote-a", "pve1", "qemu", 101,
			&pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: 0.25},
			&pb.PVEMetric{Name: "mem_used", Unit: "bytes", Value: 1 << 30},
			&pb.PVEMetric{Name: "mem_total", Unit: "bytes", Value: 4 << 30},
			&pb.PVEMetric{Name: "disk_allocated", Unit: "bytes", Value: 1 << 40},
		), nil
	}}
	out, err := ProviderTelemetryReader{Reader: fr}.ReadTelemetry(context.Background(), TelemetryRead{Target: tg, Live: true})
	if err != nil {
		t.Fatal(err)
	}
	p := got.GetMetrics()
	if got.GetMethod() != pb.PVEReadMethod_PVE_READ_METHOD_METRICS || got.GetRemoteId() != "remote-a" || p == nil ||
		p.GetNode() != "pve1" || p.GetKind() != "qemu" || p.GetVmid() != 101 || p.GetGeneration() != 7 || !p.GetLive() {
		t.Fatalf("request = %v", got)
	}
	if len(out) != 2 || out[0].Metric != TelemetryMetricCPU || out[0].Value != 0.25 || out[1].Metric != TelemetryMetricRAM || out[1].Value != 0.25 {
		t.Fatalf("samples = %+v", out)
	}
	for _, s := range out {
		if s.Metric == TelemetryMetricDisk {
			t.Fatal("PVE disk allocation mapped to filesystem disk")
		}
	}
}

func TestProviderTelemetryReaderUnavailableIsMissingNotZero(t *testing.T) {
	fr := &fakeReader{readFn: func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		return &pb.ReadPVEResponse{RemoteId: "remote-a", Payload: &pb.ReadPVEResponse_Metrics{Metrics: &pb.PVEMetrics{
			State: pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE, Reason: "read failed"}}}, nil
	}}
	out, err := ProviderTelemetryReader{Reader: fr}.ReadTelemetry(context.Background(), TelemetryRead{Target: provTarget("remote-a", 0, 0)})
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestProviderTelemetryReaderRejectsMismatchedOrMalformed(t *testing.T) {
	tg := provTarget("remote-a", 101, 1)
	ok := func() []*pb.PVEMetric { return []*pb.PVEMetric{{Name: "cpu", Unit: "ratio", Value: 0.5}} }
	cases := map[string]*pb.ReadPVEResponse{
		"other remote": metricsResp("remote-b", "pve1", "qemu", 101, ok()...),
		"other vmid":   metricsResp("remote-a", "pve1", "qemu", 102, ok()...),
		"other node":   metricsResp("remote-a", "pve2", "qemu", 101, ok()...),
		"other kind":   metricsResp("remote-a", "pve1", "lxc", 101, ok()...),
		"no payload":   {RemoteId: "remote-a"},
		"wrong payload": {RemoteId: "remote-a", Payload: &pb.ReadPVEResponse_Nodes{Nodes: &pb.PVENodes{
			State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE}}},
		"no state":       {RemoteId: "remote-a", Payload: &pb.ReadPVEResponse_Metrics{Metrics: &pb.PVEMetrics{Node: "pve1", Kind: "qemu", Vmid: 101}}},
		"duplicate name": metricsResp("remote-a", "pve1", "qemu", 101, append(ok(), ok()...)...),
		"nan":            metricsResp("remote-a", "pve1", "qemu", 101, &pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: math.NaN()}),
		"cpu unit":       metricsResp("remote-a", "pve1", "qemu", 101, &pb.PVEMetric{Name: "cpu", Unit: "percent", Value: 50}),
		"mem unit":       metricsResp("remote-a", "pve1", "qemu", 101, &pb.PVEMetric{Name: "mem_used", Unit: "kib", Value: 5}),
		"nil metric":     metricsResp("remote-a", "pve1", "qemu", 101, nil),
	}
	var many []*pb.PVEMetric
	for i := range maxMetricsPerResponse + 1 {
		many = append(many, &pb.PVEMetric{Name: "m" + itoa(i), Unit: "bytes", Value: 1})
	}
	cases["too many metrics"] = metricsResp("remote-a", "pve1", "qemu", 101, many...)
	for name, resp := range cases {
		fr := &fakeReader{readFn: func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) { return resp, nil }}
		if out, err := (ProviderTelemetryReader{Reader: fr}).ReadTelemetry(context.Background(), TelemetryRead{Target: tg}); err == nil {
			t.Errorf("%s: accepted, samples %+v", name, out)
		}
	}
	big := metricsResp("remote-a", "pve1", "qemu", 101, &pb.PVEMetric{Name: strings.Repeat("x", maxMetricsResponseBytes), Unit: "bytes"})
	fr := &fakeReader{readFn: func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) { return big, nil }}
	if _, err := (ProviderTelemetryReader{Reader: fr}).ReadTelemetry(context.Background(), TelemetryRead{Target: tg}); !errors.Is(err, ErrOversize) {
		t.Errorf("oversize: %v", err)
	}
	// Out-of-range values are dropped rather than clamped.
	fr = &fakeReader{readFn: func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		return metricsResp("remote-a", "pve1", "qemu", 101,
			&pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: 1.5},
			&pb.PVEMetric{Name: "mem_used", Unit: "bytes", Value: 5},
			&pb.PVEMetric{Name: "mem_total", Unit: "bytes", Value: 0}), nil
	}}
	if out, err := (ProviderTelemetryReader{Reader: fr}).ReadTelemetry(context.Background(), TelemetryRead{Target: tg}); err != nil || len(out) != 0 {
		t.Errorf("out of range: %+v %v", out, err)
	}
	// SSH targets are not provider reads.
	if _, err := (ProviderTelemetryReader{Reader: fr}).ReadTelemetry(context.Background(), TelemetryRead{Target: sshTarget("h", "host.metrics")}); !errors.Is(err, ErrTelemetryInvalid) {
		t.Errorf("ssh target: %v", err)
	}
}

// grantFixture builds an approved read grant as ListReadGrants returns it.
func grantFixture(t *testing.T, id string, now time.Time, mut func(*permit.ReadGrantDoc)) *pb.ReadGrant {
	t.Helper()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: id, Issuer: "admin",
		CreatedUnix: now.Add(-time.Hour).Unix(), ExpiryUnix: now.Add(6 * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerBoth, MinIntervalS: 10, RunBudget: 600,
		RateProfile: permit.ProviderTelemetryProfile,
		ProviderTargets: []permit.ProviderTarget{{
			RemoteID: "remote-a", TrustPin: testPin, TrustGeneration: 1, CredentialVersion: 1,
			Methods: []string{permit.ProviderMethodMetrics},
			MetricsTargets: []permit.ProviderMetricsTarget{
				{Node: "pve1", Kind: "node"},
				{Node: "pve1", Kind: "qemu", VMID: 101, Generation: 2},
			},
		}},
	}
	if mut != nil {
		mut(&d)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	_, canon, digest, err := permit.ParseReadGrant(raw, now)
	if err != nil {
		t.Fatalf("fixture grant invalid: %v", err)
	}
	return &pb.ReadGrant{GrantId: id, GrantDigest: digest, CanonicalGrant: canon, ApprovedBy: "admin", CreatedUnix: d.CreatedUnix, ExpiryUnix: d.ExpiryUnix}
}

func sshGrantMut(d *permit.ReadGrantDoc) {
	d.RateProfile = schedgrant.TelemetryReadProfile
	d.ProviderTargets = nil
	d.Trigger = permit.TriggerScheduled
	d.RunBudget = 100
	d.Actions = []permit.ReadGrantAction{
		{ActionID: "host.metrics", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)},
	}
	d.Targets = []canonical.Target{{HostID: "host-1", HostKeyFingerprint: hostKey1}, {HostID: "host-2", HostKeyFingerprint: hostKey2}}
	d.Credentials = []permit.ReadGrantCredential{
		{HostID: "host-1", CredentialRef: "ssh-default", CredentialVersion: "SHA256:" + strings.Repeat("c", 43)},
		{HostID: "host-2", CredentialRef: "ssh-default", CredentialVersion: "SHA256:" + strings.Repeat("c", 43)},
	}
}

var (
	hostKey1 = "SHA256:" + strings.Repeat("1", 43)
	hostKey2 = "SHA256:" + strings.Repeat("2", 43)
)

const (
	gid1 = "11111111-1111-4111-8111-111111111111"
	gid2 = "22222222-2222-4222-8222-222222222222"
	gid3 = "33333333-3333-4333-8333-333333333333"
)

func activeRemoteInfo() *pb.PVERemoteInfo {
	return &pb.PVERemoteInfo{RemoteId: "remote-a", TrustPin: testPin, TrustGeneration: 1, State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE}
}

func TestTelemetryLeasesFromProviderGrant(t *testing.T) {
	now := telT0
	g := grantFixture(t, gid1, now, nil)
	ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, TelemetryIdentities{Remotes: []*pb.PVERemoteInfo{activeRemoteInfo()}}, now)
	if len(ls) != 1 {
		t.Fatalf("leases = %+v", ls)
	}
	l := ls[0]
	if l.GrantID != gid1 || l.GrantDigest != g.GrantDigest || !l.Scheduled || !l.OnDemand || l.RunBudget != 600 ||
		l.MinInterval != 10*time.Second || !l.ExpiresAt.Equal(time.Unix(g.ExpiryUnix, 0)) || len(l.Targets) != 2 {
		t.Fatalf("lease = %+v", l)
	}
	want := provTarget("remote-a", 101, 2)
	if l.Targets[1] != want {
		t.Fatalf("target = %+v, want %+v", l.Targets[1], want)
	}
}

func TestTelemetryLeasesDropStaleOrForeignGrants(t *testing.T) {
	now := telT0
	ids := TelemetryIdentities{Remotes: []*pb.PVERemoteInfo{activeRemoteInfo()}}
	revoked := grantFixture(t, gid1, now, nil)
	revoked.RevokedUnix = now.Unix()
	expiredByServer := grantFixture(t, gid2, now, nil)
	expiredByServer.ExpiryUnix = now.Unix()
	tampered := grantFixture(t, gid3, now, nil)
	tampered.GrantDigest = strings.Repeat("0", 64)
	providerRead := grantFixture(t, gid1, now, func(d *permit.ReadGrantDoc) {
		d.RateProfile = permit.ProviderReadProfile
		d.MinIntervalS = 60
		d.ProviderTargets[0].Methods = []string{"nodes"}
		d.ProviderTargets[0].MetricsTargets = nil
	})
	wrongID := grantFixture(t, gid2, now, nil)
	wrongID.GrantId = gid3
	for name, g := range map[string]*pb.ReadGrant{
		"revoked": revoked, "expired": expiredByServer, "digest": tampered,
		"inventory profile": providerRead, "id": wrongID, "nil": nil,
		"garbage": {GrantId: gid1, CanonicalGrant: []byte("{"), ExpiryUnix: now.Add(time.Hour).Unix()},
	} {
		if ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, ids, now); len(ls) != 0 {
			t.Errorf("%s: leases = %+v", name, ls)
		}
	}
	// A grant past its expiry yields nothing even before the server notices.
	g := grantFixture(t, gid1, now, nil)
	if ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, ids, time.Unix(g.ExpiryUnix, 0)); len(ls) != 0 {
		t.Errorf("expired: %+v", ls)
	}
}

func TestTelemetryLeasesSkipDuplicateGrantIDs(t *testing.T) {
	now := telT0
	g := grantFixture(t, gid1, now, nil)
	ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g, g}, TelemetryIdentities{Remotes: []*pb.PVERemoteInfo{activeRemoteInfo()}}, now)
	if len(ls) != 1 {
		t.Fatalf("leases = %d", len(ls))
	}
	s, _, _ := newTel(t, &telReader{})
	if err := s.SetLeases(ls); err != nil {
		t.Fatalf("derived leases rejected: %v", err)
	}
}

func TestTelemetryLeasesRequireCurrentRemoteIdentity(t *testing.T) {
	now := telT0
	g := grantFixture(t, gid1, now, nil)
	for name, r := range map[string]*pb.PVERemoteInfo{
		"re-pinned":       {RemoteId: "remote-a", TrustPin: strings.Repeat("cd", 32), TrustGeneration: 1, State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE},
		"new generation":  {RemoteId: "remote-a", TrustPin: testPin, TrustGeneration: 2, State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE},
		"inactive":        {RemoteId: "remote-a", TrustPin: testPin, TrustGeneration: 1},
		"other remote id": {RemoteId: "remote-b", TrustPin: testPin, TrustGeneration: 1, State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE},
	} {
		if ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, TelemetryIdentities{Remotes: []*pb.PVERemoteInfo{r}}, now); len(ls) != 0 {
			t.Errorf("%s: leases = %+v", name, ls)
		}
	}
}

func TestTelemetryLeasesFromSSHGrantRequireCurrentHostKey(t *testing.T) {
	now := telT0
	g := grantFixture(t, gid2, now, sshGrantMut)
	ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, TelemetryIdentities{HostKeys: map[string]string{
		"host-1": hostKey1,
		"host-2": "SHA256:" + strings.Repeat("9", 43), // replaced key
	}}, now)
	if len(ls) != 1 || len(ls[0].Targets) != 1 {
		t.Fatalf("leases = %+v", ls)
	}
	l := ls[0]
	if (l.Targets[0] != TelemetryTarget{Source: TelemetrySSH, HostID: "host-1", HostKey: hostKey1, ActionID: "host.metrics"}) {
		t.Fatalf("target = %+v", l.Targets[0])
	}
	if !l.Scheduled || l.OnDemand || l.RunBudget != 100 {
		t.Fatalf("lease = %+v", l)
	}
	if ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, TelemetryIdentities{}, now); len(ls) != 0 {
		t.Fatalf("no host keys: %+v", ls)
	}
}

func TestTelemetryLeasesFeedScheduler(t *testing.T) {
	now := telT0
	g := grantFixture(t, gid1, now, nil)
	ls := TelemetryLeasesFromGrants([]*pb.ReadGrant{g}, TelemetryIdentities{Remotes: []*pb.PVERemoteInfo{activeRemoteInfo()}}, now)
	fr := &fakeReader{readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		p := req.GetMetrics()
		return metricsResp(req.GetRemoteId(), p.GetNode(), p.GetKind(), p.GetVmid(), &pb.PVEMetric{Name: "cpu", Unit: "ratio", Value: 0.4}), nil
	}}
	clk := &fakeClock{t: now}
	sink := &telSink{}
	s, err := NewTelemetryScheduler(ProviderTelemetryReader{Reader: fr}, sink, TelemetryConfig{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLeases(ls); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		s.RunOnce(context.Background())
		clk.Add(ProviderMetricsSpacing)
	}
	if sink.count() != 2 {
		t.Fatalf("samples = %d", sink.count())
	}
}
