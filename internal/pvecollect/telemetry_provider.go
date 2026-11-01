// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Provider metrics response limits. The executor's PVEMetrics carries a
// fixed set of at most a dozen metrics; anything larger is malformed.
const (
	// maxMetricsResponseBytes bounds one ReadPVE METRICS response.
	maxMetricsResponseBytes = 64 << 10
	// maxMetricsPerResponse bounds the metrics of one response.
	maxMetricsPerResponse = 32
)

// Executor metric names and units the provider reader understands
// (executor.readPveMetrics). Disk allocation and I/O are not filesystem
// utilization and are never mapped to the disk metric.
const (
	pveMetricCPU      = "cpu"
	pveMetricMemUsed  = "mem_used"
	pveMetricMemTotal = "mem_total"
	pveUnitRatio      = "ratio"
	pveUnitBytes      = "bytes"
)

// ErrMetricsMismatch is returned when a metrics response does not describe
// the requested target or is malformed.
var ErrMetricsMismatch = errors.New("pvecollect: metrics response does not match the request")

// ProviderTelemetryReader performs provider telemetry reads through the
// executor's typed ReadPVE METRICS method. It never names a URL or path.
type ProviderTelemetryReader struct {
	Reader Reader
}

// ReadTelemetry reads one exact provider metrics target. An unavailable
// dataset yields no samples (missing, never zero).
func (p ProviderTelemetryReader) ReadTelemetry(ctx context.Context, read TelemetryRead) ([]TelemetrySample, error) {
	t := read.Target
	if p.Reader == nil || t.Source != TelemetryProvider || !t.Valid() {
		return nil, ErrTelemetryInvalid
	}
	resp, err := p.Reader.ReadPVE(ctx, &pb.ReadPVERequest{
		RemoteId: t.RemoteID,
		Method:   pb.PVEReadMethod_PVE_READ_METHOD_METRICS,
		Params: &pb.ReadPVERequest_Metrics{Metrics: &pb.PVEReadMetricsParams{
			Node: t.Node, Kind: t.Kind, Vmid: t.VMID, Generation: t.Generation, Live: read.Live,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("pvecollect: read metrics %s: %w", t.RemoteID, err)
	}
	if proto.Size(resp) > maxMetricsResponseBytes {
		return nil, ErrOversize
	}
	m := resp.GetMetrics()
	if resp.GetRemoteId() != t.RemoteID || m == nil {
		return nil, ErrMetricsMismatch
	}
	switch m.GetState() {
	case pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE:
	case pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE:
		return nil, nil
	default:
		return nil, ErrMetricsMismatch
	}
	if m.GetNode() != t.Node || m.GetKind() != t.Kind || m.GetVmid() != t.VMID || len(m.GetMetrics()) > maxMetricsPerResponse {
		return nil, ErrMetricsMismatch
	}
	vals := map[string]float64{}
	for _, x := range m.GetMetrics() {
		if x == nil {
			return nil, ErrMetricsMismatch
		}
		if _, dup := vals[x.GetName()]; dup {
			return nil, ErrMetricsMismatch
		}
		v := x.GetValue()
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, ErrMetricsMismatch
		}
		switch x.GetName() {
		case pveMetricCPU:
			if x.GetUnit() != pveUnitRatio {
				return nil, ErrMetricsMismatch
			}
		case pveMetricMemUsed, pveMetricMemTotal:
			if x.GetUnit() != pveUnitBytes {
				return nil, ErrMetricsMismatch
			}
		}
		vals[x.GetName()] = v
	}
	var out []TelemetrySample
	if v, ok := vals[pveMetricCPU]; ok && v >= 0 && v <= 1 {
		out = append(out, TelemetrySample{Target: t, Metric: TelemetryMetricCPU, Value: v})
	}
	used, okU := vals[pveMetricMemUsed]
	total, okT := vals[pveMetricMemTotal]
	if okU && okT && total > 0 && used >= 0 && used <= total {
		out = append(out, TelemetrySample{Target: t, Metric: TelemetryMetricRAM, Value: used / total})
	}
	return out, nil
}

// TelemetryIdentities is the current identity of every target kind, used
// to drop lease targets whose binding has gone stale (a re-pinned remote
// or replaced host key needs a new grant).
type TelemetryIdentities struct {
	// Remotes is the executor's current remote list (ListPVERemotes).
	Remotes []*pb.PVERemoteInfo
	// HostKeys maps an enrolled, unblocked host ID to its pinned host key
	// fingerprint. Hosts not listed get no SSH telemetry.
	HostKeys map[string]string
}

// TelemetryLeasesFromGrants derives scheduler leases from the executor's
// approved read grants. Only active, unexpired read-grant-v2 documents
// with the provider_telemetry or telemetry rate profile contribute, and
// only their targets whose remote trust binding or host key matches the
// current identity. The result selects work only; the executor
// re-authorizes every read.
func TelemetryLeasesFromGrants(grants []*pb.ReadGrant, ids TelemetryIdentities, now time.Time) []TelemetryLease {
	remotes := map[string]*pb.PVERemoteInfo{}
	for _, r := range ids.Remotes {
		if r != nil && r.GetState() == pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE {
			remotes[r.GetRemoteId()] = r
		}
	}
	var out []TelemetryLease
	total := 0
	for _, g := range grants {
		if len(out) >= MaxTelemetryLeases {
			break
		}
		if g == nil || g.GetRevokedUnix() != 0 || !now.Before(time.Unix(g.GetExpiryUnix(), 0)) {
			continue
		}
		doc, _, digest, err := permit.ParseReadGrant(g.GetCanonicalGrant(), now)
		if err != nil || doc.ID != g.GetGrantId() || digest != g.GetGrantDigest() {
			continue
		}
		l := TelemetryLease{
			GrantID: doc.ID, GrantDigest: digest,
			Scheduled:   doc.Trigger == permit.TriggerScheduled || doc.Trigger == permit.TriggerBoth,
			OnDemand:    doc.Trigger == permit.TriggerOnDemand || doc.Trigger == permit.TriggerBoth,
			ExpiresAt:   time.Unix(min(doc.ExpiryUnix, g.GetExpiryUnix()), 0),
			MinInterval: time.Duration(doc.MinIntervalS) * time.Second,
			RunBudget:   int(min(doc.RunBudget, int64(MaxTelemetryRunBudget))),
		}
		switch doc.RateProfile {
		case permit.ProviderTelemetryProfile:
			for _, pt := range doc.ProviderTargets {
				cur, ok := remotes[pt.RemoteID]
				if !ok || cur.GetTrustPin() != pt.TrustPin || cur.GetTrustGeneration() != pt.TrustGeneration {
					continue
				}
				for _, mt := range pt.MetricsTargets {
					l.Targets = append(l.Targets, TelemetryTarget{
						Source: TelemetryProvider, RemoteID: pt.RemoteID, TrustPin: pt.TrustPin, TrustGeneration: pt.TrustGeneration,
						Node: mt.Node, Kind: mt.Kind, VMID: mt.VMID, Generation: mt.Generation,
					})
				}
			}
		case schedgrant.TelemetryReadProfile:
			for _, ht := range doc.Targets {
				if key, ok := ids.HostKeys[ht.HostID]; !ok || key != ht.HostKeyFingerprint {
					continue
				}
				for _, a := range doc.Actions {
					if !schedgrant.IsTelemetryAction(a.ActionID) {
						continue
					}
					l.Targets = append(l.Targets, TelemetryTarget{Source: TelemetrySSH, HostID: ht.HostID, HostKey: ht.HostKeyFingerprint, ActionID: a.ActionID})
				}
			}
		default:
			continue
		}
		if l.validate() != nil || total+len(l.Targets) > MaxTelemetryTargets {
			continue
		}
		total += len(l.Targets)
		out = append(out, l)
	}
	return out
}
