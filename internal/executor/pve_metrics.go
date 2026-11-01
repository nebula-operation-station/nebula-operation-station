// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Metrics request limits per remote (spec 17 "SSH/provider telemetry
// leases", spec 12 "Visible-target requests"). They apply on top of the
// telemetry grant's interval and budget and are kept in memory only: a
// restart starts with no live targets, which is the conservative state.
const (
	// pveMetricsMaxLiveTargets is the number of distinct live targets one
	// remote serves at a time.
	pveMetricsMaxLiveTargets = 4
	// pveMetricsLiveRenewal is how long a live target stays registered
	// without a further live request (a hidden or closed chart stops
	// renewing and frees its slot after this time).
	pveMetricsLiveRenewal = 30 * time.Second
	// pveMetricsRequestSpacing is the minimum spacing of two metrics
	// requests to one remote (one request per second).
	pveMetricsRequestSpacing = time.Second
)

// pveMetricsGate enforces the per-remote live-target and request-rate caps.
type pveMetricsGate struct {
	mu      sync.Mutex
	remotes map[string]*pveMetricsRemote
}

type pveMetricsRemote struct {
	last time.Time
	live map[string]time.Time
}

// admit reserves one metrics request for remoteID: at most one request per
// second, and for live reads at most four distinct targets renewed within
// the last 30 seconds. The returned undo releases the reservation when
// the request is not authorized after all, so an unauthorized request
// never occupies a live slot.
func (g *pveMetricsGate) admit(remoteID, target string, live bool, now time.Time) (undo func(), err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.remotes == nil {
		g.remotes = map[string]*pveMetricsRemote{}
	}
	r, ok := g.remotes[remoteID]
	if !ok {
		r = &pveMetricsRemote{live: map[string]time.Time{}}
		g.remotes[remoteID] = r
	}
	// A clock step backwards restarts spacing at the new time instead of
	// blocking requests until the clock catches up.
	if !r.last.IsZero() && !now.Before(r.last) && now.Sub(r.last) < pveMetricsRequestSpacing {
		return nil, status.Error(codes.ResourceExhausted, "read pve: one metrics request per second per remote")
	}
	for k, at := range r.live {
		if now.Sub(at) >= pveMetricsLiveRenewal || now.Before(at) {
			delete(r.live, k)
		}
	}
	prevLive, hadLive := r.live[target]
	if live && !hadLive && len(r.live) >= pveMetricsMaxLiveTargets {
		return nil, status.Error(codes.ResourceExhausted, "read pve: four live metrics targets per remote are already active")
	}
	prevLast := r.last
	r.last = now
	if live {
		r.live[target] = now
	}
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.last.Equal(now) {
			r.last = prevLast
		}
		if live && r.live[target].Equal(now) {
			if hadLive {
				r.live[target] = prevLive
			} else {
				delete(r.live, target)
			}
		}
	}, nil
}

// Metric names and units of PVEMetrics. Node rates are bytes per second;
// guest I/O values are cumulative byte counters since guest start (PVE
// status/current reports no guest rates). disk_allocated is the guest's
// configured disk size, never filesystem usage.
const (
	pveMetricCPU           = "cpu"
	pveMetricMemUsed       = "mem_used"
	pveMetricMemTotal      = "mem_total"
	pveMetricDiskRead      = "disk_read_rate"
	pveMetricDiskWrite     = "disk_write_rate"
	pveMetricNetIn         = "net_in_rate"
	pveMetricNetOut        = "net_out_rate"
	pveMetricDiskReadSum   = "disk_read_total"
	pveMetricDiskWriteSum  = "disk_write_total"
	pveMetricNetInSum      = "net_in_total"
	pveMetricNetOutSum     = "net_out_total"
	pveMetricDiskAllocated = "disk_allocated"

	pveUnitRatio       = "ratio"
	pveUnitBytes       = "bytes"
	pveUnitBytesPerSec = "bytes_per_second"
)

// readPveMetrics reads the current status of one exact metrics target and
// maps it to fixed metric names and units. Missing values stay absent.
func readPveMetrics(ctx context.Context, base string, hc *http.Client, token pveapi.TokenSupplier, target permit.ProviderMetricsTarget) *pb.PVEMetrics {
	out := &pb.PVEMetrics{Node: target.Node, Kind: target.Kind, Vmid: target.VMID}
	unavailable := func(reason string) *pb.PVEMetrics {
		out.State, out.Reason = pveUnavailable, reason
		return out
	}
	auth := func(ctx context.Context) (string, string, error) {
		v, err := token(ctx)
		return "Authorization", v, err
	}
	c, err := pveapi.NewMetricsClient(base+"/api2/json", hc, auth, pveapi.WithPerCallTimeout(pveReadRequestTimeout))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	add := func(name, unit string, v *float64) {
		if v != nil {
			out.Metrics = append(out.Metrics, &pb.PVEMetric{Name: name, Unit: unit, Value: *v})
		}
	}
	addInt := func(name, unit string, v *int64) {
		if v != nil {
			f := float64(*v)
			add(name, unit, &f)
		}
	}
	if target.Kind == permit.MetricsKindNode {
		m, err := c.NodeStatus(ctx, target.Node)
		if err != nil {
			return unavailable(pveMetricsReason(err))
		}
		out.Status = pveNodeStatusName(m.Status)
		add(pveMetricCPU, pveUnitRatio, m.CPU)
		addInt(pveMetricMemUsed, pveUnitBytes, m.MemUsed)
		addInt(pveMetricMemTotal, pveUnitBytes, m.MemTotal)
		addInt(pveMetricDiskRead, pveUnitBytesPerSec, m.DiskRead)
		addInt(pveMetricDiskWrite, pveUnitBytesPerSec, m.DiskWrite)
		addInt(pveMetricNetIn, pveUnitBytesPerSec, m.NetIn)
		addInt(pveMetricNetOut, pveUnitBytesPerSec, m.NetOut)
	} else {
		kind := pveapi.KindQEMU
		if target.Kind == permit.MetricsKindLXC {
			kind = pveapi.KindLXC
		}
		m, err := c.GuestStatus(ctx, target.Node, kind, int(target.VMID))
		if err != nil {
			return unavailable(pveMetricsReason(err))
		}
		out.Status = pveGuestStatusName(m.Status)
		add(pveMetricCPU, pveUnitRatio, m.CPU)
		addInt(pveMetricMemUsed, pveUnitBytes, m.MemUsed)
		addInt(pveMetricMemTotal, pveUnitBytes, m.MemTotal)
		addInt(pveMetricDiskAllocated, pveUnitBytes, m.DiskAllocated)
		addInt(pveMetricDiskReadSum, pveUnitBytes, m.DiskReadBytes)
		addInt(pveMetricDiskWriteSum, pveUnitBytes, m.DiskWriteBytes)
		addInt(pveMetricNetInSum, pveUnitBytes, m.NetInBytes)
		addInt(pveMetricNetOutSum, pveUnitBytes, m.NetOutBytes)
	}
	out.State = pveAvailable
	return out
}

// pveMetricsReason maps a metrics client error to a fixed reason; raw PVE
// text never reaches the caller.
func pveMetricsReason(err error) string {
	switch {
	case errorsIsAny(err, pveapi.ErrInvalidRange, pveapi.ErrTooLarge):
		return pveReasonInvalid
	default:
		return pveReasonRead
	}
}

func pveNodeStatusName(s string) string {
	switch s {
	case "online", "offline":
		return s
	}
	return "unknown"
}

func pveGuestStatusName(s string) string {
	switch s {
	case "running", "stopped", "paused":
		return s
	}
	return "unknown"
}
