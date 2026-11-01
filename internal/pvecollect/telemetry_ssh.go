// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// SSH telemetry reads (ADR 0006 P1-26, spec 07 "Telemetry profile"). The
// TelemetryScheduler decides when a read is due; SSHTelemetryReader
// performs it on the server as one run of a read-only built-in action
// (the same artifacts the ordinary SSH observation schedule runs) under
// the approved telemetry read grant the scheduler names. The executor
// re-checks the grant (host, key, action, artifact, trigger, interval and
// budget) on every run. Telemetry runs are not stored as executions: at a
// 10-second cadence they would flood the execution history; their values
// go to the metric buckets only.

const (
	// telemetryRunTimeout bounds one SSH telemetry run, well below the
	// executor's per-action limit.
	telemetryRunTimeout = 20 * time.Second
	// telemetryCallTimeout bounds one executor metadata call.
	telemetryCallTimeout = 10 * time.Second
)

// TelemetryExecutor is the executor surface SSH telemetry reads use (server
// role). The generated executor client satisfies it.
type TelemetryExecutor interface {
	ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error)
	RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error)
}

// TelemetryHosts gives the inventory hosts (inventory.Store).
type TelemetryHosts interface {
	Get(ctx context.Context, id string) (inventory.Host, error)
}

// Errors of SSH telemetry reads.
var (
	// ErrTelemetryUnsupported is returned for a telemetry action whose
	// result has no box metric (it is never run).
	ErrTelemetryUnsupported = errors.New("pvecollect: telemetry action has no box metric")
	// ErrTelemetryHostKey is returned when the host's current pin no
	// longer matches the leased host key, or the host is blocked.
	ErrTelemetryHostKey = errors.New("pvecollect: telemetry host key no longer matches the lease")
)

// SSHTelemetryReader performs SSH telemetry reads. It implements
// TelemetryReader for TelemetrySSH targets.
type SSHTelemetryReader struct {
	Exec  TelemetryExecutor
	Hosts TelemetryHosts
}

// TelemetryHostKeys returns the current pinned host key of every
// unblocked host, for TelemetryIdentities.HostKeys.
func TelemetryHostKeys(ctx context.Context, exec TelemetryExecutor) (map[string]string, error) {
	cctx, cancel := context.WithTimeout(ctx, telemetryCallTimeout)
	defer cancel()
	r, err := exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return nil, fmt.Errorf("pvecollect: list host keys: %w", err)
	}
	out := map[string]string{}
	for _, p := range r.GetHosts() {
		if p != nil && !p.GetBlocked() && p.GetFingerprint() != "" {
			out[p.GetHostId()] = p.GetFingerprint()
		}
	}
	return out, nil
}

// ReadTelemetry runs the target's telemetry action once under the read's
// grant and maps the result to box metrics. A metric the host could not
// read is absent, never zero.
func (r SSHTelemetryReader) ReadTelemetry(ctx context.Context, read TelemetryRead) ([]TelemetrySample, error) {
	t := read.Target
	if r.Exec == nil || r.Hosts == nil || t.Source != TelemetrySSH || !t.Valid() || read.GrantID == "" {
		return nil, ErrTelemetryInvalid
	}
	if t.ActionID != "host.metrics" && t.ActionID != "filesystem.list" {
		return nil, ErrTelemetryUnsupported
	}
	a, ok := actions.Lookup(t.ActionID)
	if !ok || !a.ReadOnly || a.Durable || len(a.Params) != 0 {
		return nil, ErrTelemetryUnsupported
	}
	h, err := r.Hosts.Get(ctx, t.HostID)
	if err != nil {
		return nil, fmt.Errorf("pvecollect: telemetry host %s: %w", t.HostID, err)
	}
	cctx, cancel := context.WithTimeout(ctx, telemetryCallTimeout)
	pins, err := r.Exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("pvecollect: telemetry host keys: %w", err)
	}
	var pin *pb.HostKeyPin
	for _, p := range pins.GetHosts() {
		if p.GetHostId() == t.HostID {
			pin = p
		}
	}
	if pin == nil || pin.GetBlocked() || pin.GetFingerprint() != t.HostKey {
		return nil, ErrTelemetryHostKey
	}
	var eps []string
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		eps = append(eps, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	trigger := pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED
	if read.Live {
		trigger = pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND
	}
	run := &pb.AuthorizeRunRequest{HostId: t.HostID, HostKeyFingerprint: t.HostKey, ActionId: a.ID, ModuleVersion: a.Version,
		Artifact: a.Script, ParametersJson: []byte(`{}`), CredentialRef: pin.GetCredentialRef()}
	timeout := min(a.Timeout, telemetryRunTimeout)
	rctx, cancel := context.WithTimeout(ctx, timeout+telemetryCallTimeout)
	defer cancel()
	resp, err := r.Exec.RunReadGrant(rctx, &pb.RunReadGrantRequest{GrantId: read.GrantID, Run: run, Endpoints: eps,
		TimeoutSeconds: uint32(timeout / time.Second), Trigger: trigger})
	if err != nil {
		return nil, fmt.Errorf("pvecollect: telemetry run %s on %s: %w", a.ID, t.HostID, err)
	}
	res := resp.GetResult()
	if res.GetClass() != "success" {
		return nil, nil
	}
	return sshTelemetrySamples(t, res.GetResult())
}

// sshTelemetrySamples maps a successful telemetry action result to box
// metric fractions. The result is untrusted host output; the hostmetrics
// parsers bound and validate it.
func sshTelemetrySamples(t TelemetryTarget, result []byte) ([]TelemetrySample, error) {
	var out []TelemetrySample
	add := func(metric string, v float64) {
		if v >= 0 && v <= 1 {
			out = append(out, TelemetrySample{Target: t, Metric: metric, Value: v})
		}
	}
	switch t.ActionID {
	case "host.metrics":
		m, err := hostmetrics.ParseMetrics(result)
		if err != nil {
			return nil, fmt.Errorf("pvecollect: telemetry host.metrics on %s: %w", t.HostID, err)
		}
		if m.Phase != "done" {
			return nil, nil
		}
		if m.CPU.Available {
			add(TelemetryMetricCPU, m.CPU.Percent/100)
		}
		if m.Mem.Available && m.Mem.TotalBytes > 0 {
			add(TelemetryMetricRAM, float64(m.Mem.UsedBytes)/float64(m.Mem.TotalBytes))
		}
		if m.Disk.Available && m.Disk.TotalBytes > 0 {
			add(TelemetryMetricDisk, float64(m.Disk.UsedBytes)/float64(m.Disk.TotalBytes))
		}
	case "filesystem.list":
		f, err := hostmetrics.ParseFilesystems(result)
		if err != nil {
			return nil, fmt.Errorf("pvecollect: telemetry filesystem.list on %s: %w", t.HostID, err)
		}
		if f.Phase != "done" || !f.Available {
			return nil, nil
		}
		if m, ok := f.Fullest(); ok && m.SizeBytes > 0 {
			add(TelemetryMetricDisk, float64(m.UsedBytes)/float64(m.SizeBytes))
		}
	}
	return out, nil
}
