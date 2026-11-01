// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// TelemetrySourceSSH labels samples from the SSH telemetry pipeline.
const TelemetrySourceSSH = "ssh-telemetry"

// MetricRecorder is the P1-25 metric bucket store (pveinventory.Store).
type MetricRecorder interface {
	RecordSample(ctx context.Context, t pveinventory.MetricTarget, m pveinventory.MetricName, value float64, source string) error
}

// ErrNoMetricTarget is returned for a sample with no box series to land
// in, e.g. an SSH host without a reviewed link to a node or guest.
var ErrNoMetricTarget = errors.New("pvecollect: sample has no metric target")

// BucketSink feeds telemetry samples into the P1-25 five-minute buckets.
// Live and history samples share the bucket of the time they are recorded
// (the store's injected clock). Provider samples map to their node or
// guest incarnation series; SSH samples need SSHTarget, which resolves a
// host to the box series of its reviewed link (no link: not recorded).
type BucketSink struct {
	Store     MetricRecorder
	SSHTarget func(ctx context.Context, hostID string) (pveinventory.MetricTarget, bool)
}

// RecordTelemetry records one sample.
func (b BucketSink) RecordTelemetry(ctx context.Context, s TelemetrySample) error {
	if b.Store == nil {
		return fmt.Errorf("%w: no store", ErrTelemetryInvalid)
	}
	var (
		target pveinventory.MetricTarget
		source string
	)
	switch s.Target.Source {
	case TelemetryProvider:
		source = pvecontract.SourcePVEAPI
		target = pveinventory.MetricTarget{RemoteID: s.Target.RemoteID}
		if s.Target.Kind == TelemetryKindNode {
			target.Kind, target.Node = pveinventory.MetricTargetNode, s.Target.Node
		} else {
			target.Kind, target.VMID, target.Generation = pveinventory.MetricTargetGuest, s.Target.VMID, s.Target.Generation
		}
	case TelemetrySSH:
		source = TelemetrySourceSSH
		if b.SSHTarget == nil {
			return ErrNoMetricTarget
		}
		t, ok := b.SSHTarget(ctx, s.Target.HostID)
		if !ok {
			return ErrNoMetricTarget
		}
		target = t
	default:
		return ErrTelemetryInvalid
	}
	var metric pveinventory.MetricName
	switch s.Metric {
	case TelemetryMetricCPU:
		metric = pveinventory.MetricCPU
	case TelemetryMetricRAM:
		metric = pveinventory.MetricRAM
	case TelemetryMetricDisk:
		if s.Target.Source == TelemetryProvider {
			// PVE allocation is not filesystem utilization.
			return ErrNoMetricTarget
		}
		metric = pveinventory.MetricDisk
	default:
		return ErrTelemetryInvalid
	}
	if err := b.Store.RecordSample(ctx, target, metric, s.Value, source); err != nil {
		return fmt.Errorf("pvecollect: record %s sample: %w", s.Metric, err)
	}
	return nil
}
