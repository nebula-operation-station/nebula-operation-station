// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"sync/atomic"
	"testing"
)

// newMetricsFuzzServer wires a catch-all server plus a MetricsClient. The base
// URL passed to NewMetricsClient must end with /api2/json.
func newMetricsFuzzServer(f *testing.F) (*fuzzServer, *MetricsClient, *atomic.Value) {
	body := &atomic.Value{}
	body.Store([]byte(`{"data":{}}`))
	fs := newFuzzServer(f, func(string) []byte {
		b, _ := body.Load().([]byte)
		return b
	})
	c := newFuzzMetricsClient(f, fs.url()+"/api2/json")
	return fs, c, body
}

// FuzzNodeStatus feeds hostile bodies to NodeStatus (the doGet + unmarshalData
// path). The size limit (defaultMaxBody) is the asserted rejection; the parser
// range-checks every numeric field, so invalid values surface as errors.
func FuzzNodeStatus(f *testing.F) {
	f.Add(readFuzzFixture(f, "node_status_pve8.json"))
	_, c, body := newMetricsFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.NodeStatus(ctx, "pve1")
		assertFuzzInvariants(t, data, int(defaultMaxBody), false, err, nil)
	})
}

// FuzzGuestStatus feeds hostile bodies to GuestStatus.
func FuzzGuestStatus(f *testing.F) {
	f.Add(readFuzzFixture(f, "qemu_status_running_pve8.json"))
	_, c, body := newMetricsFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.GuestStatus(ctx, "pve1", KindQemu, 100)
		assertFuzzInvariants(t, data, int(defaultMaxBody), false, err, nil)
	})
}

// FuzzNodeRRDData feeds hostile bodies to NodeRRDData and asserts the returned
// series is non-nil-free on success (the parser bounds the point count).
func FuzzNodeRRDData(f *testing.F) {
	f.Add(readFuzzFixture(f, "node_rrd_hour_pve8.json"))
	_, c, body := newMetricsFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.NodeRRDData(ctx, "pve1", TimeframeHour, 8<<30)
		assertFuzzInvariants(t, data, int(defaultMaxBody), false, err, nil)
	})
}

// FuzzGuestRRDData feeds hostile bodies to GuestRRDData.
func FuzzGuestRRDData(f *testing.F) {
	f.Add(readFuzzFixture(f, "qemu_rrd_hour_pve8.json"))
	_, c, body := newMetricsFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.GuestRRDData(ctx, "pve1", KindQemu, 100, TimeframeHour)
		assertFuzzInvariants(t, data, int(defaultMaxBody), false, err, nil)
	})
}
