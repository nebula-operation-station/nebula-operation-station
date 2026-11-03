// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

var sanitizeT0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func sanitizeTarget() pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetryProvider, RemoteID: "remote-a",
		TrustPin: strings.Repeat("ab", 32), TrustGeneration: 1,
		Node: "pve1", Kind: pvecollect.TelemetryKindNode,
	}
}

func TestValueEventSanitises(t *testing.T) {
	tests := []struct {
		name    string
		boxID   string
		metric  string
		value   float64
		ts      time.Time
		wantOK  bool
		wantVal float64
	}{
		{"cpu in range", "node:pve1", pvecollect.TelemetryMetricCPU, 0.1234, sanitizeT0, true, 0.123},
		{"ram zero", "node:pve1", pvecollect.TelemetryMetricRAM, 0, sanitizeT0, true, 0},
		{"disk one", "node:pve1", pvecollect.TelemetryMetricDisk, 1, sanitizeT0, true, 1},
		{"guest box id", "guest:pve1:101", pvecollect.TelemetryMetricCPU, 0.5, sanitizeT0, true, 0.5},
		{"host box id", "host:web01", pvecollect.TelemetryMetricCPU, 0.5, sanitizeT0, true, 0.5},
		{"unknown metric dropped", "node:pve1", "temperature", 0.5, sanitizeT0, false, 0},
		{"negative dropped", "node:pve1", pvecollect.TelemetryMetricCPU, -0.1, sanitizeT0, false, 0},
		{"above one dropped", "node:pve1", pvecollect.TelemetryMetricCPU, 1.0001, sanitizeT0, false, 0},
		{"nan dropped", "node:pve1", pvecollect.TelemetryMetricCPU, math.NaN(), sanitizeT0, false, 0},
		{"inf dropped", "node:pve1", pvecollect.TelemetryMetricCPU, math.Inf(1), sanitizeT0, false, 0},
		{"zero timestamp dropped", "node:pve1", pvecollect.TelemetryMetricCPU, 0.5, time.Time{}, false, 0},
		{"pre-epoch timestamp dropped", "node:pve1", pvecollect.TelemetryMetricCPU, 0.5, time.Unix(-1, 0), false, 0},
		{"empty box id dropped", "", pvecollect.TelemetryMetricCPU, 0.5, sanitizeT0, false, 0},
		{"oversized box id dropped", strings.Repeat("n", 200), pvecollect.TelemetryMetricCPU, 0.5, sanitizeT0, false, 0},
		{"box id with newline dropped", "node:pve1\nx", pvecollect.TelemetryMetricCPU, 0.5, sanitizeT0, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := pvecollect.TelemetrySample{Target: sanitizeTarget(), Metric: tt.metric, Value: tt.value, ObservedAt: tt.ts}
			ev, ok := valueEvent(tt.boxID, s)
			if ok != tt.wantOK {
				t.Fatalf("valueEvent ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ev.Name != "value" {
				t.Fatalf("event name = %q, want value", ev.Name)
			}
			var p struct {
				ID     string  `json:"id"`
				Metric string  `json:"metric"`
				Value  float64 `json:"value"`
				TS     int64   `json:"ts"`
			}
			if err := json.Unmarshal(ev.Data, &p); err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
			if p.ID != tt.boxID || p.Metric != tt.metric || p.Value != tt.wantVal {
				t.Fatalf("payload = %+v, want id %s metric %s value %g", p, tt.boxID, tt.metric, tt.wantVal)
			}
			if p.TS != tt.ts.Unix() {
				t.Fatalf("ts = %d, want %d", p.TS, tt.ts.Unix())
			}
			// The payload must carry only the four fixed fields.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(ev.Data, &raw); err != nil {
				t.Fatalf("payload is not an object: %v", err)
			}
			if len(raw) != 4 {
				t.Fatalf("payload has %d fields, want exactly 4", len(raw))
			}
		})
	}
}

func TestValueEventCarriesNoFreeText(t *testing.T) {
	// A sample whose target carries names and keys must not leak them
	// into the payload.
	s := pvecollect.TelemetrySample{
		Target: pvecollect.TelemetryTarget{
			Source: pvecollect.TelemetrySSH, HostID: "web01",
			HostKey: "SHA256:secretfingerprint", ActionID: "host.metrics",
		},
		Metric: pvecollect.TelemetryMetricCPU, Value: 0.25, ObservedAt: sanitizeT0,
	}
	ev, ok := valueEvent("host:web01", s)
	if !ok {
		t.Fatal("valueEvent refused a valid host sample")
	}
	for _, leak := range []string{"secretfingerprint", "host.metrics", "SHA256"} {
		if strings.Contains(string(ev.Data), leak) {
			t.Fatalf("payload leaks %q: %s", leak, ev.Data)
		}
	}
}

func TestAgeEvent(t *testing.T) {
	tests := []struct {
		name    string
		boxID   string
		age     time.Duration
		wantOK  bool
		wantAge int
	}{
		{"normal", "node:pve1", 16 * time.Second, true, 16},
		{"fractional rounds down", "node:pve1", 16900 * time.Millisecond, true, 16},
		{"negative clamped to zero", "node:pve1", -time.Second, true, 0},
		{"bounded at max", "node:pve1", 48 * time.Hour, true, maxAgeSeconds},
		{"invalid box id", "", time.Minute, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := ageEvent(tt.boxID, tt.age)
			if ok != tt.wantOK {
				t.Fatalf("ageEvent ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ev.Name != "age" {
				t.Fatalf("event name = %q, want age", ev.Name)
			}
			var p struct {
				ID  string `json:"id"`
				Age int    `json:"age"`
			}
			if err := json.Unmarshal(ev.Data, &p); err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
			if p.ID != tt.boxID || p.Age != tt.wantAge {
				t.Fatalf("payload = %+v, want id %s age %d", p, tt.boxID, tt.wantAge)
			}
		})
	}
}

func TestValidBoxID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"node:pve1", true},
		{"node:", false},
		{"guest:pve1:101", true},
		{"guest:pve1:101:2", false}, // "pve1:101" is no node name
		{"guest:pve1:", false},
		{"guest::101", false},
		{"guest:pve1:10a", false},
		{"guest:pve1:0101", false}, // non-canonical decimal
		{"guest:pve1:99", false},   // below MinVMID
		{"guest:pve1:" + strings.Repeat("9", 11), false},
		{"node:pve1\nevent: x", false},
		{"node:pve_1", false},
		{"host:web01", true},
		{"host:", false},
		{"host:web 01", false},
		{"host:<b>", false},
		{"", false},
		{"pve1", false},
		{"node:" + strings.Repeat("a", 200), false},
	}
	for _, tt := range tests {
		if got := validBoxID(tt.id); got != tt.want {
			t.Errorf("validBoxID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestNewViewerID(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 64; i++ {
		id, err := newViewerID()
		if err != nil {
			t.Fatalf("newViewerID: %v", err)
		}
		if len(id) != 32 {
			t.Fatalf("viewer id length = %d, want 32", len(id))
		}
		if !validViewerID(id) {
			t.Fatalf("viewer id %q fails validViewerID", id)
		}
		if ids[id] {
			t.Fatalf("viewer id %q generated twice", id)
		}
		ids[id] = true
	}
}
