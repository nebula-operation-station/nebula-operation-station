// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// randRead is crypto/rand, replaceable in tests.
var randRead = func(p []byte) (int, error) { return rand.Read(p) }

// maxBoxIDBytes bounds a box ID (fixed kind prefix plus bounded node
// name / VMID / host ID).
const maxBoxIDBytes = 128

// valueEvent builds the sanitized SSE payload of one sample for one box.
// It returns false when the sample carries nothing the client may show:
// an unknown metric, an out-of-range value, a missing timestamp or an
// invalid box ID. The payload holds only the server-built box ID, a
// fixed metric token, a fraction in [0,1] and a unix timestamp — no
// host names beyond the box ID, endpoints, keys or free text (ADR 0006
// P1-37: sanitized values).
func valueEvent(boxID string, s pvecollect.TelemetrySample) (Event, bool) {
	if !validBoxID(boxID) {
		return Event{}, false
	}
	switch s.Metric {
	case pvecollect.TelemetryMetricCPU, pvecollect.TelemetryMetricRAM, pvecollect.TelemetryMetricDisk:
	default:
		return Event{}, false
	}
	v := s.Value
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
		return Event{}, false
	}
	v = math.Round(v*1000) / 1000
	ts := s.ObservedAt.Unix()
	if ts <= 0 {
		return Event{}, false
	}
	b, err := json.Marshal(struct {
		ID     string  `json:"id"`
		Metric string  `json:"metric"`
		Value  float64 `json:"value"`
		TS     int64   `json:"ts"`
	}{boxID, s.Metric, v, ts})
	if err != nil {
		return Event{}, false
	}
	return Event{Name: "value", Data: b}, true
}

// ageEvent builds the deferred-box label payload: the age of the box's
// last observation in whole seconds, bounded to maxAgeSeconds.
func ageEvent(boxID string, age time.Duration) (Event, bool) {
	if !validBoxID(boxID) {
		return Event{}, false
	}
	secs := int(age / time.Second)
	if secs < 0 {
		secs = 0
	}
	if secs > maxAgeSeconds {
		secs = maxAgeSeconds
	}
	b, err := json.Marshal(struct {
		ID  string `json:"id"`
		Age int    `json:"age"`
	}{boxID, secs})
	if err != nil {
		return Event{}, false
	}
	return Event{Name: "age", Data: b}, true
}

// helloData is the first event of a stream: the server-generated viewer
// ID the client posts back with its visible-box updates, and the renewal
// interval the client must keep.
func helloData(viewerID string) []byte {
	b, err := json.Marshal(struct {
		Viewer string `json:"viewer"`
		Renew  int    `json:"renew"`
	}{viewerID, int(clientRenewal / time.Second)})
	if err != nil {
		return []byte("{}")
	}
	return b
}

// validBoxID accepts exactly the three box ID shapes boxRef.boxID
// builds — "node:<name>", "guest:<name>:<vmid>", "host:<id>" — checked
// with the same validators (PVE node name, VMID range, canonical host
// ID). An ID that could not have been built server-side is never sent.
func validBoxID(id string) bool {
	if id == "" || len(id) > maxBoxIDBytes {
		return false
	}
	switch {
	case strings.HasPrefix(id, "node:"):
		return pvecontract.ValidNodeName(id[len("node:"):])
	case strings.HasPrefix(id, "guest:"):
		rest := id[len("guest:"):]
		i := strings.LastIndex(rest, ":")
		if i <= 0 {
			return false
		}
		digits := rest[i+1:]
		vmid, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || vmid < pvecontract.MinVMID || vmid > pvecontract.MaxVMID ||
			strconv.FormatUint(vmid, 10) != digits {
			return false
		}
		return pvecontract.ValidNodeName(rest[:i])
	case strings.HasPrefix(id, "host:"):
		return canonical.ValidHostID(id[len("host:"):])
	}
	return false
}

// newViewerID generates the server-side viewer ID (32 hex chars).
func newViewerID() (string, error) {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("live: viewer id: %w", err)
	}
	return fmt.Sprintf("%x", b[:]), nil
}
