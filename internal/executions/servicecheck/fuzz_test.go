// SPDX-License-Identifier: AGPL-3.0-or-later

package servicecheck

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzParseResult: the probe result is written by a managed host and is
// untrusted. Any accepted document must satisfy the probe bounds and must
// round-trip through its own encoding.
func FuzzParseResult(f *testing.F) {
	for _, doc := range []string{
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":12,"http_status":200}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":0,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"redirect","latency_ms":8,"http_status":301}`,
		`{"format":"service-check-v1","phase":"done","status":"http-error","latency_ms":23,"http_status":503}`,
		`{"format":"service-check-v1","phase":"done","status":"refused","latency_ms":3,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"timeout","latency_ms":5000,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":5001,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":-1,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":0,"body":"x"}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"latency_ms":1,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1.5,"http_status":0}`,
		`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":0} {}`,
		`not json`,
		``,
	} {
		f.Add([]byte(doc))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseResult(b)
		if err != nil {
			return
		}
		if len(b) == 0 || len(b) > MaxDocSize {
			t.Fatalf("accepted a %d-byte document", len(b))
		}
		if err := ValidateResult(r); err != nil {
			t.Fatalf("accepted result fails ValidateResult: %v (%+v)", err, r)
		}
		if r.Latency < 0 || r.Latency > MaxLatencyMS*time.Millisecond {
			t.Fatalf("latency %v outside 0-%d ms", r.Latency, MaxLatencyMS)
		}
		enc, err := json.Marshal(doc{
			Format:     Format,
			Phase:      "done",
			Status:     string(r.Status),
			LatencyMS:  r.Latency.Milliseconds(),
			HTTPStatus: r.HTTPStatus,
		})
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseResult(enc)
		if err != nil {
			t.Fatalf("re-encoded result %s does not parse: %v", enc, err)
		}
		if again != r {
			t.Fatalf("re-encoded result parses to %+v, want %+v", again, r)
		}
	})
}
