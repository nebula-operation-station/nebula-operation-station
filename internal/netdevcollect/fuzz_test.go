// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// fuzzMarker is planted in seed records. Error text must never quote it:
// the spool is untrusted input and its errors reach logs.
const fuzzMarker = "ZQMARK7f3a9c"

// FuzzDecodeRecord feeds arbitrary bytes to the spool record decoder with a
// payload limit. It must never panic. A rejected record wraps
// ErrInvalidRecord and its text never quotes a marker from the input. An
// accepted record has a valid device ID and a known read, its payload fits
// the limit, and re-encoding and decoding it gives the same record.
func FuzzDecodeRecord(f *testing.F) {
	for _, read := range []string{ReadCBSVLANs, ReadPANOSZones} {
		raw, err := json.Marshal(Record{DeviceID: testDevice, Read: read, TrustGeneration: 3,
			ObservedAt: testTime, Data: json.RawMessage(`{"vlans":[]}`)})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, uint16(1<<10))
	}
	f.Add([]byte(`{"device_id":"core-sw-01","read":"cbs_vlans","trust_generation":1,`+
		`"observed_at":"`+fuzzMarker+`","incomplete":false,"data":{}}`), uint16(1<<10))
	f.Add([]byte(`{"device_id":`+fuzzMarker+`}`), uint16(1<<10))
	f.Add([]byte(`{"`+fuzzMarker+`":1}`), uint16(1<<10))
	f.Add([]byte(`{"device_id":"core-sw-01","read":"cbs_vlans","trust_generation":1,`+
		`"observed_at":"2026-11-10T12:00:00Z","incomplete":false,"data":{"v":"`+fuzzMarker+`"}}`), uint16(4))
	f.Add([]byte(`{"device_id":"core-sw-01","read":"cbs_vlans","trust_generation":1,`+
		`"observed_at":"2026-11-10T12:00:00Z","incomplete":false,"data":{"v":"1"}}`), uint16(1<<10))
	f.Add([]byte(`{`), uint16(1))

	f.Fuzz(func(t *testing.T, raw []byte, sel uint16) {
		limit := 1 + int(sel)
		rec, err := decodeRecord(raw, limit)
		if err != nil {
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("error %v does not wrap ErrInvalidRecord", err)
			}
			if bytes.Contains(raw, []byte(fuzzMarker)) && strings.Contains(err.Error(), fuzzMarker) {
				t.Fatalf("error text quotes input: %v", err)
			}
			return
		}
		if !netdevcontract.ValidDeviceID(rec.DeviceID) {
			t.Fatalf("accepted malformed device ID %q", rec.DeviceID)
		}
		if _, ok := readLimits[rec.Read]; !ok {
			t.Fatalf("accepted unknown read %q", rec.Read)
		}
		if !validTrustGeneration(rec.TrustGeneration) {
			t.Fatalf("accepted trust generation %d", rec.TrustGeneration)
		}
		if len(rec.Data) > limit {
			t.Fatalf("payload has %d bytes, limit %d", len(rec.Data), limit)
		}
		enc, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("re-encode accepted record: %v", err)
		}
		again, err := decodeRecord(enc, limit)
		if err != nil {
			t.Fatalf("re-decode accepted record: %v", err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, rec.Data); err != nil {
			t.Fatalf("accepted payload is not JSON: %v", err)
		}
		if again.DeviceID != rec.DeviceID || again.Read != rec.Read ||
			again.TrustGeneration != rec.TrustGeneration || again.Incomplete != rec.Incomplete ||
			!again.ObservedAt.Equal(rec.ObservedAt) || !bytes.Equal(again.Data, compact.Bytes()) {
			t.Fatalf("round trip changed the record: %+v became %+v", rec, again)
		}
	})
}

// TestRecordTimeErrorDoesNotQuoteInput is the regression test for the
// finding of FuzzDecodeRecord: encoding/json's time error quoted the
// observed_at value into the error text.
func TestRecordTimeErrorDoesNotQuoteInput(t *testing.T) {
	raw := `{"device_id":"core-sw-01","read":"cbs_vlans","trust_generation":1,` +
		`"observed_at":"` + fuzzMarker + `","incomplete":false,"data":{}}`
	_, err := decodeRecord([]byte(raw), 1<<10)
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("err = %v, want ErrInvalidRecord", err)
	}
	if strings.Contains(err.Error(), fuzzMarker) {
		t.Fatalf("error quotes input: %v", err)
	}
}

// TestRecordSyntaxErrorDoesNotQuoteInput checks that a syntax error at the
// marker, which encoding/json reports by quoting the offending byte, does
// not reach the error text.
func TestRecordSyntaxErrorDoesNotQuoteInput(t *testing.T) {
	for _, raw := range []string{
		`{"device_id":` + fuzzMarker + `}`,
		`{"` + fuzzMarker + `":1}`,
		`{"device_id":"core-sw-01","data":{"v":` + fuzzMarker + `}}`,
	} {
		_, err := decodeRecord([]byte(raw), 1<<10)
		if !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("%s: err = %v, want ErrInvalidRecord", raw, err)
		}
		if strings.Contains(err.Error(), fuzzMarker) {
			t.Fatalf("%s: error quotes input: %v", raw, err)
		}
	}
}

// TestRecordPayloadLimitIsInclusive checks the payload limit at the byte:
// a payload of exactly limit bytes is accepted, one byte more is refused.
func TestRecordPayloadLimitIsInclusive(t *testing.T) {
	const limit = 32
	build := func(n int) string {
		data := `{"v":"` + strings.Repeat("a", n-len(`{"v":""}`)) + `"}`
		return `{"device_id":"core-sw-01","read":"cbs_vlans","trust_generation":1,` +
			`"observed_at":"2026-11-10T12:00:00Z","incomplete":false,"data":` + data + `}`
	}
	if _, err := decodeRecord([]byte(build(limit)), limit); err != nil {
		t.Fatalf("payload of exactly %d bytes refused: %v", limit, err)
	}
	if _, err := decodeRecord([]byte(build(limit+1)), limit); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("payload of %d bytes: err = %v, want ErrInvalidRecord", limit+1, err)
	}
}
