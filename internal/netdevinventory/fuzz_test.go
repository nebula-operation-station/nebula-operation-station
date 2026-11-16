// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fuzzMarker is planted in seed payloads. Error text must never quote it:
// payloads come from managed hosts and are untrusted.
const fuzzMarker = "ZQMARK7f3a9c"

// FuzzDecodePayload feeds arbitrary payloads to DecodePayload for every
// value of NetDeviceRead, including unknown numbers. It must never panic.
// Each error wraps ErrInvalidPayload or ErrUnknownRead, and its text never
// quotes a marker from the payload.
func FuzzDecodePayload(f *testing.F) {
	for _, c := range ingestCases() {
		raw, err := protojson.Marshal(c.msg)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(c.read), raw)
	}
	f.Add(uint8(pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS), []byte(`{"vlans":[{"id":1,"name":"`+fuzzMarker+`"}]}`))
	f.Add(uint8(pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS), []byte(`{"`+fuzzMarker+`":1}`))
	f.Add(uint8(pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES), []byte(`{"ports":[{"mode":"`+fuzzMarker+`"}]}`))
	f.Add(uint8(pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES), []byte(`{"zones":[{"type":99}]}`))
	f.Add(uint8(pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS),
		[]byte(`{"entries":[{"rule_name":"r","last_hit_unix":"`+fuzzMarker+`"}]}`))
	f.Add(uint8(0), []byte(`{}`))
	f.Add(uint8(255), []byte(`{}`))

	f.Fuzz(func(t *testing.T, read uint8, payload []byte) {
		rows, err := DecodePayload(pb.NetDeviceRead(read), payload)
		if err != nil {
			if !errors.Is(err, ErrInvalidPayload) && !errors.Is(err, ErrUnknownRead) {
				t.Fatalf("error %v wraps neither ErrInvalidPayload nor ErrUnknownRead", err)
			}
			if bytes.Contains(payload, []byte(fuzzMarker)) && strings.Contains(err.Error(), fuzzMarker) {
				t.Fatalf("error text quotes payload: %v", err)
			}
			return
		}
		if len(payload) > MaxIngestPayloadBytes {
			t.Fatalf("accepted a payload of %d bytes, limit %d", len(payload), MaxIngestPayloadBytes)
		}
		if rows == nil {
			t.Fatal("accepted payload maps onto no rows")
		}
	})
}

// TestDecodePayloadSizeLimitIsInclusive checks the payload limit at the
// byte: exactly MaxIngestPayloadBytes is accepted, one byte more is refused.
func TestDecodePayloadSizeLimitIsInclusive(t *testing.T) {
	pad := func(n int) []byte {
		return append([]byte(`{}`), bytes.Repeat([]byte(" "), n-2)...)
	}
	read := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	if _, err := DecodePayload(read, pad(MaxIngestPayloadBytes)); err != nil {
		t.Fatalf("payload of exactly %d bytes refused: %v", MaxIngestPayloadBytes, err)
	}
	_, err := DecodePayload(read, pad(MaxIngestPayloadBytes+1))
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("payload of %d bytes: err = %v, want ErrInvalidPayload", MaxIngestPayloadBytes+1, err)
	}
}

// TestDecodePayloadErrorDoesNotQuoteInput checks that the decoder's own
// error texts, which quote the payload, never reach the caller.
func TestDecodePayloadErrorDoesNotQuoteInput(t *testing.T) {
	for _, payload := range []string{
		`{"` + fuzzMarker + `":1}`,
		`{"vlans":[{"id":"` + fuzzMarker + `"}]}`,
		`{"vlans":` + fuzzMarker + `}`,
	} {
		_, err := DecodePayload(pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, []byte(payload))
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("%s: err = %v, want ErrInvalidPayload", payload, err)
		}
		if strings.Contains(err.Error(), fuzzMarker) {
			t.Fatalf("%s: error quotes payload: %v", payload, err)
		}
	}
}
