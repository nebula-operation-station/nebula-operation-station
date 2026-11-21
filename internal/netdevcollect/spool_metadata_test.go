// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// validMetadataPayload is one device metadata document of testDevice as the
// collector writes it.
const validMetadataPayload = `{"device_id":"core-sw-01","family":"cbs","label":"Core switch",` +
	`"trust_generation":3,"blocked":false,"block_reason":""}`

func TestDeviceMetadataRoundTrip(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, ReadDeviceMetadata, validMetadataPayload)
	if _, err := parseSpoolName(name); err != nil {
		t.Fatalf("published name %s does not parse: %v", name, err)
	}
	taken, err := s.Take(context.Background(), name)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if taken.Record.Read != ReadDeviceMetadata || taken.Record.DeviceID != testDevice || taken.Record.TrustGeneration != 3 {
		t.Fatalf("record identity = %+v", taken.Record)
	}
	got, err := DecodeDeviceMetadata(taken.Record.Data)
	if err != nil {
		t.Fatalf("DecodeDeviceMetadata: %v", err)
	}
	want := DeviceMetadata{DeviceID: testDevice, Family: netdevcontract.FamilyCBS, Label: "Core switch",
		TrustGeneration: 3, Blocked: false, BlockReason: ""}
	if got != want {
		t.Fatalf("decoded = %+v, want %+v", got, want)
	}
}

func TestDeviceMetadataBlockedStateRoundTrip(t *testing.T) {
	s := newSpool(t)
	payload := `{"device_id":"fw-01","family":"panos","label":"","trust_generation":1,"blocked":true,"block_reason":"pin changed"}`
	name, err := s.Write(context.Background(), "fw-01", ReadDeviceMetadata, 1, false, []byte(payload))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	taken, err := s.Take(context.Background(), name)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	got, err := DecodeDeviceMetadata(taken.Record.Data)
	if err != nil {
		t.Fatalf("DecodeDeviceMetadata: %v", err)
	}
	if !got.Blocked || got.BlockReason != "pin changed" || got.Family != netdevcontract.FamilyPANOS || got.Label != "" {
		t.Fatalf("decoded = %+v", got)
	}
}

func TestDeviceMetadataSchemaRejections(t *testing.T) {
	long := strings.Repeat("x", MaxDeviceMetadataTextBytes+1)
	cases := []struct {
		name, payload string
	}{
		{"not an object", `["core-sw-01"]`},
		{"unknown field", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":"","endpoint_ip":"10.0.0.2"}`},
		{"credential field", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":"","credential_version":4}`},
		{"trust pin field", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":"","trust_pin":"` + strings.Repeat("a", 64) + `"}`},
		{"missing label", `{"device_id":"core-sw-01","family":"cbs","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"missing block_reason", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false}`},
		{"wrong type for blocked", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":"no","block_reason":""}`},
		{"malformed device id", `{"device_id":"Core_SW","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"unknown family", `{"device_id":"core-sw-01","family":"pfsense","label":"a","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"zero trust generation", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":0,"blocked":false,"block_reason":""}`},
		{"trust generation over the limit", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":` +
			uintString(netdevcontract.MaxTrustGeneration+1) + `,"blocked":false,"block_reason":""}`},
		{"control character in label", `{"device_id":"core-sw-01","family":"cbs","label":"a\nb","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"escape character in block reason", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":true,"block_reason":"\u001b[2J"}`},
		{"label over the text limit", `{"device_id":"core-sw-01","family":"cbs","label":"` + long + `","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"block reason over the text limit", `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":true,"block_reason":"` + long + `"}`},
		{"trailing value", validMetadataPayload + ` {}`},
		{"duplicate field", `{"device_id":"core-sw-01","device_id":"fw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":""}`},
		{"invalid UTF-8", "{\"device_id\":\"core-sw-01\",\"family\":\"cbs\",\"label\":\"\xff\",\"trust_generation\":3,\"blocked\":false,\"block_reason\":\"\"}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeDeviceMetadata([]byte(tc.payload)); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("DecodeDeviceMetadata err = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestDeviceMetadataAcceptsTextAtTheLimit(t *testing.T) {
	label := strings.Repeat("l", MaxDeviceMetadataTextBytes)
	payload := `{"device_id":"core-sw-01","family":"cbs","label":"` + label + `","trust_generation":3,"blocked":false,"block_reason":""}`
	got, err := DecodeDeviceMetadata([]byte(payload))
	if err != nil {
		t.Fatalf("label at the limit: %v", err)
	}
	if got.Label != label {
		t.Fatalf("label length = %d, want %d", len(got.Label), len(label))
	}
}

func TestDeviceMetadataPayloadLimitIsInclusive(t *testing.T) {
	pad := MaxDeviceMetadataBytes - len(validMetadataPayload)
	atLimit := validMetadataPayload[:len(validMetadataPayload)-1] + strings.Repeat(" ", pad) + "}"
	if len(atLimit) != MaxDeviceMetadataBytes {
		t.Fatalf("test payload is %d bytes, want %d", len(atLimit), MaxDeviceMetadataBytes)
	}
	s := newSpool(t)
	mustWrite(t, s, testDevice, ReadDeviceMetadata, atLimit)

	over := validMetadataPayload[:len(validMetadataPayload)-1] + strings.Repeat(" ", pad+1) + "}"
	if _, err := s.Write(context.Background(), testDevice, ReadDeviceMetadata, 3, false, []byte(over)); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize metadata err = %v, want ErrOversize", err)
	}
}

func TestWriteRejectsMetadataThatDoesNotMatchTheRecord(t *testing.T) {
	s := newSpool(t)
	ctx := context.Background()
	// The payload names fw-01 but the record is for core-sw-01.
	if _, err := s.Write(ctx, testDevice, ReadDeviceMetadata, 3, false, []byte(validMetadataPayload)); err != nil {
		t.Fatalf("matching write: %v", err)
	}
	if _, err := s.Write(ctx, "fw-01", ReadDeviceMetadata, 3, false, []byte(validMetadataPayload)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("device mismatch err = %v, want ErrInvalidRecord", err)
	}
	// The payload says generation 3 but the record claims 4.
	if _, err := s.Write(ctx, testDevice, ReadDeviceMetadata, 4, false, []byte(validMetadataPayload)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("generation mismatch err = %v, want ErrInvalidRecord", err)
	}
	if _, err := s.Write(ctx, testDevice, ReadDeviceMetadata, 3, false, []byte(`{"vlans":[]}`)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("foreign payload err = %v, want ErrInvalidRecord", err)
	}
}

func TestReadNameSetStaysClosedWithMetadata(t *testing.T) {
	if n, ok := ReadLimit(ReadDeviceMetadata); !ok || n != MaxDeviceMetadataBytes {
		t.Fatalf("ReadLimit(%s) = %d, %v; want %d", ReadDeviceMetadata, n, ok, MaxDeviceMetadataBytes)
	}
	if ReadDeviceMetadata != "device_metadata" {
		t.Fatalf("ReadDeviceMetadata = %q", ReadDeviceMetadata)
	}
	for _, bad := range []string{"device_metadata/../x", "Device_Metadata", "device-metadata", "device_metadata2"} {
		if _, ok := ReadLimit(bad); ok {
			t.Errorf("ReadLimit(%q) accepted", bad)
		}
	}
	s := newSpool(t)
	if _, err := s.Write(context.Background(), testDevice, "device_metadata2", 3, false, []byte(validMetadataPayload)); !errors.Is(err, ErrUnknownRead) {
		t.Fatalf("unknown read err = %v, want ErrUnknownRead", err)
	}
}

// uintString formats n in decimal for a JSON number.
func uintString(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
