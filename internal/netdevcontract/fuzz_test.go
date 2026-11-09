// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"errors"
	"strings"
	"testing"
)

// FuzzDecodeDevice feeds arbitrary bytes to the device decoder; it must
// never panic, and every accepted device must validate and re-encode.
func FuzzDecodeDevice(f *testing.F) {
	for _, d := range []Device{baseCBSDevice(), basePANOSDevice()} {
		raw, err := MarshalDevice(d)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{`))
	f.Add([]byte(`{"device_id":"a","family":"cbs","endpoints":[{"address":"10.0.0.1","port":22}],"pin_kind":"ssh-host-key","trust_pin":"` + validPin + `","trust_generation":1}`))
	f.Add([]byte(strings.Repeat(`{"a":`, MaxJSONNesting+2) + `1` + strings.Repeat(`}`, MaxJSONNesting+2)))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := DecodeDevice(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not match ErrInvalid", err)
			}
			return
		}
		if _, err := MarshalDevice(d); err != nil {
			t.Fatalf("accepted device does not re-encode: %v", err)
		}
	})
}

// FuzzDecodeObservation feeds arbitrary bytes to the observation decoder;
// it must never panic, and every accepted observation must re-encode and
// decode to the same document.
func FuzzDecodeObservation(f *testing.F) {
	for _, o := range []Observation{baseCBSObservation(), basePANOSObservation()} {
		raw, err := MarshalObservation(o)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"device_id":"sw-1","family":"cbs","trust_generation":1,"observed_at":"2026-11-09T12:00:00Z","vlans":{"state":"available","value":[]}}`))
	f.Add([]byte(`{"device_id":"sw-1","family":"cbs","trust_generation":1,"observed_at":"2026-11-09T12:00:00Z","ports":{"state":"unavailable","reason":"timeout"}}`))
	f.Add([]byte(`{"device_id":"fw-1","family":"panos","trust_generation":1,"observed_at":"2026-11-09T12:00:00Z","hit_counts":{"state":"incomplete","value":[{"rule_name":"r","hits":1}],"reason":"over_limit"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		o, err := DecodeObservation(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not match ErrInvalid", err)
			}
			return
		}
		raw, err := MarshalObservation(o)
		if err != nil {
			t.Fatalf("accepted observation does not re-encode: %v", err)
		}
		again, err := DecodeObservation(raw)
		if err != nil {
			t.Fatalf("re-encoded observation does not decode: %v", err)
		}
		raw2, err := MarshalObservation(again)
		if err != nil || string(raw2) != string(raw) {
			t.Fatalf("encoding is not stable: %v", err)
		}
	})
}

// FuzzCheckXML feeds arbitrary bytes to the PAN-OS XML limit check; it must
// never panic.
func FuzzCheckXML(f *testing.F) {
	f.Add([]byte(`<response status="success"><result><entry name="a"/></result></response>`))
	f.Add(nested(MaxXMLDepth + 1))
	f.Add([]byte(`<!DOCTYPE a><a/>`))
	f.Add([]byte("<a>\xff</a>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = CheckXML(data, MaxPANOSResponseBytes)
	})
}

// FuzzCheckLines feeds arbitrary bytes to the CBS line limit check; it must
// never panic.
func FuzzCheckLines(f *testing.F) {
	f.Add([]byte("hostname sw1\ninterface gi1/0/1\n"))
	f.Add([]byte(strings.Repeat("a", MaxLineBytes+1)))
	f.Add([]byte("\r\n\r\n\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = CheckLines(data, 1<<16, 16)
	})
}
