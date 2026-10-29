// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const validPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const validRemoteJSON = `{
	"remote_id": "poxmox",
	"name": "Poxmox cluster",
	"kind": "cluster",
	"endpoints": [
		{"host": "poxmox", "port": 8006},
		{"host": "poxmox2", "port": 8006}
	],
	"trust_pin": "` + validPin + `",
	"trust_generation": 3
}`

func TestDecodeRemote(t *testing.T) {
	tooManyEndpoints := make([]string, MaxEndpointsPerRemote+1)
	for i := range tooManyEndpoints {
		tooManyEndpoints[i] = fmt.Sprintf(`{"host":"n%d","port":8006}`, i)
	}
	standalone := `{"remote_id":"solo","kind":"standalone","endpoints":[{"host":"solo","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`

	cases := []struct {
		name    string
		raw     []byte
		wantErr string // substring of the error; empty means success
	}{
		{"valid cluster", []byte(validRemoteJSON), ""},
		{"valid standalone", []byte(standalone), ""},
		{"name omitted", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"poxmox","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), ""},
		{"empty remote_id", []byte(`{"remote_id":"","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "remote_id"},
		{"uppercase remote_id", []byte(`{"remote_id":"Poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "remote_id"},
		{"leading hyphen remote_id", []byte(`{"remote_id":"-poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "remote_id"},
		{"remote_id too long", []byte(`{"remote_id":"` + strings.Repeat("a", 65) + `","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "remote_id"},
		{"remote_id with space", []byte(`{"remote_id":"pox mox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "remote_id"},
		{"unknown kind", []byte(`{"remote_id":"poxmox","kind":"grid","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "kind"},
		{"missing kind", []byte(`{"remote_id":"poxmox","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "kind"},
		{"no endpoints", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[],"trust_pin":"` + validPin + `","trust_generation":1}`), "endpoint"},
		{"standalone with two endpoints", []byte(`{"remote_id":"solo","kind":"standalone","endpoints":[{"host":"a","port":8006},{"host":"b","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "standalone"},
		{"too many endpoints", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[` + strings.Join(tooManyEndpoints, ",") + `],"trust_pin":"` + validPin + `","trust_generation":1}`), "too many endpoints"},
		{"endpoint host uppercase", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"Poxmox","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "host"},
		{"endpoint host empty", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "host"},
		{"endpoint host underscore", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"pox_mox","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "host"},
		{"endpoint host trailing hyphen", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"poxmox-","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "host"},
		{"endpoint host too long", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"` + strings.Repeat("a", 254) + `","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "host"},
		{"endpoint host ip literal", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"10.77.10.2","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), ""},
		{"endpoint port zero", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":0}],"trust_pin":"` + validPin + `","trust_generation":1}`), "port"},
		{"endpoint port too large", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":70000}],"trust_pin":"` + validPin + `","trust_generation":1}`), "port"},
		{"endpoint port negative", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":-1}],"trust_pin":"` + validPin + `","trust_generation":1}`), "port"},
		{"duplicate endpoints", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006},{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "duplicated"},
		{"trust pin 63 hex", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin[:63] + `","trust_generation":1}`), "trust_pin"},
		{"trust pin uppercase", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + strings.ToUpper(validPin) + `","trust_generation":1}`), "trust_pin"},
		{"trust pin non-hex", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + strings.Repeat("g", 64) + `","trust_generation":1}`), "trust_pin"},
		{"trust generation zero", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":0}`), "trust_generation"},
		{"unknown field", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1,"extra":true}`), "unknown field"},
		{"unknown field in endpoint", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006,"tls":true}],"trust_pin":"` + validPin + `","trust_generation":1}`), "unknown field"},
		{"duplicate key", []byte(`{"remote_id":"poxmox","remote_id":"other","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "duplicate key"},
		{"invalid utf8", []byte("{\"remote_id\":\"pox\xffmox\",\"kind\":\"cluster\",\"endpoints\":[{\"host\":\"a\",\"port\":8006}],\"trust_pin\":\"" + validPin + "\",\"trust_generation\":1}"), "UTF-8"},
		{"invalid escape", []byte(`{"remote_id":"pox\xffmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "escape"},
		{"oversize string", []byte(`{"remote_id":"poxmox","name":"` + strings.Repeat("a", MaxTextFieldBytes+1) + `","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`), "exceeds"},
		{"deep nesting", []byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1,"extra":` + strings.Repeat(`{"k":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5) + `}`), "nesting"},
		{"too many objects", []byte("[" + strings.Repeat(`{},`, MaxObjectsPerDocument+1) + `{}` + "]"), "objects"},
		{"oversize document", []byte(strings.Repeat(" ", MaxResponseBytes+1)), "exceeds"},
		{"trailing data", []byte(validRemoteJSON + " {}"), "trailing"},
		{"trailing invalid character", []byte(validRemoteJSON + " !"), "trailing"},
		{"trailing incomplete literal", []byte(validRemoteJSON + " tru"), "trailing"},
		{"trailing unterminated string", []byte(validRemoteJSON + ` "unfinished`), "trailing"},
		{"trailing closing delimiter", []byte(validRemoteJSON + " ]"), "trailing"},
		{"trailing whitespace", []byte(validRemoteJSON + " \t\r\n"), ""},
		{"top level array", []byte(`[1]`), "decode"},
		{"top level string", []byte(`"poxmox"`), "decode"},
		{"empty input", []byte(``), "malformed JSON"},
		{"malformed json", []byte(`{"remote_id":`), "malformed JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := DecodeRemote(tc.raw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if _, verr := ValidateRemote(r); verr != nil {
					t.Fatalf("decoded remote fails validation: %v", verr)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRemoteRoundTrip(t *testing.T) {
	r, err := DecodeRemote([]byte(validRemoteJSON))
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalRemote(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRemote(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, got) {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", r, got)
	}
}
