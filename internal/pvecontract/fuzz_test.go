// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzDecodeRemote feeds arbitrary bytes to the remote decoder; it must
// never panic.
func FuzzDecodeRemote(f *testing.F) {
	f.Add([]byte(validRemoteJSON))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"remote_id":"poxmox","kind":"cluster","endpoints":[{"host":"a","port":8006}],"trust_pin":"` + validPin + `","trust_generation":1}`))
	f.Add([]byte(strings.Repeat(`{"a":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5)))
	f.Add([]byte("[" + strings.Repeat(`{},`, 1000) + `{}` + "]"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeRemote(data)
	})
}

// FuzzDecodeObservation feeds arbitrary bytes to the observation decoder;
// it must never panic.
func FuzzDecodeObservation(f *testing.F) {
	b, err := json.Marshal(baseObservation())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"remote_id":"poxmox"}`))
	f.Add([]byte(`{"nodes":{"state":"unavailable","reason":"x"}}`))
	f.Add([]byte(strings.Repeat(`{"a":`, MaxNesting+5) + `1` + strings.Repeat(`}`, MaxNesting+5)))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeObservation(data)
	})
}
