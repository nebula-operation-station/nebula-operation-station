// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"errors"
	"strings"
	"testing"
)

// TestDecodeGuestNetRejectsDuplicateKeys pins that a repeated key is refused,
// so a record cannot carry two values for one field.
func TestDecodeGuestNetRejectsDuplicateKeys(t *testing.T) {
	good, err := MarshalGuestNet(validGuestNetRecord())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"top-level duplicate": strings.Replace(string(good), `"version":1`, `"version":1,"version":1`, 1),
		"nic duplicate":       strings.Replace(string(good), `"vlan":30`, `"vlan":30,"vlan":0`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGuestNet([]byte(raw)); !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("decode err = %v, want ErrGuestNetInvalid", err)
			}
		})
	}
}

// TestDecodeGuestNetRejectsCaseVariantKeys pins that keys match the schema
// names exactly. encoding/json would otherwise bind "REMOTE" to remote.
func TestDecodeGuestNetRejectsCaseVariantKeys(t *testing.T) {
	good, err := MarshalGuestNet(validGuestNetRecord())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"top-level case variant": strings.Replace(string(good), `"remote"`, `"REMOTE"`, 1),
		"nic case variant":       strings.Replace(string(good), `"bridge"`, `"Bridge"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGuestNet([]byte(raw)); !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("decode err = %v, want ErrGuestNetInvalid", err)
			}
		})
	}
}
