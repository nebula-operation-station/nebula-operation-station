// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"strings"
	"testing"
)

func TestValidBridgeName(t *testing.T) {
	for _, s := range []string{"vmbr0", "vmbr0.100", "br-lan", "vnet_1", "0br", "-br", "a", strings.Repeat("b", 15), "a.."} {
		if !ValidBridgeName(s) {
			t.Errorf("ValidBridgeName(%q) = false", s)
		}
	}
	for _, s := range []string{"", ".", "..", strings.Repeat("b", 16), "br/0", "br:0", "br 0", "br\t0", "br\n0",
		"br\x00", "br\x7f", "br\xff", "brü", "<script>", "br,0", "br=0", "br;0"} {
		if ValidBridgeName(s) {
			t.Errorf("ValidBridgeName(%q) = true", s)
		}
	}
}
