// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"strings"
	"testing"
)

func TestValidMountPoint(t *testing.T) {
	for _, ok := range []string{"/", "/srv/data", `C:\`, `d:\Data\Sub`} {
		if !validMountPoint(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "data", "C:", `CC:\`, "/a\x00b", "/a\nb", "/\xff", "/" + strings.Repeat("a", MaxLabelBytes)} {
		if validMountPoint(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPVENamesPreserveCase(t *testing.T) {
	for _, ok := range []string{"Pre-Upgrade", "base", "Prod.Pool", "a_1"} {
		if !pveNameRe.MatchString(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "a b", "a/b", "<script>", strings.Repeat("a", 65)} {
		if pveNameRe.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
