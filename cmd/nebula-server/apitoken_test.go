// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

func TestNewAPITokenPrintsTheTokenAndOnlyItsHash(t *testing.T) {
	var out strings.Builder
	if err := newAPIToken("homeassistant:inventory.read,operations.read", &out); err != nil {
		t.Fatal(err)
	}
	tok := regexp.MustCompile(`nos_[A-Za-z0-9_-]{43}`).FindString(out.String())
	if tok == "" || !strings.Contains(out.String(), `"sha256": "`+api.HashToken(tok)+`"`) || strings.Count(out.String(), tok) != 1 {
		t.Fatal(out.String())
	}
	for _, bad := range []string{"", "x", "x:", ":inventory.read", "x:vault.read", "Home Assistant:inventory.read"} {
		if err := newAPIToken(bad, &out); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
