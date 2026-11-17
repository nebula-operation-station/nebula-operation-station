// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

func TestNewAPITokenCreatesOpsTokenWithItsScopes(t *testing.T) {
	var out strings.Builder
	if err := newAPIToken("ops-agent:ops.read,ops.notes.write", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ops.read"`) || !strings.Contains(out.String(), `"ops.notes.write"`) ||
		!strings.Contains(out.String(), "Ops token:") {
		t.Fatal(out.String())
	}
	for _, mixed := range []string{"ops-agent:ops.read,inventory.read", "ops-agent:ops.read,vuln.inventory.read"} {
		if err := newAPIToken(mixed, &out); err == nil || !strings.Contains(err.Error(), "carries no other scope") {
			t.Errorf("%q: %v", mixed, err)
		}
	}
}

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
