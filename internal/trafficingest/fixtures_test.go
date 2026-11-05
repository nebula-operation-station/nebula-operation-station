// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse MAC %s: %v", s, err)
	}
	return m
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type fixtureSection struct {
	Status    string `json:"status"`
	Truncated bool   `json:"truncated"`
	Data      string `json:"data"`
}

// netFactsDoc assembles a net-facts-v1 result document as the net.facts
// script prints it from the recorded command outputs of host dir and the
// socket table ss.
func netFactsDoc(t *testing.T, dir, ss string) []byte {
	t.Helper()
	return netFactsDocWith(t, dir, readFixture(t, filepath.Join(dir, ss)), nil)
}

// netFactsDocWith is netFactsDoc with explicit socket text and section
// overrides.
func netFactsDocWith(t *testing.T, dir string, ss []byte, override map[string]fixtureSection) []byte {
	t.Helper()
	ok := func(b []byte) fixtureSection {
		return fixtureSection{Status: "ok", Data: base64.StdEncoding.EncodeToString(b)}
	}
	doc := map[string]any{
		"format":      "net-facts-v1",
		"phase":       "done",
		"addr":        ok(readFixture(t, filepath.Join(dir, "addr.json"))),
		"link":        ok(readFixture(t, filepath.Join(dir, "link.json"))),
		"route":       ok(readFixture(t, filepath.Join(dir, "route.json"))),
		"route6":      fixtureSection{Status: "unavailable"},
		"neigh":       ok(readFixture(t, filepath.Join(dir, "neigh.json"))),
		"neigh6":      fixtureSection{Status: "unavailable"},
		"bridge_vlan": fixtureSection{Status: "absent"},
		"lldp":        fixtureSection{Status: "absent"},
		"sockets":     ok(ss),
		"conntrack":   fixtureSection{Status: "absent"},
	}
	for k, v := range override {
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode net.facts document: %v", err)
	}
	return b
}
