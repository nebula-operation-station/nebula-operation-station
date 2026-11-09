// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"strings"
	"testing"
)

func TestCrownJewelTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{"crown_jewels", "crown_jewel_history"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

func TestCrownJewelsRejectBadRows(t *testing.T) {
	db := openTemp(t)
	insert := func(node, role string, impact int, by, reason string) error {
		_, err := db.Exec(`INSERT INTO crown_jewels (node_id, role, impact, marked_by, reason, marked_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, 1)`, node, role, impact, by, reason)
		return err
	}
	if err := insert("host:a", "executor_host", 10, "admin", ""); err != nil {
		t.Fatalf("valid row rejected: %v", err)
	}
	for _, node := range []string{"pve:n1", "guest:100", "ctr:abc", "dev:fw"} {
		if err := insert(node, "other", 1, "admin", ""); err != nil {
			t.Errorf("valid node %q rejected: %v", node, err)
		}
	}
	cases := []struct {
		name, node, role string
		impact           int
		by, reason       string
	}{
		{"duplicate", "host:a", "nas", 8, "admin", ""},
		{"internet entry", "internet", "other", 5, "admin", ""},
		{"netbird entry", "netbird", "other", 5, "admin", ""},
		{"unmanaged", "unk:10.0.0.1", "other", 5, "admin", ""},
		{"bare prefix", "host:", "other", 5, "admin", ""},
		{"no prefix", "fw", "firewall", 10, "admin", ""},
		{"too long", "host:" + strings.Repeat("x", 124), "other", 5, "admin", ""},
		{"unknown role", "host:b", "router", 5, "admin", ""},
		{"impact 0", "host:b", "other", 0, "admin", ""},
		{"impact 11", "host:b", "other", 11, "admin", ""},
		{"no admin", "host:b", "other", 5, "", ""},
		{"long reason", "host:b", "other", 5, "admin", strings.Repeat("r", 513)},
	}
	for _, c := range cases {
		if err := insert(c.node, c.role, c.impact, c.by, c.reason); err == nil {
			t.Errorf("%s: row accepted", c.name)
		}
	}
}

func TestCrownJewelHistoryShapeByAction(t *testing.T) {
	db := openTemp(t)
	insert := func(action string, oldRole, oldImpact, newRole, newImpact any) error {
		_, err := db.Exec(`INSERT INTO crown_jewel_history (node_id, action, old_role, old_impact, new_role, new_impact, admin, at)
			VALUES ('host:a', ?, ?, ?, ?, ?, 'admin', 1)`, action, oldRole, oldImpact, newRole, newImpact)
		return err
	}
	if err := insert("marked", nil, nil, "nas", 8); err != nil {
		t.Errorf("marked rejected: %v", err)
	}
	if err := insert("changed", "nas", 8, "nas", 6); err != nil {
		t.Errorf("changed rejected: %v", err)
	}
	if err := insert("unmarked", "nas", 6, nil, nil); err != nil {
		t.Errorf("unmarked rejected: %v", err)
	}
	bad := []struct {
		name                         string
		action                       string
		oldRole, oldImp, newRole, ni any
	}{
		{"marked with old", "marked", "nas", 8, "nas", 8},
		{"unmarked with new", "unmarked", "nas", 8, "nas", 8},
		{"changed without old", "changed", nil, nil, "nas", 8},
		{"role without impact", "marked", nil, nil, "nas", nil},
		{"unknown action", "deleted", "nas", 8, nil, nil},
		{"impact out of range", "marked", nil, nil, "nas", 12},
	}
	for _, c := range bad {
		if err := insert(c.action, c.oldRole, c.oldImp, c.newRole, c.ni); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
