// SPDX-License-Identifier: AGPL-3.0-or-later

package jewels_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type fixture struct {
	db    *sql.DB
	store *jewels.Store
	logs  *bytes.Buffer
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &fixture{db: db, logs: &bytes.Buffer{}, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	log := slog.New(slog.NewJSONHandler(f.logs, nil))
	f.store, err = jewels.New(db, log, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// auditLines returns the audit log lines written so far.
func (f *fixture) auditLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["msg"] == "audit" {
			out = append(out, m)
		}
	}
	return out
}

func TestNewRequiresAuditLogger(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := jewels.New(db, nil, nil); err == nil {
		t.Error("store without audit logger accepted")
	}
	if _, err := jewels.New(nil, slog.New(slog.DiscardHandler), nil); err == nil {
		t.Error("store without database accepted")
	}
}

func TestRoleSuggestionsMatchDecision20261109(t *testing.T) {
	want := map[jewels.Role]int{
		jewels.RoleExecutorHost:  10,
		jewels.RoleFirewall:      10,
		jewels.RolePVENode:       8,
		jewels.RoleNAS:           8,
		jewels.RoleHomeAssistant: 8,
	}
	for _, r := range jewels.Roles() {
		got, ok := r.SuggestedImpact()
		if w, has := want[r]; has {
			if !ok || got != w {
				t.Errorf("%s suggested = %d, %v; want %d", r, got, ok, w)
			}
		} else if ok {
			t.Errorf("%s has a suggestion %d; want none", r, got)
		}
		if r.Label() == "" {
			t.Errorf("%s has no label", r)
		}
	}
	if jewels.Role("router").Valid() {
		t.Error("unknown role valid")
	}
}

func TestMarkIsAuditedWithExplicitWeight(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.Mark(ctx, jewels.Mark{Node: "pve:node1", Role: jewels.RolePVENode, Impact: 6, Admin: "maintainer", Reason: "lab core"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Action != jewels.ActionMarked || c.NewImpact != 6 || c.Suggested != 8 || c.ID == 0 {
		t.Fatalf("change = %+v", c)
	}
	list, err := f.store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Impact != 6 || list[0].Role != jewels.RolePVENode || list[0].MarkedBy != "maintainer" || !list[0].MarkedAt.Equal(f.now) {
		t.Fatalf("list = %+v", list)
	}
	lines := f.auditLines(t)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want 1", len(lines))
	}
	a := lines[0]
	if a["kind"] != "crown_jewel_marked" || a["node"] != "pve:node1" || a["user"] != "maintainer" ||
		a["impact"] != float64(6) || a["suggested_impact"] != float64(8) || a["suggestion_confirmed"] != false {
		t.Errorf("audit line = %v", a)
	}
	if strings.Contains(f.logs.String(), "lab core") {
		t.Error("free reason text in the audit log line")
	}
	h, err := f.store.History(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 1 || h[0].Action != jewels.ActionMarked || h[0].Reason != "lab core" || h[0].Suggested != 8 || h[0].NewImpact != 6 {
		t.Fatalf("history = %+v", h)
	}
}

func TestMarkNeverFillsSuggestedWeight(t *testing.T) {
	f := newFixture(t)
	_, err := f.store.Mark(context.Background(), jewels.Mark{Node: "host:exec", Role: jewels.RoleExecutorHost, Admin: "maintainer"})
	if !errors.Is(err, jewels.ErrInvalidImpact) {
		t.Fatalf("mark without weight: %v, want ErrInvalidImpact", err)
	}
	if list, _ := f.store.List(context.Background()); len(list) != 0 {
		t.Fatalf("jewel stored without explicit weight: %+v", list)
	}
	if len(f.auditLines(t)) != 0 {
		t.Error("rejected mark audited")
	}
}

func TestMarkRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	ok := jewels.Mark{Node: "host:a", Role: jewels.RoleNAS, Impact: 8, Admin: "maintainer"}
	cases := []struct {
		name string
		edit func(*jewels.Mark)
		want error
	}{
		{"internet entry", func(m *jewels.Mark) { m.Node = attackpath.InternetID }, jewels.ErrInvalidNode},
		{"netbird entry", func(m *jewels.Mark) { m.Node = attackpath.NetBirdID }, jewels.ErrInvalidNode},
		{"unmanaged", func(m *jewels.Mark) { m.Node = "unk:10.0.0.9" }, jewels.ErrInvalidNode},
		{"bare prefix", func(m *jewels.Mark) { m.Node = "host:" }, jewels.ErrInvalidNode},
		{"no prefix", func(m *jewels.Mark) { m.Node = "nas01" }, jewels.ErrInvalidNode},
		{"control char", func(m *jewels.Mark) { m.Node = "host:a\nb" }, jewels.ErrInvalidNode},
		{"space", func(m *jewels.Mark) { m.Node = "host:a b" }, jewels.ErrInvalidNode},
		{"bad utf8", func(m *jewels.Mark) { m.Node = "host:\xff" }, jewels.ErrInvalidNode},
		{"too long", func(m *jewels.Mark) { m.Node = "host:" + strings.Repeat("x", attackpath.MaxIDBytes) }, jewels.ErrInvalidNode},
		{"unknown role", func(m *jewels.Mark) { m.Role = "router" }, jewels.ErrInvalidRole},
		{"empty role", func(m *jewels.Mark) { m.Role = "" }, jewels.ErrInvalidRole},
		{"impact 0", func(m *jewels.Mark) { m.Impact = 0 }, jewels.ErrInvalidImpact},
		{"impact 11", func(m *jewels.Mark) { m.Impact = 11 }, jewels.ErrInvalidImpact},
		{"impact negative", func(m *jewels.Mark) { m.Impact = -1 }, jewels.ErrInvalidImpact},
		{"no admin", func(m *jewels.Mark) { m.Admin = "" }, jewels.ErrInvalidText},
		{"long admin", func(m *jewels.Mark) { m.Admin = strings.Repeat("a", jewels.MaxAdminBytes+1) }, jewels.ErrInvalidText},
		{"long reason", func(m *jewels.Mark) { m.Reason = strings.Repeat("r", jewels.MaxReasonBytes+1) }, jewels.ErrInvalidText},
		{"reason control", func(m *jewels.Mark) { m.Reason = "a\x1bb" }, jewels.ErrInvalidText},
		{"reason bad utf8", func(m *jewels.Mark) { m.Reason = "\xc3" }, jewels.ErrInvalidText},
	}
	for _, c := range cases {
		m := ok
		c.edit(&m)
		if _, err := f.store.Mark(context.Background(), m); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if len(f.auditLines(t)) != 0 {
		t.Error("rejected marks audited")
	}
}

func TestMarkChangeAndNoop(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m := jewels.Mark{Node: "dev:fw", Role: jewels.RoleFirewall, Impact: 10, Admin: "maintainer"}
	if _, err := f.store.Mark(ctx, m); err != nil {
		t.Fatal(err)
	}
	c, err := f.store.Mark(ctx, m)
	if err != nil || c.Action != "" {
		t.Fatalf("same mark again: %+v, %v; want no change", c, err)
	}
	f.now = f.now.Add(time.Hour)
	m.Impact, m.Admin = 9, "second"
	c, err = f.store.Mark(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if c.Action != jewels.ActionChanged || c.OldImpact != 10 || c.OldRole != jewels.RoleFirewall || c.NewImpact != 9 {
		t.Fatalf("change = %+v", c)
	}
	list, _ := f.store.List(ctx)
	if len(list) != 1 || list[0].Impact != 9 || list[0].MarkedBy != "second" || !list[0].UpdatedAt.Equal(f.now) || list[0].MarkedAt.Equal(f.now) {
		t.Fatalf("list = %+v", list)
	}
	lines := f.auditLines(t)
	if len(lines) != 2 || lines[1]["kind"] != "crown_jewel_changed" || lines[1]["old_impact"] != float64(10) || lines[1]["impact"] != float64(9) {
		t.Fatalf("audit = %v", lines)
	}
}

func TestUnmarkIsAudited(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.store.Unmark(ctx, "host:a", "maintainer", ""); !errors.Is(err, jewels.ErrNotFound) {
		t.Fatalf("unmark unknown: %v", err)
	}
	if _, err := f.store.Mark(ctx, jewels.Mark{Node: "host:a", Role: jewels.RoleHomeAssistant, Impact: 8, Admin: "maintainer"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Unmark(ctx, "host:a", "", ""); !errors.Is(err, jewels.ErrInvalidText) {
		t.Fatalf("unmark without admin: %v", err)
	}
	c, err := f.store.Unmark(ctx, "host:a", "maintainer", "retired")
	if err != nil {
		t.Fatal(err)
	}
	if c.Action != jewels.ActionUnmarked || c.OldImpact != 8 || c.OldRole != jewels.RoleHomeAssistant {
		t.Fatalf("change = %+v", c)
	}
	if list, _ := f.store.List(ctx); len(list) != 0 {
		t.Fatalf("still listed: %+v", list)
	}
	lines := f.auditLines(t)
	if len(lines) != 2 || lines[1]["kind"] != "crown_jewel_unmarked" || lines[1]["old_impact"] != float64(8) {
		t.Fatalf("audit = %v", lines)
	}
	h, _ := f.store.History(ctx, 0)
	if len(h) != 2 || h[0].Action != jewels.ActionUnmarked || h[1].Action != jewels.ActionMarked {
		t.Fatalf("history = %+v", h)
	}
}

func TestMarkLimit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range jewels.MaxJewels {
		if _, err := f.store.Mark(ctx, jewels.Mark{Node: fmt.Sprintf("host:h%02d", i), Role: jewels.RoleOther, Impact: 1 + i%10, Admin: "maintainer"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.Mark(ctx, jewels.Mark{Node: "host:extra", Role: jewels.RoleOther, Impact: 5, Admin: "maintainer"}); !errors.Is(err, jewels.ErrLimit) {
		t.Fatalf("mark beyond limit: %v", err)
	}
	// Changing an existing jewel at the limit still works.
	if _, err := f.store.Mark(ctx, jewels.Mark{Node: "host:h00", Role: jewels.RoleOther, Impact: 10, Admin: "maintainer"}); err != nil {
		t.Fatalf("change at limit: %v", err)
	}
}

func TestTargetsFeedAttackPathOrderedByImpact(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, m := range []jewels.Mark{
		{Node: "host:nas", Role: jewels.RoleNAS, Impact: 8, Admin: "maintainer"},
		{Node: "host:exec", Role: jewels.RoleExecutorHost, Impact: 10, Admin: "maintainer"},
		{Node: "guest:101", Role: jewels.RoleOther, Impact: 3, Admin: "maintainer"},
	} {
		if _, err := f.store.Mark(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.store.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []attackpath.Target{{Node: "host:exec", Impact: 10}, {Node: "host:nas", Impact: 8}, {Node: "guest:101", Impact: 3}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

func TestNodeKind(t *testing.T) {
	cases := map[string]attackpath.NodeKind{
		"host:a": attackpath.NodeHost, "pve:n": attackpath.NodePVENode, "guest:1": attackpath.NodeGuest,
		"ctr:x": attackpath.NodeContainer, "dev:fw": attackpath.NodeNetworkDevice,
	}
	for id, want := range cases {
		if got, err := jewels.NodeKind(id); err != nil || got != want {
			t.Errorf("NodeKind(%q) = %v, %v; want %v", id, got, err, want)
		}
	}
	for _, id := range []string{"", "internet", "netbird", "unk:x", "host:", "x:y"} {
		if _, err := jewels.NodeKind(id); !errors.Is(err, jewels.ErrInvalidNode) {
			t.Errorf("NodeKind(%q) err = %v", id, err)
		}
	}
}
