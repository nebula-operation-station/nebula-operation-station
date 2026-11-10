// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os/user"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
)

const testExecutorUID = 900

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeLookup resolves names from m and reports any other name the way
// os/user does for an unknown user.
func fakeLookup(m map[string]uint32) func(string) (uint32, error) {
	return func(name string) (uint32, error) {
		if uid, ok := m[name]; ok {
			return uid, nil
		}
		return 0, user.UnknownUserError(name)
	}
}

// pveOnly configures server, admins and the pve-collector user; the
// netdev-collector is disabled.
func pveOnly(server, admins, pve string) roleUsers {
	return roleUsers{Server: server, Admins: admins, Collectors: map[peercred.Role]string{
		peercred.RolePVECollector: pve, peercred.RoleNetDevCollector: "",
	}}
}

// logRecord is one JSON log line written by resolveRolesWith.
type logRecord struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	User  string `json:"user"`
}

// captureLog returns a logger that writes JSON lines to the returned
// function's result.
func captureLog() (*slog.Logger, func(t *testing.T) []logRecord) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	return log, func(t *testing.T) []logRecord {
		t.Helper()
		var out []logRecord
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var r logRecord
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("log line %q: %v", line, err)
			}
			out = append(out, r)
		}
		return out
	}
}

// parseCollectorFlags runs the executor's collector flag registration on
// a fresh flag set and parses args, as the executor start does.
func parseCollectorFlags(t *testing.T, args ...string) map[peercred.Role]string {
	t.Helper()
	fs := flag.NewFlagSet("nebula-executor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := collectorUserFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return f.values()
}

func TestCollectorUserFlagsDefaults(t *testing.T) {
	got := parseCollectorFlags(t)
	want := map[peercred.Role]string{
		peercred.RolePVECollector:    "nebula-pve-collector",
		peercred.RoleNetDevCollector: "nebula-netdev-collector",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults = %v, want %v", got, want)
	}
	got = parseCollectorFlags(t, "-pve-collector-user=pc", "-netdev-collector-user=nd")
	want = map[peercred.Role]string{peercred.RolePVECollector: "pc", peercred.RoleNetDevCollector: "nd"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed = %v, want %v", got, want)
	}
}

// TestExecutorStartAssignsBothCollectorRoles: the start path (flags ->
// roleUsers -> resolveRolesWith) maps each collector UID to its own role.
func TestExecutorStartAssignsBothCollectorRoles(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "pc": 902, "nd": 903}
	collectors := parseCollectorFlags(t, "-pve-collector-user=pc", "-netdev-collector-user=nd")
	log, records := captureLog()
	roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, roleUsers{Server: "srv", Admins: "alice", Collectors: collectors}, log)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32][]peercred.Role{
		901:  {peercred.RoleServer},
		1000: {peercred.RoleAdmin},
		902:  {peercred.RolePVECollector},
		903:  {peercred.RoleNetDevCollector},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
	for _, r := range records(t) {
		if r.Level == "WARN" {
			t.Errorf("unexpected warning %q", r.Msg)
		}
	}
	// The resolved table authorizes each collector for its own method only.
	p := peercred.NewPolicy(roles, map[string][]peercred.Role{
		"/pve": {peercred.RolePVECollector}, "/nd": {peercred.RoleNetDevCollector},
	})
	if _, ok := p.Allowed(903, "/nd"); !ok {
		t.Error("netdev-collector uid not allowed its method")
	}
	if _, ok := p.Allowed(903, "/pve"); ok {
		t.Error("netdev-collector uid allowed a pve-collector method")
	}
	if _, ok := p.Allowed(902, "/nd"); ok {
		t.Error("pve-collector uid allowed a netdev-collector method")
	}
}

// TestExecutorStartMissingDefaultCollectorUserWarns: a missing default
// collector user leaves that role unassigned and logs a warning, for the
// netdev-collector exactly like for the pve-collector.
func TestExecutorStartMissingDefaultCollectorUserWarns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		users   map[string]uint32
		missing peercred.Role
		present peercred.Role
		uid     uint32
	}{
		{"netdev missing", map[string]uint32{"srv": 901, "alice": 1000, "nebula-pve-collector": 902}, peercred.RoleNetDevCollector, peercred.RolePVECollector, 902},
		{"pve missing", map[string]uint32{"srv": 901, "alice": 1000, "nebula-netdev-collector": 903}, peercred.RolePVECollector, peercred.RoleNetDevCollector, 903},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log, records := captureLog()
			roles, err := resolveRolesWith(fakeLookup(tc.users), testExecutorUID,
				roleUsers{Server: "srv", Admins: "alice", Collectors: parseCollectorFlags(t)}, log)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(roles[tc.uid], []peercred.Role{tc.present}) {
				t.Fatalf("uid %d roles = %v, want %s", tc.uid, roles[tc.uid], tc.present)
			}
			for uid, rs := range roles {
				if slices.Contains(rs, tc.missing) {
					t.Fatalf("uid %d got the %s role", uid, tc.missing)
				}
			}
			cfg, _ := peercred.CollectorConfigFor(tc.missing)
			var warned int
			for _, r := range records(t) {
				if r.Level != "WARN" {
					continue
				}
				warned++
				if r.User != cfg.DefaultUser || !strings.Contains(r.Msg, string(tc.missing)) {
					t.Errorf("warning = %+v, want one for %s user %s", r, tc.missing, cfg.DefaultUser)
				}
			}
			if warned != 1 {
				t.Fatalf("got %d warnings, want 1", warned)
			}
		})
	}
}

// TestExecutorStartRefusesSharedNetDevCollectorUser: the netdev-collector
// user must be dedicated: root, the executor, the server, an admin or the
// pve-collector user stop the start with the shared peercred sentinels.
func TestExecutorStartRefusesSharedNetDevCollectorUser(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "pc": 902, "rootish": 0, "exec": testExecutorUID}
	for _, tc := range []struct {
		nd   string
		want error
	}{
		{"rootish", peercred.ErrRoleUserRoot},
		{"exec", peercred.ErrRoleUserExecutor},
		{"srv", peercred.ErrRoleUserShared},
		{"alice", peercred.ErrRoleUserShared},
		{"pc", peercred.ErrRoleUserShared},
		{"custom-nd", peercred.ErrCollectorUserMissing},
	} {
		collectors := parseCollectorFlags(t, "-pve-collector-user=pc", "-netdev-collector-user="+tc.nd)
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, roleUsers{Server: "srv", Admins: "alice", Collectors: collectors}, quietLog)
		if !errors.Is(err, tc.want) || roles != nil {
			t.Errorf("netdev-collector %q: err = %v (roles %v), want %v", tc.nd, err, roles, tc.want)
		}
	}
}

func TestResolveRolesAssignsCollectorRole(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "bob": 1001, "coll": 902}
	roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly("srv", "alice,bob", "coll"), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32][]peercred.Role{
		901:  {peercred.RoleServer},
		1000: {peercred.RoleAdmin},
		1001: {peercred.RoleAdmin},
		902:  {peercred.RolePVECollector},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
}

func TestResolveRolesCollectorMissingOrDisabled(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000}
	for _, name := range []string{"nebula-pve-collector", " nebula-pve-collector ", "", "   "} {
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly("srv", "alice", name), quietLog)
		if err != nil {
			t.Fatalf("collector %q: %v", name, err)
		}
		if len(roles) != 2 {
			t.Fatalf("collector %q: roles = %v, want only server and admin", name, roles)
		}
		for uid, rs := range roles {
			if slices.Contains(rs, peercred.RolePVECollector) {
				t.Fatalf("collector %q: uid %d got the pve-collector role", name, uid)
			}
		}
	}
}

func TestResolveRolesRejectsSharedCollectorUID(t *testing.T) {
	cases := []struct {
		name string
		uid  uint32
		want error
	}{
		{"root", 0, peercred.ErrRoleUserRoot},
		{"executor", testExecutorUID, peercred.ErrRoleUserExecutor},
		{"server", 901, peercred.ErrRoleUserShared},
		{"admin", 1000, peercred.ErrRoleUserShared},
	}
	for _, c := range cases {
		users := map[string]uint32{"srv": 901, "alice": 1000, "coll": c.uid}
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly("srv", "alice", "coll"), quietLog)
		if !errors.Is(err, c.want) {
			t.Errorf("collector shares the %s uid: err = %v (roles %v), want %v", c.name, err, roles, c.want)
		}
	}
}

// TestResolveRolesMissingConfiguredCollectorStopsStart: a collector user
// named explicitly (not the default) that does not exist stops the start;
// only the default name is tolerated as an install without a collector.
func TestResolveRolesMissingConfiguredCollectorStopsStart(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000}
	for _, name := range []string{"coll", " coll ", "nebula-pve-colector"} {
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly("srv", "alice", name), quietLog)
		if !errors.Is(err, peercred.ErrCollectorUserMissing) {
			t.Errorf("collector %q: err = %v (roles %v), want ErrCollectorUserMissing", name, err, roles)
		}
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			t.Errorf("collector %q: err = %v, want it to wrap the unknown-user error", name, err)
		}
	}
}

func TestResolveRolesCollectorLookupFailureStopsStart(t *testing.T) {
	boom := errors.New("nss unavailable")
	lookup := func(name string) (uint32, error) {
		switch name {
		case "srv":
			return 901, nil
		case "alice":
			return 1000, nil
		}
		return 0, boom
	}
	if _, err := resolveRolesWith(lookup, testExecutorUID, pveOnly("srv", "alice", "coll"), quietLog); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

func TestResolveRolesServerAndAdminRulesUnchanged(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "rootish": 0, "exec": testExecutorUID, "coll": 902}
	bad := []struct {
		name, server, admins string
		want                 error
	}{
		{"server is root", "rootish", "alice", peercred.ErrRoleUserRoot},
		{"server is executor", "exec", "alice", peercred.ErrRoleUserExecutor},
		{"admin is server", "srv", "srv", peercred.ErrRoleUserShared},
		{"admin is executor", "srv", "exec", peercred.ErrRoleUserExecutor},
		{"admin is root", "srv", "rootish", peercred.ErrRoleUserRoot},
	}
	for _, c := range bad {
		if _, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly(c.server, c.admins, "coll"), quietLog); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	unknown := []struct{ name, server, admins string }{
		{"unknown server", "nobody-here", "alice"},
		{"unknown admin", "srv", "nobody-here"},
	}
	for _, c := range unknown {
		_, err := resolveRolesWith(fakeLookup(users), testExecutorUID, pveOnly(c.server, c.admins, "coll"), quietLog)
		var uerr user.UnknownUserError
		if !errors.As(err, &uerr) || string(uerr) != "nobody-here" {
			t.Errorf("%s: err = %v, want the unknown-user error for nobody-here", c.name, err)
		}
	}
}
