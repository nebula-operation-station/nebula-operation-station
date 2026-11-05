// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"io"
	"log/slog"
	"os/user"
	"reflect"
	"slices"
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

func TestResolveRolesAssignsCollectorRole(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "bob": 1001, "coll": 902}
	roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, "srv", "alice,bob", "coll", quietLog)
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
	for _, name := range []string{"coll", "", "   "} {
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, "srv", "alice", name, quietLog)
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
	cases := map[string]uint32{
		"root":     0,
		"executor": testExecutorUID,
		"server":   901,
		"admin":    1000,
	}
	for name, uid := range cases {
		users := map[string]uint32{"srv": 901, "alice": 1000, "coll": uid}
		if roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, "srv", "alice", "coll", quietLog); err == nil {
			t.Errorf("collector shares the %s uid: accepted with roles %v", name, roles)
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
	if _, err := resolveRolesWith(lookup, testExecutorUID, "srv", "alice", "coll", quietLog); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

func TestResolveRolesServerAndAdminRulesUnchanged(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "rootish": 0, "exec": testExecutorUID, "coll": 902}
	bad := []struct{ name, server, admins string }{
		{"server is root", "rootish", "alice"},
		{"server is executor", "exec", "alice"},
		{"unknown server", "nobody-here", "alice"},
		{"admin is server", "srv", "srv"},
		{"admin is executor", "srv", "exec"},
		{"admin is root", "srv", "rootish"},
		{"unknown admin", "srv", "nobody-here"},
	}
	for _, c := range bad {
		if _, err := resolveRolesWith(fakeLookup(users), testExecutorUID, c.server, c.admins, "coll", quietLog); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
