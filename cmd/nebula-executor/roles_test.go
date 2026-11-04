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
	for _, name := range []string{defaultPveCollectorUser, " " + defaultPveCollectorUser + " ", "", "   "} {
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
	cases := []struct {
		name string
		uid  uint32
		want error
	}{
		{"root", 0, errRootUser},
		{"executor", testExecutorUID, errExecutorUser},
		{"server", 901, errSharedUser},
		{"admin", 1000, errSharedUser},
	}
	for _, c := range cases {
		users := map[string]uint32{"srv": 901, "alice": 1000, "coll": c.uid}
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, "srv", "alice", "coll", quietLog)
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
		roles, err := resolveRolesWith(fakeLookup(users), testExecutorUID, "srv", "alice", name, quietLog)
		if !errors.Is(err, errCollectorUserMissing) {
			t.Errorf("collector %q: err = %v (roles %v), want errCollectorUserMissing", name, err, roles)
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
	if _, err := resolveRolesWith(lookup, testExecutorUID, "srv", "alice", "coll", quietLog); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

func TestResolveRolesServerAndAdminRulesUnchanged(t *testing.T) {
	users := map[string]uint32{"srv": 901, "alice": 1000, "rootish": 0, "exec": testExecutorUID, "coll": 902}
	bad := []struct {
		name, server, admins string
		want                 error
	}{
		{"server is root", "rootish", "alice", errRootUser},
		{"server is executor", "exec", "alice", errExecutorUser},
		{"admin is server", "srv", "srv", errSharedUser},
		{"admin is executor", "srv", "exec", errExecutorUser},
		{"admin is root", "srv", "rootish", errRootUser},
	}
	for _, c := range bad {
		if _, err := resolveRolesWith(fakeLookup(users), testExecutorUID, c.server, c.admins, "coll", quietLog); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	unknown := []struct{ name, server, admins string }{
		{"unknown server", "nobody-here", "alice"},
		{"unknown admin", "srv", "nobody-here"},
	}
	for _, c := range unknown {
		_, err := resolveRolesWith(fakeLookup(users), testExecutorUID, c.server, c.admins, "coll", quietLog)
		var uerr user.UnknownUserError
		if !errors.As(err, &uerr) || string(uerr) != "nobody-here" {
			t.Errorf("%s: err = %v, want the unknown-user error for nobody-here", c.name, err)
		}
	}
}
