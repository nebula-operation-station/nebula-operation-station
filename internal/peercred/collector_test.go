// SPDX-License-Identifier: AGPL-3.0-or-later

package peercred

import (
	"errors"
	"fmt"
	"os/user"
	"slices"
	"testing"
)

// fakeLookup resolves names from a fixed table; any other name is an
// unknown user, exactly like os/user.Lookup.
func fakeLookup(users map[string]uint32) func(string) (uint32, error) {
	return func(name string) (uint32, error) {
		if name == "broken" {
			return 0, errors.New("nss unavailable")
		}
		uid, ok := users[name]
		if !ok {
			return 0, user.UnknownUserError(name)
		}
		return uid, nil
	}
}

// TestNetDevCollectorRoleIsDistinct: the netdev-collector role has its own
// name, its own configuration key and default user, and is neither the
// server, admin nor pve-collector role.
func TestNetDevCollectorRoleIsDistinct(t *testing.T) {
	if RoleNetDevCollector != "netdev-collector" {
		t.Fatalf("RoleNetDevCollector = %q", RoleNetDevCollector)
	}
	for _, r := range []Role{RoleServer, RoleAdmin, RolePVECollector} {
		if r == RoleNetDevCollector {
			t.Fatalf("netdev-collector role equals %q", r)
		}
	}
	nd, ok := CollectorConfigFor(RoleNetDevCollector)
	if !ok || nd.Flag != "netdev-collector-user" || nd.DefaultUser != "nebula-netdev-collector" {
		t.Fatalf("netdev-collector config = %+v ok=%v", nd, ok)
	}
	pve, ok := CollectorConfigFor(RolePVECollector)
	if !ok || pve.Flag != "pve-collector-user" || pve.DefaultUser != "nebula-pve-collector" {
		t.Fatalf("pve-collector config = %+v ok=%v", pve, ok)
	}
	for _, r := range []Role{RoleServer, RoleAdmin, Role("discovery"), ""} {
		if _, ok := CollectorConfigFor(r); ok {
			t.Errorf("%q has a collector config", r)
		}
	}
}

// TestAssignCollectorUserMapsOwnUID: the configured user's UID gets exactly
// the netdev-collector role, next to (not merged with) the pve-collector.
func TestAssignCollectorUserMapsOwnUID(t *testing.T) {
	const self = 900
	lookup := fakeLookup(map[string]uint32{
		"nebula-server": 1001, "alice": 1002, "nebula-pve-collector": 1003, "nebula-netdev-collector": 1004, "custom-nd": 1005,
	})
	for _, tc := range []struct {
		name, user string
		wantUID    uint32
	}{
		{"default user", "nebula-netdev-collector", 1004},
		{"configured user", "custom-nd", 1005},
		{"surrounding space", "  custom-nd ", 1005},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roles := map[uint32][]Role{1001: {RoleServer}, 1002: {RoleAdmin}}
			if got, err := AssignCollectorUser(roles, lookup, self, RolePVECollector, "nebula-pve-collector"); err != nil || got != CollectorAssigned {
				t.Fatalf("pve-collector: got=%v err=%v", got, err)
			}
			got, err := AssignCollectorUser(roles, lookup, self, RoleNetDevCollector, tc.user)
			if err != nil || got != CollectorAssigned {
				t.Fatalf("got=%v err=%v", got, err)
			}
			if !slices.Equal(roles[tc.wantUID], []Role{RoleNetDevCollector}) {
				t.Fatalf("uid %d roles %v, want only netdev-collector", tc.wantUID, roles[tc.wantUID])
			}
			if !slices.Equal(roles[1003], []Role{RolePVECollector}) {
				t.Fatalf("pve-collector uid roles %v", roles[1003])
			}
			p := NewPolicy(roles, map[string][]Role{"/m": {RoleNetDevCollector}})
			if _, ok := p.Allowed(tc.wantUID, "/m"); !ok {
				t.Fatal("netdev-collector uid not allowed its method")
			}
			for _, uid := range []uint32{1001, 1002, 1003} {
				if _, ok := p.Allowed(uid, "/m"); ok {
					t.Errorf("uid %d allowed a netdev-collector method", uid)
				}
			}
		})
	}
}

// TestAssignCollectorUserRefusesSharedUID: the collector UID must be a
// dedicated user: root, the executor's own UID and any UID that already
// holds a role (server, admin, the other collector) stop the start, and
// the role table is left unchanged.
func TestAssignCollectorUserRefusesSharedUID(t *testing.T) {
	const self = 900
	lookup := fakeLookup(map[string]uint32{
		"root": 0, "nebula-executor": self, "nebula-server": 1001, "alice": 1002, "nebula-pve-collector": 1003,
	})
	for _, tc := range []struct {
		user string
		want error
	}{
		{"root", ErrRoleUserRoot},
		{"nebula-executor", ErrRoleUserExecutor},
		{"nebula-server", ErrRoleUserShared},
		{"alice", ErrRoleUserShared},
		{"nebula-pve-collector", ErrRoleUserShared},
	} {
		t.Run(tc.user, func(t *testing.T) {
			roles := map[uint32][]Role{1001: {RoleServer}, 1002: {RoleAdmin}, 1003: {RolePVECollector}}
			before := fmt.Sprint(roles)
			got, err := AssignCollectorUser(roles, lookup, self, RoleNetDevCollector, tc.user)
			if got != CollectorNotAssigned || !errors.Is(err, tc.want) {
				t.Fatalf("got=%v err=%v, want %v", got, err, tc.want)
			}
			if fmt.Sprint(roles) != before {
				t.Fatalf("roles changed on refusal: %v", roles)
			}
		})
	}
	// The same refusal holds in the other direction: a pve-collector
	// configured with the netdev-collector's UID.
	roles := map[uint32][]Role{1003: {RoleNetDevCollector}}
	if got, err := AssignCollectorUser(roles, lookup, self, RolePVECollector, "nebula-pve-collector"); got != CollectorNotAssigned || !errors.Is(err, ErrRoleUserShared) {
		t.Fatalf("pve-collector on netdev-collector uid: got=%v err=%v", got, err)
	}
}

// TestAssignCollectorUserMissingUser: an empty name disables the role; a
// missing default user leaves it unassigned and says so in the result (the
// caller logs a warning); a missing explicitly configured user or any
// other lookup failure stops the start. Both collector roles behave alike.
func TestAssignCollectorUserMissingUser(t *testing.T) {
	lookup := fakeLookup(map[string]uint32{})
	for _, tc := range []struct {
		role    Role
		user    string
		want    CollectorAssignment
		wantErr error
		anyErr  bool
	}{
		{RoleNetDevCollector, "", CollectorDisabled, nil, false},
		{RoleNetDevCollector, "   ", CollectorDisabled, nil, false},
		{RoleNetDevCollector, "nebula-netdev-collector", CollectorDefaultUserMissing, nil, false},
		{RoleNetDevCollector, " nebula-netdev-collector ", CollectorDefaultUserMissing, nil, false},
		{RoleNetDevCollector, "custom-nd", CollectorNotAssigned, ErrCollectorUserMissing, true},
		{RoleNetDevCollector, "broken", CollectorNotAssigned, nil, true},
		{RolePVECollector, "", CollectorDisabled, nil, false},
		{RolePVECollector, "nebula-pve-collector", CollectorDefaultUserMissing, nil, false},
		{RolePVECollector, "nebula-netdev-collector", CollectorNotAssigned, ErrCollectorUserMissing, true},
		{RolePVECollector, "broken", CollectorNotAssigned, nil, true},
	} {
		t.Run(string(tc.role)+"/"+tc.user, func(t *testing.T) {
			roles := map[uint32][]Role{}
			got, err := AssignCollectorUser(roles, lookup, 900, tc.role, tc.user)
			if got != tc.want || len(roles) != 0 {
				t.Fatalf("got=%v roles=%v, want %v and no role", got, roles, tc.want)
			}
			if (err != nil) != tc.anyErr || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("err = %v, want error=%v (%v)", err, tc.anyErr, tc.wantErr)
			}
		})
	}
}

// TestAssignCollectorUserRefusesNonCollectorRole: the helper assigns only
// the collector roles; server, admin or an unknown role are refused.
func TestAssignCollectorUserRefusesNonCollectorRole(t *testing.T) {
	lookup := fakeLookup(map[string]uint32{"x": 1500})
	for _, r := range []Role{RoleServer, RoleAdmin, Role("discovery")} {
		roles := map[uint32][]Role{}
		if got, err := AssignCollectorUser(roles, lookup, 900, r, "x"); got != CollectorNotAssigned || !errors.Is(err, ErrNotCollectorRole) || len(roles) != 0 {
			t.Errorf("role %q: got=%v err=%v roles=%v", r, got, err, roles)
		}
	}
}
