// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for single-endpoint edits (job ep01): adding an alternate
// endpoint, changing the order and removing one, with explicit, unique
// priorities 0..n-1, duplicate and limit checks, and the rule that the
// last endpoint of a host cannot be removed.

package inventory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// endpointHost is a host with one primary endpoint.
func endpointHost(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, _ := openStore(t)
	ctx := context.Background()
	h := validHost()
	h.Endpoints = []Endpoint{{Address: "10.0.0.11", Port: 22}}
	if _, err := s.Create(ctx, h, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return s, ctx
}

// priorities returns the stored (address, port, priority) rows of a host
// in priority order.
func priorities(t *testing.T, s *Store, hostID string) []int {
	t.Helper()
	rows, err := s.db.Query(`
		SELECT e.priority FROM host_endpoints e JOIN hosts h ON h.id = e.host_id
		WHERE h.name = ? ORDER BY e.priority, e.id`, hostID)
	if err != nil {
		t.Fatalf("query priorities: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func wantEndpoints(t *testing.T, s *Store, ctx context.Context, want []Endpoint) {
	t.Helper()
	h, err := s.Get(ctx, "web-01")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(h.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", h.Endpoints, want)
	}
	p := priorities(t, s, "web-01")
	for i := range p {
		if p[i] != i {
			t.Fatalf("priorities = %v, want 0..%d without gaps or ties", p, len(p)-1)
		}
	}
}

func TestAddEndpointAppendsAlternate(t *testing.T) {
	s, ctx := endpointHost(t)
	ch, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "VPN.Example.ORG", Port: 0})
	if err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	want := []Endpoint{{"10.0.0.11", 22}, {"vpn.example.org", 22}}
	if !reflect.DeepEqual(ch.Before, want[:1]) || !reflect.DeepEqual(ch.After, want) {
		t.Fatalf("change = %+v", ch)
	}
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "2001:DB8:0:0::1", Port: 2222}); err != nil {
		t.Fatalf("AddEndpoint v6: %v", err)
	}
	wantEndpoints(t, s, ctx, append(want, Endpoint{"2001:db8::1", 2222}))
}

func TestAddEndpointRejectsDuplicates(t *testing.T) {
	s, ctx := endpointHost(t)
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "fd00::9", Port: 22}); err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	for _, e := range []Endpoint{
		{"10.0.0.11", 22},
		{"10.0.0.11", 0}, // default port 22
		{"fd00:0::9", 22},
		{"FD00::9", 22},
	} {
		if _, err := s.AddEndpoint(ctx, "web-01", e); !errors.Is(err, ErrEndpointExists) {
			t.Errorf("AddEndpoint(%v) = %v, want ErrEndpointExists", e, err)
		}
	}
	// Same address, other port is a different endpoint.
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{"10.0.0.11", 2222}); err != nil {
		t.Errorf("AddEndpoint other port: %v", err)
	}
}

func TestAddEndpointRejectsMoreThanFour(t *testing.T) {
	s, ctx := endpointHost(t)
	for _, a := range []string{"10.0.0.12", "10.0.0.13", "10.0.0.14"} {
		if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{a, 22}); err != nil {
			t.Fatalf("AddEndpoint %s: %v", a, err)
		}
	}
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{"10.0.0.15", 22}); !errors.Is(err, ErrTooManyEndpoints) {
		t.Fatalf("fifth endpoint: err = %v, want ErrTooManyEndpoints", err)
	}
	h, _ := s.Get(ctx, "web-01")
	if len(h.Endpoints) != MaxEditableEndpoints {
		t.Fatalf("endpoints = %d, want %d", len(h.Endpoints), MaxEditableEndpoints)
	}
}

func TestAddEndpointRejectsMalformed(t *testing.T) {
	s, ctx := endpointHost(t)
	for _, e := range []Endpoint{
		{"", 22},
		{"   ", 22},
		{"<script>", 22},
		{"host name", 22},
		{"fe80::1%eth0", 22},
		{"10.0.0.300", 22},
		{"-bad.example", 22},
		{"10.0.0.20:22", 22},
		{"[fd00::1]", 22},
		{"ok.example", -1},
		{"ok.example", 65536},
		{"bad\xff", 22},
	} {
		if _, err := s.AddEndpoint(ctx, "web-01", e); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("AddEndpoint(%q, %d) = %v, want ErrInvalidEndpoint", e.Address, e.Port, err)
		}
	}
	wantEndpoints(t, s, ctx, []Endpoint{{"10.0.0.11", 22}})
}

func TestMoveEndpointChangesOrder(t *testing.T) {
	s, ctx := endpointHost(t)
	for _, a := range []string{"10.0.0.12", "10.0.0.13"} {
		if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{a, 22}); err != nil {
			t.Fatalf("AddEndpoint: %v", err)
		}
	}
	ch, err := s.MoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.13", 22}, 0)
	if err != nil {
		t.Fatalf("MoveEndpoint: %v", err)
	}
	want := []Endpoint{{"10.0.0.13", 22}, {"10.0.0.11", 22}, {"10.0.0.12", 22}}
	if !reflect.DeepEqual(ch.After, want) {
		t.Fatalf("after = %v, want %v", ch.After, want)
	}
	wantEndpoints(t, s, ctx, want)
	if _, err := s.MoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.13", 0}, 2); err != nil {
		t.Fatalf("MoveEndpoint down: %v", err)
	}
	wantEndpoints(t, s, ctx, []Endpoint{{"10.0.0.11", 22}, {"10.0.0.12", 22}, {"10.0.0.13", 22}})
}

func TestMoveEndpointRejectsUnknownAndOutOfRange(t *testing.T) {
	s, ctx := endpointHost(t)
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{"10.0.0.12", 22}); err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	if _, err := s.MoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.99", 22}, 0); !errors.Is(err, ErrEndpointNotFound) {
		t.Errorf("unknown: err = %v, want ErrEndpointNotFound", err)
	}
	for _, to := range []int{-1, 2, 100} {
		if _, err := s.MoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.12", 22}, to); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("to=%d: err = %v, want ErrInvalidEndpoint", to, err)
		}
	}
	wantEndpoints(t, s, ctx, []Endpoint{{"10.0.0.11", 22}, {"10.0.0.12", 22}})
}

func TestRemoveEndpointRenumbers(t *testing.T) {
	s, ctx := endpointHost(t)
	for _, a := range []string{"10.0.0.12", "10.0.0.13"} {
		if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{a, 22}); err != nil {
			t.Fatalf("AddEndpoint: %v", err)
		}
	}
	ch, err := s.RemoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.11", 22})
	if err != nil {
		t.Fatalf("RemoveEndpoint: %v", err)
	}
	if len(ch.Before) != 3 || len(ch.After) != 2 {
		t.Fatalf("change = %+v", ch)
	}
	// The first alternate becomes the primary.
	wantEndpoints(t, s, ctx, []Endpoint{{"10.0.0.12", 22}, {"10.0.0.13", 22}})
	if _, err := s.RemoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.11", 22}); !errors.Is(err, ErrEndpointNotFound) {
		t.Errorf("removed twice: err = %v, want ErrEndpointNotFound", err)
	}
}

func TestRemoveLastEndpointRefused(t *testing.T) {
	s, ctx := endpointHost(t)
	if _, err := s.RemoveEndpoint(ctx, "web-01", Endpoint{"10.0.0.11", 22}); !errors.Is(err, ErrLastEndpoint) {
		t.Fatalf("err = %v, want ErrLastEndpoint", err)
	}
	wantEndpoints(t, s, ctx, []Endpoint{{"10.0.0.11", 22}})
}

func TestEndpointEditsUnknownHost(t *testing.T) {
	s, ctx := endpointHost(t)
	e := Endpoint{"10.0.0.11", 22}
	if _, err := s.AddEndpoint(ctx, "nope", Endpoint{"10.0.0.12", 22}); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("add: %v", err)
	}
	if _, err := s.MoveEndpoint(ctx, "nope", e, 0); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("move: %v", err)
	}
	if _, err := s.RemoveEndpoint(ctx, "nope", e); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("remove: %v", err)
	}
}

func TestEndpointKeyNormalizes(t *testing.T) {
	cases := []struct {
		in   Endpoint
		want string
	}{
		{Endpoint{"10.0.0.1", 0}, "10.0.0.1:22"},
		{Endpoint{"Host.Example", 2222}, "host.example:2222"},
		{Endpoint{"2001:DB8::0:1", 22}, "[2001:db8::1]:22"},
	}
	for _, c := range cases {
		if got := EndpointKey(c.in); got != c.want {
			t.Errorf("EndpointKey(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestValidateRejectsDuplicateSpellings checks that Validate (and so
// Create and Update) uses the same duplicate rule as the endpoint edits:
// two spellings of one normalized endpoint are a duplicate.
func TestValidateRejectsDuplicateSpellings(t *testing.T) {
	cases := []struct {
		name string
		eps  []Endpoint
	}{
		{"ipv6 zero group", []Endpoint{{Address: "fd00::9", Port: 22}, {Address: "fd00:0::9", Port: 22}}},
		{"ipv6 case", []Endpoint{{Address: "fd00::9", Port: 22}, {Address: "FD00::9", Port: 22}}},
		{"ipv6 full form", []Endpoint{{Address: "fd00:0:0:0:0:0:0:9", Port: 0}, {Address: "fd00::9", Port: 22}}},
		{"hostname case", []Endpoint{{Address: "web.example.org", Port: 22}, {Address: "WEB.example.org", Port: 22}}},
		{"default port", []Endpoint{{Address: "10.0.0.11", Port: 0}, {Address: "10.0.0.11", Port: 22}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ctx := endpointHost(t)
			h := validHost()
			h.Endpoints = c.eps
			var verr *ValidationError
			if err := Validate(h); !errors.As(err, &verr) {
				t.Fatalf("Validate = %v, want ValidationError", err)
			}
			h.ID = "web-02"
			if _, err := s.Create(ctx, h, CreateOptions{}); !errors.As(err, &verr) {
				t.Fatalf("Create = %v, want ValidationError", err)
			}
			h.ID = "web-01"
			if _, err := s.Update(ctx, h); !errors.As(err, &verr) {
				t.Fatalf("Update = %v, want ValidationError", err)
			}
			wantEndpoints(t, s, ctx, []Endpoint{{Address: "10.0.0.11", Port: 22}})
		})
	}
	// Different ports on one address stay two endpoints.
	h := validHost()
	h.Endpoints = []Endpoint{{Address: "fd00::9", Port: 22}, {Address: "fd00:0::9", Port: 2222}}
	if err := Validate(h); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

// TestEndpointEditsRefuseStoredDuplicateSpellings covers rows stored
// before the normalized duplicate rule: two spellings of one endpoint
// must not be collapsed by a move or remove (which would update one row
// twice or delete nothing); the edit is refused and nothing changes.
func TestEndpointEditsRefuseStoredDuplicateSpellings(t *testing.T) {
	s, ctx := endpointHost(t)
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "fd00::9", Port: 22}); err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	if _, err := s.db.Exec(`
		INSERT INTO host_endpoints (host_id, address, port, priority, created_at)
		SELECT id, 'fd00:0::9', 22, 2, '2026-01-01T00:00:00Z' FROM hosts WHERE name = 'web-01'`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	want := []Endpoint{{Address: "10.0.0.11", Port: 22}, {Address: "fd00::9", Port: 22}, {Address: "fd00:0::9", Port: 22}}
	var verr *ValidationError
	if _, err := s.MoveEndpoint(ctx, "web-01", Endpoint{Address: "fd00::9", Port: 22}, 0); !errors.As(err, &verr) {
		t.Fatalf("MoveEndpoint = %v, want ValidationError", err)
	}
	if _, err := s.RemoveEndpoint(ctx, "web-01", Endpoint{Address: "fd00:0::9", Port: 22}); !errors.As(err, &verr) {
		t.Fatalf("RemoveEndpoint = %v, want ValidationError", err)
	}
	if _, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "10.0.0.12", Port: 22}); !errors.As(err, &verr) {
		t.Fatalf("AddEndpoint = %v, want ValidationError", err)
	}
	h, err := s.Get(ctx, "web-01")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(h.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", h.Endpoints, want)
	}
	// The settings form (Update) repairs the list.
	h.Endpoints = want[:2]
	if _, err := s.Update(ctx, h); err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantEndpoints(t, s, ctx, want[:2])
}

// TestAddEndpointRefusesEndpointOfOtherHost: an endpoint another host
// already has (in any spelling) is refused inside the add transaction,
// and of two concurrent adds of one endpoint to two hosts at most one
// is stored, so two hosts never share an endpoint (and a pinned key).
func TestAddEndpointRefusesEndpointOfOtherHost(t *testing.T) {
	s, ctx := endpointHost(t)
	other := validHost()
	other.ID = "db-01"
	other.Endpoints = []Endpoint{{Address: "fd00::50", Port: 22}}
	if _, err := s.Create(ctx, other, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := s.AddEndpoint(ctx, "web-01", Endpoint{Address: "FD00:0::50"})
	if !errors.Is(err, ErrEndpointInUse) || !strings.Contains(err.Error(), "db-01") {
		t.Fatalf("AddEndpoint = %v, want ErrEndpointInUse naming db-01", err)
	}
	wantEndpoints(t, s, ctx, []Endpoint{{Address: "10.0.0.11", Port: 22}})

	for round := 0; round < 5; round++ {
		ep := Endpoint{Address: fmt.Sprintf("10.9.0.%d", round+1), Port: 22}
		var wg sync.WaitGroup
		for _, id := range []string{"web-01", "db-01"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				_, _ = s.AddEndpoint(ctx, id, ep)
			}(id)
		}
		wg.Wait()
		owners := 0
		for _, id := range []string{"web-01", "db-01"} {
			h, err := s.Get(ctx, id)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if indexOf(h.Endpoints, ep) >= 0 {
				owners++
			}
		}
		if owners > 1 {
			t.Fatalf("round %d: %s stored on %d hosts", round, EndpointKey(ep), owners)
		}
		// Remove it again so the next round starts from the same state.
		for _, id := range []string{"web-01", "db-01"} {
			_, _ = s.RemoveEndpoint(ctx, id, ep)
		}
	}
}

// TestUpdateWithEndpointChangeReturnsBeforeAndAfter checks that the
// endpoint list before an update is the one the update replaced.
func TestUpdateWithEndpointChangeReturnsBeforeAndAfter(t *testing.T) {
	s, ctx := endpointHost(t)
	h, err := s.Get(ctx, "web-01")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	h.Endpoints = []Endpoint{{Address: "fd00::9", Port: 0}, {Address: "10.0.0.11", Port: 22}}
	got, ch, err := s.UpdateWithEndpointChange(ctx, h)
	if err != nil {
		t.Fatalf("UpdateWithEndpointChange: %v", err)
	}
	if want := []Endpoint{{Address: "10.0.0.11", Port: 22}}; !reflect.DeepEqual(ch.Before, want) {
		t.Errorf("Before = %v, want %v", ch.Before, want)
	}
	if !reflect.DeepEqual(ch.After, got.Endpoints) {
		t.Errorf("After = %v, stored %v", ch.After, got.Endpoints)
	}
	unknown := Host{ID: "nope", Environment: EnvDev, Criticality: CriticalityLow,
		Endpoints: []Endpoint{{Address: "10.0.0.1"}}}
	if _, ch, err := s.UpdateWithEndpointChange(ctx, unknown); !errors.Is(err, ErrHostNotFound) || ch.After != nil {
		t.Errorf("unknown host = %v (after %v), want ErrHostNotFound and no change", err, ch.After)
	}
}
