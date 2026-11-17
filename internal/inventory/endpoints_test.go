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
	"reflect"
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
