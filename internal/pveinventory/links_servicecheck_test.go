// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/servicecheck"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

func TestServicePlacementExplicitLifecycle(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	mustCreateHost(t, db, mkManagedHost("web1", "127.0.0.1"))
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatal(err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "api")).build())
	if all, err := s.ListServicePlacements(ctx, 0); err != nil || len(all) != 0 {
		t.Fatalf("inferred placements: %v %v", all, err)
	}
	for _, p := range []ServicePlacement{
		{ServiceName: "api-host", Kind: PlacementHost, HostID: "web1", Source: "manual"},
		{ServiceName: "api-guest", Kind: PlacementGuest, RemoteID: "remote-a", VMID: 100, Generation: 1, Source: "manual"},
		{ServiceName: "api-replica-1", Kind: PlacementContainer, HostID: "web1", ContainerID: strings.Repeat("a", 64), Source: "reviewed-compose"},
		{ServiceName: "api-replica-2", Kind: PlacementContainer, HostID: "web1", ContainerID: strings.Repeat("b", 64), Source: "manual", CheckProtocol: "http", CheckDestination: "127.0.0.1", CheckPort: 8080, CheckInternal: true},
	} {
		got, err := s.SetServicePlacement(ctx, p, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if got.RecordedBy != "alice" || !got.RecordedAt.Equal(*now) || !got.RemovedAt.IsZero() {
			t.Fatalf("metadata: %+v", got)
		}
		read, err := s.GetServicePlacement(ctx, p.ServiceName)
		if err != nil || read != got {
			t.Fatalf("roundtrip: %+v, %v; want %+v", read, err, got)
		}
		if _, err := s.SetServicePlacement(ctx, p, "bob"); !errors.Is(err, ErrServicePlaced) {
			t.Fatalf("duplicate: %v", err)
		}
		*now = now.Add(time.Second)
		removed, err := s.RemoveServicePlacement(ctx, p.ServiceName, "bob", "reassigned")
		if err != nil || removed.RemovedAt.IsZero() || removed.RemovedBy != "bob" || removed.RemoveReason != "reassigned" {
			t.Fatalf("remove: %+v %v", removed, err)
		}
		if _, err := s.GetServicePlacement(ctx, p.ServiceName); !errors.Is(err, ErrPlacementNotFound) {
			t.Fatalf("removed: %v", err)
		}
		if _, err := s.RemoveServicePlacement(ctx, p.ServiceName, "bob", "again"); !errors.Is(err, ErrPlacementNotFound) {
			t.Fatalf("second remove: %v", err)
		}
		if _, err := s.SetServicePlacement(ctx, p, "carol"); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pve_service_placements WHERE service_name=?`, p.ServiceName).Scan(&n); err != nil || n != 2 {
			t.Fatalf("history count %d %v", n, err)
		}
	}
	if all, err := s.ListServicePlacements(ctx, 1); err != nil || len(all) != 1 {
		t.Fatalf("bounded list: %v %v", all, err)
	}
	if _, err := s.ListServicePlacements(ctx, MaxPlacementQuery+1); err == nil {
		t.Fatal("unbounded list")
	}
}

func TestServicePlacementRejectsInvalidInput(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	mustCreateHost(t, db, mkManagedHost("web1", "127.0.0.1"))
	base := ServicePlacement{ServiceName: "api", Kind: PlacementHost, HostID: "web1", Source: "manual"}
	for name, change := range map[string]func(*ServicePlacement){
		"empty name":     func(p *ServicePlacement) { p.ServiceName = "" },
		"long name":      func(p *ServicePlacement) { p.ServiceName = strings.Repeat("a", 129) },
		"bad utf8":       func(p *ServicePlacement) { p.Source = "\xff" },
		"long source":    func(p *ServicePlacement) { p.Source = strings.Repeat("a", 65) },
		"unknown kind":   func(p *ServicePlacement) { p.Kind = "inferred" },
		"unknown host":   func(p *ServicePlacement) { p.HostID = "missing" },
		"mixed identity": func(p *ServicePlacement) { p.ContainerID = strings.Repeat("a", 64) },
		"unknown incarnation": func(p *ServicePlacement) {
			p.Kind = PlacementGuest
			p.HostID = ""
			p.RemoteID = "remote-a"
			p.VMID = 100
			p.Generation = 1
		},
		"short container":        func(p *ServicePlacement) { p.Kind = PlacementContainer; p.ContainerID = "abcdef" },
		"partial check":          func(p *ServicePlacement) { p.CheckProtocol = "http" },
		"approval without check": func(p *ServicePlacement) { p.CheckInternal = true },
		"metadata unapproved": func(p *ServicePlacement) {
			p.CheckProtocol = "http"
			p.CheckDestination = "169.254.169.254"
			p.CheckPort = 80
		},
		"port": func(p *ServicePlacement) { p.CheckProtocol = "tcp"; p.CheckDestination = "web1"; p.CheckPort = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			change(&p)
			if _, err := s.SetServicePlacement(ctx, p, "alice"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := s.SetServicePlacement(ctx, base, "bad actor!"); err == nil {
		t.Fatal("bad actor")
	}
	if _, err := s.SetServicePlacement(ctx, base, "alice"); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"", strings.Repeat("a", MaxUnlinkReasonLen+1), "\xff"} {
		if _, err := s.RemoveServicePlacement(ctx, "api", "alice", reason); err == nil {
			t.Fatal("bad reason")
		}
	}
	if _, err := s.RemoveServicePlacement(ctx, "api", "bad actor!", "reviewed"); err == nil {
		t.Fatal("bad removal actor")
	}
}

func TestGuestPlacementNeverFollowsVMIDReuse(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatal(err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 1, "api")).build())
	p := ServicePlacement{ServiceName: "api", Kind: PlacementGuest, RemoteID: "remote-a", VMID: 100, Generation: 1, Source: "manual"}
	if _, err := s.SetServicePlacement(ctx, p, "alice"); err != nil {
		t.Fatal(err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 2, "api")).build())
	if _, err := s.GetServicePlacement(ctx, "api"); !errors.Is(err, ErrPlacementNotFound) {
		t.Fatalf("stale placement: %v", err)
	}
	if all, err := s.ListServicePlacements(ctx, 0); err != nil || len(all) != 0 {
		t.Fatalf("stale list: %v %v", all, err)
	}
	// Sweep must cover placements even without an SSH host link.
	if _, err := s.SweepVMIDReuse(ctx, "remote-a"); err != nil {
		t.Fatal(err)
	}
	p.Generation = 2
	if _, err := s.SetServicePlacement(ctx, p, "alice"); err != nil {
		t.Fatalf("review new incarnation: %v", err)
	}
}

func TestServicePlacementNeverFollowsHostReenrollment(t *testing.T) {
	for _, kind := range []string{PlacementHost, PlacementContainer} {
		t.Run(kind, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			ctx := context.Background()
			mustCreateHost(t, db, mkManagedHost("web1", "127.0.0.1"))
			mustCreateHost(t, db, mkManagedHost("web2", "127.0.0.2"))
			p := ServicePlacement{
				ServiceName: "api", Kind: kind, HostID: "web1", Source: "manual",
				CheckProtocol: "http", CheckDestination: "127.0.0.1", CheckPort: 8080, CheckInternal: true,
			}
			if kind == PlacementContainer {
				p.ContainerID = strings.Repeat("a", 64)
			}
			original, err := s.SetServicePlacement(ctx, p, "alice")
			if err != nil {
				t.Fatal(err)
			}
			other := p
			other.ServiceName, other.HostID = "other", "web2"
			unaffected, err := s.SetServicePlacement(ctx, other, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if err := inventory.New(db).Delete(ctx, "web1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetServicePlacement(ctx, "api"); !errors.Is(err, ErrPlacementNotFound) {
				t.Fatalf("placement after deletion: %v", err)
			}
			mustCreateHost(t, db, mkManagedHost("web1", "127.0.0.3"))
			if _, err := s.GetServicePlacement(ctx, "api"); !errors.Is(err, ErrPlacementNotFound) {
				t.Fatalf("placement resurrected after re-enrollment: %v", err)
			}
			if all, err := s.ListServicePlacements(ctx, 0); err != nil || len(all) != 1 || all[0] != unaffected {
				t.Fatalf("active placements after re-enrollment: %+v %v", all, err)
			}
			history, err := scanPlacementRow(db.QueryRowContext(ctx,
				`SELECT `+placementColumns+` FROM pve_service_placements WHERE service_name = ?`, "api"))
			if err != nil {
				t.Fatal(err)
			}
			if history.RemovedAt.IsZero() || history.RemovedBy == "" || history.RemoveReason == "" {
				t.Fatalf("missing deletion tombstone: %+v", history)
			}
			preserved := history
			preserved.RemovedAt, preserved.RemovedBy, preserved.RemoveReason = time.Time{}, "", ""
			if preserved != original {
				t.Fatalf("placement history changed: %+v; want %+v", preserved, original)
			}
			p.CheckProtocol, p.CheckDestination, p.CheckPort, p.CheckInternal = "", "", 0, false
			fresh, err := s.SetServicePlacement(ctx, p, "bob")
			if err != nil {
				t.Fatalf("fresh placement after re-enrollment: %v", err)
			}
			got, err := s.GetServicePlacement(ctx, "api")
			if err != nil || got != fresh || got.CheckConfigured() || got.CheckInternal {
				t.Fatalf("fresh placement inherited approval: %+v %v", got, err)
			}
			var n int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pve_service_placements WHERE service_name = ?`, "api").Scan(&n); err != nil || n != 2 {
				t.Fatalf("placement history count: %d %v", n, err)
			}
		})
	}
}

func TestServiceEndpointHealthStaysSeparateFromRuntime(t *testing.T) {
	check := servicecheck.Check{Protocol: "http", Destination: "web1", Port: 80}
	p := ServicePlacement{CheckProtocol: check.Protocol, CheckDestination: check.Destination, CheckPort: check.Port}
	for _, tc := range []struct {
		name   string
		p      ServicePlacement
		check  servicecheck.Check
		result *servicecheck.Result
		want   BoxState
	}{
		{"unconfigured", ServicePlacement{}, check, &servicecheck.Result{Status: servicecheck.StatusOK, HTTPStatus: 200}, StateUnknown},
		{"not yet checked", p, check, nil, StateUnknown},
		{"ok", p, check, &servicecheck.Result{Status: servicecheck.StatusOK, HTTPStatus: 200, Latency: time.Millisecond}, StateOK},
		{"timeout", p, check, &servicecheck.Result{Status: servicecheck.StatusTimeout, Latency: 5 * time.Second}, StateCritical},
		{"other port", p, servicecheck.Check{Protocol: "http", Destination: "web1", Port: 81}, &servicecheck.Result{Status: servicecheck.StatusOK, HTTPStatus: 200}, StateUnknown},
		{"invalid result", p, check, &servicecheck.Result{Status: servicecheck.StatusOK, HTTPStatus: 503}, StateUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.p.Health(StateOff, tc.check, tc.result)
			if h.Runtime != StateOff || h.Endpoint != tc.want {
				t.Fatalf("health: %+v", h)
			}
		})
	}
}

func TestServicePlacementConcurrentCreationIsUnique(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	mustCreateHost(t, db, mkManagedHost("web1", "127.0.0.1"))
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := s.SetServicePlacement(ctx, ServicePlacement{ServiceName: "api", Kind: PlacementHost, HostID: "web1", Source: "manual"}, "alice")
			results <- err
		}()
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent inserts: %d", successes)
	}
	all, err := s.ListServicePlacements(ctx, 0)
	if err != nil || len(all) != 1 {
		t.Fatalf("placements: %v %v", all, err)
	}
}
