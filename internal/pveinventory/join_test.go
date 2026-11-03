// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

func joinFixture(t *testing.T) *Store {
	t.Helper()
	s, _, _ := newTestStore(t)
	if err := s.UpsertRemote(context.Background(), remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	g := mkGuest(120, 1, "web1.lab.test")
	g.UUID = testGuestUUID
	mustIngestGuest(t, s, newObsA().guests(g).build())
	return s
}

const testGuestUUID = "0f8fad5b-d9cb-469f-a165-70867728950e"

func joinRequest() GuestJoin {
	return GuestJoin{
		RemoteID: "remote-a", Node: "p1", VMID: 120, Generation: 1, GuestName: "web1.lab.test",
		Host: inventory.Host{ID: "web1", DisplayName: "web1.lab.test",
			Endpoints: []inventory.Endpoint{{Address: "192.168.10.12", Port: 22}}, CredentialRef: "nebula-default"},
		Actor: "alice",
		Enrollment: CommittedEnrollment{
			Digest: strings.Repeat("ab", 32), HostID: "web1", Endpoint: "192.168.10.12:22", CredentialRef: "nebula-default",
			Fingerprint: "SHA256:" + strings.Repeat("A", 43), RemoteID: "remote-a", Node: "p1", VMID: 120, Generation: 1,
			GuestName: "web1.lab.test", GuestUUID: testGuestUUID, JoinMethod: JoinMethodAgent, Pinned: true,
		},
	}
}

// approvedAsIs makes the committed enrollment name j's guest, as if the
// executor had approved and pinned exactly that guest.
func approvedAsIs(j *GuestJoin) {
	j.Enrollment.RemoteID, j.Enrollment.Node, j.Enrollment.VMID = j.RemoteID, j.Node, j.VMID
	j.Enrollment.Generation, j.Enrollment.GuestName = j.Generation, j.GuestName
}

func TestJoinProvisionedGuestCreatesHostAndLink(t *testing.T) {
	s := joinFixture(t)
	ctx := context.Background()
	got, err := s.JoinProvisionedGuest(ctx, joinRequest())
	if err != nil {
		t.Fatalf("JoinProvisionedGuest: %v", err)
	}
	if got.Link.RemoteID != "remote-a" || got.Link.VMID != 120 || got.Link.Generation != 1 || got.Link.HostID != "web1" ||
		got.Link.CreatedBy != "alice" || got.Node != "p1" {
		t.Fatalf("join = %+v", got)
	}
	h, err := s.hostStore().Get(ctx, "web1")
	if err != nil {
		t.Fatalf("host not created: %v", err)
	}
	if len(h.Endpoints) != 1 || h.Endpoints[0].Address != "192.168.10.12" || h.CredentialRef != "nebula-default" {
		t.Fatalf("host = %+v", h)
	}
	// Criticality left unset is unknown, which counts as HIGH (spec 11).
	if h.Criticality != inventory.CriticalityHigh || got.Host.Criticality != inventory.CriticalityHigh {
		t.Fatalf("criticality = %q, want HIGH by default", h.Criticality)
	}
	l, err := s.GetLink(ctx, "remote-a", 120, 1)
	if err != nil || l.HostID != "web1" {
		t.Fatalf("GetLink = %+v, %v", l, err)
	}
}

func TestJoinProvisionedGuestMarksStagedEntryImported(t *testing.T) {
	s := joinFixture(t)
	ctx := context.Background()
	staged, err := s.SweepStaging(ctx, "remote-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 1 || staged[0].VMID != 120 {
		t.Fatalf("staged = %+v, want the new guest", staged)
	}
	if _, err := s.JoinProvisionedGuest(ctx, joinRequest()); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListStaging(ctx, "remote-a", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ImportedAt.IsZero() || list[0].ImportedAsset != "web1" || list[0].ImportedBy != "alice" {
		t.Fatalf("staging = %+v, want imported as web1", list)
	}
}

func TestJoinProvisionedGuestKeepsExplicitCriticality(t *testing.T) {
	s := joinFixture(t)
	req := joinRequest()
	req.Host.Criticality, req.Host.Environment = inventory.CriticalityMedium, inventory.EnvProd
	got, err := s.JoinProvisionedGuest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host.Criticality != inventory.CriticalityMedium || got.Host.Environment != inventory.EnvProd {
		t.Fatalf("host = %+v", got.Host)
	}
}

func TestJoinProvisionedGuestRefusesWrongIncarnation(t *testing.T) {
	cases := map[string]struct {
		mod  func(j *GuestJoin)
		want error
	}{
		"other node":       {func(j *GuestJoin) { j.Node = "p2" }, ErrJoinGuestMismatch},
		"other name":       {func(j *GuestJoin) { j.GuestName = "db1.lab.test" }, ErrJoinGuestMismatch},
		"other generation": {func(j *GuestJoin) { j.Generation = 2 }, ErrGuestNotFound},
		"other vmid":       {func(j *GuestJoin) { j.VMID = 121 }, ErrGuestNotFound},
		"other remote":     {func(j *GuestJoin) { j.RemoteID = "remote-b" }, ErrGuestNotFound},
		"other uuid":       {func(j *GuestJoin) { j.Enrollment.GuestUUID = "11111111-2222-4333-8444-555555555555" }, ErrJoinGuestMismatch},
		"uuid unbound":     {func(j *GuestJoin) { j.Enrollment.GuestUUID = "" }, ErrJoinGuestMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := joinFixture(t)
			req := joinRequest()
			c.mod(&req)
			approvedAsIs(&req)
			if _, err := s.JoinProvisionedGuest(context.Background(), req); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if _, err := s.hostStore().Get(context.Background(), "web1"); !errors.Is(err, inventory.ErrHostNotFound) {
				t.Fatalf("no host may be left behind: %v", err)
			}
		})
	}
}

func TestJoinProvisionedGuestRejectsMalformedInput(t *testing.T) {
	cases := map[string]func(j *GuestJoin){
		"actor":      func(j *GuestJoin) { j.Actor = "al ice" },
		"remote":     func(j *GuestJoin) { j.RemoteID = "Remote A" },
		"node":       func(j *GuestJoin) { j.Node = "p1/../x" },
		"vmid":       func(j *GuestJoin) { j.VMID = 5 },
		"generation": func(j *GuestJoin) { j.Generation = 0 },
		"guest name": func(j *GuestJoin) { j.GuestName = "" },
		"host id":    func(j *GuestJoin) { j.Host.ID = "Web 1" },
		"no endpoint": func(j *GuestJoin) {
			j.Host.Endpoints = nil
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := joinFixture(t)
			req := joinRequest()
			mod(&req)
			if _, err := s.JoinProvisionedGuest(context.Background(), req); err == nil {
				t.Fatal("malformed join accepted")
			}
			if _, err := s.hostStore().Get(context.Background(), "web1"); !errors.Is(err, inventory.ErrHostNotFound) {
				t.Fatalf("no host may be left behind: %v", err)
			}
		})
	}
}

func TestJoinProvisionedGuestNeverReusesAnExistingHost(t *testing.T) {
	s := joinFixture(t)
	mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
	if _, err := s.JoinProvisionedGuest(context.Background(), joinRequest()); !errors.Is(err, inventory.ErrHostExists) {
		t.Fatalf("err = %v, want ErrHostExists", err)
	}
	if _, err := s.GetLink(context.Background(), "remote-a", 120, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("no link may be created: %v", err)
	}
}

func TestJoinProvisionedGuestRefusesLinkedIncarnationAtomically(t *testing.T) {
	s := joinFixture(t)
	mustCreateHost(t, s.db, mkManagedHost("old", "10.77.10.101"))
	if _, err := s.CreateLink(context.Background(), "remote-a", 120, 1, "old", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JoinProvisionedGuest(context.Background(), joinRequest()); !errors.Is(err, ErrLinkExists) {
		t.Fatalf("err = %v, want ErrLinkExists", err)
	}
	if _, err := s.hostStore().Get(context.Background(), "web1"); !errors.Is(err, inventory.ErrHostNotFound) {
		t.Fatalf("the host must be rolled back with the link: %v", err)
	}
}

func TestJoinProvisionedGuestRefusesUnapprovedJoin(t *testing.T) {
	cases := map[string]func(j *GuestJoin){
		"not pinned":     func(j *GuestJoin) { j.Enrollment.Pinned = false },
		"no enrollment":  func(j *GuestJoin) { j.Enrollment = CommittedEnrollment{} },
		"other host id":  func(j *GuestJoin) { j.Host.ID = "web2" },
		"other endpoint": func(j *GuestJoin) { j.Host.Endpoints = []inventory.Endpoint{{Address: "192.168.10.13", Port: 22}} },
		"other port":     func(j *GuestJoin) { j.Host.Endpoints = []inventory.Endpoint{{Address: "192.168.10.12", Port: 2222}} },
		"extra endpoint": func(j *GuestJoin) {
			j.Host.Endpoints = append(j.Host.Endpoints, inventory.Endpoint{Address: "10.0.0.9", Port: 22})
		},
		"other credential":  func(j *GuestJoin) { j.Host.CredentialRef = "other" },
		"empty credential":  func(j *GuestJoin) { j.Host.CredentialRef = "" },
		"other remote":      func(j *GuestJoin) { j.Enrollment.RemoteID = "remote-b" },
		"other node":        func(j *GuestJoin) { j.Enrollment.Node = "p2" },
		"other vmid":        func(j *GuestJoin) { j.Enrollment.VMID = 121 },
		"other generation":  func(j *GuestJoin) { j.Enrollment.Generation = 2 },
		"other guest name":  func(j *GuestJoin) { j.Enrollment.GuestName = "db1.lab.test" },
		"unknown method":    func(j *GuestJoin) { j.Enrollment.JoinMethod = "tofu" },
		"bad digest":        func(j *GuestJoin) { j.Enrollment.Digest = "nope" },
		"bad fingerprint":   func(j *GuestJoin) { j.Enrollment.Fingerprint = "MD5:aa" },
		"bad endpoint form": func(j *GuestJoin) { j.Enrollment.Endpoint = "ssh://192.168.10.12" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := joinFixture(t)
			req := joinRequest()
			mod(&req)
			if _, err := s.JoinProvisionedGuest(context.Background(), req); !errors.Is(err, ErrJoinNotApproved) {
				t.Fatalf("err = %v, want ErrJoinNotApproved", err)
			}
			if _, err := s.hostStore().Get(context.Background(), req.Host.ID); !errors.Is(err, inventory.ErrHostNotFound) {
				t.Fatalf("no host may be created: %v", err)
			}
			if _, err := s.GetLink(context.Background(), "remote-a", 120, 1); !errors.Is(err, ErrLinkNotFound) {
				t.Fatalf("no link may be created: %v", err)
			}
		})
	}
}

func TestJoinProvisionedGuestAcceptsDefaultPortAndReportsPin(t *testing.T) {
	s := joinFixture(t)
	req := joinRequest()
	req.Host.Endpoints = []inventory.Endpoint{{Address: "192.168.10.12"}}
	req.Enrollment.JoinMethod = JoinMethodReview
	got, err := s.JoinProvisionedGuest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != req.Enrollment.Fingerprint || got.JoinMethod != JoinMethodReview {
		t.Fatalf("result = %+v", got)
	}
}
