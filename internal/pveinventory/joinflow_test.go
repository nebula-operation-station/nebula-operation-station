// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeJoinExecutor answers like the executor: the commit echoes the
// approved binding.
type fakeJoinExecutor struct {
	proposals int
	proposed  []*pb.ProposeGuestJoinRequest
	commits   []*pb.CommitGuestJoinRequest
	pinned    bool
	// echo overrides the committed binding the executor reports.
	echo func(c *pb.CommitGuestJoinResponse)
}

func (f *fakeJoinExecutor) ProposeGuestJoin(_ context.Context, in *pb.ProposeGuestJoinRequest, _ ...grpc.CallOption) (*pb.ProposeGuestJoinResponse, error) {
	f.proposals++
	f.proposed = append(f.proposed, in)
	h := in.GetHost()
	return &pb.ProposeGuestJoinResponse{JoinMethod: JoinMethodReview, AgentDetail: "guest agent unavailable",
		Host: &pb.EnrollHost{HostId: h.GetHostId(), Endpoint: h.GetEndpoint() + ":22", SshUser: "nebula",
			CredentialRef: "nebula-default", Fingerprint: "SHA256:" + strings.Repeat("B", 43), KeyType: "ssh-ed25519"},
		Guest:  in.GetGuest(),
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: strings.Repeat("cd", 32)},
	}, nil
}

func (f *fakeJoinExecutor) CommitGuestJoin(_ context.Context, in *pb.CommitGuestJoinRequest, _ ...grpc.CallOption) (*pb.CommitGuestJoinResponse, error) {
	f.commits = append(f.commits, in)
	c := &pb.CommitGuestJoinResponse{
		Result:          &pb.EnrollResult{HostId: in.GetHost().GetHostId(), Pinned: f.pinned, Fingerprint: in.GetHost().GetFingerprint()},
		ExecutionDigest: in.GetExecutionDigest(), Guest: in.GetGuest(), Host: in.GetHost(), JoinMethod: in.GetJoinMethod(),
	}
	if f.echo != nil {
		f.echo(c)
	}
	return c, nil
}

func flowProposal() GuestJoinProposal {
	return GuestJoinProposal{RemoteID: "remote-a", Node: "p1", VMID: 120, Generation: 1, GuestName: "web1.lab.test",
		HostID: "web1", Endpoint: "192.168.10.12"}
}

func flowHost() inventory.Host {
	return inventory.Host{ID: "web1", DisplayName: "web1.lab.test", Endpoints: []inventory.Endpoint{{Address: "192.168.10.12", Port: 22}},
		CredentialRef: "nebula-default"}
}

func TestGuestJoinFlowCreatesHostFromCommittedBinding(t *testing.T) {
	s := joinFixture(t)
	ex := &fakeJoinExecutor{pinned: true}
	f := &GuestJoinFlow{Store: s, Executor: ex}
	ctx := context.Background()
	p, err := f.Propose(ctx, flowProposal())
	if err != nil {
		t.Fatal(err)
	}
	if ex.proposed[0].GetGuest().GetGuestUuid() != testGuestUUID {
		t.Fatalf("the proposal must carry the recorded incarnation UUID: %v", ex.proposed[0].GetGuest())
	}
	got, err := f.Commit(ctx, p, flowHost(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.commits) != 1 || ex.commits[0].GetExecutionDigest() != p.GetPermit().GetExecutionDigest() ||
		ex.commits[0].GetJoinMethod() != JoinMethodReview || ex.commits[0].GetGuest().GetVmid() != 120 {
		t.Fatalf("commit requests = %v", ex.commits)
	}
	if got.Link.HostID != "web1" || got.Link.VMID != 120 || got.JoinMethod != JoinMethodReview || got.Fingerprint != p.GetHost().GetFingerprint() {
		t.Fatalf("result = %+v", got)
	}
}

func TestGuestJoinFlowCreatesNothingWithoutPin(t *testing.T) {
	s := joinFixture(t)
	f := &GuestJoinFlow{Store: s, Executor: &fakeJoinExecutor{pinned: false}}
	ctx := context.Background()
	p, err := f.Propose(ctx, flowProposal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Commit(ctx, p, flowHost(), "alice"); !errors.Is(err, ErrJoinNotPinned) {
		t.Fatalf("err = %v, want ErrJoinNotPinned", err)
	}
	if _, err := s.hostStore().Get(ctx, "web1"); !errors.Is(err, inventory.ErrHostNotFound) {
		t.Fatalf("no host may be created: %v", err)
	}
}

func TestGuestJoinFlowRefusesHostOtherThanApproved(t *testing.T) {
	cases := map[string]func(h *inventory.Host, ex *fakeJoinExecutor){
		"caller host id": func(h *inventory.Host, _ *fakeJoinExecutor) { h.ID = "web2" },
		"caller endpoint": func(h *inventory.Host, _ *fakeJoinExecutor) {
			h.Endpoints = []inventory.Endpoint{{Address: "192.168.10.99", Port: 22}}
		},
		"executor approved another guest": func(_ *inventory.Host, ex *fakeJoinExecutor) {
			ex.echo = func(c *pb.CommitGuestJoinResponse) {
				c.Guest = &pb.GuestJoinTarget{RemoteId: "remote-a", Node: "p1", Vmid: 121, Generation: 1, GuestName: "web1.lab.test"}
			}
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := joinFixture(t)
			ex := &fakeJoinExecutor{pinned: true}
			h := flowHost()
			mod(&h, ex)
			f := &GuestJoinFlow{Store: s, Executor: ex}
			p, err := f.Propose(context.Background(), flowProposal())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Commit(context.Background(), p, h, "alice"); err == nil {
				t.Fatal("join of an unapproved host accepted")
			}
			if _, err := s.GetLink(context.Background(), "remote-a", 120, 1); !errors.Is(err, ErrLinkNotFound) {
				t.Fatalf("no link may be created: %v", err)
			}
		})
	}
}

func TestGuestJoinFlowProposeChecksInventoryFirst(t *testing.T) {
	cases := map[string]struct {
		mod  func(p *GuestJoinProposal, s *Store)
		want error
	}{
		"unknown incarnation": {func(p *GuestJoinProposal, _ *Store) { p.Generation = 2 }, ErrGuestNotFound},
		"other name":          {func(p *GuestJoinProposal, _ *Store) { p.GuestName = "db1.lab.test" }, ErrJoinGuestMismatch},
		"other node":          {func(p *GuestJoinProposal, _ *Store) { p.Node = "p2" }, ErrJoinGuestMismatch},
		"host exists": {func(_ *GuestJoinProposal, s *Store) {
			mustCreateHost(t, s.db, mkManagedHost("web1", "10.77.10.101"))
		}, inventory.ErrHostExists},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := joinFixture(t)
			ex := &fakeJoinExecutor{pinned: true}
			p := flowProposal()
			c.mod(&p, s)
			if _, err := (&GuestJoinFlow{Store: s, Executor: ex}).Propose(context.Background(), p); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if ex.proposals != 0 {
				t.Fatal("nothing may be proposed on the executor")
			}
		})
	}
}
