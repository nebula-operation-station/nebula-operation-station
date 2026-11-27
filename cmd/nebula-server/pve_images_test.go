// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"os/user"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// imageFake is the executor stand-in for the image RPCs. It records every
// call and answers with the canned responses or errors of the test.
type imageFake struct {
	pb.UnimplementedExecutorServiceServer

	mu    sync.Mutex
	calls []string

	proposeReq  *pb.ProposePVEImagePrepareRequest
	commitReq   *pb.CommitPVEImagePrepareRequest
	proposeResp *pb.ProposePVEImagePrepareResponse
	commitResp  *pb.CommitPVEImagePrepareResponse
	listResp    *pb.ListPVEImagesResponse
	proposeErr  error
	commitErr   error
	listErr     error
}

func (f *imageFake) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *imageFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// GetStatus lets executorclient.New finish its connection probe.
func (f *imageFake) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (f *imageFake) ProposePVEImagePrepare(_ context.Context, in *pb.ProposePVEImagePrepareRequest) (*pb.ProposePVEImagePrepareResponse, error) {
	f.record("propose")
	f.mu.Lock()
	f.proposeReq = in
	f.mu.Unlock()
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	return f.proposeResp, nil
}

func (f *imageFake) CommitPVEImagePrepare(_ context.Context, in *pb.CommitPVEImagePrepareRequest) (*pb.CommitPVEImagePrepareResponse, error) {
	f.record("commit")
	f.mu.Lock()
	f.commitReq = in
	f.mu.Unlock()
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return f.commitResp, nil
}

func (f *imageFake) ListPVEImages(context.Context, *pb.ListPVEImagesRequest) (*pb.ListPVEImagesResponse, error) {
	f.record("list")
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

// imageLazy returns a lazyExecutor connected through the real executor client
// to a fake executor served on a Unix socket.
func imageLazy(t *testing.T, f *imageFake) *lazyExecutor {
	t.Helper()
	sock := serveExecutor(t, f)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(t.Context(), executorclient.Options{SocketPath: sock, ExecutorUser: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	l := new(lazyExecutor)
	l.c.Store(c)
	return l
}

func imageSpec() *pb.PVEImagePrepareSpec {
	return &pb.PVEImagePrepareSpec{RemoteId: "pve-a", Node: "pve1", Storage: "local-lvm",
		ImageId: "ubuntu-24.04-amd64", ImportStorage: "local", Vmid: 9000}
}

func imageCatalogList() *pb.ListPVEImagesResponse {
	return &pb.ListPVEImagesResponse{
		CatalogSequence: 7,
		CatalogDigest:   "abc123",
		Images: []*pb.PVEImage{
			{Image: &pb.PVECatalogImage{Id: "ubuntu-24.04-amd64", Os: "ubuntu", Release: "24.04", Arch: "amd64"}, Trust: "signed"},
			{Image: &pb.PVECatalogImage{Id: "local-custom", Os: "debian", Release: "12", Arch: "amd64"}, Trust: "local"},
		},
		Templates: []*pb.PVETemplateRecord{{ImageId: "ubuntu-24.04-amd64", Vmid: 9000, Trust: "signed"}},
	}
}

// TestServerForwardsImageRPCsUnchanged: propose, commit and list reach the
// executor exactly as the caller sent them, and the executor's answers come
// back unchanged. The server adds no approval and rewrites nothing.
func TestServerForwardsImageRPCsUnchanged(t *testing.T) {
	proposeResp := &pb.ProposePVEImagePrepareResponse{
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: "d1"},
		Image:  &pb.PVEImage{Image: &pb.PVECatalogImage{Id: "ubuntu-24.04-amd64"}, Trust: "signed"},
	}
	commitResp := &pb.CommitPVEImagePrepareResponse{ExecutionId: "e1"}
	f := &imageFake{proposeResp: proposeResp, commitResp: commitResp, listResp: imageCatalogList()}
	l := imageLazy(t, f)
	ctx := t.Context()

	spec := imageSpec()
	gotProposal, err := l.ProposePVEImagePrepare(ctx, &pb.ProposePVEImagePrepareRequest{Spec: spec})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !proto.Equal(f.proposeReq.GetSpec(), spec) {
		t.Errorf("propose reached the executor as %v, want %v", f.proposeReq.GetSpec(), spec)
	}
	if !proto.Equal(gotProposal, proposeResp) {
		t.Errorf("propose response = %v, want %v", gotProposal, proposeResp)
	}

	gotCommit, err := l.CommitPVEImagePrepare(ctx, &pb.CommitPVEImagePrepareRequest{Spec: spec, ExecutionDigest: "d1"})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if f.commitReq.GetExecutionDigest() != "d1" || !proto.Equal(f.commitReq.GetSpec(), spec) {
		t.Errorf("commit reached the executor as %v, want the approved spec and digest", f.commitReq)
	}
	if !proto.Equal(gotCommit, commitResp) {
		t.Errorf("commit response = %v, want %v", gotCommit, commitResp)
	}

	gotList, err := l.ListPVEImages(ctx, &pb.ListPVEImagesRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !proto.Equal(gotList, imageCatalogList()) {
		t.Errorf("list response = %v, want the executor's list unchanged", gotList)
	}
}

// TestServerRefusesCommitWithoutApprovedDigest: the server never sends a
// commit that lacks the execution digest the user approved, or the spec it
// was proposed with. The executor is not called at all.
func TestServerRefusesCommitWithoutApprovedDigest(t *testing.T) {
	cases := []struct {
		name string
		in   *pb.CommitPVEImagePrepareRequest
	}{
		{name: "empty digest", in: &pb.CommitPVEImagePrepareRequest{Spec: imageSpec()}},
		{name: "nil spec", in: &pb.CommitPVEImagePrepareRequest{ExecutionDigest: "d1"}},
		{name: "nothing", in: &pb.CommitPVEImagePrepareRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &imageFake{commitResp: &pb.CommitPVEImagePrepareResponse{}}
			l := imageLazy(t, f)
			out, err := commitImagePrepare(t.Context(), l, tc.in)
			if out != nil || !errors.Is(err, ErrImageNotApproved) {
				t.Fatalf("commit = (%v, %v), want (nil, ErrImageNotApproved)", out, err)
			}
			if f.callCount() != 0 {
				t.Errorf("executor received %d calls, want none", f.callCount())
			}
		})
	}
}

// TestServerCannotApproveByForwarding: a commit the server sends with a
// digest nobody approved is refused by the executor (no approved permit), and
// the server reports that refusal as the executor's, not as an approval.
func TestServerCannotApproveByForwarding(t *testing.T) {
	f := &imageFake{commitErr: status.Error(codes.PermissionDenied,
		"pve image prepare: no approved permit covers this preparation")}
	l := imageLazy(t, f)
	_, err := commitImagePrepare(t.Context(), l, &pb.CommitPVEImagePrepareRequest{
		Spec: imageSpec(), ExecutionDigest: "never-approved"})
	if !errors.Is(err, executorclient.ErrPermissionDenied) {
		t.Fatalf("commit err = %v, want the executor's permission denial", err)
	}
	if errors.Is(err, ErrImageNotApproved) {
		t.Error("executor refusal reported as a server-side approval gap")
	}
	if f.callCount() != 1 {
		t.Errorf("executor received %d calls, want exactly the one commit", f.callCount())
	}
}

// TestImageErrorMapping: each executor failure the UI must tell apart maps to
// its own sentinel, and no other image sentinel matches it.
func TestImageErrorMapping(t *testing.T) {
	all := []error{ErrImageUnknown, ErrImageAlreadyPrepared, ErrImageRemoteChanged,
		ErrImageTemplateChanged, ErrImageExecutorUnavailable}
	cases := []struct {
		name string
		err  error
		want error // nil: no image sentinel
	}{
		{"image not in catalog", status.Error(codes.NotFound, "pve image prepare: the image is not in the catalog"), ErrImageUnknown},
		{"template already prepared", status.Error(codes.AlreadyExists, "pve image prepare: the image is already prepared on this storage"), ErrImageAlreadyPrepared},
		{"remote changed", status.Error(codes.FailedPrecondition, "pve image prepare: the node, storage or remote changed; propose again"), ErrImageRemoteChanged},
		{"template gone or changed", status.Error(codes.FailedPrecondition, "pve image prepare: the template is gone or changed"), ErrImageTemplateChanged},
		{"executor unavailable", status.Error(codes.Unavailable, "pve image prepare: the executor is down"), ErrImageExecutorUnavailable},
		{"executor not connected", errNotConnected, ErrImageExecutorUnavailable},
		{"other not found is not an unknown image", status.Error(codes.NotFound, "pve remote not found"), nil},
		{"permission denied passes through", status.Error(codes.PermissionDenied, "pve image prepare: no approved permit covers this preparation"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := new(lazyExecutor)
			if tc.err != errNotConnected {
				l = imageLazy(t, &imageFake{proposeErr: tc.err})
			}
			out, err := proposeImagePrepare(t.Context(), l, &pb.ProposePVEImagePrepareRequest{Spec: imageSpec()})
			if out != nil || err == nil {
				t.Fatalf("propose = (%v, %v), want an error and no response", out, err)
			}
			for _, s := range all {
				if got := errors.Is(err, s); got != (s == tc.want) {
					t.Errorf("errors.Is(err, %v) = %v, want %v (err: %v)", s, got, s == tc.want, err)
				}
			}
		})
	}
}

// TestUnreachableExecutorIsNeverAnEmptyList: when the executor cannot be
// reached, the list fails with ErrImageExecutorUnavailable and returns no
// response. A caller must never see "no images" for "could not ask".
func TestUnreachableExecutorIsNeverAnEmptyList(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		out, err := listImages(t.Context(), new(lazyExecutor))
		if out != nil || !errors.Is(err, ErrImageExecutorUnavailable) {
			t.Fatalf("list = (%v, %v), want (nil, ErrImageExecutorUnavailable)", out, err)
		}
	})
	t.Run("executor refuses with unavailable", func(t *testing.T) {
		f := &imageFake{listErr: status.Error(codes.Unavailable, "down")}
		out, err := listImages(t.Context(), imageLazy(t, f))
		if out != nil || !errors.Is(err, ErrImageExecutorUnavailable) {
			t.Fatalf("list = (%v, %v), want (nil, ErrImageExecutorUnavailable)", out, err)
		}
	})
}

// TestLazyExecutorHasNoLocalImageRPCs: local catalog entries are written by
// the admin role over the admin socket only (ADR 0008 amendment 2, D3 (a)).
// The server's executor must not offer AddPVELocalImage or RemovePVELocalImage.
func TestLazyExecutorHasNoLocalImageRPCs(t *testing.T) {
	var x any = new(lazyExecutor)
	if _, ok := x.(interface {
		AddPVELocalImage(context.Context, *pb.AddPVELocalImageRequest, ...grpc.CallOption) (*pb.AddPVELocalImageResponse, error)
	}); ok {
		t.Error("lazyExecutor forwards AddPVELocalImage")
	}
	if _, ok := x.(interface {
		RemovePVELocalImage(context.Context, *pb.RemovePVELocalImageRequest, ...grpc.CallOption) (*pb.RemovePVELocalImageResponse, error)
	}); ok {
		t.Error("lazyExecutor forwards RemovePVELocalImage")
	}
}
