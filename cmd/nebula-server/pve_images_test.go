// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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

// serveImageFake serves x on a Unix socket in a temporary directory and
// returns the socket path and a stop function. The server stops at test end
// too; stop is for tests that need the executor to go away mid-test.
func serveImageFake(t *testing.T, x pb.ExecutorServiceServer) (string, func()) {
	t.Helper()
	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "nos-pi11f-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, x)
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return sock, srv.Stop
}

// lazyForSocket returns a lazyExecutor connected through the real executor
// client to the socket.
func lazyForSocket(t *testing.T, sock string) *lazyExecutor {
	t.Helper()
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

// imageLazy returns a lazyExecutor connected to a fake executor.
func imageLazy(t *testing.T, f *imageFake) *lazyExecutor {
	t.Helper()
	sock, _ := serveImageFake(t, f)
	return lazyForSocket(t, sock)
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

// The executor's own answers, with the exact texts of pveImagePrepareRPCError
// (internal/executor/pve_rpc.go). Each Unavailable here is sent while the
// executor is reachable.
var (
	execBusy    = status.Error(codes.Unavailable, "pve image prepare: another mutation of the node is in progress")
	execUnread  = status.Error(codes.Unavailable, "pve image prepare: the prepared template could not be read; nothing was proposed or recorded")
	execRecords = status.Error(codes.Unavailable, "pve image prepare: the template or job records are unavailable")
)

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
			// The production path (the lazy executor itself) and the wrapper
			// both refuse before any call.
			for name, call := range map[string]func() (*pb.CommitPVEImagePrepareResponse, error){
				"wrapper": func() (*pb.CommitPVEImagePrepareResponse, error) {
					return commitImagePrepare(t.Context(), l, tc.in)
				},
				"lazy executor": func() (*pb.CommitPVEImagePrepareResponse, error) {
					return l.CommitPVEImagePrepare(t.Context(), tc.in)
				},
			} {
				out, err := call()
				if out != nil || !errors.Is(err, ErrImageNotApproved) {
					t.Fatalf("%s commit = (%v, %v), want (nil, ErrImageNotApproved)", name, out, err)
				}
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

// uiMessage is the text the UI shows for a classified error: the sentinel's
// text first, then the cause for logs.
func uiMessage(err error, sentinel error) bool {
	return err != nil && strings.HasPrefix(err.Error(), sentinel.Error())
}

// TestImageErrorMapping: each executor failure maps to its own sentinel, the UI
// text starts with that sentinel's text, and no other image sentinel matches.
// The Unavailable cases are the executor's real answers (busy, unreadable
// template, unavailable records); a busy or unreadable executor is not an
// unreachable one.
func TestImageErrorMapping(t *testing.T) {
	all := []error{ErrImageUnknown, ErrImageAlreadyPrepared, ErrImageRemoteChanged,
		ErrImageTemplateChanged, ErrImageExecutorUnavailable, ErrImageBusy, ErrImageTryAgain}
	cases := []struct {
		name string
		err  error
		want error // nil: no image sentinel
	}{
		{"image not in catalog", status.Error(codes.NotFound, "pve image prepare: the image is not in the catalog"), ErrImageUnknown},
		{"template already prepared", status.Error(codes.AlreadyExists, "pve image prepare: the image is already prepared on this storage"), ErrImageAlreadyPrepared},
		{"remote changed", status.Error(codes.FailedPrecondition, "pve image prepare: the node, storage or remote changed; propose again"), ErrImageRemoteChanged},
		{"template gone or changed", status.Error(codes.FailedPrecondition, "pve image prepare: the template is gone or changed"), ErrImageTemplateChanged},
		{"node busy with another mutation", execBusy, ErrImageBusy},
		{"template could not be read", execUnread, ErrImageTryAgain},
		{"template or job records unavailable", execRecords, ErrImageTryAgain},
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
			if tc.want != nil && !uiMessage(err, tc.want) {
				t.Errorf("UI message = %q, want it to start with %q", err, tc.want)
			}
		})
	}
}

// TestCommitImageErrorMapping: a commit whose outcome is not clear is never
// reported as "nothing was changed". The executor's busy answer is shown as
// busy; its unreadable or unavailable answers and a lost transport are shown
// as an unknown outcome.
func TestCommitImageErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"node busy with another mutation", execBusy, ErrImageBusy},
		{"template could not be read after the run", execUnread, ErrImageOutcomeUnknown},
		{"template or job records unavailable", execRecords, ErrImageOutcomeUnknown},
		{"executor deadline before the answer", status.Error(codes.DeadlineExceeded, "context deadline exceeded"), ErrImageOutcomeUnknown},
		{"executor not connected: nothing sent", errNotConnected, ErrImageExecutorUnavailable},
		{"permission denied passes through", status.Error(codes.PermissionDenied, "pve image prepare: no approved permit covers this preparation"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := new(lazyExecutor)
			if tc.err != errNotConnected {
				l = imageLazy(t, &imageFake{commitErr: tc.err})
			}
			out, err := commitImagePrepare(t.Context(), l, &pb.CommitPVEImagePrepareRequest{Spec: imageSpec(), ExecutionDigest: "d1"})
			if out != nil || err == nil {
				t.Fatalf("commit = (%v, %v), want an error and no response", out, err)
			}
			if tc.want == nil {
				if errors.Is(err, ErrImageOutcomeUnknown) || errors.Is(err, ErrImageExecutorUnavailable) {
					t.Errorf("commit err = %v, want the executor's own error", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("commit err = %v, want %v", err, tc.want)
			}
			if !uiMessage(err, tc.want) {
				t.Errorf("UI message = %q, want it to start with %q", err, tc.want)
			}
			if tc.want == ErrImageOutcomeUnknown || tc.want == ErrImageBusy {
				if strings.Contains(err.Error(), "nothing was") {
					t.Errorf("commit message %q claims nothing changed while the outcome is not known", err)
				}
			}
		})
	}
}

// TestTransportFailureIsExecutorUnreachable: a real transport failure (the
// executor's socket is closed under a live client) is reported as unreachable
// for reads and proposals, and as an unknown outcome for a commit that was
// sent. It is never reported as busy or as the executor's own answer.
func TestTransportFailureIsExecutorUnreachable(t *testing.T) {
	f := &imageFake{proposeResp: &pb.ProposePVEImagePrepareResponse{}, commitResp: &pb.CommitPVEImagePrepareResponse{}, listResp: imageCatalogList()}
	sock, stop := serveImageFake(t, f)
	l := lazyForSocket(t, sock)
	stop()

	t.Run("list", func(t *testing.T) {
		out, err := listImages(t.Context(), l)
		if out != nil || !errors.Is(err, ErrImageExecutorUnavailable) || !uiMessage(err, ErrImageExecutorUnavailable) {
			t.Fatalf("list = (%v, %v), want (nil, ErrImageExecutorUnavailable)", out, err)
		}
		if errors.Is(err, ErrImageBusy) || errors.Is(err, ErrImageTryAgain) {
			t.Errorf("transport failure matched an executor answer: %v", err)
		}
	})
	t.Run("propose", func(t *testing.T) {
		out, err := proposeImagePrepare(t.Context(), l, &pb.ProposePVEImagePrepareRequest{Spec: imageSpec()})
		if out != nil || !errors.Is(err, ErrImageExecutorUnavailable) || !uiMessage(err, ErrImageExecutorUnavailable) {
			t.Fatalf("propose = (%v, %v), want (nil, ErrImageExecutorUnavailable)", out, err)
		}
	})
	t.Run("commit", func(t *testing.T) {
		out, err := commitImagePrepare(t.Context(), l, &pb.CommitPVEImagePrepareRequest{Spec: imageSpec(), ExecutionDigest: "d1"})
		if out != nil || !errors.Is(err, ErrImageOutcomeUnknown) || !uiMessage(err, ErrImageOutcomeUnknown) {
			t.Fatalf("commit = (%v, %v), want (nil, ErrImageOutcomeUnknown)", out, err)
		}
		if strings.Contains(err.Error(), "nothing was") {
			t.Errorf("commit message %q claims nothing changed after a sent commit", err)
		}
	})
}

// TestUnreachableExecutorIsNeverAnEmptyList: when the executor cannot be
// reached, or answers that it is busy, the list fails with an image sentinel
// and returns no response. A caller must never see "no images" for "could not
// ask".
func TestUnreachableExecutorIsNeverAnEmptyList(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		out, err := listImages(t.Context(), new(lazyExecutor))
		if out != nil || !errors.Is(err, ErrImageExecutorUnavailable) {
			t.Fatalf("list = (%v, %v), want (nil, ErrImageExecutorUnavailable)", out, err)
		}
	})
	t.Run("executor busy", func(t *testing.T) {
		out, err := listImages(t.Context(), imageLazy(t, &imageFake{listErr: execBusy}))
		if out != nil || !errors.Is(err, ErrImageBusy) || errors.Is(err, ErrImageExecutorUnavailable) {
			t.Fatalf("list = (%v, %v), want (nil, ErrImageBusy)", out, err)
		}
	})
}

// TestLazyExecutorRefusesUnapprovedCommit: the production path (the lazy
// executor the UI uses) refuses a commit without the spec or the approved
// digest before it reaches the executor.
func TestLazyExecutorRefusesUnapprovedCommit(t *testing.T) {
	f := &imageFake{commitResp: &pb.CommitPVEImagePrepareResponse{}}
	l := imageLazy(t, f)
	_, err := l.CommitPVEImagePrepare(t.Context(), &pb.CommitPVEImagePrepareRequest{Spec: imageSpec()})
	if !errors.Is(err, ErrImageNotApproved) {
		t.Fatalf("commit err = %v, want ErrImageNotApproved", err)
	}
	if f.callCount() != 0 {
		t.Errorf("executor received %d calls, want none", f.callCount())
	}
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
