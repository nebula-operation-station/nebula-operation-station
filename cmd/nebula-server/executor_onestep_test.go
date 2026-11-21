// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// enrollRelayFake is the executor side of the one-step RPCs. It records
// each request under its method name and answers with a fixed reply, or
// with failWith when that is set. It is served on a real peercred socket.
type enrollRelayFake struct {
	pb.UnimplementedExecutorServiceServer
	mu       sync.Mutex
	got      map[string]proto.Message
	failWith error
}

// take records the request, or returns failWith without recording it.
func (f *enrollRelayFake) take(method string, in proto.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	f.got[method] = proto.Clone(in)
	return nil
}

// request returns the request the fake recorded for method, if any.
func (f *enrollRelayFake) request(method string) proto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got[method]
}

// GetStatus is the probe that executorclient.New makes.
func (f *enrollRelayFake) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (f *enrollRelayFake) CreateEnrollOffer(_ context.Context, in *pb.CreateEnrollOfferRequest) (*pb.CreateEnrollOfferResponse, error) {
	if err := f.take("CreateEnrollOffer", in); err != nil {
		return nil, err
	}
	return &pb.CreateEnrollOfferResponse{OfferId: "reply-create"}, nil
}

func (f *enrollRelayFake) FetchEnrollScript(_ context.Context, in *pb.FetchEnrollScriptRequest) (*pb.FetchEnrollScriptResponse, error) {
	if err := f.take("FetchEnrollScript", in); err != nil {
		return nil, err
	}
	return &pb.FetchEnrollScriptResponse{Script: []byte("reply-fetch")}, nil
}

func (f *enrollRelayFake) ShowEnrollScript(_ context.Context, in *pb.ShowEnrollScriptRequest) (*pb.ShowEnrollScriptResponse, error) {
	if err := f.take("ShowEnrollScript", in); err != nil {
		return nil, err
	}
	return &pb.ShowEnrollScriptResponse{Script: []byte("reply-show")}, nil
}

func (f *enrollRelayFake) DownloadEnrollScript(_ context.Context, in *pb.DownloadEnrollScriptRequest) (*pb.DownloadEnrollScriptResponse, error) {
	if err := f.take("DownloadEnrollScript", in); err != nil {
		return nil, err
	}
	return &pb.DownloadEnrollScriptResponse{Script: []byte("reply-download")}, nil
}

func (f *enrollRelayFake) SubmitPairingCode(_ context.Context, in *pb.SubmitPairingCodeRequest) (*pb.SubmitPairingCodeResponse, error) {
	if err := f.take("SubmitPairingCode", in); err != nil {
		return nil, err
	}
	return &pb.SubmitPairingCodeResponse{Endpoint: "reply-submit"}, nil
}

func (f *enrollRelayFake) CommitPairedEnroll(_ context.Context, in *pb.CommitPairedEnrollRequest) (*pb.CommitPairedEnrollResponse, error) {
	if err := f.take("CommitPairedEnroll", in); err != nil {
		return nil, err
	}
	return &pb.CommitPairedEnrollResponse{HostId: "reply-commit"}, nil
}

func (f *enrollRelayFake) RevokeEnrollOffer(_ context.Context, in *pb.RevokeEnrollOfferRequest) (*pb.RevokeEnrollOfferResponse, error) {
	if err := f.take("RevokeEnrollOffer", in); err != nil {
		return nil, err
	}
	return &pb.RevokeEnrollOfferResponse{State: "reply-revoke"}, nil
}

// enrollRelayCase is one of the seven one-step calls with a request that
// uses every field the dialog sets, and the reply the fake sends back.
type enrollRelayCase struct {
	method string
	req    proto.Message
	want   proto.Message
	call   func(context.Context, *lazyExecutor, proto.Message) (proto.Message, error)
}

func enrollRelayCases() []enrollRelayCase {
	return []enrollRelayCase{
		{
			method: "CreateEnrollOffer",
			req: &pb.CreateEnrollOfferRequest{HostId: "web1", SshUser: "nebula", CredentialRef: "nebula-default",
				Sudo: true, SessionBinding: []byte("binding-create")},
			want: &pb.CreateEnrollOfferResponse{OfferId: "reply-create"},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.CreateEnrollOffer(ctx, m.(*pb.CreateEnrollOfferRequest))
			},
		},
		{
			method: "FetchEnrollScript",
			req:    &pb.FetchEnrollScriptRequest{OfferId: "offer-fetch", ClientAddr: "192.0.2.10", PeerAddr: "192.0.2.11"},
			want:   &pb.FetchEnrollScriptResponse{Script: []byte("reply-fetch")},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.FetchEnrollScript(ctx, m.(*pb.FetchEnrollScriptRequest))
			},
		},
		{
			method: "ShowEnrollScript",
			req:    &pb.ShowEnrollScriptRequest{OfferId: "offer-show", SessionBinding: []byte("binding-show")},
			want:   &pb.ShowEnrollScriptResponse{Script: []byte("reply-show")},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.ShowEnrollScript(ctx, m.(*pb.ShowEnrollScriptRequest))
			},
		},
		{
			method: "DownloadEnrollScript",
			req: &pb.DownloadEnrollScriptRequest{OfferId: "offer-download", SessionBinding: []byte("binding-download"),
				ClientAddr: "192.0.2.12", PeerAddr: "192.0.2.13"},
			want: &pb.DownloadEnrollScriptResponse{Script: []byte("reply-download")},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.DownloadEnrollScript(ctx, m.(*pb.DownloadEnrollScriptRequest))
			},
		},
		{
			method: "SubmitPairingCode",
			req: &pb.SubmitPairingCodeRequest{OfferIdHash: "hash-submit", SessionBinding: []byte("binding-submit"),
				Code: "ABCD-EFGH", Endpoint: "web1.lab:22"},
			want: &pb.SubmitPairingCodeResponse{Endpoint: "reply-submit"},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.SubmitPairingCode(ctx, m.(*pb.SubmitPairingCodeRequest))
			},
		},
		{
			method: "CommitPairedEnroll",
			req:    &pb.CommitPairedEnrollRequest{OfferIdHash: "hash-commit", SessionBinding: []byte("binding-commit"), PermitDigest: "digest-commit"},
			want:   &pb.CommitPairedEnrollResponse{HostId: "reply-commit"},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.CommitPairedEnroll(ctx, m.(*pb.CommitPairedEnrollRequest))
			},
		},
		{
			method: "RevokeEnrollOffer",
			req:    &pb.RevokeEnrollOfferRequest{OfferIdHash: "hash-revoke"},
			want:   &pb.RevokeEnrollOfferResponse{State: "reply-revoke"},
			call: func(ctx context.Context, l *lazyExecutor, m proto.Message) (proto.Message, error) {
				return l.RevokeEnrollOffer(ctx, m.(*pb.RevokeEnrollOfferRequest))
			},
		},
	}
}

// serveEnrollRelay serves svc on a real peercred socket for the test user,
// who holds the server role, and returns the socket path.
func serveEnrollRelay(t *testing.T, svc pb.ExecutorServiceServer) string {
	t.Helper()
	uidRoles := map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}
	policy := peercred.NewPolicy(uidRoles, executor.MethodRoles())
	// A Unix socket path is limited in length, so use a short directory
	// instead of t.TempDir.
	dir, err := os.MkdirTemp("", "nos")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: sock, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(nil)),
		grpc.StreamInterceptor(policy.StreamInterceptor(nil)),
	)
	pb.RegisterExecutorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return sock
}

// connectLazy stores a real executorclient, dialled to sock, in l.
func connectLazy(t *testing.T, l *lazyExecutor, sock string) {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := executorclient.New(ctx, executorclient.Options{SocketPath: sock, ExecutorUser: me.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	l.c.Store(client)
}

// TestOnestepRPCsNotConnectedReturnErrNotConnected checks that each of the
// seven calls answers errNotConnected before the executor is connected,
// and does not panic.
func TestOnestepRPCsNotConnectedReturnErrNotConnected(t *testing.T) {
	l := new(lazyExecutor)
	for _, c := range enrollRelayCases() {
		t.Run(c.method, func(t *testing.T) {
			_, err := c.call(t.Context(), l, c.req)
			if err != errNotConnected {
				t.Fatalf("err = %v, want errNotConnected", err)
			}
		})
	}
}

// TestOnestepRPCsRelayUnchanged checks that each of the seven calls
// reaches the executor with the request it was given, and that the reply
// comes back unchanged.
func TestOnestepRPCsRelayUnchanged(t *testing.T) {
	fake := &enrollRelayFake{got: map[string]proto.Message{}}
	l := new(lazyExecutor)
	connectLazy(t, l, serveEnrollRelay(t, fake))
	for _, c := range enrollRelayCases() {
		t.Run(c.method, func(t *testing.T) {
			got, err := c.call(t.Context(), l, c.req)
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if !proto.Equal(got, c.want) {
				t.Errorf("reply = %v, want %v", got, c.want)
			}
			sent := fake.request(c.method)
			if sent == nil {
				t.Fatal("executor received no request")
			}
			if !proto.Equal(sent, c.req) {
				t.Errorf("executor received %v, want %v", sent, c.req)
			}
		})
	}
}

// TestOnestepExecutorRefusalKeepsCode checks what the dialog needs from a
// refusal: while the executor has no offer configuration (FailedPrecondition,
// "not configured"), the server passes the code and message on. The dialog
// then shows the message (ui.onestepRefusal) and does not answer 500.
func TestOnestepExecutorRefusalKeepsCode(t *testing.T) {
	fake := &enrollRelayFake{got: map[string]proto.Message{}, failWith: status.Error(codes.FailedPrecondition, "not configured")}
	l := new(lazyExecutor)
	connectLazy(t, l, serveEnrollRelay(t, fake))
	for _, c := range enrollRelayCases() {
		t.Run(c.method, func(t *testing.T) {
			_, err := c.call(t.Context(), l, c.req)
			st, ok := status.FromError(err)
			if !ok || st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "not configured") {
				t.Fatalf("err = %v (ok %v), want FailedPrecondition with \"not configured\"", err, ok)
			}
		})
	}
}

// stubInventory satisfies ui.InventoryStore for routing only. The dialog
// never reaches it here, because the test web session holds no privileged
// session.
type stubInventory struct{ ui.InventoryStore }

// TestOnestepDialogIsServedByLazyExecutor checks that the dialog route is
// served with the lazyExecutor, as main.go wires it, and no longer answers
// 404, both before and after the executor connects. Without a privileged
// session the dialog renders its notice with 403.
func TestOnestepDialogIsServedByLazyExecutor(t *testing.T) {
	var _ ui.EnrollOffers = (*lazyExecutor)(nil)
	l := new(lazyExecutor)
	h := newOnestepTestHandler(t, l)
	connected := new(lazyExecutor)
	connectLazy(t, connected, serveEnrollRelay(t, &enrollRelayFake{got: map[string]proto.Message{}}))
	hConnected := newOnestepTestHandler(t, connected)

	for name, handler := range map[string]http.Handler{"not connected": h.Handler(), "connected": hConnected.Handler()} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inventory/enroll/onestep", nil))
			if rec.Code == http.StatusNotFound || rec.Code == http.StatusInternalServerError {
				t.Fatalf("dialog = %d, want it served", rec.Code)
			}
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "privileged session") {
				t.Errorf("dialog = %d without a privileged session, want 403 with the notice", rec.Code)
			}
		})
	}
}

// newOnestepTestHandler builds the UI handler with l as the enrollment
// executor and status provider, as cmd/nebula-server does.
func newOnestepTestHandler(t *testing.T, l *lazyExecutor) *ui.Handler {
	t.Helper()
	h, err := ui.New(ui.Options{
		PublicOrigin: "https://nebula.test",
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Status:       l,
		Enroll:       l,
		Inventory:    stubInventory{},
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
