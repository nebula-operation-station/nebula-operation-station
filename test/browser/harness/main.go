// SPDX-License-Identifier: AGPL-3.0-or-later

// Command harness runs the executor service in-process together with the
// web login for the browser test (make test-browser). It is test code: it
// serves /__code, which issues a registration code like `nebula webauthn
// code`, without any authentication. Never build it into a release.
//
//	harness PORT DIR
//
// RP ID is "localhost" and the origin http://localhost:PORT, which browsers
// treat as a secure context.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// direct calls the service without gRPC; role checks are covered by
// test/security.
type direct struct{ s *executor.Service }

func (d direct) BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, _ ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	return d.s.BeginLogin(ctx, in)
}
func (d direct) FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, _ ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	return d.s.FinishLogin(ctx, in)
}
func (d direct) BeginRegistration(ctx context.Context, in *pb.BeginRegistrationRequest, _ ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	return d.s.BeginRegistration(ctx, in)
}
func (d direct) FinishRegistration(ctx context.Context, in *pb.FinishRegistrationRequest, _ ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	return d.s.FinishRegistration(ctx, in)
}

func (d direct) BeginPrivilegedSession(ctx context.Context, in *pb.BeginPrivilegedSessionRequest, _ ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	return d.s.BeginPrivilegedSession(ctx, in)
}

func (d direct) CompletePrivilegedSession(ctx context.Context, in *pb.CompletePrivilegedSessionRequest, _ ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	return d.s.CompletePrivilegedSession(ctx, in)
}

func (d direct) Lock(ctx context.Context, in *pb.LockRequest, _ ...grpc.CallOption) (*pb.LockResponse, error) {
	return d.s.Lock(ctx, in)
}

func (d direct) GetStatus(ctx context.Context, in *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return d.s.GetStatus(ctx, in)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	port, dir := os.Args[1], os.Args[2]
	origin := "http://localhost:" + port
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	exDir := filepath.Join(dir, "ex")
	must(os.MkdirAll(exDir, 0o700))
	db, err := executordb.Open(exDir)
	must(err)
	creds, err := executor.LoadCredentials(db, exDir, log)
	must(err)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "localhost", Origins: []string{origin}, Counters: db}, creds)
	must(err)
	rp, err := riskpolicy.New(db)
	must(err)
	a, err := permit.New(permit.Options{Verifier: v, Store: db, RiskPolicy: rp})
	must(err)
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "localhost", Origins: []string{origin}, Audit: executor.RegistrationAuditLogger(log)}, v, db)
	must(err)
	kd := filepath.Join(dir, "keys")
	must(os.MkdirAll(kd, 0o700))
	svc := executor.NewService(a, keyring.New(kd), db, reg, log)

	sdb, err := serverdb.Open(filepath.Join(dir, "server.db"))
	must(err)
	ah, err := auth.New(auth.Options{Executor: direct{svc}, Sessions: auth.NewStore(sdb, nil), Log: log})
	must(err)
	u, err := ui.New(ui.Options{PublicOrigin: origin, Status: direct{svc}, Log: log})
	must(err)
	mux := http.NewServeMux()
	// Test hook: issue a one-time code like `nebula webauthn code`.
	mux.HandleFunc("/__code", func(w http.ResponseWriter, r *http.Request) {
		c, err := svc.CreateRegistrationCode(r.Context(), &pb.CreateRegistrationCodeRequest{UserName: "axel", Label: "e2e"})
		must(err)
		fmt.Fprint(w, c.GetCode())
	})
	mux.Handle("/", middleware.Handler(middleware.Options{PublicOrigin: origin}, ah.Wrap(u.Handler())))
	must(http.ListenAndServe("127.0.0.1:"+port, mux))
}
