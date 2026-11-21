// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// notConfiguredMsg is the refusal of CreateEnrollOffer while no enrollment
// configuration is installed.
const notConfiguredMsg = "one-step enrollment is not configured"

// loadEnrollFlags parses args with the executor's enrollment flags on a
// fresh flag set and loads them, as the executor start does.
func loadEnrollFlags(t *testing.T, args ...string) (enrollConfig, error) {
	t.Helper()
	fs := flag.NewFlagSet("nebula-executor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := registerEnrollFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return f.load()
}

// recordingEnrollSetter forwards to the real service and records every
// installed configuration.
type recordingEnrollSetter struct {
	*executor.Service
	calls []executor.EnrollOfferConfig
}

func (r *recordingEnrollSetter) SetEnrollOffers(c executor.EnrollOfferConfig) error {
	r.calls = append(r.calls, c)
	return r.Service.SetEnrollOffers(c)
}

// createOfferAsServer calls CreateEnrollOffer over a Unix socket in a temp
// directory through the real gRPC server and role table, as the server role.
func createOfferAsServer(t *testing.T, svc *executor.Service) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := definitionClient(t, svc, peercred.RoleServer)
	_, err := client.CreateEnrollOffer(ctx, &pb.CreateEnrollOfferRequest{HostId: "web-1", CredentialRef: "cred",
		SessionBinding: []byte("session-0123456789abcdef")})
	return err
}

// TestEnrollSourceInstallsOfferConfig: with a valid -enroll-source the
// executor start installs the enrollment configuration, so the server
// role's CreateEnrollOffer over the socket is no longer refused as "not
// configured" and goes on to the privileged-session check.
func TestEnrollSourceInstallsOfferConfig(t *testing.T) {
	e := newExecutorUnderTest(t)
	cfg, err := loadEnrollFlags(t, "-enroll-source", "192.0.2.10,2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingEnrollSetter{Service: e.svc}
	if err := setupEnrollOffers(rec, cfg, quietLog); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(rec.calls) != 1 || !slices.Equal(rec.calls[0].Sources, []string{"192.0.2.10", "2001:db8::/32"}) || rec.calls[0].NetBird != nil {
		t.Fatalf("installed %+v, want the two sources and no NetBird", rec.calls)
	}
	err = createOfferAsServer(t, e.svc)
	if status.Code(err) != codes.FailedPrecondition || strings.Contains(err.Error(), notConfiguredMsg) ||
		!strings.Contains(err.Error(), "privileged session") {
		t.Fatalf("create with config installed: %v, want the privileged-session refusal", err)
	}
}

// TestNoEnrollSourceKeepsOffersRefused: without enrollment flags the setter
// is not called and CreateEnrollOffer stays refused with FailedPrecondition
// "not configured", as before.
func TestNoEnrollSourceKeepsOffersRefused(t *testing.T) {
	for _, args := range [][]string{
		nil,
		// NetBird alone installs nothing either: there is no source.
		{"-netbird-management-url", "https://netbird.example.org"},
	} {
		e := newExecutorUnderTest(t)
		cfg, err := loadEnrollFlags(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingEnrollSetter{Service: e.svc}
		if err := setupEnrollOffers(rec, cfg, quietLog); err != nil {
			t.Fatalf("setup %v: %v", args, err)
		}
		if len(rec.calls) != 0 {
			t.Fatalf("setup %v installed %+v", args, rec.calls)
		}
		err = createOfferAsServer(t, e.svc)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), notConfiguredMsg) {
			t.Fatalf("create %v without config: %v, want FailedPrecondition %q", args, err, notConfiguredMsg)
		}
	}
}

// TestEnrollNetBirdStaysLocked: a NetBird management URL does not open the
// NetBird branch; the executor has no key-passing mode table yet (EN-16e,
// ADR 0013 Q11 open), so only the sources are installed.
func TestEnrollNetBirdStaysLocked(t *testing.T) {
	e := newExecutorUnderTest(t)
	cfg, err := loadEnrollFlags(t, "-enroll-source", "192.0.2.10", "-netbird-management-url", "https://netbird.example.org")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingEnrollSetter{Service: e.svc}
	if err := setupEnrollOffers(rec, cfg, quietLog); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(rec.calls) != 1 || rec.calls[0].NetBird != nil {
		t.Fatalf("installed %+v, want no NetBird part", rec.calls)
	}
}

// TestSetupEnrollOffersRefusalStopsStart: a configuration the service
// refuses is returned as a start error with context, and nothing is
// installed.
func TestSetupEnrollOffersRefusalStopsStart(t *testing.T) {
	e := newExecutorUnderTest(t)
	err := setupEnrollOffers(e.svc, enrollConfig{Sources: []string{"nos.example.org"}}, quietLog)
	if err == nil || !strings.Contains(err.Error(), "install enrollment configuration") {
		t.Fatalf("setup with an invalid source: %v, want an error with context", err)
	}
	if err := createOfferAsServer(t, e.svc); !strings.Contains(err.Error(), notConfiguredMsg) {
		t.Fatalf("refused config was installed: %v", err)
	}
}

// TestRunInstallsEnrollOffers: run() calls setupEnrollOffers(svc,
// enrollCfg, ...) as a statement of its body, checks its error, and does
// so after building svc and before serving it.
func TestRunInstallsEnrollOffers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "run" {
			run = fd
		}
	}
	if run == nil || run.Body == nil {
		t.Fatal("main.go has no func run")
	}
	isIdent := func(e ast.Expr, name string) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	built, installed, served := -1, -1, -1
	for i, st := range run.Body.List {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) != 1 {
				continue
			}
			c, ok := s.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || !isIdent(sel.X, "executor") {
				continue
			}
			if sel.Sel.Name == "NewService" && isIdent(s.Lhs[0], "svc") && built < 0 {
				built = i
			}
			if sel.Sel.Name == "NewGRPCServer" && len(c.Args) > 0 && isIdent(c.Args[0], "svc") && served < 0 {
				served = i
			}
		case *ast.IfStmt:
			init, ok := s.Init.(*ast.AssignStmt)
			if !ok || len(init.Rhs) != 1 || len(init.Lhs) != 1 || !isIdent(init.Lhs[0], "err") {
				continue
			}
			c, ok := init.Rhs[0].(*ast.CallExpr)
			if ok && isIdent(c.Fun, "setupEnrollOffers") && len(c.Args) >= 2 && isIdent(c.Args[0], "svc") &&
				isIdent(c.Args[1], "enrollCfg") && installed < 0 {
				installed = i
			}
		}
	}
	if built < 0 || installed < 0 || served < 0 || built >= installed || installed >= served {
		t.Fatalf("run() must build svc, check `if err := setupEnrollOffers(svc, enrollCfg, ...)` and then serve svc; positions built=%d installed=%d served=%d",
			built, installed, served)
	}
}

// enrollWiringHelperEnv makes the test binary run the executor's main with
// the arguments after "--".
const enrollWiringHelperEnv = "NOS_TEST_EXECUTOR_ENROLL_WIRING"

// TestInvalidEnrollSourceDoesNotStart: the shipped executor binary with an
// invalid -enroll-source exits non-zero before anything else starts.
func TestInvalidEnrollSourceDoesNotStart(t *testing.T) {
	if os.Getenv(enrollWiringHelperEnv) == "1" {
		args := os.Args
		for i, a := range args {
			if a == "--" {
				os.Args = append([]string{"nebula-executor"}, args[i+1:]...)
				break
			}
		}
		main()
		os.Exit(0)
	}
	for _, src := range []string{"nos.example.org", "192.0.2.10/8", ""} {
		dir := t.TempDir()
		args := []string{"-test.run=^TestInvalidEnrollSourceDoesNotStart$", "--",
			"-data-dir", filepath.Join(dir, "absent"), "-socket", filepath.Join(dir, "executor.sock"), "-enroll-source", src}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), enrollWiringHelperEnv+"=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
			t.Fatalf("start with -enroll-source %q: err = %v, want non-zero exit", src, err)
		}
		if msg := stderr.String(); !strings.Contains(msg, "invalid enrollment configuration") || !strings.Contains(msg, "-enroll-source") {
			t.Errorf("-enroll-source %q: stderr = %q", src, msg)
		}
		if _, err := os.Stat(filepath.Join(dir, "executor.sock")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("-enroll-source %q: socket exists after a refused start (%v)", src, err)
		}
	}
}
