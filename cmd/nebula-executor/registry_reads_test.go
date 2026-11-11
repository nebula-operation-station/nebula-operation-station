// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

// recordingRegistrySetter forwards to the real service and records what
// setupRegistryReads wired.
type recordingRegistrySetter struct {
	*executor.Service
	wired executor.RegistryReadAuthorizer
}

func (r *recordingRegistrySetter) SetRegistryReadAuthorizer(a executor.RegistryReadAuthorizer) {
	r.wired = a
	r.Service.SetRegistryReadAuthorizer(a)
}

func registryTestRead() executor.RegistryRead {
	return executor.RegistryRead{RegistryID: "corp", Method: "tag_digest", Repository: "team/app",
		ConfigDigest: strings.Repeat("a", 64), ConfigVersion: 1, CredentialID: strings.Repeat("b", 32), CredentialVersion: 1}
}

// TestSetupRegistryReadsWiresLeaseProfile: the shipped executor wires the
// lease-backed authorizer instead of the fail-closed default; it obeys the
// read pause and, with reads resumed, refuses a read no lease covers.
func TestSetupRegistryReadsWiresLeaseProfile(t *testing.T) {
	e := newExecutorUnderTest(t)
	rec := &recordingRegistrySetter{Service: e.svc}
	setupRegistryReads(rec)
	checkLeaseAuthorizer(t, e, rec)
}

// TestWireServedServiceWiresRegistryReads: main's service wiring (the
// function run calls on the service it serves) installs the lease-backed
// registry read authorizer, not the fail-closed default.
func TestWireServedServiceWiresRegistryReads(t *testing.T) {
	e := newExecutorUnderTest(t)
	rec := &recordingRegistrySetter{Service: e.svc}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wireServedService(rec, &executor.PveGuestPowerBindings{}, pub, dir, dir)
	checkLeaseAuthorizer(t, e, rec)
}

// TestRunCallsWireServedService: run() itself calls wireServedService on
// the service it builds (svc := executor.NewService(...)) and later serves
// (executor.NewGRPCServer(svc, ...)), as a statement of run's own body, in
// that order. It parses main.go, so a commented-out call, one in a nested
// or dead block, or one on another value fails, and with
// TestWireServedServiceWiresRegistryReads the served executor is proven
// to use the lease-backed authorizer, not the fail-closed default.
func TestRunCallsWireServedService(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
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
	isCall := func(e ast.Expr, pkg, name string) (*ast.CallExpr, bool) {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			return c, pkg == "" && f.Name == name
		case *ast.SelectorExpr:
			x, ok := f.X.(*ast.Ident)
			return c, ok && x.Name == pkg && f.Sel.Name == name
		}
		return nil, false
	}
	firstArgIsSvc := func(c *ast.CallExpr) bool {
		if len(c.Args) == 0 {
			return false
		}
		id, ok := c.Args[0].(*ast.Ident)
		return ok && id.Name == "svc"
	}
	built, wired, served := -1, -1, -1
	for i, st := range run.Body.List {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				if id, ok := s.Lhs[0].(*ast.Ident); ok && id.Name == "svc" {
					if _, ok := isCall(s.Rhs[0], "executor", "NewService"); ok && built < 0 {
						built = i
					}
				}
				if c, ok := isCall(s.Rhs[0], "executor", "NewGRPCServer"); ok && firstArgIsSvc(c) && served < 0 {
					served = i
				}
			}
		case *ast.ExprStmt:
			if c, ok := isCall(s.X, "", "wireServedService"); ok && firstArgIsSvc(c) && wired < 0 {
				wired = i
			}
		}
	}
	if built < 0 || wired < 0 || served < 0 || built >= wired || wired >= served {
		t.Fatalf("run() must build svc, call wireServedService(svc, ...) and then serve svc, as statements of its body; positions built=%d wired=%d served=%d", built, wired, served)
	}
	// svc is not reassigned between wiring and serving.
	for _, st := range run.Body.List[wired+1 : served] {
		if s, ok := st.(*ast.AssignStmt); ok {
			for _, l := range s.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Name == "svc" {
					t.Fatal("run() reassigns svc after wiring it")
				}
			}
		}
	}
}

// checkLeaseAuthorizer checks that rec.wired is the production lease
// authorizer: paused until read dispatch resumes, then refusing a read no
// lease covers.
func checkLeaseAuthorizer(t *testing.T, e *executorUnderTest, rec *recordingRegistrySetter) {
	t.Helper()
	if rec.wired == nil {
		t.Fatal("no registry read authorizer wired")
	}
	_, err := rec.wired.AuthorizeRegistryRead(registryTestRead())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "paused") {
		t.Fatalf("before read dispatch resumes: %v", err)
	}
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	_, err = rec.wired.AuthorizeRegistryRead(registryTestRead())
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "no approved registry read lease") {
		t.Fatalf("without a lease: %v", err)
	}
	if strings.Contains(status.Convert(err).Message(), "no read-grant profile") {
		t.Fatal("the fail-closed default is still wired")
	}
}
