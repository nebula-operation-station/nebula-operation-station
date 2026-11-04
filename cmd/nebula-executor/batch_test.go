// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const batchTestPassphrase = "batch-wiring-test-passphrase-0123456789"

// executorUnderTest builds the executor service the way run() does: a real
// executor.db, verifier, permit authority, risk policy and an unlocked
// keyring holding one credential "cred".
type executorUnderTest struct {
	svc      *executor.Service
	auth     *permit.Authority
	verifier *webauthnverify.Verifier
	risk     permit.RiskPolicy
	db       *executordb.DB
	pub      ssh.PublicKey
}

func newExecutorUnderTest(t *testing.T) *executorUnderTest {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "batch.test", Origins: []string{"https://batch.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := executor.NewExecutorRiskPolicy(db, &executor.PveGuestPowerBindings{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Mode: permit.ModeStandard, Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "batch.test", Origins: []string{"https://batch.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pubRaw, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "cred", []byte(batchTestPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cred.key"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := keyring.New(keysDir)
	if _, err := keys.Unlock([]byte(batchTestPassphrase)); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keys, db, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &executorUnderTest{svc: svc, auth: auth, verifier: verifier, risk: risk, db: db, pub: pub}
}

// The shipped executor's setup wires the batch authority: before it the
// batch RPCs are Unimplemented (the server falls back to "joined"); after
// it the real service answers the credential-version read with a version a
// canonical batch binds exactly, and takes proposals.
func TestSetupBatchAuthorityServesBatches(t *testing.T) {
	e := newExecutorUnderTest(t)
	ctx := context.Background()
	read := &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{"cred"}}
	if _, err := e.svc.GetBatchCredentialVersions(ctx, read); status.Code(err) != codes.Unimplemented {
		t.Fatalf("before setup: %v", err)
	}
	a, err := setupBatchAuthority(e.svc, batchConfig{
		Mode: permit.ModeStandard, Verifier: e.verifier, Risk: e.risk, Source: e.db, Store: e.db,
		Session: e.auth.Session, AdminUID: noBatchAdminUID, Audit: func(permit.Event) {},
	})
	if err != nil || a == nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(a.Lock)
	if _, err := e.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp, err := e.svc.GetBatchCredentialVersions(ctx, read)
	if err != nil {
		t.Fatal(err)
	}
	v := resp.GetVersions()
	if len(v) != 1 || v[0].GetVersion() != executor.CredentialVersionOf(e.pub) || v[0].GetVersion() == 0 ||
		v[0].GetVersion() > canonical.MaxCredentialVersion || v[0].GetPublicKeyFingerprint() != ssh.FingerprintSHA256(e.pub) {
		t.Fatalf("versions = %v", v)
	}
	// The proposal RPC is served by the authority now (a malformed plan is
	// refused by it, not Unimplemented).
	_, err = e.svc.ProposeBatch(ctx, &pb.ProposeBatchRequest{BatchJson: []byte(`{}`),
		Members: []*pb.BatchMemberInput{{MemberId: "m", Artifact: []byte("#!/bin/sh\n"), ParametersJson: []byte(`{}`)}}})
	if c := status.Code(err); c == codes.Unimplemented || c == codes.OK {
		t.Fatalf("propose: %v", err)
	}
}

// Missing executor dependencies fail the setup instead of serving batches
// without a policy.
func TestSetupBatchAuthorityRequiresPolicyInputs(t *testing.T) {
	e := newExecutorUnderTest(t)
	if _, err := setupBatchAuthority(e.svc, batchConfig{Mode: permit.ModeStandard, Verifier: e.verifier, Source: e.db,
		Session: e.auth.Session}); err == nil {
		t.Error("setup without a risk policy")
	}
	if _, err := setupBatchAuthority(e.svc, batchConfig{Mode: permit.ModeStandard, Risk: e.risk, Source: e.db,
		Session: e.auth.Session}); err == nil {
		t.Error("setup without a verifier")
	}
	if _, err := e.svc.GetBatchCredentialVersions(context.Background(), &pb.GetBatchCredentialVersionsRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("failed setup left batches wired: %v", err)
	}
}

// Without an admin user no peer can approve a batch locally.
func TestBatchAdminUID(t *testing.T) {
	uid, err := batchAdminUID(" , ")
	if err != nil || uid != math.MaxUint32 {
		t.Errorf("no admin: %d %v", uid, err)
	}
	if _, err := batchAdminUID("no-such-user-nebula-test"); err == nil {
		t.Error("unknown admin user accepted")
	}
}

// run(), the shipped executor's entry point, wires the batch authority with
// setupBatchAuthority and locks it on shutdown; the tests above exercise
// that function with the real service.
func TestRunWiresBatchAuthority(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := c.Fun.(type) {
			case *ast.Ident:
				calls[fun.Name] = true
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok {
					calls[x.Name+"."+fun.Sel.Name] = true
				}
			}
			return true
		})
	}
	for _, want := range []string{"setupBatchAuthority", "batchAdminUID", "batchAuth.Lock"} {
		if !calls[want] {
			t.Errorf("run() does not call %s", want)
		}
	}
}
