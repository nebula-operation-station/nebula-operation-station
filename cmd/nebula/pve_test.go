// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const pveTestToken = "pveadmin@pve!custody=S3cr3t-Token-Value"

const pveTestPassphrase = "test-vault-passphrase-0123456789-abcdef"

// pveSelfSignedCert builds a self-signed ECDSA certificate for 127.0.0.1.
func pveSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pve-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// pvePinningServer starts a TLS server that presents the given
// certificate and answers GET /version with 200 only for the pinned
// test token. It returns the endpoint host:port and the leaf
// fingerprint.
func pvePinningServer(t *testing.T, cert tls.Certificate) (string, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken="+pveTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			io.WriteString(w, `{"data":{"version":"8.2"}}`)
		case "/api2/json/access/users":
			if r.URL.Query().Get("full") != "1" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"data":[{"userid":"pveadmin@pve","tokens":[{"tokenid":"custody","privsep":1,"expire":2000000000}]}]}`)
		case "/api2/json/access/permissions":
			io.WriteString(w, `{"data":{"/":{"Sys.Audit":1},"/vms":{"VM.Audit":1},"/storage":{"Datastore.Audit":1},"/pool":{"Pool.Audit":1}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	fp := pvetransport.Fingerprint(mustParseCert(t, cert.Certificate[0]))
	return net.JoinHostPort(host, port), hex.EncodeToString(fp[:])
}

// mustParseCert parses a DER certificate; test-only.
func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

// The CLI tests retain a live executor and its exclusive database lock.
var pveTestExecutors sync.Map

func pveTestDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(); pveTestExecutors.Delete(dir) })
	pveTestExecutors.Store(dir, db)
	keysDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "pve.test", Origins: []string{"https://pve.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: db, RiskPolicy: risk})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "pve.test", Origins: []string{"https://pve.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, log)
	svc.SetVaultParams(vault.MinParams)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}, executor.MethodRoles())
	server := executor.NewGRPCServer(svc, policy, log)
	socketDir := t.TempDir()
	socket := filepath.Join(socketDir, "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEBULA_EXECUTOR_USER", u.Username)
	t.Setenv("NEBULA_EXECUTOR_SOCKET", socket)
	// A nonexistent client-side data directory demonstrates RPC custody.
	t.Setenv("NEBULA_EXECUTOR_DATA_DIR", filepath.Join(dir, "not-client-accessible"))
	conn, err := dialExecutor()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.InitVault(ctx, &pb.InitVaultRequest{Passphrase: []byte(pveTestPassphrase)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte(pveTestPassphrase), Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pveTestDB(t *testing.T, dir string) *executordb.DB {
	t.Helper()
	db, ok := pveTestExecutors.Load(dir)
	if !ok {
		t.Fatal("test executor unavailable")
	}
	return db.(*executordb.DB)
}

// pveTestAsk answers the CLI prompts: the vault passphrase and the
// token prompt. Anything else is a bug in the test.
func pveTestAsk(t *testing.T) prompter {
	t.Helper()
	return func(prompt string) ([]byte, error) {
		switch {
		case strings.Contains(prompt, "passphrase"):
			return []byte(pveTestPassphrase), nil
		case strings.Contains(prompt, "token"):
			return []byte(pveTestToken), nil
		}
		return nil, fmt.Errorf("unexpected prompt %q", prompt)
	}
}

func TestPveCmdUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"remote"},
		{"remote", "bogus"},
		{"remote", "add"},
		{"remote", "add", "id1", "--kind", "wrong", "--endpoint", "h:8006"},
	} {
		var out bytes.Buffer
		err := pveCmd(args, strings.NewReader(""), func(string) ([]byte, error) {
			return nil, errors.New("no prompts in usage test")
		}, &out)
		if err == nil {
			t.Fatalf("args %v: expected an error", args)
		}
	}
}

func TestPveRemoteListEmpty(t *testing.T) {
	pveTestDataDir(t)
	var out bytes.Buffer
	if err := pveCmd([]string{"remote", "list"}, strings.NewReader(""), pveTestAsk(t), &out); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), "no pve remotes") {
		t.Fatalf("list output %q", out.String())
	}
}

func TestPveRemoteAddWrongConfirmationAborts(t *testing.T) {
	dir := pveTestDataDir(t)
	endpoint, _ := pvePinningServer(t, pveSelfSignedCert(t))
	stdin := "deadbeef\n"
	var out bytes.Buffer
	err := pveCmd([]string{"remote", "add", "testlab", "--kind", "standalone", "--endpoint", endpoint},
		strings.NewReader(stdin), pveTestAsk(t), &out)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want confirmation mismatch, got %v", err)
	}
	db := pveTestDB(t, dir)
	if _, ok, _ := db.GetRemote("testlab"); ok {
		t.Fatal("remote stored although the fingerprint confirmation was wrong")
	}
}

func TestPveRemoteAddStoresMetadataOnly(t *testing.T) {
	dir := pveTestDataDir(t)
	endpoint, pin := pvePinningServer(t, pveSelfSignedCert(t))
	stdin := pin + "\n"
	var out bytes.Buffer
	err := pveCmd([]string{"remote", "add", "testlab", "--kind", "standalone", "--endpoint", endpoint, "--name", "Test Lab"},
		strings.NewReader(stdin), pveTestAsk(t), &out)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "S3cr3t-Token-Value") {
		t.Fatalf("token secret in CLI output: %s", got)
	}
	db := pveTestDB(t, dir)
	rm, ok, err := db.GetRemote("testlab")
	if err != nil || !ok {
		t.Fatalf("remote not stored: ok=%v err=%v", ok, err)
	}
	if rm.Credentials.ReadRef == "" || rm.Credentials.ReadVersion == 0 {
		t.Fatalf("read credential ref missing: %+v", rm.Credentials)
	}
	if rm.TrustPin != pin {
		t.Fatalf("stored pin %s != presented %s", rm.TrustPin, pin)
	}
	// The secret must not appear in any file of the data directory.
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("S3cr3t-Token-Value")) {
			t.Fatalf("token secret found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk data dir: %v", err)
	}
}

func TestPveRemoteRemoveRequiresYes(t *testing.T) {
	dir := pveTestDataDir(t)
	endpoint, pin := pvePinningServer(t, pveSelfSignedCert(t))
	var out bytes.Buffer
	err := pveCmd([]string{"remote", "add", "testlab", "--kind", "standalone", "--endpoint", endpoint},
		strings.NewReader(pin+"\n"), pveTestAsk(t), &out)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Refused without the typed yes.
	if err := pveCmd([]string{"remote", "remove", "testlab"}, strings.NewReader("no\n"), pveTestAsk(t), &out); err == nil {
		t.Fatal("remove accepted a 'no' confirmation")
	}
	if rm, ok := pvePeekRemote(t, dir); !ok || rm.State != executordb.StateActive {
		t.Fatalf("remote removed although not confirmed: %+v", rm)
	}
	// Confirmed.
	if err := pveCmd([]string{"remote", "remove", "testlab"}, strings.NewReader("yes\n"), pveTestAsk(t), &out); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if rm, ok := pvePeekRemote(t, dir); !ok || rm.State != executordb.StateRemoved {
		t.Fatalf("remote not tombstoned: %+v", rm)
	}
	// The list must not show secrets.
	var listOut bytes.Buffer
	if err := pveCmd([]string{"remote", "list"}, strings.NewReader(""), pveTestAsk(t), &listOut); err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(listOut.String(), "S3cr3t-Token-Value") {
		t.Fatalf("secret in list output: %s", listOut.String())
	}
}

// pvePeekRemote reads from the executor's live database for assertions.
func pvePeekRemote(t *testing.T, dir string) (executordb.PveRemote, bool) {
	t.Helper()
	rm, ok, err := pveTestDB(t, dir).GetRemote("testlab")
	if err != nil {
		t.Fatal(err)
	}
	return rm, ok
}

func TestPveRepinReadsPipedConfirmations(t *testing.T) {
	dir := pveTestDataDir(t)
	endpoint, newPin := pvePinningServer(t, pveSelfSignedCert(t))
	oldCert := pveSelfSignedCert(t)
	oldFP := pvetransport.Fingerprint(mustParseCert(t, oldCert.Certificate[0]))
	oldPin := hex.EncodeToString(oldFP[:])
	ep, err := parsePveEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// Seed the old identity while the endpoint now presents the replacement.
	db := pveTestDB(t, dir)
	remote, err := pvecontract.ValidateRemote(pvecontract.Remote{RemoteID: "testlab", Kind: pvecontract.KindStandalone, Endpoints: []pvecontract.Endpoint{ep}, TrustPin: oldPin, TrustGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddRemote(remote, executordb.PveRemoteCredentials{ReadRef: executor.PveVaultID("testlab", executor.PvePurposeRead), ReadVersion: 1}, "test"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	// Both fingerprints and approval arrive in one write to the pipe.
	err = pveCmd([]string{"remote", "repin", "testlab"}, strings.NewReader(oldPin+"\n"+newPin+"\nyes\n"), pveTestAsk(t), &out)
	if err != nil {
		t.Fatalf("piped re-pin: %v", err)
	}
	rm, ok := pvePeekRemote(t, dir)
	if !ok || rm.TrustPin != newPin || rm.TrustGeneration != 2 {
		t.Fatalf("re-pin did not commit: %+v", rm)
	}
}

func TestPveConfirmationInputIsBounded(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", maxPveConfirmationBytes+2) + "\n", strings.Repeat("x", maxPveConfirmationBytes+2)} {
		if _, err := pveAskLine(strings.NewReader(input), "", "fingerprint"); err == nil {
			t.Fatal("oversized confirmation accepted")
		}
	}
}
