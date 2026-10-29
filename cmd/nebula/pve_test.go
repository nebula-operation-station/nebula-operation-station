// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const pveTestToken = "pveadmin!custody!S3cr3t-Token-Value"

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
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "PVEAPIToken="+pveTestToken {
			io.WriteString(w, `{"version":"test"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
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

// pveTestDataDir creates a temporary executor data directory with an
// initialized vault and points NEBULA_EXECUTOR_DATA_DIR at it. The DB
// is closed before returning: the executor database allows a single
// holder, and the CLI opens it itself.
func pveTestDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv("NEBULA_EXECUTOR_DATA_DIR", dir)
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	v := vault.New(db)
	if err := v.Init([]byte(pveTestPassphrase), vault.DefaultParams, "test"); err != nil {
		_ = db.Close()
		t.Fatalf("init vault: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	return dir
}

// pveTestDB opens the test data directory for assertions (after the
// CLI has finished and closed its handle).
func pveTestDB(t *testing.T, dir string) *executordb.DB {
	t.Helper()
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
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

// pvePeekRemote opens the data directory, reads one remote, and closes
// the handle again (the executor DB allows a single holder).
func pvePeekRemote(t *testing.T, dir string) (executordb.PveRemote, bool) {
	t.Helper()
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	rm, ok, err := db.GetRemote("testlab")
	if err != nil {
		t.Fatalf("get remote: %v", err)
	}
	return rm, ok
}
