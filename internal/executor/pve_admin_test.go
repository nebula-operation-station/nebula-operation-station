// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

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
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// testChain is a generated CA + leaf pair for the PVE admin tests.
type testChain struct {
	ca   *x509.Certificate
	leaf *x509.Certificate
	tls  tls.Certificate
}

func makeTestChain(t *testing.T) testChain {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test PVE CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pve1.example.test"},
		DNSNames:     []string{"pve1.example.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return testChain{
		ca:   caCert,
		leaf: leafCert,
		tls:  tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
	}
}

// fpHex is the hex-encoded SHA-256 fingerprint of a certificate.
func fpHex(c *x509.Certificate) string {
	fp := pvetransport.Fingerprint(c)
	return hex.EncodeToString(fp[:])
}

func probeResultFrom(chain testChain, hosts ...string) PveProbeResult {
	res := PveProbeResult{}
	for _, h := range hosts {
		res.Endpoints = append(res.Endpoints, PveProbeEndpoint{
			Host:            h,
			Port:            8006,
			Leaf:            chain.leaf,
			LeafFingerprint: fpHex(chain.leaf),
			CA:              chain.ca,
			CAFingerprint:   fpHex(chain.ca),
		})
	}
	return res
}

// fakePveProbe records calls and returns a fixed result.
type fakePveProbe struct {
	calls  int
	result PveProbeResult
	err    error
}

func (f *fakePveProbe) call(ctx context.Context, eps []pvecontract.Endpoint) (PveProbeResult, error) {
	f.calls++
	return f.result, f.err
}

// fakePveValidate records calls and returns a fixed error.
type fakePveValidate struct {
	calls  int
	tokens [][]byte
	err    error
}

func (f *fakePveValidate) call(ctx context.Context, eps []pvecontract.Endpoint, trust pvetransport.Trust, token []byte) error {
	f.calls++
	f.tokens = append(f.tokens, append([]byte(nil), token...))
	return f.err
}

// recordingRevoke records revoke calls.
type recordingRevoke struct {
	reasons []string
	err     error
}

func (r *recordingRevoke) call(remoteID, reason string) error {
	r.reasons = append(r.reasons, remoteID+" "+reason)
	return r.err
}

// pveTestEnv is a PveAdmin over a fresh DB + unlocked vault.
type pveTestEnv struct {
	t          *testing.T
	db         *executordb.DB
	vault      *vault.Vault
	admin      *PveAdmin
	probe      *fakePveProbe
	validate   *fakePveValidate
	revoke     *recordingRevoke
	logBuf     *bytes.Buffer
	passphrase string
}

func newPveTestEnv(t *testing.T) *pveTestEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New(db)
	v.SetMinParams(vault.MinParams)
	pass := strings.Repeat("correct-horse-battery-staple-", 4)
	if err := v.Init([]byte(pass), vault.MinParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	e := &pveTestEnv{
		t:          t,
		db:         db,
		vault:      v,
		probe:      &fakePveProbe{},
		validate:   &fakePveValidate{},
		revoke:     &recordingRevoke{},
		passphrase: pass,
	}
	e.logBuf = &bytes.Buffer{}
	e.admin = &PveAdmin{
		DB:            db,
		Vault:         v,
		Probe:         e.probe.call,
		ValidateToken: e.validate.call,
		RevokeGrants:  e.revoke.call,
		Now:           func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) },
		Log:           slog.New(slog.NewTextHandler(e.logBuf, nil)),
	}
	return e
}

func (e *pveTestEnv) add(t *testing.T, id string, kind pvecontract.Kind, eps []pvecontract.Endpoint, confirmedPin string, readToken []byte) (executordb.PveRemote, error) {
	t.Helper()
	return e.admin.AddRemote(context.Background(), PveAddRemote{
		RemoteID:     id,
		Kind:         kind,
		Endpoints:    eps,
		ConfirmedPin: confirmedPin,
		ReadToken:    readToken,
		By:           "admin",
	})
}

func pveEndpoints(hosts ...string) []pvecontract.Endpoint {
	eps := make([]pvecontract.Endpoint, 0, len(hosts))
	for _, h := range hosts {
		eps = append(eps, pvecontract.Endpoint{Host: h, Port: 8006})
	}
	return eps
}

// TestPveAddRemoteRequiresFingerprintConfirmation: an empty or wrong typed
// confirmation aborts the add before anything is stored.
func TestPveAddRemoteRequiresFingerprintConfirmation(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")

	// An empty confirmation is rejected (the pin is part of the contract).
	_, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, "", []byte("nosread!tok1!okvalue"))
	if !errors.Is(err, pvecontract.ErrInvalid) {
		t.Fatalf("empty confirmation: err = %v, want ErrInvalid", err)
	}
	// A wrong confirmation aborts with ErrPvePinMismatch.
	_, err = e.add(t, "lab-pve", pvecontract.KindCluster, eps, strings.Repeat("0", 64), []byte("nosread!tok1!okvalue"))
	if !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("wrong confirmation: err = %v, want ErrPvePinMismatch", err)
	}
	if _, ok, err := e.db.GetRemote("lab-pve"); err != nil || ok {
		t.Fatalf("remote stored despite failed confirmation: ok=%v err=%v", ok, err)
	}
	infos, err := e.vault.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("vault secrets stored despite failed confirmation: %d", len(infos))
	}
}

// TestPveAddRemoteStoresPinAndOpaqueRefs: a confirmed add stores the pin
// and opaque refs; the secret lives only in the vault; the audit trail
// never contains the token.
func TestPveAddRemoteStoresPinAndOpaqueRefs(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	token := []byte("nosread!tok1!S3CRET-VALUE")

	rm, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, token)
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != executordb.StateActive || rm.TrustPin != pin || rm.TrustGeneration != 1 {
		t.Fatalf("remote = %+v, want active pin=%s gen=1", rm, pin)
	}
	ref := PveVaultID("lab-pve", PvePurposeRead)
	if rm.Credentials.ReadRef != ref || rm.Credentials.ReadVersion != 1 {
		t.Fatalf("credentials = %+v, want %s@1", rm.Credentials, ref)
	}
	got, err := e.vault.Open(ref)
	if err != nil || string(got) != string(token) {
		t.Fatalf("vault.Open = %q, %v; want the token", got, err)
	}
	changes, err := e.db.RemoteChanges("lab-pve")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if strings.Contains(c.Detail, "S3CRET-VALUE") {
			t.Fatalf("token value in audit trail: %q", c.Detail)
		}
	}
}

// TestPveAddRemoteRejectsTokenProfile: password-realm and built-in admin
// tokens are refused before any probe or endpoint validation.
func TestPveAddRemoteRejectsTokenProfile(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")

	for _, tok := range [][]byte{
		[]byte("root@pam!tok1!value"),
		[]byte("Administrator!tok1!value"),
		[]byte("PVEVMAdmin!tok1!value"),
		[]byte("nosread!tok1"), // malformed: no value
	} {
		_, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, tok)
		if !errors.Is(err, ErrPveTokenRejected) && !errors.Is(err, ErrPveTokenFormat) {
			t.Fatalf("token %q: err = %v, want refused", tok, err)
		}
	}
	if e.probe.calls != 0 {
		t.Fatalf("probe ran %d times for refused profiles", e.probe.calls)
	}
	if e.validate.calls != 0 {
		t.Fatalf("endpoint validation ran %d times for refused profiles", e.validate.calls)
	}
	if _, ok, _ := e.db.GetRemote("lab-pve"); ok {
		t.Fatal("remote stored despite refused token")
	}
}

// TestPveTokenNeverLoggedOrReturned: token values never appear in logs,
// errors, or replies — on success or on a failed rotation.
func TestPveTokenNeverLoggedOrReturned(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	secret := "NEVER-LEAK-7f3a9c"
	token := []byte("nosread!tok1!" + secret)

	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, token); err != nil {
		t.Fatal(err)
	}
	e.validate.err = ErrPveTokenInvalid
	_, err := e.admin.RotateToken(context.Background(), PveRotateToken{
		RemoteID: "lab-pve", Purpose: PvePurposeRead,
		Token: []byte("nosread!tok2!" + secret), By: "admin",
	})
	if !errors.Is(err, ErrPveTokenInvalid) {
		t.Fatalf("rotate err = %v, want ErrPveTokenInvalid", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("token in error: %v", err)
	}
	if strings.Contains(e.logBuf.String(), secret) {
		t.Fatalf("token in logs: %s", e.logBuf.String())
	}
}

// TestPveRotateTokenAtomic: the old version stays authoritative until the
// new token is validated; only then does the registry switch, and the
// dependent grants are revoked.
func TestPveRotateTokenAtomic(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")

	tokenA := []byte("nosread!tok1!valueA")
	rm, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	ref := rm.Credentials.ReadRef

	// A rejected new token must not change the registry or the vault.
	e.validate.err = ErrPveTokenInvalid
	_, err = e.admin.RotateToken(context.Background(), PveRotateToken{
		RemoteID: "lab-pve", Purpose: PvePurposeRead,
		Token: []byte("nosread!tok2!valueB"), By: "admin",
	})
	if !errors.Is(err, ErrPveTokenInvalid) {
		t.Fatal(err)
	}
	after, ok, err := e.db.GetRemote("lab-pve")
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	if after.Credentials.ReadRef != ref || after.Credentials.ReadVersion != 1 {
		t.Fatalf("registry changed on failed rotation: %+v", after.Credentials)
	}
	got, err := e.vault.Open(ref)
	if err != nil || string(got) != string(tokenA) {
		t.Fatalf("vault changed on failed rotation: %q, %v", got, err)
	}

	// A validated new token switches the registry atomically.
	e.validate.err = nil
	tokenB := []byte("nosread!tok2!valueB")
	rm2, err := e.admin.RotateToken(context.Background(), PveRotateToken{
		RemoteID: "lab-pve", Purpose: PvePurposeRead, Token: tokenB, By: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rm2.Credentials.ReadRef != ref || rm2.Credentials.ReadVersion != 2 {
		t.Fatalf("credentials = %+v, want %s@2", rm2.Credentials, ref)
	}
	got, err = e.vault.Open(ref)
	if err != nil || string(got) != string(tokenB) {
		t.Fatalf("vault.Open = %q, %v; want token B", got, err)
	}
	if len(e.revoke.reasons) != 1 || !strings.Contains(e.revoke.reasons[0], "rotation") {
		t.Fatalf("revoke calls = %v, want one rotation revoke", e.revoke.reasons)
	}
}

// TestPveRemoveOrder: remove disables, revokes grants, removes the vault
// secrets, then tombstones — and the trail shows that order.
func TestPveRemoveOrder(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, []byte("nosread!tok1!valueA")); err != nil {
		t.Fatal(err)
	}

	rm, err := e.admin.RemoveRemote(context.Background(), PveRemove{RemoteID: "lab-pve", By: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != executordb.StateRemoved {
		t.Fatalf("state = %s, want removed", rm.State)
	}
	if _, err := e.vault.Open(PveVaultID("lab-pve", PvePurposeRead)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("vault secret still present after remove: %v", err)
	}
	if len(e.revoke.reasons) != 1 || !strings.Contains(e.revoke.reasons[0], "removed") {
		t.Fatalf("revoke calls = %v, want one removal revoke", e.revoke.reasons)
	}
	changes, err := e.db.RemoteChanges("lab-pve")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) < 2 {
		t.Fatalf("trail too short: %d", len(changes))
	}
	last := changes[len(changes)-2:]
	if last[0].ChangeType != executordb.ChangeBlocked || last[1].ChangeType != executordb.ChangeRemoved {
		t.Fatalf("trail tail = %+v, want blocked then removed", last)
	}
}

// TestPveRemoveStopsWhenRevokeFails: a failed grant revoke leaves the
// remote disabled but not tombstoned, and the vault secret in place.
func TestPveRemoveStopsWhenRevokeFails(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, []byte("nosread!tok1!valueA")); err != nil {
		t.Fatal(err)
	}
	e.revoke.err = errors.New("grant store unavailable")

	_, err := e.admin.RemoveRemote(context.Background(), PveRemove{RemoteID: "lab-pve", By: "admin"})
	if err == nil {
		t.Fatal("remove succeeded despite failed revoke")
	}
	stored, ok, err := e.db.GetRemote("lab-pve")
	if err != nil || !ok {
		t.Fatal(err, ok)
	}
	if stored.State != executordb.StateBlocked {
		t.Fatalf("state = %s, want blocked", stored.State)
	}
	if _, err := e.vault.Open(PveVaultID("lab-pve", PvePurposeRead)); err != nil {
		t.Fatalf("vault secret deleted before revoke succeeded: %v", err)
	}
}

// TestPveLockedVaultRefuses: with the vault locked, add, rotate and
// remove are refused and remove leaves no side effect.
func TestPveLockedVaultRefuses(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, []byte("nosread!tok1!valueA")); err != nil {
		t.Fatal(err)
	}
	e.vault.Lock()

	_, err := e.add(t, "lab-pve2", pvecontract.KindCluster, pveEndpoints("pve2.example.test"), fpHex(chain.ca), []byte("nosread!tok1!valueA"))
	if !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("add on locked vault: err = %v, want ErrLocked", err)
	}
	_, err = e.admin.RotateToken(context.Background(), PveRotateToken{
		RemoteID: "lab-pve", Purpose: PvePurposeRead, Token: []byte("nosread!tok2!valueB"), By: "admin",
	})
	if !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("rotate on locked vault: err = %v, want ErrLocked", err)
	}
	_, err = e.admin.RemoveRemote(context.Background(), PveRemove{RemoteID: "lab-pve", By: "admin"})
	if !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("remove on locked vault: err = %v, want ErrLocked", err)
	}
	stored, ok, err := e.db.GetRemote("lab-pve")
	if err != nil || !ok || stored.State != executordb.StateActive {
		t.Fatalf("remove touched the remote on a locked vault: %+v ok=%v err=%v", stored, ok, err)
	}
	if len(e.revoke.reasons) != 0 {
		t.Fatalf("revoke ran on a locked vault: %v", e.revoke.reasons)
	}
}

// TestPveRepin: the current pin and a typed confirmation of the newly
// presented trust identity are both required; a successful repin bumps
// the generation.
func TestPveRepin(t *testing.T) {
	e := newPveTestEnv(t)
	chain1 := makeTestChain(t)
	pin1 := fpHex(chain1.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain1, "pve1.example.test")
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin1, []byte("nosread!tok1!valueA")); err != nil {
		t.Fatal(err)
	}

	// A wrong current pin is refused.
	_, err := e.admin.Repin(context.Background(), PveRepin{
		RemoteID: "lab-pve", OldPin: strings.Repeat("0", 64), ConfirmedNewPin: pin1, By: "admin",
	})
	if !errors.Is(err, executordb.ErrInvalid) {
		t.Fatalf("wrong old pin: err = %v, want ErrInvalid", err)
	}

	// A wrong confirmation of the new identity is refused.
	chain2 := makeTestChain(t)
	pin2 := fpHex(chain2.ca)
	e.probe.result = probeResultFrom(chain2, "pve1.example.test")
	_, err = e.admin.Repin(context.Background(), PveRepin{
		RemoteID: "lab-pve", OldPin: pin1, ConfirmedNewPin: pin1, By: "admin",
	})
	if !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("wrong new confirmation: err = %v, want ErrPvePinMismatch", err)
	}

	rm, err := e.admin.Repin(context.Background(), PveRepin{
		RemoteID: "lab-pve", OldPin: pin1, ConfirmedNewPin: pin2, By: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rm.TrustPin != pin2 || rm.TrustGeneration != 2 {
		t.Fatalf("remote = pin %s gen %d, want pin %s gen 2", rm.TrustPin, rm.TrustGeneration, pin2)
	}
	if len(e.revoke.reasons) != 1 || !strings.Contains(e.revoke.reasons[0], "re-pin") {
		t.Fatalf("revoke calls = %v, want one re-pin revoke", e.revoke.reasons)
	}
}

// TestPveProbeAndTokenValidateLoopback exercises the real probe and
// token validation against a loopback TLS server presenting a CA chain.
func TestPveProbeAndTokenValidateLoopback(t *testing.T) {
	chain := makeTestChain(t)
	const goodToken = "nosread!tok1!okvalue"
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "PVEAPIToken="+goodToken {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"8.2"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{chain.tls}}
	srv.StartTLS()
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	eps := []pvecontract.Endpoint{{Host: host, Port: uint16(port)}}

	res, err := DefaultPveProbe(context.Background(), eps)
	if err != nil {
		t.Fatal(err)
	}
	pin, trust, err := res.TrustIdentity(pvecontract.KindCluster)
	if err != nil {
		t.Fatal(err)
	}
	if pin != fpHex(chain.ca) {
		t.Fatalf("pin = %s, want the CA fingerprint", pin)
	}
	if err := DefaultPveTokenValidate(context.Background(), eps, trust, []byte(goodToken)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	err = DefaultPveTokenValidate(context.Background(), eps, trust, []byte("nosread!tok1!wrong"))
	if !errors.Is(err, ErrPveTokenInvalid) {
		t.Fatalf("wrong token: err = %v, want ErrPveTokenInvalid", err)
	}
	if strings.Contains(err.Error(), "tok1") {
		t.Fatalf("token value in error: %v", err)
	}
}

// TestPveStandaloneLeafPin: a standalone remote is pinned to its leaf
// fingerprint, and a changed leaf is refused on rotation.
func TestPveStandaloneLeafPin(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	eps := pveEndpoints("standalone.example.test")
	e.probe.result = probeResultFrom(chain, "standalone.example.test")
	leafPin := fpHex(chain.leaf)

	rm, err := e.add(t, "standalone", pvecontract.KindStandalone, eps, leafPin, []byte("nosread!tok1!okvalue"))
	if err != nil {
		t.Fatal(err)
	}
	if rm.TrustPin != leafPin {
		t.Fatalf("pin = %s, want the leaf fingerprint", rm.TrustPin)
	}

	// A probe that presents a different leaf must be refused.
	other := makeTestChain(t)
	e.probe.result = probeResultFrom(other, "standalone.example.test")
	_, err = e.admin.RotateToken(context.Background(), PveRotateToken{
		RemoteID: "standalone", Purpose: PvePurposeRead, Token: []byte("nosread!tok2!okvalue"), By: "admin",
	})
	if !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("changed leaf: err = %v, want ErrPvePinMismatch", err)
	}
}

// TestPveClusterCAAgreement: cluster endpoints that disagree on the CA
// fingerprint are refused.
func TestPveClusterCAAgreement(t *testing.T) {
	e := newPveTestEnv(t)
	chain1 := makeTestChain(t)
	chain2 := makeTestChain(t)
	e.probe.result = PveProbeResult{
		Endpoints: []PveProbeEndpoint{
			probeResultFrom(chain1, "pve1.example.test").Endpoints[0],
			probeResultFrom(chain2, "pve2.example.test").Endpoints[0],
		},
	}
	eps := pveEndpoints("pve1.example.test", "pve2.example.test")
	_, err := e.add(t, "cluster", pvecontract.KindCluster, eps, fpHex(chain1.ca), []byte("nosread!tok1!okvalue"))
	if !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("disagreeing CAs: err = %v, want ErrPvePinMismatch", err)
	}
}

// TestPveListMetadataOnly: list returns registry metadata and never a
// secret value.
func TestPveListMetadataOnly(t *testing.T) {
	e := newPveTestEnv(t)
	chain := makeTestChain(t)
	pin := fpHex(chain.ca)
	eps := pveEndpoints("pve1.example.test")
	e.probe.result = probeResultFrom(chain, "pve1.example.test")
	token := []byte("nosread!tok1!TOPSECRET")
	if _, err := e.add(t, "lab-pve", pvecontract.KindCluster, eps, pin, token); err != nil {
		t.Fatal(err)
	}
	remotes, err := e.admin.ListRemotes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(remotes) != 1 {
		t.Fatalf("list = %d remotes, want 1", len(remotes))
	}
	out, err := json.Marshal(remotes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "TOPSECRET") {
		t.Fatalf("list output contains the token: %s", out)
	}
}
