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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// leafOnlyCluster is a PVE-like cluster: one self-signed "PVE Cluster
// Manager CA" and one leaf per node, each node serving only its leaf.
type leafOnlyCluster struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	leaves map[string]*x509.Certificate
	tls    map[string]tls.Certificate
}

// certWindow keeps the generated certificates valid both for the fixed
// test clock (2026-10-29) and for time.Now in the loopback tests.
func certWindow() (time.Time, time.Time) {
	now := time.Now()
	return now.Add(-2 * 365 * 24 * time.Hour), now.Add(2 * 365 * 24 * time.Hour)
}

func newTestCA(t *testing.T, tmpl *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func caTemplate(cn string) *x509.Certificate {
	nb, na := certWindow()
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
}

func pemOf(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func issueLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string, eku []x509.ExtKeyUsage) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := certWindow()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// Leaf only, like pve-ssl.pem on a default PVE node.
	return leaf, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func makeLeafOnlyCluster(t *testing.T, hosts ...string) leafOnlyCluster {
	t.Helper()
	ca, key := newTestCA(t, caTemplate("PVE Cluster Manager CA"))
	c := leafOnlyCluster{ca: ca, caKey: key, caPEM: pemOf(ca), leaves: map[string]*x509.Certificate{}, tls: map[string]tls.Certificate{}}
	for _, h := range hosts {
		c.leaves[h], c.tls[h] = issueLeaf(t, ca, key, h, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	}
	return c
}

// probe is what DefaultPveProbe reports for the cluster: leaves, no CA.
func (c leafOnlyCluster) probe(hosts ...string) PveProbeResult {
	res := PveProbeResult{}
	for _, h := range hosts {
		res.Endpoints = append(res.Endpoints, PveProbeEndpoint{Host: h, Port: 8006, Leaf: c.leaves[h], LeafFingerprint: fpHex(c.leaves[h])})
	}
	return res
}

var labHosts = []string{"192.168.0.17", "192.168.0.18", "192.168.0.19"}

func testNow() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) }

func mustParseCA(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	ca, err := ParsePveSuppliedCA(raw, testNow())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestPveLeafOnlyClusterWithCAFilePinsSuppliedCA(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	ca := mustParseCA(t, c.caPEM)
	pin, trust, err := c.probe(labHosts...).TrustIdentityWithCA(pvecontract.KindCluster, ca, testNow())
	if err != nil {
		t.Fatal(err)
	}
	if pin != fpHex(c.ca) {
		t.Fatalf("pin = %s, want the supplied CA fingerprint %s", pin, fpHex(c.ca))
	}
	if trust.CA == nil || !bytes.Equal(trust.CA.Raw, c.ca.Raw) || trust.LeafFingerprint != [32]byte{} {
		t.Fatalf("trust = %+v, want exactly the supplied CA", trust)
	}
}

func TestPveLeafOnlyClusterWithoutCAFileIsInvalidArgument(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	_, _, err := c.probe(labHosts...).TrustIdentity(pvecontract.KindCluster)
	if !errors.Is(err, ErrPveClusterNoCA) {
		t.Fatalf("err = %v, want ErrPveClusterNoCA", err)
	}
	st := status.Convert(pveRPCError(err))
	if st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "--ca-file") || !strings.Contains(st.Message(), "/etc/pve/pve-root-ca.pem") {
		t.Fatalf("rpc error = %v, want InvalidArgument naming --ca-file and pve-root-ca.pem", st)
	}
}

func TestPveWrongCAFileIsRefused(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	other := makeLeafOnlyCluster(t)
	_, _, err := c.probe(labHosts...).TrustIdentityWithCA(pvecontract.KindCluster, mustParseCA(t, other.caPEM), testNow())
	if !errors.Is(err, ErrPveLeafNotChained) {
		t.Fatalf("err = %v, want ErrPveLeafNotChained", err)
	}
	if code := status.Code(pveRPCError(err)); code != codes.InvalidArgument {
		t.Fatalf("rpc code = %v, want InvalidArgument", code)
	}
}

func TestPveCAFileMustCoverEveryEndpoint(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	foreign := makeLeafOnlyCluster(t, labHosts[2])
	res := c.probe(labHosts...)
	res.Endpoints[2] = foreign.probe(labHosts[2]).Endpoints[0]
	_, _, err := res.TrustIdentityWithCA(pvecontract.KindCluster, mustParseCA(t, c.caPEM), testNow())
	if !errors.Is(err, ErrPveLeafNotChained) || !strings.Contains(err.Error(), labHosts[2]) {
		t.Fatalf("err = %v, want ErrPveLeafNotChained for %s", err, labHosts[2])
	}
}

func TestPveCAFileLeafWithoutServerAuthIsRefused(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts[0])
	c.leaves[labHosts[0]], _ = issueLeaf(t, c.ca, c.caKey, labHosts[0], []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	_, _, err := c.probe(labHosts[0]).TrustIdentityWithCA(pvecontract.KindCluster, mustParseCA(t, c.caPEM), testNow())
	if !errors.Is(err, ErrPveLeafNotChained) {
		t.Fatalf("err = %v, want ErrPveLeafNotChained", err)
	}
}

func TestPvePresentedCADiffersFromCAFileIsMismatch(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	presented := makeTestChain(t)
	res := c.probe(labHosts...)
	res.Endpoints[1].CA, res.Endpoints[1].CAFingerprint = presented.ca, fpHex(presented.ca)
	_, _, err := res.TrustIdentityWithCA(pvecontract.KindCluster, mustParseCA(t, c.caPEM), testNow())
	if !errors.Is(err, ErrPvePinMismatch) || !errors.Is(err, ErrPveCAFileMismatch) {
		t.Fatalf("err = %v, want ErrPvePinMismatch and ErrPveCAFileMismatch", err)
	}
	if code := status.Code(pveRPCError(err)); code != codes.InvalidArgument {
		t.Fatalf("rpc code = %v, want InvalidArgument", code)
	}
}

func TestPvePresentedCAEqualToCAFileIsAccepted(t *testing.T) {
	c := makeLeafOnlyCluster(t, labHosts...)
	res := c.probe(labHosts...)
	res.Endpoints[0].CA, res.Endpoints[0].CAFingerprint = c.ca, fpHex(c.ca)
	pin, _, err := res.TrustIdentityWithCA(pvecontract.KindCluster, mustParseCA(t, c.caPEM), testNow())
	if err != nil || pin != fpHex(c.ca) {
		t.Fatalf("pin, err = %s, %v; want the CA fingerprint", pin, err)
	}
}

func TestPveStandaloneRefusesCAFileAndIsUnchangedWithout(t *testing.T) {
	chain := makeTestChain(t)
	res := probeResultFrom(chain, "standalone.example.test")
	_, _, err := res.TrustIdentityWithCA(pvecontract.KindStandalone, chain.ca, testNow())
	if !errors.Is(err, ErrPveSuppliedCA) {
		t.Fatalf("standalone with CA file: err = %v, want ErrPveSuppliedCA", err)
	}
	pin, trust, err := res.TrustIdentity(pvecontract.KindStandalone)
	if err != nil || pin != fpHex(chain.leaf) || trust.LeafFingerprint != pvetransport.Fingerprint(chain.leaf) || trust.CA != nil {
		t.Fatalf("standalone without CA file: pin=%s trust=%+v err=%v", pin, trust, err)
	}
}

func TestPveSuppliedCAParse(t *testing.T) {
	c := makeLeafOnlyCluster(t, "pve1.example.test")
	other := makeLeafOnlyCluster(t)
	// An intermediate CA: IsCA, but not self-signed.
	nb, na := certWindow()
	interTmpl := caTemplate("intermediate")
	interTmpl.SerialNumber = big.NewInt(7)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, c.ca, &interKey.PublicKey, c.caKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	// A self-signed certificate that is not a CA.
	notCATmpl := caTemplate("not a ca")
	notCATmpl.IsCA, notCATmpl.KeyUsage = false, x509.KeyUsageDigitalSignature
	notCA, _ := newTestCA(t, notCATmpl)
	expiredTmpl := caTemplate("expired")
	expiredTmpl.NotBefore, expiredTmpl.NotAfter = nb, testNow().Add(-time.Hour)
	expired, _ := newTestCA(t, expiredTmpl)
	futureTmpl := caTemplate("future")
	futureTmpl.NotBefore, futureTmpl.NotAfter = testNow().Add(time.Hour), na
	future, _ := newTestCA(t, futureTmpl)
	withHeader := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: c.ca.Raw})
	large := append(append([]byte{}, c.caPEM...), bytes.Repeat([]byte("\n"), MaxPveCAFileBytes)...)

	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"valid", c.caPEM, true},
		{"valid with surrounding whitespace", append(append([]byte("\n  "), c.caPEM...), '\n', '\n'), true},
		{"empty", nil, false},
		{"too large", large, false},
		{"two certificates", pemOf(c.ca, other.ca), false},
		{"not pem", c.ca.Raw, false},
		{"text before the block", append([]byte("subject=PVE Cluster Manager CA\n"), c.caPEM...), false},
		{"trailing garbage", append(append([]byte{}, c.caPEM...), []byte("junk")...), false},
		{"private key block", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), false},
		{"pem headers", withHeader, false},
		{"garbage der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 1, 2, 3}}), false},
		{"leaf instead of CA", pemOf(c.leaves["pve1.example.test"]), false},
		{"intermediate not self-signed", pemOf(inter), false},
		{"self-signed but not CA", pemOf(notCA), false},
		{"expired", pemOf(expired), false},
		{"not yet valid", pemOf(future), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := ParsePveSuppliedCA(tc.raw, testNow())
			if tc.ok {
				if err != nil || !bytes.Equal(ca.Raw, c.ca.Raw) {
					t.Fatalf("ParsePveSuppliedCA = %v, %v; want the CA", ca, err)
				}
				return
			}
			if !errors.Is(err, ErrPveSuppliedCA) {
				t.Fatalf("err = %v, want ErrPveSuppliedCA", err)
			}
			if code := status.Code(pveRPCError(err)); code != codes.InvalidArgument {
				t.Fatalf("rpc code = %v, want InvalidArgument", code)
			}
		})
	}
}

func (e *pveTestEnv) addWithCA(t *testing.T, id string, eps []pvecontract.Endpoint, pin string, caPEM []byte) (executordb.PveRemote, error) {
	t.Helper()
	return e.admin.AddRemote(context.Background(), PveAddRemote{
		RemoteID: id, Kind: pvecontract.KindCluster, Endpoints: eps, ConfirmedPin: pin,
		ReadToken: []byte("nosread@pve!tok1=okvalue"), CAPEM: caPEM, By: "admin",
	})
}

func TestPveAddLeafOnlyClusterWithCAFile(t *testing.T) {
	e := newPveTestEnv(t)
	c := makeLeafOnlyCluster(t, labHosts...)
	eps := pveEndpoints(labHosts...)
	e.probe.result = c.probe(labHosts...)

	// Without --ca-file the add fails with the actionable error, not Internal.
	_, err := e.add(t, "nebulanetwork", pvecontract.KindCluster, eps, fpHex(c.ca), []byte("nosread@pve!tok1=okvalue"))
	if !errors.Is(err, ErrPveClusterNoCA) {
		t.Fatalf("add without CA file: %v", err)
	}
	// The typed fingerprint is still required: a wrong one stores nothing.
	if _, err := e.addWithCA(t, "nebulanetwork", eps, fpHex(c.leaves[labHosts[0]]), c.caPEM); !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("wrong typed fingerprint: %v", err)
	}
	if e.validate.calls != 0 {
		t.Fatalf("token sent before trust was confirmed: %d validations", e.validate.calls)
	}
	if infos, _ := e.vault.List(); len(infos) != 0 {
		t.Fatalf("vault entries after refused add: %v", infos)
	}

	rm, err := e.addWithCA(t, "nebulanetwork", eps, fpHex(c.ca), c.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if rm.TrustPin != fpHex(c.ca) {
		t.Fatalf("pin = %s, want the CA file fingerprint", rm.TrustPin)
	}
	stored, err := e.admin.StoredClusterCA(rm)
	if err != nil || stored == nil || !bytes.Equal(stored.Raw, c.ca.Raw) {
		t.Fatalf("StoredClusterCA = %v, %v; want the supplied CA", stored, err)
	}

	// Rotation re-verifies the leaf-only endpoints against the stored CA
	// and hands the token validation exactly that trust.
	var gotTrust pvetransport.Trust
	e.admin.ValidateToken = func(_ context.Context, _ []pvecontract.Endpoint, trust pvetransport.Trust, _ []byte) error {
		gotTrust = trust
		return nil
	}
	if _, err := e.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: "nebulanetwork", Purpose: PvePurposeRead, Token: []byte("nosread@pve!tok2=okvalue"), By: "admin"}); err != nil {
		t.Fatalf("rotate on leaf-only cluster: %v", err)
	}
	if gotTrust.CA == nil || !bytes.Equal(gotTrust.CA.Raw, c.ca.Raw) {
		t.Fatalf("rotation trust = %+v, want the stored CA", gotTrust)
	}

	// Remove deletes the stored CA with the other vault entries.
	if _, err := e.admin.RemoveRemote(context.Background(), PveRemove{RemoteID: "nebulanetwork", By: "admin"}); err != nil {
		t.Fatal(err)
	}
	if infos, _ := e.vault.List(); len(infos) != 0 {
		t.Fatalf("vault entries after remove: %v", infos)
	}
}

func TestPveRotationOfLeafOnlyClusterWithForeignLeafBlocks(t *testing.T) {
	e := newPveTestEnv(t)
	c := makeLeafOnlyCluster(t, labHosts...)
	eps := pveEndpoints(labHosts...)
	e.probe.result = c.probe(labHosts...)
	if _, err := e.addWithCA(t, "nebulanetwork", eps, fpHex(c.ca), c.caPEM); err != nil {
		t.Fatal(err)
	}
	// A node now serves a leaf of a different CA: the rotation refuses and
	// sends no token.
	foreign := makeLeafOnlyCluster(t, labHosts[1])
	e.probe.result.Endpoints[1] = foreign.probe(labHosts[1]).Endpoints[0]
	calls := e.validate.calls
	_, err := e.admin.RotateToken(context.Background(), PveRotateToken{RemoteID: "nebulanetwork", Purpose: PvePurposeRead, Token: []byte("nosread@pve!tok2=okvalue"), By: "admin"})
	if !errors.Is(err, ErrPvePinMismatch) {
		t.Fatalf("rotate with foreign leaf: %v", err)
	}
	if e.validate.calls != calls {
		t.Fatal("token sent to an endpoint whose leaf does not chain to the pinned CA")
	}
	rm, _, _ := e.db.GetRemote("nebulanetwork")
	if rm.State != executordb.StateBlocked {
		t.Fatalf("state = %s, want blocked", rm.State)
	}
}

func TestPveStoredClusterCAMustMatchPin(t *testing.T) {
	e := newPveTestEnv(t)
	c := makeLeafOnlyCluster(t, labHosts...)
	e.probe.result = c.probe(labHosts...)
	rm, err := e.addWithCA(t, "nebulanetwork", pveEndpoints(labHosts...), fpHex(c.ca), c.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	// A CA stored under the pin's id but with another fingerprint is never
	// used as trust.
	other := makeLeafOnlyCluster(t)
	if _, err := e.vault.Put(pveCAVaultID(rm.RemoteID, rm.TrustPin), other.ca.Raw, "test"); err != nil {
		t.Fatal(err)
	}
	if ca, err := e.admin.StoredClusterCA(rm); ca != nil || err == nil {
		t.Fatalf("StoredClusterCA = %v, %v; want a refusal", ca, err)
	}
	// Nothing stored (a cluster that presents its CA) is not an error.
	if err := e.vault.Delete(pveCAVaultID(rm.RemoteID, rm.TrustPin)); err != nil {
		t.Fatal(err)
	}
	if ca, err := e.admin.StoredClusterCA(rm); ca != nil || err != nil {
		t.Fatalf("StoredClusterCA without entry = %v, %v; want nil, nil", ca, err)
	}
}

func TestPveRepinLeafOnlyClusterToNewCAFile(t *testing.T) {
	e := newPveTestEnv(t)
	c1 := makeLeafOnlyCluster(t, labHosts...)
	eps := pveEndpoints(labHosts...)
	e.probe.result = c1.probe(labHosts...)
	rm, err := e.addWithCA(t, "nebulanetwork", eps, fpHex(c1.ca), c1.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin1 := rm.TrustPin
	c2 := makeLeafOnlyCluster(t, labHosts...)
	pin2 := fpHex(c2.ca)
	e.probe.result = c2.probe(labHosts...)
	e.admin.AuthorizeRepin = func(context.Context, executordb.PveRemote, PveRepin) error { return nil }

	// Without the new CA file the re-pin names the missing file.
	if _, err := e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: pin1, ConfirmedNewPin: pin2, By: "admin"}); !errors.Is(err, ErrPveClusterNoCA) {
		t.Fatalf("repin without CA file: %v", err)
	}
	// The old CA file does not chain the new leaves.
	if _, err := e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: pin1, ConfirmedNewPin: pin2, CAPEM: c1.caPEM, By: "admin"}); !errors.Is(err, ErrPveLeafNotChained) {
		t.Fatalf("repin with old CA file: %v", err)
	}
	rm, err = e.admin.Repin(context.Background(), PveRepin{RemoteID: "nebulanetwork", OldPin: pin1, ConfirmedNewPin: pin2, CAPEM: c2.caPEM, By: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if rm.TrustPin != pin2 || rm.TrustGeneration != 2 {
		t.Fatalf("remote = %s gen %d, want %s gen 2", rm.TrustPin, rm.TrustGeneration, pin2)
	}
	stored, err := e.admin.StoredClusterCA(rm)
	if err != nil || stored == nil || !bytes.Equal(stored.Raw, c2.ca.Raw) {
		t.Fatalf("stored CA after repin = %v, %v", stored, err)
	}
	if _, err := e.vault.Open(pveCAVaultID("nebulanetwork", pin1)); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("old CA still stored: %v", err)
	}
}

// startLeafOnlyServer serves a PVE-like API on loopback presenting only
// the leaf of cluster c for 127.0.0.1.
func startLeafOnlyServer(t *testing.T, c leafOnlyCluster, token string) pvecontract.Endpoint {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken="+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			fmt.Fprint(w, `{"data":{"version":"9.0"}}`)
		case "/api2/json/access/users":
			fmt.Fprint(w, `{"data":[{"userid":"nosread@pve","tokens":[{"tokenid":"tok1","privsep":1,"expire":4000000000}]}]}`)
		case "/api2/json/access/permissions":
			fmt.Fprint(w, `{"data":{"/":{"Sys.Audit":1},"/vms":{"VM.Audit":1},"/storage":{"Datastore.Audit":1},"/pool":{"Pool.Audit":1}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{c.tls["127.0.0.1"]}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return pvecontract.Endpoint{Host: host, Port: uint16(port)}
}

// TestPveTransportVerifiesLeafOnlyChainAgainstCAFile: the real probe of a
// node that serves only its leaf, then pinned connections with Trust{CA}
// built from the CA file (pvetransport, as every later connection uses).
func TestPveTransportVerifiesLeafOnlyChainAgainstCAFile(t *testing.T) {
	const token = "nosread@pve!tok1=okvalue"
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	eps := []pvecontract.Endpoint{startLeafOnlyServer(t, c, token)}

	res, err := DefaultPveProbe(context.Background(), eps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Endpoints[0].CA != nil {
		t.Fatal("leaf-only server reported a CA")
	}
	ca, err := ParsePveSuppliedCA(c.caPEM, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pin, trust, err := res.TrustIdentityWithCA(pvecontract.KindCluster, ca, time.Now())
	if err != nil || pin != fpHex(c.ca) {
		t.Fatalf("pin, err = %s, %v", pin, err)
	}
	if err := DefaultPveTokenValidate(context.Background(), eps, trust, []byte(token)); err != nil {
		t.Fatalf("pinned connection over leaf-only chain refused: %v", err)
	}
	// A connection pinned to another CA never sends the token.
	other := makeLeafOnlyCluster(t)
	err = DefaultPveTokenValidate(context.Background(), eps, pvetransport.Trust{CA: other.ca}, []byte(token))
	if !errors.Is(err, pvetransport.ErrTrustMismatch) {
		t.Fatalf("foreign CA: err = %v, want ErrTrustMismatch", err)
	}
}

func TestPveProbeRPCLeafOnlyCluster(t *testing.T) {
	e := newPveTestEnv(t)
	svc := newReconcileEnv(t).svc
	svc.db, svc.vault = e.db, e.vault
	c := makeLeafOnlyCluster(t, "127.0.0.1")
	ep := startLeafOnlyServer(t, c, "nosread@pve!tok1=okvalue")
	eps := []*pb.PVEEndpoint{{Host: ep.Host, Port: uint32(ep.Port)}}
	ctx := context.Background()

	_, err := svc.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: "cluster", Endpoints: eps})
	if st := status.Convert(err); st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "--ca-file") {
		t.Fatalf("probe without CA file = %v, want InvalidArgument naming --ca-file", err)
	}
	res, err := svc.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: "cluster", Endpoints: eps, CaPem: c.caPEM})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetTrustPin() != fpHex(c.ca) {
		t.Fatalf("trust pin = %s, want the CA file fingerprint", res.GetTrustPin())
	}
	_, err = svc.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: "standalone", Endpoints: eps, CaPem: c.caPEM})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("standalone with CA file = %v, want InvalidArgument", err)
	}
	_, err = svc.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: "cluster", Endpoints: eps, CaPem: bytes.Repeat([]byte("A"), MaxPveCAFileBytes+1)})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized CA file = %v, want InvalidArgument", err)
	}
}
