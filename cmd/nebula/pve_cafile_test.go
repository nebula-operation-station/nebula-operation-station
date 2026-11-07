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
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
)

// pveLeafOnlyCluster is a PVE-like cluster CA and the leaf-only TLS
// certificate one node serves for 127.0.0.1.
type pveLeafOnlyCluster struct {
	ca    *x509.Certificate
	caPEM []byte
	caFP  string
	leaf  tls.Certificate
}

func newPveLeafOnlyCluster(t *testing.T) pveLeafOnlyCluster {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PVE Cluster Manager CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca := mustParseCert(t, caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "pve1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	fp := pvetransport.Fingerprint(ca)
	return pveLeafOnlyCluster{
		ca:    ca,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caFP:  hex.EncodeToString(fp[:]),
		// Leaf only, like pve-ssl.pem on a default PVE node.
		leaf: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

func writeTestFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPveReadCAFileLimits(t *testing.T) {
	c := newPveLeafOnlyCluster(t)
	other := newPveLeafOnlyCluster(t)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.leaf.Certificate[0]})

	raw, fp, err := readPveCAFile(writeTestFile(t, "pve-root-ca.pem", c.caPEM), time.Now())
	if err != nil || !bytes.Equal(raw, c.caPEM) || fp != c.caFP {
		t.Fatalf("valid CA file: fp=%s err=%v; want %s", fp, err, c.caFP)
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing", filepath.Join(t.TempDir(), "absent.pem")},
		{"directory", t.TempDir()},
		{"too large", writeTestFile(t, "big.pem", append(append([]byte{}, c.caPEM...), bytes.Repeat([]byte("\n"), maxPveCAFileBytes)...))},
		{"two certificates", writeTestFile(t, "two.pem", append(append([]byte{}, c.caPEM...), other.caPEM...))},
		{"leaf instead of CA", writeTestFile(t, "leaf.pem", leafPEM)},
		{"empty", writeTestFile(t, "empty.pem", nil)},
		{"der", writeTestFile(t, "ca.der", c.ca.Raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readPveCAFile(tc.path, time.Now()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, _, err := readPveCAFile(writeTestFile(t, "two.pem", append(append([]byte{}, c.caPEM...), other.caPEM...)), time.Now()); !errors.Is(err, executor.ErrPveSuppliedCA) {
		t.Fatalf("two certificates: err = %v, want ErrPveSuppliedCA", err)
	}
}

// TestPveReadCAFileRefusesFIFOAndDeviceWithoutBlocking: a FIFO or device
// is refused before it is opened, so the CLI never waits for a writer.
func TestPveReadCAFileRefusesFIFOAndDeviceWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "ca.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, os.DevNull} {
		done := make(chan error, 1)
		go func() {
			_, _, err := readPveCAFile(path, time.Now())
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("%s: err = %v, want not a regular file", path, err)
			}
		case <-time.After(5 * time.Second):
			// Unblock the reader so the test can finish.
			if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
				_ = w.Close()
			}
			t.Fatalf("%s: readPveCAFile blocked", path)
		}
	}
}

func TestPveRemoteAddStandaloneRefusesCAFile(t *testing.T) {
	c := newPveLeafOnlyCluster(t)
	err := pveCmd([]string{"remote", "add", "lab", "--kind", "standalone", "--endpoint", "127.0.0.1:8006", "--ca-file", writeTestFile(t, "ca.pem", c.caPEM)},
		strings.NewReader(""), func(string) ([]byte, error) { return nil, errors.New("no prompts") }, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "only for --kind cluster") {
		t.Fatalf("standalone --ca-file: %v", err)
	}
}

func TestPveRemoteAddLeafOnlyClusterWithCAFile(t *testing.T) {
	dir := pveTestDataDir(t)
	c := newPveLeafOnlyCluster(t)
	endpoint, leafPin := pvePinningServer(t, c.leaf)
	caPath := writeTestFile(t, "pve-root-ca.pem", c.caPEM)

	// Without --ca-file the executor names the missing file.
	var out bytes.Buffer
	err := pveCmd([]string{"remote", "add", "nebulanetwork", "--kind", "cluster", "--endpoint", endpoint},
		strings.NewReader(c.caFP+"\n"), pveTestAsk(t), &out)
	if err == nil || !strings.Contains(err.Error(), "--ca-file") || !strings.Contains(err.Error(), "InvalidArgument") {
		t.Fatalf("leaf-only cluster without --ca-file: %v", err)
	}

	// Typing the leaf fingerprint instead of the CA's stores nothing.
	err = pveCmd([]string{"remote", "add", "nebulanetwork", "--kind", "cluster", "--endpoint", endpoint, "--ca-file", caPath},
		strings.NewReader(leafPin+"\n"), pveTestAsk(t), &out)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("leaf fingerprint typed: %v", err)
	}
	if _, ok, _ := pveTestDB(t, dir).GetRemote("nebulanetwork"); ok {
		t.Fatal("remote stored without the CA fingerprint confirmed")
	}

	out.Reset()
	err = pveCmd([]string{"remote", "add", "nebulanetwork", "--kind", "cluster", "--endpoint", endpoint, "--ca-file", caPath},
		strings.NewReader(c.caFP+"\n"), pveTestAsk(t), &out)
	if err != nil {
		t.Fatalf("add with --ca-file: %v", err)
	}
	if !strings.Contains(out.String(), "ca   "+c.caFP) {
		t.Fatalf("CA file fingerprint not shown: %s", out.String())
	}
	rm, ok, err := pveTestDB(t, dir).GetRemote("nebulanetwork")
	if err != nil || !ok || rm.TrustPin != c.caFP {
		t.Fatalf("remote = %+v ok=%v err=%v, want pin %s", rm, ok, err, c.caFP)
	}

	// A CA file of another cluster is refused on re-pin before any change.
	other := newPveLeafOnlyCluster(t)
	err = pveCmd([]string{"remote", "repin", "nebulanetwork", "--ca-file", writeTestFile(t, "other.pem", other.caPEM)},
		strings.NewReader(c.caFP+"\n"+other.caFP+"\nyes\n"), pveTestAsk(t), &out)
	if err == nil || !strings.Contains(err.Error(), "InvalidArgument") {
		t.Fatalf("repin with a foreign CA file: %v", err)
	}
}
