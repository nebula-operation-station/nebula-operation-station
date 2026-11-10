// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const (
	testNetDevPin  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testNetDevPin2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// netDevFaultStore wraps the executor database and fails chosen calls, so
// the vault and the registry see the same storage faults.
type netDevFaultStore struct {
	*executordb.DB
	// failPutAfter fails every PutSecret after this many succeeded (-1: never).
	failPutAfter int
	puts         int
	failDelete   bool
	failInsert   bool
}

func (s *netDevFaultStore) PutSecret(v executordb.VaultSecret) error {
	if s.failPutAfter >= 0 && s.puts >= s.failPutAfter {
		return errors.New("injected put failure")
	}
	s.puts++
	return s.DB.PutSecret(v)
}

func (s *netDevFaultStore) DeleteSecret(id string) (bool, error) {
	if s.failDelete {
		return false, errors.New("injected delete failure")
	}
	return s.DB.DeleteSecret(id)
}

func (s *netDevFaultStore) InsertNetDevice(d executordb.NetDevice) (executordb.NetDevice, error) {
	if s.failInsert {
		return executordb.NetDevice{}, errors.New("injected insert failure")
	}
	return s.DB.InsertNetDevice(d)
}

type netDevTestEnv struct {
	dir   string
	db    *executordb.DB
	store *netDevFaultStore
	vault *vault.Vault
	reg   *NetDeviceRegistry
	// lookups counts resolver calls.
	lookups int
}

func newNetDevTestEnv(t *testing.T) *netDevTestEnv {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t, dir)
	store := &netDevFaultStore{DB: db, failPutAfter: -1}
	v := vault.New(store)
	v.SetMinParams(testVaultParams)
	pass := strings.Repeat("correct-horse-battery-staple-", 4)
	if err := v.Init([]byte(pass), testVaultParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	e := &netDevTestEnv{dir: dir, db: db, store: store, vault: v}
	e.reg = &NetDeviceRegistry{
		Store: store,
		Vault: v,
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			e.lookups++
			return nil, errors.New("no resolver configured in this test")
		},
	}
	return e
}

func (e *netDevTestEnv) resolveTo(addrs ...string) {
	e.reg.Resolve = func(_ context.Context, _ string) ([]netip.Addr, error) {
		e.lookups++
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func (e *netDevTestEnv) secretIDs(t *testing.T) []string {
	t.Helper()
	list, err := e.vault.List()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, i := range list {
		ids = append(ids, i.ID)
	}
	return ids
}

func cbsReq(id, endpoint string) NetDeviceRegistration {
	return NetDeviceRegistration{
		DeviceID: id,
		Family:   netdevcontract.FamilyCBS,
		Label:    "core switch",
		Endpoint: endpoint,
		Port:     22,
		PinKind:  netdevcontract.PinSSHHostKey,
		Pin:      testNetDevPin,
		By:       "admin",
	}
}

// refusedAddrs are addresses of every refused class.
var refusedAddrs = []struct{ name, addr string }{
	{"public v4", "8.8.8.8"},
	{"public v4 cgnat", "100.64.0.1"},
	{"broadcast", "255.255.255.255"},
	{"public v6", "2606:4700::1111"},
	{"documentation v6", "2001:db8::1"},
	{"loopback v4", "127.0.0.1"},
	{"loopback v4 other", "127.10.0.1"},
	{"loopback v6", "::1"},
	{"link-local v4", "169.254.10.1"},
	{"link-local v6", "fe80::1"},
	{"multicast v4", "224.0.0.1"},
	{"multicast v4 admin scope", "239.1.2.3"},
	{"multicast v6 link", "ff02::1"},
	{"multicast v6 site", "ff05::2"},
	{"unspecified v4", "0.0.0.0"},
	{"unspecified v6", "::"},
	{"v4-mapped private", "::ffff:10.0.0.1"},
	{"v4-mapped private 192", "::ffff:192.168.1.1"},
	{"v4-mapped loopback", "::ffff:127.0.0.1"},
	{"v4-compatible private", "::10.0.0.1"},
	{"nat64 of private", "64:ff9b::a00:1"},
	{"6to4 of private", "2002:a00:1::1"},
	{"teredo", "2001::1"},
	{"zoned ula", "fd00::1%eth0"},
	{"zoned link-local", "fe80::1%eth0"},
}

var acceptedAddrs = []string{"10.0.0.1", "10.255.255.254", "172.16.5.4", "172.31.0.1", "192.168.1.1", "fd12:3456::1", "fc00::1"}

func TestCheckDeviceAddrRefusesEveryNonPrivateClass(t *testing.T) {
	for _, tc := range refusedAddrs {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckDeviceAddr(netip.MustParseAddr(tc.addr)); !errors.Is(err, ErrNetDeviceAddress) {
				t.Fatalf("CheckDeviceAddr(%s) = %v, want ErrNetDeviceAddress", tc.addr, err)
			}
		})
	}
	if err := CheckDeviceAddr(netip.Addr{}); !errors.Is(err, ErrNetDeviceAddress) {
		t.Fatalf("zero address: %v", err)
	}
	for _, a := range acceptedAddrs {
		if err := CheckDeviceAddr(netip.MustParseAddr(a)); err != nil {
			t.Fatalf("CheckDeviceAddr(%s) = %v, want nil", a, err)
		}
	}
}

func TestNetDevRegisterRefusesAddressLiteralClasses(t *testing.T) {
	for _, tc := range refusedAddrs {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevTestEnv(t)
			_, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", tc.addr))
			if !errors.Is(err, ErrNetDeviceAddress) {
				t.Fatalf("register %s: %v, want ErrNetDeviceAddress", tc.addr, err)
			}
			if e.lookups != 0 {
				t.Fatalf("address literal %s was resolved", tc.addr)
			}
			if ids := e.secretIDs(t); len(ids) != 0 {
				t.Fatalf("vault entries left behind: %v", ids)
			}
			if _, ok, err := e.db.GetNetDevice("sw1"); err != nil || ok {
				t.Fatalf("device stored: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestNetDevRegisterRefusesResolvedAddressClasses(t *testing.T) {
	for _, tc := range refusedAddrs {
		if strings.Contains(tc.addr, "%") {
			continue // a resolver never returns a zone; covered by the literal test
		}
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevTestEnv(t)
			e.resolveTo(tc.addr)
			req := cbsReq("sw1", "switch.lab.example")
			req.Label = ""
			_, err := e.reg.RegisterNetDevice(context.Background(), req)
			if !errors.Is(err, ErrNetDeviceAddress) {
				t.Fatalf("name resolving to %s: %v, want ErrNetDeviceAddress", tc.addr, err)
			}
			if ids := e.secretIDs(t); len(ids) != 0 {
				t.Fatalf("vault entries left behind: %v", ids)
			}
		})
	}
}

func TestNetDevRegisterLiteralStoresDeviceAndKeys(t *testing.T) {
	for _, a := range acceptedAddrs {
		t.Run(a, func(t *testing.T) {
			e := newNetDevTestEnv(t)
			dev, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", a))
			if err != nil {
				t.Fatal(err)
			}
			if e.lookups != 0 {
				t.Fatal("address literal was resolved")
			}
			if dev.EndpointIP != netip.MustParseAddr(a).String() || dev.Port != 22 || dev.Label != "core switch" {
				t.Fatalf("stored device %+v", dev)
			}
			if dev.TrustGeneration != 1 || dev.Blocked || dev.CredentialRef != "" {
				t.Fatalf("new device state %+v", dev)
			}
			got, ok, err := e.db.GetNetDevice("sw1")
			if err != nil || !ok || got.EndpointIP != dev.EndpointIP {
				t.Fatalf("stored row: %+v ok=%v err=%v", got, ok, err)
			}
			dk, err := e.vault.Open(dev.DigestKeyRef)
			if err != nil {
				t.Fatalf("open digest key: %v", err)
			}
			fk, err := e.vault.Open(dev.FingerprintKeyRef)
			if err != nil {
				t.Fatalf("open fingerprint key: %v", err)
			}
			if len(dk) != NetDeviceKeyBytes || len(fk) != NetDeviceKeyBytes {
				t.Fatalf("key lengths %d %d", len(dk), len(fk))
			}
			if bytes.Equal(dk, fk) || bytes.Equal(dk, make([]byte, NetDeviceKeyBytes)) {
				t.Fatal("digest and fingerprint keys are not independent random keys")
			}
			ap, err := DialAddr(got)
			if err != nil || ap != netip.AddrPortFrom(netip.MustParseAddr(a), 22) {
				t.Fatalf("DialAddr = %v, %v", ap, err)
			}
		})
	}
}

func TestNetDevKeysArePerDevice(t *testing.T) {
	e := newNetDevTestEnv(t)
	d1, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	r2 := cbsReq("sw2", "10.0.0.2")
	r2.Pin = testNetDevPin2
	d2, err := e.reg.RegisterNetDevice(context.Background(), r2)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{d1.DigestKeyRef: true, d1.FingerprintKeyRef: true, d2.DigestKeyRef: true, d2.FingerprintKeyRef: true}
	if len(refs) != 4 {
		t.Fatalf("vault references are shared: %v", refs)
	}
	k1, _ := e.vault.Open(d1.DigestKeyRef)
	k2, _ := e.vault.Open(d2.DigestKeyRef)
	if bytes.Equal(k1, k2) {
		t.Fatal("two devices share a digest key")
	}
}

func TestNetDevKeyRefsFitForLongDeviceIDs(t *testing.T) {
	e := newNetDevTestEnv(t)
	id := strings.Repeat("a", netdevcontract.MaxDeviceIDBytes)
	dev, err := e.reg.RegisterNetDevice(context.Background(), cbsReq(id, "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if dev.DigestKeyRef == dev.FingerprintKeyRef || len(dev.DigestKeyRef) > 64 || len(dev.FingerprintKeyRef) > 64 {
		t.Fatalf("refs %q %q", dev.DigestKeyRef, dev.FingerprintKeyRef)
	}
}

func TestNetDevRegisterResolvesNameOnceAndKeepsItAsLabel(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.resolveTo("192.168.10.2")
	req := cbsReq("sw1", "Switch.Lab.Example.")
	req.Label = ""
	dev, err := e.reg.RegisterNetDevice(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if e.lookups != 1 {
		t.Fatalf("resolver called %d times, want 1", e.lookups)
	}
	if dev.EndpointIP != "192.168.10.2" || dev.Label != "switch.lab.example" {
		t.Fatalf("stored %+v", dev)
	}
	if _, err := DialAddr(dev); err != nil {
		t.Fatal(err)
	}
	if e.lookups != 1 {
		t.Fatal("DialAddr resolved a name")
	}
}

func TestNetDevRegisterNameWithConflictingLabelIsRefused(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.resolveTo("192.168.10.2")
	req := cbsReq("sw1", "switch.lab.example")
	req.Label = "something else"
	if _, err := e.reg.RegisterNetDevice(context.Background(), req); !errors.Is(err, ErrNetDeviceRequest) {
		t.Fatalf("got %v, want ErrNetDeviceRequest", err)
	}
	req.Label = "switch.lab.example"
	if _, err := e.reg.RegisterNetDevice(context.Background(), req); err != nil {
		t.Fatalf("matching label: %v", err)
	}
}

func TestNetDevRegisterNameNeedsExactlyOneAddress(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
	}{
		{"none", nil},
		{"two private", []string{"10.0.0.1", "10.0.0.2"}},
		{"same twice", []string{"10.0.0.1", "10.0.0.1"}},
		{"private and public", []string{"10.0.0.1", "8.8.8.8"}},
		{"v4 and v6", []string{"10.0.0.1", "fd00::1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevTestEnv(t)
			e.resolveTo(tc.addrs...)
			req := cbsReq("sw1", "switch.lab.example")
			req.Label = ""
			if _, err := e.reg.RegisterNetDevice(context.Background(), req); !errors.Is(err, ErrNetDeviceResolve) {
				t.Fatalf("got %v, want ErrNetDeviceResolve", err)
			}
			if ids := e.secretIDs(t); len(ids) != 0 {
				t.Fatalf("vault entries left behind: %v", ids)
			}
		})
	}
}

func TestNetDevRegisterResolverErrorFailsClosed(t *testing.T) {
	e := newNetDevTestEnv(t)
	req := cbsReq("sw1", "switch.lab.example")
	req.Label = ""
	if _, err := e.reg.RegisterNetDevice(context.Background(), req); !errors.Is(err, ErrNetDeviceResolve) {
		t.Fatalf("got %v, want ErrNetDeviceResolve", err)
	}
	if e.lookups != 1 {
		t.Fatalf("lookups %d", e.lookups)
	}
	if ids := e.secretIDs(t); len(ids) != 0 {
		t.Fatalf("vault entries left behind: %v", ids)
	}
}

func TestNetDevRegisterWithoutResolverRefusesNames(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.reg.Resolve = nil
	req := cbsReq("sw1", "switch.lab.example")
	req.Label = ""
	if _, err := e.reg.RegisterNetDevice(context.Background(), req); !errors.Is(err, ErrNetDeviceResolve) {
		t.Fatalf("got %v, want ErrNetDeviceResolve", err)
	}
}

func TestNetDevRegisterRefusesMalformedRequests(t *testing.T) {
	mut := []struct {
		name string
		f    func(*NetDeviceRegistration)
	}{
		{"empty endpoint", func(r *NetDeviceRegistration) { r.Endpoint = "" }},
		{"endpoint with port", func(r *NetDeviceRegistration) { r.Endpoint = "10.0.0.1:22" }},
		{"bracketed v6", func(r *NetDeviceRegistration) { r.Endpoint = "[fd00::1]" }},
		{"url", func(r *NetDeviceRegistration) { r.Endpoint = "ssh://10.0.0.1" }},
		{"numeric last label", func(r *NetDeviceRegistration) { r.Endpoint = "10.1" }},
		{"short v4 form", func(r *NetDeviceRegistration) { r.Endpoint = "167772161" }},
		{"hex v4 form", func(r *NetDeviceRegistration) { r.Endpoint = "0x0a.0.0.1" }},
		{"octal-looking v4", func(r *NetDeviceRegistration) { r.Endpoint = "010.0.0.1" }},
		{"underscore name", func(r *NetDeviceRegistration) { r.Endpoint = "sw_1.lab" }},
		{"space in name", func(r *NetDeviceRegistration) { r.Endpoint = "sw 1.lab" }},
		{"too long name", func(r *NetDeviceRegistration) { r.Endpoint = strings.Repeat("a.", 130) + "lab" }},
		{"long label in name", func(r *NetDeviceRegistration) { r.Endpoint = strings.Repeat("a", 64) + ".lab" }},
		{"non-ascii name", func(r *NetDeviceRegistration) { r.Endpoint = "swïtch.lab" }},
		{"kelvin sign lowers to ascii", func(r *NetDeviceRegistration) { r.Endpoint = "Kswitch.lab"; r.Label = "" }},
		{"port zero", func(r *NetDeviceRegistration) { r.Port = 0 }},
		{"bad device id", func(r *NetDeviceRegistration) { r.DeviceID = "SW 1" }},
		{"bad pin", func(r *NetDeviceRegistration) { r.Pin = "abc" }},
		{"wrong pin kind", func(r *NetDeviceRegistration) { r.PinKind = netdevcontract.PinTLSLeaf }},
		{"unknown family", func(r *NetDeviceRegistration) { r.Family = "pfsense" }},
		{"empty label for literal", func(r *NetDeviceRegistration) { r.Label = "" }},
		{"control char label", func(r *NetDeviceRegistration) { r.Label = "a\x1bb" }},
		{"invalid utf-8 label", func(r *NetDeviceRegistration) { r.Label = "a\xffb" }},
		{"long label", func(r *NetDeviceRegistration) { r.Label = strings.Repeat("x", netdevcontract.MaxLabelBytes+1) }},
		{"no actor", func(r *NetDeviceRegistration) { r.By = "" }},
	}
	for _, tc := range mut {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevTestEnv(t)
			e.resolveTo("10.0.0.9")
			req := cbsReq("sw1", "10.0.0.1")
			tc.f(&req)
			if _, err := e.reg.RegisterNetDevice(context.Background(), req); err == nil {
				t.Fatal("malformed request accepted")
			}
			if e.lookups != 0 {
				t.Fatal("malformed request reached the resolver")
			}
			if ids := e.secretIDs(t); len(ids) != 0 {
				t.Fatalf("vault entries left behind: %v", ids)
			}
		})
	}
}

func TestNetDevRegisterVaultFailureRollsBack(t *testing.T) {
	for _, after := range []int{0, 1} {
		e := newNetDevTestEnv(t)
		e.store.failPutAfter = after
		if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err == nil {
			t.Fatalf("put failure after %d: registration succeeded", after)
		}
		if ids := e.secretIDs(t); len(ids) != 0 {
			t.Fatalf("put failure after %d: vault entries left behind: %v", after, ids)
		}
		if _, ok, err := e.db.GetNetDevice("sw1"); err != nil || ok {
			t.Fatalf("device stored: ok=%v err=%v", ok, err)
		}
		// The id stays usable after the rollback.
		e.store.failPutAfter = -1
		if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err != nil {
			t.Fatalf("retry after rollback: %v", err)
		}
	}
}

func TestNetDevRegisterDBFailureRollsBackVault(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.store.failInsert = true
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err == nil {
		t.Fatal("insert failure: registration succeeded")
	}
	if ids := e.secretIDs(t); len(ids) != 0 {
		t.Fatalf("vault entries left behind: %v", ids)
	}
}

func TestNetDevRegisterRollbackFailureIsReported(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.store.failInsert = true
	e.store.failDelete = true
	_, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1"))
	if !errors.Is(err, ErrNetDeviceRollback) {
		t.Fatalf("got %v, want ErrNetDeviceRollback", err)
	}
	if _, ok, gerr := e.db.GetNetDevice("sw1"); gerr != nil || ok {
		t.Fatalf("device stored: ok=%v err=%v", ok, gerr)
	}
	// Orphaned entries are never adopted: a retry refuses rather than
	// reusing a key that a third party might have set.
	e.store.failInsert, e.store.failDelete = false, false
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); !errors.Is(err, ErrNetDeviceKeyExists) {
		t.Fatalf("retry over orphaned entries: %v, want ErrNetDeviceKeyExists", err)
	}
}

func TestNetDevRegisterRefusesPreexistingVaultEntry(t *testing.T) {
	e := newNetDevTestEnv(t)
	dRef, _ := netDevKeyRefs("sw1")
	if _, err := e.vault.Put(dRef, []byte("attacker-chosen-key-material-0000"), "someone"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); !errors.Is(err, ErrNetDeviceKeyExists) {
		t.Fatalf("got %v, want ErrNetDeviceKeyExists", err)
	}
	// The pre-existing entry is not deleted or overwritten by the rollback.
	got, err := e.vault.Open(dRef)
	if err != nil || string(got) != "attacker-chosen-key-material-0000" {
		t.Fatalf("pre-existing entry changed: %v", err)
	}
	if ids := e.secretIDs(t); len(ids) != 1 {
		t.Fatalf("vault entries: %v", ids)
	}
}

func TestNetDevRegisterLockedVaultFailsClosed(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.vault.Lock()
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("got %v, want vault.ErrLocked", err)
	}
	if _, ok, err := e.db.GetNetDevice("sw1"); err != nil || ok {
		t.Fatalf("device stored: ok=%v err=%v", ok, err)
	}
}

func TestNetDevRegisterDuplicatePin(t *testing.T) {
	e := newNetDevTestEnv(t)
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	before := e.secretIDs(t)
	_, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw2", "10.0.0.2"))
	if !errors.Is(err, ErrDuplicateTrustIdentity) || !errors.Is(err, executordb.ErrNetTrustIdentityInUse) {
		t.Fatalf("got %v, want ErrDuplicateTrustIdentity", err)
	}
	if after := e.secretIDs(t); len(after) != len(before) {
		t.Fatalf("vault entries of the refused device left behind: %v -> %v", before, after)
	}
	if _, ok, err := e.db.GetNetDevice("sw2"); err != nil || ok {
		t.Fatalf("duplicate stored: ok=%v err=%v", ok, err)
	}
}

func TestNetDevRegisterDuplicateIDKeepsExistingKeys(t *testing.T) {
	e := newNetDevTestEnv(t)
	d1, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := e.vault.Open(d1.DigestKeyRef)
	r := cbsReq("sw1", "10.0.0.2")
	r.Pin = testNetDevPin2
	if _, err := e.reg.RegisterNetDevice(context.Background(), r); err == nil {
		t.Fatal("second registration of the same id accepted")
	}
	k2, err := e.vault.Open(d1.DigestKeyRef)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("existing device key changed or deleted: %v", err)
	}
}

func TestNetDevDialAddrRechecksTamperedDevice(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.LookupDialAddr(context.Background(), "sw1"); err != nil {
		t.Fatalf("clean device: %v", err)
	}
	// In-memory tampering: every refused class, plus non-canonical text.
	for _, tc := range refusedAddrs {
		d := dev
		d.EndpointIP = tc.addr
		if _, err := DialAddr(d); !errors.Is(err, ErrNetDeviceAddress) {
			t.Fatalf("DialAddr(%s) = %v, want ErrNetDeviceAddress", tc.addr, err)
		}
	}
	for _, bad := range []string{"", "switch.lab.example", "localhost", "10.0.0.1:22", "FD00::1", "fd00:0::1", " 10.0.0.1"} {
		d := dev
		d.EndpointIP = bad
		if _, err := DialAddr(d); !errors.Is(err, ErrNetDeviceAddress) {
			t.Fatalf("DialAddr(%q) = %v, want ErrNetDeviceAddress", bad, err)
		}
	}
	d := dev
	d.Port = 0
	if _, err := DialAddr(d); err == nil {
		t.Fatal("port 0 accepted")
	}
	d = dev
	d.Blocked, d.BlockReason = true, "pin mismatch"
	if _, err := DialAddr(d); !errors.Is(err, ErrNetDeviceNotDialable) {
		t.Fatalf("blocked device: %v", err)
	}

	// Tampering with the stored row (the executor holds the database
	// exclusively, so close it, edit the file, and reopen).
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(e.dir, executordb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`UPDATE netdev_devices SET endpoint_ip = '8.8.8.8' WHERE id = 'sw1'`)
	closeErr := raw.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	db, err := executordb.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db, e.store.DB = db, db
	if ap, err := e.reg.LookupDialAddr(context.Background(), "sw1"); err == nil {
		t.Fatalf("tampered row dialled at %v", ap)
	}
	if e.lookups != 0 {
		t.Fatal("dial path resolved a name")
	}
}

func TestNetDevLookupDialAddrUnknownAndBlocked(t *testing.T) {
	e := newNetDevTestEnv(t)
	if _, err := e.reg.LookupDialAddr(context.Background(), "nope"); !errors.Is(err, executordb.ErrNetDeviceNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
	if _, err := e.reg.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.BlockNetDevice("sw1", "pin mismatch"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.LookupDialAddr(context.Background(), "sw1"); !errors.Is(err, ErrNetDeviceNotDialable) {
		t.Fatalf("blocked device: %v", err)
	}
	if _, err := e.db.UnblockNetDevice("sw1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.TombstoneNetDevice("sw1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.LookupDialAddr(context.Background(), "sw1"); !errors.Is(err, ErrNetDeviceNotDialable) {
		t.Fatalf("tombstoned device: %v", err)
	}
}

func TestNetDevRegistryMissingDepsFailClosed(t *testing.T) {
	e := newNetDevTestEnv(t)
	r := &NetDeviceRegistry{Vault: e.vault}
	if _, err := r.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err == nil {
		t.Fatal("registry without store accepted a device")
	}
	r = &NetDeviceRegistry{Store: e.store}
	if _, err := r.RegisterNetDevice(context.Background(), cbsReq("sw1", "10.0.0.1")); err == nil {
		t.Fatal("registry without vault accepted a device")
	}
}

func TestNetDevRegisterPANOS(t *testing.T) {
	e := newNetDevTestEnv(t)
	req := NetDeviceRegistration{
		DeviceID: "fw1", Family: netdevcontract.FamilyPANOS, Label: "edge fw",
		Endpoint: "fd00:10::1", Port: 443, PinKind: netdevcontract.PinTLSLeaf, Pin: testNetDevPin, By: "admin",
	}
	dev, err := e.reg.RegisterNetDevice(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := DialAddr(dev)
	if err != nil || ap.String() != "[fd00:10::1]:443" {
		t.Fatalf("DialAddr = %v, %v", ap, err)
	}
}
