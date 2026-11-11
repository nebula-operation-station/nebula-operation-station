// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

const (
	importCBS   = "core-sw-01"
	importPANOS = "fw-01"
	importGen   = 3
)

// readPayloads holds one valid spooled payload per read (protojson with
// proto field names, as the poller writes it).
var readPayloads = []struct {
	read, device, payload string
	stored                netdevinventory.Read
}{
	{ReadCBSVersion, importCBS, `{"model":"CBS350-24P","firmware":"3.4.0.17","serial":"PSZ1"}`, netdevinventory.ReadFacts},
	{ReadCBSVLANs, importCBS, `{"vlans":[{"id":1,"name":"default"},{"id":20,"name":"lab"}]}`, netdevinventory.ReadVLANs},
	{ReadCBSInterfaces, importCBS, `{"ports":[{"name":"gi1","admin_state":"NET_DEV_LINK_STATE_UP","oper_state":"NET_DEV_LINK_STATE_UP","mode":"NET_DEV_PORT_MODE_ACCESS","access_vlan":1}]}`, netdevinventory.ReadPorts},
	{ReadCBSMACTable, importCBS, `{"entries":[{"vlan":1,"mac":"aa:bb:cc:dd:ee:ff","port":"gi1","type":"NET_DEV_MAC_TYPE_DYNAMIC"}]}`, netdevinventory.ReadMACTable},
	{ReadCBSLLDP, importCBS, `{"neighbors":[{"local_port":"gi1","chassis_id":"aa:bb:cc:00:00:01","port_id":"eth0","capabilities":["NET_DEV_LLDP_CAPABILITY_BRIDGE"]}]}`, netdevinventory.ReadLLDPNeighbors},
	{ReadPANOSZones, importPANOS, `{"zones":[{"name":"trust","type":"NET_DEV_ZONE_TYPE_LAYER3","interfaces":["ethernet1/1"]}]}`, netdevinventory.ReadFirewallPolicy},
	{ReadPANOSObjects, importPANOS, `{"addresses":[{"name":"web","type":"NET_DEV_ADDRESS_TYPE_IP_NETMASK","value":"10.0.0.5/32"}],"tags":["prod"]}`, netdevinventory.ReadFirewallPolicy},
	{ReadPANOSSecurityRules, importPANOS, `{"rules":[{"name":"allow-web","from_zones":["untrust"],"to_zones":["trust"],"action":"NET_DEV_RULE_ACTION_ALLOW"}]}`, netdevinventory.ReadFirewallPolicy},
	{ReadPANOSNATRules, importPANOS, `{"rules":[{"name":"snat","from_zones":["trust"],"to_zones":["untrust"]}]}`, netdevinventory.ReadFirewallPolicy},
	{ReadPANOSRuleHitCounts, importPANOS, `{"entries":[{"rule_name":"allow-web","hits":"3","last_hit_unix":"1762776000"}]}`, netdevinventory.ReadHitCounts},
}

type importEnv struct {
	spool *Spool
	store *netdevinventory.Store
	imp   *Importer
	now   *time.Time
}

// newImportEnv returns a spool, a store over a fresh server database with
// both test devices registered, and an Importer over them.
func newImportEnv(t *testing.T) *importEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	now := testTime.Add(10 * time.Minute)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	store := netdevinventory.NewWithNow(db, clock)
	for _, d := range []netdevcontract.Device{
		{DeviceID: importCBS, Name: "Core switch", Family: netdevcontract.FamilyCBS,
			Endpoints: []netdevcontract.Endpoint{{Address: "192.168.1.2", Port: 22}},
			PinKind:   netdevcontract.PinSSHHostKey, TrustPin: strings.Repeat("a", 64), TrustGeneration: importGen},
		{DeviceID: importPANOS, Name: "Edge firewall", Family: netdevcontract.FamilyPANOS,
			Endpoints: []netdevcontract.Endpoint{{Address: "192.168.1.1", Port: 443}},
			PinKind:   netdevcontract.PinTLSLeaf, TrustPin: strings.Repeat("b", 64), TrustGeneration: importGen},
	} {
		if err := store.UpsertDevice(context.Background(), d); err != nil {
			t.Fatalf("UpsertDevice: %v", err)
		}
	}
	sp := newSpool(t)
	env := &importEnv{spool: sp, store: store, now: &now}
	env.imp = &Importer{Spool: sp, Store: store, Now: clock}
	return env
}

func (e *importEnv) write(t *testing.T, device, read string, gen uint64, incomplete bool, payload string) string {
	t.Helper()
	name, err := e.spool.Write(context.Background(), device, read, gen, incomplete, []byte(payload))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return name
}

func (e *importEnv) run(t *testing.T) ImportReport {
	t.Helper()
	rep, err := e.imp.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

// spoolFiles lists the regular files left in the spool directory.
func spoolFiles(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	for _, n := range dirNames(t, s.Dir) {
		if n != KeptDirName {
			out = append(out, n)
		}
	}
	return out
}

func TestImportStoresEveryReadKind(t *testing.T) {
	for _, rp := range readPayloads {
		for _, incomplete := range []bool{false, true} {
			if incomplete && rp.read == ReadCBSVersion {
				continue // facts cannot be incomplete by contract
			}
			t.Run(rp.read+map[bool]string{false: "", true: "/incomplete"}[incomplete], func(t *testing.T) {
				e := newImportEnv(t)
				e.write(t, rp.device, rp.read, importGen, incomplete, rp.payload)
				rep := e.run(t)
				if rep.Imported != 1 || rep.Kept+rep.Retry+rep.Failed != 0 {
					t.Fatalf("report = %+v", rep)
				}
				if left := spoolFiles(t, e.spool); len(left) != 0 {
					t.Fatalf("spool not confirmed: %v", left)
				}
				ds, err := e.store.GetDataset(context.Background(), rp.device, rp.stored)
				if err != nil {
					t.Fatalf("GetDataset: %v", err)
				}
				want := netdevinventory.StateFresh
				if incomplete {
					want = netdevinventory.StatePartial
				}
				if ds.State != want || ds.RowCount == 0 {
					t.Fatalf("dataset state %s rows %d, want %s with rows", ds.State, ds.RowCount, want)
				}
			})
		}
	}
}

func TestImportKeepsInvalidRecordWithReason(t *testing.T) {
	cases := []struct {
		name, device, read string
		gen                uint64
		incomplete         bool
		payload            string
		tamper             func(t *testing.T, path string)
		reason             string
	}{
		{name: "undecodable payload", device: importCBS, read: ReadCBSVLANs, gen: importGen,
			payload: `{"vlans":[{"id":1}],"unknown":true}`, reason: ReasonInvalidPayload},
		{name: "unspecified enum", device: importCBS, read: ReadCBSMACTable, gen: importGen,
			payload: `{"entries":[{"vlan":1,"mac":"aa:bb:cc:dd:ee:ff"}]}`, reason: ReasonInvalidPayload},
		{name: "rows fail contract", device: importCBS, read: ReadCBSMACTable, gen: importGen,
			payload: `{"entries":[{"vlan":1,"mac":"AA:BB:CC:DD:EE:FF","type":"NET_DEV_MAC_TYPE_DYNAMIC"}]}`, reason: ReasonInvalidRows},
		{name: "incomplete facts", device: importCBS, read: ReadCBSVersion, gen: importGen, incomplete: true,
			payload: `{"model":"CBS350","firmware":"3.4"}`, reason: ReasonInvalidRows},
		{name: "unknown device", device: "ghost-sw", read: ReadCBSVLANs, gen: importGen,
			payload: `{"vlans":[]}`, reason: ReasonUnknownDevice},
		{name: "wrong family", device: importPANOS, read: ReadCBSVLANs, gen: importGen,
			payload: `{"vlans":[]}`, reason: ReasonWrongFamily},
		{name: "trust generation changed", device: importCBS, read: ReadCBSVLANs, gen: importGen + 1,
			payload: `{"vlans":[]}`, reason: ReasonTrustGenerationChanged},
		{name: "tampered file mode", device: importCBS, read: ReadCBSVLANs, gen: importGen, payload: `{"vlans":[]}`,
			tamper: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}, reason: ReasonInvalidRecord},
		{name: "record does not match name", device: importCBS, read: ReadCBSVLANs, gen: importGen, payload: `{"vlans":[]}`,
			tamper: func(t *testing.T, path string) {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = []byte(strings.Replace(string(raw), importCBS, "other-sw", 1))
				if err := os.WriteFile(path, raw, 0o640); err != nil {
					t.Fatal(err)
				}
			}, reason: ReasonInvalidRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newImportEnv(t)
			name := e.write(t, tc.device, tc.read, tc.gen, tc.incomplete, tc.payload)
			if tc.tamper != nil {
				tc.tamper(t, filepath.Join(e.spool.Dir, name))
			}
			rep := e.run(t)
			if rep.Kept != 1 || rep.Imported != 0 {
				t.Fatalf("report = %+v", rep)
			}
			if left := spoolFiles(t, e.spool); len(left) != 0 {
				t.Fatalf("rejected record still in the spool: %v", left)
			}
			keptDir := filepath.Join(e.spool.Dir, KeptDirName)
			if _, err := os.Stat(filepath.Join(keptDir, name)); err != nil {
				t.Fatalf("record not kept: %v", err)
			}
			reason, err := os.ReadFile(filepath.Join(keptDir, name+keptReasonSuffix))
			if err != nil || string(reason) != "reason: "+tc.reason+"\n" {
				t.Fatalf("reason file = %q, %v; want %s", reason, err, tc.reason)
			}
			// Never retried: the next pass sees nothing.
			if rep := e.run(t); rep.Files != 0 || rep.Kept != 0 {
				t.Fatalf("second pass = %+v", rep)
			}
		})
	}
}

// failingStore fails while fail is set and records every call.
type failingStore struct {
	mu    sync.Mutex
	inner DatasetStore
	fail  bool
	calls []time.Time
}

func (f *failingStore) ReplaceDataset(ctx context.Context, deviceID string, read netdevinventory.Read, gen uint64,
	observedAt time.Time, incomplete bool, rows netdevinventory.Rows) (netdevinventory.ReplaceResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, observedAt)
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return netdevinventory.ReplaceResult{}, errors.New("database is locked")
	}
	return f.inner.ReplaceDataset(ctx, deviceID, read, gen, observedAt, incomplete, rows)
}

func TestImportStoreErrorLeavesSpoolFileForRetry(t *testing.T) {
	e := newImportEnv(t)
	fs := &failingStore{inner: e.store, fail: true}
	e.imp.Store = fs
	older := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	newer := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1},{"id":2}]}`)

	rep := e.run(t)
	if rep.Retry != 1 || rep.Deferred != 1 || rep.Imported != 0 || rep.Kept != 0 {
		t.Fatalf("first pass = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); !slices.Equal(left, []string{older, newer}) && !slices.Equal(left, []string{newer, older}) {
		t.Fatalf("spool = %v, want both files", left)
	}
	if _, err := e.store.GetDataset(context.Background(), importCBS, netdevinventory.ReadVLANs); !errors.Is(err, netdevinventory.ErrDatasetNotFound) {
		t.Fatalf("store changed after a failed write: %v", err)
	}
	// The first failure is retried on the next pass; it fails again and
	// the device backs off.
	if rep := e.run(t); rep.Retry != 1 {
		t.Fatalf("second pass = %+v", rep)
	}
	if rep := e.run(t); rep.Retry != 0 || rep.Deferred != 2 {
		t.Fatalf("pass during backoff = %+v", rep)
	}
	fs.mu.Lock()
	fs.fail = false
	fs.mu.Unlock()
	*e.now = e.now.Add(importRetryBase)
	rep = e.run(t)
	if rep.Imported != 2 || rep.Retry != 0 {
		t.Fatalf("pass after recovery = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
	ds, err := e.store.GetDataset(context.Background(), importCBS, netdevinventory.ReadVLANs)
	if err != nil || ds.RowCount != 2 {
		t.Fatalf("dataset = %+v, %v; want the newer read", ds, err)
	}
}

// TestImportRedeliveryAfterCommitIsIdempotent covers a crash between the
// store commit and the confirm: the next pass stores the same dataset
// again, which changes nothing, and then confirms the file.
func TestImportRedeliveryAfterCommitIsIdempotent(t *testing.T) {
	e := newImportEnv(t)
	name := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	taken, err := e.spool.Take(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := netdevinventory.DecodePayload(spoolReadEnum[ReadCBSVLANs], taken.Record.Data)
	if err != nil {
		t.Fatal(err)
	}
	first, err := e.store.ReplaceDataset(context.Background(), importCBS, netdevinventory.ReadVLANs, importGen,
		taken.Record.ObservedAt, false, rows)
	if err != nil {
		t.Fatal(err)
	}
	rep := e.run(t)
	if rep.Imported != 1 || rep.Unchanged != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
	ds, err := e.store.GetDataset(context.Background(), importCBS, netdevinventory.ReadVLANs)
	if err != nil || ds.ID != first.DatasetID {
		t.Fatalf("dataset %+v, %v; want unchanged id %d", ds, err, first.DatasetID)
	}
}

func TestImportDuplicateRecordIsIdempotent(t *testing.T) {
	e := newImportEnv(t)
	e.spool.Now = fixedNow(testTime)
	e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	rep := e.run(t)
	if rep.Imported != 2 || rep.Unchanged != 1 || rep.Kept+rep.Retry+rep.Replayed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
}

func TestImportOrdersByObservedAt(t *testing.T) {
	e := newImportEnv(t)
	fs := &failingStore{inner: e.store}
	e.imp.Store = fs
	// Written newest first; each read of the device must still be stored
	// oldest first, or the store would refuse the older one.
	at := []time.Duration{3 * time.Minute, time.Minute, 2 * time.Minute}
	for i, d := range at {
		e.spool.Now = fixedNow(testTime.Add(d))
		e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":`+string(rune('1'+i))+`}]}`)
	}
	e.spool.Now = fixedNow(testTime)
	e.write(t, importPANOS, ReadPANOSRuleHitCounts, importGen, false, `{"entries":[]}`)
	rep := e.run(t)
	if rep.Imported != 4 || rep.Replayed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if !slices.IsSortedFunc(fs.calls, func(a, b time.Time) int { return a.Compare(b) }) || len(fs.calls) != 4 {
		t.Fatalf("store calls not in observation order: %v", fs.calls)
	}
	ds, err := e.store.GetDataset(context.Background(), importCBS, netdevinventory.ReadVLANs)
	if err != nil || !ds.ObservedAt.Equal(testTime.Add(3*time.Minute).Truncate(time.Microsecond)) {
		t.Fatalf("current dataset = %+v, %v; want the newest", ds, err)
	}
}

func TestImportRemovesSupersededRecord(t *testing.T) {
	e := newImportEnv(t)
	rows, err := netdevinventory.DecodePayload(spoolReadEnum[ReadCBSVLANs], []byte(`{"vlans":[{"id":5}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.ReplaceDataset(context.Background(), importCBS, netdevinventory.ReadVLANs, importGen,
		testTime.Add(5*time.Minute), false, rows); err != nil {
		t.Fatal(err)
	}
	e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	rep := e.run(t)
	if rep.Replayed != 1 || rep.Imported+rep.Kept != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
}

func TestImportRemovesRejectedRecordWhenKeptUnusable(t *testing.T) {
	cases := map[string]func(t *testing.T, keptDir string){
		"not a directory": func(t *testing.T, keptDir string) {
			if err := os.WriteFile(keptDir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"world-writable": func(t *testing.T, keptDir string) {
			if err := os.Mkdir(keptDir, keptDirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keptDir, 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"full": func(t *testing.T, keptDir string) {
			if err := os.Mkdir(keptDir, keptDirMode); err != nil {
				t.Fatal(err)
			}
			for i := range 2 * MaxKeptFiles {
				if err := os.WriteFile(filepath.Join(keptDir, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			e := newImportEnv(t)
			keptDir := filepath.Join(e.spool.Dir, KeptDirName)
			prepare(t, keptDir)
			e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[],"bad":1}`)
			rep := e.run(t)
			if rep.Kept != 1 {
				t.Fatalf("report = %+v", rep)
			}
			if left := spoolFiles(t, e.spool); len(left) != 0 {
				t.Fatalf("spool = %v, want empty", left)
			}
		})
	}
}

func TestImporterRequiresConfiguration(t *testing.T) {
	if _, err := (&Importer{}).Run(context.Background()); !errors.Is(err, ErrImporterNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}

// okStore accepts every dataset without a database and counts the calls.
type okStore struct {
	mu    sync.Mutex
	calls int
}

func (s *okStore) ReplaceDataset(context.Context, string, netdevinventory.Read, uint64, time.Time, bool,
	netdevinventory.Rows) (netdevinventory.ReplaceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return netdevinventory.ReplaceResult{}, nil
}

// spoolOf lists the spool files of one device and read, oldest first.
func spoolOf(t *testing.T, s *Spool, device, read string) []string {
	t.Helper()
	names, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range names {
		if p, err := parseSpoolName(n); err == nil && p.device == device && p.read == read {
			out = append(out, n)
		}
	}
	return out
}

// TestImportSpoolStaysBoundedDuringStoreOutage: while the store keeps
// failing, every read of the device keeps at most MaxPendingPerRead files
// (the newest valid one and those after it); after recovery only those are
// replayed and the newest read is stored.
func TestImportSpoolStaysBoundedDuringStoreOutage(t *testing.T) {
	e := newImportEnv(t)
	fs := &failingStore{inner: e.store, fail: true}
	e.imp.Store = fs
	vlans := func(id int) string { return fmt.Sprintf(`{"vlans":[{"id":%d}]}`, id) }
	macs := `{"entries":[{"vlan":1,"mac":"aa:bb:cc:dd:ee:ff","port":"gi1","type":"NET_DEV_MAC_TYPE_DYNAMIC"}]}`
	e.write(t, importCBS, ReadCBSVLANs, importGen, false, vlans(1))
	if rep := e.run(t); rep.Retry != 1 {
		t.Fatalf("first pass = %+v", rep)
	}
	var newest string
	for pass := range 5 {
		for i := range 4 {
			newest = e.write(t, importCBS, ReadCBSVLANs, importGen, false, vlans(2+pass*4+i))
			e.write(t, importCBS, ReadCBSMACTable, importGen, false, macs)
		}
		// Every second pass is due and fails again; the others back off.
		if pass%2 == 1 {
			*e.now = e.now.Add(importRetryMax)
		}
		rep := e.run(t)
		if rep.Pruned == 0 {
			t.Fatalf("pass %d = %+v, want pruned files", pass, rep)
		}
		for _, read := range []string{ReadCBSVLANs, ReadCBSMACTable} {
			if got := spoolOf(t, e.spool, importCBS, read); len(got) > MaxPendingPerRead {
				t.Fatalf("pass %d: %s keeps %d files, want at most %d", pass, read, len(got), MaxPendingPerRead)
			}
		}
	}
	if got := spoolOf(t, e.spool, importCBS, ReadCBSVLANs); got[len(got)-1] != newest {
		t.Fatalf("newest file %s not kept: %v", newest, got)
	}
	// A newer invalid file is rejected; the valid ones before it count.
	bad := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[],"evil":1}`)
	rep := e.run(t)
	if rep.Kept != 1 {
		t.Fatalf("pass with invalid newest = %+v", rep)
	}
	if got := spoolOf(t, e.spool, importCBS, ReadCBSVLANs); slices.Contains(got, bad) || len(got) > MaxPendingPerRead {
		t.Fatalf("spool after invalid newest = %v", got)
	}

	fs.mu.Lock()
	fs.fail = false
	fs.calls = nil
	fs.mu.Unlock()
	*e.now = e.now.Add(importRetryMax)
	rep = e.run(t)
	if rep.Retry != 0 || rep.Imported == 0 || rep.Imported > 2*MaxPendingPerRead {
		t.Fatalf("pass after recovery = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
	if len(fs.calls) > 2*MaxPendingPerRead {
		t.Fatalf("%d store calls after recovery, want at most %d", len(fs.calls), 2*MaxPendingPerRead)
	}
	ds, err := e.store.GetDataset(context.Background(), importCBS, netdevinventory.ReadVLANs)
	if p, _ := parseSpoolName(newest); err != nil || ds.ObservedAt.UnixMicro() != p.nanos/1000 {
		t.Fatalf("dataset = %+v, %v; want the newest read", ds, err)
	}
}

// TestImportKeepsOlderFilesUntilANewerOneIsValid: files of a failing
// device beyond the bound stay while no newer file was judged valid.
func TestImportKeepsOlderFilesUntilANewerOneIsValid(t *testing.T) {
	e := newImportEnv(t)
	fs := &failingStore{inner: e.store, fail: true}
	e.imp.Store = fs
	first := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	if rep := e.run(t); rep.Retry != 1 {
		t.Fatalf("first pass = %+v", rep)
	}
	// One newer valid file, then newer invalid ones: a pass judges at most
	// MaxPendingPerRead of them (all invalid, so rejected) and finds no
	// newer valid file, so the older ones stay.
	second := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":2}]}`)
	for range MaxPendingPerRead {
		e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[],"evil":1}`)
	}
	rep := e.run(t)
	if rep.Pruned != 0 || rep.Kept != MaxPendingPerRead {
		t.Fatalf("report = %+v, want %d kept and nothing pruned", rep, MaxPendingPerRead)
	}
	if got := spoolOf(t, e.spool, importCBS, ReadCBSVLANs); !slices.Equal(got, []string{first, second}) {
		t.Fatalf("spool = %v, want %s and %s", got, first, second)
	}
}

// TestImportOlderPolicyPartAfterNewerPartIsStored: a policy part observed
// before another part that was stored first (a clock step, or a read that
// failed transiently) is stored, not dropped as superseded; an older read
// of the same part still is.
func TestImportOlderPolicyPartAfterNewerPartIsStored(t *testing.T) {
	e := newImportEnv(t)
	payload := map[string]string{}
	for _, rp := range readPayloads {
		payload[rp.read] = rp.payload
	}
	e.spool.Now = fixedNow(testTime.Add(2 * time.Minute))
	e.write(t, importPANOS, ReadPANOSSecurityRules, importGen, false, payload[ReadPANOSSecurityRules])
	if rep := e.run(t); rep.Imported != 1 {
		t.Fatalf("rules pass = %+v", rep)
	}
	// Clock stepped back: zones observed before the stored rules.
	e.spool.Now = fixedNow(testTime.Add(time.Minute))
	e.write(t, importPANOS, ReadPANOSZones, importGen, false, payload[ReadPANOSZones])
	if rep := e.run(t); rep.Imported != 1 || rep.Replayed != 0 {
		t.Fatalf("zones pass = %+v, want imported", rep)
	}
	// A transiently unreadable NAT read is retried after the others went in.
	e.spool.Now = fixedNow(testTime.Add(90 * time.Second))
	nat := e.write(t, importPANOS, ReadPANOSNATRules, importGen, false, payload[ReadPANOSNATRules])
	e.spool.Now = fixedNow(testTime.Add(3 * time.Minute))
	e.write(t, importPANOS, ReadPANOSObjects, importGen, false, payload[ReadPANOSObjects])
	// The NAT file is moved aside for one pass: to the importer it is a
	// read that is not there yet (as after a transient read failure).
	natPath := filepath.Join(e.spool.Dir, nat)
	aside := filepath.Join(t.TempDir(), nat)
	if err := os.Rename(natPath, aside); err != nil {
		t.Fatal(err)
	}
	if rep := e.run(t); rep.Imported != 1 {
		t.Fatalf("objects pass = %+v", rep)
	}
	if err := os.Rename(aside, natPath); err != nil {
		t.Fatal(err)
	}
	if rep := e.run(t); rep.Imported != 1 || rep.Replayed != 0 {
		t.Fatalf("NAT retry pass = %+v, want imported", rep)
	}
	ds, err := e.store.GetDataset(context.Background(), importPANOS, netdevinventory.ReadFirewallPolicy)
	if err != nil || ds.State != netdevinventory.StateFresh {
		t.Fatalf("dataset = %+v, %v", ds, err)
	}
	// An older read of a part already stored is still superseded.
	e.spool.Now = fixedNow(testTime.Add(30 * time.Second))
	e.write(t, importPANOS, ReadPANOSZones, importGen, false, `{"zones":[]}`)
	if rep := e.run(t); rep.Replayed != 1 || rep.Imported != 0 {
		t.Fatalf("older zones pass = %+v, want superseded", rep)
	}
}

// TestImportUnmovedRecordOnlyRetriesRemoval: a rejected record that can
// neither be kept nor removed is never imported again; later passes only
// retry its removal.
func TestImportUnmovedRecordOnlyRetriesRemoval(t *testing.T) {
	e := newImportEnv(t)
	fs := &failingStore{inner: e.store}
	e.imp.Store = fs
	if err := os.WriteFile(filepath.Join(e.spool.Dir, KeptDirName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	discardErr := errors.New("remove failed")
	spoolDiscard = func(*Spool, context.Context, string) error { return discardErr }
	t.Cleanup(func() { spoolDiscard = (*Spool).Discard })

	name := e.write(t, "ghost-sw", ReadCBSVLANs, importGen, false, `{"vlans":[]}`)
	for pass := range 2 {
		rep := e.run(t)
		if rep.Failed != 1 || rep.Kept != 0 || !slices.Contains(rep.Errors, name+": keep_failed") {
			t.Fatalf("pass %d = %+v", pass, rep)
		}
		if left := spoolFiles(t, e.spool); !slices.Equal(left, []string{name}) {
			t.Fatalf("pass %d: spool = %v", pass, left)
		}
	}
	spoolDiscard = (*Spool).Discard
	rep := e.run(t)
	if rep.Kept != 1 || rep.Failed != 0 {
		t.Fatalf("pass after removal works = %+v", rep)
	}
	if left := spoolFiles(t, e.spool); len(left) != 0 {
		t.Fatalf("spool = %v, want empty", left)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.calls) != 1 {
		t.Fatalf("store called %d times, want once (no import retry)", len(fs.calls))
	}
}

func TestMoveToKeptRefusesWhenFull(t *testing.T) {
	e := newImportEnv(t)
	keptDir := filepath.Join(e.spool.Dir, KeptDirName)
	if err := os.Mkdir(keptDir, keptDirMode); err != nil {
		t.Fatal(err)
	}
	for i := range 2 * MaxKeptFiles {
		if err := os.WriteFile(filepath.Join(keptDir, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	name := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[]}`)
	if err := e.spool.moveToKept(context.Background(), name, ReasonInvalidPayload); !errors.Is(err, ErrKeptFull) {
		t.Fatalf("err = %v, want ErrKeptFull", err)
	}
	if left := spoolFiles(t, e.spool); !slices.Equal(left, []string{name}) {
		t.Fatalf("spool = %v, want the record left in place", left)
	}
}

// TestKeptReasonFileIsReplaced: a reason file left by an interrupted
// earlier attempt is overwritten with the current reason.
func TestKeptReasonFileIsReplaced(t *testing.T) {
	e := newImportEnv(t)
	name := e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[],"evil":1}`)
	keptDir := filepath.Join(e.spool.Dir, KeptDirName)
	if err := os.Mkdir(keptDir, keptDirMode); err != nil {
		t.Fatal(err)
	}
	reasonPath := filepath.Join(keptDir, name+keptReasonSuffix)
	if err := os.WriteFile(reasonPath, []byte("reason: "+ReasonUnknownDevice+"\n"), keptReasonMode); err != nil {
		t.Fatal(err)
	}
	if rep := e.run(t); rep.Kept != 1 {
		t.Fatalf("report = %+v", rep)
	}
	got, err := os.ReadFile(reasonPath)
	if err != nil || string(got) != "reason: "+ReasonInvalidPayload+"\n" {
		t.Fatalf("reason file = %q, %v; want %s", got, err, ReasonInvalidPayload)
	}
}

// TestImportDefersBeyondMaxRecordsPerRun: one pass stores at most
// MaxRecordsPerRun records; the rest wait for the next pass.
func TestImportDefersBeyondMaxRecordsPerRun(t *testing.T) {
	e := newImportEnv(t)
	st := &okStore{}
	e.imp.Store = st
	for range MaxRecordsPerRun + 2 {
		e.write(t, importCBS, ReadCBSVLANs, importGen, false, `{"vlans":[{"id":1}]}`)
	}
	rep := e.run(t)
	if rep.Imported != MaxRecordsPerRun || rep.Deferred != 2 {
		t.Fatalf("first pass = %+v", rep)
	}
	rep = e.run(t)
	if rep.Imported != 2 || rep.Deferred != 0 {
		t.Fatalf("second pass = %+v", rep)
	}
	if st.calls != MaxRecordsPerRun+2 {
		t.Fatalf("store calls = %d", st.calls)
	}
}
