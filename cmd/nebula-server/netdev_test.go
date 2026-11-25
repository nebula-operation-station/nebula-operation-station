// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// netdevTestNow is the clock of the netdev wiring tests.
var netdevTestNow = time.Date(2026, time.November, 25, 10, 0, 0, 0, time.UTC)

// netdevTestEnv is the server database and spool of one test.
type netdevTestEnv struct {
	db    *sql.DB
	root  string
	now   time.Time
	clock func() time.Time
	imp   *netdevImport
}

// newNetDevTestEnv opens a server database and an empty spool in a temporary
// directory. The importer runs on the test clock.
func newNetDevTestEnv(t *testing.T) *netdevTestEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	e := &netdevTestEnv{db: db, root: filepath.Join(t.TempDir(), "netdev"), now: netdevTestNow}
	// The collector creates its spool; the test creates the same directory.
	if err := os.Mkdir(e.root, 0o700); err != nil {
		t.Fatalf("create spool: %v", err)
	}
	e.clock = func() time.Time { return e.now }
	e.imp = newNetDevImport(db, e.root, slog.New(slog.NewTextHandler(io.Discard, nil)), e.clock)
	return e
}

// publish writes one spool record of device and read through the collector's
// spool writer, as the collector does.
func (e *netdevTestEnv) publish(t *testing.T, device, read string, gen uint64, payload string) {
	t.Helper()
	sp := &netdevcollect.Spool{Dir: e.root, Now: e.clock}
	if _, err := sp.Write(context.Background(), device, read, gen, false, []byte(payload)); err != nil {
		t.Fatalf("spool write %s/%s: %v", device, read, err)
	}
}

// TestNetDevImportWritesDeviceRowFromMetadata: a spooled metadata record of a
// new device becomes a collector-reported device row, so the pages show the
// device at once.
func TestNetDevImportWritesDeviceRowFromMetadata(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.publish(t, "sw1", netdevcollect.ReadDeviceMetadata, 3,
		`{"device_id":"sw1","family":"cbs","label":"Core switch","trust_generation":3,"blocked":false,"block_reason":""}`)

	rep, err := e.imp.imp.Run(context.Background())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rep.MetadataWritten != 1 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want one metadata row written", rep)
	}
	d, err := netdevinventory.NewWithNow(e.db, e.clock).GetDevice(context.Background(), "sw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.Label != "Core switch" || d.Origin != netdevinventory.OriginCollectorReported {
		t.Fatalf("device = %+v, want the reported label and origin", d)
	}
}

// TestNetDevImportRejectsDatasetOfUnknownDevice: a dataset of a device the
// inventory does not know is kept with its reason and creates no row.
func TestNetDevImportRejectsDatasetOfUnknownDevice(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.publish(t, "ghost", netdevcollect.ReadCBSVersion, 3,
		`{"model":"CBS350-24P","firmware":"3.4.0.17","serial":"PSZ1"}`)

	rep, err := e.imp.imp.Run(context.Background())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rep.Kept != 1 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want the dataset kept", rep)
	}
	_, err = netdevinventory.NewWithNow(e.db, e.clock).GetDevice(context.Background(), "ghost")
	if !errors.Is(err, netdevinventory.ErrDeviceNotFound) {
		t.Fatalf("GetDevice(ghost) = %v, want ErrDeviceNotFound", err)
	}
}

// TestNetDevStaleDeviceKeepsItsRow: a device the collector has not reported
// for DeviceReportStaleAfter reads as stale and its row stays.
func TestNetDevStaleDeviceKeepsItsRow(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.publish(t, "sw1", netdevcollect.ReadDeviceMetadata, 3,
		`{"device_id":"sw1","family":"cbs","label":"Core switch","trust_generation":3,"blocked":false,"block_reason":""}`)
	if _, err := e.imp.imp.Run(context.Background()); err != nil {
		t.Fatalf("import: %v", err)
	}

	later := netdevTestNow.Add(netdevinventory.DeviceReportStaleAfter + time.Minute)
	d, err := netdevinventory.NewWithNow(e.db, func() time.Time { return later }).GetDevice(context.Background(), "sw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.State != netdevinventory.DeviceStale {
		t.Fatalf("state = %v, want stale", d.State)
	}
	if d.Origin != netdevinventory.OriginCollectorReported || d.Label != "Core switch" {
		t.Fatalf("stale device = %+v, want its row unchanged", d)
	}
}

// TestNetDevPagesAnswerOnlyAdmins: the pages are mounted over the server
// database; a request without an admin session is refused, not answered
// with an empty list.
func TestNetDevPagesAnswerOnlyAdmins(t *testing.T) {
	e := newNetDevTestEnv(t)
	mux := http.NewServeMux()
	d := serverDeps{db: e.db, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		isAdmin: func(context.Context) bool { return false }}
	if err := mountNetDevPages(d, testUIOptions(), mux); err != nil {
		t.Fatalf("mountNetDevPages: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/netdev", "/netdev/sw1", "/netdev/sw1/firewall"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403 without an admin session", path, res.StatusCode)
		}
	}
}

// TestNetDevPagesNotMountedWithoutAdminRule: without the admin rule no
// network device route exists, so the page answers 404 behind the session.
func TestNetDevPagesNotMountedWithoutAdminRule(t *testing.T) {
	e := newNetDevTestEnv(t)
	mux := http.NewServeMux()
	d := serverDeps{db: e.db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := mountNetDevPages(d, testUIOptions(), mux); err != nil {
		t.Fatalf("mountNetDevPages: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/netdev", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /netdev = %d, want 404 without the admin rule", rec.Code)
	}
}

// testUIOptions are the ui.Options the netdev tests build the pages with.
func testUIOptions() ui.Options {
	return ui.Options{PublicOrigin: "https://nebula.example.org", Now: func() time.Time { return netdevTestNow }}
}
