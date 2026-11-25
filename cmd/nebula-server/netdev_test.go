// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
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

// netdevHTTP is the HTTP chain of the server for the netdev pages: the
// security middleware, the real session check (auth.Wrap) and the pages
// mounted by mountNetDevPages with the admin rule of the server. Its admin
// session belongs to "admin", its non-admin session to "bob"; the admin rule
// of the wiring answers true for "admin" only.
type netdevHTTP struct {
	srv   *http.Server
	admin string // token of the admin's web session
	user  string // token of a signed-in non-admin's web session
}

// newNetDevHTTP mounts the netdev pages of e on the server chain.
func newNetDevHTTP(t *testing.T, e *netdevTestEnv) *netdevHTTP {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	isAdmin := func(ctx context.Context) bool {
		s, ok := auth.SessionFrom(ctx)
		return ok && s.UserName == "admin"
	}
	mux := http.NewServeMux()
	d := serverDeps{db: e.db, log: log, isAdmin: isAdmin}
	if err := mountNetDevPages(d, testUIOptions(e.clock), mux, e.clock); err != nil {
		t.Fatalf("mountNetDevPages: %v", err)
	}
	sessions := auth.NewStore(e.db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	admin, _, err := sessions.Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatalf("admin session: %v", err)
	}
	user, _, err := sessions.Create(context.Background(), "cred-2", "bob")
	if err != nil {
		t.Fatalf("user session: %v", err)
	}
	srv, err := webServer(swOrigin, login, mux, nil)
	if err != nil {
		t.Fatalf("webServer: %v", err)
	}
	return &netdevHTTP{srv: srv, admin: admin, user: user}
}

// get sends GET path with the web session token; an empty token sends no
// cookie.
func (h *netdevHTTP) get(path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, swOrigin+path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	rec := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(rec, req)
	return rec
}

// TestNetDevPagesAnswerOnlyAdmins: a signed-in non-admin is refused on every
// netdev page with 403, and an admin gets the list. The 403 comes from the
// admin rule of the wiring, so a rule that always answered true would fail.
func TestNetDevPagesAnswerOnlyAdmins(t *testing.T) {
	e := newNetDevTestEnv(t)
	h := newNetDevHTTP(t, e)
	for _, path := range []string{"/netdev", "/netdev/sw1", "/netdev/sw1/firewall"} {
		if rec := h.get(path, h.user); rec.Code != http.StatusForbidden {
			t.Errorf("GET %s as a non-admin = %d, want 403", path, rec.Code)
		}
		if rec := h.get(path, ""); rec.Code == http.StatusOK {
			t.Errorf("GET %s without a session = 200, want it refused", path)
		}
	}
	if rec := h.get("/netdev", h.admin); rec.Code != http.StatusOK {
		t.Fatalf("GET /netdev as the admin = %d, want 200", rec.Code)
	}
}

// TestNetDevImportedDatasetShowsOnPages: a metadata record and a dataset of
// the same device, imported in one pass, show on the list and on the device
// page. The device row is marked as reported by the collector and the dataset
// shows its state and its content.
func TestNetDevImportedDatasetShowsOnPages(t *testing.T) {
	e := newNetDevTestEnv(t)
	e.publish(t, "sw1", netdevcollect.ReadDeviceMetadata, 3,
		`{"device_id":"sw1","family":"cbs","label":"Core switch","trust_generation":3,"blocked":false,"block_reason":""}`)
	e.publish(t, "sw1", netdevcollect.ReadCBSVersion, 3,
		`{"model":"CBS350-24P","firmware":"3.4.0.17","serial":"PSZ1"}`)
	rep, err := e.imp.imp.Run(context.Background())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rep.MetadataWritten != 1 || rep.Imported != 1 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want the metadata written and the dataset imported", rep)
	}
	h := newNetDevHTTP(t, e)

	list := h.get("/netdev", h.admin)
	if list.Code != http.StatusOK {
		t.Fatalf("GET /netdev = %d, want 200", list.Code)
	}
	body := list.Body.String()
	if !strings.Contains(body, "Core switch") || !strings.Contains(body, netdevReportedBadge) {
		t.Fatal("list does not show the imported device as reported by the collector")
	}
	if !strings.Contains(body, string(netdevinventory.ReadFacts)+": fresh") {
		t.Fatalf("list does not show the imported dataset as fresh")
	}

	detail := h.get("/netdev/sw1", h.admin)
	if detail.Code != http.StatusOK {
		t.Fatalf("GET /netdev/sw1 = %d, want 200", detail.Code)
	}
	page := detail.Body.String()
	if !strings.Contains(page, netdevReportedBadge) {
		t.Fatal("device page does not mark the device as reported by the collector")
	}
	if !strings.Contains(page, "CBS350-24P") {
		t.Fatal("device page does not show the imported dataset's model")
	}
}

// TestNetDevImportOnceLogsOutage: while the spool is missing, every pass fails
// and the importer logs the outage once, not at each retry.
func TestNetDevImportOnceLogsOutage(t *testing.T) {
	e := newNetDevTestEnv(t)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	n := newNetDevImport(e.db, filepath.Join(t.TempDir(), "missing"), log, e.clock)

	for range 3 {
		n.pass(context.Background())
	}
	if got := strings.Count(logs.String(), "netdev spool unavailable"); got != 1 {
		t.Fatalf("outage logged %d times, want once", got)
	}
}

// TestNetDevImportLogsOutageAgainAfterRecovery: a pass that succeeds ends the
// outage, so the next outage is logged again, and only once.
func TestNetDevImportLogsOutageAgainAfterRecovery(t *testing.T) {
	e := newNetDevTestEnv(t)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	root := filepath.Join(t.TempDir(), "netdev")
	n := newNetDevImport(e.db, root, log, e.clock)
	outages := func() int { return strings.Count(logs.String(), "netdev spool unavailable") }

	n.pass(context.Background())
	n.pass(context.Background())
	if got := outages(); got != 1 {
		t.Fatalf("first outage logged %d times, want once", got)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("create spool: %v", err)
	}
	// The importer reads only a spool in the collector's mode (setgid group
	// directory), so the test gives it that mode as the collector would.
	if err := os.Chmod(root, os.ModeDir|0o770|os.ModeSetgid); err != nil {
		t.Fatalf("chmod spool: %v", err)
	}
	n.pass(context.Background())
	if n.unavailable {
		t.Fatal("a successful pass did not end the outage")
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("remove spool: %v", err)
	}
	n.pass(context.Background())
	n.pass(context.Background())
	if got := outages(); got != 2 {
		t.Fatalf("second outage logged %d times in total, want 2", got)
	}
}

// TestNetDevImportMissingSpoolIsUnavailable: a spool directory that does not
// exist is an error of the pass (the spool is not available); it is not a
// fault of any record and it stores nothing.
func TestNetDevImportMissingSpoolIsUnavailable(t *testing.T) {
	e := newNetDevTestEnv(t)
	n := newNetDevImport(e.db, filepath.Join(t.TempDir(), "missing"), slog.New(slog.DiscardHandler), e.clock)
	rep, err := n.imp.Run(context.Background())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Run = %v, want a not-exist error for the missing spool", err)
	}
	if rep.Kept != 0 || rep.MetadataWritten != 0 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want nothing stored or kept", rep)
	}
}

// TestNetDevPagesNotMountedWithoutAdminRule: without the admin rule no
// network device route exists, so the page answers 404 behind the session.
func TestNetDevPagesNotMountedWithoutAdminRule(t *testing.T) {
	e := newNetDevTestEnv(t)
	mux := http.NewServeMux()
	d := serverDeps{db: e.db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := mountNetDevPages(d, testUIOptions(e.clock), mux, e.clock); err != nil {
		t.Fatalf("mountNetDevPages: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/netdev", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /netdev = %d, want 404 without the admin rule", rec.Code)
	}
}

// netdevReportedBadge is the marker of a row written from a collector report
// (internal/web/ui, web/templates/netdev.html).
const netdevReportedBadge = `<span class="badge badge--ok">reported by collector</span>`

// testUIOptions are the ui.Options the netdev tests build the pages with; the
// pages read the clock now.
func testUIOptions(now func() time.Time) ui.Options {
	return ui.Options{PublicOrigin: swOrigin, Now: now}
}
