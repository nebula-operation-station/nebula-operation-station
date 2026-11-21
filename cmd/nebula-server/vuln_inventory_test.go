// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

const invTestHost = "web"

var invTestAt = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

// invEnv is a migrated server.db with the inventory service on it. The
// executions service reads the core.facts results from the same database.
type invEnv struct {
	db  *sql.DB
	svc *vulnInventoryService
	log *bytes.Buffer
	ops *executions.Service
}

func newInvEnv(t *testing.T) *invEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	ops := executions.New(context.Background(), nil, db, nil, log)
	svc, err := newVulnInventoryService(db, ops, log)
	if err != nil {
		t.Fatal(err)
	}
	return &invEnv{db: db, svc: svc, log: buf, ops: ops}
}

// factsBase is when the core.facts results of these tests finish by default:
// an hour after every package list the tests store, so that the release is
// never older than the list. insertFacts adds n seconds to it, which keeps
// the order of n.
var factsBase = invTestAt.Add(time.Hour)

// insertFacts stores a successful core.facts result of host, finished at
// factsBase plus n seconds. Every call needs its own n, which makes the
// execution ID unique.
func (e *invEnv) insertFacts(t *testing.T, n int, host string, result []byte) {
	t.Helper()
	e.insertFactsAt(t, n, host, result, factsBase.Add(time.Duration(n)*time.Second))
}

// insertFactsAt stores a successful core.facts result of host that finished
// at finished. n makes the execution ID unique.
func (e *invEnv) insertFactsAt(t *testing.T, n int, host string, result []byte, finished time.Time) {
	t.Helper()
	id := fmt.Sprintf("facts-%030d", n) // executions.id is 36 characters
	at := finished.Unix()
	if _, err := e.db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at)
		VALUES (?, 'core.facts', '1.0.0', ?, 'LOW', 'finished', 0, 60, 'axel', ?, ?)`, id, strings.Repeat("a", 64), at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:x', 'nebula-default', '[]', 'finished', 'success', ?, ?, ?)`, id, host, result, at, at); err != nil {
		t.Fatal(err)
	}
}

// staticFacts is a core.facts source that returns result, finished at at,
// and runs onCall first (it may cancel the parent context or close the
// database to simulate a shutdown or a failing store).
type staticFacts struct {
	result []byte
	at     time.Time
	onCall func()
}

func (s staticFacts) LastResult(context.Context, string, string) ([]byte, time.Time, bool, error) {
	if s.onCall != nil {
		s.onCall()
	}
	return s.result, s.at, true, nil
}

// factsResult is a core.facts 1.x document with the given os-release text.
func factsResult(t *testing.T, osRelease string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"os_release": base64.StdEncoding.EncodeToString([]byte(osRelease)),
		"uname":      "", "hostname": "", "uptime": "", "proxmox": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const debian12Release = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"

// installedEnvelope wraps a nos-installed-v1 text in the 1.1.0 JSON result.
func installedEnvelope(t *testing.T, text string, truncated bool) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"format": osdebian.InstalledFormat, "text": text, "truncated": truncated})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// debian12Text is the nos-installed-v1 text of the Debian 12 fixture.
func debian12Text(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../internal/executions/osdebian/testdata/installed/debian12.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// latestRead reads the newest stored read of host.
func (e *invEnv) latestRead(t *testing.T, host string) vulninventory.Read {
	t.Helper()
	r, err := e.svc.store.Latest(context.Background(), host)
	if err != nil {
		t.Fatalf("latest read of %s: %v", host, err)
	}
	return r
}

func TestInstalledResultIsStoredComplete(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 1, invTestHost, factsResult(t, debian12Release))
	result := installedEnvelope(t, debian12Text(t), false)

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-install-1", invTestAt, result)

	r := e.latestRead(t, invTestHost)
	if !r.Complete || r.Reason != "" {
		t.Fatalf("read complete=%v reason=%q, want complete", r.Complete, r.Reason)
	}
	if r.Ecosystem != "debian:bookworm" {
		t.Fatalf("ecosystem = %q, want debian:bookworm", r.Ecosystem)
	}
	if r.Kernel.Release != "6.1.0-26-amd64" {
		t.Fatalf("kernel release = %q, want the running kernel", r.Kernel.Release)
	}
	if r.ExecutionID != "exec-install-1" || !r.ReadAt.Equal(invTestAt) {
		t.Fatalf("read execution %q at %v", r.ExecutionID, r.ReadAt)
	}
	found := false
	for _, c := range r.Components {
		if c.Source == "jansson" && c.SourceVersion == "2.14-2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("jansson with its source version not stored: %+v", r.Components)
	}
	logged := e.log.String()
	if !strings.Contains(logged, "vuln_inventory_read_stored") || !strings.Contains(logged, "complete=true") {
		t.Fatalf("no audit line for the stored read: %s", logged)
	}
}

func TestInstalledResultWithoutFactsIsStoredIncomplete(t *testing.T) {
	e := newInvEnv(t)
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-install-2", invTestAt, installedEnvelope(t, debian12Text(t), false))

	r := e.latestRead(t, invTestHost)
	if r.Complete {
		t.Fatalf("read without core.facts is complete")
	}
	if r.Reason != vulninventory.ReasonNoEcosystem {
		t.Fatalf("reason = %q, want %q", r.Reason, vulninventory.ReasonNoEcosystem)
	}
	if r.Ecosystem != "" || len(r.Components) != 0 {
		t.Fatalf("read stored ecosystem %q and %d components without a release", r.Ecosystem, len(r.Components))
	}
}

func TestTruncatedInstalledResultIsStoredIncomplete(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 2, invTestHost, factsResult(t, debian12Release))

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-install-3", invTestAt, installedEnvelope(t, debian12Text(t), true))

	r := e.latestRead(t, invTestHost)
	if r.Complete {
		t.Fatalf("truncated result stored as complete")
	}
	if r.Reason != osdebian.ReasonTruncated {
		t.Fatalf("reason = %q, want %q", r.Reason, osdebian.ReasonTruncated)
	}
}

func TestNonJSONInstalledResultIsStoredIncompleteWithFormatReason(t *testing.T) {
	tests := []struct {
		name   string
		result []byte
	}{
		{"plain text result", []byte(debian12Text(t))},
		{"not JSON", []byte("{not json")},
		{"empty", nil},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newInvEnv(t)
			e.insertFacts(t, 3+i, invTestHost, factsResult(t, debian12Release))

			e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-install-4", invTestAt, tc.result)

			r := e.latestRead(t, invTestHost)
			if r.Complete {
				t.Fatalf("unreadable result stored as complete")
			}
			if r.Reason != osdebian.ReasonResultFormat {
				t.Fatalf("reason = %q, want %q", r.Reason, osdebian.ReasonResultFormat)
			}
		})
	}
}

// TestInstalledResultWithFactsOlderThanListIsStoredIncomplete: the release
// must come from a core.facts run at least as recent as the list. Older facts
// give an incomplete read with no components and no ecosystem.
func TestInstalledResultWithFactsOlderThanListIsStoredIncomplete(t *testing.T) {
	e := newInvEnv(t)
	e.insertFactsAt(t, 20, invTestHost, factsResult(t, debian12Release), invTestAt.Add(-time.Minute))

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-stale-facts", invTestAt, installedEnvelope(t, debian12Text(t), false))

	r := e.latestRead(t, invTestHost)
	if r.Complete || r.Reason != vulninventory.ReasonFactsOlder || r.ExecutionID != "exec-stale-facts" {
		t.Fatalf("latest read complete=%v reason=%q execution=%q, want facts-older marker", r.Complete, r.Reason, r.ExecutionID)
	}
	if r.Ecosystem != "" || len(r.Components) != 0 {
		t.Fatalf("read stored ecosystem %q and %d components from older facts", r.Ecosystem, len(r.Components))
	}
}

// TestFactsAtOrAfterListGiveCompleteRead: facts from the same run time as
// the list (same second) or newer are current, so the read is complete.
func TestFactsAtOrAfterListGiveCompleteRead(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
	}{
		{"same second", invTestAt},
		{"newer", invTestAt.Add(time.Minute)},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newInvEnv(t)
			e.insertFactsAt(t, 21+i, invTestHost, factsResult(t, debian12Release), tc.at)

			e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-current", invTestAt, installedEnvelope(t, debian12Text(t), false))

			r := e.latestRead(t, invTestHost)
			if !r.Complete || r.Ecosystem != "debian:bookworm" {
				t.Fatalf("read complete=%v ecosystem=%q reason=%q, want complete debian:bookworm", r.Complete, r.Ecosystem, r.Reason)
			}
		})
	}
}

// TestUpgradedHostIsNotMatchedWithOldRelease: a host upgraded from bookworm
// to trixie whose core.facts has not run since keeps its list incomplete;
// the old release is never used for the new package list. A fresh core.facts
// (trixie) makes the next list complete under debian:trixie.
func TestUpgradedHostIsNotMatchedWithOldRelease(t *testing.T) {
	const trixieRelease = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n"
	e := newInvEnv(t)
	// The bookworm facts ran before the upgrade; the trixie list follows.
	e.insertFactsAt(t, 22, invTestHost, factsResult(t, debian12Release), invTestAt.Add(-time.Hour))

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-trixie-1", invTestAt, installedEnvelope(t, debian12Text(t), false))
	r := e.latestRead(t, invTestHost)
	if r.Complete || r.Reason != vulninventory.ReasonFactsOlder || r.Ecosystem == "debian:bookworm" {
		t.Fatalf("list after upgrade: complete=%v reason=%q ecosystem=%q, want facts-older marker", r.Complete, r.Reason, r.Ecosystem)
	}

	// Fresh trixie facts, run at the time of the next list.
	e.insertFactsAt(t, 23, invTestHost, factsResult(t, trixieRelease), invTestAt.Add(2*time.Minute))
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-trixie-2", invTestAt.Add(2*time.Minute), installedEnvelope(t, debian12Text(t), false))
	r = e.latestRead(t, invTestHost)
	if r.Ecosystem != "debian:trixie" {
		t.Fatalf("ecosystem after fresh facts = %q (complete=%v reason=%q), want debian:trixie", r.Ecosystem, r.Complete, r.Reason)
	}
}

// TestShutdownWritesNoMarker: when the server shuts down (the parent context
// is cancelled) the observer writes nothing: no refusal or lookup marker
// replaces the older complete read, and the cancellation is logged by class.
func TestShutdownWritesNoMarker(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 24, invTestHost, factsResult(t, debian12Release))
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-before", invTestAt, installedEnvelope(t, debian12Text(t), false))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.svc.ObserveInstalled(ctx, invTestHost, "exec-shutdown", invTestAt.Add(time.Minute), installedEnvelope(t, hostileText(), false))

	if r := e.latestRead(t, invTestHost); r.ExecutionID != "exec-before" || !r.Complete {
		t.Fatalf("latest read %q complete=%v after shutdown, want exec-before complete", r.ExecutionID, r.Complete)
	}
	logged := e.log.String()
	if !strings.Contains(logged, "error_class=canceled") {
		t.Fatalf("shutdown not logged by class: %s", logged)
	}
	if strings.Contains(logged, "error_class=invalid_read") || strings.Contains(logged, "error_class=limit") {
		t.Fatalf("shutdown logged as a store refusal: %s", logged)
	}
}

// TestCancelledStoreWriteIsNotARefusal: a context cancelled during the store
// write (shutdown) is not recorded as a refusal of the list: no marker, the
// older complete read stays the latest, and the error is logged as canceled.
func TestCancelledStoreWriteIsNotARefusal(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 25, invTestHost, factsResult(t, debian12Release))
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-good-2", invTestAt, installedEnvelope(t, debian12Text(t), false))

	ctx, cancel := context.WithCancel(context.Background())
	e.svc.facts = staticFacts{result: factsResult(t, debian12Release), at: factsBase, onCall: cancel}
	e.svc.ObserveInstalled(ctx, invTestHost, "exec-cancel", invTestAt.Add(time.Minute), installedEnvelope(t, debian12Text(t), false))

	if r := e.latestRead(t, invTestHost); r.ExecutionID != "exec-good-2" || !r.Complete {
		t.Fatalf("latest read %q complete=%v reason=%q, want exec-good-2 complete", r.ExecutionID, r.Complete, r.Reason)
	}
	logged := e.log.String()
	if !strings.Contains(logged, "error_class=canceled") || strings.Contains(logged, "error_class=invalid_read") {
		t.Fatalf("cancelled store write not logged as canceled: %s", logged)
	}
}

// TestStoreOutageIsNotRecordedAsRefusal: a store error that is not a limit
// or format refusal (here a closed database, as with a lost connection or a
// busy store) is logged as a store error, never as a refusal of the list.
func TestStoreOutageIsNotRecordedAsRefusal(t *testing.T) {
	e := newInvEnv(t)
	e.svc.facts = staticFacts{result: factsResult(t, debian12Release), at: factsBase, onCall: func() {
		if err := e.db.Close(); err != nil {
			t.Fatal(err)
		}
	}}

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-outage", invTestAt, installedEnvelope(t, debian12Text(t), false))

	logged := e.log.String()
	if !strings.Contains(logged, "error_class=store") {
		t.Fatalf("store outage not logged by class: %s", logged)
	}
	if strings.Contains(logged, "error_class=invalid_read") || strings.Contains(logged, "error_class=limit") {
		t.Fatalf("store outage logged as a refusal: %s", logged)
	}
}

// TestInventoryStoreFailureIsLoggedWithoutResultText: a read the store
// refuses (here a host ID over the store's limit) is logged by class only,
// and the run is not failed (ObserveInstalled returns nothing).
func TestInventoryStoreFailureIsLoggedWithoutResultText(t *testing.T) {
	e := newInvEnv(t)
	longHost := strings.Repeat("h", 200)
	e.insertFacts(t, 5, longHost, factsResult(t, debian12Release))

	e.svc.ObserveInstalled(context.Background(), longHost, "exec-install-5", invTestAt, installedEnvelope(t, debian12Text(t), false))

	logged := e.log.String()
	if !strings.Contains(logged, "vulnerability inventory: store read") || !strings.Contains(logged, "error_class=invalid_read") {
		t.Fatalf("store failure not logged by class: %s", logged)
	}
	for _, secret := range []string{"libjansson4", "jansson", "6.1.0-26-amd64", "installed"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log contains result text %q: %s", secret, logged)
		}
	}
}

// TestInventoryLookupFailureIsLoggedByClass: a closed database fails the
// core.facts lookup; the observer logs the class without result text and
// does not panic, even though no marker can be written to a closed database.
func TestInventoryLookupFailureIsLoggedByClass(t *testing.T) {
	e := newInvEnv(t)
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-install-6", invTestAt, installedEnvelope(t, debian12Text(t), false))

	logged := e.log.String()
	if !strings.Contains(logged, "error_class=lookup") {
		t.Fatalf("lookup failure not logged by class: %s", logged)
	}
	if strings.Contains(logged, "libjansson4") {
		t.Fatalf("log contains result text: %s", logged)
	}
}

// failingFacts is a core.facts source whose lookup always fails.
type failingFacts struct{}

func (failingFacts) LastResult(context.Context, string, string) ([]byte, time.Time, bool, error) {
	return nil, time.Time{}, false, errors.New("lookup refused")
}

// TestInventoryLookupFailureMarksHostPartial: when the release lookup fails,
// the newest list is stored as a partial read with no components, so the
// older complete read is no longer the latest (fail closed), but it stays
// the last complete read.
func TestInventoryLookupFailureMarksHostPartial(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 7, invTestHost, factsResult(t, debian12Release))
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-old", invTestAt, installedEnvelope(t, debian12Text(t), false))
	if r := e.latestRead(t, invTestHost); !r.Complete {
		t.Fatalf("setup: first read not complete: %q", r.Reason)
	}

	e.svc.facts = failingFacts{}
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-lookup", invTestAt.Add(time.Minute), installedEnvelope(t, debian12Text(t), false))

	r := e.latestRead(t, invTestHost)
	if r.Complete || r.Reason != vulninventory.ReasonLookupFailed || r.ExecutionID != "exec-lookup" {
		t.Fatalf("latest read complete=%v reason=%q execution=%q, want partial lookup marker of exec-lookup", r.Complete, r.Reason, r.ExecutionID)
	}
	if len(r.Components) != 0 {
		t.Fatalf("partial marker stores %d components", len(r.Components))
	}
	last, err := e.svc.store.LastComplete(context.Background(), invTestHost)
	if err != nil || last.ExecutionID != "exec-old" {
		t.Fatalf("last complete = %q, %v; want exec-old", last.ExecutionID, err)
	}
	if !strings.Contains(e.log.String(), "error_class=lookup") {
		t.Fatalf("lookup failure not logged by class: %s", e.log.String())
	}
}

// hostileVersion is a binary version the parser accepts (an epoch and a
// 128-character upstream version: 139 bytes) that the store refuses, because
// its version field is limited to 128 bytes.
// The parser allows an epoch of up to 10 digits and 128 upstream characters;
// the store's version field is 128 bytes in total, so this is accepted by the
// parser and refused by the store.
var hostileVersion = "1234567890:" + strings.Repeat("a", 128)

// hostileText is a nos-installed-v1 text whose one package has hostileVersion.
func hostileText() string {
	return "nos-installed-v1\nP\tinstalled\tlibjansson4\tamd64\t" + hostileVersion + "\tjansson\t2.14-2\t\t.\nK\t6.1.0-26-amd64\t#1 SMP\nEND\t1\n"
}

// TestInventoryStoreRefusalMarksHostPartial: hostile package content that the
// store refuses (a field over its limit) leaves a partial marker as the latest
// read; the older complete read remains the last complete one. The refused
// content is not logged.
func TestInventoryStoreRefusalMarksHostPartial(t *testing.T) {
	e := newInvEnv(t)
	e.insertFacts(t, 8, invTestHost, factsResult(t, debian12Release))
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-good", invTestAt, installedEnvelope(t, debian12Text(t), false))

	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-hostile", invTestAt.Add(time.Minute), installedEnvelope(t, hostileText(), false))

	r := e.latestRead(t, invTestHost)
	if r.Complete || r.Reason != vulninventory.ReasonRefused || r.ExecutionID != "exec-hostile" {
		t.Fatalf("latest read complete=%v reason=%q execution=%q, want refused marker of exec-hostile", r.Complete, r.Reason, r.ExecutionID)
	}
	if len(r.Components) != 0 {
		t.Fatalf("refused marker stores %d components", len(r.Components))
	}
	last, err := e.svc.store.LastComplete(context.Background(), invTestHost)
	if err != nil || last.ExecutionID != "exec-good" {
		t.Fatalf("last complete = %q, %v; want exec-good", last.ExecutionID, err)
	}
	logged := e.log.String()
	if !strings.Contains(logged, "error_class=invalid_read") {
		t.Fatalf("store refusal not logged by class: %s", logged)
	}
	for _, secret := range []string{hostileVersion, "1234567890:", "libjansson4"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log contains the refused package content %q: %s", secret, logged)
		}
	}
}

// TestInventoryWorkIsBoundedByTimeout: the release lookup runs under the
// observeTimeout deadline, so a stuck database cannot hold the run's finish
// path for longer.
func TestInventoryWorkIsBoundedByTimeout(t *testing.T) {
	e := newInvEnv(t)
	rec := &deadlineFacts{}
	e.svc.facts = rec
	e.svc.ObserveInstalled(context.Background(), invTestHost, "exec-deadline", invTestAt, installedEnvelope(t, debian12Text(t), false))

	if !rec.hasDeadline {
		t.Fatalf("release lookup has no deadline")
	}
	if left := time.Until(rec.deadline); left > observeTimeout || left <= 0 {
		t.Fatalf("deadline in %v, want within %v", left, observeTimeout)
	}
}

// deadlineFacts records the deadline of the lookup context and finds nothing.
type deadlineFacts struct {
	hasDeadline bool
	deadline    time.Time
}

func (d *deadlineFacts) LastResult(ctx context.Context, _, _ string) ([]byte, time.Time, bool, error) {
	d.deadline, d.hasDeadline = ctx.Deadline()
	return nil, time.Time{}, false, nil
}

// srcHost is the inventory host of the export tests. Its display name and
// address must never reach the export (ADR 0011 D3).
const (
	srcHost    = "srv-a"
	srcName    = "srv-a.lab.example"
	srcAddress = "192.0.2.44"
)

// srcEnv is the vulnerability API of newVTEnv, with the export served from
// the real inventory store and the stored reads of the same database.
type srcEnv struct {
	*vtEnv
	hosts *inventory.Store
	inv   vulnInventory
}

func newSrcEnv(t *testing.T) *srcEnv {
	t.Helper()
	e := newVTEnv(t)
	// vulninventory stamps TakenAt and checks read times with its own
	// package clock, which is the real clock. The test clock follows the
	// real clock, so reads and TakenAt agree and no snapshot is "taken after
	// the clock". Tests that move the clock use Add, as before.
	e.clk.followReal()
	hosts := inventory.NewWithNow(e.db, e.clk.Now)
	inv, err := newVulnInventory(e.db, hosts, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vtToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"192.0.2.10"}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{tok}}, e.svc, inv, vtAgentCfg{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || vh == nil {
		t.Fatalf("newVulnAPI = %v, %v", vh, err)
	}
	readOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "read-only api", http.StatusTeapot) })
	e.api = api.Mount(readOnly, vh)
	return &srcEnv{vtEnv: e, hosts: hosts, inv: inv}
}

// addHost creates an inventory host with a display name and an address.
func (e *srcEnv) addHost(t *testing.T, id string) {
	t.Helper()
	if _, err := e.hosts.Create(context.Background(), inventory.Host{ID: id, DisplayName: id + ".lab.example",
		Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
		Endpoints: []inventory.Endpoint{{Address: srcAddress, Port: 22}}, CredentialRef: id}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// srcRead is the read that addRead stores: one source package, openssl.
func srcRead(host, exec string, at time.Time, complete bool, pkg string) vulninventory.Read {
	r := vulninventory.Read{HostID: host, ExecutionID: exec, ReadAt: at, Complete: complete, Ecosystem: "debian:bookworm",
		Kernel: vulninventory.Kernel{Release: "6.1.0-28-amd64", State: string(osdebian.KernelMapped), Source: "linux", Version: "6.1.119-1"},
		Components: []vulninventory.Component{{Source: pkg, SourceVersion: "3.0.15-1~deb12u1",
			Binaries: []vulninventory.Binary{{Name: pkg, Version: "3.0.15-1~deb12u1", Arch: "amd64"}}}}}
	if !complete {
		r.Reason = vulninventory.ReasonIncomplete
	}
	return r
}

// addRead stores a read of host, taken at the clock's time, as the ADR says
// a package list read is stored.
func (e *srcEnv) addRead(t *testing.T, r vulninventory.Read) {
	t.Helper()
	st, err := vulninventory.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

// srcPage is the part of the export page these tests read.
type srcPage struct {
	SnapshotID string `json:"snapshot_id"`
	Generation int64  `json:"generation"`
	Subjects   []struct {
		SubjectKind string `json:"subject_kind"`
		SubjectRef  struct {
			ID string `json:"id"`
		} `json:"subject_ref"`
		Ecosystem string `json:"ecosystem"`
		Kernel    *struct {
			Release       string `json:"release"`
			Mapped        bool   `json:"mapped"`
			SourcePackage string `json:"source_package"`
			SourceVersion string `json:"source_version"`
		} `json:"running_kernel"`
		Complete   bool `json:"complete"`
		Components []struct {
			SourcePackage string `json:"source_package"`
			SourceVersion string `json:"source_version"`
			Binaries      []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Arch    string `json:"arch"`
			} `json:"binaries"`
		} `json:"components"`
	} `json:"subjects"`
}

// exportPage GETs the export and decodes its first page.
func (e *srcEnv) exportPage(t *testing.T) (srcPage, string) {
	t.Helper()
	rec := e.do(t, http.MethodGet, "/api/v1/vuln/inventory", vtToken, vtHermes, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET inventory = %d %s", rec.Code, rec.Body)
	}
	var p srcPage
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p, rec.Body.String()
}

// startRun starts a run that names snapID as its inventory snapshot.
func (e *srcEnv) startRun(t *testing.T, snapID string) int {
	t.Helper()
	at := e.clk.Now().Add(-time.Hour).Format(time.RFC3339)
	var sources []any
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		sources = append(sources, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data", "content_date": at})
	}
	rec := e.do(t, http.MethodPost, "/api/v1/vuln/runs", vtToken, vtHermes,
		map[string]any{"inventory_snapshot_id": snapID, "matcher_version": "1.4.0", "sources": sources})
	return rec.Code
}

func TestVulnExportServesStoredHostFromInventory(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	p, body := e.exportPage(t)
	if len(p.Subjects) != 1 {
		t.Fatalf("subjects = %d, want 1: %s", len(p.Subjects), body)
	}
	s := p.Subjects[0]
	if s.SubjectKind != "host" || s.SubjectRef.ID != srcHost || s.Ecosystem != "debian:bookworm" || !s.Complete {
		t.Fatalf("subject = %+v, want the complete host", s)
	}
	if s.Kernel == nil || s.Kernel.Release != "6.1.0-28-amd64" || !s.Kernel.Mapped || s.Kernel.SourcePackage != "linux" || s.Kernel.SourceVersion != "6.1.119-1" {
		t.Fatalf("running kernel = %+v, want the mapped kernel", s.Kernel)
	}
	if len(s.Components) != 1 || s.Components[0].SourcePackage != "openssl" || len(s.Components[0].Binaries) != 1 || s.Components[0].Binaries[0].Name != "openssl" {
		t.Fatalf("components = %+v, want openssl with its binary", s.Components)
	}
	if strings.Contains(body, srcName) || strings.Contains(body, srcAddress) {
		t.Fatalf("export carries the host name or address: %s", body)
	}
}

func TestVulnExportKernelSourceOnlyWhenMapped(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	r := srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl")
	r.Kernel.State = "kernel_version_unknown"
	e.addRead(t, r)
	p, _ := e.exportPage(t)
	k := p.Subjects[0].Kernel
	if k == nil || k.Release != "6.1.0-28-amd64" || k.Mapped || k.SourcePackage != "" || k.SourceVersion != "" {
		t.Fatalf("running kernel = %+v, want the release only", k)
	}
}

func TestVulnExportPartialReadIsIncomplete(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), false, "openssl"))
	p, _ := e.exportPage(t)
	if len(p.Subjects) != 1 || p.Subjects[0].Complete {
		t.Fatalf("subjects = %+v, want one incomplete subject", p.Subjects)
	}
}

func TestVulnExportLeavesOutHostWithoutRead(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addHost(t, "srv-b")
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	p, _ := e.exportPage(t)
	if len(p.Subjects) != 1 || p.Subjects[0].SubjectRef.ID != srcHost {
		t.Fatalf("subjects = %+v, want only %s", p.Subjects, srcHost)
	}
}

func TestVulnExportSecondReadMakesNewSnapshotOldIDKeepsOldState(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-2*time.Minute), true, "openssl"))
	first, _ := e.exportPage(t)
	e.addRead(t, srcRead(srcHost, "exec-2", e.clk.Now().Add(-time.Minute), false, "curl"))
	second, _ := e.exportPage(t)
	if second.SnapshotID == first.SnapshotID || second.Generation <= first.Generation {
		t.Fatalf("second snapshot %s gen %d after %s gen %d, want a new ID and a higher generation",
			second.SnapshotID, second.Generation, first.SnapshotID, first.Generation)
	}
	if second.Subjects[0].Complete {
		t.Fatalf("second snapshot still complete, want the newer partial read")
	}
	old, err := e.inv.VulnSnapshot(context.Background(), first.SnapshotID)
	if err != nil {
		t.Fatalf("old snapshot: %v", err)
	}
	if old.Generation != first.Generation || len(old.Subjects) != 1 || !old.Subjects[0].Complete ||
		len(old.Subjects[0].Components) != 1 || old.Subjects[0].Components[0].Source != "openssl" {
		t.Fatalf("old snapshot = %+v, want the first read unchanged", old)
	}
}

// hourGeneration is the generation floor of the hour of now (see
// VulnSnapshot): the hour value that the export uses when it is higher.
func hourGeneration(now time.Time) int64 {
	return now.UTC().Truncate(vulnInventoryBucket).Unix() / int64(vulnInventoryBucket/time.Second)
}

// TestVulnExportFloorFromRunStateIsKept: a stored run floor above the hour
// value is kept, so the export's generation is above it, not just above the
// hour value. Dropping the stored floor from the export fails this test.
func TestVulnExportFloorFromRunStateIsKept(t *testing.T) {
	e := newSrcEnv(t)
	floor := hourGeneration(e.clk.Now()) + 1000
	if _, err := e.db.Exec(`UPDATE vuln_store_state SET max_inventory_generation = ? WHERE id = 1`, floor); err != nil {
		t.Fatal(err)
	}
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	p, _ := e.exportPage(t)
	if p.Generation <= floor {
		t.Fatalf("generation = %d, want above the stored floor %d (hour value %d)", p.Generation, floor, hourGeneration(e.clk.Now()))
	}
	if code := e.startRun(t, p.SnapshotID); code != http.StatusCreated {
		t.Fatalf("first run start = %d, want 201", code)
	}
}

func TestVulnRunStartWithSnapshotOlderThanMaxAgeIsConflict(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	p, _ := e.exportPage(t)
	e.clk.Add(vulnstore.MaxInventoryAge + time.Hour)
	if code := e.startRun(t, p.SnapshotID); code != http.StatusConflict {
		t.Fatalf("run start with a snapshot %v old = %d, want 409", vulnstore.MaxInventoryAge+time.Hour, code)
	}
}

func TestVulnExportNeverServesAnEmptySnapshotForAFailedHostList(t *testing.T) {
	e := newSrcEnv(t)
	failing := vulnHostLister(srcFailingHosts{})
	inv, err := newVulnInventory(e.db, failing, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := inv.VulnSnapshot(context.Background(), ""); err == nil || errors.Is(err, api.ErrVulnSnapshotGone) {
		t.Fatalf("snapshot = %+v, %v; want an error that is not Gone", s, err)
	}
}

// srcFailingHosts is a host list that cannot be read.
type srcFailingHosts struct{}

func (srcFailingHosts) List(context.Context) ([]inventory.Host, error) {
	return nil, errors.New("inventory unreadable")
}

func TestVulnInventoryOldNosEmptyIDsAreGone(t *testing.T) {
	e := newSrcEnv(t)
	for _, id := range []string{"nos-empty-1784000000", "nos-inv-999999999", "x y", strings.Repeat("a", 200)} {
		if _, err := e.inv.VulnSnapshot(context.Background(), id); !errors.Is(err, api.ErrVulnSnapshotGone) {
			t.Fatalf("snapshot %q: err = %v, want ErrVulnSnapshotGone", id, err)
		}
	}
}

func TestVulnSweepPrunesSnapshotsOlderThanMaxAge(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-2*time.Minute), true, "openssl"))
	old, _ := e.exportPage(t)
	e.addRead(t, srcRead(srcHost, "exec-2", e.clk.Now().Add(-time.Minute), true, "curl"))
	_, _ = e.exportPage(t)
	// Age the first snapshot past MaxInventoryAge in the store's own clock.
	if _, err := e.db.Exec(`UPDATE vuln_inventory_snapshots SET taken_at = taken_at - ? WHERE id = ?`,
		int64((vulnstore.MaxInventoryAge + time.Hour).Seconds()), old.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.sweepSnapshots(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM vuln_inventory_snapshots WHERE id = ?`, old.SnapshotID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expired snapshot still stored after the sweep")
	}
	if _, err := e.inv.VulnSnapshot(context.Background(), old.SnapshotID); !errors.Is(err, api.ErrVulnSnapshotGone) {
		t.Fatalf("pruned snapshot: err = %v, want ErrVulnSnapshotGone", err)
	}
}

// countingReads counts the snapshot loads of the store. Each load decodes
// every pinned read body of the snapshot, so the count is the decode count.
type countingReads struct {
	*vulninventory.Store
	loads int
}

func (c *countingReads) Snapshot(ctx context.Context, id string) (vulninventory.Snapshot, error) {
	c.loads++
	return c.Store.Snapshot(ctx, id)
}

// TestVulnInventoryDecodesSnapshotOncePerID: paging the export and starting
// runs against one snapshot decode its bodies once. Every later call with the
// same ID is served from the decoded copy, and the current snapshot keeps the
// same ID while it is reused.
func TestVulnInventoryDecodesSnapshotOncePerID(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	st, err := vulninventory.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingReads{Store: st}
	inv := newVulnInventoryOn(counted, e.db, inventory.NewWithNow(e.db, e.clk.Now), e.clk.Now)
	ctx := context.Background()
	first, err := inv.VulnSnapshot(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		cur, err := inv.VulnSnapshot(ctx, "")
		if err != nil || cur.ID != first.ID {
			t.Fatalf("current #%d = %s, %v; want %s", i, cur.ID, err, first.ID)
		}
		byID, err := inv.VulnSnapshot(ctx, first.ID)
		if err != nil || byID.ID != first.ID || len(byID.Subjects) != 1 {
			t.Fatalf("page #%d = %+v, %v; want the same snapshot", i, byID, err)
		}
	}
	if counted.loads != 1 {
		t.Fatalf("snapshot bodies decoded %d times for one snapshot, want 1", counted.loads)
	}
}

// TestVulnInventoryFutureTakenAtIsGone: a snapshot whose TakenAt lies after
// the clock (the wall clock stepped back) is expired, as the reuse rule of
// the store treats a negative age. It is Gone by ID even when it is cached.
func TestVulnInventoryFutureTakenAtIsGone(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	p, _ := e.exportPage(t)
	e.clk.Add(-2 * time.Hour)
	if _, err := e.inv.VulnSnapshot(context.Background(), p.SnapshotID); !errors.Is(err, api.ErrVulnSnapshotGone) {
		t.Fatalf("snapshot taken after the clock: err = %v, want ErrVulnSnapshotGone", err)
	}
}
