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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
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
