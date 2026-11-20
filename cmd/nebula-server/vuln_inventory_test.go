// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

// insertFacts stores a successful core.facts result of host. Every call
// needs its own n, which makes the execution ID unique.
func (e *invEnv) insertFacts(t *testing.T, n int, host string, result []byte) {
	t.Helper()
	id := fmt.Sprintf("facts-%030d", n) // executions.id is 36 characters
	if _, err := e.db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at)
		VALUES (?, 'core.facts', '1.0.0', ?, 'LOW', 'finished', 0, 60, 'axel', ?, ?)`, id, strings.Repeat("a", 64), n, n); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:x', 'nebula-default', '[]', 'finished', 'success', ?, ?, ?)`, id, host, result, n, n); err != nil {
		t.Fatal(err)
	}
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

// TestInventoryLookupFailureStoresNothing: a closed database fails the
// core.facts lookup; the observer logs the class and stores nothing.
func TestInventoryLookupFailureStoresNothing(t *testing.T) {
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
