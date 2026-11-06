// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
)

// pveJobOn is testPveJob(step) of execution id on remote.
func pveJobOn(remote, id string, vmid uint64, step int) PveJob {
	j := testPveJob(step)
	j.RemoteID, j.ExecutionID, j.VMID = remote, id, vmid
	return j
}

func TestClosePveJobsOnlyForInactiveRemote(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-lab", pinOf("lab-ca")))
	addPveRemote(t, db, pveClusterRemote("pve-other", pinOf("other-ca")))
	a := pveJobOn("pve-lab", "00000000-0000-4000-9000-00000000000a", 101, 1)
	b := pveJobOn("pve-lab", "00000000-0000-4000-9000-00000000000b", 102, 1)
	o := pveJobOn("pve-other", "00000000-0000-4000-9000-00000000000c", 101, 1)
	for _, j := range []PveJob{a, b, o} {
		if err := db.CreatePveJobIntent(j); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecordPveJobUPID(b.ExecutionID, 1, strings.Replace(testUPID, ":101:", ":102:", 1), "pve1"); err != nil {
		t.Fatal(err)
	}

	// An active remote's steps are reconciled, never closed by hand.
	if _, err := db.ClosePveJobs("pve-lab", "admin", "remote decommissioned", closeAll); !errors.Is(err, ErrPveRemoteActive) {
		t.Fatalf("close on active remote: %v", err)
	}
	if _, err := db.ClosePveJobs("pve-none", "admin", "x", closeAll); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("close on unknown remote: %v", err)
	}
	if open, _ := db.OpenPveJobs(); len(open) != 3 {
		t.Fatalf("refused close changed steps: %+v", open)
	}

	if _, err := db.BlockRemote("pve-lab", "trust verification failed", "admin"); err != nil {
		t.Fatal(err)
	}
	closed, err := db.ClosePveJobs("pve-lab", "alice", "certificate replaced; host reinstalled", closeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 2 || closed[0].ExecutionID != a.ExecutionID || closed[1].ExecutionID != b.ExecutionID {
		t.Fatalf("closed: %+v", closed)
	}
	for _, c := range closed {
		j, _, _ := db.PveJob(c.ExecutionID, 1)
		if j.State != PveJobUnknown || j.ClosedBy != "alice" || j.ClosedReason != "certificate replaced; host reinstalled" || j.FinishedAt.IsZero() {
			t.Fatalf("closed job: %+v", j)
		}
	}
	// The other remote is untouched, and the target takes a new intent.
	open, _ := db.OpenPveJobs()
	if len(open) != 1 || open[0].RemoteID != "pve-other" || open[0].ClosedBy != "" {
		t.Fatalf("open after close: %+v", open)
	}
	if err := db.CreatePveJobIntent(pveJobOn("pve-lab", "00000000-0000-4000-9000-00000000000d", 101, 1)); err != nil {
		t.Fatalf("target still busy after close: %v", err)
	}
	// Nothing left to close is not an error.
	if _, err := db.RemoveRemote("pve-other", "admin"); err != nil {
		t.Fatal(err)
	}
	if again, err := db.ClosePveJobs("pve-other", "alice", "removed", closeAll); err != nil || len(again) != 1 {
		t.Fatalf("close on removed remote: %v %+v", err, again)
	}
}

// closeAll is a ClosePveJobs step check that accepts every step.
func closeAll(PveJob) error { return nil }

// TestClosePveJobsCheckRefusalClosesNothing: a step the check refuses
// aborts the whole close, so no step of the remote is closed; a missing
// check is refused.
func TestClosePveJobsCheckRefusalClosesNothing(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-lab", pinOf("lab-ca")))
	a := pveJobOn("pve-lab", "00000000-0000-4000-9000-00000000000a", 101, 1)
	b := pveJobOn("pve-lab", "00000000-0000-4000-9000-00000000000b", 102, 1)
	for _, j := range []PveJob{a, b} {
		if err := db.CreatePveJobIntent(j); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.BlockRemote("pve-lab", "trust verification failed", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ClosePveJobs("pve-lab", "alice", "reason", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("close without check: %v", err)
	}
	errBusy := errors.New("still in flight")
	var checked []string
	_, err := db.ClosePveJobs("pve-lab", "alice", "reason", func(j PveJob) error {
		checked = append(checked, j.ExecutionID)
		if j.ExecutionID == b.ExecutionID {
			return errBusy
		}
		return nil
	})
	if !errors.Is(err, errBusy) || len(checked) != 2 {
		t.Fatalf("refused close: %v, checked %v", err, checked)
	}
	if open, _ := db.OpenPveJobs(); len(open) != 2 || open[0].ClosedBy != "" || open[1].ClosedBy != "" {
		t.Fatalf("refused close changed steps: %+v", open)
	}
}

func TestClosePveJobsRejectsBadActorOrReason(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-lab", pinOf("lab-ca")))
	if _, err := db.BlockRemote("pve-lab", "test", "admin"); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"no actor":       {"", "reason"},
		"long actor":     {strings.Repeat("a", 65), "reason"},
		"no reason":      {"admin", ""},
		"long reason":    {"admin", strings.Repeat("r", MaxPveJobCloseReason+1)},
		"control reason": {"admin", "line\nbreak"},
		"invalid utf8":   {"admin", "\xff"},
	}
	for name, c := range cases {
		if _, err := db.ClosePveJobs("pve-lab", c[0], c[1], closeAll); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPveJobNodeGrammarIsThePermitRule(t *testing.T) {
	for _, node := range []string{"pve1.lab.test", "ProxmoxBAI.lab", "pve-", "PVE-", "pve_1", "PVE_1", strings.Repeat("a", 64), strings.Repeat("A", 64)} {
		j := testPveJob(1)
		j.Node = node
		if err := validatePveJob(j); !errors.Is(err, ErrInvalid) {
			t.Errorf("node %q accepted: %v", node, err)
		}
		if _, ok := ParsePveUPID(strings.Replace(testUPID, "UPID:pve1:", "UPID:"+node+":", 1)); ok {
			t.Errorf("UPID with node %q accepted", node)
		}
	}
	j := testPveJob(1)
	j.Node = strings.Repeat("a", 63)
	if err := validatePveJob(j); err != nil {
		t.Errorf("63-character node refused: %v", err)
	}
	j.Node = "ProxmoxBAI"
	if err := validatePveJob(j); err != nil {
		t.Errorf("mixed-case node refused: %v", err)
	}
}

// The task of a mutation on "ProxmoxBAI" is bound to the exact node name.
func TestPveUPIDKeepsNodeCase(t *testing.T) {
	u, ok := ParsePveUPID(strings.Replace(testUPID, "UPID:pve1:", "UPID:ProxmoxBAI:", 1))
	if !ok {
		t.Fatal("UPID of a mixed-case node refused")
	}
	if u.Node != "ProxmoxBAI" {
		t.Fatalf("node = %q", u.Node)
	}
}

func TestPveUPIDRejectsOutOfRangeStartTime(t *testing.T) {
	for _, start := range []string{"00000000", "F4865701"} {
		if _, ok := ParsePveUPID(strings.Replace(testUPID, ":65F0A1B2:", ":"+start+":", 1)); ok {
			t.Errorf("start time %s accepted", start)
		}
	}
}

// TestPveUPIDGrammarIsSubsetOfPveapi spot-checks that the job record's UPID
// grammar stays within pveapi: a fixed corpus of UPIDs the record accepts,
// including its length and digit bounds, is also accepted by the pveapi
// writer, which dispatches mutations and reads their task status. It does
// not cover the tasks.go listing parser. The writer is served by a
// loopback test server.
func TestPveUPIDGrammarIsSubsetOfPveapi(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, rest, _ := strings.Cut(r.URL.Path, "/tasks/")
		upid := strings.TrimSuffix(rest, "/status")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"upid": upid, "status": "stopped", "exitstatus": "OK"}})
	}))
	t.Cleanup(ts.Close)
	wr, err := pveapi.NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) { return "PVEAPIToken=a@pve!b=c", nil }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	accepted := []string{
		testUPID,
		"UPID:pve1:00001234:1ABCDEF01:68FF93E0:qmstart:101:nebula@pve!action:",
		"UPID:" + strings.Repeat("n", 63) + ":FFFFFFFF:FFFFFFFFF:F4865700:" + strings.Repeat("z", 32) + ":" + strings.Repeat("i", 30) + ":" + strings.Repeat("u", 40) + "@pve!" + strings.Repeat("t", 40) + ":",
		"UPID:a:00000001:00000001:00000001:aptupdate::nebula@pve!action:",
		"UPID:pve-2:000A1B2C:0123ABCD:65F0A1B2:vzdump:local.zfs_1-a:nebula@pve!action:",
		"UPID:ProxmoxBAI:00001234:00ABCDEF:65F0A1B2:qmclone:9000:nebula@pve!action:",
		"UPID:" + strings.Repeat("N", 63) + ":00001234:00ABCDEF:65F0A1B2:qmclone:9000:nebula@pve!action:",
	}
	for _, upid := range accepted {
		if _, ok := ParsePveUPID(upid); !ok {
			t.Fatalf("corpus UPID refused by executordb: %s", upid)
		}
		if _, err := wr.TaskStatus(context.Background(), upid); err != nil {
			t.Errorf("executordb accepts a UPID pveapi refuses (%v): %s", err, upid)
		}
	}
}
