// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"
)

const testUPID = "UPID:pve1:000A1B2C:0123ABCD:65F0A1B2:qmstart:101:nebula@pve!action:"

func testPveJob(step int) PveJob {
	return PveJob{
		ExecutionID: "00000000-0000-4000-9000-000000000001", Step: step, Digest: strings.Repeat("a", 64),
		Action: "pve.guest.start", RemoteID: "pve-lab", TrustGeneration: 3, Kind: "qemu", Node: "pve1", VMID: 101,
		RequestDigest: strings.Repeat("b", 64), TaskType: "qmstart", TaskUser: "nebula@pve!action",
	}
}

func TestPveJobUPIDMustBeTheStepsTask(t *testing.T) {
	cases := map[string]string{
		"other task type": strings.Replace(testUPID, ":qmstart:", ":vzdump:", 1),
		"other user":      strings.Replace(testUPID, "nebula@pve!action", "root@pam", 1),
		"other token":     strings.Replace(testUPID, "nebula@pve!action", "nebula@pve!read", 1),
	}
	for name, upid := range cases {
		t.Run(name, func(t *testing.T) {
			db := openT(t, privateDir(t))
			if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
				t.Fatal(err)
			}
			if err := db.RecordPveJobUPID(testPveJob(1).ExecutionID, 1, upid, "pve1"); !errors.Is(err, ErrPveJobTask) {
				t.Fatalf("foreign task stored: %v", err)
			}
			if j, _, _ := db.PveJob(testPveJob(1).ExecutionID, 1); j.UPID != "" || j.State != PveJobDispatching {
				t.Fatalf("job: %+v", j)
			}
		})
	}
}

func TestPveJobUPIDBelongsToOneStep(t *testing.T) {
	db := openT(t, privateDir(t))
	id := testPveJob(1).ExecutionID
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(id, 1, testUPID, "pve1"); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishPveJob(id, 1, PveJobSucceeded, "OK"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePveJobIntent(testPveJob(2)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(id, 2, testUPID, "pve1"); !errors.Is(err, ErrPveUPIDRecorded) {
		t.Fatalf("step 1's task stored for step 2: %v", err)
	}
	other := testPveJob(1)
	other.ExecutionID = "00000000-0000-4000-9000-000000000002"
	if err := db.CreatePveJobIntent(other); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(other.ExecutionID, 1, testUPID, "pve1"); !errors.Is(err, ErrPveUPIDRecorded) {
		t.Fatalf("task stored for another job: %v", err)
	}
	if used, err := db.PveUPIDRecorded(testUPID); err != nil || !used {
		t.Fatalf("recorded: %v %v", used, err)
	}
	if used, err := db.PveUPIDRecorded(strings.Replace(testUPID, "000A1B2C", "000A1B2D", 1)); err != nil || used {
		t.Fatalf("unrecorded: %v %v", used, err)
	}
	// The unique index holds even without the check in RecordPveJobUPID.
	if _, err := db.sql.Exec(`UPDATE pve_jobs SET upid = ?, task_node = 'pve1' WHERE execution_id = ? AND step = 1`, testUPID, other.ExecutionID); err == nil {
		t.Fatal("unique index allowed a reused UPID")
	}
}

func TestPveJobIntentIsDurableAndSingle(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePveJobIntent(testPveJob(1)); !errors.Is(err, ErrPveJobExists) {
		t.Fatalf("second intent: %v", err)
	}
	db.Close()
	// After a restart the intent is still there, still blocks a new
	// dispatch and is listed for reconciliation.
	db = openT(t, dir)
	if err := db.CreatePveJobIntent(testPveJob(1)); !errors.Is(err, ErrPveJobExists) {
		t.Fatalf("intent after restart: %v", err)
	}
	open, err := db.OpenPveJobs()
	if err != nil || len(open) != 1 || open[0].State != PveJobDispatching || open[0].UPID != "" {
		t.Fatalf("open jobs: %+v, %v", open, err)
	}
}

func TestPveJobStepsAreOrdered(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.CreatePveJobIntent(testPveJob(2)); !errors.Is(err, ErrPveJobOrder) {
		t.Fatalf("step 2 without step 1: %v", err)
	}
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePveJobIntent(testPveJob(2)); !errors.Is(err, ErrPveJobOrder) {
		t.Fatalf("step 2 before step 1 has its UPID: %v", err)
	}
	if err := db.RecordPveJobUPID(testPveJob(1).ExecutionID, 1, testUPID, "pve1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePveJobIntent(testPveJob(2)); !errors.Is(err, ErrPveJobOrder) {
		t.Fatalf("step 2 before step 1 succeeded: %v", err)
	}
	if err := db.FinishPveJob(testPveJob(1).ExecutionID, 1, PveJobSucceeded, "OK"); err != nil {
		t.Fatal(err)
	}
	other := testPveJob(2)
	other.VMID = 102
	if err := db.CreatePveJobIntent(other); !errors.Is(err, ErrPveJobOrder) {
		t.Fatalf("step 2 on another target: %v", err)
	}
	if err := db.CreatePveJobIntent(testPveJob(2)); err != nil {
		t.Fatal(err)
	}
}

func TestPveJobUPIDStoredOnce(t *testing.T) {
	db := openT(t, privateDir(t))
	id := testPveJob(1).ExecutionID
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(id, 1, testUPID, "pve1"); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(id, 1, strings.Replace(testUPID, "000A1B2C", "000A1B2D", 1), "pve1"); !errors.Is(err, ErrPveJobState) {
		t.Fatalf("UPID replaced: %v", err)
	}
	j, ok, err := db.PveJob(id, 1)
	if err != nil || !ok || j.UPID != testUPID || j.TaskNode != "pve1" || j.State != PveJobRunning || j.DispatchedAt.IsZero() {
		t.Fatalf("job: %+v %v %v", j, ok, err)
	}
	if err := db.RecordPveJobUPID(id, 9, testUPID, "pve1"); !errors.Is(err, ErrPveJobNotFound) {
		t.Fatalf("unknown step: %v", err)
	}
}

func TestPveJobRejectsMalformedUPID(t *testing.T) {
	cases := map[string][2]string{
		"empty":            {"", "pve1"},
		"node mismatch":    {testUPID, "pve2"},
		"no prefix":        {strings.TrimPrefix(testUPID, "UPID:"), "pve1"},
		"control chars":    {strings.Replace(testUPID, "qmstart", "qm\nstart", 1), "pve1"},
		"lowercase hex":    {strings.Replace(testUPID, "000A1B2C", "000a1b2c", 1), "pve1"},
		"oversized":        {"UPID:pve1:000A1B2C:0123ABCD:65F0A1B2:qmstart:101:" + strings.Repeat("a", 300) + "@pve:", "pve1"},
		"path in node":     {strings.Replace(testUPID, "pve1", "../x", 1), "../x"},
		"missing trailing": {strings.TrimSuffix(testUPID, ":"), "pve1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			db := openT(t, privateDir(t))
			if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
				t.Fatal(err)
			}
			if err := db.RecordPveJobUPID(testPveJob(1).ExecutionID, 1, c[0], c[1]); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestPveJobTerminalStates(t *testing.T) {
	db := openT(t, privateDir(t))
	id := testPveJob(1).ExecutionID
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	// Success needs an observed task.
	if err := db.FinishPveJob(id, 1, PveJobSucceeded, "OK"); !errors.Is(err, ErrPveJobState) {
		t.Fatalf("success without UPID: %v", err)
	}
	if err := db.MarkPveJobReconciling(id, 1); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishPveJob(id, 1, PveJobUnknown, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkPveJobReconciling(id, 1); !errors.Is(err, ErrPveJobState) {
		t.Fatalf("terminal job reopened: %v", err)
	}
	if err := db.RecordPveJobUPID(id, 1, testUPID, "pve1"); !errors.Is(err, ErrPveJobState) {
		t.Fatalf("UPID on terminal job: %v", err)
	}
	if err := db.FinishPveJob(id, 1, "running", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-terminal finish: %v", err)
	}
	open, err := db.OpenPveJobs()
	if err != nil || len(open) != 0 {
		t.Fatalf("open: %+v %v", open, err)
	}
}

func TestPveJobExitStatusIsSanitized(t *testing.T) {
	db := openT(t, privateDir(t))
	id := testPveJob(1).ExecutionID
	if err := db.CreatePveJobIntent(testPveJob(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPveJobUPID(id, 1, testUPID, "pve1"); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishPveJob(id, 1, PveJobFailed, "bad\x1b[2Jterm"); err != nil {
		t.Fatal(err)
	}
	j, _, _ := db.PveJob(id, 1)
	if j.ExitStatus != "invalid exit status" || j.State != PveJobFailed {
		t.Fatalf("job: %+v", j)
	}
}

func TestPveJobRejectsMalformedIntent(t *testing.T) {
	cases := map[string]func(*PveJob){
		"step 0":        func(j *PveJob) { j.Step = 0 },
		"step too high": func(j *PveJob) { j.Step = MaxPveJobSteps + 1 },
		"digest":        func(j *PveJob) { j.Digest = "xyz" },
		"action":        func(j *PveJob) { j.Action = "patching.install_all" },
		"kind":          func(j *PveJob) { j.Kind = "vm" },
		"node":          func(j *PveJob) { j.Node = "a/b" },
		"generation":    func(j *PveJob) { j.TrustGeneration = 0 },
		"no task type":  func(j *PveJob) { j.TaskType = "" },
		"task type":     func(j *PveJob) { j.TaskType = "qm:start" },
		"no task user":  func(j *PveJob) { j.TaskUser = "" },
		"task user":     func(j *PveJob) { j.TaskUser = "root@pam" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			db := openT(t, privateDir(t))
			j := testPveJob(1)
			mutate(&j)
			if err := db.CreatePveJobIntent(j); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}
