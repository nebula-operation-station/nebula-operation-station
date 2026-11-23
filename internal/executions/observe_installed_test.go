// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingInstalled records every ObserveInstalled call.
type recordingInstalled struct {
	mu    sync.Mutex
	calls []installedCall
}

type installedCall struct {
	host, exec  string
	started, at time.Time
	result      string
}

func (r *recordingInstalled) ObserveInstalled(_ context.Context, hostID, execID string, started, finished time.Time, result []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, installedCall{host: hostID, exec: execID, started: started, at: finished, result: string(result)})
}

func (r *recordingInstalled) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// TestInstalledObserverSeesSuccessfulListOnce: a successful
// package.list_installed run reaches the observer exactly once, with the
// host, the execution, the start and finish times of the host row and the
// untouched result. The clock is set to a later time, so a second s.now()
// call would show up as a wrong finish time.
func TestInstalledObserverSeesSuccessfulListOnce(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	rec := &recordingInstalled{}
	s.SetInstalledObserver(rec)
	started := time.Date(2026, 11, 20, 9, 29, 0, 0, time.UTC)
	finished := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	clock := finished.Add(time.Hour)
	s.now = func() time.Time { return clock }
	exec := strings.Repeat("7", 36)
	seedExecution(t, db, exec, "package.list_installed", "web", "success", nil, 100, finished.Unix())
	if _, err := db.Exec(`UPDATE execution_hosts SET started_at = ? WHERE execution_id = ?`, started.Unix(), exec); err != nil {
		t.Fatal(err)
	}
	doc := `{"format":"nos-installed-v1","text":"nos-installed-v1\n","truncated":false}`
	s.finishHost(exec, "package.list_installed", "web", "success", "", 0, []byte(doc), nil, false)

	if rec.count() != 1 {
		t.Fatalf("observer calls = %d, want 1", rec.count())
	}
	c := rec.calls[0]
	if c.host != "web" || c.exec != exec || c.result != doc {
		t.Fatalf("call = %+v, want host web, execution and the untouched result", c)
	}
	if !c.started.Equal(started) {
		t.Fatalf("observer start = %v, want the host row's started_at %v", c.started, started)
	}
	var stored int64
	if err := db.QueryRow(`SELECT finished_at FROM execution_hosts WHERE execution_id = ? AND host_id = ?`, exec, "web").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !c.at.Equal(time.Unix(stored, 0)) || !c.at.Equal(clock) {
		t.Fatalf("observer finish = %v, want the stored finished_at %v (= the one clock read %v)", c.at, time.Unix(stored, 0), clock)
	}
}

// TestInstalledObserverNotCalledForOtherClassesOrActions: only a success of
// package.list_installed is observed. Other classes carry no document, and
// other actions are not the installed list.
func TestInstalledObserverNotCalledForOtherClassesOrActions(t *testing.T) {
	tests := []struct {
		name, action, class string
	}{
		{"failed", "package.list_installed", "failed"},
		{"skipped", "package.list_installed", classSkipped},
		{"not run", "package.list_installed", classNotRun},
		{"precheck failed", "package.list_installed", "precheck_failed"},
		{"unknown class", "package.list_installed", "unknown"},
		{"other action success", "package.list_updates", "success"},
		{"core.facts success", "core.facts", "success"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, db := setup(t, &fakeExec{})
			rec := &recordingInstalled{}
			s.SetInstalledObserver(rec)
			exec := strings.Repeat(string(rune('a'+i)), 36)
			seedExecution(t, db, exec, tc.action, "web", "success", nil, 100, 100)
			s.finishHost(exec, tc.action, "web", tc.class, "", 1, []byte(`{"format":"nos-installed-v1"}`), nil, false)
			if n := rec.count(); n != 0 {
				t.Fatalf("observer calls = %d, want 0", n)
			}
		})
	}
}

// panickingInstalled panics on every call, with a value that carries result text.
type panickingInstalled struct{}

func (panickingInstalled) ObserveInstalled(context.Context, string, string, time.Time, time.Time, []byte) {
	panic("libjansson4 6.1.0-26-amd64")
}

// TestInstalledObserverPanicDoesNotBreakOpsRefresh: a panic in the observer
// is contained; the finish path still refreshes the host's ops state, and the
// panic value (which may carry host text) is not logged.
func TestInstalledObserverPanicDoesNotBreakOpsRefresh(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	buf := &strings.Builder{}
	s.log = slog.New(slog.NewTextHandler(buf, nil))
	s.SetInstalledObserver(panickingInstalled{})
	exec := strings.Repeat("p", 36)
	seedExecution(t, db, exec, "package.list_installed", "web", "success", nil, 100, 100)

	s.finishHost(exec, "package.list_installed", "web", "success", "", 0, []byte(`{}`), nil, false)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_ops_state WHERE host_id = ?`, "web").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("host_ops_state rows = %d after a panicking observer, want 1", n)
	}
	if strings.Contains(buf.String(), "libjansson4") {
		t.Fatalf("panic value logged: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "error_class=panic") {
		t.Fatalf("panic not logged by class: %s", buf.String())
	}
}

// TestInstalledObserverNilIsOff: without an observer a successful run still
// writes its finish row and refreshes the host's ops state, and nothing panics.
func TestInstalledObserverNilIsOff(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	exec := strings.Repeat("9", 36)
	finished := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	seedExecution(t, db, exec, "package.list_installed", "web", "success", nil, 100, finished.Unix())
	s.finishHost(exec, "package.list_installed", "web", "success", "", 0, []byte(`{}`), nil, false)

	var state, class string
	var doneAt int64
	if err := db.QueryRow(`SELECT state, class, finished_at FROM execution_hosts WHERE execution_id = ? AND host_id = ?`, exec, "web").
		Scan(&state, &class, &doneAt); err != nil {
		t.Fatal(err)
	}
	if state != "finished" || class != "success" || doneAt == 0 {
		t.Fatalf("finish row = state %q class %q finished_at %d, want finished/success with a finish time", state, class, doneAt)
	}
	var ops int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_ops_state WHERE host_id = ?`, "web").Scan(&ops); err != nil {
		t.Fatal(err)
	}
	if ops != 1 {
		t.Fatalf("host_ops_state rows = %d, want the ops state refreshed once", ops)
	}
}

// TestLastOSChangeIsNewestFullUpgradeThatRan: the OS change of a host is the
// finish of its newest package.install_all that ran, whatever its class: a
// failed or unknown upgrade may have applied in whole or in part. Upgrades
// that did not reach the host's command (precheck_failed, not_executed),
// other actions and other hosts do not count, and a host without one has none.
func TestLastOSChangeIsNewestFullUpgradeThatRan(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	base := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC).Unix()
	seq := 0
	seed := func(action, host, class string, at int64) {
		seq++
		seedExecution(t, db, strings.Repeat(string(rune('a'+seq)), 36), action, host, class, nil, at, at)
	}
	if _, ok, err := s.LastOSChange(context.Background(), "web"); err != nil || ok {
		t.Fatalf("no upgrade yet: ok = %v, err = %v; want no change, no error", ok, err)
	}
	seed("package.install_all", "web", "success", base)
	seed("package.install_all", "web", "precheck_failed", base+3600)
	seed("package.install_all", "web", "not_executed", base+3700)
	seed("package.install_security", "web", "success", base+7200)
	seed("package.install_all", "db", "success", base+9000)
	seed("package.install_all", "web", "success", base+1800)
	seed("package.install_all", "web", "failed", base+2400)

	at, ok, err := s.LastOSChange(context.Background(), "web")
	if err != nil || !ok {
		t.Fatalf("LastOSChange: ok = %v, err = %v; want a change", ok, err)
	}
	if want := time.Unix(base+2400, 0); !at.Equal(want) {
		t.Fatalf("LastOSChange = %v, want the newest full upgrade that ran (failed) %v", at, want)
	}

	seed("package.install_all", "web", "unknown", base+3000)
	at, _, err = s.LastOSChange(context.Background(), "web")
	if err != nil {
		t.Fatalf("LastOSChange: %v", err)
	}
	if want := time.Unix(base+3000, 0); !at.Equal(want) {
		t.Fatalf("LastOSChange = %v, want the unknown upgrade %v", at, want)
	}
}

// TestUpgradeOverlapsListRead: a package.install_all of the host that ran
// while the list ran (started before the list ended, and still running or
// finished after the list started) overlaps the read; the list is then not
// fresh. Upgrades that ended before the list or began after it, upgrades that
// did not reach the command, other actions and other hosts do not overlap.
func TestUpgradeOverlapsListRead(t *testing.T) {
	listFrom := time.Date(2026, 11, 20, 9, 29, 0, 0, time.UTC)
	listTo := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	at := func(sec int) int64 { return listFrom.Add(time.Duration(sec) * time.Second).Unix() }
	const (
		running  = "running"
		finished = "finished"
	)
	tests := []struct {
		name    string
		action  string
		host    string
		state   string
		class   string
		started int64
		end     int64 // finished_at; unused while running
		want    bool
	}{
		{"running, started before the list", "package.install_all", "web", running, "", at(-300), 0, true},
		{"running, started during the list", "package.install_all", "web", running, "", at(10), 0, true},
		{"finished during the list", "package.install_all", "web", finished, "success", at(-300), at(10), true},
		{"started before, finished as the list started", "package.install_all", "web", finished, "success", at(-300), at(0), true},
		{"failed during the list", "package.install_all", "web", finished, "failed", at(-5), at(5), true},
		{"unknown during the list", "package.install_all", "web", finished, "unknown", at(-5), at(5), true},
		{"finished before the list", "package.install_all", "web", finished, "success", at(-600), at(-60), false},
		{"started after the list", "package.install_all", "web", running, "", at(61), 0, false},
		{"precheck_failed during the list", "package.install_all", "web", finished, "precheck_failed", at(-5), at(5), false},
		{"other action during the list", "package.install_security", "web", finished, "success", at(-5), at(5), false},
		{"other host during the list", "package.install_all", "db", finished, "success", at(-5), at(5), false},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, db := setup(t, &fakeExec{})
			id := strings.Repeat(string(rune('a'+i)), 36)
			var fin any
			if tc.state == finished {
				fin = tc.end
			}
			if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at)
				VALUES (?, ?, '1.0.0', ?, 'LOW', ?, 0, 60, 'axel', ?)`, id, tc.action, strings.Repeat("a", 64), tc.state, tc.started); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, started_at, finished_at)
				VALUES (?, ?, 'SHA256:x', 'nebula-default', '[]', ?, ?, ?, ?)`, id, tc.host, tc.state, tc.class, tc.started, fin); err != nil {
				t.Fatal(err)
			}
			got, err := s.UpgradeOverlaps(context.Background(), "web", listFrom, listTo)
			if err != nil {
				t.Fatalf("UpgradeOverlaps: %v", err)
			}
			if got != tc.want {
				t.Fatalf("UpgradeOverlaps = %v, want %v", got, tc.want)
			}
		})
	}
}
