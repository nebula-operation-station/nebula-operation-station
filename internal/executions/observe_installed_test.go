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
	host, exec string
	at         time.Time
	result     string
}

func (r *recordingInstalled) ObserveInstalled(_ context.Context, hostID, execID string, at time.Time, result []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, installedCall{host: hostID, exec: execID, at: at, result: string(result)})
}

func (r *recordingInstalled) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// TestInstalledObserverSeesSuccessfulListOnce: a successful
// package.list_installed run reaches the observer exactly once, with the
// host, the execution, the finish time and the untouched result.
func TestInstalledObserverSeesSuccessfulListOnce(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	rec := &recordingInstalled{}
	s.SetInstalledObserver(rec)
	at := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	exec := strings.Repeat("7", 36)
	seedExecution(t, db, exec, "package.list_installed", "web", "success", nil, 100, 100)
	doc := `{"format":"nos-installed-v1","text":"nos-installed-v1\n","truncated":false}`
	s.finishHost(exec, "package.list_installed", "web", "success", "", 0, []byte(doc), nil, false)

	if rec.count() != 1 {
		t.Fatalf("observer calls = %d, want 1", rec.count())
	}
	c := rec.calls[0]
	if c.host != "web" || c.exec != exec || !c.at.Equal(at) || c.result != doc {
		t.Fatalf("call = %+v, want host web, execution, finish time and the untouched result", c)
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

func (panickingInstalled) ObserveInstalled(context.Context, string, string, time.Time, []byte) {
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

// TestInstalledObserverNilIsOff: without an observer a successful run is
// stored as before and nothing panics.
func TestInstalledObserverNilIsOff(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	exec := strings.Repeat("9", 36)
	seedExecution(t, db, exec, "package.list_installed", "web", "success", nil, 100, 100)
	s.finishHost(exec, "package.list_installed", "web", "success", "", 0, []byte(`{}`), nil, false)
}
