// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// recordingImage records every ObserveImage call.
type recordingImage struct {
	mu    sync.Mutex
	calls []imageCall
}

type imageCall struct {
	host, exec string
}

func (r *recordingImage) ObserveImage(_ context.Context, hostID, execID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, imageCall{host: hostID, exec: execID})
}

func (r *recordingImage) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// TestImageObserverSeesSuccessfulPackagesOnce: a successful image.packages
// run reaches the observer exactly once, with the host and the execution.
// The observer gets no result: it reads what the execution stored.
func TestImageObserverSeesSuccessfulPackagesOnce(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	rec := &recordingImage{}
	s.SetImageObserver(rec)
	exec := strings.Repeat("i", 36)
	seedExecution(t, db, exec, "image.packages", "web", "success", nil, 100, 100)

	s.finishHost(exec, "image.packages", "web", "success", "", 0, []byte(`{"format":"image-packages-v1"}`), nil, false)

	if rec.count() != 1 {
		t.Fatalf("observer calls = %d, want 1", rec.count())
	}
	if c := rec.calls[0]; c.host != "web" || c.exec != exec {
		t.Fatalf("call = %+v, want host web and execution %s", c, exec)
	}
}

// TestImageObserverNotCalledForOtherClassesOrActions: only a success of
// image.packages is observed. Other classes carry no package list, and other
// actions are not the image read.
func TestImageObserverNotCalledForOtherClassesOrActions(t *testing.T) {
	tests := []struct {
		name, action, class string
	}{
		{"failed", "image.packages", "failed"},
		{"script failed", "image.packages", "script_failed"},
		{"precheck failed", "image.packages", "precheck_failed"},
		{"unknown class", "image.packages", "unknown"},
		{"skipped", "image.packages", classSkipped},
		{"not run", "image.packages", classNotRun},
		{"docker.inspect success", "docker.inspect", "success"},
		{"package.list_installed success", "package.list_installed", "success"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, db := setup(t, &fakeExec{})
			rec := &recordingImage{}
			s.SetImageObserver(rec)
			exec := strings.Repeat(string(rune('a'+i)), 36)
			seedExecution(t, db, exec, tc.action, "web", "success", nil, 100, 100)
			s.finishHost(exec, tc.action, "web", tc.class, "", 1, []byte(`{"format":"image-packages-v1"}`), nil, false)
			if n := rec.count(); n != 0 {
				t.Fatalf("observer calls = %d, want 0", n)
			}
		})
	}
}

// TestImageObserverNilIsOff: without an observer a successful image.packages
// run still writes its finish row and refreshes the host's ops state.
func TestImageObserverNilIsOff(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	s.SetImageObserver(nil)
	exec := strings.Repeat("n", 36)
	seedExecution(t, db, exec, "image.packages", "web", "success", nil, 100, 100)

	s.finishHost(exec, "image.packages", "web", "success", "", 0, []byte(`{}`), nil, false)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_ops_state WHERE host_id = ?`, "web").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("host_ops_state rows = %d with no image observer, want 1", n)
	}
}

// panickingImage panics on every call, with a value that carries package text.
type panickingImage struct{}

func (panickingImage) ObserveImage(context.Context, string, string) {
	panic("libjansson4 6.1.0-26-amd64")
}

// TestImageObserverPanicDoesNotBreakOpsRefresh: a panic in the observer is
// contained; the finish path still refreshes the host's ops state, and the
// panic value (which may carry package text) is not logged, only its class.
func TestImageObserverPanicDoesNotBreakOpsRefresh(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	buf := &strings.Builder{}
	s.log = slog.New(slog.NewTextHandler(buf, nil))
	s.SetImageObserver(panickingImage{})
	exec := strings.Repeat("q", 36)
	seedExecution(t, db, exec, "image.packages", "web", "success", nil, 100, 100)

	s.finishHost(exec, "image.packages", "web", "success", "", 0, []byte(`{}`), nil, false)

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
