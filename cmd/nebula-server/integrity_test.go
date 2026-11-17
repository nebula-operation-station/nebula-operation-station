// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

func TestIntegrityCheckIntervalIsADRValue(t *testing.T) {
	// ADR 0015 D4 "When", Q2: every 60 minutes.
	if integrityCheckInterval.Minutes() != 60 {
		t.Fatalf("interval %s, want 60m", integrityCheckInterval)
	}
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "1.0.0")
	if m.Interval != integrityCheckInterval {
		t.Fatalf("monitor interval %s", m.Interval)
	}
}

// TestIntegrityServerChecksInstallRoot: the production monitor checks the
// installed system under "/" and detects the flavour per run, not once
// at start.
func TestIntegrityServerChecksInstallRoot(t *testing.T) {
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "v1.2.3")
	if m.Options.Root != "/" {
		t.Fatalf("root %q, want /", m.Options.Root)
	}
	if m.Options.Flavour != "" || m.Flavour == nil {
		t.Fatalf("flavour fixed at build time (%q) or not detected per run", m.Options.Flavour)
	}
}

// TestIntegrityServerChecksOnlyExecutorAdmittedReference: ADR 0015 D4
// "Reference" allows checks only against the executor-admitted list,
// never against the copy in /usr/share. The server cannot read that copy
// yet (IG-04), so a release run is incomplete even when /usr/share holds
// a release directory, and no file is hashed.
func TestIntegrityServerChecksOnlyExecutorAdmittedReference(t *testing.T) {
	root := t.TempDir()
	writeReleaseDir(t, filepath.Join(root, "usr/share/nebula/release"),
		release.ManifestFile, release.SignatureFile, release.InstalledFilesArtifact)
	m := newIntegrityMonitorAt(slog.New(slog.DiscardHandler), "v1.2.3", root)
	if m.ReferenceSource != integrity.SourceExecutorAdmitted {
		t.Fatalf("reference source %q", m.ReferenceSource)
	}
	mux := http.NewServeMux()
	mountIntegrityStatus(mux, m)
	if got := getIntegrityStatus(t, mux); got.ReferenceSource != integrity.SourceExecutorAdmitted {
		t.Fatalf("pending status %+v", got)
	}
	m.RunOnce(context.Background())
	got := getIntegrityStatus(t, mux)
	if got.State != integrity.StateIncomplete || got.Cause != integrity.CauseNoAdmittedReference ||
		got.ReferenceSource != integrity.SourceExecutorAdmitted {
		t.Fatalf("status %+v, want incomplete/%s from %s", got, integrity.CauseNoAdmittedReference,
			integrity.SourceExecutorAdmitted)
	}
	if got.Files != 0 || got.BytesHashed != 0 || got.ReleaseVersion != "" || got.ListDigest != "" {
		t.Fatalf("the /usr/share copy was used: %+v", got)
	}
}

func writeReleaseDir(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegrityFlavourRecoversAfterTransientError: a marker that cannot
// be inspected fails detection for that run only; the monitor asks
// again on the next run instead of keeping "" until a restart.
func TestIntegrityFlavourRecoversAfterTransientError(t *testing.T) {
	root := t.TempDir()
	// "run" as a regular file: Lstat of run/.containerenv fails with
	// ENOTDIR, which is neither "exists" nor "does not exist".
	blocker := filepath.Join(root, "run")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	m := newIntegrityMonitorAt(slog.New(slog.DiscardHandler), "v1.2.3", root)
	if f, err := m.Flavour(context.Background()); err == nil {
		t.Fatalf("flavour %q despite an uninspectable marker", f)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	f, err := m.Flavour(context.Background())
	if err != nil || f != "tarball:"+runtime.GOARCH {
		t.Fatalf("flavour %q, %v after recovery", f, err)
	}
}

func TestIntegrityInstallFlavour(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker string
		want   string
	}{
		{"deb package", "var/lib/dpkg/info/nebula-operation-station.list", "deb:" + runtime.GOARCH},
		{"docker", ".dockerenv", "container:" + runtime.GOARCH},
		{"podman", "run/.containerenv", "container:" + runtime.GOARCH},
		{"tarball", "", "tarball:" + runtime.GOARCH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.marker != "" {
				p := filepath.Join(root, tc.marker)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := installFlavour(root); err != nil || got != tc.want {
				t.Fatalf("flavour %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// TestIntegrityServerWithoutListIsIncompleteOrNotCheckable: a release
// without an executor-admitted list is ADR 0015 D4 "check could not run
// completely" (incomplete, ERROR); only a development build has no list
// to check against. Previously the release case read /usr/share and
// reported no-installed-files-list; D4 forbids that copy.
func TestIntegrityServerWithoutListIsIncompleteOrNotCheckable(t *testing.T) {
	root := t.TempDir()
	// What install.sh provides today: manifest and signature, no list.
	writeReleaseDir(t, filepath.Join(root, "usr/share/nebula/release"), release.ManifestFile, release.SignatureFile)
	for _, tc := range []struct {
		name, version string
		state         integrity.State
		cause, level  string
	}{
		{"release without admitted list", "v1.2.3", integrity.StateIncomplete, integrity.CauseNoAdmittedReference, "ERROR"},
		{"development build", "dev", integrity.StateNotCheckable, integrity.CauseDevelopmentBuild, "WARN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			m := newIntegrityMonitorAt(slog.New(slog.NewJSONHandler(&logBuf, nil)), tc.version, root)
			mux := http.NewServeMux()
			mountIntegrityStatus(mux, m)

			if got := getIntegrityStatus(t, mux); got.State != integrity.StatePending {
				t.Fatalf("before the start check: %q", got.State)
			}
			m.RunOnce(context.Background())
			got := getIntegrityStatus(t, mux)
			if got.State != tc.state || got.Cause != tc.cause || got.Runs != 1 {
				t.Fatalf("status %+v, want %s/%s", got, tc.state, tc.cause)
			}
			if got.Note != integrity.RootCompromiseNote {
				t.Fatalf("note %q", got.Note)
			}
			if !strings.Contains(logBuf.String(), `"state":"`+string(tc.state)+`"`) ||
				!strings.Contains(logBuf.String(), `"level":"`+tc.level+`"`) {
				t.Fatalf("log: %s", logBuf.String())
			}
		})
	}
}

// TestIntegrityServerRejectsUnsignedList: an unsigned list in /usr/share
// never makes the check ok; the server does not read it at all (ADR 0015
// D4 "Reference"), so the run stays incomplete.
func TestIntegrityServerRejectsUnsignedList(t *testing.T) {
	root := t.TempDir()
	writeReleaseDir(t, filepath.Join(root, "usr/share/nebula/release"),
		release.ManifestFile, release.SignatureFile, release.InstalledFilesArtifact)
	m := newIntegrityMonitorAt(slog.New(slog.DiscardHandler), "1.2.3", root)
	st := m.RunOnce(context.Background())
	if st.State != integrity.StateIncomplete || st.Cause != integrity.CauseNoAdmittedReference {
		t.Fatalf("state %q cause %q, want incomplete/%s", st.State, st.Cause, integrity.CauseNoAdmittedReference)
	}
}

func TestIntegrityStatusOnlyGET(t *testing.T) {
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "dev")
	mux := http.NewServeMux()
	mountIntegrityStatus(mux, m)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, integrityStatusPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}

// TestRunWiresIntegritySelfCheck starts the real server: the start check
// runs (a test binary is a development build, so the result is
// "not checkable", never ok), and the status is served only with a
// session.
func TestRunWiresIntegritySelfCheck(t *testing.T) {
	st, stderr := runServerSelfCheck(t)
	if st.State != integrity.StateNotCheckable || st.Cause != integrity.CauseDevelopmentBuild || st.Runs != 1 {
		t.Fatalf("status %+v, want one not-checkable start check", st)
	}
	if !strings.Contains(stderr, `"kind":"integrity_self_check"`) {
		t.Fatalf("no self-check log record: %s", stderr)
	}
}

// TestRunWiresIntegritySelfCheckReleaseBuild runs the production path
// through runServer as a release build: the monitor main.go builds takes
// no /usr/share copy (ADR 0015 D4 "Reference"), so without an
// executor-admitted list the start check is incomplete at ERROR, never
// ok and never not-checkable.
func TestRunWiresIntegritySelfCheckReleaseBuild(t *testing.T) {
	saved := version.Version
	version.Version = "v1.2.3"
	t.Cleanup(func() { version.Version = saved })

	st, stderr := runServerSelfCheck(t)
	if st.State != integrity.StateIncomplete || st.Cause != integrity.CauseNoAdmittedReference || st.Runs != 1 {
		t.Fatalf("status %+v, want one incomplete/%s start check", st, integrity.CauseNoAdmittedReference)
	}
	if st.ReferenceSource != integrity.SourceExecutorAdmitted || st.Files != 0 || st.BytesHashed != 0 {
		t.Fatalf("status %+v: checked against something other than the executor-admitted list", st)
	}
	type logRecord struct {
		Level, Kind, State, Cause string
		Source                    string `json:"reference_source"`
	}
	var rec logRecord
	found := false
	for line := range strings.SplitSeq(stderr, "\n") {
		var r logRecord
		if json.Unmarshal([]byte(line), &r) == nil && r.Kind == "integrity_self_check" && r.State != "" {
			rec, found = r, true
			break
		}
	}
	if !found || rec.Level != "ERROR" || rec.State != string(integrity.StateIncomplete) ||
		rec.Cause != integrity.CauseNoAdmittedReference || rec.Source != integrity.SourceExecutorAdmitted {
		t.Fatalf("self-check log record %+v (found %v): %s", rec, found, stderr)
	}
}

// runServerSelfCheck starts the real server, waits for the start check,
// checks that the status needs a session and returns the status and the
// server's log after stopping it.
func runServerSelfCheck(t *testing.T) (integrity.SelfCheck, string) {
	t.Helper()
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	alice, _ := vrSessions(t, dir)
	s := startVR(t, dir, vrConfig(t, dir, sock, nil))

	if code, body := s.do(t, http.MethodGet, integrityStatusPath, "", "", nil); code == http.StatusOK {
		t.Fatalf("status served without a session: %s", body)
	}
	deadline := time.Now().Add(10 * time.Second)
	var st integrity.SelfCheck
	for {
		code, body := s.do(t, http.MethodGet, integrityStatusPath, alice, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", integrityStatusPath, code, body)
		}
		if err := json.Unmarshal(body, &st); err != nil {
			t.Fatal(err)
		}
		if st.Runs > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.stop()
	return st, s.stderr.String()
}

func getIntegrityStatus(t *testing.T, h http.Handler) integrity.SelfCheck {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, integrityStatusPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", integrityStatusPath, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache control %q", cc)
	}
	var st integrity.SelfCheck
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}
