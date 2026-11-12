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
)

func TestIntegrityCheckIntervalIsADRValue(t *testing.T) {
	// ADR 0015 D4 "When", Q2: every 60 minutes.
	if integrityCheckInterval.Minutes() != 60 {
		t.Fatalf("interval %s, want 60m", integrityCheckInterval)
	}
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "1.0.0", t.TempDir(), t.TempDir())
	if m.Interval != integrityCheckInterval {
		t.Fatalf("monitor interval %s", m.Interval)
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
			if got := installFlavour(root); got != tc.want {
				t.Fatalf("flavour %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIntegrityServerWithoutListIsNotCheckable(t *testing.T) {
	releaseDir := t.TempDir()
	// What install.sh provides today: manifest and signature, no list.
	for _, name := range []string{release.ManifestFile, release.SignatureFile} {
		if err := os.WriteFile(filepath.Join(releaseDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, version, cause string
	}{
		{"release without list", "v1.2.3", integrity.CauseNoList},
		{"development build", "dev", integrity.CauseDevelopmentBuild},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			m := newIntegrityMonitor(slog.New(slog.NewJSONHandler(&logBuf, nil)), tc.version, releaseDir, t.TempDir())
			mux := http.NewServeMux()
			mountIntegrityStatus(mux, m)

			if got := getIntegrityStatus(t, mux); got.State != integrity.StatePending {
				t.Fatalf("before the start check: %q", got.State)
			}
			m.RunOnce(context.Background())
			got := getIntegrityStatus(t, mux)
			if got.State != integrity.StateNotCheckable || got.Cause != tc.cause || got.Runs != 1 {
				t.Fatalf("status %+v, want not-checkable/%s", got, tc.cause)
			}
			if got.Note != integrity.RootCompromiseNote {
				t.Fatalf("note %q", got.Note)
			}
			if !strings.Contains(logBuf.String(), `"state":"not-checkable"`) {
				t.Fatalf("log: %s", logBuf.String())
			}
		})
	}
}

func TestIntegrityServerRejectsUnsignedList(t *testing.T) {
	releaseDir := t.TempDir()
	for _, name := range []string{release.ManifestFile, release.SignatureFile, release.InstalledFilesArtifact} {
		if err := os.WriteFile(filepath.Join(releaseDir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "1.2.3", releaseDir, t.TempDir())
	st := m.RunOnce(context.Background())
	if st.State != integrity.StateIncomplete || st.Cause != integrity.CauseReferenceRejected {
		t.Fatalf("state %q cause %q, want incomplete/reference-rejected", st.State, st.Cause)
	}
}

func TestIntegrityStatusOnlyGET(t *testing.T) {
	m := newIntegrityMonitor(slog.New(slog.DiscardHandler), "dev", t.TempDir(), t.TempDir())
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
	if st.State != integrity.StateNotCheckable || st.Cause != integrity.CauseDevelopmentBuild || st.Runs != 1 {
		t.Fatalf("status %+v, want one not-checkable start check", st)
	}
	s.stop()
	if !strings.Contains(s.stderr.String(), `"kind":"integrity_self_check"`) {
		t.Fatalf("no self-check log record: %s", s.stderr)
	}
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
