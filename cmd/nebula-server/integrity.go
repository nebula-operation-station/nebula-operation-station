// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// I1 self-check of nebula-server (ADR 0015 D4, IG-03). The server checks
// the installed NOS files at start and every integrityCheckInterval, logs
// each run and shows the latest result under integrityStatusPath. It
// does not react: findings, notifications and the unlock refusal are
// IG-04 and the executor's job.
const (
	// integrityCheckInterval is the period after the start check (ADR
	// 0015 D4 "When", Q2: every 60 minutes).
	integrityCheckInterval = integrity.DefaultInterval
	// integrityInstallRoot is the root of the installed NOS files the
	// server checks.
	integrityInstallRoot = "/"
	// integrityStatusPath serves the latest result as JSON behind the
	// session, like the other server pages.
	integrityStatusPath = "/integrity/status"
	// debPackageList exists when NOS was installed from the .deb.
	debPackageList = "var/lib/dpkg/info/nebula-operation-station.list"
)

// containerMarkers exist inside a Docker or Podman container.
var containerMarkers = []string{".dockerenv", "run/.containerenv"}

// newIntegrityMonitor returns the server's I1 monitor for the running
// version, checking the installed files under integrityInstallRoot.
func newIntegrityMonitor(log *slog.Logger, version string) *integrity.Monitor {
	return newIntegrityMonitorAt(log, version, integrityInstallRoot)
}

// newIntegrityMonitorAt is newIntegrityMonitor for the installation under
// root.
//
// Reference (ADR 0015 D4 "Reference"): checks run only against the
// installed-files list the executor admitted into its own storage, never
// against the copy in /usr/share. Nothing admits that list yet and the
// server cannot read executor storage (both IG-04), so a release build
// reports every run as incomplete (no-admitted-reference) at ERROR and
// hashes nothing; a development build stays not-checkable. The server
// does not react to either (IG-04). Previously the server re-admitted the
// /usr/share copy against its built-in anchors on every run; that
// deviation from D4 is removed.
//
// The install flavour is detected on every run (Monitor.Flavour), so a
// marker that could not be inspected once does not stick until restart.
func newIntegrityMonitorAt(log *slog.Logger, version, root string) *integrity.Monitor {
	v := strings.TrimPrefix(version, "v")
	return &integrity.Monitor{
		Load: func(context.Context) (integrity.Reference, error) {
			if !release.ValidReleaseVersion(v) {
				return integrity.Reference{}, integrity.ErrDevelopmentBuild
			}
			return integrity.Reference{}, fmt.Errorf("%w: the server cannot read it yet (IG-04)",
				integrity.ErrNoAdmittedReference)
		},
		ReferenceSource: integrity.SourceExecutorAdmitted,
		Options:         integrity.Options{Root: root},
		Flavour:         func(context.Context) (string, error) { return installFlavour(root) },
		Interval:        integrityCheckInterval,
		Log:             log,
	}
}

// installFlavour names the install flavour of the installation under
// root: container, deb or tarball, on this architecture. A marker that
// cannot be inspected is an error, never a guessed flavour.
func installFlavour(root string) (string, error) {
	exists := func(rel string) (bool, error) {
		_, err := os.Lstat(filepath.Join(root, rel))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, fs.ErrNotExist):
			return false, nil
		default:
			return false, fmt.Errorf("inspect flavour marker %s: %w", rel, err)
		}
	}
	for _, m := range containerMarkers {
		found, err := exists(m)
		if err != nil {
			return "", err
		}
		if found {
			return "container:" + runtime.GOARCH, nil
		}
	}
	found, err := exists(debPackageList)
	switch {
	case err != nil:
		return "", err
	case found:
		return "deb:" + runtime.GOARCH, nil
	}
	return "tarball:" + runtime.GOARCH, nil
}

// mountIntegrityStatus serves the monitor's latest result.
func mountIntegrityStatus(mux *http.ServeMux, m *integrity.Monitor) {
	mux.HandleFunc("GET "+integrityStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		b, err := json.Marshal(m.Status())
		if err != nil {
			http.Error(w, "integrity status unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
}
