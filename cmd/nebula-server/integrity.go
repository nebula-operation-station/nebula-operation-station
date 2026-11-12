// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
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
	// integrityReferenceDir holds release-manifest.json, its signature
	// and installed-files.json as install.sh and the upgrade place them.
	integrityReferenceDir = "/usr/share/nebula/release"
	// integrityStatusPath serves the latest result as JSON behind the
	// session, like the other server pages.
	integrityStatusPath = "/integrity/status"
	// debPackageList exists when NOS was installed from the .deb.
	debPackageList = "var/lib/dpkg/info/nebula-operation-station.list"
)

// containerMarkers exist inside a Docker or Podman container.
var containerMarkers = []string{".dockerenv", "run/.containerenv"}

// newIntegrityMonitor returns the server's I1 monitor for the running
// version, reading the signed reference from dir and checking the files
// under root.
//
// The server has no durable release root state of its own (that is the
// executor's, ADR 0015 D4 "Reference"), so the manifest signature is
// verified against the root anchors compiled into this binary. A list
// signed by a later, rotated root is therefore rejected (incomplete),
// never accepted from keys beside the files.
func newIntegrityMonitor(log *slog.Logger, version, dir, root string) *integrity.Monitor {
	v := strings.TrimPrefix(version, "v")
	return &integrity.Monitor{
		Load: func(context.Context) (integrity.Reference, error) {
			state, err := compiledRootState()
			if err != nil {
				return integrity.Reference{}, err
			}
			return integrity.LoadReference(state, v, dir)
		},
		Options:  integrity.Options{Root: root, Flavour: installFlavour(root)},
		Interval: integrityCheckInterval,
		Log:      log,
	}
}

func compiledRootState() (release.RootState, error) {
	anchors, err := release.Anchors()
	if err != nil {
		return release.RootState{}, err
	}
	return release.Bootstrap(anchors)
}

// installFlavour names the install flavour of the installation under
// root: container, deb or tarball, on this architecture. When a marker
// cannot be inspected it returns "", which the check reports as
// incomplete instead of checking against a guessed flavour.
func installFlavour(root string) string {
	exists := func(rel string) (bool, bool) {
		_, err := os.Lstat(filepath.Join(root, rel))
		switch {
		case err == nil:
			return true, true
		case errors.Is(err, fs.ErrNotExist):
			return false, true
		default:
			return false, false
		}
	}
	for _, m := range containerMarkers {
		found, ok := exists(m)
		if !ok {
			return ""
		}
		if found {
			return "container:" + runtime.GOARCH
		}
	}
	found, ok := exists(debPackageList)
	switch {
	case !ok:
		return ""
	case found:
		return "deb:" + runtime.GOARCH
	}
	return "tarball:" + runtime.GOARCH
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
