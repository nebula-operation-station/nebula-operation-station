// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// defaultBuiltinBundleDir is where the executor reads the locally verified
// NOS release bundle (release-manifest.json, its signature and
// builtins.tar) that `nebula artifact trust-builtins` reviews (ADR 0007
// E15/E16). The server never supplies this path.
const defaultBuiltinBundleDir = "/usr/share/nebula/release"

// builtinTrustDirName is the built-in trust store under the data dir.
const builtinTrustDirName = "trust"

// builtinTrustSetter is the part of *executor.Service that wiring needs.
type builtinTrustSetter interface {
	SetBuiltinTrust(executor.BuiltinTrust)
}

// wireBuiltinTrust opens (and on first start bootstraps) the built-in
// trust store in storeDir, reviews the release bundle in bundleDir against
// it on request, and records every commit's exact artifact trust in
// artifacts, the executor's risk authority. It must run before the server
// serves. It returns an error if the store cannot be opened; the caller
// then leaves built-in trust unwired (review/commit unimplemented, status
// UNAVAILABLE), which only keeps built-ins at their untrusted floor.
func wireBuiltinTrust(svc builtinTrustSetter, storeDir, bundleDir string, anchors []release.Anchor,
	now func() time.Time, artifacts executor.BuiltinArtifactTrust) error {
	bt, err := executor.NewDirBuiltinTrust(storeDir, bundleDir, anchors, now, artifacts)
	if err != nil {
		return fmt.Errorf("built-in trust (store %s, bundle %s): %w", storeDir, bundleDir, err)
	}
	svc.SetBuiltinTrust(bt)
	return nil
}

// builtinBundlePresence says whether a release bundle is installed in the
// bundle directory at all. It never says anything about trust: a present
// bundle is still read and verified in full, and an absent one leaves the
// built-ins at their untrusted floor.
type builtinBundlePresence int

const (
	// builtinBundlePresent: something is in the bundle location (complete,
	// partial, unreadable, symlinked or otherwise unexpected). The
	// verifying reader decides; a broken bundle is UNAVAILABLE. It is the
	// zero value, so any doubt falls on the verifying path.
	builtinBundlePresent builtinBundlePresence = iota
	// builtinBundleNotInstalled: the directory is missing, or it is a
	// real directory holding none of the three bundle files.
	builtinBundleNotInstalled
)

func (p builtinBundlePresence) String() string {
	if p == builtinBundleNotInstalled {
		return "not installed"
	}
	return "present"
}

// classifyBuiltinBundle reports whether no release bundle is installed in
// dir, by the same rule the status RPC uses for NOT_INSTALLED
// (executor.BuiltinBundleNotInstalled): only a missing directory, or a real
// directory holding none of the three bundle files, is not installed;
// everything else is builtinBundlePresent.
func classifyBuiltinBundle(dir string) builtinBundlePresence {
	if executor.BuiltinBundleNotInstalled(dir) {
		return builtinBundleNotInstalled
	}
	return builtinBundlePresent
}

// setupBuiltinTrust wires built-in trust with the compiled release anchors
// and the executor's configured directories; an empty storeDir means
// <dataDir>/trust. A failure is logged, not fatal: the executor keeps
// serving with built-ins untrusted.
func setupBuiltinTrust(svc builtinTrustSetter, dataDir, storeDir, bundleDir string,
	artifacts executor.BuiltinArtifactTrust, log *slog.Logger) {
	if storeDir == "" {
		storeDir = filepath.Join(dataDir, builtinTrustDirName)
	}
	anchors, err := release.Anchors()
	if err == nil {
		err = wireBuiltinTrust(svc, storeDir, bundleDir, anchors, time.Now, artifacts)
	}
	if err != nil {
		log.Warn("built-in trust unavailable; built-ins stay untrusted", "err", err)
		return
	}
	if classifyBuiltinBundle(bundleDir) == builtinBundleNotInstalled {
		// Not a fault (source/quickstart installs ship no bundle): say
		// so plainly. Built-ins stay at their untrusted floor.
		log.Info("built-in trust configured; no release bundle installed, built-ins stay untrusted",
			"store", storeDir, "bundle", bundleDir)
		return
	}
	log.Info("built-in trust configured", "store", storeDir, "bundle", bundleDir)
}
