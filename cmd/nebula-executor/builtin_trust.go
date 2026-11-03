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
	log.Info("built-in trust configured", "store", storeDir, "bundle", bundleDir)
}
