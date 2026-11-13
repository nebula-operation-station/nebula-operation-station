// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

// integrityInstallRoot is the root of the installed NOS files the
// executor checks (ADR 0015 D4 "Who").
const integrityInstallRoot = "/"

// integrityChecker is the part of *executor.Service that wiring needs.
type integrityChecker interface {
	SetIntegrityCheck(executor.IntegrityCheckConfig) error
	RunIntegrityChecks(ctx context.Context)
}

// setupIntegrityCheck wires the periodic I1 check (ADR 0015 D4 "When",
// Q2) with its state in dataDir, the default 60-minute interval and the
// default limits (4,096 files, 1 GiB per run). It runs after built-in
// trust admitted the reference. It returns the loop to start in its own
// goroutine, or nil when the check could not be wired (logged, not
// fatal).
func setupIntegrityCheck(svc integrityChecker, dataDir, root string, log *slog.Logger) func(context.Context) {
	err := svc.SetIntegrityCheck(executor.IntegrityCheckConfig{
		StatePath: filepath.Join(dataDir, executor.IntegrityCheckStateFile),
		Root:      root,
		Flavour:   func(context.Context) (string, error) { return executor.DetectInstallFlavour(root) },
	})
	if err != nil {
		log.Error("integrity check unavailable", "err", err)
		return nil
	}
	return svc.RunIntegrityChecks
}
