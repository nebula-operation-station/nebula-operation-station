// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-ops-agent is the NOS ops agent (ADR 0016): a oneshot that
// turns open vulnerability findings into fix notes. It never executes
// anything and holds no provider token. Usage:
//
//	nebula-ops-agent -config /etc/nebula-ops-agent/config.json run
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpsearch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/state"
)

// runTimeout bounds one whole run. It covers the worst case: every call of
// the run times out (run.MaxLLMCallsPerRun × run.CallTimeout).
const runTimeout = run.MaxLLMCallsPerRun * run.CallTimeout

// stateFile is the run-state file inside the state directory.
const stateFile = "run-state.json"

func main() {
	os.Exit(realMain(os.Args[1:], os.Stderr))
}

func realMain(args []string, stderr io.Writer) int {
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	fs := flag.NewFlagSet("nebula-ops-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "absolute path of the agent config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || fs.Arg(0) != "run" {
		fmt.Fprintln(stderr, "usage: nebula-ops-agent -config <file> run")
		return 2
	}
	if err := runOnce(*cfgPath, logger); err != nil {
		logger.Error("ops agent run failed", "error", err.Error())
		return 1
	}
	return 0
}

// runOnce wires the collaborators and performs one run. Errors name files
// and statuses only; they never carry prompt, answer or token text.
func runOnce(cfgPath string, logger *slog.Logger) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	api, err := nosclient.New(nosclient.Config{BaseURL: cfg.NOSBaseURL, TokenFile: cfg.NOSTokenFile, CAFile: cfg.NOSCAFile})
	if err != nil {
		return fmt.Errorf("nos client: %w", err)
	}
	st := &state.Store{Path: filepath.Join(cfg.StateDir, stateFile)}
	deps := run.Deps{
		NOS:            api,
		State:          st,
		CredentialFile: cfg.LLMCredentialFile,
		Log:            logger,
	}
	if ix, err := helpdocs.FromDocsembed(); err != nil {
		logger.Warn("ops agent: documentation index unavailable; no chunks in prompts")
	} else {
		deps.Docs = helpsearch.New(ix)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	_, err = run.Run(ctx, deps)
	if errors.Is(err, nosclient.ErrUnauthorized) {
		return fmt.Errorf("nos refused the token: %w", err)
	}
	return err
}
