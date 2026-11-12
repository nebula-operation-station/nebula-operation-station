// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command nebula-vuln-agent is the vulnerability agent of ADR 0011
// amendment 1. One invocation is one run; the schedule is a systemd timer
// (va08). It runs as its own user, holds no SSH key, host credential or
// NOS secret besides its API token, and talks to NOS only through the
// /api/v1 vuln export and run protocol.
//
// Usage:
//
//	nebula-vuln-agent [flags] run        sync feeds, match, assess, submit
//	nebula-vuln-agent [flags] sync-only  sync feeds only; never contacts NOS
//	nebula-vuln-agent [flags] dry-run    like run, but print the records to
//	                                     stdout instead of submitting them
//
// Exit codes: 0 success; 1 the run failed; 2 usage or configuration
// error; 3 the run finished degraded (a feed failed to sync, a document
// or record was rejected, or a finding was withheld).
//
// Logs are structured JSON on stderr. The NOS token and the LLM API key
// are read from their files and never logged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// Exit codes.
const (
	exitOK       = 0
	exitFailed   = 1
	exitUsage    = 2
	exitDegraded = 3
)

// defaultConfigPath is read when -config is not given; it may be absent.
const defaultConfigPath = "/etc/nebula-vuln-agent/config.json"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := realMain(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// flagValues are the command-line overrides of the configuration file.
type flagValues struct {
	config                       string
	dataDir, nosURL, tokenFile   string
	caFile                       string
	llmEnabled                   bool
	llmURL, llmModel, llmKeyFile string
	logLevel                     string
}

func realMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nebula-vuln-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var fv flagValues
	fs.StringVar(&fv.config, "config", defaultConfigPath, "JSON configuration file")
	fs.StringVar(&fv.dataDir, "data-dir", "", "data directory (feed snapshots, CSAF state, run evidence)")
	fs.StringVar(&fv.nosURL, "nos-url", "", "NOS server, https://host[:port]")
	fs.StringVar(&fv.tokenFile, "token-file", "", "file with the NOS API token (mode 0600 or 0400)")
	fs.StringVar(&fv.caFile, "ca-file", "", "PEM file with the CA the NOS certificate is pinned to")
	fs.BoolVar(&fv.llmEnabled, "llm-enabled", false, "enable the assessor when NOS serves no LLM settings")
	fs.StringVar(&fv.llmURL, "llm-url", "", "LLM base URL (OpenAI-compatible) when NOS serves none")
	fs.StringVar(&fv.llmModel, "llm-model", "", "LLM model when NOS serves none")
	fs.StringVar(&fv.llmKeyFile, "llm-key-file", "", "file with the LLM API key (only ever read locally)")
	fs.StringVar(&fv.logLevel, "log-level", "", "debug, info, warn or error")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: nebula-vuln-agent [flags] run|sync-only|dry-run")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	mode := run.Mode(fs.Arg(0))
	switch mode {
	case run.ModeRun, run.ModeSyncOnly, run.ModeDryRun:
	default:
		_, _ = fmt.Fprintf(stderr, "nebula-vuln-agent: unknown command; use run, sync-only or dry-run\n")
		return exitUsage
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	boot := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := loadConfig(fv.config, set["config"])
	if err != nil {
		boot.Error("configuration refused", "error", err.Error())
		return exitUsage
	}
	cfg.applyFlags(fv, set)
	if err := cfg.validate(mode); err != nil {
		boot.Error("configuration refused", "error", err.Error())
		return exitUsage
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	r, err := newRunner(cfg, mode, stdout, log)
	if err != nil {
		log.Error("startup failed", "error", err.Error())
		if errors.Is(err, run.ErrConfig) {
			return exitUsage
		}
		return exitFailed
	}
	rep, err := r.Run(ctx, mode)
	return exitCode(rep, err)
}

// exitCode maps the outcome of a run to the process exit code.
func exitCode(rep *run.Report, err error) int {
	switch {
	case errors.Is(err, run.ErrConfig):
		return exitUsage
	case err != nil:
		return exitFailed
	case rep != nil && rep.Degraded():
		return exitDegraded
	}
	return exitOK
}

// applyFlags lets explicitly set flags override the file.
func (c *fileConfig) applyFlags(fv flagValues, set map[string]bool) {
	if set["data-dir"] {
		c.DataDir = fv.dataDir
	}
	if set["nos-url"] {
		c.NOS.URL = fv.nosURL
	}
	if set["token-file"] {
		c.NOS.TokenFile = fv.tokenFile
	}
	if set["ca-file"] {
		c.NOS.CAFile = fv.caFile
	}
	if set["llm-enabled"] {
		c.LLM.Enabled = fv.llmEnabled
	}
	if set["llm-url"] {
		c.LLM.BaseURL = fv.llmURL
	}
	if set["llm-model"] {
		c.LLM.Model = fv.llmModel
	}
	if set["llm-key-file"] {
		c.LLM.APIKeyFile = fv.llmKeyFile
	}
	if set["log-level"] {
		c.LogLevel = fv.logLevel
	}
}

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// newRunner wires the run from the validated configuration. The feed
// table and its origins are fixed in vulnfeed; the configuration cannot
// add an origin.
func newRunner(cfg fileConfig, mode run.Mode, stdout io.Writer, log *slog.Logger) (*run.Runner, error) {
	allow, err := vulnfeed.NewAllowlist(vulnfeed.DefaultOrigins())
	if err != nil {
		return nil, fmt.Errorf("feed allowlist: %w", err)
	}
	fetcher, err := vulnfeed.NewFetcher(vulnfeed.FetcherConfig{Allowlist: allow})
	if err != nil {
		return nil, fmt.Errorf("feed fetcher: %w", err)
	}
	providers, err := cfg.csafProviders()
	if err != nil {
		return nil, err
	}
	rc := run.Config{DataDir: cfg.DataDir, Fetcher: fetcher, CSAF: providers, LLM: cfg.llm(),
		AssessPhaseMax: time.Duration(cfg.AssessPhaseMax), Out: stdout, Logger: log}
	if mode != run.ModeSyncOnly {
		nc, err := nosclient.New(nosclient.Config{BaseURL: cfg.NOS.URL, TokenFile: cfg.NOS.TokenFile, CAFile: cfg.NOS.CAFile})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", run.ErrConfig, err)
		}
		rc.NOS = nc
		if cfg.NOS.AgentConfig == nil || *cfg.NOS.AgentConfig {
			ac, err := run.NewHTTPAgentConfig(run.AgentConfigOptions{BaseURL: cfg.NOS.URL, TokenFile: cfg.NOS.TokenFile, CAFile: cfg.NOS.CAFile})
			if err != nil {
				return nil, fmt.Errorf("%w: %w", run.ErrConfig, err)
			}
			rc.AgentConfig = ac
		}
	}
	r, err := run.New(rc)
	if err != nil {
		return nil, err
	}
	nosHost := ""
	if u, err := url.Parse(cfg.NOS.URL); err == nil {
		nosHost = u.Host
	}
	log.Info("nebula-vuln-agent starting", "mode", string(mode), "data_dir", cfg.DataDir, "nos", nosHost,
		"llm_local_enabled", cfg.LLM.Enabled, "llm_settings_from_nos", rc.AgentConfig != nil, "csaf_providers", len(providers))
	return r, nil
}
