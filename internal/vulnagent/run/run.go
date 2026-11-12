// SPDX-License-Identifier: AGPL-3.0-or-later

// Package run orchestrates one run of the vulnerability agent (ADR 0011
// amendment 1, A1.3): feed sync, export read, matching, the optional
// assessment and the run protocol, strictly in this order and never
// interleaved. It records the run evidence (sources with their snapshot
// IDs and content dates, rejected documents, counts) in the data
// directory and in the log.
//
// Nothing in this package prints, logs or stores the NOS token or the
// LLM API key: the token is read only by nosclient and by the agent
// settings read (agentcfg.go, as a redacting type), the API key only by
// the LLM client of internal/vulnagent/agent.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// Phase budgets (A1.3, A1.4).
const (
	// DefaultAssessPhaseMax bounds the assessment phase by default.
	DefaultAssessPhaseMax = 2 * time.Hour
	// HardMaxAssessPhaseMax caps the configurable assessment phase.
	HardMaxAssessPhaseMax = 4 * time.Hour
	// UploadPhaseMax bounds run start, batches and complete; fixed.
	UploadPhaseMax = 90 * time.Minute
	// TemplateMarginTokens is reserved for the endpoint's chat and tool
	// templates when checking the declared context window (A1.4).
	TemplateMarginTokens = 4096
)

// Mode selects what a run does.
type Mode string

// Modes.
const (
	// ModeRun syncs, matches, assesses and submits to NOS.
	ModeRun Mode = "run"
	// ModeSyncOnly syncs the feeds and stops; it never contacts NOS.
	ModeSyncOnly Mode = "sync-only"
	// ModeDryRun does everything ModeRun does up to the upload, then
	// prints the records instead of starting a NOS run.
	ModeDryRun Mode = "dry-run"
)

// Sentinel errors; the command maps them to exit codes.
var (
	// ErrConfig: the configuration is invalid; nothing was done.
	ErrConfig = errors.New("vulnagent/run: invalid configuration")
	// ErrNoFeeds: no feed snapshot is available, so nothing can match.
	ErrNoFeeds = errors.New("vulnagent/run: no feed snapshot available")
	// ErrExport: the inventory export could not be read.
	ErrExport = errors.New("vulnagent/run: inventory export failed")
	// ErrLoad: a local feed snapshot could not be loaded.
	ErrLoad = errors.New("vulnagent/run: loading feed snapshots failed")
	// ErrMatch: matching failed.
	ErrMatch = errors.New("vulnagent/run: matching failed")
	// ErrUpload: the run protocol with NOS failed.
	ErrUpload = errors.New("vulnagent/run: run protocol failed")
)

// NOS is the part of nosclient.Client a run uses.
type NOS interface {
	Export(ctx context.Context, visit func(nosclient.Page) error) (*nosclient.Snapshot, error)
	StartRun(ctx context.Context, snap *nosclient.Snapshot, req nosclient.StartRequest) (*nosclient.Run, error)
}

// CSAFProvider is a signed CSAF feed with its pinned keys.
type CSAFProvider struct {
	// Feed is the provider's entry of the feed table (integrity signed).
	Feed vulnfeed.Feed
	// Vendor selects the product classification.
	Vendor vulnfeed.CSAFVendor
	// Keys are the pinned provider keys.
	Keys *vulnfeed.CSAFKeyring
}

// LLMConfig is the local assessor configuration. The API key is only
// ever read from APIKeyFile, by the LLM client.
type LLMConfig struct {
	// Enabled switches the assessor on when NOS serves no settings.
	Enabled bool
	// BaseURL and Model are used when NOS serves empty values.
	BaseURL, Model string
	// APIKeyFile is the optional file with the endpoint credential.
	APIKeyFile string
	// AllowPlainHTTP permits an http base URL (never with a key).
	AllowPlainHTTP bool
	// ContextWindow is the model's declared context window in tokens.
	ContextWindow int
	// Language is the assessment language when NOS serves none.
	Language agent.Language
	// OperatorInstructions are used when NOS serves none.
	OperatorInstructions string
	// Limits are the assessor limits; zero means agent.DefaultLimits.
	Limits agent.Limits
}

// Config configures a Runner.
type Config struct {
	// DataDir holds the feed store, the CSAF state and the run evidence.
	DataDir string
	// Feeds is the feed table; nil means vulnfeed.Feeds(). Signed feeds
	// are synced only through CSAF.
	Feeds []vulnfeed.Feed
	// Fetcher downloads the feeds. Required.
	Fetcher *vulnfeed.Fetcher
	// CSAF lists the signed providers that have pinned keys.
	CSAF []CSAFProvider
	// NOS is the NOS client; required except for ModeSyncOnly.
	NOS NOS
	// AgentConfig reads the LLM settings from NOS; nil uses LLM only.
	AgentConfig AgentConfigSource
	// LLM is the local assessor configuration.
	LLM LLMConfig
	// NewLLM builds the LLM client; nil uses agent.NewHTTPClient.
	NewLLM func(agent.ClientConfig) (agent.LLM, error)
	// AssessPhaseMax bounds the assessment phase; zero means
	// DefaultAssessPhaseMax.
	AssessPhaseMax time.Duration
	// Out receives the records of a dry run, one JSON object per line.
	Out io.Writer
	// Logger receives structured run logs; nil discards.
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Runner runs the agent.
type Runner struct {
	cfg   Config
	feeds []vulnfeed.Feed
	store *vulnfeed.Store
	sync  *vulnfeed.Syncer
	csaf  *vulnfeed.CSAFClient
	log   *slog.Logger
	now   func() time.Time
}

// New validates cfg and opens the feed store.
func New(cfg Config) (*Runner, error) {
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		return nil, fmt.Errorf("data directory must be an absolute path: %w", ErrConfig)
	}
	if cfg.Fetcher == nil {
		return nil, fmt.Errorf("feed fetcher required: %w", ErrConfig)
	}
	if cfg.AssessPhaseMax == 0 {
		cfg.AssessPhaseMax = DefaultAssessPhaseMax
	}
	if cfg.AssessPhaseMax < 0 || cfg.AssessPhaseMax > HardMaxAssessPhaseMax {
		return nil, fmt.Errorf("assessment phase outside 0..%s: %w", HardMaxAssessPhaseMax, ErrConfig)
	}
	if cfg.LLM.Limits == (agent.Limits{}) {
		cfg.LLM.Limits = agent.DefaultLimits()
	}
	if cfg.LLM.Language == "" {
		cfg.LLM.Language = agent.LanguageDE
	}
	if err := checkLocalLLM(cfg.LLM); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	feeds := cfg.Feeds
	if feeds == nil {
		feeds = vulnfeed.Feeds()
	}
	for _, p := range cfg.CSAF {
		if p.Keys == nil || p.Feed.Name == "" {
			return nil, fmt.Errorf("csaf provider without feed or keys: %w", ErrConfig)
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	store, err := vulnfeed.OpenStore(filepath.Join(cfg.DataDir, feedsDir), cfg.Now)
	if err != nil {
		return nil, fmt.Errorf("open feed store: %w", err)
	}
	syncer, err := vulnfeed.NewSyncer(cfg.Fetcher, store)
	if err != nil {
		return nil, fmt.Errorf("feed syncer: %w", err)
	}
	cc, err := vulnfeed.NewCSAFClient(cfg.Fetcher, cfg.Now)
	if err != nil {
		return nil, fmt.Errorf("csaf client: %w", err)
	}
	return &Runner{cfg: cfg, feeds: feeds, store: store, sync: syncer, csaf: cc, log: log, now: cfg.Now}, nil
}

// Data directory layout.
const (
	feedsDir    = "feeds"
	csafDir     = "csaf"
	evidenceDir = "evidence"
	scratchDir  = "scratch"
)

// Run makes one agent run in mode. The report is returned also on error
// (as far as the run got) and is written to the evidence directory.
func (r *Runner) Run(ctx context.Context, mode Mode) (*Report, error) {
	switch mode {
	case ModeRun, ModeDryRun:
		if r.cfg.NOS == nil {
			return nil, fmt.Errorf("mode %s needs a NOS client: %w", mode, ErrConfig)
		}
	case ModeSyncOnly:
	default:
		return nil, fmt.Errorf("unknown mode: %w", ErrConfig)
	}
	rep := &Report{Mode: mode, StartedAt: r.now().UTC()}
	r.log.Info("run started", "mode", string(mode))
	err := r.run(ctx, mode, rep)
	rep.FinishedAt = r.now().UTC()
	if err != nil {
		rep.Error = cleanText(err.Error(), maxEvidenceText)
	}
	if werr := r.writeEvidence(rep); werr != nil {
		r.log.Error("write run evidence", "error", werr)
	}
	r.logSummary(rep)
	return rep, err
}

func (r *Runner) run(ctx context.Context, mode Mode, rep *Report) error {
	// Phase 1: feed sync.
	r.syncFeeds(ctx, rep)
	if mode == ModeSyncOnly {
		return nil
	}
	// Phase 2: export read.
	parts, snap, err := r.export(ctx)
	if err != nil {
		return err
	}
	rep.InventorySnapshotID = snap.ID
	rep.Subjects = len(snap.Subjects)
	// Phase 3: matching on the pinned local snapshots.
	m, err := r.match(ctx, parts, rep)
	if err != nil {
		return err
	}
	// Phase 4: optional assessment, bounded by AssessPhaseMax.
	r.assess(ctx, m, rep)
	// Phase 5: run protocol, or the printout of a dry run.
	if mode == ModeDryRun {
		return r.printRecords(m, rep)
	}
	return r.upload(ctx, snap, m, rep)
}
