// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Evidence limits.
const (
	// maxEvidenceText bounds one text field of the evidence (errors,
	// reasons, untrusted provider strings).
	maxEvidenceText = 256
	// MaxRejectedDocs bounds the rejected documents kept per run.
	MaxRejectedDocs = 100
	// MaxEvidenceFiles is the number of run evidence files kept.
	MaxEvidenceFiles = 30
)

// Source statuses in the evidence.
const (
	SourceUpdated     = "updated"
	SourceNotModified = "not_modified"
	SourceFailed      = "failed"
	SourceSkipped     = "skipped"
)

// SourceEvidence is the sync outcome of one feed.
type SourceEvidence struct {
	Feed      string                    `json:"feed"`
	SourceID  string                    `json:"source_id"`
	Status    string                    `json:"status"`
	Integrity vulnfinding.IntegrityMode `json:"integrity"`
	// SnapshotID and ContentDate describe the snapshot in use after the
	// sync (the previous one when the sync failed); empty when none.
	SnapshotID  string    `json:"snapshot_id,omitempty"`
	ContentDate time.Time `json:"content_date,omitzero"`
	// Error is the sanitised failure reason.
	Error string `json:"error,omitempty"`
}

// RejectedDoc is one signed document the sync rejected.
type RejectedDoc struct {
	Feed       string `json:"feed"`
	TrackingID string `json:"tracking_id,omitempty"`
	URL        string `json:"url,omitempty"`
	Reason     string `json:"reason"`
}

// RunSource is one source as the run named it at start.
type RunSource struct {
	SourceID    string    `json:"source_id"`
	SnapshotID  string    `json:"snapshot_id"`
	DateKind    string    `json:"date_kind"`
	ContentDate time.Time `json:"content_date,omitzero"`
	Feeds       []string  `json:"feeds"`
}

// LLMEvidence says whether and how the assessor ran.
type LLMEvidence struct {
	Enabled bool `json:"enabled"`
	// Origin is "nos" when the settings came from NOS, "local" otherwise.
	Origin string `json:"origin"`
	// Model and Host name the endpoint (never a credential).
	Model string `json:"model,omitempty"`
	Host  string `json:"host,omitempty"`
	// SettingsVersion is the version NOS served.
	SettingsVersion int64  `json:"settings_version,omitempty"`
	Reason          string `json:"reason,omitempty"`
	// Failed: the assessor was off for this run because the NOS settings
	// could not be read or the effective settings or endpoint were
	// refused (fail closed); the run is degraded.
	Failed   bool  `json:"failed,omitempty"`
	Assessed int   `json:"assessed"`
	Calls    int   `json:"calls"`
	Tokens   int64 `json:"tokens"`
}

// Report is the evidence of one run.
type Report struct {
	Mode       Mode      `json:"mode"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Sources       []SourceEvidence `json:"sources"`
	RejectedDocs  []RejectedDoc    `json:"rejected_docs,omitempty"`
	RejectedTotal int              `json:"rejected_total"`

	InventorySnapshotID string      `json:"inventory_snapshot_id,omitempty"`
	Subjects            int         `json:"subjects"`
	RunSources          []RunSource `json:"run_sources,omitempty"`
	MatcherVersion      string      `json:"matcher_version,omitempty"`
	Findings            int         `json:"findings"`
	Gaps                int         `json:"gaps"`
	Withheld            int         `json:"withheld"`
	FeedPartsCut        int         `json:"feed_parts_cut"`
	LLM                 LLMEvidence `json:"llm"`

	RunID           string                `json:"run_id,omitempty"`
	Batches         int                   `json:"batches"`
	SubjectsCovered int                   `json:"subjects_covered"`
	Rejected        int                   `json:"records_rejected"`
	Completion      *nosclient.Completion `json:"completion,omitempty"`
	Printed         int                   `json:"records_printed"`

	Error string `json:"error,omitempty"`
}

// Degraded reports a run that finished but not cleanly: a feed failed to
// sync, a document or record was rejected, a finding was withheld, or the
// assessor failed closed.
func (r *Report) Degraded() bool {
	if r.LLM.Failed {
		return true
	}
	for _, s := range r.Sources {
		if s.Status == SourceFailed {
			return true
		}
	}
	return r.RejectedTotal > 0 || r.Rejected > 0 || r.Withheld > 0
}

func (r *Report) addRejected(d RejectedDoc) {
	r.RejectedTotal++
	if len(r.RejectedDocs) < MaxRejectedDocs {
		r.RejectedDocs = append(r.RejectedDocs, d)
	}
}

// writeEvidence stores the report as one JSON file per run (mode 0600)
// and keeps the newest MaxEvidenceFiles.
func (r *Runner) writeEvidence(rep *Report) error {
	dir := filepath.Join(r.cfg.DataDir, evidenceDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("evidence directory: %w", err)
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	name := rep.StartedAt.Format("20060102T150405.000000000Z") + "-" + string(rep.Mode) + ".json"
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write evidence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("prune evidence: %w", err)
	}
	var files []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			files = append(files, e.Name())
		}
	}
	slices.Sort(files)
	for len(files) > MaxEvidenceFiles {
		if err := os.Remove(filepath.Join(dir, files[0])); err != nil {
			return fmt.Errorf("prune evidence: %w", err)
		}
		files = files[1:]
	}
	return nil
}

// logSummary logs the counts of a run; never a record, text or secret.
func (r *Runner) logSummary(rep *Report) {
	attrs := []any{"mode", string(rep.Mode), "inventory_snapshot", rep.InventorySnapshotID,
		"subjects", rep.Subjects, "findings", rep.Findings, "gaps", rep.Gaps, "withheld", rep.Withheld,
		"feed_parts_cut", rep.FeedPartsCut, "documents_rejected", rep.RejectedTotal,
		"llm_enabled", rep.LLM.Enabled, "assessed", rep.LLM.Assessed,
		"run_id", rep.RunID, "batches", rep.Batches, "subjects_covered", rep.SubjectsCovered,
		"records_rejected", rep.Rejected, "records_printed", rep.Printed,
		"duration", rep.FinishedAt.Sub(rep.StartedAt).String()}
	if rep.Error != "" {
		r.log.Error("run failed", append(attrs, "error", rep.Error)...)
		return
	}
	r.log.Info("run finished", attrs...)
}

// cleanText keeps valid, printable runes of s up to max bytes; others
// become '?'. Used for every untrusted or error string kept as evidence.
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, c := range s {
		if c == utf8.RuneError || !unicode.IsPrint(c) {
			c = '?'
		}
		if b.Len()+utf8.RuneLen(c) > max {
			break
		}
		b.WriteRune(c)
	}
	return b.String()
}
