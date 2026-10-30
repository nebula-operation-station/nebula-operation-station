// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The pvecollect Importer (ADR 0006, P1-10) is the server-side reader of the
// spool: it revalidates every spooled observation with the same checks the
// collector applies on write (flat name, regular file, size limit, strict
// decode, name/document match), rejects replays, and feeds the surviving
// observations into the pveinventory store. The server never talks to PVE
// itself; the spool is its only input.
//
// The spool is a one-shot handoff: every file is removed after it has been
// processed (imported, partial, replayed or rejected). The collector
// re-collects each remote within one interval, and a kept file could never
// be re-applied once the store's collection watermark has advanced, so
// keeping it would only grow the spool.

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// fileOutcome is the processing result of one spool file.
type fileOutcome int

const (
	// fileImported means the observation was ingested without dataset
	// errors.
	fileImported fileOutcome = iota
	// filePartial means the observation was ingested with at least one
	// dataset error; the applied datasets are kept.
	filePartial
	// fileReplayed means the observation was rejected as a replay or a
	// stale collection.
	fileReplayed
	// fileRejected means the file failed read-side validation or ingest
	// validation and nothing was applied.
	fileRejected
)

// ImportReport summarizes one ImportOnce pass.
type ImportReport struct {
	// Files is the number of spool files seen.
	Files int
	// Imported is the number of observations ingested without dataset
	// errors.
	Imported int
	// Partial is the number of observations ingested with at least one
	// dataset error.
	Partial int
	// Replayed is the number of observations rejected as replay or stale.
	Replayed int
	// Rejected is the number of files that failed validation and were
	// dropped.
	Rejected int
	// Errors carries one short line per partial or rejected file.
	Errors []string
}

// Importer reads the spool and feeds observations into the PVE inventory
// store. It is safe for use by a single Run loop.
type Importer struct {
	spool *Spool
	store *pveinventory.Store
	log   *slog.Logger
}

// NewImporter builds an Importer. spool and store must be non-nil; a nil
// log is replaced with a discard logger.
func NewImporter(spool *Spool, store *pveinventory.Store, log *slog.Logger) (*Importer, error) {
	if spool == nil {
		return nil, errors.New("pvecollect: spool is nil")
	}
	if store == nil {
		return nil, errors.New("pvecollect: store is nil")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Importer{spool: spool, store: store, log: log}, nil
}

// ImportOnce processes every spool file: revalidate, replay-check, ingest,
// remove. Per-file failures are recorded in the report and do not abort the
// pass. It returns an error only when the spool itself cannot be listed.
func (im *Importer) ImportOnce(ctx context.Context) (ImportReport, error) {
	names, err := im.spool.List(ctx)
	if err != nil {
		return ImportReport{}, fmt.Errorf("pvecollect: list spool: %w", err)
	}
	rep := ImportReport{Files: len(names)}
	for _, name := range names {
		outcome, msg := im.importFile(ctx, name)
		switch outcome {
		case fileImported:
			rep.Imported++
		case filePartial:
			rep.Partial++
			rep.Errors = append(rep.Errors, name+": "+msg)
		case fileReplayed:
			rep.Replayed++
		case fileRejected:
			rep.Rejected++
			rep.Errors = append(rep.Errors, name+": "+msg)
		}
	}
	return rep, nil
}

// Run imports the spool every interval until ctx is cancelled. The first
// pass runs immediately. It returns nil when ctx is done.
func (im *Importer) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if rep, err := im.ImportOnce(ctx); err != nil {
			im.log.Warn("pvecollect: import pass failed", "error", err)
		} else if rep.Files > 0 {
			im.log.Info("pvecollect: import pass",
				"files", rep.Files, "imported", rep.Imported,
				"partial", rep.Partial, "replayed", rep.Replayed,
				"rejected", rep.Rejected)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// importFile processes one spool file and always removes it afterwards.
// The returned message is short and safe to log: it comes from the spool's
// own validation errors or the store's ingest summary, never from raw file
// content.
func (im *Importer) importFile(ctx context.Context, name string) (fileOutcome, string) {
	// ReadFile revalidates everything the collector checked on write:
	// name shape, regular file, size limit, strict decode, and that the
	// document matches its file name.
	obs, err := im.spool.ReadFile(ctx, name)
	if err != nil {
		im.drop(ctx, name, err)
		return fileRejected, err.Error()
	}
	// Fast in-memory replay guard; the store's transactional freshness
	// check is the durable one.
	if err := im.spool.CheckReplay(obs); err != nil {
		im.drop(ctx, name, err)
		return fileReplayed, err.Error()
	}
	irep, err := im.store.IngestObservation(ctx, obs)
	switch {
	case err == nil:
		im.drop(ctx, name, nil)
		return fileImported, ""
	case errors.Is(err, pveinventory.ErrStaleObservation):
		im.drop(ctx, name, err)
		return fileReplayed, err.Error()
	case len(irep.Errors) > 0:
		// Per-dataset failures: the applied datasets are committed, the
		// failed ones are recorded in the report. The file is dropped
		// because the collection watermark has advanced and a retry
		// would be rejected as stale.
		im.drop(ctx, name, err)
		return filePartial, err.Error()
	default:
		// Whole-observation validation failed; nothing was applied.
		im.drop(ctx, name, err)
		return fileRejected, err.Error()
	}
}

// drop removes a processed spool file. A removal failure is logged, not
// fatal: the next pass reprocesses the file, which is safe because ingest
// is idempotent and stale files are rejected.
func (im *Importer) drop(ctx context.Context, name string, why error) {
	if err := im.spool.Remove(ctx, name); err != nil {
		im.log.Warn("pvecollect: remove spool file", "file", name, "error", err)
		return
	}
	if why != nil {
		im.log.Info("pvecollect: dropped spool file", "file", name, "reason", why)
	}
}
