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
// processed (imported, replayed or rejected). The collector re-collects each
// remote within one interval, and a file could never be re-applied once the
// store's collection watermark has passed it, so keeping such a file would
// only grow the spool. A file that could not be read or that the store failed
// on stays: the failure says nothing about the observation, and its own
// generation may be ingested again, so the next pass retries it until it
// applies or a newer generation supersedes it. Only a fault of the file itself
// (ErrInvalidObservation) rejects it. A processed file that cannot be removed
// is not processed again (stuckFiles); only the unlink is retried. A file
// below its remote's stored generation is dropped by name, unread, so a
// backlog left behind costs no decoding after a restart either. A pass
// interrupted by shutdown leaves its remaining files for the next start.

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
	// filePartial means the store failed at least one dataset; the applied
	// datasets are kept and the file stays for the next pass.
	filePartial
	// fileReplayed means the observation was rejected as a replay or a
	// stale collection.
	fileReplayed
	// fileRejected means the file failed read-side validation or ingest
	// validation and nothing was applied.
	fileRejected
	// fileInterrupted means the context ended during ingest; the file
	// stays for the next run.
	fileInterrupted
	// fileUnread means the file could not be read, which says nothing about
	// it; it stays for the next pass.
	fileUnread
)

// ImportReport summarizes one ImportOnce pass.
type ImportReport struct {
	// Files is the number of spool files seen.
	Files int
	// Imported is the number of observations ingested without dataset
	// errors.
	Imported int
	// Partial is the number of observations the store failed at least one
	// dataset of; their files stay for the next pass.
	Partial int
	// Replayed is the number of observations rejected as replay or stale.
	Replayed int
	// Rejected is the number of files that failed validation and were
	// dropped.
	Rejected int
	// Failed is the number of files that could not be read; they stay for
	// the next pass.
	Failed int
	// Skipped is the number of files this importer processed earlier that
	// could not be removed yet.
	Skipped int
	// Errors carries one short line per partial, rejected or failed file.
	Errors []string
}

// Importer reads the spool and feeds observations into the PVE inventory
// store. It is safe for use by a single Run loop.
type Importer struct {
	spool *Spool
	store *pveinventory.Store
	log   *slog.Logger
	// remove unlinks a processed file; it is Spool.Remove outside tests.
	remove func(context.Context, string) error
	// stuck holds processed files whose removal failed.
	stuck stuckFiles
	// blocked is set for the rest of a pass once the directory refused an
	// unlink; warned once the current stuck files were reported.
	blocked, warned bool
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
	return &Importer{spool: spool, store: store, log: log, remove: spool.Remove, stuck: stuckFiles{}}, nil
}

// ImportOnce processes every spool file: revalidate, replay-check, ingest,
// remove. Files an earlier pass processed but could not remove are only
// removed again, and files below their remote's stored generation are
// dropped unread. Per-file failures are recorded in the report and do not
// abort the pass; a file that could not be read or that the store failed on
// stays for the next pass. It returns an error when the spool itself cannot
// be listed or ctx ends; files not reached stay in the spool.
func (im *Importer) ImportOnce(ctx context.Context) (ImportReport, error) {
	names, err := im.spool.List(ctx)
	if err != nil {
		return ImportReport{}, fmt.Errorf("pvecollect: list spool: %w", err)
	}
	im.stuck.prune(names)
	im.blocked = false
	marks := map[string]uint64{}
	rep := ImportReport{Files: len(names)}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if _, stuck := im.stuck[name]; stuck {
			rep.Skipped++
			im.stuck.unlink(ctx, name, im.remove, &im.blocked)
			continue
		}
		if im.superseded(ctx, name, marks) {
			rep.Replayed++
			im.drop(ctx, name, nil)
			continue
		}
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
		case fileUnread:
			rep.Failed++
			rep.Errors = append(rep.Errors, name+": "+msg)
		}
	}
	im.stuck.warn(im.log, "pvecollect: remove spool file", &im.warned)
	return rep, nil
}

// superseded reports, from the file name alone, whether the store already
// holds a newer generation of the file's remote, which would refuse this
// file as stale anyway. The generation itself is not superseded: an
// interrupted ingest may have advanced the watermark without finishing its
// datasets, so that file still gets its full ingest. marks caches the
// store's answer for one pass; a remote the store cannot answer for is
// processed normally. Only the name's validated remote reaches the store.
func (im *Importer) superseded(ctx context.Context, name string, marks map[string]uint64) bool {
	remote, generation, err := parseSpoolName(name)
	if err != nil {
		return false
	}
	mark, known := marks[remote]
	if !known {
		if r, err := im.store.GetRemote(ctx, remote); err == nil {
			mark = r.LastCollectionGeneration
		}
		marks[remote] = mark
	}
	return generation < mark
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
			if ctx.Err() == nil {
				im.log.Warn("pvecollect: import pass failed", "reason", "spool_unavailable")
			}
		} else if rep.Files > rep.Skipped {
			im.log.Info("pvecollect: import pass",
				"files", rep.Files, "imported", rep.Imported,
				"partial", rep.Partial, "replayed", rep.Replayed,
				"rejected", rep.Rejected, "failed", rep.Failed)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// importFile processes one spool file and removes it afterwards, unless it
// could not be read, ctx ended during ingest or the store failed: the failure
// then does not come from the file, and a retry of the same generation applies
// what is missing.
// The returned message is short and safe to log: it comes from the spool's
// fixed rejection codes, never decoder or validation text.
func (im *Importer) importFile(ctx context.Context, name string) (fileOutcome, string) {
	// ReadFile revalidates everything the collector checked on write:
	// name shape, regular file, size limit, strict decode, and that the
	// document matches its file name.
	obs, err := im.spool.ReadFile(ctx, name)
	if errors.Is(err, ErrInvalidObservation) {
		im.drop(ctx, name, err)
		return fileRejected, "invalid_observation"
	}
	if err != nil {
		im.log.Warn("pvecollect: observation kept for retry", "file", name, "reason", "read_failed")
		return fileUnread, "read_failed"
	}
	// Fast in-memory replay guard; the store's transactional freshness
	// check is the durable one.
	if err := im.spool.CheckReplay(obs); err != nil {
		im.drop(ctx, name, err)
		return fileReplayed, "replayed_observation"
	}
	irep, err := im.store.IngestObservation(ctx, obs)
	switch {
	case err != nil && ctx.Err() != nil:
		return fileInterrupted, ""
	case err == nil:
		im.drop(ctx, name, nil)
		return fileImported, ""
	case errors.Is(err, pveinventory.ErrStaleObservation):
		im.drop(ctx, name, err)
		return fileReplayed, "replayed_observation"
	case len(irep.Errors) > 0:
		// The observation passed validation, so these are store failures.
		// The applied datasets are committed; the file stays, because the
		// watermark admits its own generation and ingest is idempotent, so
		// the next pass applies the failed datasets. Store errors can quote
		// observation values, so only a fixed code is logged.
		im.log.Warn("pvecollect: observation kept for retry", "file", name, "reason", "store_failed")
		return filePartial, "partial_observation"
	default:
		// Whole-observation validation failed; nothing was applied.
		im.drop(ctx, name, err)
		return fileRejected, "invalid_observation"
	}
}

// drop removes a processed spool file. A removal failure is not fatal: the
// file moves to stuck, so later passes only retry the unlink, and the pass
// reports all such files in one warning.
func (im *Importer) drop(ctx context.Context, name string, why error) {
	if im.stuck.unlink(ctx, name, im.remove, &im.blocked) && why != nil {
		im.log.Info("pvecollect: dropped spool file", "file", name, "reason", rejectionCode(why))
	}
}

// rejectionCode deliberately discards error text from all untrusted decoders
// and validators. Only this fixed vocabulary may reach rejection logs.
func rejectionCode(err error) string {
	switch {
	case errors.Is(err, ErrOversize):
		return "oversize_observation"
	case errors.Is(err, ErrSymlink):
		return "symlink_refused"
	case errors.Is(err, ErrReplayed), errors.Is(err, pveinventory.ErrStaleObservation):
		return "replayed_observation"
	default:
		return "invalid_observation"
	}
}
