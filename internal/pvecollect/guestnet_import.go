// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// GuestNetClockSkew bounds how far in the future a record's observation
// time may lie relative to the importer's clock.
const GuestNetClockSkew = 5 * time.Minute

// ErrGuestNetStale is returned (wrapped) by a GuestNetSink for a record
// older than what it already holds or outside its retention; the
// importer drops such a record as replayed.
var ErrGuestNetStale = errors.New("pvecollect: stale guest nic record")

// GuestNetSink receives validated guest NIC records on the server side,
// for example the traffic store's provider guest links
// (GuestNetStoreSink). A sink must treat the record as the collector's
// claim about the remote, not as inventory. An error wrapping
// ErrGuestNetStale or ErrGuestNetInvalid makes the importer drop the
// record; any other error keeps it for the next pass.
type GuestNetSink interface {
	ImportGuestNet(ctx context.Context, rec GuestNetRecord) error
}

// GuestNetImportReport summarizes one GuestNetImporter.ImportOnce pass.
type GuestNetImportReport struct {
	// Files is the number of pending records seen.
	Files int
	// Imported is the number of records the sink accepted.
	Imported int
	// Replayed is the number of records not newer than the last imported
	// record of their remote; they are dropped.
	Replayed int
	// Rejected is the number of records that failed validation or were
	// dated in the future; they are dropped.
	Rejected int
	// Failed is the number of records the sink refused; they stay for the
	// next pass.
	Failed int
}

// GuestNetImporter is the server side of the guest NIC handoff: it only
// lists, reads and unlinks spool files and never contacts Proxmox. It is
// meant for a single import loop.
type GuestNetImporter struct {
	spool *Spool
	sink  GuestNetSink
	log   *slog.Logger
	// Now is the importer's clock; it defaults to time.Now.
	Now func() time.Time
	// seen is the last imported observation time per remote.
	seen map[string]int64
}

// NewGuestNetImporter builds an importer on a server-side spool. spool and
// sink must be non-nil; a nil log is replaced with a discard logger.
func NewGuestNetImporter(spool *Spool, sink GuestNetSink, log *slog.Logger) (*GuestNetImporter, error) {
	if spool == nil {
		return nil, errors.New("pvecollect: spool is nil")
	}
	if sink == nil {
		return nil, errors.New("pvecollect: guest nic sink is nil")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &GuestNetImporter{spool: spool, sink: sink, log: log, Now: time.Now, seen: make(map[string]int64)}, nil
}

// ImportOnce processes every pending record in name order (per remote,
// oldest first). Per-file outcomes are counted and do not abort the pass;
// it returns an error only when the directory cannot be listed, including
// a symlinked entry (tampering).
func (im *GuestNetImporter) ImportOnce(ctx context.Context) (GuestNetImportReport, error) {
	names, err := im.spool.ListGuestNet(ctx)
	if err != nil {
		return GuestNetImportReport{}, fmt.Errorf("pvecollect: list guest nic records: %w", err)
	}
	rep := GuestNetImportReport{Files: len(names)}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		rec, err := im.spool.ReadGuestNet(ctx, name)
		if err != nil {
			rep.Rejected++
			im.drop(ctx, name, "invalid_record")
			continue
		}
		if rec.ObservedUnix > im.Now().Add(GuestNetClockSkew).Unix() {
			rep.Rejected++
			im.drop(ctx, name, "future_record")
			continue
		}
		if last, ok := im.seen[rec.Remote]; ok && rec.ObservedUnix <= last {
			rep.Replayed++
			im.drop(ctx, name, "replayed_record")
			continue
		}
		if err := im.sink.ImportGuestNet(ctx, rec); err != nil {
			// The sink's error text may quote record values, so only a
			// fixed code is logged.
			switch {
			case errors.Is(err, ErrGuestNetStale):
				rep.Replayed++
				im.drop(ctx, name, "stale_record")
				continue
			case errors.Is(err, ErrGuestNetInvalid):
				rep.Rejected++
				im.drop(ctx, name, "sink_rejected")
				continue
			}
			// Kept for the next pass.
			rep.Failed++
			im.log.Warn("pvecollect: guest nic import failed", "file", name, "reason", "sink_failed")
			continue
		}
		im.seen[rec.Remote] = rec.ObservedUnix
		rep.Imported++
		im.drop(ctx, name, "")
	}
	return rep, nil
}

// drop removes a processed record. A removal failure is logged; the next
// pass sees the file again and drops it as replayed or invalid. File names
// are logged only after parsing, so they match the fixed name pattern.
func (im *GuestNetImporter) drop(ctx context.Context, name, reason string) {
	if err := im.spool.RemoveGuestNet(ctx, name); err != nil {
		im.log.Warn("pvecollect: remove guest nic record", "file", name, "reason", "remove_failed")
		return
	}
	if reason != "" {
		im.log.Info("pvecollect: dropped guest nic record", "file", name, "reason", reason)
	}
}
