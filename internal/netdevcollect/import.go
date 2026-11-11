// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

// The Importer (ADR 0010 D4, plan ND-16 part 2) is the nebula-server side
// of the spool. It mirrors internal/pvecollect/importer.go:
//
//   - two phases: a record is taken (read and revalidated, the file stays),
//     validated, stored with Store.ReplaceDataset, and only after that
//     transaction committed is the file confirmed (removed). A crash or a
//     failed confirm leaves the file; the next pass stores the same dataset
//     again, which the store treats as an idempotent redelivery;
//   - validation before writing: the spool revalidates the record (name,
//     owner, mode, size, strict decode, closed set of reads), the payload
//     is strictly decoded into its typed executor message and mapped onto
//     netdevinventory rows, and the store checks the device, its family and
//     trust generation and every row against netdevcontract inside its
//     write transaction;
//   - a fault of the record itself is never retried: the file moves to the
//     kept/ subdirectory with a <name>.reason file holding a fixed reason
//     code, so an operator can look at it. A replayed or superseded record
//     is removed, as pvecollect drops replays;
//   - a failure that says nothing about the record (an unreadable file, a
//     database error) leaves the file for a retry. A store failure halts
//     the device for the rest of the pass, so its later records can never
//     overtake the failed one, and its retries back off;
//   - while a device has a store failure on record its spool stays
//     bounded: per read, files beyond the newest MaxPendingPerRead are
//     removed once a newer file of the read was judged valid (taken and
//     decoded), as pvecollect does with maxKeptPerRemote.
//
// Records are processed oldest observation first (Spool.List order), at
// most MaxRecordsPerRun per pass. Logs carry file names (which follow the
// strict spool grammar) and fixed codes only, never payload or error text
// from decoders, validators or the database.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	// MaxRecordsPerRun bounds the records one Run stores; the rest wait
	// for the next pass.
	MaxRecordsPerRun = 512
	// KeptDirName is the spool subdirectory that holds rejected records.
	KeptDirName = "kept"
	// MaxKeptFiles bounds the rejected records kept/ holds. Beyond it a
	// rejected record is removed instead, with the same logged reason.
	MaxKeptFiles = 1000
	// keptReasonSuffix names the reason file next to a kept record.
	keptReasonSuffix = ".reason"
	// keptDirMode is the mode the importer creates kept/ with.
	keptDirMode = 0o750
	// keptReasonMode is the mode of a reason file.
	keptReasonMode = 0o640
	// importRetryBase is the delay after the second store failure of a
	// device in a row; the first is retried on the next pass.
	importRetryBase = time.Minute
	// importRetryMax caps the store retry delay of a device.
	importRetryMax = 5 * time.Minute
	// MaxPendingPerRead bounds the spool files of one (device, read) that a
	// device with a store failure on record keeps, like pvecollect's
	// maxKeptPerRemote. Older files of that read are removed as superseded
	// once a newer one was judged valid: every read is a full snapshot of
	// its dataset or part, and the store would refuse the older one after
	// the newer one anyway. Until a newer file is judged valid the older
	// ones may hold the last valid read and stay. A pass judges at most
	// this many files per read.
	MaxPendingPerRead = 3
)

// Fixed reason codes of kept or removed records.
const (
	ReasonInvalidRecord          = "invalid_record"
	ReasonInvalidPayload         = "invalid_payload"
	ReasonInvalidRows            = "invalid_rows"
	ReasonUnknownDevice          = "unknown_device"
	ReasonWrongFamily            = "wrong_family"
	ReasonTrustGenerationChanged = "trust_generation_changed"
	ReasonObservationTooOld      = "observation_too_old"
	ReasonFutureObservation      = "future_observation"
	ReasonReplayed               = "replayed_record"
	ReasonSuperseded             = "superseded_record"
)

// Sentinel errors of the importer.
var (
	// ErrImporterNotConfigured means an Importer lacks Spool, Store or Now.
	ErrImporterNotConfigured = errors.New("netdevcollect: importer is not configured")
	// ErrKeptDir means the kept/ subdirectory is not usable: not a
	// directory, a symlink, or not owned by this process.
	ErrKeptDir = errors.New("netdevcollect: kept directory is not usable")
	// ErrKeptFull means kept/ already holds MaxKeptFiles records.
	ErrKeptFull = errors.New("netdevcollect: kept directory is full")
)

// DatasetStore is the part of *netdevinventory.Store the importer writes
// through.
type DatasetStore interface {
	ReplaceDataset(ctx context.Context, deviceID string, read netdevinventory.Read, trustGeneration uint64,
		observedAt time.Time, incomplete bool, rows netdevinventory.Rows) (netdevinventory.ReplaceResult, error)
}

// ImportReport summarizes one Run.
type ImportReport struct {
	// Files is the number of spool files listed.
	Files int
	// Imported counts records stored and confirmed.
	Imported int
	// Unchanged counts imported records that stored nothing new (an
	// identical payload or a redelivery).
	Unchanged int
	// Replayed counts records removed as replays or superseded by a newer
	// stored dataset.
	Replayed int
	// Kept counts records moved to kept/ (or removed when kept/ was full
	// or unusable) because the record itself is at fault.
	Kept int
	// Retry counts records the store failed on; they stay for a retry.
	Retry int
	// Failed counts records that could not be read or confirmed; they stay.
	Failed int
	// Deferred counts records left for a later pass: their device is
	// halted or backing off, or the pass reached MaxRecordsPerRun.
	Deferred int
	// Pruned counts records of a device with a store failure on record
	// removed because a newer record of the same read, judged valid, waits
	// in the spool (see MaxPendingPerRead).
	Pruned int
	// Errors holds one "<file>: <code>" line per kept, retried or failed
	// record.
	Errors []string
}

// Importer moves spooled read results into the netdev inventory store.
// Spool, Store and Now are required; Log may be nil. Run must not be
// copied after first use; concurrent Runs are serialized.
type Importer struct {
	Spool *Spool
	Store DatasetStore
	Now   func() time.Time
	Log   *slog.Logger

	mu sync.Mutex
	// backoff holds the store retry state of devices whose last store
	// attempt failed.
	backoff map[string]importBackoff
	// unmoved holds rejected records whose move and removal both failed;
	// later passes only retry that, never the import.
	unmoved map[string]string
}

type importBackoff struct {
	notBefore time.Time
	delay     time.Duration
	// valid maps a spool read to the newest file of it judged valid (taken
	// and decoded) that still waits in the spool.
	valid map[string]string
}

// spoolDiscard removes a spool file. Tests replace it to simulate a
// failing removal.
var spoolDiscard = (*Spool).Discard

// spoolReadEnum maps a spool read name to its typed executor read.
var spoolReadEnum = func() map[string]pb.NetDeviceRead {
	m := make(map[string]pb.NetDeviceRead, len(spoolReadName))
	for k, v := range spoolReadName {
		m[v] = k
	}
	return m
}()

type importOutcome int

const (
	outcomeDone importOutcome = iota
	outcomeStored
	outcomeStoreFailed
	outcomeInterrupted
)

func (im *Importer) log() *slog.Logger {
	if im.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return im.Log
}

// Run processes the oldest spool records once. It returns an error only
// when the importer is not configured, the spool cannot be listed or ctx
// ends; per-record failures are counted in the report.
func (im *Importer) Run(ctx context.Context) (ImportReport, error) {
	if im.Spool == nil || im.Store == nil || im.Now == nil {
		return ImportReport{}, ErrImporterNotConfigured
	}
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.backoff == nil {
		im.backoff = map[string]importBackoff{}
		im.unmoved = map[string]string{}
	}
	names, err := im.Spool.List(ctx)
	if err != nil {
		return ImportReport{}, fmt.Errorf("netdevcollect: import: %w", err)
	}
	listed := make(map[string]struct{}, len(names))
	devices := map[string]struct{}{}
	for _, name := range names {
		listed[name] = struct{}{}
		if n, err := parseSpoolName(name); err == nil {
			devices[n.device] = struct{}{}
		}
	}
	for name := range im.unmoved {
		if _, ok := listed[name]; !ok {
			delete(im.unmoved, name)
		}
	}
	for dev := range im.backoff {
		if _, ok := devices[dev]; !ok {
			delete(im.backoff, dev)
		}
	}

	rep := ImportReport{Files: len(names)}
	now := im.Now()
	handled, err := im.pruneSuperseded(ctx, names, &rep)
	if err != nil {
		return rep, err
	}
	halted := map[string]struct{}{}
	taken := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		if _, ok := handled[name]; ok {
			continue
		}
		if reason, ok := im.unmoved[name]; ok {
			im.reject(ctx, name, reason, &rep)
			continue
		}
		n, err := parseSpoolName(name)
		if err != nil {
			continue // List only returns well-formed names
		}
		_, stop := halted[n.device]
		if stop || now.Before(im.backoff[n.device].notBefore) || taken >= MaxRecordsPerRun {
			rep.Deferred++
			continue
		}
		taken++
		switch im.importOne(ctx, name, &rep) {
		case outcomeStored:
			delete(im.backoff, n.device)
		case outcomeStoreFailed:
			halted[n.device] = struct{}{}
			b := im.backoff[n.device]
			b.notBefore = now.Add(b.delay)
			b.delay = min(max(2*b.delay, importRetryBase), importRetryMax)
			// The record reached the store, so it decoded: it is valid.
			b.judgedValid(n.read, name)
			im.backoff[n.device] = b
		case outcomeInterrupted:
			return rep, ctx.Err()
		}
	}
	if rep.Retry+rep.Failed+rep.Kept+rep.Pruned > 0 {
		im.log().Warn("netdev import: records not imported", "kept", rep.Kept, "store_failed", rep.Retry,
			"read_failed", rep.Failed, "deferred", rep.Deferred, "pruned", rep.Pruned)
	}
	return rep, nil
}

// judgedValid records name as a valid file of read if it is the newest so
// far.
func (b *importBackoff) judgedValid(read, name string) {
	if b.valid == nil {
		b.valid = map[string]string{}
	}
	if v, ok := b.valid[read]; !ok || spoolBefore(v, name) {
		b.valid[read] = name
	}
}

// spoolBefore reports whether spool file a comes before b in Spool.List
// order (observation time, then name).
func spoolBefore(a, b string) bool {
	na, errA := parseSpoolName(a)
	nb, errB := parseSpoolName(b)
	if errA != nil || errB != nil {
		return false
	}
	if na.nanos != nb.nanos {
		return na.nanos < nb.nanos
	}
	return a < b
}

// pruneSuperseded bounds the spool of every device with a store failure on
// record (MaxPendingPerRead): per read, the newest files are judged newest
// first until one is valid, and files beyond the newest MaxPendingPerRead
// that are older than it are removed as superseded. Files a judgement
// rejected or dropped are handled too. It returns every handled name, which
// the pass must not process again; its error is only ever ctx's.
func (im *Importer) pruneSuperseded(ctx context.Context, names []string, rep *ImportReport) (map[string]struct{}, error) {
	handled := map[string]struct{}{}
	if len(im.backoff) == 0 {
		return handled, nil
	}
	runs := map[string][]string{}
	var keys []string
	for _, name := range names {
		if _, ok := im.unmoved[name]; ok {
			continue
		}
		n, err := parseSpoolName(name)
		if err != nil {
			continue
		}
		if _, failing := im.backoff[n.device]; !failing {
			continue
		}
		if _, ok := runs[n.key()]; !ok {
			keys = append(keys, n.key())
		}
		runs[n.key()] = append(runs[n.key()], name) // oldest first, as listed
	}
	for _, k := range keys {
		run := runs[k]
		if len(run) <= MaxPendingPerRead {
			continue
		}
		n, _ := parseSpoolName(run[0])
		b := im.backoff[n.device]
		valid := b.valid[n.read]
		if !slices.Contains(run, valid) {
			valid = "" // that file left the spool
		}
		for i, judged := len(run)-1, 0; i >= 0 && judged < MaxPendingPerRead; i-- {
			if valid != "" && !spoolBefore(valid, run[i]) {
				break // a valid file at least this new is known
			}
			judged++
			j, err := im.judge(ctx, run[i], rep)
			if err != nil {
				return handled, err
			}
			if j == judgeHandled {
				handled[run[i]] = struct{}{}
				continue
			}
			if j == judgeValid {
				valid = run[i]
				break
			}
		}
		if valid == "" {
			continue
		}
		b.judgedValid(n.read, valid)
		im.backoff[n.device] = b
		for _, name := range run[:len(run)-MaxPendingPerRead] {
			if _, ok := handled[name]; ok || !spoolBefore(name, valid) {
				continue
			}
			if err := spoolDiscard(im.Spool, ctx, name); err != nil {
				if ctx.Err() != nil {
					return handled, ctx.Err()
				}
				rep.Failed++
				rep.Errors = append(rep.Errors, name+": remove_failed")
				continue
			}
			handled[name] = struct{}{}
			rep.Pruned++
			im.log().Info("netdev import: record removed", "file", name, "reason", ReasonSuperseded)
		}
	}
	return handled, nil
}

type judgement int

const (
	// judgeUnread: the file could not be read; nothing is known.
	judgeUnread judgement = iota
	// judgeValid: the record is taken and its payload decodes.
	judgeValid
	// judgeHandled: the record was rejected or dropped as a replay.
	judgeHandled
)

// judge takes and decodes one record without storing it. A record at
// fault is rejected and a replay dropped, as importOne would. Its error is
// only ever ctx's.
func (im *Importer) judge(ctx context.Context, name string, rep *ImportReport) (judgement, error) {
	t, err := im.Spool.Take(ctx, name)
	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidRecord), errors.Is(err, ErrBadName):
		im.reject(ctx, name, ReasonInvalidRecord, rep)
		return judgeHandled, nil
	case errors.Is(err, ErrReplayed):
		im.drop(ctx, name, ReasonReplayed, rep)
		return judgeHandled, nil
	case ctx.Err() != nil:
		return judgeUnread, ctx.Err()
	default:
		return judgeUnread, nil
	}
	read, ok := spoolReadEnum[t.Record.Read]
	if !ok {
		im.reject(ctx, name, ReasonInvalidRecord, rep)
		return judgeHandled, nil
	}
	if _, err := netdevinventory.DecodePayload(read, t.Record.Data); err != nil {
		im.reject(ctx, name, ReasonInvalidPayload, rep)
		return judgeHandled, nil
	}
	return judgeValid, nil
}

// importOne takes, validates, stores and confirms one record.
func (im *Importer) importOne(ctx context.Context, name string, rep *ImportReport) importOutcome {
	t, err := im.Spool.Take(ctx, name)
	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidRecord), errors.Is(err, ErrBadName):
		im.reject(ctx, name, ReasonInvalidRecord, rep)
		return outcomeDone
	case errors.Is(err, ErrReplayed):
		im.drop(ctx, name, ReasonReplayed, rep)
		return outcomeDone
	case ctx.Err() != nil:
		return outcomeInterrupted
	default:
		rep.Failed++
		rep.Errors = append(rep.Errors, name+": read_failed")
		return outcomeDone
	}
	rec := t.Record
	read, ok := spoolReadEnum[rec.Read]
	if !ok {
		im.reject(ctx, name, ReasonInvalidRecord, rep)
		return outcomeDone
	}
	rows, err := netdevinventory.DecodePayload(read, rec.Data)
	if err != nil {
		im.reject(ctx, name, ReasonInvalidPayload, rep)
		return outcomeDone
	}
	res, err := im.Store.ReplaceDataset(ctx, rec.DeviceID, rows.Read(), rec.TrustGeneration, rec.ObservedAt,
		rec.Incomplete, rows)
	if err == nil {
		// The dataset is committed; only now may the file go. If the confirm
		// fails, the file stays and the next pass redelivers the dataset.
		if err := t.Confirm(ctx); err != nil {
			if ctx.Err() != nil {
				return outcomeInterrupted
			}
			rep.Failed++
			rep.Errors = append(rep.Errors, name+": confirm_failed")
			return outcomeDone
		}
		rep.Imported++
		if res.Unchanged {
			rep.Unchanged++
		}
		return outcomeStored
	}
	if ctx.Err() != nil {
		return outcomeInterrupted
	}
	if errors.Is(err, netdevinventory.ErrOutOfOrder) {
		im.drop(ctx, name, ReasonSuperseded, rep)
		return outcomeDone
	}
	if reason, ok := storeRejection(err); ok {
		im.reject(ctx, name, reason, rep)
		return outcomeDone
	}
	// Anything else lies with the store, not the record: the file stays.
	rep.Retry++
	rep.Errors = append(rep.Errors, name+": store_failed")
	return outcomeStoreFailed
}

// storeRejection maps a store error that condemns the record to its fixed
// reason code.
func storeRejection(err error) (string, bool) {
	switch {
	case errors.Is(err, netdevinventory.ErrDeviceNotFound):
		return ReasonUnknownDevice, true
	case errors.Is(err, netdevinventory.ErrWrongFamily):
		return ReasonWrongFamily, true
	case errors.Is(err, netdevinventory.ErrTrustGenerationChanged):
		return ReasonTrustGenerationChanged, true
	case errors.Is(err, netdevinventory.ErrObservationTooOld):
		return ReasonObservationTooOld, true
	case errors.Is(err, netdevinventory.ErrFutureObservation):
		return ReasonFutureObservation, true
	case errors.Is(err, netdevinventory.ErrInvalidRows), errors.Is(err, netdevinventory.ErrRowsMismatch),
		errors.Is(err, netdevinventory.ErrUnknownRead):
		return ReasonInvalidRows, true
	}
	return "", false
}

// reject moves a record that is at fault to kept/ with its reason. When
// kept/ is full or unusable the record is removed instead; when that fails
// too, later passes retry only this, never the import.
func (im *Importer) reject(ctx context.Context, name, reason string, rep *ImportReport) {
	err := im.Spool.moveToKept(ctx, name, reason)
	if err != nil {
		if derr := spoolDiscard(im.Spool, ctx, name); derr != nil {
			im.unmoved[name] = reason
			rep.Failed++
			rep.Errors = append(rep.Errors, name+": keep_failed")
			return
		}
		im.log().Warn("netdev import: rejected record removed, kept/ unavailable", "file", name, "reason", reason)
	} else {
		im.log().Info("netdev import: record kept", "file", name, "reason", reason)
	}
	delete(im.unmoved, name)
	rep.Kept++
	rep.Errors = append(rep.Errors, name+": "+reason)
}

// drop removes a replayed or superseded record.
func (im *Importer) drop(ctx context.Context, name, reason string, rep *ImportReport) {
	if err := spoolDiscard(im.Spool, ctx, name); err != nil {
		rep.Failed++
		rep.Errors = append(rep.Errors, name+": remove_failed")
		return
	}
	rep.Replayed++
	im.log().Info("netdev import: record removed", "file", name, "reason", reason)
}

// moveToKept writes <name>.reason into kept/ and then renames the record
// there, never replacing a kept record. A reason file left by an
// interrupted earlier attempt is replaced with the current reason.
func (s *Spool) moveToKept(ctx context.Context, name, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := parseSpoolName(name); err != nil {
		return err
	}
	dir, err := s.openDir(false)
	if err != nil {
		return err
	}
	defer dir.Close()
	kept, err := openKeptDir(dir)
	if err != nil {
		return err
	}
	defer kept.Close()
	entries, err := kept.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("netdevcollect: list %s: %w", KeptDirName, err)
	}
	if len(entries) >= 2*MaxKeptFiles {
		return ErrKeptFull
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("netdevcollect: keep %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s", errNonRegular, name)
	}
	// A reason file left by an interrupted earlier attempt may name another
	// reason: replace it. Unlinking first (never opening the old entry)
	// keeps a planted FIFO or symlink from being opened.
	reasonName := name + keptReasonSuffix
	if err := unix.Unlinkat(int(kept.Fd()), reasonName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("netdevcollect: keep %s: replace reason: %w", name, err)
	}
	fd, err := unix.Openat(int(kept.Fd()), reasonName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, keptReasonMode)
	if err != nil {
		return fmt.Errorf("netdevcollect: keep %s: create reason: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), reasonName)
	_, werr := f.WriteString("reason: " + reason + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	f.Close()
	if werr != nil {
		return fmt.Errorf("netdevcollect: keep %s: write reason: %w", name, werr)
	}
	if err := unix.Renameat2(int(dir.Fd()), name, int(kept.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("netdevcollect: keep %s: %w", name, err)
		}
		// Already kept under this unique name: drop the duplicate entry.
		if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
			return fmt.Errorf("netdevcollect: keep %s: %w", name, err)
		}
	}
	if err := kept.Sync(); err != nil {
		return fmt.Errorf("netdevcollect: keep %s: sync %s: %w", name, KeptDirName, err)
	}
	return dir.Sync()
}

// openKeptDir creates (if needed) and opens kept/ below the pinned spool
// directory without following a symlink. It must be owned by this process
// and not writable by others.
func openKeptDir(dir *os.File) (*os.File, error) {
	if err := unix.Mkdirat(int(dir.Fd()), KeptDirName, keptDirMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("netdevcollect: create %s: %w", KeptDirName, err)
	}
	fd, err := unix.Openat(int(dir.Fd()), KeptDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", ErrKeptDir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: stat: %w", ErrKeptDir, err)
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o002 != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: foreign owner or world-writable", ErrKeptDir)
	}
	return os.NewFile(uintptr(fd), KeptDirName), nil
}
