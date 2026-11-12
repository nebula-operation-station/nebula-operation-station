// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// MaxCSAFStateBytes bounds the stored state of one CSAF provider.
const MaxCSAFStateBytes = 256 << 20

// syncFeeds is run order phase 1. A feed that fails keeps its previous
// snapshot; the failure is recorded and the run goes on. Dated and
// undated feeds go first, so a proxy-dated feed sees its companions'
// new dates.
func (r *Runner) syncFeeds(ctx context.Context, rep *Report) {
	var proxy []vulnfeed.Feed
	for _, f := range r.feeds {
		switch {
		case f.Integrity == vulnfinding.IntegritySigned:
			if r.csafProvider(f.Name) == nil {
				rep.Sources = append(rep.Sources, SourceEvidence{Feed: f.Name, SourceID: f.SourceID, Integrity: f.Integrity,
					Status: SourceSkipped, Error: "no pinned provider keys configured"})
			}
		case f.DateKind == vulnfeed.DateKindProxy:
			proxy = append(proxy, f)
		default:
			rep.Sources = append(rep.Sources, r.syncFeed(ctx, f))
		}
	}
	for _, f := range proxy {
		rep.Sources = append(rep.Sources, r.syncFeed(ctx, f))
	}
	for _, p := range r.cfg.CSAF {
		rep.Sources = append(rep.Sources, r.syncCSAF(ctx, p, rep))
	}
}

func (r *Runner) csafProvider(feed string) *CSAFProvider {
	for i := range r.cfg.CSAF {
		if r.cfg.CSAF[i].Feed.Name == feed {
			return &r.cfg.CSAF[i]
		}
	}
	return nil
}

func (r *Runner) syncFeed(ctx context.Context, f vulnfeed.Feed) SourceEvidence {
	ev := SourceEvidence{Feed: f.Name, SourceID: f.SourceID, Integrity: f.Integrity}
	res, err := r.sync.Sync(ctx, f, vulnfeed.SyncOptions{ContentDate: r.dateFunc(ctx, f.Name)})
	switch {
	case err == nil:
		ev.Status = SourceUpdated
		if res.NotModified {
			ev.Status = SourceNotModified
		}
	case errors.Is(err, vulnfeed.ErrPruneFailed):
		// The snapshot was committed; only the cleanup failed.
		ev.Status = SourceUpdated
		r.log.Warn("feed snapshot prune failed", "feed", f.Name, "error", cleanText(err.Error(), maxEvidenceText))
	default:
		ev.Status = SourceFailed
		ev.Error = cleanText(err.Error(), maxEvidenceText)
		r.log.Warn("feed sync failed, previous snapshot stays in use", "feed", f.Name, "error", ev.Error)
	}
	if m, lerr := r.store.Load(f.Name); lerr == nil {
		ev.SnapshotID, ev.ContentDate = m.SnapshotID(), m.ContentDate
	}
	r.log.Info("feed synced", "feed", f.Name, "source", f.SourceID, "status", ev.Status,
		"snapshot", ev.SnapshotID, "content_date", ev.ContentDate)
	return ev
}

// dateFunc returns the content date extractor of a dated feed: the
// format's own parser, so a file whose date cannot be read, or that does
// not parse, is never accepted.
func (r *Runner) dateFunc(ctx context.Context, feed string) vulnfeed.DateFunc {
	switch feedFormat(feed) {
	case formatDebianList:
		return func(rd io.Reader) (time.Time, error) {
			l, err := vulnfeed.ParseDebianAdvisoryList(ctx, rd)
			return l.Newest, err
		}
	case formatOSV:
		return func(rd io.Reader) (time.Time, error) { return r.osvDate(ctx, rd) }
	case formatNVD:
		return func(rd io.Reader) (time.Time, error) {
			zr, err := vulnfeed.DecompressGzip(rd, vulnfeed.MaxNVDFeedBytes)
			if err != nil {
				return time.Time{}, err
			}
			defer zr.Close()
			s, err := vulnfeed.ParseNVD(ctx, zr, func(vulnfeed.NVDRecord) error { return nil })
			return s.Newest, err
		}
	case formatKEV:
		return func(rd io.Reader) (time.Time, error) {
			c, err := vulnfeed.ParseKEV(ctx, rd)
			return c.Released, err
		}
	case formatEPSS:
		return func(rd io.Reader) (time.Time, error) {
			zr, err := vulnfeed.DecompressGzip(rd, vulnfeed.MaxEPSSBytes)
			if err != nil {
				return time.Time{}, err
			}
			defer zr.Close()
			s, err := vulnfeed.ParseEPSS(ctx, zr)
			return s.Date, err
		}
	}
	return nil
}

// osvDate copies the archive to a scratch file (the zip reader needs
// random access) and returns its newest record date.
func (r *Runner) osvDate(ctx context.Context, rd io.Reader) (time.Time, error) {
	dir := filepath.Join(r.cfg.DataDir, scratchDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return time.Time{}, fmt.Errorf("scratch directory: %w", err)
	}
	f, err := os.CreateTemp(dir, "osv-*")
	if err != nil {
		return time.Time{}, fmt.Errorf("scratch file: %w", err)
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	n, err := io.Copy(f, rd)
	if err != nil {
		return time.Time{}, fmt.Errorf("scratch copy: %w", err)
	}
	s, err := vulnfeed.ParseOSVArchive(ctx, f, n, func(vulnfeed.OSVRecord) error { return nil })
	return s.Newest, err
}

// Feed formats the run knows how to read.
const (
	formatUnknown = iota
	formatDebianTracker
	formatDebianList
	formatOSV
	formatNVD
	formatKEV
	formatEPSS
)

func feedFormat(name string) int {
	switch name {
	case "debian-tracker":
		return formatDebianTracker
	case "debian-dsa", "debian-dla":
		return formatDebianList
	case "osv-debian", "osv-ubuntu", "osv-alpine", "osv-go":
		return formatOSV
	case "nvd-modified":
		return formatNVD
	case "cisa-kev":
		return formatKEV
	case "first-epss":
		return formatEPSS
	}
	return formatUnknown
}

// syncCSAF syncs one signed provider and stores its accepted state. A
// failed sync keeps the previous state; rejected documents go into the
// evidence.
func (r *Runner) syncCSAF(ctx context.Context, p CSAFProvider, rep *Report) SourceEvidence {
	ev := SourceEvidence{Feed: p.Feed.Name, SourceID: p.Feed.SourceID, Integrity: p.Feed.Integrity}
	prev, err := r.loadCSAFState(p.Feed.Name)
	if err != nil {
		// A broken state is discarded: the next sync starts empty, which
		// only re-fetches documents (revisions are re-checked against the
		// documents themselves).
		r.log.Warn("csaf state discarded", "feed", p.Feed.Name, "error", cleanText(err.Error(), maxEvidenceText))
		prev = vulnfeed.CSAFState{}
	}
	next, crep, err := r.csaf.Sync(ctx, vulnfeed.CSAFSource{Feed: p.Feed, Vendor: p.Vendor, Keys: p.Keys}, prev)
	for _, rj := range crep.Rejected {
		reason := "rejected"
		if rj.Err != nil {
			reason = rj.Err.Error()
		}
		rep.addRejected(RejectedDoc{Feed: p.Feed.Name, TrackingID: cleanText(rj.TrackingID, maxEvidenceText),
			URL: cleanText(rj.URL, maxEvidenceText), Reason: cleanText(reason, maxEvidenceText)})
	}
	// Rejections beyond the reported list still count.
	if extra := crep.RejectedTotal - len(crep.Rejected); extra > 0 {
		rep.RejectedTotal += extra
	}
	if err != nil {
		ev.Status = SourceFailed
		ev.Error = cleanText(err.Error(), maxEvidenceText)
		r.log.Warn("csaf sync failed, previous state stays in use", "feed", p.Feed.Name, "error", ev.Error)
		next = prev
	} else {
		ev.Status = SourceUpdated
		if crep.Accepted == 0 {
			ev.Status = SourceNotModified
		}
		if err := r.saveCSAFState(p.Feed.Name, next); err != nil {
			ev.Status = SourceFailed
			ev.Error = cleanText(err.Error(), maxEvidenceText)
		}
	}
	if len(next.Documents) > 0 {
		id, err := csafSnapshotID(next)
		if err == nil {
			ev.SnapshotID, ev.ContentDate = id, next.ContentDate()
		}
	}
	r.log.Info("csaf synced", "feed", p.Feed.Name, "status", ev.Status, "accepted", crep.Accepted,
		"unchanged", crep.Unchanged, "rejected", crep.RejectedTotal, "snapshot", ev.SnapshotID)
	return ev
}

func (r *Runner) csafStatePath(feed string) string {
	return filepath.Join(r.cfg.DataDir, csafDir, feed+".json")
}

func (r *Runner) loadCSAFState(feed string) (vulnfeed.CSAFState, error) {
	f, err := os.Open(r.csafStatePath(feed))
	if errors.Is(err, fs.ErrNotExist) {
		return vulnfeed.CSAFState{}, nil
	}
	if err != nil {
		return vulnfeed.CSAFState{}, fmt.Errorf("open csaf state %s: %w", feed, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxCSAFStateBytes+1))
	if err != nil {
		return vulnfeed.CSAFState{}, fmt.Errorf("read csaf state %s: %w", feed, err)
	}
	if len(b) > MaxCSAFStateBytes {
		return vulnfeed.CSAFState{}, fmt.Errorf("csaf state %s over %d bytes", feed, MaxCSAFStateBytes)
	}
	var st vulnfeed.CSAFState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil || dec.More() {
		return vulnfeed.CSAFState{}, fmt.Errorf("decode csaf state %s: invalid", feed)
	}
	return st, nil
}

func (r *Runner) saveCSAFState(feed string, st vulnfeed.CSAFState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode csaf state %s: %w", feed, err)
	}
	if len(b) > MaxCSAFStateBytes {
		return fmt.Errorf("csaf state %s over %d bytes", feed, MaxCSAFStateBytes)
	}
	dir := filepath.Join(r.cfg.DataDir, csafDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("csaf state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("write csaf state %s: %w", feed, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write csaf state %s: %w", feed, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write csaf state %s: %w", feed, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write csaf state %s: %w", feed, err)
	}
	if err := os.Rename(tmp.Name(), r.csafStatePath(feed)); err != nil {
		return fmt.Errorf("write csaf state %s: %w", feed, err)
	}
	return nil
}

// csafSnapshotID is the content address of an accepted CSAF state.
func csafSnapshotID(st vulnfeed.CSAFState) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("encode csaf state: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
