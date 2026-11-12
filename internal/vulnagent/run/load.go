// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnmatch"
)

// export is run order phase 2: the whole inventory export. A snapshot
// that disappears during the read is read again once from the start.
func (r *Runner) export(ctx context.Context) ([]nosclient.SubjectPart, *nosclient.Snapshot, error) {
	for attempt := 0; ; attempt++ {
		var parts []nosclient.SubjectPart
		snap, err := r.cfg.NOS.Export(ctx, func(p nosclient.Page) error {
			parts = append(parts, p.Subjects...)
			return nil
		})
		if err == nil {
			r.log.Info("inventory exported", "snapshot", snap.ID, "generation", snap.Generation,
				"pages", snap.Pages, "subjects", len(snap.Subjects))
			return parts, snap, nil
		}
		if errors.Is(err, nosclient.ErrSnapshotGone) && attempt == 0 {
			r.log.Warn("inventory snapshot gone during export, reading again")
			continue
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrExport, err)
	}
}

// loadedFeed is one feed snapshot set in the matcher DB.
type loadedFeed struct {
	feed     vulnfeed.Feed
	manifest vulnfeed.Manifest
	// snapshotID and contentDate for CSAF (no manifest).
	snapshotID  string
	contentDate time.Time
}

// loadDB reads every feed's current snapshot into a matcher DB and the
// assessor's snapshot view. A feed without a usable snapshot is left out
// (the matcher then reports its subjects as coverage gaps); a snapshot
// that fails while being parsed fails the run, because the DB would hold
// part of it.
func (r *Runner) loadDB(ctx context.Context, view *snapshotView, rep *Report) (*vulnmatch.DB, []loadedFeed, error) {
	db := vulnmatch.NewDB()
	var loaded []loadedFeed
	for _, f := range r.feeds {
		if f.Integrity == vulnfinding.IntegritySigned {
			continue
		}
		format := feedFormat(f.Name)
		if format == formatUnknown {
			continue
		}
		m, err := r.store.Load(f.Name)
		if errors.Is(err, vulnfeed.ErrNoSnapshot) {
			continue
		}
		if err != nil {
			r.markUnusable(rep, f.Name, err)
			continue
		}
		obj, err := r.openVerified(m)
		if err != nil {
			r.markUnusable(rep, f.Name, err)
			continue
		}
		err = func() error {
			defer func() { _ = obj.Close() }()
			if err := db.SetFeed(f.Name, vulnmatch.FeedRefFromManifest(m)); err != nil {
				return err
			}
			return r.parseInto(ctx, db, view, f, format, obj, m.Size)
		}()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: feed %s: %w", ErrLoad, f.Name, err)
		}
		loaded = append(loaded, loadedFeed{feed: f, manifest: m, snapshotID: m.SnapshotID(), contentDate: m.ContentDate})
	}
	for _, p := range r.cfg.CSAF {
		// A state that cannot be read leaves the signed source out of
		// matching; the source is marked failed so the run is degraded.
		st, err := r.loadCSAFState(p.Feed.Name)
		if err != nil {
			r.markUnusable(rep, p.Feed.Name, err)
			continue
		}
		if len(st.Documents) == 0 {
			continue
		}
		id, err := csafSnapshotID(st)
		if err != nil {
			r.markUnusable(rep, p.Feed.Name, err)
			continue
		}
		if err := db.SetFeed(p.Feed.Name, vulnmatch.FeedRef{SourceID: p.Feed.SourceID, SnapshotID: id, Integrity: p.Feed.Integrity}); err != nil {
			return nil, nil, fmt.Errorf("%w: feed %s: %w", ErrLoad, p.Feed.Name, err)
		}
		keys := make([]string, 0, len(st.Documents))
		for k := range st.Documents {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if err := db.AddCSAF(p.Feed.Name, st.Documents[k].Advisory); err != nil {
				return nil, nil, fmt.Errorf("%w: feed %s: %w", ErrLoad, p.Feed.Name, err)
			}
		}
		loaded = append(loaded, loadedFeed{feed: p.Feed, snapshotID: id, contentDate: st.ContentDate()})
	}
	return db, loaded, nil
}

func (r *Runner) markUnusable(rep *Report, feed string, err error) {
	msg := cleanText(err.Error(), maxEvidenceText)
	r.log.Warn("feed snapshot unusable, left out of the run", "feed", feed, "error", msg)
	for i := range rep.Sources {
		if rep.Sources[i].Feed == feed {
			rep.Sources[i].Status = SourceFailed
			rep.Sources[i].Error = msg
			rep.Sources[i].SnapshotID = ""
		}
	}
}

// openVerified opens the snapshot object of m and checks its size and
// SHA-256 on the opened file before it is parsed, so the bytes parsed are
// the bytes accepted at sync.
func (r *Runner) openVerified(m vulnfeed.Manifest) (*os.File, error) {
	// Store layout of internal/vulnfeed: <store>/objects/<feed>/<sha256>.
	p := filepath.Join(r.cfg.DataDir, feedsDir, "objects", m.Feed, m.SHA256)
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open snapshot: %w", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != m.Size {
		_ = f.Close()
		return nil, fmt.Errorf("snapshot size: %w", vulnfeed.ErrCorruptSnapshot)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, m.Size)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("hash snapshot: %w", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		_ = f.Close()
		return nil, fmt.Errorf("snapshot digest: %w", vulnfeed.ErrCorruptSnapshot)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("rewind snapshot: %w", err)
	}
	return f, nil
}

// parseInto parses one verified snapshot into the DB and the view.
func (r *Runner) parseInto(ctx context.Context, db *vulnmatch.DB, view *snapshotView, f vulnfeed.Feed, format int, obj *os.File, size int64) error {
	switch format {
	case formatDebianTracker:
		_, err := vulnfeed.ParseDebianTracker(ctx, obj, func(e vulnfeed.DebianEntry) error {
			if err := db.AddDebian(e); err != nil {
				return err
			}
			view.addDebian(f.SourceID, e)
			return nil
		})
		return err
	case formatDebianList:
		// Dates only: the lists proxy-date the tracker.
		return nil
	case formatOSV:
		_, err := vulnfeed.ParseOSVArchive(ctx, obj, size, func(rec vulnfeed.OSVRecord) error {
			if err := db.AddOSV(f.Name, rec); err != nil {
				return err
			}
			view.addOSV(f.SourceID, rec)
			return nil
		})
		return err
	case formatNVD:
		zr, err := vulnfeed.DecompressGzip(obj, vulnfeed.MaxNVDFeedBytes)
		if err != nil {
			return err
		}
		defer func() { _ = zr.Close() }()
		_, err = vulnfeed.ParseNVD(ctx, zr, func(rec vulnfeed.NVDRecord) error {
			if err := db.AddNVD(rec); err != nil {
				return err
			}
			view.addNVD(f.SourceID, rec)
			return nil
		})
		return err
	case formatKEV:
		c, err := vulnfeed.ParseKEV(ctx, obj)
		if err != nil {
			return err
		}
		for _, e := range c.Entries {
			if err := db.AddKEV(e); err != nil {
				return err
			}
			view.addKEV(e)
		}
		return nil
	case formatEPSS:
		zr, err := vulnfeed.DecompressGzip(obj, vulnfeed.MaxEPSSBytes)
		if err != nil {
			return err
		}
		defer func() { _ = zr.Close() }()
		s, err := vulnfeed.ParseEPSS(ctx, zr)
		if err != nil {
			return err
		}
		if err := db.SetEPSS(s); err != nil {
			return err
		}
		view.setEPSS(s)
		return nil
	}
	return nil
}

// runSources folds the loaded feeds into the sources a run names at
// start: one entry per source ID. Several feeds of one source (the OSV
// ecosystems) are named with a combined snapshot ID over their snapshot
// IDs and the oldest content date, so the source is never newer than
// its oldest part.
func runSources(loaded []loadedFeed) []RunSource {
	bySource := map[string][]loadedFeed{}
	var order []string
	for _, l := range loaded {
		if _, ok := bySource[l.feed.SourceID]; !ok {
			order = append(order, l.feed.SourceID)
		}
		bySource[l.feed.SourceID] = append(bySource[l.feed.SourceID], l)
	}
	sourceOfFeed := map[string]loadedFeed{}
	for _, l := range loaded {
		sourceOfFeed[l.feed.Name] = l
	}
	var out []RunSource
	for _, id := range order {
		ls := bySource[id]
		rs := RunSource{SourceID: id}
		var ids []string
		for _, l := range ls {
			rs.Feeds = append(rs.Feeds, l.feed.Name)
			ids = append(ids, l.feed.Name+"="+l.snapshotID)
			if rs.ContentDate.IsZero() || (!l.contentDate.IsZero() && l.contentDate.Before(rs.ContentDate)) {
				rs.ContentDate = l.contentDate
			}
		}
		if len(ls) == 1 {
			rs.SnapshotID = ls[0].snapshotID
		} else {
			slices.Sort(ids)
			sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
			rs.SnapshotID = "sha256:" + hex.EncodeToString(sum[:])
		}
		f := ls[0].feed
		switch f.DateKind {
		case vulnfeed.DateKindUndated:
			rs.DateKind, rs.ContentDate = nosclient.DateKindNone, time.Time{}
		case vulnfeed.DateKindProxy:
			// The companion with the newest content date gave the date.
			var best loadedFeed
			for _, c := range f.ProxyCompanions {
				if l, ok := sourceOfFeed[c]; ok && l.contentDate.After(best.contentDate) {
					best = l
				}
			}
			if best.feed.SourceID == "" {
				rs.DateKind, rs.ContentDate = nosclient.DateKindNone, time.Time{}
			} else {
				rs.DateKind = nosclient.DateKindProxyPrefix + best.feed.SourceID
			}
		default:
			rs.DateKind = nosclient.DateKindData
		}
		if rs.DateKind != nosclient.DateKindNone && rs.ContentDate.IsZero() {
			rs.DateKind = nosclient.DateKindNone
		}
		out = append(out, rs)
	}
	return out
}

// startRequest builds the run start from the named sources.
func startRequest(sources []RunSource, loaded []loadedFeed, matcherVersion string) nosclient.StartRequest {
	integrity := map[string]vulnfinding.IntegrityMode{}
	for _, l := range loaded {
		integrity[l.feed.SourceID] = l.feed.Integrity
	}
	req := nosclient.StartRequest{MatcherVersion: matcherVersion}
	for _, s := range sources {
		req.Sources = append(req.Sources, nosclient.SourceSnapshot{SourceID: s.SourceID, SnapshotID: s.SnapshotID,
			Integrity: integrity[s.SourceID], DateKind: s.DateKind, ContentDate: s.ContentDate})
	}
	return req
}
