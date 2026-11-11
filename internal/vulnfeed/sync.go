// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// ErrSignedUnsupported: signed-mode verification is not available yet
// (va03), so signed feeds fail closed instead of falling back to unsigned.
var ErrSignedUnsupported = errors.New("vulnfeed: signed feeds need signature verification")

// DateFunc extracts a dated feed's content date from its bytes (the
// format parsers provide it).
type DateFunc func(r io.Reader) (time.Time, error)

// SyncOptions carries the per-format parts of a sync.
type SyncOptions struct {
	// ContentDate extracts the content date of a DateKindDated feed.
	// Required for dated feeds; ignored otherwise.
	ContentDate DateFunc
	// Sequence of a signed offline bundle; zero otherwise.
	Sequence uint64
}

// SyncResult is the outcome of a successful sync.
type SyncResult struct {
	// Manifest is the feed's accepted snapshot after the sync.
	Manifest Manifest
	// NotModified: the origin answered 304; Manifest is unchanged.
	NotModified bool
}

// Syncer fetches feeds into the snapshot store.
type Syncer struct {
	fetcher *Fetcher
	store   *Store
	// checksumTimeout bounds one checksum companion fetch.
	checksumTimeout time.Duration
}

// NewSyncer builds a Syncer.
func NewSyncer(f *Fetcher, s *Store) (*Syncer, error) {
	if f == nil || s == nil {
		return nil, fmt.Errorf("new syncer: fetcher and store required: %w", ErrInvalidFeed)
	}
	return &Syncer{fetcher: f, store: s, checksumTimeout: ChecksumFetchTimeout}, nil
}

// Sync fetches feed, checks its integrity and content date, and commits it
// as the feed's new snapshot. On any failure the previous snapshot stays
// in use and nothing partial is kept. A proxy-dated feed's companions must
// be synced first; its date is their newest content date.
func (s *Syncer) Sync(ctx context.Context, feed Feed, opt SyncOptions) (SyncResult, error) {
	if err := feed.validate(); err != nil {
		return SyncResult{}, err
	}
	if feed.Integrity == vulnfinding.IntegritySigned {
		return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, ErrSignedUnsupported)
	}
	var proxyDate time.Time
	switch feed.DateKind {
	case DateKindDated:
		if opt.ContentDate == nil {
			return SyncResult{}, fmt.Errorf("sync %s: no date extractor: %w", feed.Name, ErrNoContentDate)
		}
	case DateKindProxy:
		d, err := s.store.ProxyDate(feed)
		if err != nil {
			return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
		}
		proxyDate = d
	}
	prev, err := s.store.Load(feed.Name)
	switch {
	case errors.Is(err, ErrNoSnapshot):
		prev = Manifest{}
	case err != nil:
		return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
	}

	st, err := s.store.Stage(feed)
	if err != nil {
		return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
	}
	defer st.Abort() // no-op after Commit
	res, err := s.fetcher.Fetch(ctx, feed.URL, feed.MaxBytes, prev.Validators, st)
	if err != nil {
		return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
	}
	if res.NotModified {
		// The bytes are unchanged, but a proxy-dated feed's content date
		// follows its companions, which may have moved forward.
		if feed.DateKind == DateKindProxy && proxyDate.After(prev.ContentDate) {
			m, err := s.store.RedateProxy(feed, proxyDate)
			if err != nil {
				return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
			}
			return SyncResult{Manifest: m, NotModified: true}, nil
		}
		return SyncResult{Manifest: prev, NotModified: true}, nil
	}
	if feed.Integrity == vulnfinding.IntegrityChecksum {
		if err := s.verifyChecksum(ctx, feed, st); err != nil {
			return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
		}
	}
	acc := Accept{Sequence: opt.Sequence, Validators: res.Validators}
	switch feed.DateKind {
	case DateKindDated:
		r, err := st.Reader()
		if err != nil {
			return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
		}
		d, err := opt.ContentDate(r)
		if err != nil || d.IsZero() {
			return SyncResult{}, fmt.Errorf("sync %s: content date from data: %w", feed.Name, ErrNoContentDate)
		}
		acc.ContentDate = d
	case DateKindProxy:
		acc.ContentDate = proxyDate
	}
	m, err := s.store.Commit(feed, st, acc)
	if err != nil {
		return SyncResult{}, fmt.Errorf("sync %s: %w", feed.Name, err)
	}
	return SyncResult{Manifest: m}, nil
}
