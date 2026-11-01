// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// This file is the durable rollback state of the signed image catalog
// (ADR 0008 PV-03, review of PR #153). The highest accepted catalog
// sequence and the digest of its exact bytes survive executor restarts, so
// an older, validly signed catalog (for example one that still lists a
// withdrawn image) or another catalog with the same sequence is refused
// after a restart as well.

// Catalog state limits.
const (
	// maxPveCatalogState bounds the catalog state file.
	maxPveCatalogState = 4 << 10
	// maxPveCatalogSequence is the highest catalog sequence (2^53 - 1), as
	// in the release catalog format.
	maxPveCatalogSequence = 1<<53 - 1
)

// ErrPveCatalogState is returned when the durable catalog state is
// missing from the configuration, unreadable, malformed or cannot be
// written. The catalog is then not changed (fail closed).
var ErrPveCatalogState = errors.New("executor: image catalog state unavailable")

// PveCatalogState is the highest signed catalog the executor accepted.
type PveCatalogState struct {
	// Sequence is the catalog's sequence.
	Sequence int64 `json:"sequence"`
	// Digest is the lowercase hex SHA-256 of the catalog's exact bytes.
	Digest string `json:"digest"`
}

func (s PveCatalogState) validate() error {
	if s.Sequence < 1 || s.Sequence > maxPveCatalogSequence {
		return fmt.Errorf("catalog state sequence %d out of range", s.Sequence)
	}
	if !validHexDigest(s.Digest) {
		return errors.New("catalog state digest is not 64 lowercase hex digits")
	}
	return nil
}

// PveCatalogStateStore persists the catalog rollback state.
type PveCatalogStateStore interface {
	// PveCatalogState returns the stored state; ok is false when none was
	// ever written. A present but invalid state is an error.
	PveCatalogState() (st PveCatalogState, ok bool, err error)
	// PutPveCatalogState durably replaces the stored state.
	PutPveCatalogState(st PveCatalogState) error
}

// FilePveCatalogState keeps the catalog state in one JSON file, written
// atomically (temporary file, fsync, rename, directory fsync) with mode
// 0600, like FilePveTemplateStore. It is safe for concurrent use within one
// process.
type FilePveCatalogState struct {
	// Path is the state file, e.g. <state dir>/pve-catalog.json.
	Path string

	mu sync.Mutex
}

// PveCatalogState implements PveCatalogStateStore.
func (s *FilePveCatalogState) PveCatalogState() (PveCatalogState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return PveCatalogState{}, false, nil
	}
	if err != nil {
		return PveCatalogState{}, false, fmt.Errorf("open catalog state: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPveCatalogState+1))
	if err != nil {
		return PveCatalogState{}, false, fmt.Errorf("read catalog state: %w", err)
	}
	if len(raw) > maxPveCatalogState {
		return PveCatalogState{}, false, fmt.Errorf("catalog state exceeds %d bytes", maxPveCatalogState)
	}
	var st PveCatalogState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return PveCatalogState{}, false, fmt.Errorf("decode catalog state: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return PveCatalogState{}, false, errors.New("decode catalog state: trailing data")
	}
	if err := st.validate(); err != nil {
		return PveCatalogState{}, false, fmt.Errorf("decode catalog state: %w", err)
	}
	return st, true, nil
}

// PutPveCatalogState implements PveCatalogStateStore.
func (s *FilePveCatalogState) PutPveCatalogState(st PveCatalogState) error {
	if err := st.validate(); err != nil {
		return fmt.Errorf("write catalog state: %w", err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode catalog state: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(s.Path, raw)
}
