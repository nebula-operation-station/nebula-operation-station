// SPDX-License-Identifier: AGPL-3.0-or-later

// Package state keeps the agent's only state: the daily count of LLM calls
// (ADR 0016 D6, at most 200 per day). It is one small JSON file in the
// agent's state directory.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// MaxStateBytes bounds the state file; a larger file is refused.
const MaxStateBytes = 1 << 10

// ErrCorrupt: the state file exists but does not hold a valid counter. The
// caller must stop; it must not reset the count.
var ErrCorrupt = errors.New("ops agent state file is corrupt")

// Store is the counter file. Now is injected; it defaults to time.Now.
type Store struct {
	// Path is the file, inside a directory the agent owns.
	Path string
	// Now returns the current time; nil uses time.Now.
	Now func() time.Time
}

type record struct {
	Day      string `json:"day"`
	LLMCalls int    `json:"llm_calls"`
}

func (s Store) today() string {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return now().UTC().Format("2006-01-02")
}

// Used returns the LLM calls recorded for the current UTC day. A missing
// file or a record of an earlier day counts as zero.
func (s Store) Used() (int, error) {
	r, err := s.load()
	if err != nil {
		return 0, err
	}
	if r.Day != s.today() {
		return 0, nil
	}
	return r.LLMCalls, nil
}

// Add records n more LLM calls for the current UTC day and writes the file
// atomically with mode 0600.
func (s Store) Add(n int) error {
	if n < 0 {
		return fmt.Errorf("record llm calls: negative count: %w", ErrCorrupt)
	}
	cur, err := s.Used()
	if err != nil {
		return err
	}
	body, err := json.Marshal(record{Day: s.today(), LLMCalls: cur + n})
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return s.write(body)
}

func (s Store) load() (record, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return record{}, nil
	}
	if err != nil {
		return record{}, fmt.Errorf("open state: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if err != nil {
		return record{}, fmt.Errorf("read state: %w", err)
	}
	if len(raw) > MaxStateBytes {
		return record{}, fmt.Errorf("state file too large: %w", ErrCorrupt)
	}
	var r record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || dec.More() {
		return record{}, fmt.Errorf("decode state: %w", ErrCorrupt)
	}
	if r.LLMCalls < 0 {
		return record{}, fmt.Errorf("state count negative: %w", ErrCorrupt)
	}
	return r, nil
}

func (s Store) write(body []byte) error {
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}
