// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Template store limits.
const (
	// maxPveTemplateStore bounds the template record file.
	maxPveTemplateStore = 1 << 20
	// maxPveTemplateRecords bounds the records in it.
	maxPveTemplateRecords = 4096
)

// FilePveTemplateStore keeps template records in one JSON file, written
// atomically (temporary file, fsync, rename, directory fsync) with mode
// 0600. It is safe for concurrent use within one process.
type FilePveTemplateStore struct {
	// Path is the record file, e.g. <state dir>/pve-templates.json.
	Path string

	mu sync.Mutex
}

func (s *FilePveTemplateStore) load() ([]PveTemplateRecord, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open template records: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPveTemplateStore+1))
	if err != nil {
		return nil, fmt.Errorf("read template records: %w", err)
	}
	if len(raw) > maxPveTemplateStore {
		return nil, fmt.Errorf("template records exceed %d bytes", maxPveTemplateStore)
	}
	var recs []PveTemplateRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&recs); err != nil {
		return nil, fmt.Errorf("decode template records: %w", err)
	}
	if len(recs) > maxPveTemplateRecords {
		return nil, fmt.Errorf("more than %d template records", maxPveTemplateRecords)
	}
	return recs, nil
}

// PveTemplate implements PveTemplateStore.
func (s *FilePveTemplateStore) PveTemplate(key PveTemplateKey) (PveTemplateRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return PveTemplateRecord{}, false, err
	}
	for _, r := range recs {
		if r.PveTemplateKey == key {
			return r, true, nil
		}
	}
	return PveTemplateRecord{}, false, nil
}

// PutPveTemplate implements PveTemplateStore.
func (s *FilePveTemplateStore) PutPveTemplate(rec PveTemplateRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return err
	}
	replaced := false
	for i := range recs {
		if recs[i].PveTemplateKey == rec.PveTemplateKey {
			recs[i], replaced = rec, true
		}
	}
	if !replaced {
		if len(recs) >= maxPveTemplateRecords {
			return fmt.Errorf("template records full (%d)", maxPveTemplateRecords)
		}
		recs = append(recs, rec)
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("encode template records: %w", err)
	}
	if len(raw) > maxPveTemplateStore {
		return fmt.Errorf("template records exceed %d bytes", maxPveTemplateStore)
	}
	return writeFileAtomic(s.Path, raw)
}

// writeFileAtomic replaces path with data durably.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary record file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod record file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write record file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync record file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close record file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace record file: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open record directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync record directory: %w", err)
	}
	return nil
}
