// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"fmt"
	"os"
	"path/filepath"
)

// PendingFile is the executor's write-ahead record of a built-in trust
// commit's artifact trust, kept in the store directory while the commit
// is in flight.
const PendingFile = "pending-artifact-trust.json"

// MaxPending bounds the pending record.
const MaxPending = 8 << 20

// WritePending durably and atomically writes the pending record (private
// file, fsync, rename, directory fsync) into the store directory dir.
func WritePending(dir string, b []byte) error {
	if len(b) > MaxPending {
		return fmt.Errorf("%w: pending artifact trust would exceed %d bytes", ErrQuota, MaxPending)
	}
	return writeAtomic(dir, PendingFile, b)
}

// ReadPending reads the pending record from dir. A missing record is an
// error satisfying errors.Is(err, os.ErrNotExist).
func ReadPending(dir string) ([]byte, error) {
	return readBounded(filepath.Join(dir, PendingFile), MaxPending)
}

// RemovePending removes the pending record from dir durably. A missing
// record is not an error.
func RemovePending(dir string) error {
	if err := os.Remove(filepath.Join(dir, PendingFile)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("trust: remove %s: %w", PendingFile, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("trust: open directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("trust: sync directory: %w", err)
	}
	return nil
}
