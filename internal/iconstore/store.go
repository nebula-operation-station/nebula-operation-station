// SPDX-License-Identifier: AGPL-3.0-or-later

package iconstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"io/fs"
	"os"
	"path/filepath"
)

// FileMode is the permission of stored icon files.
const FileMode fs.FileMode = 0o640

// ErrInvalidIcon means an Icon or hash handed to Store is not something
// Sanitize could have produced.
var ErrInvalidIcon = errors.New("iconstore: invalid icon")

// Store writes sanitized icons into one directory, content-addressed by
// Icon.SHA256 as "<sha256>-64.png" and "<sha256>-128.png". File names are
// built only from a validated hex digest and a fixed size, never from
// input-supplied names or paths.
type Store struct {
	dir string
}

// NewStore returns a Store for the existing directory dir.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("iconstore: empty store directory")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("iconstore: open store directory: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("iconstore: store path %s is not a directory", dir)
	}
	return &Store{dir: filepath.Clean(dir)}, nil
}

// Path returns the file path of the icon with the given hash and size
// (SmallSize or LargeSize). It does not check that the file exists.
func (s *Store) Path(hash string, size int) (string, error) {
	if !validHash(hash) {
		return "", fmt.Errorf("%w: hash is not 64 lowercase hex digits", ErrInvalidIcon)
	}
	if size != SmallSize && size != LargeSize {
		return "", fmt.Errorf("%w: size %d", ErrInvalidIcon, size)
	}
	return filepath.Join(s.dir, fmt.Sprintf("%s-%d.png", hash, size)), nil
}

// Put stores both sizes of ic. It first checks that ic is self-consistent
// (hash matches PNG128, both parts are PNGs of the right size), then writes
// each file atomically via a temporary file and rename. Files that already
// exist are left alone, so Put is idempotent.
func (s *Store) Put(ctx context.Context, ic Icon) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("store icon: %w", err)
	}
	if err := validateIcon(ic); err != nil {
		return err
	}
	for _, part := range []struct {
		size int
		data []byte
	}{{SmallSize, ic.PNG64}, {LargeSize, ic.PNG128}} {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("store icon %s: %w", ic.SHA256, err)
		}
		p, err := s.Path(ic.SHA256, part.size)
		if err != nil {
			return err
		}
		if err := s.writeOnce(p, part.data); err != nil {
			return fmt.Errorf("store icon %s size %d: %w", ic.SHA256, part.size, err)
		}
	}
	return nil
}

func validHash(h string) bool {
	if len(h) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateIcon(ic Icon) error {
	if !validHash(ic.SHA256) {
		return fmt.Errorf("%w: hash is not 64 lowercase hex digits", ErrInvalidIcon)
	}
	sum := sha256.Sum256(ic.PNG128)
	if hex.EncodeToString(sum[:]) != ic.SHA256 {
		return fmt.Errorf("%w: hash does not match PNG128", ErrInvalidIcon)
	}
	for _, part := range []struct {
		size int
		data []byte
	}{{SmallSize, ic.PNG64}, {LargeSize, ic.PNG128}} {
		if !bytes.HasPrefix(part.data, pngMagic) {
			return fmt.Errorf("%w: %d px part is not a PNG", ErrInvalidIcon, part.size)
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(part.data))
		if err != nil {
			return fmt.Errorf("%w: %d px part: %w", ErrInvalidIcon, part.size, err)
		}
		if cfg.Width != part.size || cfg.Height != part.size {
			return fmt.Errorf("%w: %d px part is %dx%d", ErrInvalidIcon, part.size, cfg.Width, cfg.Height)
		}
	}
	return nil
}

// writeOnce writes data to path unless a regular file already exists
// there. Anything else at path (symlink, directory, device) is an error.
func (s *Store) writeOnce(path string, data []byte) (err error) {
	switch fi, statErr := os.Lstat(path); {
	case statErr == nil && fi.Mode().IsRegular():
		return nil
	case statErr == nil:
		return fmt.Errorf("existing entry is not a regular file (mode %v)", fi.Mode().Type())
	case !errors.Is(statErr, fs.ErrNotExist):
		return fmt.Errorf("stat target: %w", statErr)
	}

	f, err := os.CreateTemp(s.dir, ".icon-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(FileMode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return syncDir(s.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open store directory: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync store directory: %w", err)
	}
	return nil
}
