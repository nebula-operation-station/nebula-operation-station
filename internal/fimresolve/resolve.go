// SPDX-License-Identifier: AGPL-3.0-or-later

package fimresolve

import (
	"bytes"
	"errors"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// MaxSymlinkFollows is the number of symlinks one resolution may follow
// (ADR 0015 D9, the Linux limit). The 41st symlink is rejected with
// ErrSymlinkLimit, which also covers loops.
const MaxSymlinkFollows = 40

var (
	// ErrNilLookup is returned when the lookup function is nil.
	ErrNilLookup = errors.New("nil lookup function")
	// ErrNotAbsolute is returned for an empty path or one not starting with "/".
	ErrNotAbsolute = errors.New("path is empty or not absolute")
	// ErrNotFound is returned when a component has no record in the set,
	// including a target outside the scanned roots. It fails closed.
	ErrNotFound = errors.New("no record for path component")
	// ErrNotDir is returned when a component followed by another component or
	// a trailing slash is neither a directory nor a symlink.
	ErrNotDir = errors.New("path component is not a directory")
	// ErrSymlinkLimit is returned for a symlink loop or when more than
	// MaxSymlinkFollows symlinks would be followed.
	ErrSymlinkLimit = errors.New("symlink loop or more than MaxSymlinkFollows symlinks")
	// ErrEmptyLink is returned when a symlink has an empty target.
	ErrEmptyLink = errors.New("empty symlink target")
	// ErrTooLong is returned when the path still to be resolved, a
	// resolved intermediate path or the result exceeds fimscan.MaxPathBytes.
	ErrTooLong = errors.New("path longer than fimscan.MaxPathBytes")
)

// Resolve resolves path against the record set that lookup describes, one
// component at a time, and returns the resolved absolute path. lookup is
// called with the absolute path of each component reached; it reports the
// record at that path and whether one exists. Symlinks are followed (ADR
// 0015 D9); the returned path contains no symlink, "." or ".." component.
//
// The returned slice is newly allocated. The path argument is not modified.
func Resolve(lookup func(path []byte) (fimscan.Record, bool), path []byte) ([]byte, error) {
	if lookup == nil {
		return nil, ErrNilLookup
	}
	if len(path) == 0 || path[0] != '/' {
		return nil, ErrNotAbsolute
	}
	if len(path) > fimscan.MaxPathBytes {
		return nil, ErrTooLong
	}

	// rest is the path still to be resolved, leading "/" included. It is
	// always a fresh slice, so the caller's path is never written.
	rest := append([]byte(nil), path...)
	// buf is the absolute path of the directory reached so far. ends[i] is
	// the length of buf before the i-th pushed component, so a ".." or a
	// restart at "/" truncates buf without copying.
	buf := []byte{'/'}
	var ends []int
	follows := 0

	for len(rest) > 0 {
		name := rest
		slash := false
		if i := bytes.IndexByte(rest, '/'); i >= 0 {
			name = rest[:i]
			rest = rest[i+1:]
			slash = true
		} else {
			rest = nil
		}

		switch {
		case len(name) == 0, string(name) == ".":
			continue
		case string(name) == "..":
			if n := len(ends); n > 0 {
				buf = buf[:ends[n-1]]
				ends = ends[:n-1]
			}
			continue
		}

		child, err := childPath(buf, name)
		if err != nil {
			return nil, err
		}
		rec, ok := lookup(child)
		if !ok {
			return nil, ErrNotFound
		}

		if rec.Type == fimscan.TypeSymlink {
			follows++
			if follows > MaxSymlinkFollows {
				return nil, ErrSymlinkLimit
			}
			if len(rec.Link) == 0 {
				return nil, ErrEmptyLink
			}
			if len(rec.Link) > fimscan.MaxPathBytes {
				return nil, ErrTooLong
			}
			// The path still to be resolved becomes target, then the
			// link's trailing slash (if any), then what follows it.
			next := make([]byte, 0, len(rec.Link)+1+len(rest))
			next = append(next, rec.Link...)
			if slash {
				next = append(next, '/')
				next = append(next, rest...)
			}
			if len(next) > fimscan.MaxPathBytes {
				return nil, ErrTooLong
			}
			rest = next
			if rec.Link[0] == '/' {
				buf = buf[:1]
				ends = ends[:0]
			}
			continue
		}

		if slash && rec.Type != fimscan.TypeDir {
			return nil, ErrNotDir
		}
		// A non-directory final component is a valid result; the loop ends
		// because rest is empty after it.
		ends = append(ends, len(buf))
		if len(buf) > 1 {
			buf = append(buf, '/')
		}
		buf = append(buf, name...)
	}

	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

// childPath returns the absolute path of name inside the directory dir, or
// ErrTooLong when it would exceed fimscan.MaxPathBytes.
func childPath(dir, name []byte) ([]byte, error) {
	n := len(dir) + len(name)
	if len(dir) > 1 {
		n++
	}
	if n > fimscan.MaxPathBytes {
		return nil, ErrTooLong
	}
	p := make([]byte, 0, n)
	p = append(p, dir...)
	if len(dir) > 1 {
		p = append(p, '/')
	}
	return append(p, name...), nil
}
