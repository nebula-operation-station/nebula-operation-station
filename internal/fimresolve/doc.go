// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimresolve resolves paths of a fim-scan-v1 record set component by
// component, the way the kernel does, without ever resolving lexically
// (ADR 0015 D9 "Symlinks at or above SSH positions").
//
// The package is a pure library: it receives a lookup function over one
// record set and a path, and returns the resolved absolute path or an error.
// It has no notion of findings, severities or SSH positions; classifying the
// result is the job of a caller such as package fimbaseline.
//
// Rules, as in ADR 0015 D9:
//
//   - Resolution starts at "/". A "." component is dropped. A ".." moves to
//     the parent of the directory reached so far, after every symlink before
//     it has been followed, and stays at "/".
//   - A symlink component is replaced by its target: an absolute target
//     restarts at "/", a relative one continues from the directory that
//     holds the link.
//   - At most MaxSymlinkFollows symlinks are followed per resolution.
//   - The path still to be resolved, target included, and every intermediate
//     path must stay within fimscan.MaxPathBytes (4,096 bytes).
//   - A component that is followed by another component or by a trailing
//     slash must be a directory or a symlink; a non-final component that is
//     neither fails with ErrNotDir.
//   - A component without a record fails with ErrNotFound. The root "/" is
//     the start of every resolution and is not looked up; it is always a
//     directory.
//
// Paths are raw bytes and need not be UTF-8. Every failure is an error; the
// package never returns a path after a failed step and never panics on any
// input.
package fimresolve
