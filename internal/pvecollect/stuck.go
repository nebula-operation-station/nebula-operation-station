// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"log/slog"

	"golang.org/x/sys/unix"
)

// stuckFiles holds the processed spool files an importer could not unlink,
// for example because the server's mount of the spool is read-only. A file
// name fixes its remote and generation (or observation time), and the
// collector never republishes a name while the file exists, so a name listed
// here needs no further processing: the importer only retries the unlink,
// without importing again. The set is pruned to the directory listing on
// every pass, so it never outgrows the spool.
//
// It lives in memory. After a restart the observation importer recognizes
// the backlog by name against the store's durable generation, and guest NIC
// records stay bounded because the collector supersedes older ones, so a
// restart reads at most one file per remote again.
type stuckFiles map[string]struct{}

// prune forgets every name that is no longer listed.
func (f stuckFiles) prune(listed []string) {
	if len(f) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(listed))
	for _, name := range listed {
		keep[name] = struct{}{}
	}
	for name := range f {
		if _, ok := keep[name]; !ok {
			delete(f, name)
		}
	}
}

// unlink removes a processed file and reports whether it did. A file that
// is already gone needs nothing; any other failure keeps it in the set.
// blocked spans one pass: once the directory refused an unlink as a whole,
// the rest of the pass does not try, so a backlog costs one failing syscall
// per pass and drains in one pass after the refusal ends.
func (f stuckFiles) unlink(ctx context.Context, name string, remove func(context.Context, string) error, blocked *bool) bool {
	if *blocked {
		f[name] = struct{}{}
		return false
	}
	err := remove(ctx, name)
	if err == nil || errors.Is(err, unix.ENOENT) {
		delete(f, name)
		return err == nil
	}
	f[name] = struct{}{}
	*blocked = errors.Is(err, unix.EROFS) || errors.Is(err, unix.EACCES)
	return false
}

// warn logs msg once per episode of stuck files, at the end of a pass and
// with their number, however large the backlog gets. warned is cleared when
// the set is empty again. File names stay out of it: one line must do.
func (f stuckFiles) warn(log *slog.Logger, msg string, warned *bool) {
	if len(f) == 0 {
		*warned = false
		return
	}
	if !*warned {
		*warned = true
		log.Warn(msg, "files", len(f), "reason", "remove_failed")
	}
}
