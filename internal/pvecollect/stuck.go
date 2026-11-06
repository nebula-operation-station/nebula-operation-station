// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// stuckFiles holds the processed spool files an importer could not unlink,
// for example because the server's mount of the spool is still read-only.
// A file name fixes its remote and generation (or observation time), and
// the collector never republishes a name while the file exists, so a name
// listed here needs no further processing: the importer only retries the
// unlink, without importing again and without logging again. The set is
// pruned to the directory listing on every pass, so it never outgrows the
// spool. It lives in memory: after a restart each such file is processed
// once more, which ingest tolerates, and the failure is logged once more.
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

// retry tries the unlink of a stuck file again and forgets the file once
// it is gone. Further failures are not reported; the first one was.
func (f stuckFiles) retry(ctx context.Context, name string, remove func(context.Context, string) error) {
	if err := remove(ctx, name); err == nil || errors.Is(err, unix.ENOENT) {
		delete(f, name)
	}
}
