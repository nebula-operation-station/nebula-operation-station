// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// maxOpenRetries bounds retries of openat2 after EINTR or EAGAIN.
const maxOpenRetries = 8

// openDirNoSymlinks opens the absolute directory path read-only for an
// offline check without following a symlink in any path component, the
// last one included (openat2 RESOLVE_NO_SYMLINKS). A symlink anywhere on
// the way is refused, never followed. A kernel without openat2 (Linux
// older than 5.6) fails closed.
func openDirNoSymlinks(path string) (int, error) {
	if !strings.HasPrefix(path, "/") {
		return -1, errors.New("path must be absolute")
	}
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	var err error
	for range maxOpenRetries {
		var fd int
		fd, err = unix.Openat2(unix.AT_FDCWD, path, &how)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			break
		}
	}
	if errors.Is(err, unix.ENOSYS) {
		return -1, fmt.Errorf("openat2 is not available (Linux 5.6 or newer is required): %w", err)
	}
	if errors.Is(err, unix.ELOOP) {
		return -1, fmt.Errorf("a path component is a symlink, which is never followed: %w", err)
	}
	return -1, err
}
