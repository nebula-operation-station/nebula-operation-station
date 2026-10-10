// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fsguard checks that private directories really are private before
// a process stores secrets in them.
package fsguard

import (
	"fmt"
	"os"
	"syscall"
)

// CheckPrivateDir verifies that path is a directory (not a symlink), owned by
// the effective UID and not accessible by group or others.
func CheckPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("fsguard: %s is not a directory", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("fsguard: %s has mode %o; must be 0700", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("fsguard: cannot read owner of %s", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("fsguard: %s is owned by uid %d, expected %d", path, st.Uid, os.Geteuid())
	}
	return nil
}

// EnsurePrivateDir creates path with mode 0700 if missing and then checks it.
func EnsurePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return CheckPrivateDir(path)
}
