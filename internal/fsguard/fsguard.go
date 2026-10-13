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

// CheckPrivateFile verifies that path is a regular file (not a symlink),
// owned by the effective UID and not accessible by group or others. A
// missing file is reported with an error for which os.IsNotExist is true.
func CheckPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("fsguard: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("fsguard: %s has mode %o; must be 0600", path, fi.Mode().Perm())
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

// EnsurePrivateFile creates path as an empty file with mode 0600 if it does
// not exist, and then checks it with CheckPrivateFile. An existing file with
// a looser mode, another owner or a symlink at the path is an error; it is
// never repaired silently.
func EnsurePrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	switch {
	case err == nil:
		if cerr := f.Close(); cerr != nil {
			return cerr
		}
	case os.IsExist(err):
		// Checked below.
	default:
		return err
	}
	return CheckPrivateFile(path)
}
