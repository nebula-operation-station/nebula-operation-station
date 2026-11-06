// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"golang.org/x/sys/unix"
)

// guestNetDirName is the shared spool directory for guest NIC records,
// next to results/. Like results/ it lets the server group list, read and
// unlink entries; only the collector creates it and writes into it.
const guestNetDirName = "guestnet"

var guestNetNameRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,63})\.obs-([0-9]{20})\.json$`)

// guestNetFileName names a record after its remote and observation time,
// so every snapshot has its own file and the server unlinks exactly what
// it imported.
func guestNetFileName(remote string, observedUnix int64) string {
	return fmt.Sprintf("%s.obs-%0*d.json", remote, generationDigits, observedUnix)
}

// parseGuestNetName returns the remote and observation time encoded in a
// guest NIC record name.
func parseGuestNetName(name string) (string, int64, error) {
	m := guestNetNameRe.FindStringSubmatch(name)
	if m == nil || !pvecontract.ValidRemoteID(m[1]) {
		return "", 0, ErrBadName
	}
	at, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || at <= 0 {
		return "", 0, ErrBadName
	}
	return m[1], at, nil
}

// guestNetDir opens the guest NIC directory relative to the pinned spool
// root, refusing a symlink. The writer creates it with the shared mode;
// the reader never creates it and gets an ENOENT error while the collector
// has not published a record yet.
func (s *Spool) guestNetDir() (*os.File, error) {
	root := int(s.rootDir.Fd())
	if s.writer {
		if err := unix.Mkdirat(root, guestNetDirName, 0o770); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("pvecollect: create guest nic directory: %w", err)
		}
	}
	fd, err := unix.Openat(root, guestNetDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, directoryError(root, guestNetDirName, err)
	}
	dir := os.NewFile(uintptr(fd), guestNetDirName)
	if s.writer {
		if err := ensureDirMode(dir, spoolDirMode); err != nil {
			dir.Close()
			return nil, fmt.Errorf("pvecollect: chmod guest nic directory: %w", err)
		}
	}
	return dir, nil
}

// WriteGuestNet validates and atomically publishes one remote's guest NIC
// snapshot (collector side only) and returns its file name. A retry of an
// identical snapshot is accepted; older pending snapshots of the same
// remote are superseded and removed, so the backlog stays bounded while
// the server is not importing.
func (s *Spool) WriteGuestNet(_ context.Context, rec GuestNetRecord) (string, error) {
	if !s.writer {
		return "", errors.New("pvecollect: read-side spool")
	}
	raw, err := MarshalGuestNet(rec)
	if err != nil {
		return "", err
	}
	dir, err := s.guestNetDir()
	if err != nil {
		return "", err
	}
	defer dir.Close()
	name := guestNetFileName(rec.Remote, rec.ObservedUnix)
	if err := writeAt(dir, name, raw, spoolFileMode, false); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("pvecollect: publish guest nic record: %w", err)
		}
		existing, readErr := readAt(dir, name, MaxGuestNetBytes)
		if readErr != nil {
			return "", fmt.Errorf("pvecollect: publish guest nic record: %w", readErr)
		}
		if string(existing) != string(raw) {
			return "", errors.New("pvecollect: existing guest nic record differs")
		}
	}
	names, err := listGuestNet(dir)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		remote, at, _ := parseGuestNetName(n)
		if remote != rec.Remote || at >= rec.ObservedUnix {
			continue
		}
		if err := removeRegularAt(dir, n); err != nil && !errors.Is(err, unix.ENOENT) {
			return "", fmt.Errorf("pvecollect: supersede guest nic record: %w", err)
		}
	}
	return name, nil
}

// ListGuestNet returns the sorted pending guest NIC record names. Names
// that do not parse and non-regular entries are skipped; a symlink is
// refused with ErrSymlink.
func (s *Spool) ListGuestNet(_ context.Context) ([]string, error) {
	dir, err := s.guestNetDir()
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return listGuestNet(dir)
}

func listGuestNet(dir *os.File) ([]string, error) {
	// A new descriptor gives each listing an independent directory offset.
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), guestNetDirName)
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("pvecollect: list guest nic records: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, ErrSymlink
		}
		if !e.Type().IsRegular() {
			continue
		}
		if _, _, err := parseGuestNetName(e.Name()); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// ReadGuestNet reads and revalidates a named record through the pinned
// directory. The record's remote and observation time must match its name.
// Errors that condemn the record wrap ErrGuestNetInvalid; any other error,
// such as a directory that cannot be opened, leaves it unjudged.
func (s *Spool) ReadGuestNet(_ context.Context, name string) (GuestNetRecord, error) {
	remote, at, err := parseGuestNetName(name)
	if err != nil {
		return GuestNetRecord{}, err
	}
	dir, err := s.guestNetDir()
	if err != nil {
		return GuestNetRecord{}, err
	}
	defer dir.Close()
	raw, err := s.read(dir, name, MaxGuestNetBytes)
	if err != nil {
		if fileFault(err) {
			return GuestNetRecord{}, fmt.Errorf("%w: %w", ErrGuestNetInvalid, err)
		}
		return GuestNetRecord{}, err
	}
	rec, err := DecodeGuestNet(raw)
	if err != nil {
		return GuestNetRecord{}, err
	}
	if rec.Remote != remote || rec.ObservedUnix != at {
		return GuestNetRecord{}, fmt.Errorf("%w: identity does not match the file name", ErrGuestNetInvalid)
	}
	return rec, nil
}

// RemoveGuestNet consumes a named record. It never follows a symlink.
func (s *Spool) RemoveGuestNet(_ context.Context, name string) error {
	if _, _, err := parseGuestNetName(name); err != nil {
		return err
	}
	dir, err := s.guestNetDir()
	if err != nil {
		return err
	}
	defer dir.Close()
	return removeRegularAt(dir, name)
}

// removeRegularAt unlinks a regular file relative to dir, refusing a
// symlink or any other file type.
func removeRegularAt(dir *os.File, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("pvecollect: nonregular guest nic record")
	}
	return unix.Unlinkat(int(dir.Fd()), name, 0)
}
