// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"golang.org/x/sys/unix"
)

const (
	requestsDirName = "requests"
	liveDirName     = "live"
	liveWantName    = "live.json"
	// The root protects collector-owned state; the shared directories let
	// the server group write the want-list (requests) and read the samples
	// (live). Setgid preserves the provisioned shared group on new files.
	liveRootMode    = os.FileMode(0o750) | os.ModeSetgid
	requestsDirMode = os.FileMode(0o770) | os.ModeSetgid
	liveDirMode     = os.FileMode(0o750) | os.ModeSetgid
	liveFileMode    = 0o640
)

// LiveHandoff is the bounded live handoff between the server and the
// collector: a server-written want-list under requests/ and collector-written
// per-remote samples under live/. It is safe for concurrent use. Close must
// run after all operations using the handoff have completed.
type LiveHandoff struct {
	root        string
	requests    string
	live        string
	requestsDir *os.File
	liveDir     *os.File
	now         func() time.Time
}

// NewLiveHandoff creates or opens a collector's live handoff, creating the
// requests/ and live/ directories with the shared modes. The root must be
// absolute and all path components must be directories without symlinks.
// Provision the root with the collector UID and the shared server group.
func NewLiveHandoff(root string) (*LiveHandoff, error) { return openLiveHandoff(root, true) }

// OpenLiveHandoff opens an existing live handoff for server-side use. It
// never creates files or changes modes, and needs only group access.
func OpenLiveHandoff(root string) (*LiveHandoff, error) { return openLiveHandoff(root, false) }

func openLiveHandoff(root string, create bool) (*LiveHandoff, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("pvecollect: live handoff root must be absolute")
	}
	dir, err := openDirPath(root, create)
	if err != nil {
		return nil, fmt.Errorf("pvecollect: open live handoff root: %w", err)
	}
	fail := func(err error) (*LiveHandoff, error) { dir.Close(); return nil, err }
	if create {
		if err := ensureDirMode(dir, liveRootMode); err != nil {
			return fail(fmt.Errorf("pvecollect: chmod live handoff root: %w", err))
		}
		if err := unix.Mkdirat(int(dir.Fd()), requestsDirName, 0o770); err != nil && !errors.Is(err, unix.EEXIST) {
			return fail(fmt.Errorf("pvecollect: create requests directory: %w", err))
		}
		if err := unix.Mkdirat(int(dir.Fd()), liveDirName, 0o750); err != nil && !errors.Is(err, unix.EEXIST) {
			return fail(fmt.Errorf("pvecollect: create live directory: %w", err))
		}
	}
	reqFD, err := unix.Openat(int(dir.Fd()), requestsDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("pvecollect: open requests directory: %w", directoryError(int(dir.Fd()), requestsDirName, err)))
	}
	requestsDir := os.NewFile(uintptr(reqFD), requestsDirName)
	if create {
		if err := ensureDirMode(requestsDir, requestsDirMode); err != nil {
			requestsDir.Close()
			return fail(fmt.Errorf("pvecollect: chmod requests directory: %w", err))
		}
	}
	liveFD, err := unix.Openat(int(dir.Fd()), liveDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		requestsDir.Close()
		return fail(fmt.Errorf("pvecollect: open live directory: %w", directoryError(int(dir.Fd()), liveDirName, err)))
	}
	liveDir := os.NewFile(uintptr(liveFD), liveDirName)
	if create {
		if err := ensureDirMode(liveDir, liveDirMode); err != nil {
			requestsDir.Close()
			liveDir.Close()
			return fail(fmt.Errorf("pvecollect: chmod live directory: %w", err))
		}
	}
	return &LiveHandoff{
		root:        root,
		requests:    filepath.Join(root, requestsDirName),
		live:        filepath.Join(root, liveDirName),
		requestsDir: requestsDir,
		liveDir:     liveDir,
		now:         time.Now,
	}, nil
}

// Close releases the pinned live handoff directory descriptors.
func (h *LiveHandoff) Close() error { return errors.Join(h.liveDir.Close(), h.requestsDir.Close()) }

// RequestsDir returns the path used to provision the requests directory.
func (h *LiveHandoff) RequestsDir() string { return h.requests }

// LiveDir returns the path used to provision the live directory.
func (h *LiveHandoff) LiveDir() string { return h.live }

func liveSamplesName(remoteID string) (string, error) {
	if !pvecontract.ValidRemoteID(remoteID) {
		return "", errors.New("pvecollect: malformed remote id")
	}
	return remoteID + ".json", nil
}

// WriteLiveWant atomically publishes the want-list to the requests directory,
// replacing any existing regular file and refusing a symbolic link.
func (h *LiveHandoff) WriteLiveWant(_ context.Context, want pvecontract.LiveWant) error {
	raw, err := pvecontract.MarshalLiveWant(want)
	if err != nil {
		return fmt.Errorf("pvecollect: marshal want-list: %w", err)
	}
	if len(raw) > pvecontract.MaxLiveWantBytes {
		return ErrOversize
	}
	if err := refuseSymlinkAt(h.requestsDir, liveWantName); err != nil {
		return fmt.Errorf("pvecollect: publish want-list: %w", err)
	}
	if err := writeAt(h.requestsDir, liveWantName, raw, liveFileMode, true); err != nil {
		return fmt.Errorf("pvecollect: publish want-list: %w", err)
	}
	return nil
}

// ReadLiveWant reads the want-list from the requests directory. A missing,
// invalid, future-dated or expired document is treated as "no targets" and
// returns a zero value with a nil error. Symlink and oversize files are
// refused with an error.
func (h *LiveHandoff) ReadLiveWant(_ context.Context) (pvecontract.LiveWant, error) {
	raw, err := readAt(h.requestsDir, liveWantName, pvecontract.MaxLiveWantBytes)
	if errors.Is(err, unix.ENOENT) {
		return pvecontract.LiveWant{}, nil
	}
	if err != nil {
		return pvecontract.LiveWant{}, fmt.Errorf("pvecollect: read want-list: %w", err)
	}
	want, err := pvecontract.DecodeLiveWant(raw)
	if err != nil {
		return pvecontract.LiveWant{}, nil
	}
	if !want.Live(h.now().Unix()) {
		return pvecontract.LiveWant{}, nil
	}
	return want, nil
}

// WriteLiveSamples atomically publishes the samples for one remote to the
// live directory, named after the remote, replacing any existing regular file
// and refusing a symbolic link.
func (h *LiveHandoff) WriteLiveSamples(_ context.Context, samples pvecontract.LiveSamples) error {
	name, err := liveSamplesName(samples.Remote)
	if err != nil {
		return err
	}
	raw, err := pvecontract.MarshalLiveSamples(samples)
	if err != nil {
		return fmt.Errorf("pvecollect: marshal samples: %w", err)
	}
	if len(raw) > pvecontract.MaxLiveSamplesBytes {
		return ErrOversize
	}
	if err := refuseSymlinkAt(h.liveDir, name); err != nil {
		return fmt.Errorf("pvecollect: publish samples: %w", err)
	}
	if err := writeAt(h.liveDir, name, raw, liveFileMode, true); err != nil {
		return fmt.Errorf("pvecollect: publish samples: %w", err)
	}
	return nil
}

// ReadLiveSamples reads and revalidates the samples for one remote through the
// pinned live directory descriptor. The document's remote must match the file
// name, and a document dated in the future relative to the reader's clock is
// refused.
func (h *LiveHandoff) ReadLiveSamples(_ context.Context, remoteID string) (pvecontract.LiveSamples, error) {
	name, err := liveSamplesName(remoteID)
	if err != nil {
		return pvecontract.LiveSamples{}, err
	}
	raw, err := readAt(h.liveDir, name, pvecontract.MaxLiveSamplesBytes)
	if err != nil {
		return pvecontract.LiveSamples{}, fmt.Errorf("pvecollect: read samples: %w", err)
	}
	samples, err := pvecontract.DecodeLiveSamples(raw)
	if err != nil {
		return pvecontract.LiveSamples{}, fmt.Errorf("pvecollect: decode samples: %w", err)
	}
	if samples.Remote != remoteID {
		return pvecontract.LiveSamples{}, errors.New("pvecollect: samples remote does not match the file name")
	}
	if err := samples.CheckClock(h.now().Unix()); err != nil {
		return pvecontract.LiveSamples{}, fmt.Errorf("pvecollect: samples dated in the future: %w", err)
	}
	return samples, nil
}

// RemoveLiveSamples unlinks the samples file for one remote, refusing symbolic
// links. Unlink never follows a final symlink even if the entry changes after
// stat.
func (h *LiveHandoff) RemoveLiveSamples(_ context.Context, remoteID string) error {
	name, err := liveSamplesName(remoteID)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(h.liveDir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("pvecollect: stat live samples: %w", err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("pvecollect: nonregular live samples file")
	}
	if err := unix.Unlinkat(int(h.liveDir.Fd()), name, 0); err != nil {
		return fmt.Errorf("pvecollect: remove live samples: %w", err)
	}
	return nil
}

// refuseSymlinkAt reports ErrSymlink when name in dir is a symbolic link.
// The rename that publishes a document replaces the directory entry and never
// follows it, so this is a tamper signal, not a safety check; any other
// existing entry (oversize, garbage) is simply replaced.
func refuseSymlinkAt(dir *os.File, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	return nil
}
