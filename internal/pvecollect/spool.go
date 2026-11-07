// SPDX-License-Identifier: AGPL-3.0-or-later
// Package pvecollect uses a bounded, descriptor-relative spool handoff.
package pvecollect

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"golang.org/x/sys/unix"
)

const (
	maxSpoolFileBytes = pvecontract.MaxResponseBytes
	resultsDirName    = "results"
	// The root protects collector-owned generation state; the shared results
	// directory permits the server group to list, read and unlink entries.
	// Setgid preserves the provisioned shared group on newly published files.
	spoolRootMode      = os.FileMode(0o750) | os.ModeSetgid
	spoolDirMode       = os.FileMode(0o770) | os.ModeSetgid
	spoolFileMode      = 0o640
	generationDigits   = 20
	maxGenerationBytes = 32
)

// Sentinel errors for spool operations.
var (
	// ErrSymlink means an operation refused a symbolic link.
	ErrSymlink = errors.New("pvecollect: symlink refused")
	// ErrOversize means a spool file exceeds its size limit.
	ErrOversize = errors.New("pvecollect: spool file exceeds the size limit")
	// ErrReplayed means an observation does not advance its remote watermark.
	ErrReplayed = errors.New("pvecollect: replayed observation")
	// ErrBadName means a spool file name is malformed.
	ErrBadName = errors.New("pvecollect: malformed spool file name")
	// ErrInvalidObservation means a spool file itself is at fault: its
	// content was read completely and failed validation, or it is not a
	// regular file within the size limit. Only such a file may be discarded;
	// any other read error says nothing about the observation.
	ErrInvalidObservation = errors.New("pvecollect: invalid spool observation")
)

// errNonRegular means an operation refused a file that is not regular.
var errNonRegular = errors.New("pvecollect: nonregular spool file")

var spoolNameRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,63})\.gen-([0-9]{20})\.json$`)

// Spool is the on-disk observation spool. It is safe for concurrent use.
// Close must run after all operations using the spool have completed.
type Spool struct {
	root       string
	results    string
	rootDir    *os.File
	resultsDir *os.File
	writer     bool
	// read loads a pending file for the importers; it is readAt outside
	// tests.
	read func(dir *os.File, name string, limit int64) ([]byte, error)
	mu   sync.Mutex
	seen map[string]watermark
}

type watermark struct {
	generation uint64
	observedAt int64
}

// NewSpool creates or opens a collector's writable spool. The root must be
// absolute and all path components must be directories without symlinks.
// Provision the root with the collector UID and the shared server group.
func NewSpool(root string) (*Spool, error) { return openSpool(root, true) }

// OpenSpool opens an existing spool for server-side reading and consumption.
// It never creates files or changes modes, and needs only group access.
func OpenSpool(root string) (*Spool, error) { return openSpool(root, false) }

func openSpool(root string, writer bool) (*Spool, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("pvecollect: spool root must be absolute")
	}
	dir, err := openDirPath(root, writer)
	if err != nil {
		return nil, fmt.Errorf("pvecollect: open spool root: %w", err)
	}
	fail := func(err error) (*Spool, error) { dir.Close(); return nil, err }
	if writer {
		if err := ensureDirMode(dir, spoolRootMode); err != nil {
			return fail(fmt.Errorf("pvecollect: chmod spool root: %w", err))
		}
		if err := unix.Mkdirat(int(dir.Fd()), resultsDirName, 0o770); err != nil && !errors.Is(err, unix.EEXIST) {
			return fail(err)
		}
	}
	fd, err := unix.Openat(int(dir.Fd()), resultsDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(directoryError(int(dir.Fd()), resultsDirName, err))
	}
	results := os.NewFile(uintptr(fd), resultsDirName)
	if writer {
		if err := ensureDirMode(results, spoolDirMode); err != nil {
			results.Close()
			return fail(err)
		}
	}
	return &Spool{root: root, results: filepath.Join(root, resultsDirName), rootDir: dir, resultsDir: results, writer: writer, read: readAt, seen: make(map[string]watermark)}, nil
}

// openDirPath walks from /, pinning and rejecting symlinks at every component.
func openDirPath(path string, create bool) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(filepath.Clean(path), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, part, 0o750); err == nil || errors.Is(err, unix.EEXIST) {
				next, err = unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		if err != nil {
			err = directoryError(fd, part, err)
			unix.Close(fd)
			return nil, err
		}
		unix.Close(fd)
		fd = next
	}
	readFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(readFD), path), nil
}

func directoryError(fd int, name string, err error) error {
	var st unix.Stat_t
	if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	return err
}

// Close releases the pinned spool directory descriptors.
func (s *Spool) Close() error { return errors.Join(s.resultsDir.Close(), s.rootDir.Close()) }

// ResultsDir returns the path used to provision the results directory.
func (s *Spool) ResultsDir() string { return s.results }

func spoolFileName(remoteID string, generation uint64) (string, error) {
	if !pvecontract.ValidRemoteID(remoteID) {
		return "", errors.New("pvecollect: malformed remote id")
	}
	if generation == 0 {
		return "", errors.New("pvecollect: collection generation must be positive")
	}
	return fmt.Sprintf("%s.gen-%0*d.json", remoteID, generationDigits, generation), nil
}

func parseSpoolName(name string) (string, uint64, error) {
	m := spoolNameRe.FindStringSubmatch(name)
	if m == nil {
		return "", 0, ErrBadName
	}
	gen, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return "", 0, ErrBadName
	}
	return m[1], gen, nil
}

// readAt rejects symlinks on open and validates the opened descriptor, never
// a preceding path stat. NONBLOCK ensures a substituted FIFO cannot block.
func readAt(dir *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, ErrSymlink
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNonRegular
	}
	if fi.Size() > limit {
		return nil, ErrOversize
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrOversize
	}
	return raw, nil
}

// fileFault reports whether a readAt error is a fault of the file itself
// rather than of the attempt to open or read it.
func fileFault(err error) bool {
	return errors.Is(err, ErrSymlink) || errors.Is(err, ErrOversize) || errors.Is(err, errNonRegular)
}

// writeAt publishes a fully written file relative to the pinned directory.
// Exclusive publication prevents a concurrent writer from being overwritten.
func writeAt(dir *os.File, name string, raw []byte, mode os.FileMode, replace bool) error {
	tmpName := ".tmp-" + rand.Text()
	fd, err := unix.Openat(int(dir.Fd()), tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmpName)
	defer f.Close()
	defer unix.Unlinkat(int(dir.Fd()), tmpName, 0)
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if replace {
		flags = 0
	}
	if err := unix.Renameat2(int(dir.Fd()), tmpName, int(dir.Fd()), name, flags); err != nil {
		return err
	}
	return dir.Sync()
}

// WriteFile validates and atomically publishes an observation. Identical
// retries are accepted only after a symlink-safe, regular, bounded read.
func (s *Spool) WriteFile(_ context.Context, obs pvecontract.Observation) (string, error) {
	if !s.writer {
		return "", errors.New("pvecollect: read-side spool")
	}
	name, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
	if err != nil {
		return "", err
	}
	raw, err := pvecontract.MarshalObservation(obs)
	if err != nil {
		return "", fmt.Errorf("pvecollect: marshal observation: %w", err)
	}
	if len(raw) > maxSpoolFileBytes {
		return "", ErrOversize
	}
	final := filepath.Join(s.results, name)
	existing, err := readAt(s.resultsDir, name, maxSpoolFileBytes)
	if err == nil {
		if string(existing) != string(raw) {
			return "", errors.New("pvecollect: existing observation differs")
		}
		return final, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return "", err
	}
	if err := writeAt(s.resultsDir, name, raw, spoolFileMode, false); err != nil {
		if errors.Is(err, unix.EEXIST) {
			existing, readErr := readAt(s.resultsDir, name, maxSpoolFileBytes)
			if readErr != nil {
				return "", readErr
			}
			if string(existing) == string(raw) {
				return final, nil
			}
		}
		return "", fmt.Errorf("pvecollect: publish observation: %w", err)
	}
	return final, nil
}

// ReadFile reads and revalidates a named observation, including its identity
// and generation, through the pinned results directory descriptor. Errors
// that condemn the file wrap ErrInvalidObservation; any other error leaves
// the observation unjudged.
func (s *Spool) ReadFile(_ context.Context, name string) (pvecontract.Observation, error) {
	remoteID, gen, err := parseSpoolName(name)
	if err != nil {
		return pvecontract.Observation{}, err
	}
	raw, err := s.read(s.resultsDir, name, maxSpoolFileBytes)
	if err != nil {
		if fileFault(err) {
			return pvecontract.Observation{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		return pvecontract.Observation{}, err
	}
	obs, err := pvecontract.DecodeObservation(raw)
	if err != nil {
		return pvecontract.Observation{}, fmt.Errorf("%w: decode: %w", ErrInvalidObservation, err)
	}
	if obs.RemoteID != remoteID || obs.CollectionGeneration != gen {
		return pvecontract.Observation{}, fmt.Errorf("%w: identity does not match the file name", ErrInvalidObservation)
	}
	return obs, nil
}

// List returns sorted regular spool names and refuses symbolic links.
func (s *Spool) List(_ context.Context) ([]string, error) {
	// A new descriptor gives each listing an independent directory offset.
	fd, err := unix.Openat(int(s.resultsDir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), resultsDirName)
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, ErrSymlink
		}
		if !e.Type().IsRegular() {
			continue
		}
		if _, _, err := parseSpoolName(e.Name()); err == nil {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// allocateGeneration durably reserves a number before it can be published.
// A separate flock description serializes allocation across processes and
// spool instances; state survives consumption of every pending result.
func (s *Spool) allocateGeneration(ctx context.Context, remoteID string) (uint64, error) {
	if !s.writer || !pvecontract.ValidRemoteID(remoteID) {
		return 0, errors.New("pvecollect: invalid generation allocator")
	}
	fd, err := unix.Openat(int(s.rootDir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return 0, err
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	name := ".generation-" + remoteID
	raw, err := readAt(s.rootDir, name, maxGenerationBytes)
	var gen uint64
	switch {
	case err == nil:
		gen, err = strconv.ParseUint(strings.TrimSuffix(string(raw), "\n"), 10, 64)
		if err != nil {
			return 0, errors.New("pvecollect: invalid generation state")
		}
	case errors.Is(err, unix.ENOENT):
		// Migrate a spool created before durable allocation without colliding
		// with pending files. Once created, state is never removed by consumption.
		names, err := s.List(ctx)
		if err != nil {
			return 0, err
		}
		for _, name := range names {
			id, pending, err := parseSpoolName(name)
			if err == nil && id == remoteID && pending > gen {
				gen = pending
			}
		}
	default:
		return 0, err
	}
	if gen >= pvecontract.MaxCollectionGeneration {
		return 0, errors.New("pvecollect: generation exhausted")
	}
	gen++
	if err := writeAt(s.rootDir, name, []byte(strconv.FormatUint(gen, 10)+"\n"), 0o600, true); err != nil {
		return 0, fmt.Errorf("pvecollect: persist generation: %w", err)
	}
	return gen, nil
}

// CheckReplay reports whether obs is a replay for its remote, using the
// in-memory watermark set by MarkIngested. An observation is accepted when
// it has a newer generation, or the same generation with an observedAt not
// earlier than the watermark. It does not mutate state.
func (s *Spool) CheckReplay(obs pvecontract.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.seen[obs.RemoteID]
	if !ok {
		return nil
	}
	if obs.CollectionGeneration < w.generation {
		return fmt.Errorf("%w: %s gen %d < %d", ErrReplayed, obs.RemoteID, obs.CollectionGeneration, w.generation)
	}
	if obs.CollectionGeneration == w.generation && obs.ObservedAt.Unix() < w.observedAt {
		return fmt.Errorf("%w: %s gen %d observed earlier than the watermark", ErrReplayed, obs.RemoteID, obs.CollectionGeneration)
	}
	return nil
}

// MarkIngested advances the in-memory watermark for obs's remote. The
// importer calls it after a successful IngestObservation.
func (s *Spool) MarkIngested(obs pvecontract.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := watermark{generation: obs.CollectionGeneration, observedAt: obs.ObservedAt.Unix()}
	if cur, ok := s.seen[obs.RemoteID]; !ok || w.generation > cur.generation || (w.generation == cur.generation && w.observedAt > cur.observedAt) {
		s.seen[obs.RemoteID] = w
	}
}

// Remove consumes a flat spool name relative to the pinned directory.
// Unlink never follows a final symlink even if the entry changes after stat.
func (s *Spool) Remove(_ context.Context, name string) error {
	if _, _, err := parseSpoolName(name); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.resultsDir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("pvecollect: nonregular spool file")
	}
	return unix.Unlinkat(int(s.resultsDir.Fd()), name, 0)
}

// chmodDir changes an open directory's mode. It is a variable so that tests
// can simulate the EPERM that the collector's systemd hardening returns.
var chmodDir = func(dir *os.File, mode os.FileMode) error { return dir.Chmod(mode) }

// dirModeMask covers the mode bits ensureDirMode compares.
const dirModeMask = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// spoolGroupName is the shared group of the collector and the server that
// install.sh and the container image give every spool directory.
const spoolGroupName = "nebula-rpc"

// ErrSpoolOwnership means a spool directory is not owned by the collector
// UID and the shared server group.
var ErrSpoolOwnership = errors.New("pvecollect: spool directory has foreign ownership")

// spoolOwnership returns the UID and GID every collector spool directory
// must have. It is a variable so that tests can simulate other owners.
var spoolOwnership = defaultSpoolOwnership

// spoolGroupLookup resolves the shared spool group by name. It is a
// variable so that tests can simulate the group database without
// depending on the host's groups.
var spoolGroupLookup = user.LookupGroup

// spoolSupplementaryGroups returns the process's supplementary GIDs. It is
// a variable so that tests can simulate group membership.
var spoolSupplementaryGroups = os.Getgroups

// defaultSpoolOwnership expects the effective UID as owner. The group is
// spoolGroupName when this process is a member of it (the collector unit
// adds it as a supplementary group); otherwise, where no shared group is
// set up, it is the process's own effective GID. Any group the process
// cannot resolve fails closed.
func defaultSpoolOwnership() (uint32, uint32, error) {
	uid, egid := uint32(os.Geteuid()), uint32(os.Getegid())
	g, err := spoolGroupLookup(spoolGroupName)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return uid, egid, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("look up group %s: %w", spoolGroupName, err)
	}
	gid64, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("group %s has invalid gid %q", spoolGroupName, g.Gid)
	}
	gid := uint32(gid64)
	if gid == egid {
		return uid, gid, nil
	}
	groups, err := spoolSupplementaryGroups()
	if err != nil {
		return 0, 0, fmt.Errorf("read supplementary groups: %w", err)
	}
	for _, sg := range groups {
		if sg >= 0 && uint32(sg) == gid {
			return uid, gid, nil
		}
	}
	return uid, egid, nil
}

// ensureDirMode checks that an open spool directory is owned by the
// collector UID and the shared group (spoolOwnership) and fails otherwise;
// it never changes ownership. It leaves a directory that already has
// exactly want (permission bits plus setgid, sticky and setuid compared)
// untouched and changes any other mode, supersets included, to exactly
// want. The collector's unit sets RestrictSUIDSGID=yes, under which every
// chmod that sets the setgid bit fails with EPERM, even when the bit is
// already set. Deployments therefore create the spool directories with
// their final modes and ownership (install.sh, the container image), and a
// running collector never needs to change them.
func ensureDirMode(dir *os.File, want os.FileMode) error {
	wantUID, wantGID, err := spoolOwnership()
	if err != nil {
		return fmt.Errorf("%s: expected ownership: %w", dir.Name(), err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return fmt.Errorf("%s: stat: %w", dir.Name(), err)
	}
	if st.Uid != wantUID || st.Gid != wantGID {
		return fmt.Errorf("%w: %s is owned by %d:%d, want %d:%d (create it with install.sh)", ErrSpoolOwnership, dir.Name(), st.Uid, st.Gid, wantUID, wantGID)
	}
	fi, err := dir.Stat()
	if err != nil {
		return err
	}
	got := fi.Mode() & dirModeMask
	if got == want {
		return nil
	}
	if err := chmodDir(dir, want); err != nil {
		return fmt.Errorf("%s has mode %v, want %v (create it with install.sh): %w", dir.Name(), got, want, err)
	}
	return nil
}
