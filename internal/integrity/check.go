// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// mergedUsr are the top-level directories that a merged-/usr system
// (current Debian) replaces with a symlink into /usr. Only these, only
// as the first path component and only with exactly this target are
// followed; every other symlink on the way to a listed file is a
// deviation.
var mergedUsr = map[string]bool{"lib": true, "bin": true, "sbin": true, "lib64": true}

// run is the state of one check.
type run struct {
	ctx      context.Context
	opts     Options
	rootFD   int
	deadline time.Time
	report   *Report
	owners   map[string]ownerIDs
	stop     Incomplete
}

type ownerIDs struct {
	uid, gid uint32
	err      error
}

// Check compares the installed files of opts.Flavour under opts.Root with
// the admitted reference. It returns an error only when the run could not
// start (no admitted reference, unknown flavour, invalid options, root
// not openable); the caller must treat that as an incomplete check, never
// as clean. Deviations, unreadable files and limits are part of the
// Report.
func Check(ctx context.Context, ref Reference, opts Options) (Report, error) {
	if !ref.admitted {
		return Report{}, ErrNoReference
	}
	o, err := opts.withDefaults()
	if err != nil {
		return Report{}, err
	}
	fl, ok := ref.list.Flavour(o.Flavour)
	if !ok {
		return Report{}, fmt.Errorf("%w: %q", ErrFlavour, o.Flavour)
	}
	// A symlink as the root itself or in any of its parent directories
	// is refused, not followed.
	rootFD, err := openDirNoSymlinks(o.Root)
	if err != nil {
		return Report{}, fmt.Errorf("open check root %s: %w", o.Root, err)
	}
	defer unix.Close(rootFD)

	start := o.Now()
	rep := Report{
		ReleaseVersion: ref.ReleaseVersion(),
		ManifestDigest: ref.ManifestDigest(),
		ListDigest:     ref.ListDigest(),
		Flavour:        fl.Name,
		Started:        start,
		Files:          make([]FileResult, 0, len(fl.Files)),
	}
	r := &run{ctx: ctx, opts: o, rootFD: rootFD, deadline: start.Add(o.Budget), report: &rep, owners: map[string]ownerIDs{}}
	for i, f := range fl.Files {
		if r.stop == "" && i >= o.MaxFiles {
			r.stop = IncompleteFiles
		}
		if r.stop == "" {
			r.checkBudget()
		}
		res := FileResult{Path: f.Path, Class: Classify(f.Path), Status: StatusNotChecked}
		if r.stop == "" {
			res.Status, res.Reason = r.checkFile(f)
			if res.Status == StatusNotChecked {
				res.Reason = ""
			}
		}
		rep.Files = append(rep.Files, res)
	}
	if r.stop == "" {
		r.scanExtras(fl)
	}
	rep.Incomplete = r.stop
	rep.Complete = r.stop == ""
	rep.Finished = o.Now()
	return rep, nil
}

// checkBudget records the first reason to stop: cancellation or the time
// budget. It reports whether the run may go on.
func (r *run) checkBudget() bool {
	if r.stop != "" {
		return false
	}
	if r.ctx.Err() != nil {
		r.stop = IncompleteCanceled
	} else if !r.opts.Now().Before(r.deadline) {
		r.stop = IncompleteTime
	}
	return r.stop == ""
}

// checkFile checks one listed file. It returns StatusNotChecked when a
// budget stopped the run while hashing.
func (r *run) checkFile(f release.InstalledFile) (Status, Reason) {
	dirFD, base, st, why := r.openParent(f.Path)
	if st != "" {
		return st, why
	}
	defer unix.Close(dirFD)
	if f.Type == release.FileSymlink {
		return r.checkSymlink(dirFD, base, f)
	}
	return r.checkRegular(dirFD, base, f)
}

// openParent opens the parent directory of the absolute path p under the
// root without following symlinks (except a merged-/usr top-level link)
// and returns its descriptor and the last component. On failure it
// returns the status for p.
func (r *run) openParent(p string) (int, string, Status, Reason) {
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			// release.ValidInstalledPath already rejects these.
			return -1, "", StatusUnreadable, ReasonOpen
		}
	}
	fd, err := unix.Dup(r.rootFD)
	if err != nil {
		return -1, "", StatusUnreadable, ReasonOpen
	}
	dirs := comps[:len(comps)-1]
	for i := 0; i < len(dirs); i++ {
		next, err := openDirNoFollow(fd, dirs[i])
		if err == nil {
			unix.Close(fd)
			fd = next
			continue
		}
		st, why := classifyOpenError(fd, dirs[i], err, true)
		if why == ReasonParent && i == 0 && mergedUsr[dirs[i]] && r.mergedUsrLink(dirs[i]) {
			// Resolve /lib as /usr/lib, inside the root.
			unix.Close(fd)
			rest := append([]string{"usr", dirs[i]}, dirs[i+1:]...)
			if fd, err = unix.Dup(r.rootFD); err != nil {
				return -1, "", StatusUnreadable, ReasonOpen
			}
			dirs = rest
			i = -1
			continue
		}
		unix.Close(fd)
		return -1, "", st, why
	}
	return fd, comps[len(comps)-1], "", ""
}

// mergedUsrLink reports whether the top-level entry name under the root is
// a symlink to exactly usr/<name> or /usr/<name>.
func (r *run) mergedUsrLink(name string) bool {
	target, err := readlinkat(r.rootFD, name)
	return err == nil && (target == "usr/"+name || target == "/usr/"+name)
}

func openDirNoFollow(dirFD int, name string) (int, error) {
	for {
		fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

// classifyOpenError maps a failed open of name in dirFD to a status by
// looking at the entry itself without following it. parent says the
// entry was needed as a directory.
func classifyOpenError(dirFD int, name string, openErr error, parent bool) (Status, Reason) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return StatusMissing, ""
		}
		return StatusUnreadable, ReasonOpen
	}
	kind := st.Mode & unix.S_IFMT
	switch {
	case parent && kind != unix.S_IFDIR:
		return StatusDifferent, ReasonParent
	case !parent && kind != unix.S_IFREG:
		return StatusDifferent, ReasonType
	}
	if errors.Is(openErr, unix.ENOENT) {
		// Raced with a removal.
		return StatusMissing, ""
	}
	return StatusUnreadable, ReasonOpen
}

func (r *run) checkSymlink(dirFD int, base string, f release.InstalledFile) (Status, Reason) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return StatusMissing, ""
		}
		return StatusUnreadable, ReasonOpen
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return StatusDifferent, ReasonType
	}
	target, err := readlinkat(dirFD, base)
	if err != nil {
		return StatusUnreadable, ReasonRead
	}
	if target != f.Target {
		return StatusDifferent, ReasonTarget
	}
	return r.checkOwner(f.Owner, st)
}

func (r *run) checkRegular(dirFD int, base string, f release.InstalledFile) (Status, Reason) {
	// O_NONBLOCK: a FIFO in place of the file must not block the open;
	// O_NOFOLLOW: a symlink in its place is a deviation, never followed.
	fd, err := unix.Openat(dirFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return classifyOpenError(dirFD, base, err, false)
	}
	file := os.NewFile(uintptr(fd), f.Path)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return StatusUnreadable, ReasonOpen
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return StatusDifferent, ReasonType
	case st.Size != f.Size:
		return StatusDifferent, ReasonSize
	case st.Mode&0o7777 != f.Mode:
		return StatusDifferent, ReasonMode
	}
	if s, why := r.checkOwner(f.Owner, st); s != StatusOK {
		return s, why
	}
	if r.report.BytesHashed+f.Size > r.opts.MaxBytes {
		r.stop = IncompleteBytes
		return StatusNotChecked, ""
	}
	return r.hash(file, f)
}

// hash reads at most f.Size+1 bytes, checking the budget between chunks.
func (r *run) hash(file *os.File, f release.InstalledFile) (Status, Reason) {
	h := sha256.New()
	buf := make([]byte, readChunk)
	lr := io.LimitReader(file, f.Size+1)
	var n int64
	for {
		if !r.checkBudget() {
			return StatusNotChecked, ""
		}
		k, err := lr.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			n += int64(k)
			r.report.BytesHashed += int64(k)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return StatusUnreadable, ReasonRead
		}
	}
	if n != f.Size {
		// Changed while it was read.
		return StatusDifferent, ReasonSize
	}
	if hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return StatusDifferent, ReasonSHA256
	}
	return StatusOK, ""
}

func (r *run) checkOwner(owner string, st unix.Stat_t) (Status, Reason) {
	ids, ok := r.owners[owner]
	if !ok {
		ids.uid, ids.gid, ids.err = r.opts.Owners(owner)
		r.owners[owner] = ids
	}
	if ids.err != nil {
		return StatusUnreadable, ReasonOwnerUnknown
	}
	if st.Uid != ids.uid || st.Gid != ids.gid {
		return StatusDifferent, ReasonOwner
	}
	return StatusOK, ""
}

// scanExtras reports /usr/bin entries named nebula* that the list does not
// have (ADR 0015 D4: an unlisted executable under /usr/bin/nebula*).
func (r *run) scanExtras(fl release.Flavour) {
	listed := make(map[string]bool, len(fl.Files))
	for _, f := range fl.Files {
		listed[f.Path] = true
	}
	dirFD, _, st, _ := r.openParent("/usr/bin/x")
	if st == StatusMissing {
		return // no /usr/bin: nothing extra; listed binaries are missing.
	}
	if st != "" {
		r.stop = IncompleteExtraScan
		return
	}
	dir := os.NewFile(uintptr(dirFD), "/usr/bin")
	defer dir.Close()
	seen, extras := 0, 0
	for {
		if !r.checkBudget() {
			return
		}
		names, err := dir.Readdirnames(1024)
		for _, name := range names {
			if !strings.HasPrefix(name, "nebula") {
				continue
			}
			p := "/usr/bin/" + name
			if listed[p] {
				continue
			}
			if extras == MaxExtras {
				r.stop = IncompleteExtraScan
				return
			}
			extras++
			r.report.Files = append(r.report.Files, FileResult{Path: escapePath(p), Class: ClassBinary, Status: StatusExtra})
		}
		if seen += len(names); seen > maxDirEntries {
			r.stop = IncompleteExtraScan
			return
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			r.stop = IncompleteExtraScan
			return
		}
	}
}

// escapePath escapes a host-supplied name for text output: non-printable
// and non-ASCII bytes become Go escapes.
func escapePath(p string) string {
	q := strconv.QuoteToASCII(p)
	return q[1 : len(q)-1]
}

func readlinkat(dirFD int, name string) (string, error) {
	buf := make([]byte, release.MaxInstalledPath+1)
	n, err := unix.Readlinkat(dirFD, name, buf)
	if err != nil {
		return "", err
	}
	if n > release.MaxInstalledPath {
		return "", fmt.Errorf("symlink target longer than %d bytes", release.MaxInstalledPath)
	}
	return string(buf[:n]), nil
}

// lookupOwner resolves "user:group". root:root is 0:0 without a lookup;
// other names come from the host's user and group database.
func lookupOwner(owner string) (uint32, uint32, error) {
	u, g, ok := strings.Cut(owner, ":")
	if !ok || u == "" || g == "" || strings.Contains(g, ":") {
		return 0, 0, fmt.Errorf("owner %q is not user:group", owner)
	}
	if owner == "root:root" {
		return 0, 0, nil
	}
	uu, err := user.Lookup(u)
	if err != nil {
		return 0, 0, fmt.Errorf("look up user %s: %w", u, err)
	}
	gg, err := user.LookupGroup(g)
	if err != nil {
		return 0, 0, fmt.Errorf("look up group %s: %w", g, err)
	}
	uid, err := strconv.ParseUint(uu.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %s: uid: %w", u, err)
	}
	gid, err := strconv.ParseUint(gg.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("group %s: gid: %w", g, err)
	}
	return uint32(uid), uint32(gid), nil
}
