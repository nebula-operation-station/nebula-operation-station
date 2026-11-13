// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Published signed root rotations an offline release directory may hold
// (spec 10 "Root rotation and revocation"). Rotation n (sequence n) is
// root-rotation-<n>.json with root-rotation-<n>.json.sig; the unnumbered
// root-rotation.json pair is accepted as rotation 1, the name the first
// enrollment recipe writes. Document and signature come in pairs.
const (
	// RotationFile is the unnumbered name of rotation 1.
	RotationFile = "root-rotation.json"
	// RotationSignatureFile is its detached signature.
	RotationSignatureFile = RotationFile + SignatureSuffix
	// RotationPrefix starts every rotation file name. Any other file
	// whose name starts with it makes the directory ErrRelease rather
	// than being ignored, so a misnamed rotation is never skipped.
	RotationPrefix = "root-rotation"
	// SignatureSuffix ends a detached signature's file name.
	SignatureSuffix = ".sig"
)

// MaxReleaseDirEntries bounds the directory entries ReadRelease lists in
// an offline release directory. It leaves room for MaxRotations pairs,
// the three release files and other release assets.
const MaxReleaseDirEntries = 4096

// ErrRelease is an offline release directory that cannot be read safely:
// a missing, oversized or non-regular file, a symlink, a misnamed, unpaired
// or missing rotation in the chain, or too many entries.
var ErrRelease = errors.New("integrity: unreadable release directory")

// Release holds the bytes of a published release as read from a
// directory (ADR 0015 D4 "Recommended outside anchor"). Nothing in it is
// trusted until AdmitRelease has verified it.
type Release struct {
	// Manifest is release-manifest.json.
	Manifest []byte
	// Signature is release-manifest.json.sig.
	Signature []byte
	// List is installed-files.json.
	List []byte
	// Rotations are the published signed root rotations, Rotations[i]
	// from the file for sequence i+1; nil if there are none.
	Rotations []release.SignedRotation
}

// rotationName is the file name of rotation n.
func rotationName(n int) string {
	return RotationPrefix + "-" + strconv.Itoa(n) + ".json"
}

// parseRotationName returns the rotation number of a numbered rotation
// document or signature name, and whether it is the signature. ok is
// false for any other name, including a leading zero, 0 and numbers
// above release.MaxRotations.
func parseRotationName(name string) (n int, sig, ok bool) {
	rest, found := strings.CutPrefix(name, RotationPrefix+"-")
	if !found {
		return 0, false, false
	}
	if s, found := strings.CutSuffix(rest, SignatureSuffix); found {
		rest, sig = s, true
	}
	digits, found := strings.CutSuffix(rest, ".json")
	if !found || digits == "" || len(digits) > 4 || digits[0] == '0' {
		return 0, false, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || n > release.MaxRotations {
		return 0, false, false
	}
	return n, sig, true
}

// ReadRelease reads the release files from the absolute directory dir.
// It only reads: no path component of dir and no file in it is followed
// if it is a symlink, each file must be a regular file within its size
// limit, and a FIFO in place of a file does not block. Missing required
// files, a rotation document without its signature or the other way
// round, a misnamed rotation file and a gap in the rotation numbers
// (1..n must all be present) are ErrRelease.
func ReadRelease(dir string) (Release, error) {
	dirFD, err := openDirNoSymlinks(dir)
	if err != nil {
		return Release{}, fmt.Errorf("%w: open directory: %v", ErrRelease, err)
	}
	defer unix.Close(dirFD)

	var rel Release
	for _, f := range []struct {
		name string
		max  int64
		dst  *[]byte
	}{
		{release.ManifestFile, release.MaxManifest, &rel.Manifest},
		{release.SignatureFile, release.MaxSignature, &rel.Signature},
		{release.InstalledFilesArtifact, release.MaxInstalledFilesDocument, &rel.List},
	} {
		if *f.dst, err = readReleaseFile(dirFD, f.name, f.max); err != nil {
			return Release{}, err
		}
	}
	names, err := rotationNames(dirFD)
	if err != nil {
		return Release{}, err
	}
	for _, name := range names {
		doc, err := readReleaseFile(dirFD, name, release.MaxRotation)
		if err != nil {
			return Release{}, err
		}
		sig, err := readReleaseFile(dirFD, name+SignatureSuffix, release.MaxSignature)
		if err != nil {
			return Release{}, err
		}
		rel.Rotations = append(rel.Rotations, release.SignedRotation{Document: doc, Signature: sig})
	}
	return rel, nil
}

// rotationNames lists dirFD and returns the rotation document names in
// sequence order 1..n. Every name must have its signature beside it and
// no number may be missing.
func rotationNames(dirFD int) ([]string, error) {
	dupFD, err := unix.FcntlInt(uintptr(dirFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: list directory: %v", ErrRelease, err)
	}
	d := os.NewFile(uintptr(dupFD), "release directory")
	defer d.Close()

	type pair struct{ doc, sig string }
	byNumber := map[int]*pair{}
	add := func(n int, name string, sig bool) error {
		p := byNumber[n]
		if p == nil {
			p = &pair{}
			byNumber[n] = p
		}
		dst := &p.doc
		if sig {
			dst = &p.sig
		}
		if *dst != "" {
			return fmt.Errorf("%w: %s and %s are both rotation %d", ErrRelease, *dst, name, n)
		}
		*dst = name
		return nil
	}
	listed, maxN := 0, 0
	for {
		batch, err := d.Readdirnames(256)
		listed += len(batch)
		if listed > MaxReleaseDirEntries {
			return nil, fmt.Errorf("%w: more than %d directory entries", ErrRelease, MaxReleaseDirEntries)
		}
		for _, name := range batch {
			if !strings.HasPrefix(name, RotationPrefix) {
				continue
			}
			n, sig, ok := parseRotationName(name)
			switch {
			case name == RotationFile:
				n, ok = 1, true
			case name == RotationSignatureFile:
				n, sig, ok = 1, true, true
			}
			if !ok {
				return nil, fmt.Errorf("%w: %q is not a valid rotation file name (%s-<1..%d>.json[%s])",
					ErrRelease, name, RotationPrefix, release.MaxRotations, SignatureSuffix)
			}
			if err := add(n, name, sig); err != nil {
				return nil, err
			}
			maxN = max(maxN, n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: list directory: %v", ErrRelease, err)
		}
	}
	names := make([]string, 0, maxN)
	for n := 1; n <= maxN; n++ {
		p := byNumber[n]
		switch {
		case p == nil:
			return nil, fmt.Errorf("%w: rotation %d is missing, but rotation %d is present", ErrRelease, n, maxN)
		case p.doc == "" || p.sig == "" || p.sig != p.doc+SignatureSuffix:
			return nil, fmt.Errorf("%w: rotation %d needs its document and its %s signature", ErrRelease, n, SignatureSuffix)
		}
		names = append(names, p.doc)
	}
	return names, nil
}

// readReleaseFile reads the regular file name in dirFD, at most max
// bytes. An absent file wraps both ErrRelease and os.ErrNotExist.
func readReleaseFile(dirFD int, name string, max int64) ([]byte, error) {
	var fd int
	var err error
	for {
		fd, err = unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("%w: %s: %w", ErrRelease, name, os.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrRelease, name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: stat %s: %v", ErrRelease, name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > max {
		return nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrRelease, name, max)
	}
	b, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrRelease, name, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrRelease, name, max)
	}
	return b, nil
}

// AdmitRelease admits rel for an offline check: the root state starts
// from anchors, which must be the anchors compiled into this binary
// (release.Anchors), and is advanced by rel's signed rotations in order,
// rotation i must have sequence i and be signed by a root active after
// rotation i-1 (ADR 0015 D2, spec 10). A rotation out of order, a gap,
// a replay or a signature by a revoked or unknown root rejects the whole
// release. Then Admit verifies the manifest signature against the
// resulting active roots, the list against the manifest and that the
// release is version. version must come from the admin, never from the
// checked installation. No key from the release directory is trusted.
func AdmitRelease(anchors []release.Anchor, version string, rel Release) (Reference, error) {
	if len(rel.Rotations) > release.MaxRotations {
		return Reference{}, fmt.Errorf("%w: more than %d rotations", release.ErrRotation, release.MaxRotations)
	}
	state, err := release.Bootstrap(anchors)
	if err != nil {
		return Reference{}, fmt.Errorf("release anchors: %w", err)
	}
	for i, r := range rel.Rotations {
		if state, _, err = state.ApplyRotation(r.Document, r.Signature); err != nil {
			return Reference{}, fmt.Errorf("apply root rotation %d: %w", i+1, err)
		}
	}
	return Admit(state, version, rel.Manifest, rel.Signature, rel.List)
}

// OfflineOwners resolves a listed owner for a check of a mounted
// installation. Only "root:root" (0:0) resolves: other names would be
// looked up in the checking machine's user database, which need not
// match the mounted installation's, and the mounted one is untrusted.
// Every other owner makes the file unreadable (owner-unknown), never ok.
func OfflineOwners(owner string) (uid, gid uint32, err error) {
	if owner != release.GeneratedOwner {
		return 0, 0, fmt.Errorf("owner %q cannot be resolved offline", owner)
	}
	return 0, 0, nil
}
