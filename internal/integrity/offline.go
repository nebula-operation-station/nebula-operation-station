// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Release root rotation files an offline release directory may hold
// (spec 10 "Root rotation and revocation"). Both or neither must exist.
const (
	// RotationFile is the published signed root rotation document.
	RotationFile = "root-rotation.json"
	// RotationSignatureFile is its detached signature.
	RotationSignatureFile = "root-rotation.json.sig"
)

// ErrRelease is an offline release directory that cannot be read safely:
// a missing, oversized or non-regular file, or a symlink.
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
	// Rotation is the optional published root rotation, nil if absent.
	Rotation *release.SignedRotation
}

// ReadRelease reads the release files from the absolute directory dir.
// It only reads: dir itself and every file are opened without following
// a symlink, each file must be a regular file within its size limit, and
// a FIFO in place of a file does not block. Missing required files and a
// lone rotation document or signature are ErrRelease.
func ReadRelease(dir string) (Release, error) {
	if !strings.HasPrefix(dir, "/") {
		return Release{}, fmt.Errorf("%w: directory must be absolute", ErrRelease)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	doc, docErr := readReleaseFile(dirFD, RotationFile, release.MaxRotation)
	sig, sigErr := readReleaseFile(dirFD, RotationSignatureFile, release.MaxSignature)
	docAbsent, sigAbsent := errors.Is(docErr, os.ErrNotExist), errors.Is(sigErr, os.ErrNotExist)
	switch {
	case docAbsent && sigAbsent:
		return rel, nil
	case docAbsent || sigAbsent:
		return Release{}, fmt.Errorf("%w: %s and %s must both be present or both absent", ErrRelease, RotationFile, RotationSignatureFile)
	case docErr != nil:
		return Release{}, docErr
	case sigErr != nil:
		return Release{}, sigErr
	}
	rel.Rotation = &release.SignedRotation{Document: doc, Signature: sig}
	return rel, nil
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
// (release.Anchors), and is advanced only by rel's signed rotation, each
// step authorized by a root trusted before it. Then Admit verifies the
// manifest signature, the list against the manifest and that the release
// is version. version must come from the admin, never from the checked
// installation (ADR 0015 D2). No key from the release directory is
// trusted.
func AdmitRelease(anchors []release.Anchor, version string, rel Release) (Reference, error) {
	state, err := release.Bootstrap(anchors)
	if err != nil {
		return Reference{}, fmt.Errorf("release anchors: %w", err)
	}
	if rel.Rotation != nil {
		if state, _, err = state.ApplyRotation(rel.Rotation.Document, rel.Rotation.Signature); err != nil {
			return Reference{}, fmt.Errorf("apply %s: %w", RotationFile, err)
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
