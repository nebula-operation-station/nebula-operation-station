// SPDX-License-Identifier: AGPL-3.0-or-later

package stage

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// ErrPackage is a built package (deb, tarball or container export) that
// cannot be staged: malformed, an unsupported format, a file type other
// than regular file or symlink where code is installed, a file not owned
// by root, an unsafe path, or a file the install flavour needs missing.
var ErrPackage = errors.New("stage: invalid release package")

// ErrMissingFlavour is an install flavour whose build output is not in
// the dist directory. Every expected flavour must be present; none is
// left out silently.
var ErrMissingFlavour = errors.New("stage: install flavour missing from dist")

// Package reading limits.
const (
	// maxArchiveEntries bounds the entries of one package archive (a
	// container export carries the whole base image).
	maxArchiveEntries = 1 << 17
	// maxArchiveContent bounds the uncompressed content of one package.
	maxArchiveContent = 4 << 30
	// maxArMembers bounds the members of a .deb.
	maxArMembers = 8
	// maxBinariesList bounds deploy/quickstart/binaries.txt.
	maxBinariesList = 64 << 10
	// maxBinaries bounds the names in the binary list.
	maxBinaries = 64
)

// Archive paths inside the release tarball.
const (
	binariesListPath = "deploy/quickstart/binaries.txt"
	tarballUnitDir   = "deploy/systemd/"
)

// Where deploy/install.sh installs from a tarball, and with which modes
// (install -m 0755 for binaries, install -m 0644 for units).
const (
	tarballBinDir   = "usr/bin/"
	tarballUnitDest = "etc/systemd/system/"
	tarballBinMode  = 0o755
	tarballUnitMode = 0o644
)

// tarballUnits are the unit files deploy/install.sh (tarball_units)
// installs from a release tarball. TestTarballUnitsMatchInstallScript
// keeps the two lists equal.
var tarballUnits = []string{
	"nebula-server.service",
	"nebula-executor.service",
	"nebula-pve-collector.service",
	"nebula-netdev-collector.service",
	"nebula-discovery.path",
	"nebula-discovery.service",
	"nebula-discovery.timer",
}

// Flavour kinds.
const (
	kindDeb       = "deb"
	kindTarball   = "tarball"
	kindContainer = "container"
)

// flavourSource is one install flavour and the dist file it is read from.
type flavourSource struct {
	name string
	kind string
	file string
	// publish marks a file that is a release payload. The container
	// export is not: the image is published to the registry.
	publish bool
}

// expectedFlavours lists every install flavour a release has, matching
// .goreleaser.yaml: deb and tarball for amd64 and arm64 (nfpms, archives)
// and the amd64 container image (dockers), exported by `make
// release-stage` as a flat filesystem tar.
func expectedFlavours(version string) []flavourSource {
	return []flavourSource{
		{name: "container:amd64", kind: kindContainer, file: "nebula_" + version + "_container_linux_amd64.tar"},
		{name: "deb:amd64", kind: kindDeb, file: "nebula-operation-station_" + version + "_amd64.deb", publish: true},
		{name: "deb:arm64", kind: kindDeb, file: "nebula-operation-station_" + version + "_arm64.deb", publish: true},
		{name: "tarball:amd64", kind: kindTarball, file: "nebula_" + version + "_linux_amd64.tar.gz", publish: true},
		{name: "tarball:arm64", kind: kindTarball, file: "nebula_" + version + "_linux_arm64.tar.gz", publish: true},
	}
}

// checkFlavoursPresent reports every expected flavour whose dist file is
// missing or not a regular file, all in one error.
func checkFlavoursPresent(dist *os.Root, flavours []flavourSource) error {
	var missing []string
	for _, f := range flavours {
		fi, err := dist.Lstat(f.file)
		if err != nil || !fi.Mode().IsRegular() {
			missing = append(missing, f.name+" ("+f.file+")")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingFlavour, strings.Join(missing, ", "))
	}
	return nil
}

// openDist opens a regular dist file without following symlinks.
func openDist(dist *os.Root, name string) (*os.File, os.FileInfo, error) {
	f, err := dist.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", name, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > release.MaxArtifactSize {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrPackage, name, int64(release.MaxArtifactSize))
	}
	return f, fi, nil
}

// stageFlavours extracts every flavour's installed file tree into
// installed/<flavour>/. Every flavour must install each binary of the
// list the tarballs carry (all equal) as /usr/bin/<name>.
func stageFlavours(ctx context.Context, dist, installed *os.Root, flavours []flavourSource) error {
	var binaries []string
	for _, f := range flavours {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.kind != kindTarball {
			continue
		}
		list, err := tarballBinaries(dist, f.file)
		if err != nil {
			return fmt.Errorf("flavour %s: %w", f.name, err)
		}
		if binaries == nil {
			binaries = list
		} else if strings.Join(list, "\n") != strings.Join(binaries, "\n") {
			return fmt.Errorf("%w: flavour %s: %s differs from the other tarballs", ErrPackage, f.name, binariesListPath)
		}
	}
	if binaries == nil {
		return fmt.Errorf("%w: no tarball flavour carries %s", ErrPackage, binariesListPath)
	}
	for _, f := range flavours {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := stageFlavour(dist, installed, f, binaries); err != nil {
			return fmt.Errorf("flavour %s: %w", f.name, err)
		}
	}
	return nil
}

func stageFlavour(dist, installed *os.Root, f flavourSource, binaries []string) error {
	if err := installed.Mkdir(f.name, 0o755); err != nil {
		return fmt.Errorf("create staging: %w", err)
	}
	r, err := installed.OpenRoot(f.name)
	if err != nil {
		return fmt.Errorf("open staging: %w", err)
	}
	defer r.Close()
	s := &stager{root: r, seen: map[string]bool{}}
	file, _, err := openDist(dist, f.file)
	if err != nil {
		return err
	}
	defer file.Close()
	switch f.kind {
	case kindDeb:
		data, err := debDataTar(bufio.NewReader(file))
		if err != nil {
			return fmt.Errorf("%s: %w", f.file, err)
		}
		err = s.walk(data, func(p string, h *tar.Header) (string, int64, bool) { return p, h.Mode, true })
		if err != nil {
			return fmt.Errorf("%s: %w", f.file, err)
		}
	case kindTarball:
		if err := s.stageTarball(file, binaries); err != nil {
			return fmt.Errorf("%s: %w", f.file, err)
		}
	case kindContainer:
		err := s.walk(file, func(p string, h *tar.Header) (string, int64, bool) { return p, h.Mode, nosArea("/" + p) })
		if err != nil {
			return fmt.Errorf("%s: %w", f.file, err)
		}
	default:
		return fmt.Errorf("unknown flavour kind %q", f.kind)
	}
	for _, b := range binaries {
		fi, err := r.Lstat(tarballBinDir + b)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s does not install /%s%s", ErrPackage, f.file, tarballBinDir, b)
		}
	}
	return nil
}

// nosArea reports whether abs is somewhere NOS installs code: the
// container flavour lists these paths of the image and nothing of the
// base system. A path here that the flavour may not list (a unit, a name
// outside the path grammar) is staged anyway so that the generator
// rejects it instead of it being dropped.
func nosArea(abs string) bool {
	if strings.HasPrefix(abs, "/usr/bin/nebula") {
		return true
	}
	for _, t := range []string{"/usr/share/nebula/", "/usr/lib/nebula/", "/usr/share/doc/nebula-operation-station/"} {
		if strings.HasPrefix(abs, t) {
			return true
		}
	}
	for _, d := range []string{"/lib/systemd/system/", "/usr/lib/systemd/system/", "/etc/systemd/system/"} {
		if strings.HasPrefix(abs, d+"nebula-") {
			return true
		}
	}
	return false
}

// debDataTar returns the data.tar of a .deb (an ar archive): debian-binary
// 2.x first, then data.tar.gz. Other data compressions are rejected; the
// nfpm default is gzip.
func debDataTar(r *bufio.Reader) (io.Reader, error) {
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("%w: not an ar archive", ErrPackage)
	}
	for i := 0; i < maxArMembers; i++ {
		h := make([]byte, 60)
		if _, err := io.ReadFull(r, h); err != nil {
			return nil, fmt.Errorf("%w: no data.tar.gz member", ErrPackage)
		}
		if string(h[58:60]) != "`\n" {
			return nil, fmt.Errorf("%w: malformed ar header", ErrPackage)
		}
		name := strings.TrimSuffix(strings.TrimRight(string(h[0:16]), " "), "/")
		size, err := strconv.ParseInt(strings.TrimRight(string(h[48:58]), " "), 10, 64)
		if err != nil || size < 0 || size > release.MaxArtifactSize {
			return nil, fmt.Errorf("%w: ar member %q has a malformed size", ErrPackage, name)
		}
		switch {
		case i == 0:
			if name != "debian-binary" || size > 16 {
				return nil, fmt.Errorf("%w: the first member is not debian-binary", ErrPackage)
			}
			v := make([]byte, size)
			if _, err := io.ReadFull(r, v); err != nil || !strings.HasPrefix(string(v), "2.") {
				return nil, fmt.Errorf("%w: unsupported deb format version", ErrPackage)
			}
		case name == "data.tar.gz":
			zr, err := gzip.NewReader(io.LimitReader(r, size))
			if err != nil {
				return nil, fmt.Errorf("%w: data.tar.gz: %v", ErrPackage, err)
			}
			return zr, nil
		case strings.HasPrefix(name, "data.tar"):
			return nil, fmt.Errorf("%w: unsupported deb data member %q (want data.tar.gz)", ErrPackage, name)
		default:
			if _, err := r.Discard(int(size)); err != nil {
				return nil, fmt.Errorf("%w: ar member %q is truncated", ErrPackage, name)
			}
		}
		if size%2 == 1 {
			if _, err := r.Discard(1); err != nil {
				return nil, fmt.Errorf("%w: ar member %q is truncated", ErrPackage, name)
			}
		}
	}
	return nil, fmt.Errorf("%w: no data.tar.gz member", ErrPackage)
}

// stager writes one flavour's installed tree.
type stager struct {
	root    *os.Root
	seen    map[string]bool
	entries int
	// regularOnly rejects symlinks (install(1) would copy their target).
	regularOnly bool
	// anyOwner skips the root ownership check: install(1) -o root -g root
	// sets the owner, so the archive's (the build user's) is irrelevant.
	anyOwner bool
	content  int64
}

// selectFunc maps an archive entry (normalized path) to its installed
// path and mode, or reports that it is not installed.
type selectFunc func(p string, h *tar.Header) (dst string, mode int64, ok bool)

// archivePath normalizes an archive entry name: no leading "./", no
// absolute path, no empty, "." or ".." component.
func archivePath(name string, dir bool) (string, error) {
	p := strings.TrimPrefix(name, "./")
	if dir {
		p = strings.TrimSuffix(p, "/")
		if p == "" || p == "." {
			return "", nil
		}
	}
	if p == "" || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: unsafe archive path %q", ErrPackage, name)
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return "", fmt.Errorf("%w: unsafe archive path %q", ErrPackage, name)
		}
	}
	return p, nil
}

// walk stages the regular files and symlinks of the tar stream r that sel
// selects. Selected entries must be regular files or symlinks owned by
// root (uid and gid 0); directories are implied.
func (s *stager) walk(r io.Reader, sel selectFunc) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: read tar: %v", ErrPackage, err)
		}
		if s.entries++; s.entries > maxArchiveEntries {
			return fmt.Errorf("%w: more than %d entries", ErrPackage, maxArchiveEntries)
		}
		if s.content += max(h.Size, 0); s.content > maxArchiveContent {
			return fmt.Errorf("%w: more than %d bytes of content", ErrPackage, int64(maxArchiveContent))
		}
		p, err := archivePath(h.Name, h.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		if p == "" {
			continue
		}
		dst, mode, ok := sel(p, h)
		if !ok {
			continue
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if err := s.add(dst, h, mode, tr); err != nil {
			return err
		}
	}
}

// add stages one entry at dst.
func (s *stager) add(dst string, h *tar.Header, mode int64, data io.Reader) error {
	if !s.anyOwner && (h.Uid != 0 || h.Gid != 0) {
		return fmt.Errorf("%w: %s is not owned by root:root", ErrPackage, h.Name)
	}
	if s.seen[dst] {
		return fmt.Errorf("%w: %s is in the archive twice", ErrPackage, h.Name)
	}
	s.seen[dst] = true
	if dir := path.Dir(dst); dir != "." {
		if err := s.root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("%w: stage %s: %v", ErrPackage, dst, err)
		}
	}
	switch h.Typeflag {
	case tar.TypeReg:
		if h.Size > release.MaxInstalledFileSize {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrPackage, h.Name, release.MaxInstalledFileSize)
		}
		f, err := s.root.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fmt.Errorf("%w: stage %s: %v", ErrPackage, dst, err)
		}
		n, err := io.Copy(f, io.LimitReader(data, h.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil || n != h.Size {
			return fmt.Errorf("%w: stage %s: short or failed copy", ErrPackage, dst)
		}
		if err := s.root.Chmod(dst, fileMode(mode)); err != nil {
			return fmt.Errorf("stage %s: %w", dst, err)
		}
	case tar.TypeSymlink:
		if s.regularOnly {
			return fmt.Errorf("%w: %s is a symlink; install(1) needs a regular file", ErrPackage, h.Name)
		}
		if err := s.root.Symlink(h.Linkname, dst); err != nil {
			return fmt.Errorf("%w: stage %s: %v", ErrPackage, dst, err)
		}
	default:
		return fmt.Errorf("%w: %s is neither a regular file nor a symlink (type %q)", ErrPackage, h.Name, h.Typeflag)
	}
	return nil
}

// fileMode converts a tar mode (permissions plus setuid, setgid, sticky)
// to an fs.FileMode.
func fileMode(m int64) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

// tarballBinaries reads the binary list a release tarball carries.
func tarballBinaries(dist *os.Root, name string) ([]string, error) {
	f, _, err := openDist(dist, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrPackage, name, err)
	}
	tr := tar.NewReader(zr)
	var list []byte
	found := false
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: read tar: %v", ErrPackage, name, err)
		}
		if n >= maxArchiveEntries {
			return nil, fmt.Errorf("%w: %s: more than %d entries", ErrPackage, name, maxArchiveEntries)
		}
		if strings.TrimPrefix(h.Name, "./") != binariesListPath {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Size > maxBinariesList {
			return nil, fmt.Errorf("%w: %s: %s must be one regular file of at most %d bytes", ErrPackage, name, binariesListPath, maxBinariesList)
		}
		found = true
		if list, err = io.ReadAll(io.LimitReader(tr, maxBinariesList)); err != nil {
			return nil, fmt.Errorf("%w: %s: read %s: %v", ErrPackage, name, binariesListPath, err)
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: %s lacks %s", ErrPackage, name, binariesListPath)
	}
	bins, err := parseBinaries(list)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return bins, nil
}

var binaryNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// parseBinaries parses deploy/quickstart/binaries.txt with the grammar of
// deploy/quickstart/binaries_lib.sh: one name per line, blank lines and
// lines starting (after blanks) with # ignored, a trailing CR stripped.
func parseBinaries(b []byte) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimLeft(line, " \t\v\f\r")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !binaryNameRe.MatchString(line) || len(line) > 64 {
			return nil, fmt.Errorf("%w: invalid binary name %q in %s", ErrPackage, line, binariesListPath)
		}
		if seen[line] {
			return nil, fmt.Errorf("%w: binary %q listed twice in %s", ErrPackage, line, binariesListPath)
		}
		seen[line] = true
		out = append(out, line)
	}
	if len(out) == 0 || len(out) > maxBinaries {
		return nil, fmt.Errorf("%w: %s lists %d binaries, want 1 to %d", ErrPackage, binariesListPath, len(out), maxBinaries)
	}
	return out, nil
}

// stageTarball stages what deploy/install.sh installs from a release
// tarball: each listed binary (a top-level regular file) as
// /usr/bin/<name> mode 0755 and each of tarballUnits from deploy/systemd/
// as /etc/systemd/system/<unit> mode 0644, all root-owned. The rest of the
// tarball is not installed.
func (s *stager) stageTarball(f *os.File, binaries []string) error {
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPackage, err)
	}
	want := map[string]string{}
	modes := map[string]int64{}
	for _, b := range binaries {
		want[b] = tarballBinDir + b
		modes[b] = tarballBinMode
	}
	for _, u := range tarballUnits {
		want[tarballUnitDir+u] = tarballUnitDest + u
		modes[tarballUnitDir+u] = tarballUnitMode
	}
	// install(1) copies a symlink's target; the tarball must ship files.
	s.regularOnly = true
	s.anyOwner = true
	err = s.walk(zr, func(p string, h *tar.Header) (string, int64, bool) {
		dst, ok := want[p]
		if !ok {
			return "", 0, false
		}
		return dst, modes[p], true
	})
	if err != nil {
		return err
	}
	for src, dst := range want {
		if !s.seen[dst] {
			return fmt.Errorf("%w: the tarball lacks %s", ErrPackage, src)
		}
	}
	return nil
}
