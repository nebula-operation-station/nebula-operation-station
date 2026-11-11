// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/gowebpki/jcs"
)

// This file is the I1 reference for NOS code (ADR 0015 D2, IG-02):
// installed-files.json, the list of every file a release installs, per
// install flavour. It is a release artifact like any other: the signed
// release manifest names its size and SHA-256 in "artifacts", so the list
// is trusted only through a manifest signature by a trusted release root.
// The list itself carries no signature and no key.

// InstalledFilesFormat is the "format" of installed-files.json.
const InstalledFilesFormat = "nebula-installed-files-v1"

// InstalledFilesArtifact is the release artifact name of the list.
const InstalledFilesArtifact = "installed-files.json"

// Installed-files limits (ADR 0015 D2).
const (
	// MaxInstalledFilesDocument bounds installed-files.json.
	MaxInstalledFilesDocument = 4 << 20
	// MaxInstalledEntries bounds the entries of one flavour.
	MaxInstalledEntries = 4096
	// MaxInstalledPath bounds an installed path and a symlink target.
	MaxInstalledPath = 255
	// MaxFlavours bounds the install flavours of one list.
	MaxFlavours = 16
	// MaxInstalledFileSize bounds one installed regular file.
	MaxInstalledFileSize = 1 << 30
)

// Installed file types.
const (
	// FileRegular is a regular file with size, SHA-256 and mode.
	FileRegular = "file"
	// FileSymlink is a symbolic link with an exact target.
	FileSymlink = "symlink"
)

// GeneratedOwner is the owner every file the generator lists has: release
// packages and install.sh install code as root:root.
const GeneratedOwner = "root:root"

// ErrInstalledFiles is an installed-files list that is well formed but not
// the one the signed release manifest covers: missing from the manifest,
// a size or digest mismatch, or a different release version.
var ErrInstalledFiles = errors.New("release: installed-files list does not match the signed manifest")

var (
	// installedPathRe: absolute, components of [A-Za-z0-9._+-].
	installedPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._+-]+)+$`)
	// symlinkTargetRe: relative or absolute, same characters.
	symlinkTargetRe = regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`)
	flavourRe       = regexp.MustCompile(`^(deb|tarball|container):[a-z][a-z0-9]{0,15}$`)
	ownerRe         = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}:[a-z_][a-z0-9_-]{0,31}$`)
	modeRe          = regexp.MustCompile(`^[0-7]{4}$`)
)

// installedTrees are directories whose whole subtree is NOS code.
var installedTrees = []string{
	"/usr/share/nebula/",
	"/usr/lib/nebula/",
	"/usr/share/doc/nebula-operation-station/",
}

// unitDirs hold the NOS systemd units: deb packages use /lib (and the
// merged /usr/lib), the tarball install /etc/systemd/system.
var unitDirs = []string{
	"/lib/systemd/system/",
	"/usr/lib/systemd/system/",
	"/etc/systemd/system/",
}

// ValidInstalledPath reports whether p may appear in installed-files.json:
// an absolute path of at most MaxInstalledPath bytes of [A-Za-z0-9/._+-],
// without empty, "." or ".." components, under a documented NOS prefix:
//
//   - /usr/bin/nebula*
//   - <unit dir>/nebula-<unit> and <unit dir>/nebula-<unit>.d/<drop-in>,
//     for unit dir /lib/systemd/system, /usr/lib/systemd/system or
//     /etc/systemd/system
//   - anything under /usr/share/nebula/, /usr/lib/nebula/ or
//     /usr/share/doc/nebula-operation-station/
//
// Configuration (/etc/nebula) and data (/var/lib/nebula, /run, caches) are
// never valid: they change by design and are not release code.
func ValidInstalledPath(p string) bool {
	if len(p) == 0 || len(p) > MaxInstalledPath || !installedPathRe.MatchString(p) {
		return false
	}
	for _, c := range strings.Split(p[1:], "/") {
		if c == "." || c == ".." {
			return false
		}
	}
	if rest, ok := strings.CutPrefix(p, "/usr/bin/"); ok {
		return strings.HasPrefix(rest, "nebula") && !strings.Contains(rest, "/")
	}
	for _, d := range unitDirs {
		rest, ok := strings.CutPrefix(p, d)
		if !ok {
			continue
		}
		parts := strings.Split(rest, "/")
		if !strings.HasPrefix(parts[0], "nebula-") {
			return false
		}
		return (len(parts) == 1 && !strings.HasSuffix(parts[0], ".d")) || (len(parts) == 2 && strings.HasSuffix(parts[0], ".d") && len(parts[0]) > len("nebula-.d"))
	}
	for _, d := range installedTrees {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// InstalledFile is one installed file of a flavour.
type InstalledFile struct {
	// Path is the absolute installed path.
	Path string
	// Type is FileRegular or FileSymlink.
	Type string
	// Size is the exact byte count of a regular file; 0 for a symlink.
	Size int64
	// SHA256 is the lowercase hex digest of a regular file's exact
	// bytes; empty for a symlink.
	SHA256 string
	// Mode is the permission and setuid/setgid/sticky bits of a regular
	// file (0 to 07777); 0 for a symlink, whose mode is not meaningful.
	Mode uint32
	// Owner is "user:group".
	Owner string
	// Target is a symlink's exact target; empty for a regular file.
	Target string
}

// Flavour is the file list of one install flavour.
type Flavour struct {
	// Name is "<deb|tarball|container>:<arch>".
	Name string
	// Files are sorted by path, without duplicates.
	Files []InstalledFile
}

// InstalledFiles is a parsed installed-files.json.
type InstalledFiles struct {
	// ReleaseVersion is the release SemVer; it equals the manifest's.
	ReleaseVersion string
	// Flavours are sorted by name.
	Flavours []Flavour
	// Digest is the SHA-256 of the exact document bytes.
	Digest string
}

// Flavour returns the flavour called name.
func (l InstalledFiles) Flavour(name string) (Flavour, bool) {
	for _, f := range l.Flavours {
		if f.Name == name {
			return f, true
		}
	}
	return Flavour{}, false
}

// ParseInstalledFiles parses a canonical installed-files.json without
// checking it against a manifest. Use VerifyInstalledFiles or
// VerifyPublishedInstalledFiles for admission. Every error wraps
// ErrFormat.
func ParseInstalledFiles(raw []byte) (InstalledFiles, error) {
	doc, err := decodeCanonical(raw, MaxInstalledFilesDocument)
	if err != nil {
		return InstalledFiles{}, err
	}
	l, err := parseInstalledFiles(doc)
	if err != nil {
		return InstalledFiles{}, fmt.Errorf("%w: installed files: %v", ErrFormat, err)
	}
	sum := sha256.Sum256(raw)
	l.Digest = hex.EncodeToString(sum[:])
	return l, nil
}

func parseInstalledFiles(doc map[string]any) (InstalledFiles, error) {
	top, err := fields(doc, "format", "release_version", "flavours")
	if err != nil {
		return InstalledFiles{}, err
	}
	if f, err := str(top, "format"); err != nil || f != InstalledFilesFormat {
		return InstalledFiles{}, fmt.Errorf("format must be %q", InstalledFilesFormat)
	}
	var l InstalledFiles
	if l.ReleaseVersion, err = str(top, "release_version"); err != nil {
		return InstalledFiles{}, err
	}
	if !ValidReleaseVersion(l.ReleaseVersion) {
		return InstalledFiles{}, errors.New("release_version must be SemVer 2.0.0 without a leading v")
	}
	fl, ok := top["flavours"].(map[string]any)
	if !ok {
		return InstalledFiles{}, errors.New(`field "flavours" must be an object`)
	}
	if len(fl) == 0 || len(fl) > MaxFlavours {
		return InstalledFiles{}, fmt.Errorf("flavours must have 1 to %d entries", MaxFlavours)
	}
	names := make([]string, 0, len(fl))
	for name := range fl {
		if !flavourRe.MatchString(name) {
			return InstalledFiles{}, errors.New("flavour names must be <deb|tarball|container>:<arch>")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entries, err := array(fl, name, 1, MaxInstalledEntries)
		if err != nil {
			return InstalledFiles{}, fmt.Errorf("flavour %s: %v", name, err)
		}
		f := Flavour{Name: name, Files: make([]InstalledFile, 0, len(entries))}
		paths := make(map[string]bool, len(entries))
		for i, v := range entries {
			e, err := parseInstalledFile(v)
			if err != nil {
				return InstalledFiles{}, fmt.Errorf("flavour %s: files[%d]: %v", name, i, err)
			}
			if i > 0 && f.Files[i-1].Path >= e.Path {
				return InstalledFiles{}, fmt.Errorf("flavour %s: files must be sorted by path without duplicates", name)
			}
			paths[e.Path] = true
			f.Files = append(f.Files, e)
		}
		// No listed file may also be a directory of another listed file.
		for _, e := range f.Files {
			for d := e.Path; ; {
				j := strings.LastIndexByte(d, '/')
				if j <= 0 {
					break
				}
				d = d[:j]
				if paths[d] {
					return InstalledFiles{}, fmt.Errorf("flavour %s: a listed file is also the directory of another", name)
				}
			}
		}
		l.Flavours = append(l.Flavours, f)
	}
	return l, nil
}

func parseInstalledFile(v any) (InstalledFile, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return InstalledFile{}, errors.New("expected an object")
	}
	var e InstalledFile
	var err error
	if e.Type, err = str(m, "type"); err != nil {
		return InstalledFile{}, err
	}
	switch e.Type {
	case FileRegular:
		if m, err = fields(m, "path", "type", "size", "sha256", "mode", "owner"); err != nil {
			return InstalledFile{}, err
		}
		if e.Size, err = integer(m, "size", 0, MaxInstalledFileSize); err != nil {
			return InstalledFile{}, err
		}
		if e.SHA256, err = sha256Hex(m, "sha256"); err != nil {
			return InstalledFile{}, err
		}
		mode, err := str(m, "mode")
		if err != nil || !modeRe.MatchString(mode) {
			return InstalledFile{}, errors.New(`field "mode" must be four octal digits`)
		}
		n, _ := strconv.ParseUint(mode, 8, 32)
		e.Mode = uint32(n)
	case FileSymlink:
		if m, err = fields(m, "path", "type", "target", "owner"); err != nil {
			return InstalledFile{}, err
		}
		if e.Target, err = str(m, "target"); err != nil || !validSymlinkTarget(e.Target) {
			return InstalledFile{}, fmt.Errorf(`field "target" must be 1 to %d bytes of [A-Za-z0-9/._+-]`, MaxInstalledPath)
		}
	default:
		return InstalledFile{}, fmt.Errorf(`field "type" must be %q or %q`, FileRegular, FileSymlink)
	}
	if e.Path, err = str(m, "path"); err != nil || !ValidInstalledPath(e.Path) {
		return InstalledFile{}, errors.New(`field "path" is not a covered NOS path`)
	}
	if e.Owner, err = str(m, "owner"); err != nil || !ownerRe.MatchString(e.Owner) {
		return InstalledFile{}, errors.New(`field "owner" must be user:group`)
	}
	return e, nil
}

func validSymlinkTarget(s string) bool {
	return len(s) > 0 && len(s) <= MaxInstalledPath && symlinkTargetRe.MatchString(s)
}

// Marshal returns the canonical (RFC 8785) document for l. It rejects a
// list that ParseInstalledFiles would reject, so its output always
// parses back to l.
func (l InstalledFiles) Marshal() ([]byte, error) {
	flavours := make(map[string]any, len(l.Flavours))
	for _, f := range l.Flavours {
		if _, dup := flavours[f.Name]; dup {
			return nil, fmt.Errorf("%w: installed files: duplicate flavour %s", ErrFormat, f.Name)
		}
		files := make([]any, 0, len(f.Files))
		for _, e := range f.Files {
			switch e.Type {
			case FileRegular:
				files = append(files, map[string]any{"path": e.Path, "type": e.Type, "size": e.Size, "sha256": e.SHA256,
					"mode": fmt.Sprintf("%04o", e.Mode), "owner": e.Owner})
			case FileSymlink:
				files = append(files, map[string]any{"path": e.Path, "type": e.Type, "target": e.Target, "owner": e.Owner})
			default:
				return nil, fmt.Errorf("%w: installed files: %s has an unknown type", ErrFormat, f.Name)
			}
		}
		flavours[f.Name] = files
	}
	b, err := json.Marshal(map[string]any{"format": InstalledFilesFormat, "release_version": l.ReleaseVersion, "flavours": flavours})
	if err != nil {
		return nil, fmt.Errorf("%w: installed files: encode: %v", ErrFormat, err)
	}
	raw, err := jcs.Transform(b)
	if err != nil {
		return nil, fmt.Errorf("%w: installed files: canonicalize: %v", ErrFormat, err)
	}
	if _, err := ParseInstalledFiles(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// VerifyInstalledFiles admits installed-files.json: sig must be a valid
// release signature over manifest by an active root of state, the
// manifest must list InstalledFilesArtifact with exactly list's size and
// SHA-256, and the list must parse and name the manifest's release
// version. Size and digest are compared before the list is parsed.
// state is the executor's durable root state, which starts from the
// anchors compiled into the binary; never pass keys supplied beside the
// files.
func VerifyInstalledFiles(state RootState, manifest, sig, list []byte) (Manifest, InstalledFiles, error) {
	if err := state.Validate(); err != nil {
		return Manifest{}, InstalledFiles{}, err
	}
	m, err := VerifyManifest(state.Active(), manifest, sig)
	if err != nil {
		return Manifest{}, InstalledFiles{}, err
	}
	l, err := matchInstalledFiles(m, list)
	if err != nil {
		return Manifest{}, InstalledFiles{}, err
	}
	return m, l, nil
}

// SignedRotation is a published root-rotation document and its detached
// signature.
type SignedRotation struct {
	// Document is the exact root-rotation.json bytes.
	Document []byte
	// Signature is the armored SSHSIG signature over Document.
	Signature []byte
}

// VerifyPublishedInstalledFiles verifies a published release (for example
// the assets of a GitHub release) without local root state: the trusted
// roots are the anchors compiled into this binary, advanced in order by
// the given signed rotations (spec 10), each authorized by a root trusted
// before it. Then it checks as VerifyInstalledFiles does. No key from the
// release page or anywhere else is consulted.
func VerifyPublishedInstalledFiles(rotations []SignedRotation, manifest, sig, list []byte) (Manifest, InstalledFiles, error) {
	anchors, err := Anchors()
	if err != nil {
		return Manifest{}, InstalledFiles{}, fmt.Errorf("compiled release anchors: %w", err)
	}
	return verifyPublished(anchors, rotations, manifest, sig, list)
}

func verifyPublished(anchors []Anchor, rotations []SignedRotation, manifest, sig, list []byte) (Manifest, InstalledFiles, error) {
	if len(rotations) > MaxRotations {
		return Manifest{}, InstalledFiles{}, fmt.Errorf("%w: more than %d rotations", ErrRotation, MaxRotations)
	}
	state, err := Bootstrap(anchors)
	if err != nil {
		return Manifest{}, InstalledFiles{}, err
	}
	for i, r := range rotations {
		if state, _, err = state.ApplyRotation(r.Document, r.Signature); err != nil {
			return Manifest{}, InstalledFiles{}, fmt.Errorf("rotation %d: %w", i+1, err)
		}
	}
	return VerifyInstalledFiles(state, manifest, sig, list)
}

// matchInstalledFiles checks list against a manifest whose signature was
// verified by the caller.
func matchInstalledFiles(m Manifest, list []byte) (InstalledFiles, error) {
	var art Artifact
	for _, a := range m.Artifacts {
		if a.Name == InstalledFilesArtifact {
			art = a
		}
	}
	if art.Name == "" {
		return InstalledFiles{}, fmt.Errorf("%w: the manifest lists no %s", ErrInstalledFiles, InstalledFilesArtifact)
	}
	sum := sha256.Sum256(list)
	if int64(len(list)) != art.Size || hex.EncodeToString(sum[:]) != art.SHA256 {
		return InstalledFiles{}, fmt.Errorf("%w: size or SHA-256 differs from the manifest", ErrInstalledFiles)
	}
	l, err := ParseInstalledFiles(list)
	if err != nil {
		return InstalledFiles{}, err
	}
	if l.ReleaseVersion != m.ReleaseVersion {
		return InstalledFiles{}, fmt.Errorf("%w: release_version %s differs from the manifest's %s", ErrInstalledFiles, l.ReleaseVersion, m.ReleaseVersion)
	}
	return l, nil
}

// GenerateInstalledFiles builds installed-files.json for release tooling
// from a build directory holding one subdirectory per install flavour,
// named exactly like the flavour ("deb:amd64", "tarball:arm64", ...), each
// the staged file tree as installed (for example the extracted package
// data). Every regular file and symlink becomes an entry; directories are
// implied. Modes come from the tree, the owner is always GeneratedOwner.
// Symlinks are recorded, never followed. Any other file type, a path
// outside the covered NOS prefixes (configuration and data must not be
// staged) or a limit violation rejects the build with ErrFormat.
func GenerateInstalledFiles(version, buildDir string) ([]byte, error) {
	if !ValidReleaseVersion(version) {
		return nil, fmt.Errorf("%w: release version %q is not SemVer", ErrFormat, version)
	}
	top, err := os.OpenRoot(buildDir)
	if err != nil {
		return nil, fmt.Errorf("open build directory: %w", err)
	}
	defer top.Close()
	ents, err := fs.ReadDir(top.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("list build directory: %w", err)
	}
	if len(ents) == 0 || len(ents) > MaxFlavours {
		return nil, fmt.Errorf("%w: the build directory needs 1 to %d flavour directories", ErrFormat, MaxFlavours)
	}
	l := InstalledFiles{ReleaseVersion: version}
	for _, ent := range ents {
		if !ent.Type().IsDir() || !flavourRe.MatchString(ent.Name()) {
			return nil, fmt.Errorf("%w: build directory entry %q is not a flavour directory", ErrFormat, ent.Name())
		}
		files, err := generateFlavour(top, ent.Name())
		if err != nil {
			return nil, fmt.Errorf("flavour %s: %w", ent.Name(), err)
		}
		l.Flavours = append(l.Flavours, Flavour{Name: ent.Name(), Files: files})
	}
	return l.Marshal()
}

func generateFlavour(top *os.Root, name string) ([]InstalledFile, error) {
	r, err := top.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer r.Close()
	var files []InstalledFile
	err = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		abs := "/" + p
		if !ValidInstalledPath(abs) {
			return fmt.Errorf("%w: %q is not a covered NOS path", ErrFormat, abs)
		}
		if len(files) == MaxInstalledEntries {
			return fmt.Errorf("%w: more than %d files", ErrFormat, MaxInstalledEntries)
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := r.Readlink(p)
			if err != nil {
				return fmt.Errorf("read link %s: %w", abs, err)
			}
			if !validSymlinkTarget(target) {
				return fmt.Errorf("%w: %s: symlink target is not 1 to %d bytes of [A-Za-z0-9/._+-]", ErrFormat, abs, MaxInstalledPath)
			}
			files = append(files, InstalledFile{Path: abs, Type: FileSymlink, Target: target, Owner: GeneratedOwner})
		case d.Type().IsRegular():
			f, err := hashInstalled(r, p)
			if err != nil {
				return err
			}
			files = append(files, f)
		default:
			return fmt.Errorf("%w: %s is neither a regular file nor a symlink", ErrFormat, abs)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: no files", ErrFormat)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// hashInstalled hashes one staged regular file without following
// symlinks and rejects a file that changes while it is read.
func hashInstalled(r *os.Root, p string) (InstalledFile, error) {
	abs := "/" + p
	// O_NONBLOCK: a FIFO swapped in after the walk must not hang the open.
	f, err := r.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return InstalledFile{}, fmt.Errorf("open %s: %w", abs, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return InstalledFile{}, fmt.Errorf("stat %s: %w", abs, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxInstalledFileSize {
		return InstalledFile{}, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrFormat, abs, MaxInstalledFileSize)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxInstalledFileSize+1))
	if err != nil {
		return InstalledFile{}, fmt.Errorf("read %s: %w", abs, err)
	}
	if n != fi.Size() {
		return InstalledFile{}, fmt.Errorf("%w: %s changed while it was hashed", ErrFormat, abs)
	}
	mode := uint32(fi.Mode().Perm())
	if fi.Mode()&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if fi.Mode()&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if fi.Mode()&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return InstalledFile{Path: abs, Type: FileRegular, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: mode, Owner: GeneratedOwner}, nil
}
