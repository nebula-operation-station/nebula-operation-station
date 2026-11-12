// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stage prepares the unsigned staging directory for offline
// release signing (docs/admin/release-signing.md) from a goreleaser dist
// directory and the repository's module tree:
//
//	payloads/                          every attachment to publish:
//	                                   archives, .deb packages, the
//	                                   goreleaser checksum file,
//	                                   builtins.tar, installed-files.json
//	module-bytes/<name>/<version>.tar  the exact nested module tars
//	installed/<flavour>/...            the installed file trees the list
//	                                   was generated from (offline recheck)
//	SHA256SUMS                         sha256sum -c list over payloads/
//
// Nothing is signed and no manifest is written; signing happens offline.
// All outputs depend only on the inputs: two runs over the same dist and
// module tree produce identical bytes.
package stage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// ErrVersion is a release version that is not SemVer without a leading
// "v" or that would make a payload name invalid in the manifest.
var ErrVersion = errors.New("stage: invalid release version")

// ErrOut is an output path that is not a new or empty real directory.
var ErrOut = errors.New("stage: output must be a new or empty directory")

// ErrChecksums is a goreleaser checksum file that is malformed or does
// not list exactly the published dist files with their hashes.
var ErrChecksums = errors.New("stage: checksum file does not match the dist files")

// Staging layout names.
const (
	PayloadsDir    = "payloads"
	ModuleBytesDir = "module-bytes"
	InstalledDir   = "installed"
	SumsFile       = "SHA256SUMS"
)

// maxChecksums bounds the goreleaser checksum file.
const maxChecksums = 64 << 10

// artifactNameRe is the manifest's artifact name grammar (spec 10).
var artifactNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// checksumLineRe is one sha256sum line of the goreleaser checksum file.
var checksumLineRe = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$`)

// Options configures one staging run.
type Options struct {
	// Version is the release version (SemVer, no leading v), the one
	// goreleaser built.
	Version string
	// Dist is the goreleaser output directory.
	Dist string
	// Out is the staging directory: new, or an existing empty directory.
	Out string
	// Modules is the module source tree (the repository's modules/).
	Modules string
}

// Result describes a finished staging.
type Result struct {
	// Payloads are the files in payloads/, sorted by name.
	Payloads []release.Artifact
	// Modules are the built-in modules, sorted by name.
	Modules []release.Module
}

// checksumsName is goreleaser's checksum file for version
// (checksum.name_template in .goreleaser.yaml).
func checksumsName(version string) string { return "nebula_" + version + "_checksums.txt" }

// Run stages a release. On any error the output directory is emptied
// again, so a partial staging is never left behind for review.
func Run(ctx context.Context, o Options) (Result, error) {
	if err := checkVersion(o.Version); err != nil {
		return Result{}, err
	}
	out, err := prepareOut(o.Out)
	if err != nil {
		return Result{}, err
	}
	defer out.Close()
	res, err := stageAll(ctx, o, out)
	if err != nil {
		if cerr := emptyDir(out); cerr != nil {
			return Result{}, fmt.Errorf("%w (cleaning %s also failed: %v)", err, o.Out, cerr)
		}
		return Result{}, err
	}
	return res, nil
}

// stageAll writes the staging into out.
func stageAll(ctx context.Context, o Options, out *os.Root) (Result, error) {
	flavours := expectedFlavours(o.Version)
	dist, err := os.OpenRoot(o.Dist)
	if err != nil {
		return Result{}, fmt.Errorf("open dist %s: %w", o.Dist, err)
	}
	defer dist.Close()
	if err := checkFlavoursPresent(dist, flavours); err != nil {
		return Result{}, err
	}
	if fi, err := dist.Lstat(checksumsName(o.Version)); err != nil || !fi.Mode().IsRegular() {
		return Result{}, fmt.Errorf("%w: %s is missing from dist", ErrChecksums, checksumsName(o.Version))
	}

	b, err := BuildBuiltins(o.Modules)
	if err != nil {
		return Result{}, err
	}
	for _, d := range []string{PayloadsDir, ModuleBytesDir, InstalledDir} {
		if err := out.Mkdir(d, 0o755); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", d, err)
		}
	}
	var res Result
	for _, m := range b.Modules {
		dir := filepath.Join(ModuleBytesDir, m.Name)
		if err := out.Mkdir(dir, 0o755); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", dir, err)
		}
		if err := writeNew(out, filepath.Join(dir, m.Version+".tar"), m.Tar); err != nil {
			return Result{}, err
		}
		a := artifactOf(m.Name, m.Tar)
		res.Modules = append(res.Modules, release.Module{Name: m.Name, Version: m.Version, Size: a.Size, SHA256: a.SHA256})
	}
	if err := writeNew(out, filepath.Join(PayloadsDir, release.BundleArtifact), b.Tar); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	installed, err := out.OpenRoot(InstalledDir)
	if err != nil {
		return Result{}, fmt.Errorf("open %s: %w", InstalledDir, err)
	}
	err = stageFlavours(dist, installed, flavours)
	installed.Close()
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	list, err := installedFiles(o.Version, filepath.Join(o.Out, InstalledDir), flavours)
	if err != nil {
		return Result{}, err
	}
	if err := writeNew(out, filepath.Join(PayloadsDir, release.InstalledFilesArtifact), list); err != nil {
		return Result{}, err
	}

	if err := copyPublished(ctx, dist, out, o.Version, flavours); err != nil {
		return Result{}, err
	}
	if res.Payloads, err = payloadList(out); err != nil {
		return Result{}, err
	}
	var sums bytes.Buffer
	for _, a := range res.Payloads {
		fmt.Fprintf(&sums, "%s  %s/%s\n", a.SHA256, PayloadsDir, a.Name)
	}
	if err := writeNew(out, SumsFile, sums.Bytes()); err != nil {
		return Result{}, err
	}
	return res, nil
}

// checkVersion accepts a release version that is valid SemVer and keeps
// every payload name within the manifest's artifact name grammar.
func checkVersion(v string) error {
	if !release.ValidReleaseVersion(v) {
		return fmt.Errorf("%w: %q is not SemVer 2.0.0 without a leading v", ErrVersion, v)
	}
	names := []string{checksumsName(v)}
	for _, f := range expectedFlavours(v) {
		names = append(names, f.file)
	}
	for _, n := range names {
		if !artifactNameRe.MatchString(n) {
			return fmt.Errorf("%w: %q makes the artifact name %q invalid", ErrVersion, v, n)
		}
	}
	return nil
}

// prepareOut creates out, or accepts an existing empty real directory,
// and opens it.
func prepareOut(p string) (*os.Root, error) {
	if p == "" {
		return nil, fmt.Errorf("%w: no output path given", ErrOut)
	}
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(p, 0o755); err != nil {
			return nil, fmt.Errorf("%w: create %s: %v", ErrOut, p, err)
		}
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrOut, err)
	case !fi.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrOut, p)
	}
	r, err := os.OpenRoot(p)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrOut, p, err)
	}
	d, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("%w: list %s: %v", ErrOut, p, err)
	}
	names, err := d.Readdirnames(1)
	d.Close()
	if len(names) > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		r.Close()
		return nil, fmt.Errorf("%w: %s is not empty", ErrOut, p)
	}
	return r, nil
}

// emptyDir removes everything Run created in out.
func emptyDir(out *os.Root) error {
	var errs []error
	for _, n := range []string{PayloadsDir, ModuleBytesDir, InstalledDir, SumsFile} {
		if err := out.RemoveAll(n); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// installedFiles generates installed-files.json from the staged trees
// with release.GenerateInstalledFiles and checks it with
// release.ParseInstalledFiles: exactly the expected flavours, the version.
func installedFiles(version, dir string, flavours []flavourSource) ([]byte, error) {
	raw, err := release.GenerateInstalledFiles(version, dir)
	if err != nil {
		return nil, fmt.Errorf("generate %s: %w", release.InstalledFilesArtifact, err)
	}
	l, err := release.ParseInstalledFiles(raw)
	if err != nil {
		return nil, fmt.Errorf("generated %s does not parse: %w", release.InstalledFilesArtifact, err)
	}
	var got, want []string
	for _, f := range l.Flavours {
		got = append(got, f.Name)
	}
	for _, f := range flavours {
		want = append(want, f.name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if l.ReleaseVersion != version || !slices.Equal(got, want) {
		return nil, fmt.Errorf("%w: generated %s covers %s %v, want %s %v", release.ErrFormat, release.InstalledFilesArtifact, l.ReleaseVersion, got, version, want)
	}
	return raw, nil
}

// copyPublished copies the published flavour files and the checksum file
// into payloads/ and checks that the checksum file lists exactly those
// files with the hashes of the copied bytes.
func copyPublished(ctx context.Context, dist, out *os.Root, version string, flavours []flavourSource) error {
	listed, err := readChecksums(dist, checksumsName(version))
	if err != nil {
		return err
	}
	copied := map[string]string{}
	for _, f := range flavours {
		if !f.publish {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := copyPayload(dist, out, f.file)
		if err != nil {
			return err
		}
		copied[a.Name] = a.SHA256
	}
	for name, sum := range listed {
		if copied[name] == "" {
			return fmt.Errorf("%w: it lists %s, which is not a published payload", ErrChecksums, name)
		}
		if copied[name] != sum {
			return fmt.Errorf("%w: %s has sha256 %s, the checksum file says %s", ErrChecksums, name, copied[name], sum)
		}
	}
	for name := range copied {
		if listed[name] == "" {
			return fmt.Errorf("%w: it does not list %s", ErrChecksums, name)
		}
	}
	_, err = copyPayload(dist, out, checksumsName(version))
	return err
}

// readChecksums parses a goreleaser checksum file: "<sha256>  <name>"
// lines, no duplicates.
func readChecksums(dist *os.Root, name string) (map[string]string, error) {
	f, fi, err := openDist(dist, name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChecksums, err)
	}
	defer f.Close()
	if fi.Size() > maxChecksums {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrChecksums, name, maxChecksums)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(f, maxChecksums))
	for sc.Scan() {
		m := checksumLineRe.FindStringSubmatch(sc.Text())
		if m == nil {
			return nil, fmt.Errorf("%w: %s has a malformed line", ErrChecksums, name)
		}
		if out[m[2]] != "" {
			return nil, fmt.Errorf("%w: %s lists %s twice", ErrChecksums, name, m[2])
		}
		out[m[2]] = m[1]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrChecksums, name, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrChecksums, name)
	}
	return out, nil
}

// copyPayload copies one regular dist file into payloads/, hashing the
// bytes it writes.
func copyPayload(dist, out *os.Root, name string) (release.Artifact, error) {
	src, fi, err := openDist(dist, name)
	if err != nil {
		return release.Artifact{}, err
	}
	defer src.Close()
	dst, err := out.OpenFile(filepath.Join(PayloadsDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return release.Artifact{}, fmt.Errorf("create payload %s: %w", name, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, release.MaxArtifactSize+1))
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return release.Artifact{}, fmt.Errorf("copy payload %s: %w", name, err)
	}
	if n != fi.Size() || n == 0 {
		return release.Artifact{}, fmt.Errorf("%w: %s changed while it was copied or is empty", ErrPackage, name)
	}
	return release.Artifact{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// payloadList hashes payloads/ and checks the manifest's artifact limits.
func payloadList(out *os.Root) ([]release.Artifact, error) {
	d, err := out.Open(PayloadsDir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", PayloadsDir, err)
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", PayloadsDir, err)
	}
	sort.Strings(names)
	if len(names) > release.MaxArtifacts {
		return nil, fmt.Errorf("%w: %d payloads, at most %d", ErrPackage, len(names), release.MaxArtifacts)
	}
	var total int64
	arts := make([]release.Artifact, 0, len(names))
	for _, n := range names {
		if !artifactNameRe.MatchString(n) {
			return nil, fmt.Errorf("%w: payload name %q is not a valid artifact name", ErrPackage, n)
		}
		f, err := out.OpenFile(filepath.Join(PayloadsDir, n), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("open payload %s: %w", n, err)
		}
		h := sha256.New()
		size, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("hash payload %s: %w", n, err)
		}
		if size == 0 || size > release.MaxArtifactSize {
			return nil, fmt.Errorf("%w: payload %s has %d bytes, want 1 to %d", ErrPackage, n, size, int64(release.MaxArtifactSize))
		}
		if total += size; total > release.MaxArtifactsTotal {
			return nil, fmt.Errorf("%w: payloads exceed %d bytes in total", ErrPackage, int64(release.MaxArtifactsTotal))
		}
		arts = append(arts, release.Artifact{Name: n, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	return arts, nil
}

// writeNew writes a new file inside out.
func writeNew(out *os.Root, name string, data []byte) error {
	f, err := out.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}
