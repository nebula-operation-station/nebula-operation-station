// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-release-check is the maintainer's offline check of a
// staged, signed release (docs/admin/release-signing.md). It is a
// maintainer tool and not part of the release packages.
//
//	nebula-release-check STAGING_DIR
//
// STAGING_DIR holds release-manifest.json, release-manifest.json.sig and
// payloads/ with exactly the payloads the manifest lists. The check uses
// internal/release with the root anchors compiled into this binary
// (internal/release/rootkeys.txt) as the only trust: no key is read from
// the directory or the command line, and no rotation is applied. It
// verifies the manifest signature (namespace nebula-release, security
// key bound to "ssh:", user presence required), then the size and
// SHA-256 of every listed payload, builtins.tar with VerifyBundle and
// installed-files.json with VerifyInstalledFiles. Missing, extra and
// differing payloads are reported one by one. Other entries of the
// staging directory (module-bytes/, installed/, SHA256SUMS, helper
// scripts) are not consulted.
//
// The command opens files read-only without following symlinks, writes
// nothing and uses no network. Exit status: 0 when everything matches,
// 1 on any problem, 2 on a usage error.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// payloadsDir is the staging subdirectory holding the payloads.
const payloadsDir = "payloads"

// maxPayloadEntries bounds the entries read from payloads/: every
// manifest artifact plus a margin, so extra files are still reported.
const maxPayloadEntries = release.MaxArtifacts + 64

// hashBuffer is the read buffer for streaming payload hashes.
const hashBuffer = 1 << 20

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nebula-release-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: nebula-release-check STAGING_DIR")
		return 2
	}
	anchors, err := release.Anchors()
	if err != nil {
		fmt.Fprintf(stderr, "nebula-release-check: compiled release anchors: %s\n", escape(err.Error()))
		return 1
	}
	return check(ctx, fs.Arg(0), anchors, stdout)
}

// checker collects the report.
type checker struct {
	out      io.Writer
	problems int
}

func (c *checker) problem(format string, a ...any) {
	c.problems++
	fmt.Fprintf(c.out, format+"\n", a...)
}

// check verifies the staging directory dir against anchors and writes a
// text report to out. It returns the exit status.
func check(ctx context.Context, dir string, anchors []release.Anchor, out io.Writer) int {
	c := &checker{out: out}
	c.verify(ctx, dir, anchors)
	if c.problems == 0 {
		fmt.Fprintln(out, "RESULT: OK")
		return 0
	}
	fmt.Fprintf(out, "RESULT: FAILED (%d problems)\n", c.problems)
	return 1
}

func (c *checker) verify(ctx context.Context, dir string, anchors []release.Anchor) {
	state, err := release.Bootstrap(anchors)
	if err != nil {
		c.problem("ERROR root anchors: %s", escape(err.Error()))
		return
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		c.problem("ERROR staging directory %s is not a directory", strconv.Quote(dir))
		return
	}
	top, err := os.OpenRoot(dir)
	if err != nil {
		c.problem("ERROR open staging directory %s: %s", strconv.Quote(dir), escape(err.Error()))
		return
	}
	defer top.Close()

	man, err := readRegular(top, release.ManifestFile, release.MaxManifest)
	if err != nil {
		c.problem("ERROR %s: %s", release.ManifestFile, escape(err.Error()))
		return
	}
	sig, err := readRegular(top, release.SignatureFile, release.MaxSignature)
	if err != nil {
		c.problem("ERROR %s: %s", release.SignatureFile, escape(err.Error()))
		return
	}
	m, err := release.VerifyManifest(state.Active(), man, sig)
	if err != nil {
		c.problem("ERROR manifest: %s", escape(err.Error()))
		return
	}
	fmt.Fprintf(c.out, "manifest: release %s, sha256 %s\n", m.ReleaseVersion, m.Digest)
	fmt.Fprintf(c.out, "signature: signed by %s %s (security key, namespace %s, user presence verified)\n",
		m.SignedBy.ID, m.SignedBy.Fingerprint(), release.Namespace)

	if fi, err := top.Lstat(payloadsDir); err != nil || !fi.IsDir() {
		c.problem("ERROR %s/ is not a directory", payloadsDir)
		return
	}
	pr, err := top.OpenRoot(payloadsDir)
	if err != nil {
		c.problem("ERROR open %s/: %s", payloadsDir, escape(err.Error()))
		return
	}
	defer pr.Close()
	present, err := listDir(pr)
	if err != nil {
		c.problem("ERROR %s/: %s", payloadsDir, escape(err.Error()))
		return
	}
	listed := make(map[string]bool, len(m.Artifacts))
	for _, a := range m.Artifacts {
		listed[a.Name] = true
	}
	for _, n := range present {
		if !listed[n] {
			c.problem("EXTRA %s: not listed in the manifest", strconv.Quote(n))
		}
	}
	for _, a := range m.Artifacts {
		if err := ctx.Err(); err != nil {
			c.problem("ERROR %s", escape(err.Error()))
			return
		}
		if !slices.Contains(present, a.Name) {
			c.problem("MISSING %s: listed in the manifest", strconv.Quote(a.Name))
			continue
		}
		switch a.Name {
		case release.BundleArtifact:
			c.checkBundle(pr, m, a)
		case release.InstalledFilesArtifact:
			c.checkInstalledFiles(pr, state, man, sig, a)
		default:
			c.checkPayload(pr, a)
		}
	}
	if !listed[release.InstalledFilesArtifact] {
		c.problem("ERROR the manifest lists no %s (mandatory, spec 10)", release.InstalledFilesArtifact)
	}
}

// checkPayload streams one payload and compares size and SHA-256.
func (c *checker) checkPayload(r *os.Root, a release.Artifact) {
	f, size, err := openRegular(r, a.Name)
	if err != nil {
		c.problem("MISMATCH %s: %s", strconv.Quote(a.Name), escape(err.Error()))
		return
	}
	defer f.Close()
	if size != a.Size {
		c.problem("MISMATCH %s: size %d, the manifest says %d", strconv.Quote(a.Name), size, a.Size)
		return
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(f, a.Size+1), make([]byte, hashBuffer))
	if err != nil {
		c.problem("MISMATCH %s: read: %s", strconv.Quote(a.Name), escape(err.Error()))
		return
	}
	if n != a.Size {
		c.problem("MISMATCH %s: size %d, the manifest says %d", strconv.Quote(a.Name), n, a.Size)
		return
	}
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		c.problem("MISMATCH %s: sha256 differs from the manifest", strconv.Quote(a.Name))
		return
	}
	fmt.Fprintf(c.out, "ok %s %d bytes sha256 %s\n", strconv.Quote(a.Name), a.Size, a.SHA256)
}

// readArtifact reads a payload of at most max bytes and checks its size
// and SHA-256 against the manifest; the returned bytes are the checked
// ones.
func (c *checker) readArtifact(r *os.Root, a release.Artifact, max int64) ([]byte, bool) {
	b, err := readRegular(r, a.Name, max)
	if err != nil {
		c.problem("MISMATCH %s: %s", strconv.Quote(a.Name), escape(err.Error()))
		return nil, false
	}
	if int64(len(b)) != a.Size {
		c.problem("MISMATCH %s: size %d, the manifest says %d", strconv.Quote(a.Name), len(b), a.Size)
		return nil, false
	}
	if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != a.SHA256 {
		c.problem("MISMATCH %s: sha256 differs from the manifest", strconv.Quote(a.Name))
		return nil, false
	}
	return b, true
}

func (c *checker) checkBundle(r *os.Root, m release.Manifest, a release.Artifact) {
	b, ok := c.readArtifact(r, a, release.MaxBundle)
	if !ok {
		return
	}
	mods, err := release.VerifyBundle(m, b)
	if err != nil {
		c.problem("MISMATCH %s: %s", strconv.Quote(a.Name), escape(err.Error()))
		return
	}
	fmt.Fprintf(c.out, "ok %s %d bytes sha256 %s\n", strconv.Quote(a.Name), a.Size, a.SHA256)
	for _, mb := range mods {
		fmt.Fprintf(c.out, "  module %s %s: %d actions verified\n", mb.Module.Name, mb.Module.Version, len(mb.Actions))
	}
}

func (c *checker) checkInstalledFiles(r *os.Root, state release.RootState, man, sig []byte, a release.Artifact) {
	b, ok := c.readArtifact(r, a, release.MaxInstalledFilesDocument)
	if !ok {
		return
	}
	_, l, err := release.VerifyInstalledFiles(state, man, sig, b)
	if err != nil {
		c.problem("MISMATCH %s: %s", strconv.Quote(a.Name), escape(err.Error()))
		return
	}
	fmt.Fprintf(c.out, "ok %s %d bytes sha256 %s\n", strconv.Quote(a.Name), a.Size, a.SHA256)
	for _, f := range l.Flavours {
		fmt.Fprintf(c.out, "  flavour %s: %d files\n", f.Name, len(f.Files))
	}
}

// listDir returns the sorted entry names of r, at most maxPayloadEntries.
func listDir(r *os.Root) ([]string, error) {
	d, err := r.Open(".")
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer d.Close()
	names, err := d.Readdirnames(maxPayloadEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list: %w", err)
	}
	if len(names) > maxPayloadEntries {
		return nil, fmt.Errorf("more than %d entries", maxPayloadEntries)
	}
	slices.Sort(names)
	return names, nil
}

// openRegular opens a regular file read-only without following symlinks
// and returns it with its size.
func openRegular(r *os.Root, name string) (*os.File, int64, error) {
	if fi, err := r.Lstat(name); err != nil || !fi.Mode().IsRegular() {
		return nil, 0, errors.New("not a regular file")
	}
	// O_NONBLOCK: a FIFO swapped in after Lstat must not hang the open.
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, errors.New("not a regular file")
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, errors.New("not a regular file")
	}
	return f, fi.Size(), nil
}

// readRegular reads a regular file of at most max bytes without
// following symlinks.
func readRegular(r *os.Root, name string, max int64) ([]byte, error) {
	f, size, err := openRegular(r, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size > max {
		return nil, fmt.Errorf("must be a regular file of at most %d bytes", max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("must be a regular file of at most %d bytes", max)
	}
	return b, nil
}

// escape renders s as one line of printable text: control bytes,
// invalid UTF-8 and non-graphic runes are escaped.
func escape(s string) string {
	q := strconv.QuoteToGraphic(s)
	return q[1 : len(q)-1]
}
