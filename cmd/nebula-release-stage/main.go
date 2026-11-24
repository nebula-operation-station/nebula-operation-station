// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-release-stage prepares the unsigned staging directory for
// offline release signing (docs/admin/release-signing.md) from goreleaser
// output: payloads/, module-bytes/, installed/ and SHA256SUMS. It signs
// nothing and writes no manifest.
//
// With --catalog and --catalog-sig it also stages the image catalog
// (image-catalog.json and image-catalog.json.sig, see internal/release
// catalog_stage.go). The signature is made offline beforehand with the
// release-signing procedure; staging checks it against the compiled root
// anchors and writes nothing that does not verify.
//
//	nebula-release-stage --version 0.1.0 --dist dist --out stage
//	nebula-release-stage --version 0.1.0 --dist dist --out stage \
//	    --catalog catalog.json --catalog-sig catalog.json.sig
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release/stage"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// readLimited reads the regular file name of at most max bytes.
func readLimited(name string, max int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nebula-release-stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o stage.Options
	fs.StringVar(&o.Version, "version", "", "release version (SemVer without a leading v), as built by goreleaser")
	fs.StringVar(&o.Dist, "dist", "dist", "goreleaser output directory")
	fs.StringVar(&o.Out, "out", "", "staging directory to create (must not exist or be empty)")
	fs.StringVar(&o.Modules, "modules", "modules", "module source tree")
	catalogPath := fs.String("catalog", "", "image catalog input (JSON in the catalog grammar); optional")
	catalogSigPath := fs.String("catalog-sig", "", "detached signature of the catalog; required with --catalog")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || o.Version == "" || o.Out == "" || (*catalogPath == "") != (*catalogSigPath == "") {
		fmt.Fprintln(stderr, "usage: nebula-release-stage --version X.Y.Z --dist DIR --out DIR [--modules DIR] [--catalog FILE --catalog-sig FILE]")
		return 2
	}
	// The catalog is checked before any output is created.
	var catalog, catalogSig []byte
	var roots []release.Root
	if *catalogPath != "" {
		var err error
		if catalog, err = readLimited(*catalogPath, release.MaxCatalog+1); err != nil {
			fmt.Fprintf(stderr, "nebula-release-stage: catalog input: %v\n", err)
			return 1
		}
		if catalogSig, err = readLimited(*catalogSigPath, release.MaxSignature); err != nil {
			fmt.Fprintf(stderr, "nebula-release-stage: catalog signature: %v\n", err)
			return 1
		}
		if roots, err = release.AnchorRoots(); err != nil {
			fmt.Fprintf(stderr, "nebula-release-stage: compiled anchors: %v\n", err)
			return 1
		}
		canonical, _, err := release.CheckCatalog(catalog, catalogSig, roots)
		if err != nil {
			fmt.Fprintf(stderr, "nebula-release-stage: catalog: %v\n", err)
			return 1
		}
		catalog = canonical
	}
	res, err := stage.Run(ctx, o)
	if err != nil {
		fmt.Fprintf(stderr, "nebula-release-stage: %v\n", err)
		return 1
	}
	if catalog != nil {
		if err := release.WriteStagedCatalog(o.Out, roots, catalog, catalogSig); err != nil {
			fmt.Fprintf(stderr, "nebula-release-stage: catalog: %v (the staging in %s is incomplete)\n", err, o.Out)
			return 1
		}
		fmt.Fprintf(stdout, "staged %s and %s\n", release.CatalogFile, release.CatalogSignatureFile)
	}
	fmt.Fprintf(stdout, "staged release %s in %s (unsigned)\n", o.Version, o.Out)
	for _, a := range res.Payloads {
		fmt.Fprintf(stdout, "payload %s %d %s\n", a.Name, a.Size, a.SHA256)
	}
	for _, m := range res.Modules {
		fmt.Fprintf(stdout, "module %s %s %d %s\n", m.Name, m.Version, m.Size, m.SHA256)
	}
	return 0
}
