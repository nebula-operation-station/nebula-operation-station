// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-release-stage prepares the unsigned staging directory for
// offline release signing (docs/admin/release-signing.md) from goreleaser
// output: payloads/, module-bytes/, installed/ and SHA256SUMS. It signs
// nothing and writes no manifest.
//
//	nebula-release-stage --version 0.1.0 --dist dist --out stage
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release/stage"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nebula-release-stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o stage.Options
	fs.StringVar(&o.Version, "version", "", "release version (SemVer without a leading v), as built by goreleaser")
	fs.StringVar(&o.Dist, "dist", "dist", "goreleaser output directory")
	fs.StringVar(&o.Out, "out", "", "staging directory to create (must not exist or be empty)")
	fs.StringVar(&o.Modules, "modules", "modules", "module source tree")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || o.Version == "" || o.Out == "" {
		fmt.Fprintln(stderr, "usage: nebula-release-stage --version X.Y.Z --dist DIR --out DIR [--modules DIR]")
		return 2
	}
	res, err := stage.Run(ctx, o)
	if err != nil {
		fmt.Fprintf(stderr, "nebula-release-stage: %v\n", err)
		return 1
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
