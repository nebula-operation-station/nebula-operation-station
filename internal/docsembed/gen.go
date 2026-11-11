// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build ignore

// gen copies the operator handbook (docs/handbook/*.md) into
// internal/docsembed/handbook so that //go:embed can reach it: embed
// patterns cannot name files outside the package directory. Run it with
// "go generate ./internal/docsembed" from the repository root after
// editing the handbook; TestEmbeddedHandbookMatchesDocs fails until the
// copy is current.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := run("../../docs/handbook", "handbook"); err != nil {
		fmt.Fprintln(os.Stderr, "docsembed gen:", err)
		os.Exit(1)
	}
}

func run(src, dst string) error {
	files, err := filepath.Glob(filepath.Join(src, "*.md"))
	if err != nil {
		return fmt.Errorf("list %s: %w", src, err)
	}
	old, err := filepath.Glob(filepath.Join(dst, "*.md"))
	if err != nil {
		return fmt.Errorf("list %s: %w", dst, err)
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("remove stale %s: %w", f, err)
		}
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		out := filepath.Join(dst, filepath.Base(f))
		if err := os.WriteFile(out, b, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
	}
	return nil
}
