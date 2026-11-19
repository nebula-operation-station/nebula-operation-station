// SPDX-License-Identifier: AGPL-3.0-or-later

// Command packlock regenerates a bootstrap module's module.lock.json
// from its module.yaml and scripts (ADR 0008, PV-07). Usage:
//
//	go run ./internal/modules/bootstrap/cmd/packlock <module-dir>
//
// It writes <module-dir>/module.lock.json and prints the lock's
// SHA-256. The generated lock is validated before it is written.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modules/bootstrap"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run packs the module in args[0] and writes its lock file. It returns
// the process exit code: 2 for a wrong argument count (usage on stderr),
// 1 for a pack or write error (message on stderr, no lock written on
// pack errors), and 0 on success with the lock's SHA-256 on stdout.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: packlock <module-dir>")
		return 2
	}
	lock, err := bootstrap.Pack(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "packlock:", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(args[0], bootstrap.LockFile), lock, 0o644); err != nil {
		fmt.Fprintln(stderr, "packlock:", err)
		return 1
	}
	sum := sha256.Sum256(lock)
	fmt.Fprintln(stdout, hex.EncodeToString(sum[:]))
	return 0
}
