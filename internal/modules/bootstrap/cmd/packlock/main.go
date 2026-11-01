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
	"os"
	"path/filepath"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modules/bootstrap"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: packlock <module-dir>")
		os.Exit(2)
	}
	lock, err := bootstrap.Pack(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "packlock:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(os.Args[1], bootstrap.LockFile), lock, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "packlock:", err)
		os.Exit(1)
	}
	sum := sha256.Sum256(lock)
	fmt.Println(hex.EncodeToString(sum[:]))
}
