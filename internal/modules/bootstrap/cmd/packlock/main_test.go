// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modules/bootstrap"
)

// testScript is a minimal valid module script.
const testScript = "#!/bin/sh\nprintf '{\"ok\":true}\\n' > \"$NEBULA_RESULT\"\n"

// testModuleYAML declares the four required actions of a bootstrap module.
const testModuleYAML = `name: alpha
version: 1.2.3
title: Alpha
description: A synthetic bootstrap module for tests.
actions:
  install:
    title: Install alpha
    description: Installs the component.
    script: actions/install.sh
    risk: medium
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [writes_config]
  verify:
    title: Verify alpha
    description: Checks the component.
    script: actions/verify.sh
    risk: low
    durable: false
    timeout: 120s
    params: []
    secrets: []
    declares: []
  update:
    title: Update alpha
    description: Updates the component.
    script: actions/update.sh
    risk: medium
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [writes_config]
  uninstall:
    title: Uninstall alpha
    description: Removes the component.
    script: actions/uninstall.sh
    risk: high
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [requires_root]
`

// writeModule writes a valid synthetic module into a fresh directory
// under t.TempDir and returns its path. No lock is written.
func writeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bootstrap.AuthorFile), []byte(testModuleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"install", "verify", "update", "uninstall"} {
		if err := os.WriteFile(filepath.Join(dir, "actions", a+".sh"), []byte(testScript), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// dirEntries lists the names in dir, failing the test on error.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestRunUsageWithoutArgumentsExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if got, want := stderr.String(), "usage: packlock <module-dir>\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunUsageWithTwoArgumentsWritesNothing(t *testing.T) {
	dir := writeModule(t)
	before := dirEntries(t, dir)

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir, "extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if got, want := stderr.String(), "usage: packlock <module-dir>\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if after := dirEntries(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("directory changed: before %v, after %v", before, after)
	}
}

func TestRunMissingModuleDirExitsOneWithoutWriting(t *testing.T) {
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.HasPrefix(stderr.String(), "packlock: ") {
		t.Fatalf("stderr = %q, want prefix %q", stderr.String(), "packlock: ")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dir, bootstrap.LockFile)); !os.IsNotExist(err) {
		t.Fatalf("lock file exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunInvalidModuleKeepsExistingLockByteIdentical(t *testing.T) {
	dir := t.TempDir()
	// module.yaml is malformed (unknown field), so Pack fails.
	if err := os.WriteFile(filepath.Join(dir, bootstrap.AuthorFile), []byte("name: x\nbogus: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := []byte("{\"keep\":\"me\"}\n")
	if err := os.WriteFile(filepath.Join(dir, bootstrap.LockFile), old, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.HasPrefix(stderr.String(), "packlock: ") {
		t.Fatalf("stderr = %q, want prefix %q", stderr.String(), "packlock: ")
	}
	got, err := os.ReadFile(filepath.Join(dir, bootstrap.LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("existing lock changed: %q", got)
	}
}

func TestRunValidModuleWritesLockAndPrintsDigest(t *testing.T) {
	dir := writeModule(t)
	want, err := bootstrap.Pack(dir)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	got, err := os.ReadFile(filepath.Join(dir, bootstrap.LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("lock file differs from bootstrap.Pack output")
	}
	sum := sha256.Sum256(got)
	wantOut := hex.EncodeToString(sum[:]) + "\n"
	if stdout.String() != wantOut {
		t.Fatalf("stdout = %q, want %q", stdout.String(), wantOut)
	}
}

func TestRunIsIdempotent(t *testing.T) {
	dir := writeModule(t)

	var out1, err1 bytes.Buffer
	if code := run([]string{dir}, &out1, &err1); code != 0 {
		t.Fatalf("first run exit code = %d; stderr = %q", code, err1.String())
	}
	first, err := os.ReadFile(filepath.Join(dir, bootstrap.LockFile))
	if err != nil {
		t.Fatal(err)
	}

	var out2, err2 bytes.Buffer
	if code := run([]string{dir}, &out2, &err2); code != 0 {
		t.Fatalf("second run exit code = %d; stderr = %q", code, err2.String())
	}
	second, err := os.ReadFile(filepath.Join(dir, bootstrap.LockFile))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("second run changed the lock file")
	}
	if out1.String() != out2.String() {
		t.Fatalf("digest changed between runs: %q vs %q", out1.String(), out2.String())
	}
}

func TestRunUnwritableLockPathExitsOne(t *testing.T) {
	// A directory at the lock path makes the write fail for every user,
	// including root, so the test does not depend on file permissions.
	dir := writeModule(t)
	if err := os.Mkdir(filepath.Join(dir, bootstrap.LockFile), 0o755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.HasPrefix(stderr.String(), "packlock: ") {
		t.Fatalf("stderr = %q, want prefix %q", stderr.String(), "packlock: ")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}
