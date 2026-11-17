// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no version":   {"--out", "x"},
		"no out":       {"--version", "0.1.0"},
		"extra arg":    {"--version", "0.1.0", "--out", "x", "extra"},
		"unknown flag": {"--sign"},
	} {
		var out, errb bytes.Buffer
		if code := run(t.Context(), args, &out, &errb); code != 2 || out.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %q", name, code, out.String())
		}
	}
}

func TestInvalidVersionFailsWithoutCreatingOut(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"--version", "v0.1.0", "--dist", t.TempDir(), "--out", out}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "invalid release version") || stdout.Len() != 0 {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr.String(), stdout.String())
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("out was created: %v", err)
	}
}

func TestMissingDistFailsAndLeavesOutEmpty(t *testing.T) {
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"--version", "0.1.0", "--dist", t.TempDir(), "--out", out, "--modules", "../../modules"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "install flavour missing") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Fatalf("out holds %v", ents)
	}
}
