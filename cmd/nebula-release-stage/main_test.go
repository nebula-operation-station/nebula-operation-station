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

// catalogInput is a small valid catalog, not in canonical form.
const catalogInput = `{"format":"nebula-image-catalog-v1","sequence":1,"images":[` +
	`{"id":"debian-12-amd64","os":"debian","release":"12","arch":"amd64",` +
	`"url":"https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",` +
	`"sha256":"abababababababababababababababababababababababababababababababab","disk_format":"qcow2"}]}`

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCatalogFlagsGoTogether: the catalog and its signature are given
// together or not at all; a usage error creates no output directory.
func TestCatalogFlagsGoTogether(t *testing.T) {
	cat := writeFile(t, "catalog.json", []byte(catalogInput))
	sig := writeFile(t, "catalog.sig", []byte("sig"))
	for name, extra := range map[string][]string{
		"catalog without signature": {"--catalog", cat},
		"signature without catalog": {"--catalog-sig", sig},
	} {
		out := filepath.Join(t.TempDir(), "out")
		var stdout, stderr bytes.Buffer
		args := append([]string{"--version", "0.1.0", "--dist", t.TempDir(), "--out", out}, extra...)
		if code := run(t.Context(), args, &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Errorf("%s: out was created", name)
		}
	}
}

// TestCatalogInputRefusesBeforeStaging covers the catalog error paths
// that stop staging before stage.Run creates the output directory.
func TestCatalogInputRefusesBeforeStaging(t *testing.T) {
	sig := writeFile(t, "catalog.sig", []byte("not a signature"))
	local := writeFile(t, "local.json", []byte(strings.Replace(catalogInput, `"id":"debian-12-amd64"`, `"id":"local-debian"`, 1)))
	huge := writeFile(t, "huge.json", bytes.Repeat([]byte(" "), 256<<10+1))
	cases := map[string][]string{
		"missing catalog":    {"--catalog", filepath.Join(t.TempDir(), "absent.json"), "--catalog-sig", sig},
		"local id":           {"--catalog", local, "--catalog-sig", sig},
		"larger than 256KiB": {"--catalog", huge, "--catalog-sig", sig},
		"bad signature":      {"--catalog", writeFile(t, "c.json", []byte(catalogInput)), "--catalog-sig", sig},
	}
	for name, extra := range cases {
		out := filepath.Join(t.TempDir(), "out")
		var stdout, stderr bytes.Buffer
		args := append([]string{"--version", "0.1.0", "--dist", t.TempDir(), "--out", out}, extra...)
		if code := run(t.Context(), args, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout.String(), stderr.String())
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Errorf("%s: out was created", name)
		}
	}
}
