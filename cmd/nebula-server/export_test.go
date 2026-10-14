// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
)

func TestExportActions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "actions")
	var out strings.Builder
	if err := exportActions(dir, &out); err != nil {
		t.Fatal(err)
	}
	for _, a := range actions.Builtin {
		p := filepath.Join(dir, strings.ReplaceAll(a.ID, ".", "_")+"-"+a.Version+".sh")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != a.SHA256() {
			t.Fatalf("%s: exported bytes differ", a.ID)
		}
		if !strings.Contains(out.String(), "nebula artifact trust --action "+a.ID+" --version "+a.Version) {
			t.Fatalf("no trust command for %s:\n%s", a.ID, out.String())
		}
	}
	if err := exportActions(dir, &out); err == nil {
		t.Fatal("existing directory overwritten")
	}
}
