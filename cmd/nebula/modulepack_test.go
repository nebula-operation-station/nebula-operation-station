// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
)

const moduleYAML = `name: telegraf
version: 1.2.0
title: Telegraf
description: Metrics agent.
actions:
  restart:
    title: Restart Telegraf
    script: actions/restart.sh
    risk: medium
    timeout: 60s
    params:
      unit: {type: name, label: Unit}
      mode: {type: choice, label: Mode, choices: [soft, hard]}
    secrets: [influx_token]
    declares: [requires_root]
ui:
  host_tab:
    title: Telegraf
    cards:
      - title: Status
        action: restart
        fields:
          - {label: Version, path: version}
          - {label: Active, path: service.active}
`

func TestModulePack(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "actions"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(moduleYAML), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "actions", "restart.sh"), []byte("systemctl restart telegraf\n"), 0o644)
	var out strings.Builder
	if err := modulePack([]string{dir}, &out); err != nil || !strings.Contains(out.String(), "-n nebula-module") {
		t.Fatalf("%v %s", err, out.String())
	}
	lock, _ := os.ReadFile(filepath.Join(dir, "module.lock.json"))
	l, _, err := modulelock.Parse(lock)
	a := l.Actions["restart"]
	if l.UI == nil || l.UI.HostTab == nil || l.UI.HostTab.Cards[0].Fields[1].Path != "service.active" {
		t.Fatalf("ui: %+v", l.UI)
	}
	if err != nil || a.Risk != "MEDIUM" || a.TimeoutS != 60 || len(a.Params) != 2 || a.Params[0].Name != "mode" || a.Secrets[0] != "influx_token" {
		t.Fatalf("%+v %v", l, err)
	}
	arch := filepath.Join(t.TempDir(), "m.tar.gz")
	if err := modulePack([]string{"--archive", arch, dir}, &out); err != nil || !strings.Contains(out.String(), "unverified") {
		t.Fatalf("%v %s", err, out.String())
	}
	f, _ := os.Open(arch)
	zr, _ := gzip.NewReader(f)
	tr := tar.NewReader(zr)
	var names []string
	for h, err := tr.Next(); err == nil; h, err = tr.Next() {
		names = append(names, h.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "actions/restart.sh,module.lock.json" {
		t.Fatal(names)
	}
	// A script changed after packing: the lock is stale.
	_ = os.WriteFile(filepath.Join(dir, "actions", "restart.sh"), []byte("rm -rf /\n"), 0o644)
	if err := modulePack([]string{"--archive", arch, dir}, &out); err == nil {
		t.Fatal("stale lock packed")
	}
	// Unknown keys in module.yaml are refused.
	_ = os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(moduleYAML+"sandbox: true\n"), 0o644)
	if err := modulePack([]string{dir}, &out); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// Packing follows no symbolic link and truncates nothing: a link could
// make the author sign and ship a file from outside the module.
func TestModulePackRefusesLinksAndLargeScripts(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "id_ed25519")
	_ = os.WriteFile(outside, []byte("PRIVATE KEY"), 0o600)
	for name, setup := range map[string]func(dir string){
		"script link": func(dir string) {
			_ = os.MkdirAll(filepath.Join(dir, "actions"), 0o755)
			_ = os.Symlink(outside, filepath.Join(dir, "actions", "restart.sh"))
		},
		"directory link": func(dir string) {
			other := t.TempDir()
			_ = os.WriteFile(filepath.Join(other, "restart.sh"), []byte("echo hi\n"), 0o644)
			_ = os.Symlink(other, filepath.Join(dir, "actions"))
		},
		"large": func(dir string) {
			_ = os.MkdirAll(filepath.Join(dir, "actions"), 0o755)
			_ = os.WriteFile(filepath.Join(dir, "actions", "restart.sh"), []byte(strings.Repeat("# x\n", 70000)), 0o644)
		},
	} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(moduleYAML), 0o644)
		setup(dir)
		var out strings.Builder
		if err := modulePack([]string{dir}, &out); err == nil {
			t.Errorf("%s: packed", name)
		}
	}
	dir := t.TempDir()
	_ = os.Symlink(outside, filepath.Join(dir, "module.yaml"))
	var out strings.Builder
	if err := modulePack([]string{dir}, &out); err == nil {
		t.Error("linked module.yaml read")
	}
}
