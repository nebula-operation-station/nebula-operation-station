// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"strings"
	"testing"
)

const pveSpoolConfig = `{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","pve_spool_dir":%%}`

func TestPVESpoolDirDefaultsWhenAbsent(t *testing.T) {
	cfg, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PVESpoolDir != DefaultPVESpoolDir {
		t.Errorf("PVESpoolDir = %q, want default %q", cfg.PVESpoolDir, DefaultPVESpoolDir)
	}
	if DefaultPVESpoolDir != "/var/lib/nebula/pve" {
		t.Errorf("DefaultPVESpoolDir = %q, want the collector's default -spool", DefaultPVESpoolDir)
	}
}

func TestPVESpoolDirFromFile(t *testing.T) {
	cfg, err := Parse([]byte(strings.ReplaceAll(pveSpoolConfig, "%%", `"/srv/pve"`)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PVESpoolDir != "/srv/pve" {
		t.Errorf("PVESpoolDir = %q, want /srv/pve", cfg.PVESpoolDir)
	}
}

func TestPVESpoolDirMustBeAbsolute(t *testing.T) {
	_, err := Parse([]byte(strings.ReplaceAll(pveSpoolConfig, "%%", `"var/lib/pve"`)))
	if err == nil || !strings.Contains(err.Error(), "pve_spool_dir") {
		t.Fatalf("err = %v, want a pve_spool_dir problem", err)
	}
}
