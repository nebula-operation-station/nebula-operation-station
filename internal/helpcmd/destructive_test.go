// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "testing"

// rowCases gives every row of destructivePatterns a positive case (must be
// destructive, naming the row) and a near miss (must not be destructive).
var rowCases = map[string]struct{ pos, neg []string }{
	"`rm` with `-r`/`-R`/`-f` (also inside a single-dash cluster such as `-rf`) or `--recursive`/`--force`": {
		pos: []string{"rm -rf /x", "rm -fr /x", "rm -R /x", "rm -r /x", "rm -f x",
			"rm -vrf /x", "rm --recursive /x", "rm --force /x", "/bin/rm -rf x"},
		neg: []string{"rm x", "rm -i x", "rm -v x", "rm --interactive=always x",
			"rm-rf x", "rmdir -p x"},
	},
	"`userdel`": {
		pos: []string{"userdel a", "sudo userdel nebula-server", "/usr/sbin/userdel b"},
		neg: []string{"usermod -L a", "userdel-helper a", "adduser a"},
	},
	"`groupdel`": {
		pos: []string{"groupdel nebula-rpc", "sudo groupdel g"},
		neg: []string{"groupmod g", "groupdelx g"},
	},
	"`shred`": {
		pos: []string{"shred -u ./nebula-default.key", "sudo -u root shred -u k"},
		neg: []string{"shredder k", "sha256sum k"},
	},
	"`dd`": {
		pos: []string{"dd if=/dev/zero of=x", "env A=1 nice -n 5 dd if=/dev/zero of=x"},
		neg: []string{"ddd x", "dda x"},
	},
	"`mkfs*`": {
		pos: []string{"mkfs.ext4 /dev/sdb1", "mkfs /dev/sdb1", "sudo mkfs.xfs /dev/x"},
		neg: []string{"mkfifo x", "mkf x"},
	},
	"`wipefs`": {
		pos: []string{"wipefs -a /dev/sdb", "sudo wipefs --all /dev/x"},
		neg: []string{"wipe x", "wipefsx -a /dev/x"},
	},
	"`truncate`": {
		pos: []string{"truncate -s 0 f", "sudo truncate f"},
		neg: []string{"truncat f", "stat f"},
	},
	"`tar` extracting (see units below)": {
		pos: []string{"tar xzf a.tar.gz", "tar --extract -f a.tar", "tar --get -f a.tar",
			"tar -C /v -xpz", "tar -xf a.tar", "tar xf a.tar", "docker run --rm -i -v v:/v debian:12-slim tar -C /v -xpz"},
		neg: []string{"tar -czf out.tgz dir", "tar -tf a.tar", "tar cf x.tar d", "tar -cf a.tar -C /v ."},
	},
	"`docker compose down -v`": {
		pos: []string{"docker compose down -v", "docker compose -f a.yml down --remove-orphans -v"},
		neg: []string{"docker compose down", "docker compose up -v", "docker compose -f a.yml down"},
	},
	"`docker volume rm`": {
		pos: []string{"docker volume rm nebula_executor-data", "docker -H x volume rm v"},
		neg: []string{"docker volume ls", "docker volume create v", "docker volume inspect v"},
	},
	"`docker system prune`": {
		pos: []string{"docker system prune -af", "docker system prune"},
		neg: []string{"docker system df", "docker image prune"},
	},
	"`apt remove`/`purge`": {
		pos: []string{"apt remove nebula", "apt purge x", "sudo apt -y remove x"},
		neg: []string{"apt install x", "apt list --upgradable", "apt update"},
	},
	"`nebula restore`": {
		pos: []string{"nebula restore ARCHIVE", "sudo nebula restore --identity k ARCHIVE"},
		neg: []string{"nebula restored ARCHIVE", "nebula backup --out x"},
	},
	"`nebula netdev remove`": {
		pos: []string{"nebula netdev remove fw-01", "sudo nebula netdev remove fw-01"},
		neg: []string{"nebula netdev removed fw-01", "nebula netdev list"},
	},
	"`nebula pve remote remove`": {
		pos: []string{"nebula pve remote remove r", "sudo nebula pve remote remove r"},
		neg: []string{"nebula pve remote add r", "nebula pve remote remove-all r"},
	},
	"`nebula container definition remove`": {
		pos: []string{"nebula container definition remove d"},
		neg: []string{"nebula container definition list", "nebula container remove d"},
	},
	"`nebula webauthn remove`": {
		pos: []string{"nebula webauthn remove k"},
		neg: []string{"nebula webauthn register", "nebula webauthn remove-all k"},
	},
	"`nebula totp remove`": {
		pos: []string{"nebula totp remove"},
		neg: []string{"nebula totp setup", "nebula totp removed"},
	},
	"`nebula signer remove`": {
		pos: []string{"nebula signer remove s"},
		neg: []string{"nebula signer add s", "nebula signers remove s"},
	},
	"`nebula secret rm`": {
		pos: []string{"nebula secret rm name"},
		neg: []string{"nebula secret set name", "nebula secret rmx name"},
	},
	"`nebula host unpin`": {
		pos: []string{"nebula host unpin web-01"},
		neg: []string{"nebula host pin web-01", "nebula host unpinned web-01"},
	},
	"`nebula host clear`": {
		pos: []string{"nebula host clear web-01"},
		neg: []string{"nebula host list", "nebula host cleared web-01"},
	},
	"`nebula artifact unpin`": {
		pos: []string{"nebula artifact unpin a"},
		neg: []string{"nebula artifact pin a", "nebula artifact unpinned a"},
	},
	"`nebula read-grant revoke`": {
		pos: []string{"nebula read-grant revoke g"},
		neg: []string{"nebula read-grant create g", "nebula read-grant revoked g"},
	},
	"`nebula schedule revoke`": {
		pos: []string{"nebula schedule revoke s"},
		neg: []string{"nebula schedule list", "nebula schedule revokes s"},
	},
	"`nebula netdev repin`": {
		pos: []string{"nebula netdev repin fw-01"},
		neg: []string{"nebula netdev pin fw-01", "nebula netdev repinned fw-01"},
	},
	"`nebula pve remote repin`": {
		pos: []string{"nebula pve remote repin r"},
		neg: []string{"nebula pve remote pin r", "nebula pve remote repinx r"},
	},
	"`nebula pve remote rotate-token`": {
		pos: []string{"nebula pve remote rotate-token r"},
		neg: []string{"nebula pve remote add r", "nebula pve remote rotate r"},
	},
}

func TestEveryDestructivePatternRowHasCases(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, p := range destructivePatterns {
		c, ok := rowCases[p.adr]
		if !ok {
			t.Errorf("row %q has no test cases", p.adr)
			continue
		}
		if len(c.pos) == 0 || len(c.neg) == 0 {
			t.Errorf("row %q needs a positive and a near-miss case", p.adr)
		}
		seen[p.adr] = true
	}
	for adr := range rowCases {
		if !seen[adr] {
			t.Errorf("test cases for %q do not match any row", adr)
		}
	}
}

func TestEachDestructivePatternRowMatchesItsPositivesOnly(t *testing.T) {
	t.Parallel()
	for _, p := range destructivePatterns {
		c, ok := rowCases[p.adr]
		if !ok {
			continue
		}
		for _, cmd := range c.pos {
			v := Assess(cmd)
			if !v.Destructive || v.Pattern != p.adr {
				t.Errorf("%q: got %+v, want destructive by row %q", cmd, v, p.adr)
			}
		}
		for _, cmd := range c.neg {
			if v := Assess(cmd); v.Destructive {
				t.Errorf("near miss %q: got %+v, want not destructive", cmd, v)
			}
		}
	}
}

func TestDestructiveADRUnitExamples(t *testing.T) {
	t.Parallel()
	destructive := []string{
		"sudo userdel a; sudo userdel b",
		"docker run --rm -v nebula_executor-data:/v debian:12-slim rm -rf /v/x",
		"docker compose exec executor rm -f /x",
		"sudo -u root shred -u k",
		"env A=1 nice -n 5 dd if=/dev/zero of=x",
		"bash -c 'rm -rf /x'",
		"nebula status && sudo nebula netdev remove fw-01",
		"nebula netdev remove fw-01",
		"cat b.tgz | docker run --rm -i -v nebula_executor-data:/v debian:12-slim tar -C /v -xpz",
		"tar xzf a.tar.gz",
		"tar --extract -f a.tar",
		"rm --recursive /x",
		"rm --force /x",
		"sudo rm -rf /var/lib/nebula /etc/nebula",
		"sudo userdel nebula-server; sudo groupdel nebula-rpc",
		"sudo groupdel nebula-rpc",
	}
	for _, cmd := range destructive {
		if v := Assess(cmd); !v.Destructive || v.Pattern == "" {
			t.Errorf("Assess(%q) = %+v, want destructive with a named row", cmd, v)
		}
	}
}

func TestDestructiveChecksEveryUnitNotOnlyTheFirstWord(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"echo ok; rm -rf /x",
		"true && dd of=x",
		"echo a | shred -u k",
		"if rm -rf /x; then :; fi",
		"! userdel a",
		"echo a > out 2>&1 && groupdel g",
		"sh -c 'echo a; sudo userdel b'",
		"echo \"$(rm -rf /x)\"",
		"echo `rm -rf /x`",
		"exec nohup nice -n 1 timeout 5s rm -rf /x",
		"/usr/bin/env -i PATH=/bin sudo -u root rm -rf /x",
	} {
		if v := Assess(cmd); !v.Destructive {
			t.Errorf("Assess(%q) = %+v, want destructive", cmd, v)
		}
	}
}

func TestDestructiveRejectsQuotedTextAndHarmlessCommands(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"echo rm -rf /x",
		`echo "rm -rf /x"`,
		`echo 'sudo userdel a'`,
		"nebula status",
		"nebula netdev list",
		"nebula backup --out /var/backups/x.age",
		"sudo nebula backup",
		"docker compose down",
		"docker compose up -v",
		"cat x.tar.gz",
		"ls -la /var/lib/nebula",
		"",
	} {
		if v := Assess(cmd); v.Destructive {
			t.Errorf("Assess(%q) = %+v, want not destructive", cmd, v)
		}
	}
}

func TestDestructiveFailsClosedWhenUnchecked(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown docker run option": "docker run --bogus-option img echo hi",
		"unknown sudo option":       "sudo --bogus echo hi",
		"unknown nice form":         "nice -5 echo hi",
		"unbalanced quote":          "echo 'abc",
		"too long":                  "echo " + string(make([]byte, MaxCommandBytes)),
		"bash -c without a string":  "bash -c",
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := Assess(cmd)
			if !v.Destructive {
				t.Errorf("Assess(%q) = %+v, want destructive", cmd, v)
			}
			if v.Pattern != "" {
				t.Errorf("Assess(%q) names row %q, want none (unchecked, not matched)", cmd, v.Pattern)
			}
		})
	}
}

func TestDestructiveVerdictIsDeterministic(t *testing.T) {
	t.Parallel()
	const cmd = "docker run --rm -v a:/v img rm -rf /v"
	first := Assess(cmd)
	for i := 0; i < 10; i++ {
		if got := Assess(cmd); got != first {
			t.Fatalf("run %d: %+v != %+v", i, got, first)
		}
	}
}
