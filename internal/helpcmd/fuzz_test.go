// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "testing"

// FuzzCommandChecks checks the properties of checks V1 and V6 for arbitrary
// input: no panic, the same input gives the same verdict, a V1-valid input
// contains only printable ASCII, appending a separator and `rm -rf /x` to a
// V1-valid input is never harmless, an unknown program anywhere is never
// harmless, and a harmless input consists only of allowlisted simple
// commands without redirection (ADR 0014 V6 allowlist). The separator is
// ` ; ` rather than `;`: a trailing unquoted backslash would escape a bare
// `;`, and then bash does not see a separator either.
func FuzzCommandChecks(f *testing.F) {
	seeds := []string{
		"",
		"nebula status",
		"sudo rm -rf /var/lib/nebula /etc/nebula",
		"sudo userdel a; sudo userdel b",
		"bash -c 'rm -rf /x'",
		"docker run --rm -v nebula_executor-data:/v debian:12-slim rm -rf /v/x",
		"cat b.tgz | docker run -i debian:12-slim tar -C /v -xpz",
		"echo 'abc",
		"echo \"$(rm x)\"",
		"echo `rm x`",
		"a\\",
		"a > /dev/null 2>&1",
		"env A=1 nice -n 5 timeout 5s dd if=/dev/zero of=x",
		"sh -c \"sh -c \\\"rm x\\\"\"",
		"nebula netdev remove fw-01",
		"nebulaе status",
		"ls -la /var/lib/nebula",
		"journalctl -u nebula-server -n 100 --no-pager | tail -n 5",
		"ip -br a show dev eth0",
		"systemctl status x > out",
		"taskset 1 rm -rf /x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		first := Assess(s)
		if again := Assess(s); again != first {
			t.Fatalf("Assess(%q) is not deterministic: %+v then %+v", s, first, again)
		}
		if CheckASCII(s) != nil {
			return
		}
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				t.Fatalf("V1-valid input %q contains byte 0x%02X", s, s[i])
			}
		}
		if v := Assess(s + " ; rm -rf /x"); v.Harmless {
			t.Fatalf("Assess(%q + %q) = %+v, want not harmless", s, " ; rm -rf /x", v)
		}
		// An unknown program is never harmless, wherever it sits.
		for _, cmd := range []string{"zzunknown " + s, s + " ; zzunknown", s + " | zzunknown"} {
			if v := Assess(cmd); v.Harmless {
				t.Fatalf("Assess(%q) = %+v, want not harmless (unknown program)", cmd, v)
			}
		}
		// A harmless verdict needs every simple command to start with an
		// allowlisted program and to have no redirection.
		if first.Harmless {
			cmds, err := splitSimple(s)
			if err != nil || len(cmds) == 0 {
				t.Fatalf("Assess(%q) is harmless, but splitSimple gives %d commands, %v", s, len(cmds), err)
			}
			for _, c := range cmds {
				if len(c.words) == 0 || c.dynamic || c.redirected || c.compound {
					t.Fatalf("Assess(%q) is harmless, but a simple command is %+v", s, c)
				}
				if _, ok := allowlist[c.words[0]]; !ok {
					t.Fatalf("Assess(%q) is harmless, but program %q is not allowlisted", s, c.words[0])
				}
			}
		}
	})
}
