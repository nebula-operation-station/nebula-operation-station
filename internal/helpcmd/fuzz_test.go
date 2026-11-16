// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "testing"

// FuzzCommandChecks checks the properties of checks V1 and V6 for arbitrary
// input: no panic, the same input gives the same verdict, a V1-valid input
// contains only printable ASCII, and appending `; rm -rf /x` to a V1-valid
// input always yields a destructive verdict.
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
		if v := Assess(s + "; rm -rf /x"); !v.Destructive {
			t.Fatalf("Assess(%q + %q) = %+v, want destructive", s, "; rm -rf /x", v)
		}
	})
}
