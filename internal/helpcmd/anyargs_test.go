// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "testing"

// TestAnyArgsProgramsFollowOpensFilesRule checks that every allowlist entry
// that accepts any argument also applies the opens-files rule: an operand
// that names dev, proc or sys is not harmless, because the program opens its
// operands (df opens each one to trigger automount, so `df /dev/watchdog`
// arms the hardware watchdog when run as root).
func TestAnyArgsProgramsFollowOpensFilesRule(t *testing.T) {
	t.Parallel()
	for name, r := range allowlist {
		if r.spec.anyArgs && !r.opensFiles {
			t.Errorf("allowlist entry %q accepts any argument but does not apply the opens-files rule", name)
		}
	}
}

// TestAnyArgsSpecialFileOperandsNeedConfirmation covers the anyArgs programs
// (ls, df, free, uptime, ps) with an operand that names a special file or
// directory; such a command must need confirmation.
func TestAnyArgsSpecialFileOperandsNeedConfirmation(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		// df: the reported bug, a watchdog device opened by the operand.
		"df /dev/watchdog",
		"df -h /dev/watchdog",
		"df /dev/watchdog /var",
		"df -- /dev/watchdog",
		"df /proc/kmsg",
		"df -h /sys/kernel/debug",
		"df /proc/1/fd",
		"df ../../dev/sda",
		"sudo df /dev/watchdog",
		// ls opens directory operands; /dev, /proc and /sys are not read.
		"ls /dev",
		"ls -la /proc/self",
		"ls /sys/class",
		// free, uptime and ps take the same rule.
		"free /proc/kmsg",
		"uptime /dev/watchdog",
		"ps -ef /sys/x",
		"ps aux -- /dev/x",
	} {
		if v := Assess(cmd); v.Harmless {
			t.Errorf("Assess(%q) = %+v, want not harmless", cmd, v)
		}
	}
}

// TestAnyArgsOperandsOutsideSpecialFilesStayHarmless checks that the rule does
// not reject ordinary operands that only contain the letters of dev, proc or
// sys as part of another element.
func TestAnyArgsOperandsOutsideSpecialFilesStayHarmless(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"df -h",
		"df -h /",
		"df /var/lib/nebula",
		"df /var/dev-tools",
		"df /devx /procs /sysfs",
		"ls -la /var/lib/nebula",
		"ls /home/garm",
		"free -m",
		"uptime",
		"ps aux",
		"ps -ef",
	} {
		if v := Assess(cmd); !v.Harmless || v.Pattern != "" {
			t.Errorf("Assess(%q) = %+v, want harmless", cmd, v)
		}
	}
}
