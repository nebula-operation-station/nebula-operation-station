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

// TestAnyArgsTildeOperandsNeedConfirmation covers an unquoted word that starts
// with `~`. The shell expands it to a home directory, and the home of user sys
// is /dev on Debian and Ubuntu, so `df ~sys/watchdog` opens /dev/watchdog. The
// word is not literal, so it is indeterminate.
func TestAnyArgsTildeOperandsNeedConfirmation(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"df ~sys/watchdog",
		"df -h ~sys/watchdog",
		"df ~/x",
		"ls ~root",
		"ls ~",
		"ls -la ~+",
		"free ~sys/x",
		"uptime ~sys/kmsg",
		"ps -ef ~sys/x",
	} {
		if v := Assess(cmd); v.Harmless {
			t.Errorf("Assess(%q) = %+v, want not harmless", cmd, v)
		}
	}
}

// TestAnyArgsShellExpansionOperandsNeedConfirmation covers operands that the
// shell rewrites before the program runs: parameters, command substitutions,
// globs and brace expansion. The program then sees a path that is not known.
func TestAnyArgsShellExpansionOperandsNeedConfirmation(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"df $HOME",
		"df ${HOME}",
		"df $HOME/x",
		"df `echo /dev/watchdog`",
		"df $(echo /dev/watchdog)",
		"df /de?/watchdog",
		"df /d[e]v/watchdog",
		"df /dev/watch*",
		"df {/dev,/tmp}",
		"df /{dev,tmp}/x",
		"ls *",
		"ls x?",
		"ls /dev/[k]msg",
		"ls -la {/proc,/tmp}",
		"ls \\/dev/watchdog",
	} {
		if v := Assess(cmd); v.Harmless {
			t.Errorf("Assess(%q) = %+v, want not harmless", cmd, v)
		}
	}
}

// TestAnyArgsBareOperandsOfFileProgramsNeedConfirmation covers the operands of
// df and ls that are not absolute. Their working directory is not known, and it
// may be under dev, proc or sys (`cd /dev && df watchdog`), so they are not
// harmless. Options are not operands and are not affected.
func TestAnyArgsBareOperandsOfFileProgramsNeedConfirmation(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"df watchdog",
		"df -h watchdog",
		"df -h / watchdog",
		"df . ..",
		"df ../x",
		"ls kmsg",
		"ls -la kmsg",
		"ls -- kmsg",
		"ls ./kmsg",
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
