// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"strings"
	"testing"
)

// TestAllowlistFormsAreHarmless covers each row of the V6 allowlist of ADR
// 0014 (decision 2026-11-16) with forms that must be harmless.
func TestAllowlistFormsAreHarmless(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"ls",
		"ls -la /var/lib/nebula",
		"df -h",
		"du -sh /var/lib/nebula",
		"free -m",
		"uptime",
		"ps aux",
		"ps -ef",
		"cat x.tar.gz",
		"cat -n /etc/nebula/server.yaml",
		"head -n 20 /var/log/syslog",
		"head -5 x",
		"tail -f /var/log/nebula.log",
		"tail -n 50 x",
		"tail --lines=50 x",
		"wc -l x",
		"grep -i error /var/log/syslog",
		"grep -e a -e b x",
		"grep --color=auto -n x y",
		"ip a",
		"ip addr",
		"ip addr show dev eth0",
		"ip -br a",
		"ip -4 -json addr show",
		"ip r",
		"ip route show table all",
		"ip ro list",
		"ss -tulpn",
		"ss -t state established",
		"journalctl -u nebula-server -n 100 --no-pager",
		"journalctl --since today",
		"journalctl -b -e",
		"journalctl --disk-usage",
		"journalctl -n 100",
		"journalctl -n100",
		"journalctl -n +5 -u x",
		"journalctl -n",
		"journalctl -n --no-pager",
		"journalctl -en 50",
		"journalctl -fn 20 -u x",
		"journalctl -en",
		"journalctl -b",
		"journalctl -b -u x",
		"journalctl -b-1",
		"journalctl -eb",
		"head -20 x",
		"tail -20 x",
		"systemctl status nebula-server",
		"systemctl status nebula-server --no-pager",
		"systemctl --no-pager status nebula-server",
		"systemctl show -p ActiveState nebula-server",
		"systemctl list-units --failed",
		"systemctl list-timers",
		"docker ps -a",
		"docker logs --tail 50 nebula",
		"docker logs -f nebula",
		"docker inspect -f '{{.State.Status}}' nebula",
		"qm list",
		"qm config 100",
		"qm status 100 --verbose",
		"pct list",
		"pct config 101",
		"pct status 101",
		"zpool status -x",
		"zpool list -H",
		"zfs list -t snapshot",
		"ps aux | grep nebula",
		"df -h && free -m",
		"uptime; uptime",
		"journalctl -u x | tail -n 5",
		"ls || ls -a",
		"ls &",
		"grep 'a b' x",
	} {
		if v := Assess(cmd); !v.Harmless || v.Pattern != "" {
			t.Errorf("Assess(%q) = %+v, want harmless", cmd, v)
		}
	}
}

// reviewBypasses are the commands that the reviews of PR #596 (tr06f, tr06g)
// found to pass the old V6 deny list. Under the allowlist each of them must
// need confirmation.
var reviewBypasses = []string{
	// tr06g HIGH: runners not on the deny list.
	"taskset 1 rm -rf /x",
	"toybox rm -rf /x",
	"podman run img rm -rf /x",
	"pct exec 100 -- rm -rf /x",
	"builtin eval 'rm -rf /x'",
	"trap 'rm -rf /x' EXIT",
	"alias ls='rm -rf /x'; ls",
	"source ./x.sh",
	". ./x.sh",
	"python3 -c 'import shutil; shutil.rmtree(\"/x\")'",
	"python -c 'import os'",
	"perl -e 'unlink \"x\"'",
	"ruby -e 'x'",
	"node -e 'x'",
	"awk 'BEGIN{system(\"rm -rf /x\")}'",
	// tr06g HIGH: su with several command options.
	"su -c 'echo hi' -c 'userdel bob'",
	"su -c 'echo hi' root --session-command 'userdel bob'",
	// tr06g MEDIUM: assignments that run code.
	"PROMPT_COMMAND='rm -rf /x'",
	"PS1='$(rm -rf /x)'",
	"GIT_SSH_COMMAND='rm -rf /x' git fetch",
	"LD_PRELOAD=/tmp/x.so ls",
	"LC_ALL=C ls",
	// tr06g MEDIUM: options that run a program.
	"tar -cf /dev/null a --checkpoint=1 --checkpoint-action=exec='rm -rf /x'",
	"tar -I 'sh -c x' -cf a b",
	"find . -exec rm {} +",
	"find . -delete",
	"find . -name x",
	// tr06g LOW: equivalent docker forms.
	"docker volume remove v",
	"docker compose down --volumes",
	"docker compose down -tv",
	// Wrappers around allowlisted programs.
	"sudo ls",
	"sudo -u root cat x",
	"env ls",
	"nice ls",
	"nice -n 5 ls",
	"nohup ls",
	"timeout 5 ls",
	"time ls",
	"exec ls",
	"command ls",
	"builtin ls",
	"xargs ls",
	"echo x | xargs cat",
	"sh -c 'ls'",
	"bash -c ls",
	"bash -lc 'cat x'",
	"su -c ls",
	"doas ls",
	"watch ls",
	"strace ls",
	"chroot / ls",
	"nsenter -t 1 -m ls",
	"systemd-run ls",
	"docker exec c ls",
	"docker run img ls",
	"docker compose exec s ls",
	"ssh h ls",
	"busybox ls",
	"stdbuf -o0 ls",
	// Program words that are not the bare allowlisted name.
	"/bin/ls",
	"./ls",
	"../bin/cat x",
	"'/usr/bin/ls'",
	"\\ls",
	"LS",
	// Redirections are never harmless.
	"ls > out",
	"ls >> out",
	"ls >out",
	"ls 1>out",
	"ls >| out",
	"ls &> out",
	"ls &>> out",
	"ls 2>&1",
	"ls 2> /dev/null",
	"cat x > /etc/passwd",
	"cat < x",
	"cat <<< x",
	"cat <<EOF",
	"cat <(ls)",
	"ls >(cat)",
	// Substitutions, expansions, globs, groups, history expansion.
	"cat $(echo x)",
	"cat `echo x`",
	"ls $HOME",
	"ls ${X}",
	"ls *.log",
	"ls x?",
	"ls [ab]",
	"ls {a,b}",
	"ls() { cat x; }; ls",
	"{ ls; }",
	"(ls)",
	"ls !!",
	"cat !$",
	"! ls",
	"if ls; then ls; fi",
	"while ls; do ls; done",
	"for f in a; do cat $f; done",
	"coproc ls",
	"ls \\; rm -rf /x",
	// Allowlisted programs with forbidden subcommands or options.
	"journalctl --vacuum-size=1M",
	"journalctl --vacuum-time=1d",
	"journalctl --vacuum-files=1",
	"journalctl --vac=1",
	"journalctl --rotate",
	"journalctl --flush",
	"journalctl --sync",
	"journalctl --relinquish-var",
	"journalctl --setup-keys",
	"journalctl --cursor-file=x",
	"journalctl --file=x",
	"journalctl -D /x",
	"journalctl -M c",
	"journalctl --unit",
	// tr06h HIGH: journalctl takes the word after a bare -n only when it is
	// a number, so the word is an option of its own.
	"journalctl -n --vacuum-size=1K",
	"journalctl -n --rotate",
	"journalctl -n --flush",
	"journalctl -n -D /x",
	"journalctl -n -M c",
	"journalctl -en --vacuum-time=1s",
	"journalctl -fn --vacuum-files=1",
	"journalctl -n 0x10 --rotate",
	"journalctl -n -0 --rotate",
	"journalctl -n 99999999999 --rotate",
	"journalctl -n all --rotate",
	"journalctl -n '' --rotate",
	"journalctl -n ++5 --rotate",
	// -b takes an attached boot (`-b-1`) or checks the next word; the next
	// word is never consumed by the check.
	"journalctl -b --rotate",
	"journalctl -eb --vacuum-size=1K",
	"journalctl -b -D /x",
	// tr06i audit: head and tail read `-5c`, `-5n` as one obsolete count
	// option; the next word is then a file, not a value.
	"head -5c /dev/watchdog",
	"head -5n /proc/kmsg",
	"tail -5c /dev/watchdog",
	"tail -5n /proc/kmsg",
	"tail -5f /dev/x",
	"head -5v /dev/x",
	"head -n5 -5c /dev/x",
	"tail -c 5 -5c /dev/x",
	"systemctl stop x",
	"systemctl restart x",
	"systemctl daemon-reload",
	"systemctl",
	"systemctl -H h status x",
	"systemctl --host=h status x",
	"systemctl stat x",
	"systemctl list x",
	"docker",
	"docker rm x",
	"docker -H tcp://h ps",
	"docker container ls",
	"docker logs --bogus x",
	"qm stop 100",
	"qm destroy 100",
	"qm",
	"pct exec 100 ls",
	"pct destroy 100",
	"zpool destroy p",
	"zpool status -c script",
	"zpool status -cscript",
	"zpool iostat -c x",
	"zfs destroy p",
	"zfs status",
	"ip",
	"ip a add 1.2.3.4/24 dev eth0",
	"ip a del 1.2.3.4/24 dev eth0",
	"ip a d 1.2.3.4/24 dev eth0",
	"ip a flush dev eth0",
	"ip route flush all",
	"ip r add default via 1.2.3.4",
	"ip -batch x",
	"ip -b x",
	"ip -force a",
	"ip -n x a",
	"ip netns exec x ls",
	"ip link set x down",
	"ip link",
	"ss -K dst 1.2.3.4",
	"ss --kill",
	"ss -tK",
	"ss -D x",
	"ss --diag=x",
	"ss -F x",
	"ss -N n",
	"grep -r x /",
	"grep -R x /",
	"grep --recursive x /",
	"grep -rn x .",
	"grep -f /x y",
	"grep -d recurse x .",
	"grep -D read x y",
	"grep x /dev/watchdog",
	"cat /dev/watchdog",
	"cat dev/watchdog",
	"cat /proc/kmsg",
	"cat /sys/kernel/debug/x",
	"head -c 1 /dev/sda",
	"tail -f /dev/x",
	"wc --files0-from=x",
	"du --files0-from=/dev/watchdog",
	"du -X /dev/watchdog .",
	"du --exclude-from=x .",
	"wc -l /dev/zero",
	"cat --bogus x",
	"tail -s",
	"head -n",
	// Not on the allowlist at all.
	"rm -rf /x",
	"echo hi",
	"true",
	"nebula status",
	"nebula netdev list",
	"tee -a ~/.ssh/authorized_keys",
	"curl https://x",
	"dd if=/dev/zero of=x",
	// Unchecked input.
	"",
	"   ",
	";",
	"echo 'abc",
	"ls 'abc",
	"ls $(",
	"l" + "ѕ",
	"ls\nrm -rf /x",
	"ls " + strings.Repeat("a", MaxCommandBytes),
}

// TestReviewBypassesNeedConfirmation is the fail-closed rule of ADR 0014 V6:
// every command that is not recognised as harmless needs confirmation, and
// no wrapper, shell, alias or interpreter hides a command from the check.
func TestReviewBypassesNeedConfirmation(t *testing.T) {
	t.Parallel()
	for _, cmd := range reviewBypasses {
		v := Assess(cmd)
		if v.Harmless {
			t.Errorf("Assess(%q) = %+v, want not harmless", cmd, v)
		}
		if !v.NeedsConfirmation() {
			t.Errorf("Assess(%q).NeedsConfirmation() = false, want true", cmd)
		}
	}
}

// TestHarmlessUnitDoesNotCoverOtherUnits checks that one allowlisted unit
// never makes the whole command harmless.
func TestHarmlessUnitDoesNotCoverOtherUnits(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"ls", "cat x", "systemctl status x", "docker ps"} {
		for _, sep := range []string{" ; ", " && ", " || ", " | ", " & "} {
			for _, other := range []string{"echo hi", "taskset 1 rm -rf /x", "ls > x", "sudo ls"} {
				for _, cmd := range []string{h + sep + other, other + sep + h} {
					if v := Assess(cmd); v.Harmless {
						t.Errorf("Assess(%q) = %+v, want not harmless", cmd, v)
					}
				}
			}
		}
	}
}

// TestZeroVerdictNeedsConfirmation checks that the zero Verdict fails closed.
func TestZeroVerdictNeedsConfirmation(t *testing.T) {
	t.Parallel()
	if !(Verdict{}).NeedsConfirmation() {
		t.Error("zero Verdict does not need confirmation")
	}
}

// TestDestructiveRowStillNamedWhenNotHarmless checks that the destructive
// wording survives the allowlist: a listed row is named, an unknown command
// is not harmless without a row.
func TestDestructiveRowStillNamedWhenNotHarmless(t *testing.T) {
	t.Parallel()
	if v := Assess("sudo rm -rf /var/lib/nebula"); v.Harmless || v.Pattern == "" {
		t.Errorf("rm -rf: got %+v, want not harmless with a row", v)
	}
	if v := Assess("echo hi"); v.Harmless || v.Pattern != "" {
		t.Errorf("echo: got %+v, want not harmless without a row", v)
	}
}

// TestOptionalValueTakesOnlyCounts checks the form that decides whether a
// bare journalctl -n takes the next word: only a count that every parser
// reads as a number, so the check never consumes a word the program reads
// as an option.
func TestOptionalValueTakesOnlyCounts(t *testing.T) {
	t.Parallel()
	for w, want := range map[string]bool{
		"0": true, "5": true, "+5": true, "123456789": true, "+0": true,
		"": false, "+": false, "++5": false, "-5": false, "-0": false,
		"05": false, "089": false, "0x10": false, "1234567890": false,
		"5k": false, " 5": false, "all": false, "--rotate": false, "-D": false,
	} {
		if got := isJournalLines(w); got != want {
			t.Errorf("isJournalLines(%q) = %v, want %v", w, got, want)
		}
	}
	for w, want := range map[string]bool{
		"-5": true, "-0": true, "-20": true,
		"-": false, "-05": false, "-5c": false, "-5n": false, "-c5": false,
		"--5": false, "-1234567890": false,
	} {
		if got := isNumericOption(w); got != want {
			t.Errorf("isNumericOption(%q) = %v, want %v", w, got, want)
		}
	}
}

// TestAllowlistEntriesHaveReasons checks that every allowlist entry carries
// the reason the ADR gives for it.
func TestAllowlistEntriesHaveReasons(t *testing.T) {
	t.Parallel()
	for name, r := range allowlist {
		if strings.TrimSpace(r.why) == "" {
			t.Errorf("allowlist entry %q has no reason", name)
		}
		if strings.ContainsAny(name, "/ ") || name == "" {
			t.Errorf("allowlist entry %q is not a bare program name", name)
		}
	}
}
