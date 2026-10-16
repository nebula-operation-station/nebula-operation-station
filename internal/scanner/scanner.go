// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scanner is the Safety Scanner (spec 10): an advisory, fixed
// pattern list over a host script. A finding can only raise an action's
// effective risk (effective risk = max(declared, scanner, trust floor)); a
// clean scan proves nothing, because a script can always hide what it does
// (variables, generated code). The executor uses it as a floor source, the
// server to show the findings before approval; both run the same list.
package scanner

import (
	"bytes"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Version names the pattern list; it changes whenever a pattern does.
const Version = "scanner-v1"

// Categories.
const (
	DownloadExecute = "download_and_execute"
	EvalEncoded     = "eval_or_encoded_payload"
	DestructiveFS   = "destructive_filesystem"
	Bootloader      = "bootloader"
	UsersGroups     = "users_and_groups"
	NetworkFirewall = "network_and_firewall"
	PackageRemoval  = "package_removal"
	RebootPower     = "reboot_or_power"
	DockerRemoval   = "docker_removal"
)

// Limits: a longer line is scanned only in its first MaxLine bytes, and at
// most MaxFindings findings are reported (the floor is computed from all).
const (
	MaxLine     = 4096
	MaxFindings = 50
	maxExcerpt  = 120
)

// Finding is one match.
type Finding struct {
	Category string
	Risk     canonical.Risk
	// Line is 1-based (the first physical line of a continued line).
	Line int
	// Excerpt is the matched text, ASCII-quoted and shortened: safe to
	// show anywhere, but still host-author text.
	Excerpt string
}

type rule struct {
	category string
	risk     canonical.Risk
	re       *regexp.Regexp
}

// cmd matches the start of a command: line start or a shell separator,
// then any wrappers (sudo -n, exec, env, nohup, timeout 30, …) and an
// optional /usr/sbin/-style directory.
const cmd = `(?:^|[;&|({!` + "`" + `]|\$\(|\b(?:then|do|else)\b)\s*` +
	`(?:(?:sudo|exec|nohup|env|command|time|nice|ionice|xargs|timeout\s+\S+)\s+(?:-\S+\s+)*)*` +
	`(?:/usr)?(?:/s?bin/)?`

// end matches the end of a command word.
const end = `(?:\s|$|;|&|\||\))`

const shell = `(?:sudo\s+(?:-\S+\s+)*)?(?:/usr)?(?:/bin/)?(?:ba|da|z|k|c)?sh\b`

var rules = []rule{
	{DownloadExecute, canonical.RiskHigh, regexp.MustCompile(`\b(?:curl|wget|fetch)\b[^|;&]*\|\s*` + shell)},
	{DownloadExecute, canonical.RiskHigh, regexp.MustCompile(`\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:python3?|perl|ruby|php|node)\b`)},
	{DownloadExecute, canonical.RiskHigh, regexp.MustCompile(`\b(?:ba|da|z|k)?sh\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)\b`)},
	{DownloadExecute, canonical.RiskHigh, regexp.MustCompile(`\b(?:ba|da|z|k)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b`)},
	{EvalEncoded, canonical.RiskHigh, regexp.MustCompile(cmd + `eval` + end)},
	{EvalEncoded, canonical.RiskHigh, regexp.MustCompile(`\bbase64\s+(?:-\S+\s+)*(?:-d|-D|--decode)\b[^;&]*\|\s*` + shell)},
	{EvalEncoded, canonical.RiskHigh, regexp.MustCompile(`\b(?:xxd\s+(?:-\S+\s+)*-r|openssl\s+(?:enc|base64)\b[^|;&]*\s-d)\b[^;&]*\|\s*` + shell)},
	{DestructiveFS, canonical.RiskHigh, regexp.MustCompile(cmd + `rm\b[^;&|]*\s(?:["']?/\*?["']?|--no-preserve-root)` + end)},
	{DestructiveFS, canonical.RiskHigh, regexp.MustCompile(cmd + `(?:mkfs(?:\.\w+)?|wipefs|shred|blkdiscard|sgdisk|fdisk|sfdisk|parted)` + end)},
	{DestructiveFS, canonical.RiskHigh, regexp.MustCompile(`\bdd\b[^;&|]*\bof=/dev/`)},
	{DestructiveFS, canonical.RiskHigh, regexp.MustCompile(`>\s*/dev/(?:sd[a-z]|nvme\d|vd[a-z]|hd[a-z]|xvd[a-z]|mmcblk\d|md\d|dm-\d)`)},
	{Bootloader, canonical.RiskHigh, regexp.MustCompile(cmd + `(?:grub2?-install|update-grub2?|grub2?-mkconfig|efibootmgr)` + end)},
	{Bootloader, canonical.RiskHigh, regexp.MustCompile(`/etc/default/grub\b|/boot/(?:grub2?|efi)/`)},
	{UsersGroups, canonical.RiskMedium, regexp.MustCompile(cmd + `(?:useradd|userdel|usermod|groupadd|groupdel|groupmod|adduser|deluser|addgroup|delgroup|passwd|chpasswd|chage|gpasswd|visudo)` + end)},
	{UsersGroups, canonical.RiskMedium, regexp.MustCompile(`/etc/(?:sudoers|shadow|gshadow)\b|/etc/(?:passwd|group)\b|\bauthorized_keys\b`)},
	{NetworkFirewall, canonical.RiskMedium, regexp.MustCompile(cmd + `(?:iptables|ip6tables|iptables-restore|ip6tables-restore|nft|ufw|firewall-cmd)` + end)},
	{NetworkFirewall, canonical.RiskMedium, regexp.MustCompile(`\bip\s+(?:-\S+\s+)*(?:route|link|addr(?:ess)?|rule|neigh)\s+(?:add|del|delete|change|replace|set|flush)\b`)},
	{NetworkFirewall, canonical.RiskMedium, regexp.MustCompile(`\bnetplan\s+apply\b|/etc/network/interfaces\b|/etc/netplan/|\bsystemctl\s+(?:-\S+\s+)*(?:restart|stop)\s+(?:networking|systemd-networkd|NetworkManager)\b`)},
	{PackageRemoval, canonical.RiskMedium, regexp.MustCompile(`\b(?:apt-get|apt|aptitude)\s+(?:\S+\s+)*?(?:remove|purge|autoremove)\b|--auto-?remove\b`)},
	{PackageRemoval, canonical.RiskMedium, regexp.MustCompile(`\bdpkg\s+(?:\S+\s+)*?(?:-r|-P|--remove|--purge)` + end)},
	{RebootPower, canonical.RiskMedium, regexp.MustCompile(cmd + `(?:reboot|shutdown|poweroff|halt|kexec)` + end)},
	{RebootPower, canonical.RiskMedium, regexp.MustCompile(`\bsystemctl\s+(?:-\S+\s+)*(?:reboot|poweroff|halt|kexec|soft-reboot)\b|/proc/sysrq-trigger`)},
	{DockerRemoval, canonical.RiskMedium, regexp.MustCompile(`\bdocker(?:-compose)?\b[^;&|]*\s(?:rm|rmi|prune|down)` + end)},
}

// Scan returns the findings in script, at most MaxFindings, and the
// highest risk among all findings ("" when clean).
func Scan(script []byte) ([]Finding, canonical.Risk) {
	var out []Finding
	var floor canonical.Risk
	for _, line := range logicalLines(script) {
		text := line.text
		if len(text) > MaxLine {
			text = text[:MaxLine]
		}
		if t := strings.TrimLeft(text, " \t"); t == "" || t[0] == '#' {
			continue
		}
		seen := map[string]bool{}
		for _, r := range rules {
			if seen[r.category] {
				continue
			}
			loc := r.re.FindStringIndex(text)
			if loc == nil {
				continue
			}
			seen[r.category] = true
			if r.risk.Rank() > floor.Rank() {
				floor = r.risk
			}
			if len(out) < MaxFindings {
				out = append(out, Finding{Category: r.category, Risk: r.risk, Line: line.no, Excerpt: excerpt(text[loc[0]:loc[1]])})
			}
		}
	}
	return out, floor
}

// Categories lists the distinct categories of findings, sorted.
func Categories(f []Finding) []string {
	var out []string
	for _, x := range f {
		if !slices.Contains(out, x.Category) {
			out = append(out, x.Category)
		}
	}
	slices.Sort(out)
	return out
}

type logical struct {
	no   int
	text string
}

// logicalLines joins backslash-continued lines.
func logicalLines(script []byte) []logical {
	var out []logical
	var cur strings.Builder
	start := 0
	for i, l := range bytes.Split(script, []byte("\n")) {
		if cur.Len() == 0 {
			start = i + 1
		}
		l = bytes.TrimSuffix(l, []byte("\r"))
		if bytes.HasSuffix(l, []byte(`\`)) && cur.Len() < MaxLine {
			cur.Write(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.Write(l)
		out = append(out, logical{no: start, text: cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, logical{no: start, text: cur.String()})
	}
	return out
}

func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxExcerpt {
		s = s[:maxExcerpt]
	}
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}
