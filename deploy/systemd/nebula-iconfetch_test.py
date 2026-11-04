# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unprivileged deployment policy tests: python3 deploy/systemd/nebula-iconfetch_test.py."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def settings(name):
    """Read repeated systemd assignments without treating comments as policy."""
    result = {}
    section = ""
    for line in (ROOT / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        key, value = line.split("=", 1)
        result.setdefault((section, key), []).append(value)
    return result


class IconfetchPolicyTest(unittest.TestCase):
    def setUp(self):
        self.unit = settings("nebula-iconfetch.service")

    def values(self, section, key):
        return self.unit.get((section, key), [])

    def test_helper_has_dedicated_unprivileged_identity(self):
        for key in ("User", "Group"):
            self.assertEqual(self.values("[Service]", key), ["nebula-iconfetch"])
        self.assertEqual(self.values("[Service]", "SupplementaryGroups"), ["nebula-icons"])
        for key, value in {
            "NoNewPrivileges": "yes",
            "CapabilityBoundingSet": "",
            "AmbientCapabilities": "",
            "RestrictSUIDSGID": "yes",
            "LimitCORE": "0",
        }.items():
            self.assertEqual(self.values("[Service]", key), [value], key)
        self.assertEqual(self.values("[Service]", "ExecStart"), [
            "/usr/bin/nebula-iconfetch -spool /var/lib/nebula/iconfetch"
        ])
        for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"):
            self.assertEqual(self.values("[Service]", key), [])

    def test_filesystem_blocks_databases_vault_and_rpc(self):
        self.assertEqual(self.values("[Service]", "ProtectSystem"), ["strict"])
        self.assertEqual(self.values("[Service]", "ReadWritePaths"), [
            "/var/lib/nebula/iconfetch/results"
        ])
        self.assertEqual(self.values("[Service]", "ReadOnlyPaths"), [
            "/var/lib/nebula/iconfetch/jobs"
        ])
        denied = " ".join(self.values("[Service]", "InaccessiblePaths")).split()
        for path in ("/var/lib/nebula/server", "/var/lib/nebula/executor",
                     "/etc/nebula", "/run/nebula"):
            self.assertIn("-" + path, denied)
        for key in ("StateDirectory", "RuntimeDirectory", "CacheDirectory", "LogsDirectory",
                    "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem"):
            self.assertEqual(self.values("[Service]", key), [], key)
        for key in ("ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables",
                    "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
                    "RestrictNamespaces", "MemoryDenyWriteExecute"):
            self.assertEqual(self.values("[Service]", key), ["yes"], key)

    def test_helper_has_bounded_resources_and_runs_once(self):
        for key, value in {"Type": "oneshot", "MemoryMax": "256M", "TasksMax": "32",
                           "TimeoutStartSec": "15min", "TimeoutStopSec": "15s",
                           "UMask": "0027"}.items():
            self.assertEqual(self.values("[Service]", key), [value], key)

    def test_network_address_families_and_private_ranges(self):
        self.assertEqual(self.values("[Service]", "RestrictAddressFamilies"), [
            "AF_INET AF_INET6"
        ])
        denied = " ".join(self.values("[Service]", "IPAddressDeny")).split()
        for address in ("localhost", "link-local", "multicast", "0.0.0.0/8",
                        "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12",
                        "192.168.0.0/16", "240.0.0.0/4", "fc00::/7"):
            self.assertIn(address, denied)
        self.assertEqual(self.values("[Service]", "IPAddressAllow"), [])

    def test_firewall_is_required_before_helper_starts(self):
        self.assertEqual(self.values("[Unit]", "BindsTo"), ["nebula-iconfetch-firewall.service"])
        self.assertIn("nebula-iconfetch-firewall.service",
                      " ".join(self.values("[Unit]", "After")).split())
        firewall = settings("nebula-iconfetch-firewall.service")
        for key, value in {
            "Type": "oneshot", "RemainAfterExit": "yes",
            "ExecStart": "/usr/sbin/nft -f /etc/nebula/nebula-iconfetch.nft",
            "CapabilityBoundingSet": "CAP_NET_ADMIN", "NoNewPrivileges": "yes",
            "ProtectSystem": "strict", "TimeoutStartSec": "15s",
        }.items():
            self.assertEqual(firewall.get(("[Service]", key)), [value], key)
        # No ignored failure, conditional skip, privileged helper command or cleanup gap.
        for key in ("ExecCondition", "ExecStop", "ExecStopPost"):
            self.assertNotIn(("[Service]", key), firewall)
        self.assertFalse(any(key.startswith("Condition") for _, key in firewall))
        self.assertEqual(self.values("[Service]", "SocketBindAllow"), [])

    def test_firewall_accepts_only_tcp_destination_443(self):
        source = (ROOT / "nebula-iconfetch.nft").read_text()
        rules = "\n".join(line.split("#", 1)[0] for line in source.splitlines())
        normalized = " ".join(rules.split())
        self.assertTrue(normalized.startswith(
            "add table inet nebula_iconfetch flush table inet nebula_iconfetch table inet nebula_iconfetch {"
        ))
        self.assertNotIn("flush ruleset", normalized)
        self.assertNotIn("delete table", normalized)
        self.assertIn("type filter hook output priority 0; policy accept;", normalized)
        self.assertIn('meta skuid "nebula-iconfetch" jump iconfetch', normalized)
        self.assertEqual(re.findall(r"[^{};\n]*\baccept\b[^{};\n]*", rules), [
            "        policy accept", "        meta l4proto tcp tcp dport 443 accept"
        ])
        for addresses in (
            "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, "
            "172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4",
            "::/128, ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8",
        ):
            self.assertIn(addresses, normalized)
        self.assertRegex(normalized, r"chain iconfetch \{ ip daddr \{[^}]+\} reject "
                         r"ip6 daddr \{[^}]+\} reject "
                         r"meta l4proto tcp tcp dport 443 accept reject \} \}")

    def test_activation_watches_jobs_and_retries_after_exit(self):
        path = settings("nebula-iconfetch.path")
        self.assertEqual(path.get(("[Path]", "PathChanged")), ["/var/lib/nebula/iconfetch/jobs"])
        self.assertEqual(path.get(("[Path]", "Unit")), ["nebula-iconfetch.service"])
        self.assertEqual(path.get(("[Install]", "WantedBy")), ["multi-user.target"])
        timer = settings("nebula-iconfetch.timer")
        self.assertEqual(timer.get(("[Timer]", "Unit")), ["nebula-iconfetch.service"])
        self.assertEqual(timer.get(("[Timer]", "OnBootSec")), ["1min"])
        self.assertEqual(timer.get(("[Timer]", "OnUnitInactiveSec")), ["1min"])
        self.assertEqual(timer.get(("[Install]", "WantedBy")), ["timers.target"])

    def test_systemd_accepts_unit_syntax(self):
        # Verify all real settings without requiring an installed helper binary.
        # The exact production ExecStart is checked separately above.
        with tempfile.TemporaryDirectory(prefix="iconfetch-units-") as directory:
            units = []
            for suffix in (".service", "-firewall.service", ".path", ".timer"):
                source = ROOT / ("nebula-iconfetch" + suffix)
                target = Path(directory) / source.name
                target.write_text(source.read_text().replace(
                    "/usr/bin/nebula-iconfetch -spool /var/lib/nebula/iconfetch",
                    "/usr/bin/true",
                ))
                units.append(str(target))
            result = subprocess.run(["systemd-analyze", "verify", *units],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
