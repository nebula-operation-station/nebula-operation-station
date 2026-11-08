#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the installer's bundle provisioning without root or services."""

import os
import re
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
NAMES = ("release-manifest.json", "release-manifest.json.sig", "builtins.tar")


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sidecars"
        self.source.mkdir()
        self.deploy = self.root / "deploy"
        self.deploy.mkdir()
        self.dest = self.root / "release"
        self.log = self.root / "install.log"
        fakebin = self.root / "bin"
        fakebin.mkdir()
        # Preserve real mkdir/copy/mode behavior; record root ownership requests
        # and remove only the chown flags that need privilege in this sandbox.
        install = fakebin / "install"
        install.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$INSTALL_LOG"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec /usr/bin/install "${args[@]}"
''')
        install.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{fakebin}:{os.environ['PATH']}",
                        INSTALL_LOG=str(self.log))
        text = (REPO / "deploy/install.sh").read_text()
        start = "# begin: release bundle\n"
        end = "# end: release bundle"
        self.assertIn(start, text, "installer must provision the bundle on every path")
        self.block = text.split(start, 1)[1].split(end, 1)[0]
        self.block = self.block.replace("release_dir=/usr/share/nebula/release",
                                       'release_dir="$TEST_RELEASE_DIR"')
        self.env.update(TEST_RELEASE_DIR=str(self.dest),
                        TEST_SCRIPT_DIR=str(self.deploy),
                        TEST_SOURCE_DIR=str(self.source))

    def run_block(self, explicit=True, success=True):
        prefix = 'set -euo pipefail\nscript_dir="$TEST_SCRIPT_DIR"\nbundle_source_dir=""\n'
        if explicit:
            prefix += 'bundle_source_dir="$TEST_SOURCE_DIR"\n'
        result = subprocess.run(["bash", "-c", prefix + self.block], env=self.env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def fill(self, directory=None):
        for name in NAMES:
            (directory or self.source).joinpath(name).write_text(f"fixture {name}\n")

    def assert_bundle(self):
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), sorted(NAMES))
        for name in NAMES:
            self.assertEqual((self.dest / name).read_bytes(),
                             (self.source / name).read_bytes())
            self.assertEqual(stat.S_IMODE((self.dest / name).stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o755)
        lines = self.log.read_text().splitlines()
        self.assertTrue(all("-o root -g root" in line for line in lines), lines)

    def test_source_and_quickstart_create_empty_directory_with_explanation(self):
        result = self.run_block(explicit=False)
        self.assertTrue(self.dest.is_dir())
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o755)
        self.assertIn("empty", result.stdout)
        self.assertIn("trust status is unreachable", result.stdout)

    def test_explicit_source_copies_only_three_files_and_is_idempotent(self):
        self.fill()
        (self.source / "unrelated").write_text("do not copy")
        self.run_block()
        self.assert_bundle()
        self.run_block()
        self.assert_bundle()

    def test_no_source_preserves_existing_bundle(self):
        self.fill()
        self.run_block()
        self.run_block(explicit=False)
        self.assert_bundle()

    def test_existing_directory_permissions_are_repaired(self):
        self.dest.mkdir(mode=0o700)
        self.run_block(explicit=False)
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o755)
        self.assertIn("-d -m 0755 -o root -g root", self.log.read_text())

    def test_adjacent_attachments_are_used_without_explicit_source(self):
        self.fill(self.deploy)
        self.run_block(explicit=False)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), sorted(NAMES))

    def test_explicit_source_takes_precedence_over_adjacent_attachments(self):
        self.fill(self.deploy)
        self.fill()
        (self.source / NAMES[0]).write_text("explicit bytes")
        self.run_block()
        self.assert_bundle()

    def test_partial_bundle_refused_before_existing_bundle_is_changed(self):
        self.fill()
        self.run_block()
        old = {name: (self.dest / name).read_bytes() for name in NAMES}
        (self.source / NAMES[-1]).unlink()
        (self.source / NAMES[0]).write_text("new bytes")
        self.run_block(success=False)
        self.assertEqual(old, {name: (self.dest / name).read_bytes() for name in NAMES})

    def test_each_symlink_and_special_file_is_refused(self):
        target = self.root / "target"
        target.write_text("untouched")
        for name in NAMES:
            for kind in ("symlink", "dangling", "directory", "fifo"):
                with self.subTest(name=name, kind=kind):
                    self.fill()
                    path = self.source / name
                    path.unlink()
                    if kind in ("symlink", "dangling"):
                        path.symlink_to(target if kind == "symlink" else self.root / "absent")
                    elif kind == "directory":
                        path.mkdir()
                    else:
                        os.mkfifo(path)
                    self.run_block(success=False)
                    self.assertFalse(any(self.dest.glob(".bundle.*")))
                    self.assertEqual(target.read_text(), "untouched")
                    path.rmdir() if kind == "directory" else path.unlink()

    def test_partial_adjacent_bundle_is_not_silently_ignored(self):
        (self.deploy / NAMES[0]).symlink_to(self.root / "absent")
        self.run_block(explicit=False, success=False)

    def test_explicit_missing_or_symlink_directory_is_refused(self):
        self.source.rmdir()
        self.run_block(success=False)
        self.fill(self.deploy)
        self.source.symlink_to(self.deploy, target_is_directory=True)
        for suffix in ("", "/", "///"):
            with self.subTest(suffix=suffix):
                self.env["TEST_SOURCE_DIR"] = str(self.source) + suffix
                self.run_block(success=False)

    def test_symlink_swapped_in_during_copy_is_not_followed(self):
        self.fill()
        target = self.root / "target"
        target.write_text("untouched")
        stub = self.root / "bin/cp"
        stub.write_text("""#!/usr/bin/env bash
src="${@: -2:1}"
rm -- "$src"
ln -s -- "$SWAP_TARGET" "$src"
exec /usr/bin/cp "$@"
""")
        stub.chmod(0o755)
        self.env["SWAP_TARGET"] = str(target)
        self.run_block(success=False)
        self.assertEqual(target.read_text(), "untouched")
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_destination_directory_symlink_is_refused(self):
        self.fill()
        self.dest.symlink_to(self.deploy, target_is_directory=True)
        self.run_block(success=False)
        self.assertEqual(list(self.deploy.iterdir()), [])

    def test_destination_file_symlinks_are_replaced_without_following(self):
        self.fill()
        self.dest.mkdir()
        target = self.root / "target"
        target.write_text("untouched")
        for name in NAMES:
            (self.dest / name).symlink_to(target)
        self.run_block()
        self.assert_bundle()
        self.assertEqual(target.read_text(), "untouched")


class BundleOptionTests(unittest.TestCase):
    def test_source_option_and_env_precedence(self):
        # Stop before all system changes, using a temporary local passwd entry.
        with tempfile.TemporaryDirectory() as directory:
            passwd = Path(directory) / "passwd"
            passwd.write_text("alice:x:1000:1000::/tmp:/bin/sh\n")
            fakebin = Path(directory) / "bin"
            fakebin.mkdir()
            getent = fakebin / "getent"
            getent.write_text('#!/bin/sh\ncat "$NEBULA_PASSWD_FILE"\n')
            getent.chmod(0o755)
            env = dict(os.environ, PATH=f"{fakebin}:{os.environ['PATH']}",
                       NEBULA_INSTALL_DRY_RUN="1",
                       NEBULA_PASSWD_FILE=str(passwd),
                       NEBULA_RELEASE_BUNDLE_DIR="/env/attachments")
            base = ["bash", str(REPO / "deploy/install.sh"),
                    "--admin-users", "alice", "--rp-id", "nebula.test"]
            for args, expected in (([], "/env/attachments"),
                                   (["--release-bundle-dir", "/option/attachments"],
                                    "/option/attachments"),
                                   (["--release-bundle-dir=/equals/attachments"],
                                    "/equals/attachments")):
                with self.subTest(args=args):
                    result = subprocess.run(base + args, env=env, text=True,
                                            capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(expected, result.stdout)
            for args in (["--release-bundle-dir"], ["--release-bundle-dir="]):
                result = subprocess.run(base + args, env=env, text=True,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


class PackagePolicyTests(unittest.TestCase):
    def test_deb_owns_empty_directory_with_explicit_root_mode(self):
        text = (REPO / ".goreleaser.yaml").read_text()
        nfpm = text.split("\nnfpms:", 1)[1].split("\ndockers:", 1)[0]
        entries = re.split(r"(?m)^      - ", nfpm)
        directories = [entry for entry in entries
                       if re.search(r"dst: /usr/share/nebula/release\s*\n", entry)]
        self.assertEqual(len(directories), 1)
        self.assertRegex(directories[0], r"type: dir\b")
        self.assertRegex(directories[0], r"mode: 0755, owner: root, group: root")
        self.assertNotRegex(directories[0], r"\bsrc:")
        for name in NAMES:
            self.assertNotIn(name, nfpm)

    def test_archive_sources_exclude_sidecars_even_when_beside_installer(self):
        text = (REPO / ".goreleaser.yaml").read_text()
        archive = text.split("\narchives:", 1)[1].split("\nnfpms:", 1)[0]
        patterns = re.findall(r"(?m)^      - src: (.+)$", archive)
        self.assertTrue(patterns)
        included = {path.relative_to(REPO).as_posix()
                    for pattern in patterns for path in REPO.glob(pattern)}
        for required in ("deploy/install.sh", "deploy/uninstall.sh",
                         "deploy/systemd/nebula-executor.service",
                         "deploy/quickstart/binaries.txt",
                         "deploy/quickstart/binaries_lib.sh"):
            self.assertIn(required, included)
        # Simulate an operator staging attachments before a packaging run.
        # GoReleaser uses these same archive source globs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy").mkdir()
            for name in NAMES:
                (root / "deploy" / name).write_text("local attachment")
            matches = [path for pattern in patterns for path in root.glob(pattern)]
            self.assertEqual(matches, [], "tarball must never embed local sidecars")

    def test_archive_keeps_deployment_layout(self):
        text = (REPO / ".goreleaser.yaml").read_text()
        archive = text.split("\narchives:", 1)[1].split("\nnfpms:", 1)[0]
        entries = re.findall(r"- src: ([^\n]+)\n\s+dst: ([^\n]+)", archive)
        self.assertTrue(entries)
        for source, dest in entries:
            # GoReleaser strips the glob's static prefix. Preserve the
            # directory for globs, and the complete path for literal files.
            expected = source.rsplit("/", 1)[0] + "/" if "*" in source else source
            self.assertEqual(dest, expected, source)

    def test_image_creates_empty_root_directory_for_read_only_executor(self):
        dockerfile = (REPO / "deploy/container/Dockerfile").read_text()
        self.assertIn("install -d -m 0755 -o root -g root /usr/share/nebula/release",
                      dockerfile)
        for line in dockerfile.splitlines():
            if line.startswith(("COPY ", "ADD ")):
                for name in NAMES:
                    self.assertNotIn(name, line)
        compose = (REPO / "deploy/container/compose.yaml").read_text()
        self.assertIn("read_only: true", compose)
        self.assertIn('security_opt: ["no-new-privileges:true"]', compose)
        executor = compose.split("\n  executor:", 1)[1].split("\n  server:", 1)[0]
        self.assertIn("<<: *hardening", executor)
        self.assertIn("/srv/nebula/release:/usr/share/nebula/release:ro", executor)


if __name__ == "__main__":
    unittest.main()
