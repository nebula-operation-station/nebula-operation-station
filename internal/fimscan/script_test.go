// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

var scriptTestKey = bytes.Repeat([]byte{0x3c}, HostKeySize)

// fakeMountinfo is the test tree's /proc/self/mountinfo: /boot/efi (vfat)
// is a covered root, /etc/pve (fuse) is excluded by design, the mount with a
// space lies below /opt, / and /proc lie below no root.
const fakeMountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 8:2 / /boot/efi rw,relatime shared:2 - vfat /dev/sda2 rw,fmask=0077
24 22 0:50 / /etc/pve rw,nosuid,nodev shared:3 - fuse /dev/fuse rw,user_id=0
25 22 8:17 / /opt/data\040disk rw,relatime shared:4 - ext4 /dev/sdb1 rw
26 22 0:5 / /proc rw,nosuid shared:5 - proc proc rw
27 22 0:60 / /usr/lib/x\011t\134b rw shared:6 opt:x - FUSE"x\ none rw
`

// weirdName is a file name with a newline, a backslash and a non-UTF-8 byte.
const weirdName = "we\nird\\\xff.conf"

type treeOpts struct {
	symlinkHome bool // /home/carol is a symlink: partial
	unreadable  bool // /etc/secret is not readable: partial
	bigSparse   bool // /opt/big is a 600 MiB sparse file
}

// buildTree creates a small host file system under a temporary root.
func buildTree(t *testing.T, o treeOpts) string {
	t.Helper()
	root := t.TempDir()
	dir := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file := func(p, content string, mode fs.FileMode) {
		dir(filepath.Dir(p))
		full := filepath.Join(root, p)
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		dir(filepath.Dir(p))
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	file("/etc/hostname", "host1\n", 0o644)
	file("/etc/shadow", "root:*:19000:0:99999:7:::\n", 0o640)
	file("/etc/"+weirdName, "x=1\n", 0o644)
	file("/etc/ld.so.cache", "cache", 0o644)
	file("/etc/pve/storage.cfg", "dir: local\n", 0o640)
	file("/etc/pve/priv/authkey.key", "secret", 0o600)
	file("/etc/ssh/sshd_config", "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n", 0o644)
	file("/etc/ssh/sshd_config.d/10-a.conf", "  include = extra.conf\nPermitRootLogin no\n", 0o644)
	file("/etc/ssh/extra.conf", "PasswordAuthentication no\n", 0o644)
	file("/etc/ssh/ssh_host_ed25519_key", "PRIVATE", 0o600)
	file("/etc/crontab", "# m h dom mon dow user command\n", 0o644)
	file("/etc/systemd/system/multi-user.target.wants/.keep", "", 0o644)
	link("/usr/lib/systemd/system/x.service", "/etc/systemd/system/multi-user.target.wants/x.service")
	if err := syscall.Mkfifo(filepath.Join(root, "etc/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	file("/boot/vmlinuz-6.1.0-18-amd64", "kernel", 0o644)
	file("/boot/grub/grub.cfg", "set superusers=root\npassword_pbkdf2 root grub.pbkdf2.sha512.x\n", 0o444)
	file("/boot/efi/EFI/debian/grubx64.efi", "efi", 0o755)
	file("/usr/bin/ls", "ELF-ls", 0o755)
	file("/usr/bin/su", "ELF-su", fs.ModeSetuid|0o755)
	link("dash", "/usr/bin/sh")
	file("/usr/sbin/sshd", "ELF-sshd", 0o755)
	file("/usr/lib/systemd/system/x.service", "[Service]\n", 0o644)
	file("/usr/lib/python3.11/os.py", "import abc\n", 0o644)
	file("/usr/lib/python3.11/__pycache__/os.cpython-311.pyc", "pyc", 0o644)
	file("/usr/lib/python3/dist-packages/m/__pycache__/m.pyc", "pyc", 0o644)
	file("/usr/lib/modules/6.1.0-18-amd64/modules.dep", "dep", 0o644)
	file("/usr/lib/modules/6.1.0-18-amd64/kernel/a.ko", "ko", 0o644)
	file("/usr/lib/modules/6.1.0-18-amd64/kernel/modules.extra", "kept", 0o644)
	dir("/usr/local/bin")
	dir("/usr/local/sbin")
	file("/usr/local/lib/python3.11/__pycache__/l.pyc", "pyc", 0o644)
	file("/usr/local/lib/libx.so", "so", 0o644)
	file("/opt/app/run", "#!/bin/sh\n", 0o755)
	file("/var/spool/cron/crontabs/root", "* * * * * true\n", 0o600)
	file("/var/lib/docker/x", "not in profile", 0o644)
	file("/tmp/x", "not in profile", 0o644)
	link("usr/bin", "/bin")
	link("usr/sbin", "/sbin")
	link("usr/lib", "/lib")
	file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA root\n", 0o600)
	file("/root/.ssh/authorized_keys2", "", 0o600)
	file("/root/.ssh/id_ed25519", "PRIVATE", 0o600)
	file("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice\n", 0o600)
	file("/home/alice/.ssh/known_hosts", "host ssh-ed25519 AAAA\n", 0o644)
	file("/home/alice/.k5login", "alice@REALM\n", 0o644)
	file("/home/alice/notes.txt", "not in profile", 0o644)
	dir("/home/bob")
	file("/elsewhere/.ssh/authorized_keys", "ssh-ed25519 AAAA carol\n", 0o600)
	if o.symlinkHome {
		link("/elsewhere", "/home/carol")
	}
	if o.unreadable {
		file("/etc/secret", "unreadable", 0o000)
	}
	if o.bigSparse {
		f, err := os.Create(filepath.Join(root, "opt/big"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(600 << 20); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	file("/proc/self/mountinfo", fakeMountinfo, 0o444)
	return root
}

// shells returns the shells the script is run with: /bin/sh (what the
// executor uses) and dash and bash when installed.
func shells(t *testing.T) []string {
	out := []string{"/bin/sh"}
	for _, s := range []string{"dash", "bash"} {
		if p, err := exec.LookPath(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// runScript runs the embedded script against root and returns its stdout.
func runScript(t *testing.T, shell, root string, params []byte) ([]byte, []byte, error) {
	t.Helper()
	return runScriptPath(t, shell, root, params, os.Getenv("PATH"))
}

func runScriptPath(t *testing.T, shell, root string, params []byte, path string, env ...string) ([]byte, []byte, error) {
	t.Helper()
	work := t.TempDir()
	scriptPath := filepath.Join(work, "action.sh")
	if err := os.WriteFile(scriptPath, Script, 0o600); err != nil {
		t.Fatal(err)
	}
	paramsPath := filepath.Join(work, "params.json")
	if err := os.WriteFile(paramsPath, params, 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, scriptPath)
	cmd.Dir = cwd
	cmd.Env = []string{
		"PATH=" + path,
		"NEBULA_PARAMS=" + paramsPath,
		"NEBULA_FIM_TEST_ROOT=" + root,
		// A here-document or temporary file would need TMPDIR.
		"TMPDIR=" + filepath.Join(work, "no-such-dir"),
		"HOME=" + filepath.Join(work, "no-such-home"),
	}
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if left, rerr := os.ReadDir(cwd); rerr != nil || len(left) != 0 {
		t.Errorf("script left %d entries in its working directory (%v)", len(left), rerr)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func scanParams(t *testing.T, mode Mode) []byte {
	t.Helper()
	b, err := Action().ParametersJSON(map[string]string{"mode": string(mode), "profile": DefaultProfileID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runAndParse(t *testing.T, shell, root string, mode Mode) *Result {
	t.Helper()
	out, stderr, err := runScript(t, shell, root, scanParams(t, mode))
	if err != nil {
		t.Fatalf("script: %v\nstderr: %s", err, stderr)
	}
	res, err := Parse(context.Background(), bytes.NewReader(out), Options{Profile: DefaultProfile(), Mode: mode, HostKey: scriptTestKey})
	if err != nil {
		t.Fatalf("parse: %v\ndocument: %.4000s", err, out)
	}
	return res
}

// expectedRecords walks the test tree independently of the script and
// returns the records fim-default-v1 must report, keyed by host path, and
// the plain SHA-256 of every file (all are hashed in these tests unless
// noted).
func expectedRecords(t *testing.T, root string) (map[string]Record, map[string][sha256.Size]byte) {
	t.Helper()
	recs := map[string]Record{}
	sums := map[string][sha256.Size]byte{}
	excluded := func(p string) bool {
		switch {
		case p == "/etc/pve" || strings.HasPrefix(p, "/etc/pve/"),
			p == "/etc/ld.so.cache",
			p == "/boot/efi" || strings.HasPrefix(p, "/boot/efi/"), // own root
			strings.HasPrefix(p, "/usr/lib/python3") && strings.Contains(p, "/__pycache__"),
			strings.HasPrefix(p, "/usr/local/lib/python3") && strings.Contains(p, "/__pycache__"),
			regexp.MustCompile(`^/usr/lib/modules/[^/]+/modules\.`).MatchString(p):
			return true
		}
		return false
	}
	add := func(full string, d fs.DirEntry) {
		host := strings.TrimPrefix(full, root)
		var st syscall.Stat_t
		if err := syscall.Lstat(full, &st); err != nil {
			t.Fatal(err)
		}
		r := Record{
			Path: []byte(host), Size: st.Size, Mode: st.Mode & 0o7777, UID: st.Uid, GID: st.Gid,
			Inode: st.Ino, Mtime: st.Mtim.Sec, Ctime: st.Ctim.Sec,
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			r.Type = TypeFile
			b, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			sums[host] = sha256.Sum256(b)
		case syscall.S_IFDIR:
			r.Type = TypeDir
		case syscall.S_IFLNK:
			r.Type = TypeSymlink
			l, err := os.Readlink(full)
			if err != nil {
				t.Fatal(err)
			}
			r.Link = []byte(l)
		default:
			r.Type = TypeOther
		}
		recs[host] = r
	}
	walk := func(start string, prune func(string) bool) {
		full := filepath.Join(root, start)
		if _, err := os.Lstat(full); err != nil {
			return
		}
		err := filepath.WalkDir(full, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			host := strings.TrimPrefix(p, root)
			if prune(host) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			add(p, d)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"/etc", "/boot", "/bin", "/sbin", "/lib", "/usr/bin", "/usr/sbin", "/usr/lib",
		"/usr/libexec", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/opt", "/var/spool/cron/crontabs"} {
		walk(s, excluded)
	}
	walk("/boot/efi", func(string) bool { return false })
	homes, _ := filepath.Glob(filepath.Join(root, "home", "*"))
	homes = append([]string{filepath.Join(root, "root")}, homes...)
	for _, h := range homes {
		if fi, err := os.Lstat(h); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		for _, rel := range homeFiles {
			m, _ := filepath.Glob(filepath.Join(h, rel))
			for _, f := range m {
				walk(strings.TrimPrefix(f, root), func(string) bool { return false })
			}
		}
	}
	return recs, sums
}

func compareRecords(t *testing.T, res *Result, want map[string]Record, sums map[string][sha256.Size]byte, unhashed map[string]bool) {
	t.Helper()
	got := map[string]Record{}
	for _, r := range res.Records {
		got[string(r.Path)] = r
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			t.Errorf("missing record %s", EscapePath([]byte(p)))
			continue
		}
		if g.Type != w.Type || g.Size != w.Size || g.Mode != w.Mode || g.UID != w.UID || g.GID != w.GID ||
			g.Inode != w.Inode || g.Mtime != w.Mtime || g.Ctime != w.Ctime || !bytes.Equal(g.Link, w.Link) {
			t.Errorf("record %s: got %+v, want %+v", EscapePath([]byte(p)), g, w)
		}
		wantHash := Hash{}
		if s, ok := sums[p]; ok && !unhashed[p] {
			wantHash = sealHash(scriptTestKey, []byte(p), s)
		}
		if g.Hash != wantHash {
			t.Errorf("record %s: hash %+v, want %+v", EscapePath([]byte(p)), g.Hash, wantHash)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected record %s", EscapePath([]byte(p)))
		}
	}
}

func rootStates(res *Result) map[string]RootState {
	m := map[string]RootState{}
	for _, r := range res.Roots {
		m[r.Pattern] = r.State
	}
	return m
}

// TestScriptOutputMatchesParserAndTree: a full run over the test tree is a
// complete fim-scan-v1 document whose records equal an independent walk of
// the tree (fim-default-v1 roots, excludes, -xdev pruning of the /boot/efi
// mount), with the D6 hash forms, the mounts below the roots and the SSH
// configuration with its includes.
func TestScriptOutputMatchesParserAndTree(t *testing.T) {
	for _, sh := range shells(t) {
		t.Run(filepath.Base(sh), func(t *testing.T) {
			root := buildTree(t, treeOpts{})
			res := runAndParse(t, sh, root, ModeFull)
			if !res.Complete() {
				t.Fatalf("run not complete: partial %v, dropped %v, host %+v, ssh %v", res.Partial, res.Dropped, res.Host, res.SSHConfigState)
			}
			want, sums := expectedRecords(t, root)
			compareRecords(t, res, want, sums, nil)

			states := rootStates(res)
			for p, s := range map[string]RootState{
				"/etc": RootScanned, "/etc/systemd/system": RootScanned, "/etc/systemd/user": RootAbsent,
				"/boot/efi": RootScanned, "/usr/libexec": RootAbsent, "/opt": RootScanned, "/bin": RootScanned,
				"/var/spool/cron/crontabs": RootScanned, "/root/.ssh/authorized_keys*": RootScanned,
				"/home/*/.ssh/authorized_keys*": RootScanned, "/home/*/.k5login": RootScanned,
				"/root/.shosts": RootAbsent, "/home/*/.ssh/known_hosts2": RootAbsent,
			} {
				if states[p] != s {
					t.Errorf("root %s: state %v, want %v", p, states[p], s)
				}
			}

			wantMounts := []Mount{{Path: []byte("/boot/efi"), FSType: "vfat"}, {Path: []byte("/etc/pve"), FSType: "fuse"}, {Path: []byte("/opt/data disk"), FSType: "ext4"}, {Path: []byte("/usr/lib/x\tt\\b"), FSType: "invalid"}}
			if len(res.Mounts) != len(wantMounts) {
				t.Fatalf("mounts %+v, want %+v", res.Mounts, wantMounts)
			}
			for i, m := range wantMounts {
				if !bytes.Equal(res.Mounts[i].Path, m.Path) || res.Mounts[i].FSType != m.FSType {
					t.Errorf("mount %d: %q %s, want %q %s", i, res.Mounts[i].Path, res.Mounts[i].FSType, m.Path, m.FSType)
				}
			}

			if res.SSHConfigState != SSHConfigValid {
				t.Fatalf("ssh config state %v", res.SSHConfigState)
			}
			var sshPaths []string
			for _, f := range res.SSHConfig {
				sshPaths = append(sshPaths, string(f.Path))
				b, err := os.ReadFile(filepath.Join(root, string(f.Path)))
				if err != nil || !bytes.Equal(b, f.Content) {
					t.Errorf("ssh config %s: content differs (%v)", f.Path, err)
				}
			}
			if want := []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-a.conf", "/etc/ssh/extra.conf"}; !slices.Equal(sshPaths, want) {
				t.Errorf("ssh config files %q, want %q", sshPaths, want)
			}

			for p, k := range map[string]HashKind{
				"/usr/bin/ls": HashPlain, "/boot/vmlinuz-6.1.0-18-amd64": HashPlain,
				"/boot/grub/grub.cfg": HashKeyed, "/etc/hostname": HashKeyed, "/opt/app/run": HashKeyed,
				"/root/.ssh/authorized_keys": HashKeyed, "/boot/efi/EFI/debian/grubx64.efi": HashKeyed,
			} {
				if r := findRecord(t, res, p); r.Hash.Kind != k {
					t.Errorf("%s: hash kind %v, want %v", p, r.Hash.Kind, k)
				}
			}
			if r := findRecord(t, res, "/etc/shadow"); !r.Hash.Secret || r.Hash.Kind != HashKeyed {
				t.Errorf("/etc/shadow hash %+v", r.Hash)
			}
			if r := findRecord(t, res, "/usr/bin/su"); r.Mode != 0o4755 {
				t.Errorf("/usr/bin/su mode %o", r.Mode)
			}
			if r := findRecord(t, res, "/etc/fifo"); r.Type != TypeOther || r.Hash.Kind != HashNone {
				t.Errorf("/etc/fifo %+v", r)
			}
			if r := findRecord(t, res, "/bin"); r.Type != TypeSymlink || string(r.Link) != "usr/bin" {
				t.Errorf("/bin %+v", r)
			}
			findRecord(t, res, "/etc/"+weirdName)
		})
	}
}

// TestScriptAwkImplementations: the document is the same with every awk
// the host may have (mawk is Debian's default; gawk and busybox awk are
// common), each skipped when not installed.
func TestScriptAwkImplementations(t *testing.T) {
	root := buildTree(t, treeOpts{})
	ref, stderr, err := runScript(t, "/bin/sh", root, scanParams(t, ModeFull))
	if err != nil {
		t.Fatalf("script: %v %s", err, stderr)
	}
	for _, c := range []struct{ name, bin string }{{"mawk", "mawk"}, {"gawk", "gawk"}, {"original-awk", "original-awk"}, {"busybox", "busybox"}} {
		t.Run(c.name, func(t *testing.T) {
			bin, err := exec.LookPath(c.bin)
			if err != nil {
				t.Skipf("%s not installed", c.bin)
			}
			dir := t.TempDir()
			if err := os.Symlink(bin, filepath.Join(dir, "awk")); err != nil {
				t.Fatal(err)
			}
			out, stderr, err := runScriptPath(t, "/bin/sh", root, scanParams(t, ModeFull), dir+":"+os.Getenv("PATH"))
			if err != nil {
				t.Fatalf("script: %v %s", err, stderr)
			}
			// The host times may differ by a second between the runs.
			norm := regexp.MustCompile(`"(started|ended)":-?[0-9]+`)
			if a, b := norm.ReplaceAll(out, nil), norm.ReplaceAll(ref, nil); !bytes.Equal(a, b) {
				t.Errorf("output with %s differs from the default awk:\n%.2000s\n---\n%.2000s", c.name, a, b)
			}
		})
	}
}

// TestScriptNeverReportsOutsideProfile:excluded and out-of-profile paths
// never appear, and nothing is read through a symlink.
func TestScriptNeverReportsOutsideProfile(t *testing.T) {
	root := buildTree(t, treeOpts{symlinkHome: true})
	res := runAndParse(t, "/bin/sh", root, ModeFull)
	for _, r := range res.Records {
		p := string(r.Path)
		for _, bad := range []string{"/__pycache__", "/modules.dep"} {
			if strings.Contains(p, bad) {
				t.Errorf("record %s is excluded", EscapePath(r.Path))
			}
		}
		for _, bad := range []string{"/etc/pve", "/etc/ld.so.cache", "/var/lib", "/tmp", "/proc", "/home/alice/notes.txt",
			"/root/.ssh/id_ed25519", "/home/carol", "/elsewhere", "/bin/", "/sbin/", "/lib/"} {
			if strings.HasPrefix(p, bad) {
				t.Errorf("record %s is outside the profile", EscapePath(r.Path))
			}
		}
	}
	findRecord(t, res, "/usr/lib/modules/6.1.0-18-amd64/kernel/modules.extra")
}

// TestScriptSymlinkedHomeIsPartial: a symlinked home directory is not
// followed; the files behind it are not scanned, so the run is partial.
func TestScriptSymlinkedHomeIsPartial(t *testing.T) {
	root := buildTree(t, treeOpts{symlinkHome: true})
	res := runAndParse(t, "/bin/sh", root, ModeFull)
	if res.Complete() || !slices.Contains(res.Partial, ReasonUnreadable) || res.Host.Unreadable != 1 {
		t.Fatalf("partial %v, host %+v", res.Partial, res.Host)
	}
	if len(res.Dropped) != 0 {
		t.Errorf("dropped %v", res.Dropped)
	}
}

// moveAndLink moves root/p to root/target and leaves a symlink to it at p.
func moveAndLink(t *testing.T, root, p, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, target)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, p), filepath.Join(root, target)); err != nil {
		t.Fatal(err)
	}
	relLink(t, root, target, p)
}

// relLink creates root/p as a relative symlink to root/target, so that it
// resolves inside the test tree.
func relLink(t *testing.T, root, target, p string) {
	t.Helper()
	rel, err := filepath.Rel(filepath.Dir(filepath.Join(root, p)), filepath.Join(root, target))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, filepath.Join(root, p)); err != nil {
		t.Fatal(err)
	}
}

// TestScriptNeverFollowsSymlinkedDirectories: a symlink in any component
// of a path is never followed: a symlinked Include directory, a symlinked
// /etc/ssh pointing outside /etc, a symlinked directory above a profile
// root. Nothing behind them is reported or shipped, and the run is partial.
func TestScriptNeverFollowsSymlinkedDirectories(t *testing.T) {
	const leak = "LEAKED-SECRET-CONTENT"
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, root string)
		check func(t *testing.T, res *Result)
	}{
		{"symlinked include directory", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "elsewhere/inc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "elsewhere/inc/leak.conf"), []byte(leak+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			relLink(t, root, "/elsewhere/inc", "/etc/ssh/linked.d")
			f, err := os.OpenFile(filepath.Join(root, "etc/ssh/sshd_config"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString("Include linked.d/*.conf\n"); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, res *Result) {
			if len(res.SSHConfig) != 3 {
				t.Errorf("ssh config files %d, want the 3 real ones", len(res.SSHConfig))
			}
		}},
		{"symlinked /etc/ssh", func(t *testing.T, root string) {
			moveAndLink(t, root, "etc/ssh", "/elsewhere/ssh")
			if err := os.WriteFile(filepath.Join(root, "elsewhere/ssh/sshd_config"), []byte(leak+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, res *Result) {
			if len(res.SSHConfig) != 0 {
				t.Errorf("ssh config read through a symlinked /etc/ssh: %d files", len(res.SSHConfig))
			}
		}},
		{"symlinked directory above a root", func(t *testing.T, root string) {
			moveAndLink(t, root, "var/spool/cron", "/elsewhere/cron")
		}, func(t *testing.T, res *Result) {
			if s := rootStates(res)["/var/spool/cron/crontabs"]; s != RootSkipped {
				t.Errorf("root behind a symlinked directory: state %v, want skipped", s)
			}
			for _, r := range res.Records {
				if strings.HasPrefix(string(r.Path), "/var/spool/cron/") {
					t.Errorf("record %s behind a symlink", EscapePath(r.Path))
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := buildTree(t, treeOpts{})
			c.setup(t, root)
			out, stderr, err := runScript(t, "/bin/sh", root, scanParams(t, ModeFull))
			if err != nil {
				t.Fatalf("script: %v %s", err, stderr)
			}
			res, err := Parse(context.Background(), bytes.NewReader(out), Options{Profile: DefaultProfile(), Mode: ModeFull, HostKey: scriptTestKey})
			if err != nil {
				t.Fatal(err)
			}
			if res.Complete() || res.Host.Unreadable == 0 {
				t.Errorf("run complete or nothing unreadable: partial %v, host %+v", res.Partial, res.Host)
			}
			for _, f := range res.SSHConfig {
				if bytes.Contains(f.Content, []byte(leak)) || !strings.HasPrefix(string(f.Path), "/etc/ssh/") {
					t.Errorf("ssh config %s read through a symlink", EscapePath(f.Path))
				}
			}
			for _, r := range res.Records {
				if strings.HasPrefix(string(r.Path), "/elsewhere") {
					t.Errorf("record %s behind a symlink", EscapePath(r.Path))
				}
			}
			c.check(t, res)
		})
	}
}

// TestScriptUnlistableHomeIsUnreadableNotMissing: SSH files below a home or
// .ssh directory the scan cannot search (mode 0700 of another user without
// sudo, NFS root_squash) are unknown: counted unreadable, the pattern is
// "error" when nothing else matched, never "missing" (RootAbsent). Needs an
// unprivileged user: root searches a mode 000 directory.
func TestScriptUnlistableHomeIsUnreadableNotMissing(t *testing.T) {
	root := buildTree(t, treeOpts{})
	locked := []string{filepath.Join(root, "root/.ssh"), filepath.Join(root, "home/dave")}
	if err := os.MkdirAll(locked[1], 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range locked {
		if err := os.Chmod(d, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, d := range locked {
			_ = os.Chmod(d, 0o755)
		}
	})
	res := runAndParse(t, "/bin/sh", root, ModeFull)
	states := rootStates(res)
	for p, s := range map[string]RootState{
		"/root/.ssh/authorized_keys*":   RootSkipped, // only /root/.ssh: unknown
		"/root/.ssh/known_hosts":        RootSkipped,
		"/root/.shosts":                 RootAbsent, // /root itself is searchable
		"/home/*/.ssh/authorized_keys*": RootScanned,
		"/home/*/.k5login":              RootScanned,
	} {
		if states[p] != s {
			t.Errorf("root %s: state %v, want %v", p, states[p], s)
		}
	}
	// /root: 3 .ssh patterns; /home/dave: all 6 patterns.
	if res.Complete() || !slices.Contains(res.Partial, ReasonUnreadable) || res.Host.Unreadable != 9 {
		t.Errorf("partial %v, host %+v", res.Partial, res.Host)
	}
}

// TestScriptUnreadableFileIsPartial: a file the scan cannot hash is
// reported by metadata, counted as unreadable, and the run is partial.
func TestScriptUnreadableFileIsPartial(t *testing.T) {
	if os.Geteuid() == 0 {
		// root reads a mode 000 file; the test needs an unprivileged user.
		t.Skip("running as root")
	}
	root := buildTree(t, treeOpts{unreadable: true})
	res := runAndParse(t, "/bin/sh", root, ModeFull)
	if r := findRecord(t, res, "/etc/secret"); r.Hash.Kind != HashNone || r.Mode != 0 {
		t.Errorf("/etc/secret %+v", r)
	}
	if res.Complete() || !slices.Contains(res.Partial, ReasonUnreadable) || res.Host.Unreadable != 1 {
		t.Fatalf("partial %v, host %+v", res.Partial, res.Host)
	}
}

// TestScriptIncrementalSkipsLargeFiles: an incremental run reports a file
// above 512 MiB by metadata only and is still complete; recent files and
// the SSH configuration are hashed.
func TestScriptIncrementalSkipsLargeFiles(t *testing.T) {
	root := buildTree(t, treeOpts{bigSparse: true})
	res := runAndParse(t, "/bin/sh", root, ModeIncremental)
	if !res.Complete() {
		t.Fatalf("partial %v, dropped %v, host %+v", res.Partial, res.Dropped, res.Host)
	}
	want, sums := expectedRecords(t, root)
	compareRecords(t, res, want, sums, map[string]bool{"/opt/big": true})
	if r := findRecord(t, res, "/opt/big"); r.Size != 600<<20 || r.Hash.Kind != HashNone {
		t.Errorf("/opt/big %+v", r)
	}
}

// runWith runs the script in mode with extra environment and PATH and
// parses the document.
func runWith(t *testing.T, root string, mode Mode, path string, env ...string) *Result {
	t.Helper()
	out, stderr, err := runScriptPath(t, "/bin/sh", root, scanParams(t, mode), path, env...)
	if err != nil {
		t.Fatalf("script: %v\nstderr: %s", err, stderr)
	}
	res, err := Parse(context.Background(), bytes.NewReader(out), Options{Profile: DefaultProfile(), Mode: mode, HostKey: scriptTestKey})
	if err != nil {
		t.Fatalf("parse: %v\ndocument: %.4000s", err, out)
	}
	return res
}

// TestScriptIncrementalWindow: an incremental run hashes only files whose
// ctime or mtime lies in the look-back window, plus /etc/ssh and /boot/efi.
// With a window of 0 minutes no file is recent, so every other file is
// reported by metadata only, and the run is still complete.
func TestScriptIncrementalWindow(t *testing.T) {
	root := buildTree(t, treeOpts{})
	res := runWith(t, root, ModeIncremental, os.Getenv("PATH"), "NEBULA_FIM_TEST_WINDOW=0")
	if !res.Complete() {
		t.Fatalf("partial %v, dropped %v, host %+v", res.Partial, res.Dropped, res.Host)
	}
	want, sums := expectedRecords(t, root)
	unhashed := map[string]bool{}
	for p := range sums {
		if !strings.HasPrefix(p, "/etc/ssh/") && !strings.HasPrefix(p, "/boot/efi/") {
			unhashed[p] = true
		}
	}
	compareRecords(t, res, want, sums, unhashed)
	if r := findRecord(t, res, "/etc/ssh/ssh_host_ed25519_key"); r.Hash.Kind == HashNone {
		t.Error("/etc/ssh is hashed in every incremental run")
	}
}

// hashedRecordsAreRight checks every hash in res against the file in the
// tree (zeros for the sparse files named in sparse) and returns the bytes
// hashed and the number of files left unhashed.
func hashedRecordsAreRight(t *testing.T, res *Result, root string, sparse map[string]bool) (hashed int64, unhashed int) {
	t.Helper()
	zero := map[int64][sha256.Size]byte{}
	for _, r := range res.Records {
		if r.Type != TypeFile {
			continue
		}
		if r.Hash.Kind == HashNone {
			unhashed++
			continue
		}
		p := string(r.Path)
		var sum [sha256.Size]byte
		if sparse[p] {
			if s, ok := zero[r.Size]; ok {
				sum = s
			} else {
				h := sha256.New()
				if _, err := io.CopyN(h, zeroReader{}, r.Size); err != nil {
					t.Fatal(err)
				}
				copy(sum[:], h.Sum(nil))
				zero[r.Size] = sum
			}
		} else {
			b, err := os.ReadFile(filepath.Join(root, p))
			if err != nil {
				t.Fatal(err)
			}
			sum = sha256.Sum256(b)
		}
		if want := sealHash(scriptTestKey, r.Path, sum); r.Hash != want {
			t.Errorf("%s: hash does not belong to the file", EscapePath(r.Path))
		}
		hashed += r.Size
	}
	return hashed, unhashed
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestScriptHashBudgetCapsBeforeReading: with a budget below the tree's
// size, the files too large for the budget are left out before sha256sum
// reads them: the hashed bytes stay within the budget (the SSH
// configuration aside), the run is truncated, and a file left out is not
// counted unreadable.
func TestScriptHashBudgetCapsBeforeReading(t *testing.T) {
	const budget = 64
	root := buildTree(t, treeOpts{})
	res := runWith(t, root, ModeFull, os.Getenv("PATH"), "NEBULA_FIM_TEST_HASH_BUDGET="+strconv.Itoa(budget))
	if !slices.Contains(res.Partial, ReasonHostTruncated) || res.Host.Unreadable != 0 {
		t.Fatalf("partial %v, host %+v", res.Partial, res.Host)
	}
	ssh := map[string]bool{}
	var sshBytes int64
	for _, f := range res.SSHConfig {
		ssh[string(f.Path)] = true
		sshBytes += int64(len(f.Content))
	}
	hashed, unhashed := hashedRecordsAreRight(t, res, root, nil)
	if hashed-sshBytes > budget || unhashed == 0 {
		t.Errorf("hashed %d bytes (%d of SSH configuration), %d files unhashed; budget %d", hashed, sshBytes, unhashed, budget)
	}
	if r := findRecord(t, res, "/etc/hostname"); r.Hash.Kind == HashNone {
		t.Error("a small file within the budget is not hashed")
	}
}

// pathWithout returns a PATH directory holding the tools the script uses,
// without the timeout tool.
func pathWithout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"sed", "awk", "od", "find", "sha256sum", "date", "id", "base64", "wc", "cat", "sleep", "nice", "ionice"} {
		bin, err := exec.LookPath(tool)
		if err != nil {
			if tool == "ionice" {
				continue
			}
			t.Fatalf("%s: %v", tool, err)
		}
		if err := os.Symlink(bin, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestScriptTimeBoundStopsHashing: hashing stops at the deadline with the
// timeout tool and, without it, with the watchdog; the run is truncated,
// no hash is attributed to the wrong file and the script returns well
// before it would have hashed everything.
func TestScriptTimeBoundStopsHashing(t *testing.T) {
	for _, c := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{"timeout", func(*testing.T) string { return os.Getenv("PATH") }},
		{"watchdog", pathWithout},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := buildTree(t, treeOpts{})
			sparse := map[string]bool{}
			// 7 GiB: within the 8 GiB budget, far more than 2 s of hashing.
			for i := range 7 {
				p := "/etc/big-" + strconv.Itoa(i)
				f, err := os.Create(filepath.Join(root, p))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(1 << 30); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				sparse[p] = true
			}
			path := c.path(t)
			if c.name == "watchdog" {
				if _, err := exec.LookPath(filepath.Join(path, "timeout")); err == nil {
					t.Fatal("timeout still on PATH")
				}
			}
			start := time.Now()
			res := runWith(t, root, ModeFull, path, "NEBULA_FIM_TEST_HASH_SECONDS=2")
			d := time.Since(start)
			if !slices.Contains(res.Partial, ReasonHostTruncated) {
				t.Errorf("run past the deadline not truncated: partial %v", res.Partial)
			}
			_, unhashed := hashedRecordsAreRight(t, res, root, sparse)
			bigUnhashed := 0
			for p := range sparse {
				if findRecord(t, res, p).Hash.Kind == HashNone {
					bigUnhashed++
				}
			}
			if unhashed == 0 || bigUnhashed == 0 {
				t.Errorf("%d files, %d large files unhashed despite the deadline", unhashed, bigUnhashed)
			}
			// Hashing ran until it was stopped (at least one second), and
			// the script returned soon after.
			if d < time.Second || d > time.Minute {
				t.Errorf("script ran %v", d)
			}
		})
	}
}

// TestScriptLeavesTreeUnchanged: the scan changes nothing in the tree it
// reads (no file created, removed or modified; access times aside).
func TestScriptLeavesTreeUnchanged(t *testing.T) {
	root := buildTree(t, treeOpts{})
	snapshot := func() map[string]string {
		m := map[string]string{}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			var st syscall.Stat_t
			if err := syscall.Lstat(p, &st); err != nil {
				return err
			}
			m[p] = strings.Join([]string{
				i64(int64(st.Mode)), i64(st.Size), i64(int64(st.Ino)), i64(st.Mtim.Sec), i64(st.Mtim.Nsec), i64(st.Ctim.Sec), i64(st.Ctim.Nsec),
			}, "/")
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	before := snapshot()
	runAndParse(t, "/bin/sh", root, ModeFull)
	after := snapshot()
	if len(before) != len(after) {
		t.Fatalf("tree has %d entries after the scan, %d before", len(after), len(before))
	}
	for p, v := range before {
		if after[p] != v {
			t.Errorf("%s changed", EscapePath([]byte(p)))
		}
	}
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }

// TestScriptRejectsBadParameters: anything but the canonical parameters of
// the contract stops the script before it reads a file.
func TestScriptRejectsBadParameters(t *testing.T) {
	root := buildTree(t, treeOpts{})
	for _, p := range []string{
		`{"mode":"weekly","profile":"fim-default-v1"}`,
		`{"mode":"full","profile":"fim-other-v1"}`,
		`{"profile":"fim-default-v1","mode":"full"}`,
		`{"mode":"full","profile":"fim-default-v1","path":"/"}`,
		`{"mode":"full"}`,
		``,
	} {
		out, _, err := runScript(t, "/bin/sh", root, []byte(p))
		if err == nil || len(out) != 0 {
			t.Errorf("params %q: err %v, %d bytes of output", p, err, len(out))
		}
	}
}

// splitScript returns the shell part and the awk program of the script.
func splitScript(t *testing.T) (shell, awk string) {
	t.Helper()
	s := string(Script)
	i := strings.Index(s, "| awk -v mode=")
	if i < 0 {
		t.Fatal("awk program not found")
	}
	return s[:i], s[i:]
}

// runAwk feeds stream, a hand-made producer stream, through the script's
// own od | awk stage in full mode and parses the document.
func runAwk(t *testing.T, stream string) *Result {
	t.Helper()
	_, awk := splitScript(t)
	cmd := exec.Command("/bin/sh", "-c", "od -An -v -tx1 "+awk)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "MODE=full"}
	cmd.Stdin = strings.NewReader(stream)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("awk: %v", err)
	}
	res, err := Parse(context.Background(), bytes.NewReader(out), Options{Profile: DefaultProfile(), Mode: ModeFull, HostKey: scriptTestKey})
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	return res
}

// TestScriptCutHashStreamNeverMisattributes: a hash pass killed by the
// time bound may end in a record cut mid-path ("/etc/a" of "/etc/abc").
// The '\0T\0' marker ends that fragment as its own field and its hash is
// dropped, so it never lands on another file; a complete record before
// the marker keeps its hash, and an earlier hash of the same path is kept.
func TestScriptCutHashStreamNeverMisattributes(t *testing.T) {
	hA := strings.Repeat("a", 64)
	hB := strings.Repeat("b", 64)
	hC := strings.Repeat("c", 64)
	meta := func(p string, ino int) string {
		return "M1 f 1 644 0 0 " + strconv.Itoa(ino) + " 1700000000.5 1700000000.5\x00" + p + "\x00\x00"
	}
	head := "B1700000000\x00Rscanned /etc\x00"
	tail := meta("/etc/a", 1) + meta("/etc/ab", 2) + "E1700000001\x00"
	for _, c := range []struct {
		name   string
		hashes string
		want   map[string]string // path -> plain hex, "" for no hash
	}{
		{"fragment after complete record", hB + "  /etc/ab\x00" + hA + "  /etc/a" + "\x00T\x00",
			map[string]string{"/etc/a": "", "/etc/ab": hB}},
		{"fragment cut in the hash", hB + "  /etc/ab\x00" + hA[:20] + "\x00T\x00",
			map[string]string{"/etc/a": "", "/etc/ab": hB}},
		{"complete record before marker", hB + "  /etc/ab\x00" + hA + "  /etc/a\x00" + "\x00T\x00",
			map[string]string{"/etc/a": hA, "/etc/ab": hB}},
		{"fragment over an earlier hash", hC + "  /etc/a\x00" + hB + "  /etc/ab\x00" + hA + "  /etc/a" + "\x00T\x00",
			map[string]string{"/etc/a": hC, "/etc/ab": hB}},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := runAwk(t, head+c.hashes+tail)
			if !slices.Contains(res.Partial, ReasonHostTruncated) {
				t.Error("cut hash pass not reported as truncated")
			}
			for p, h := range c.want {
				want := Hash{}
				if h != "" {
					want = sealHash(scriptTestKey, []byte(p), mustHex(t, h))
				}
				if got := findRecord(t, res, p).Hash; got != want {
					t.Errorf("%s: hash %+v, want %+v", p, got, want)
				}
			}
		})
	}
}

// TestScriptIsReadOnly: the script text has no write operation: no output
// redirection except to /dev/null and stderr, no here-document, no file
// changing command, one -exec (the hash tool) and an awk program that
// neither runs commands nor writes files.
func TestScriptIsReadOnly(t *testing.T) {
	shell, awk := splitScript(t)
	var code []string
	for _, line := range strings.Split(shell, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
			code = append(code, line)
		}
	}
	body := strings.Join(code, "\n")
	redir := regexp.MustCompile(`[0-9]?>{1,2}\s*([^\s);]*)`)
	for _, m := range redir.FindAllStringSubmatch(body, -1) {
		if m[1] != "/dev/null" && m[1] != "&1" && m[1] != "&2" {
			t.Errorf("write redirection %q", m[0])
		}
	}
	for _, re := range []string{
		`<<`, `\brm\b`, `\bmv\b`, `\bcp\b`, `\btouch\b`, `\bmkdir\b`, `\btee\b`, `\bdd\b`, `\bln\b`, `\bchmod\b`, `\bchown\b`,
		`\btruncate\b`, `\binstall\b`, `\bmktemp\b`, `\bmkfifo\b`, `-delete\b`, `-fprint`, `-fls\b`, `-ok\b`, `-execdir\b`, `\beval\b`,
		`\bcurl\b`, `\bwget\b`, `\bnc\b`, `(^|[\s;|&(])ssh\s`, `\bapt`, `\bdpkg\b`, `/dev/tcp`,
	} {
		if regexp.MustCompile(re).MatchString(body) {
			t.Errorf("script uses %s", re)
		}
	}
	if n := strings.Count(body, "-exec"); n != 1 || !strings.Contains(body, "-exec sha256sum -z -- \"{}\" +") {
		t.Errorf("script has %d -exec, want exactly the sha256sum one", n)
	}
	for _, bad := range []string{"system(", "getline", "close(", `> "`, `>"`, `>> `, `| "`, `|"`} {
		if strings.Contains(awk, bad) {
			t.Errorf("awk program uses %q", bad)
		}
	}
}

// TestScriptRootsMatchProfile: the script's root list and home files are
// exactly DefaultProfile, in the same order, and /etc/pve is not a root.
func TestScriptRootsMatchProfile(t *testing.T) {
	shell, _ := splitScript(t)
	lit := regexp.MustCompile(`(?m)^LITERAL_ROOTS="([^"]*)"$`).FindStringSubmatch(shell)
	hf := regexp.MustCompile(`(?m)^HOME_FILES="([^"]*)"$`).FindStringSubmatch(shell)
	if lit == nil || hf == nil {
		t.Fatal("root lists not found in the script")
	}
	var got []string
	got = append(got, strings.Fields(lit[1])...)
	for _, base := range []string{"/root", "/home/*"} {
		for _, rel := range strings.Fields(hf[1]) {
			got = append(got, base+"/"+rel)
		}
	}
	var want []string
	for _, r := range DefaultProfile().Roots {
		want = append(want, r.Pattern)
		if strings.HasPrefix(r.Pattern, "/etc/pve") || strings.HasPrefix(r.Pattern, "/var/lib") {
			t.Errorf("profile root %s is excluded by Q1", r.Pattern)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("script roots %q\nprofile roots %q", got, want)
	}
	if err := DefaultProfile().validate(); err != nil {
		t.Fatal(err)
	}
	var optional []string
	for _, r := range DefaultProfile().Roots {
		if r.Optional && !strings.HasPrefix(r.Pattern, "/root/") && !strings.HasPrefix(r.Pattern, "/home/") {
			optional = append(optional, r.Pattern)
		}
	}
	if want := []string{"/etc/systemd/user", "/boot/efi", "/usr/libexec", "/opt", "/var/spool/cron/crontabs"}; !slices.Equal(optional, want) {
		t.Errorf("optional roots %q, want %q", optional, want)
	}
}

// TestScriptSyntax: the script passes sh -n, bash -n, dash -n and
// shellcheck (each skipped when not installed, as in internal/enrollscript).
func TestScriptSyntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fim_scan.sh")
	if err := os.WriteFile(path, Script, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		bin  string
		args []string
	}{
		{"sh", []string{"-n"}},
		{"bash", []string{"-n"}},
		{"dash", []string{"-n"}},
		{"shellcheck", []string{"-s", "sh", "-S", "style"}},
	} {
		t.Run(c.bin, func(t *testing.T) {
			bin, err := exec.LookPath(c.bin)
			if err != nil {
				t.Skipf("%s not installed", c.bin)
			}
			out, err := exec.Command(bin, append(append([]string(nil), c.args...), path)...).CombinedOutput()
			if err != nil {
				t.Errorf("%s: %v\n%s", c.bin, err, out)
			}
		})
	}
}

// TestActionContract: fim.scan is a LOW, read-only, safely retried action
// with exactly the mode and profile parameters and the embedded script.
func TestActionContract(t *testing.T) {
	a := Action()
	if a.ID != "fim.scan" || !a.ReadOnly || a.Durable || a.Risk != pb.RiskClass_RISK_CLASS_LOW || a.Retry != "safe" ||
		!bytes.Equal(a.Script, Script) || len(a.Secrets) != 0 || a.Timeout <= 30*time.Minute {
		t.Fatalf("contract %+v", a)
	}
	if err := a.ValidParams(map[string]string{"mode": "full", "profile": DefaultProfileID}); err != nil {
		t.Error(err)
	}
	if err := a.ValidParams(map[string]string{"mode": "incremental", "profile": DefaultProfileID}); err != nil {
		t.Error(err)
	}
	for _, p := range []map[string]string{
		{"mode": "weekly", "profile": DefaultProfileID},
		{"mode": "full", "profile": "fim-other-v1"},
		{"mode": "full"},
		{"mode": "full", "profile": DefaultProfileID, "path": "/"},
		{"mode": "full\n", "profile": DefaultProfileID},
	} {
		if err := a.ValidParams(p); err == nil {
			t.Errorf("params %q accepted", p)
		}
	}
	if !strings.Contains(string(Script), "WIN=1560") || LookBack != 1560*time.Minute {
		t.Error("look-back window of script and LookBack differ")
	}
}
