// SPDX-License-Identifier: AGPL-3.0-or-later

package integrity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

func TestCleanTreeIsCompleteAndClean(t *testing.T) {
	f := newFixture(t, defaultTree())
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.Incomplete != "" || !r.Clean() {
		t.Fatalf("report not clean: %+v", r)
	}
	if len(r.Files) != len(f.installed) {
		t.Fatalf("got %d results, want %d", len(r.Files), len(f.installed))
	}
	for _, fr := range r.Files {
		if fr.Status != StatusOK || fr.Reason != "" {
			t.Errorf("%s: %s %s", fr.Path, fr.Status, fr.Reason)
		}
	}
	if r.ReleaseVersion != testVersion || r.Flavour != testFlavour || r.ManifestDigest != hexSum(f.manifest) || r.ListDigest != hexSum(f.list) {
		t.Fatalf("report identity %+v", r)
	}
	var want int64
	for _, tf := range f.installed {
		want += int64(len(tf.data))
	}
	if r.BytesHashed != want {
		t.Fatalf("hashed %d bytes, want %d", r.BytesHashed, want)
	}
}

func TestResultsCarryADR0015D4Class(t *testing.T) {
	f := newFixture(t, defaultTree())
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Class{
		"/usr/bin/nebula":                                  ClassBinary,
		"/usr/bin/nebula-server":                           ClassBinary,
		"/lib/systemd/system/nebula-server.service":        ClassUnit,
		"/usr/lib/systemd/system/nebula-executor.service":  ClassUnit,
		"/usr/share/nebula/release/builtins.tar":           ClassModule,
		"/usr/share/nebula/release/rootkeys.txt":           ClassRootKey,
		"/usr/share/nebula/web/app.css":                    ClassWebAsset,
		"/usr/share/doc/nebula-operation-station/guide.md": ClassCode,
	}
	for p, c := range want {
		if got := resultFor(t, r, p).Class; got != c {
			t.Errorf("%s: class %s, want %s", p, got, c)
		}
	}
}

func TestClassifyPaths(t *testing.T) {
	cases := []struct {
		path  string
		class Class
		locks bool
	}{
		{"/usr/bin/nebula-executor", ClassBinary, true},
		{"/lib/systemd/system/nebula-executor.service", ClassUnit, true},
		{"/usr/lib/systemd/system/nebula-server.service.d/10-pkg.conf", ClassUnit, true},
		{"/etc/systemd/system/nebula-server.service", ClassUnit, true},
		{"/usr/share/nebula/release/builtins.tar", ClassModule, true},
		{"/usr/share/nebula/modules/docker/1.2.0/actions/restart.sh", ClassModule, true},
		{"/usr/lib/nebula/modules/docker/module.lock.json", ClassModule, true},
		{"/usr/share/nebula/release/rootkeys.txt", ClassRootKey, true},
		{"/usr/share/nebula/release/root-rotation-2.json", ClassRootKey, true},
		{"/usr/share/nebula/web/app.js", ClassWebAsset, false},
		{"/usr/lib/nebula/web/static/app.css", ClassWebAsset, false},
		{"/usr/share/nebula/templates/index.html", ClassWebAsset, false},
		{"/usr/share/nebula/deploy/install.sh", ClassCode, true},
		{"/usr/share/doc/nebula-operation-station/guide.md", ClassCode, true},
		// Look-alike prefixes are not web assets: fail towards locking.
		{"/usr/share/nebula/webx/app.js", ClassCode, true},
		{"/usr/share/nebula/web", ClassCode, true},
	}
	for _, c := range cases {
		got := Classify(c.path)
		if got != c.class || got.Locks() != c.locks {
			t.Errorf("Classify(%s) = %s (locks %v), want %s (locks %v)", c.path, got, got.Locks(), c.class, c.locks)
		}
	}
}

func TestCheckReportsDeviations(t *testing.T) {
	type mutation func(t *testing.T, f *fixture)
	cases := []struct {
		name   string
		mutate mutation
		path   string
		status Status
		reason Reason
	}{
		{"same size other bytes", func(t *testing.T, f *fixture) {
			writeFile(t, f.path("/usr/bin/nebula-server"), "SERVER binary", 0o755)
		}, "/usr/bin/nebula-server", StatusDifferent, ReasonSHA256},
		{"size differs", func(t *testing.T, f *fixture) {
			writeFile(t, f.path("/usr/bin/nebula-executor"), "executor binary plus", 0o755)
		}, "/usr/bin/nebula-executor", StatusDifferent, ReasonSize},
		{"setuid bit added", func(t *testing.T, f *fixture) {
			chmod(t, f.path("/usr/bin/nebula-executor"), 0o755|os.ModeSetuid)
		}, "/usr/bin/nebula-executor", StatusDifferent, ReasonMode},
		{"world writable unit", func(t *testing.T, f *fixture) {
			chmod(t, f.path("/usr/lib/systemd/system/nebula-executor.service"), 0o666)
		}, "/usr/lib/systemd/system/nebula-executor.service", StatusDifferent, ReasonMode},
		{"file removed", func(t *testing.T, f *fixture) {
			remove(t, f.path("/usr/share/nebula/web/app.css"))
		}, "/usr/share/nebula/web/app.css", StatusMissing, ""},
		{"parent directory removed", func(t *testing.T, f *fixture) {
			if err := os.RemoveAll(f.path("/usr/share/doc")); err != nil {
				t.Fatal(err)
			}
		}, "/usr/share/doc/nebula-operation-station/guide.md", StatusMissing, ""},
		{"file replaced by symlink to identical copy", func(t *testing.T, f *fixture) {
			p := f.path("/usr/bin/nebula-server")
			writeFile(t, f.path("/copy"), "server binary", 0o755)
			remove(t, p)
			symlink(t, filepath.Join(f.root, "copy"), p)
		}, "/usr/bin/nebula-server", StatusDifferent, ReasonType},
		{"file replaced by directory", func(t *testing.T, f *fixture) {
			p := f.path("/usr/share/nebula/web/app.css")
			remove(t, p)
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "/usr/share/nebula/web/app.css", StatusDifferent, ReasonType},
		{"file replaced by fifo", func(t *testing.T, f *fixture) {
			p := f.path("/usr/share/nebula/web/app.css")
			remove(t, p)
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "/usr/share/nebula/web/app.css", StatusDifferent, ReasonType},
		{"listed symlink retargeted", func(t *testing.T, f *fixture) {
			p := f.path("/usr/bin/nebula")
			remove(t, p)
			symlink(t, "nebula-executor", p)
		}, "/usr/bin/nebula", StatusDifferent, ReasonTarget},
		{"listed symlink replaced by file", func(t *testing.T, f *fixture) {
			p := f.path("/usr/bin/nebula")
			remove(t, p)
			writeFile(t, p, "server binary", 0o755)
		}, "/usr/bin/nebula", StatusDifferent, ReasonType},
		{"listed symlink removed", func(t *testing.T, f *fixture) {
			remove(t, f.path("/usr/bin/nebula"))
		}, "/usr/bin/nebula", StatusMissing, ""},
		{"parent directory replaced by symlink to identical copy", func(t *testing.T, f *fixture) {
			web := f.path("/usr/share/nebula/web")
			if err := os.Rename(web, f.path("/webcopy")); err != nil {
				t.Fatal(err)
			}
			symlink(t, f.path("/webcopy"), web)
		}, "/usr/share/nebula/web/app.css", StatusDifferent, ReasonParent},
		{"parent component is a file", func(t *testing.T, f *fixture) {
			web := f.path("/usr/share/nebula/web")
			if err := os.RemoveAll(web); err != nil {
				t.Fatal(err)
			}
			writeFile(t, web, "x", 0o644)
		}, "/usr/share/nebula/web/app.css", StatusDifferent, ReasonParent},
		{"merged-usr /lib link points elsewhere", func(t *testing.T, f *fixture) {
			if err := os.MkdirAll(f.path("/evil/systemd/system"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, f.path("/evil/systemd/system/nebula-server.service"), "[Unit]\n", 0o644)
			remove(t, f.path("/lib"))
			symlink(t, "evil", f.path("/lib"))
		}, "/lib/systemd/system/nebula-server.service", StatusDifferent, ReasonParent},
		// An absolute /lib -> /usr/lib link resolves under Options.Root,
		// never on the host filesystem.
		{"merged-usr /lib link is absolute", func(t *testing.T, f *fixture) {
			remove(t, f.path("/lib"))
			symlink(t, "/usr/lib", f.path("/lib"))
		}, "/lib/systemd/system/nebula-server.service", StatusOK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, defaultTree())
			c.mutate(t, f)
			r, err := Check(context.Background(), f.ref, f.opts())
			if err != nil {
				t.Fatal(err)
			}
			got := resultFor(t, r, c.path)
			if got.Status != c.status || got.Reason != c.reason {
				t.Fatalf("%s: %s/%s, want %s/%s", c.path, got.Status, got.Reason, c.status, c.reason)
			}
			if !r.Complete {
				t.Fatalf("a deviation must not make the run incomplete: %+v", r)
			}
			if r.Clean() != (c.status == StatusOK) {
				t.Fatalf("Clean() = %v with %s", r.Clean(), got.Status)
			}
			for _, fr := range r.Files {
				if fr.Path != c.path && fr.Status != StatusOK {
					t.Errorf("unrelated %s: %s/%s", fr.Path, fr.Status, fr.Reason)
				}
			}
		})
	}
}

func TestUnreadableFileIsReportedNotClean(t *testing.T) {
	if os.Geteuid() == 0 {
		// root opens a mode 000 file; the test needs an unprivileged user.
		t.Skip("running as root")
	}
	f := newFixture(t, defaultTree())
	chmod(t, f.path("/usr/share/nebula/release/builtins.tar"), 0)
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	got := resultFor(t, r, "/usr/share/nebula/release/builtins.tar")
	if got.Status != StatusUnreadable || got.Reason != ReasonOpen {
		t.Fatalf("got %s/%s", got.Status, got.Reason)
	}
	if r.Clean() {
		t.Fatal("an unreadable file must never be clean")
	}
}

func TestOwnerIsChecked(t *testing.T) {
	f := newFixture(t, defaultTree())
	o := f.opts()
	o.Owners = func(string) (uint32, uint32, error) { return uint32(os.Getuid()) + 1, uint32(os.Getgid()), nil }
	r, err := Check(context.Background(), f.ref, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, fr := range r.Files {
		if fr.Status != StatusDifferent || fr.Reason != ReasonOwner {
			t.Errorf("%s: %s/%s, want different/owner", fr.Path, fr.Status, fr.Reason)
		}
	}

	o.Owners = func(string) (uint32, uint32, error) { return 0, 0, errors.New("no such user") }
	r, err = Check(context.Background(), f.ref, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, fr := range r.Files {
		if fr.Status != StatusUnreadable || fr.Reason != ReasonOwnerUnknown {
			t.Errorf("%s: %s/%s, want unreadable/owner-unknown", fr.Path, fr.Status, fr.Reason)
		}
	}
	if r.Clean() {
		t.Fatal("unresolvable owners must not be clean")
	}
}

func TestDefaultOwnersResolveRootWithoutLookup(t *testing.T) {
	uid, gid, err := lookupOwner("root:root")
	if err != nil || uid != 0 || gid != 0 {
		t.Fatalf("root:root = %d:%d, %v", uid, gid, err)
	}
	for _, bad := range []string{"", "root", ":root", "root:", "root:root:root"} {
		if _, _, err := lookupOwner(bad); err == nil {
			t.Errorf("lookupOwner(%q) accepted", bad)
		}
	}
}

func TestUnlistedExecutableUnderUsrBinIsExtra(t *testing.T) {
	f := newFixture(t, defaultTree())
	writeFile(t, f.path("/usr/bin/nebula-backdoor"), "x", 0o755)
	symlink(t, "nebula-server", f.path("/usr/bin/nebulax"))
	writeFile(t, f.path("/usr/bin/other-tool"), "x", 0o755)
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/usr/bin/nebula-backdoor", "/usr/bin/nebulax"} {
		got := resultFor(t, r, p)
		if got.Status != StatusExtra || got.Class != ClassBinary || !got.Class.Locks() {
			t.Errorf("%s: %+v", p, got)
		}
	}
	for _, fr := range r.Files {
		if fr.Path == "/usr/bin/other-tool" {
			t.Fatal("non-NOS binaries are not NOS files")
		}
	}
	if r.Clean() {
		t.Fatal("an extra NOS binary must not be clean")
	}
}

func TestExtraNamesWithUnsafeBytesAreEscaped(t *testing.T) {
	f := newFixture(t, defaultTree())
	writeFile(t, f.path("/usr/bin/nebula-\x1b[31mevil\n"), "x", 0o755)
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, fr := range r.Files {
		if fr.Status == StatusExtra {
			found = true
			if strings.ContainsAny(fr.Path, "\x1b\n") || fr.Path != `/usr/bin/nebula-\x1b[31mevil\n` {
				t.Fatalf("unsafe name not escaped: %q", fr.Path)
			}
		}
	}
	if !found {
		t.Fatal("extra binary not reported")
	}
}

func TestLimitsMakeTheRunIncomplete(t *testing.T) {
	cases := []struct {
		name   string
		opts   func(*Options)
		ctx    func() context.Context
		reason Incomplete
	}{
		{"file limit", func(o *Options) { o.MaxFiles = 3 }, context.Background, IncompleteFiles},
		{"byte budget", func(o *Options) { o.MaxBytes = 20 }, context.Background, IncompleteBytes},
		{"time budget", func(o *Options) {
			c := &fakeClock{now: time.Unix(1_800_000_000, 0), step: time.Second}
			o.Now, o.Budget = c.Now, 4*time.Second
		}, context.Background, IncompleteTime},
		{"canceled", func(*Options) {}, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, IncompleteCanceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, defaultTree())
			o := f.opts()
			c.opts(&o)
			r, err := Check(c.ctx(), f.ref, o)
			if err != nil {
				t.Fatal(err)
			}
			if r.Complete || r.Incomplete != c.reason || r.Clean() {
				t.Fatalf("complete %v reason %q clean %v, want incomplete %q", r.Complete, r.Incomplete, r.Clean(), c.reason)
			}
			if len(r.Files) != len(f.installed) {
				t.Fatalf("every listed file needs a result, got %d", len(r.Files))
			}
			var notChecked int
			for _, fr := range r.Files {
				if fr.Status == StatusNotChecked {
					notChecked++
				}
			}
			if notChecked == 0 {
				t.Fatal("an incomplete run must mark unchecked files")
			}
			if o.MaxBytes > 0 && r.BytesHashed > o.MaxBytes {
				t.Fatalf("hashed %d bytes over budget %d", r.BytesHashed, o.MaxBytes)
			}
		})
	}
}

func TestOptionsAboveHardLimitsAreRejected(t *testing.T) {
	f := newFixture(t, defaultTree())
	cases := []func(*Options){
		func(o *Options) { o.MaxFiles = MaxFiles + 1 },
		func(o *Options) { o.MaxFiles = -1 },
		func(o *Options) { o.MaxBytes = MaxBytes + 1 },
		func(o *Options) { o.MaxBytes = -1 },
		func(o *Options) { o.Budget = MaxBudget + time.Second },
		func(o *Options) { o.Budget = -time.Second },
		func(o *Options) { o.Root = "relative/root" },
	}
	for i, mut := range cases {
		o := f.opts()
		mut(&o)
		if _, err := Check(context.Background(), f.ref, o); !errors.Is(err, ErrOptions) {
			t.Errorf("case %d: err %v, want ErrOptions", i, err)
		}
	}
}

func TestCheckNeedsAnAdmittedReference(t *testing.T) {
	f := newFixture(t, defaultTree())
	if _, err := Check(context.Background(), Reference{}, f.opts()); !errors.Is(err, ErrNoReference) {
		t.Fatalf("zero reference: %v", err)
	}
	o := f.opts()
	o.Flavour = "tarball:amd64"
	if _, err := Check(context.Background(), f.ref, o); !errors.Is(err, ErrFlavour) {
		t.Fatalf("unknown flavour: %v", err)
	}
	o = f.opts()
	o.Root = filepath.Join(f.root, "does-not-exist")
	if _, err := Check(context.Background(), f.ref, o); err == nil {
		t.Fatal("missing root accepted")
	}
}

func TestAdmitAcceptsOnlyTheSignedListOfTheRunningVersion(t *testing.T) {
	f := newFixture(t, defaultTree())
	other := newTestSK(t)
	otherMan, otherSig := signedRelease(t, other, testVersion, f.list)
	v2List := bytes.Replace(f.list, []byte(`"`+testVersion+`"`), []byte(`"1.5.0"`), 1)
	v2Man, v2Sig := signedRelease(t, f.k, "1.5.0", v2List)
	tampered := bytes.Replace(f.list, []byte(`"0755"`), []byte(`"4755"`), 1)
	if bytes.Equal(tampered, f.list) {
		t.Fatal("tamper did not change the list")
	}
	state := f.k.state(t)

	cases := []struct {
		name                string
		state               release.RootState
		version             string
		manifest, sig, list []byte
		wantErr             error
	}{
		{"signed by an untrusted key", state, testVersion, otherMan, otherSig, f.list, nil},
		{"signature of another document", state, testVersion, f.manifest, otherSig, f.list, nil},
		{"no signature", state, testVersion, f.manifest, nil, f.list, nil},
		{"list changed after signing", state, testVersion, f.manifest, f.sig, tampered, release.ErrInstalledFiles},
		{"list of another release", state, testVersion, f.manifest, f.sig, v2List, release.ErrInstalledFiles},
		{"validly signed list of another version", state, testVersion, v2Man, v2Sig, v2List, ErrVersion},
		{"running version not SemVer", state, "dev", f.manifest, f.sig, f.list, ErrVersion},
		{"empty root state", release.RootState{}, testVersion, f.manifest, f.sig, f.list, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := Admit(c.state, c.version, c.manifest, c.sig, c.list)
			if err == nil {
				t.Fatalf("admitted: %+v", ref)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("err %v, want %v", err, c.wantErr)
			}
			if _, err := Check(context.Background(), ref, f.opts()); !errors.Is(err, ErrNoReference) {
				t.Fatalf("rejected reference still usable: %v", err)
			}
		})
	}

	// The accepted case exposes what was admitted.
	if f.ref.ReleaseVersion() != testVersion || f.ref.ManifestDigest() != hexSum(f.manifest) || f.ref.ListDigest() != hexSum(f.list) || f.ref.SignedBy() != "root-1" {
		t.Fatalf("reference %+v", f.ref)
	}
}

func TestLargeFileIsHashedCompletely(t *testing.T) {
	big := strings.Repeat("0123456789abcdef", 64<<10) // 1 MiB, several read chunks
	tree := append(defaultTree(), treeFile{path: "/usr/share/nebula/release/big.bin", data: big, mode: 0o644})
	f := newFixture(t, tree)
	r, err := Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Clean() {
		t.Fatalf("not clean: %+v", r)
	}
	// Flip one byte near the end.
	writeFile(t, f.path("/usr/share/nebula/release/big.bin"), big[:len(big)-1]+"X", 0o644)
	r, err = Check(context.Background(), f.ref, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, r, "/usr/share/nebula/release/big.bin"); got.Status != StatusDifferent || got.Reason != ReasonSHA256 {
		t.Fatalf("got %+v", got)
	}
}

func TestStatusAndReasonStringsAreFixed(t *testing.T) {
	for _, s := range []fmt.Stringer{StatusOK, StatusDifferent, StatusMissing, StatusUnreadable, StatusExtra, StatusNotChecked} {
		if s.String() == "" {
			t.Errorf("empty status string")
		}
	}
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}
