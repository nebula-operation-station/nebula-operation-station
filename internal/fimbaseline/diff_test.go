// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

func mustDiff(t testing.TB, b *Baseline, scan *fimscan.Result, opts Options) *Report {
	t.Helper()
	rep, err := Diff(b, scan, opts)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return rep
}

func with(r fimscan.Record, f func(*fimscan.Record)) fimscan.Record {
	r = cloneRecord(r)
	f(&r)
	return r
}

func TestDiffKinds(t *testing.T) {
	motd := file("/etc/motd", 1)
	link := symlink("/etc/localtime", "/usr/share/zoneinfo/UTC")
	unhashed := with(motd, func(r *fimscan.Record) { r.Hash = fimscan.Hash{} })
	base := mustBaseline(t, result(dir("/etc"), motd, link))
	tests := []struct {
		name     string
		scan     []fimscan.Record
		wantPath string
		kind     Kind
		changes  Change
	}{
		{"added", []fimscan.Record{dir("/etc"), motd, link, file("/etc/new", 1)}, "/etc/new", KindAdded, 0},
		{"added unhashed", []fimscan.Record{dir("/etc"), motd, link, with(file("/etc/new", 1), func(r *fimscan.Record) { r.Hash = fimscan.Hash{} })}, "/etc/new", KindAdded, ChangeNotHashed},
		{"removed", []fimscan.Record{dir("/etc"), link}, "/etc/motd", KindRemoved, 0},
		{"content", []fimscan.Record{dir("/etc"), file("/etc/motd", 2), link}, "/etc/motd", KindChanged, ChangeContent},
		{"mode", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.Mode = 0o600 }), link}, "/etc/motd", KindChanged, ChangeMode},
		{"owner uid", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.UID = 1000 }), link}, "/etc/motd", KindChanged, ChangeOwner},
		{"owner gid", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.GID = 4 }), link}, "/etc/motd", KindChanged, ChangeOwner},
		{"type", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.Type = fimscan.TypeOther; r.Hash = fimscan.Hash{} }), link}, "/etc/motd", KindChanged, ChangeType},
		{"type to symlink", []fimscan.Record{dir("/etc"), with(symlink("/etc/motd", "/x"), func(r *fimscan.Record) { r.Size = 10; r.Mode = 0o644; r.Inode = 100 }), link}, "/etc/motd", KindChanged, ChangeType | ChangeLink},
		{"link target", []fimscan.Record{dir("/etc"), motd, symlink("/etc/localtime", "/usr/share/zoneinfo/CET")}, "/etc/localtime", KindChanged, ChangeLink},
		{"size", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.Size = 11 }), link}, "/etc/motd", KindChanged, ChangeSize},
		{"inode", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.Inode = 7 }), link}, "/etc/motd", KindChanged, ChangeInode},
		{"times", []fimscan.Record{dir("/etc"), with(motd, func(r *fimscan.Record) { r.Ctime = 2000 }), link}, "/etc/motd", KindChanged, ChangeTimes},
		{"not hashed metadata", []fimscan.Record{dir("/etc"), with(unhashed, func(r *fimscan.Record) { r.Mtime = 2000 }), link}, "/etc/motd", KindChanged, ChangeTimes | ChangeNotHashed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustDiff(t, base, result(tc.scan...), usable())
			if len(rep.Deviations) != 1 {
				t.Fatalf("%d deviations: %+v", len(rep.Deviations), rep.Deviations)
			}
			d := rep.Deviations[0]
			if string(d.Path) != tc.wantPath || d.Kind != tc.kind || d.Changes != tc.changes {
				t.Fatalf("got %s %v %b, want %s %v %b", d.Path, d.Kind, d.Changes, tc.wantPath, tc.kind, tc.changes)
			}
			if (d.Old == nil) != (tc.kind == KindAdded) || (d.New == nil) != (tc.kind == KindRemoved) {
				t.Fatalf("old/new presence wrong for %v", d.Kind)
			}
			if d.Class != ClassNormal {
				t.Fatalf("class %v, want normal", d.Class)
			}
		})
	}
}

func TestDiffUnchanged(t *testing.T) {
	recs := []fimscan.Record{dir("/etc"), file("/etc/passwd", 1), symlink("/etc/l", "x")}
	b := mustBaseline(t, result(recs...))
	if rep := mustDiff(t, b, result(recs...), Options{}); len(rep.Deviations) != 0 || !rep.Complete {
		t.Fatalf("unchanged scan: %+v", rep)
	}
	// An incremental run that did not hash an unchanged file is no deviation.
	unhashed := with(recs[1], func(r *fimscan.Record) { r.Hash = fimscan.Hash{} })
	if rep := mustDiff(t, b, result(recs[0], unhashed, recs[2]), Options{}); len(rep.Deviations) != 0 {
		t.Fatalf("unhashed unchanged file: %+v", rep.Deviations)
	}
}

func TestDiffClasses(t *testing.T) {
	b := mustBaseline(t, result(file("/etc/passwd", 1), file("/etc/motd", 1), file("/usr/bin/ls", 1)))
	scan := result(file("/etc/passwd", 2), file("/etc/motd", 2), file("/usr/bin/ls", 1),
		file("/usr/local/bin/ls", 1), with(file("/opt/x", 1), func(r *fimscan.Record) { r.Mode = 0o4755 }))
	rep := mustDiff(t, b, scan, usable())
	want := map[string]Rule{
		"/etc/motd": 0, "/etc/passwd": RuleFixedPath,
		"/opt/x": RuleSetID, "/usr/local/bin/ls": RuleShadow,
	}
	if len(rep.Deviations) != len(want) {
		t.Fatalf("%d deviations", len(rep.Deviations))
	}
	for _, d := range rep.Deviations {
		r, ok := want[string(d.Path)]
		if !ok || d.Rules != r || (d.Class == ClassCritical) != (r != 0) {
			t.Errorf("%s: %v/%b, want rules %b", d.Path, d.Class, d.Rules, r)
		}
	}
	// Without a usable derived SSH set, everything is critical (D7).
	for _, d := range mustDiff(t, b, scan, Options{}).Deviations {
		if d.Class != ClassCritical || d.Rules&RuleUnclassifiable == 0 {
			t.Errorf("%s: %v/%b without derived set", d.Path, d.Class, d.Rules)
		}
	}
}

func TestDiffShadowUsesLatestCompleteRun(t *testing.T) {
	// The baseline has no ls; the latest complete run has /usr/bin/ls, which
	// the partial scan (with /usr/bin skipped) does not report (D7 (c)).
	b := mustBaseline(t, result(file("/etc/motd", 1)))
	scan := partial(file("/etc/motd", 1), file("/usr/local/bin/ls", 1))
	without := mustDiff(t, b, scan, usable())
	if len(without.Deviations) != 1 || without.Deviations[0].Class != ClassNormal {
		t.Fatalf("without latest run: %+v", without.Deviations)
	}
	latest := Options{SSH: stubSSH{}, LatestComplete: result(file("/usr/bin/ls", 1))}
	rep := mustDiff(t, b, scan, latest)
	if len(rep.Deviations) != 1 || rep.Deviations[0].Class != ClassCritical || rep.Deviations[0].Rules != RuleShadow {
		t.Fatalf("with latest run: %+v", rep.Deviations)
	}
}

func TestDiffRejectsLatestComplete(t *testing.T) {
	b := mustBaseline(t, result(file("/etc/a", 1)))
	other := result(file("/usr/bin/ls", 1))
	other.ProfileID = "fim-other-v1"
	big := result()
	big.Records = make([]fimscan.Record, MaxEntries+1)
	tests := []struct {
		name   string
		latest *fimscan.Result
		want   error
	}{
		{"partial", partial(file("/usr/bin/ls", 1)), ErrInvalidInput},
		{"profile", other, ErrProfileMismatch},
		{"records over limit", big, ErrLimit},
		{"bad record", result(file("/usr//ls", 1)), ErrInvalidInput},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{SSH: stubSSH{}, LatestComplete: tc.latest}
			if rep, err := Diff(b, result(file("/etc/a", 1)), opts); !errors.Is(err, tc.want) || rep != nil {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDiffPartialScanHasNoRemoved(t *testing.T) {
	b := mustBaseline(t, result(file("/etc/a", 1), file("/etc/b", 1), file("/usr/bin/c", 1)))
	rep := mustDiff(t, b, partial(file("/etc/a", 2), file("/etc/new", 1)), usable())
	if rep.Complete {
		t.Fatal("partial reported complete")
	}
	var got []string
	for _, d := range rep.Deviations {
		if d.Kind == KindRemoved {
			t.Fatalf("partial scan yields removal of %s", d.Path)
		}
		got = append(got, string(d.Path)+":"+d.Kind.String())
	}
	if want := []string{"/etc/a:changed", "/etc/new:added"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffPartialVectors(t *testing.T) {
	b := mustBaseline(t, parseFile(t, "../fimscan/testdata/valid.json"))
	for _, name := range []string{"host-reported.json", "bad-records.json"} {
		t.Run(name, func(t *testing.T) {
			scan := parseFile(t, "../fimscan/testdata/partial/"+name)
			if scan.Complete() {
				t.Fatal("vector is complete")
			}
			rep := mustDiff(t, b, scan, usable())
			for _, d := range rep.Deviations {
				if d.Kind == KindRemoved {
					t.Fatalf("partial vector yields removal of %s", fimscan.EscapePath(d.Path))
				}
			}
		})
	}
}

func TestDiffCompleteOptionalRootAbsentRemoves(t *testing.T) {
	// D5: a missing optional root is absent; baseline entries under it are
	// reported as removed like any other absent path.
	b := mustBaseline(t, result(file("/opt/app/x", 1), file("/etc/a", 1)))
	scan := result(file("/etc/a", 1))
	scan.Roots = []fimscan.RootStatus{{Pattern: "/etc", State: fimscan.RootScanned}, {Pattern: "/opt", State: fimscan.RootAbsent}}
	rep := mustDiff(t, b, scan, usable())
	if len(rep.Deviations) != 1 || rep.Deviations[0].Kind != KindRemoved || string(rep.Deviations[0].Path) != "/opt/app/x" {
		t.Fatalf("got %+v", rep.Deviations)
	}
}

func efiResult(oldType string, recs ...fimscan.Record) *fimscan.Result {
	r := result(recs...)
	r.Roots = []fimscan.RootStatus{{Pattern: "/boot", State: fimscan.RootScanned}, {Pattern: "/boot/efi", State: fimscan.RootScanned}}
	if oldType != "" {
		r.Mounts = []fimscan.Mount{{Path: []byte("/boot/efi"), FSType: oldType}}
	}
	return r
}

func TestDiffVfatRelaxation(t *testing.T) {
	shim := file("/boot/efi/EFI/debian/shimx64.efi", 1)
	grub := file("/boot/grub/grub.cfg", 1)
	b := mustBaseline(t, efiResult("vfat", dir("/boot/efi"), shim, grub))
	meta := func(r *fimscan.Record) { r.UID, r.GID, r.Mode, r.Inode, r.Mtime, r.Ctime = 1000, 1000, 0o700, 9, 5, 5 }
	unhash := func(r *fimscan.Record) { r.Hash = fimscan.Hash{} }
	tests := []struct {
		name    string
		scan    *fimscan.Result
		path    string
		changes Change // 0: no deviation expected
	}{
		{"owner, perms, inode, times ignored", efiResult("vfat", with(dir("/boot/efi"), meta), with(shim, meta), grub), "", 0},
		{"setuid still compared", efiResult("vfat", dir("/boot/efi"), with(shim, func(r *fimscan.Record) { r.Mode = 0o4644 }), grub), "/boot/efi/EFI/debian/shimx64.efi", ChangeMode},
		{"content still compared", efiResult("vfat", dir("/boot/efi"), file("/boot/efi/EFI/debian/shimx64.efi", 2), grub), "/boot/efi/EFI/debian/shimx64.efi", ChangeContent},
		{"outside efi not relaxed", efiResult("vfat", dir("/boot/efi"), shim, with(grub, meta)), "/boot/grub/grub.cfg", ChangeMode | ChangeOwner | ChangeInode | ChangeTimes},
		{"fstype change not relaxed", efiResult("ext4", dir("/boot/efi"), with(shim, meta), grub), "", 0},
		// D5: every file under a vfat /boot/efi root is hashed in every run,
		// so an unhashed record there is a deviation even when the size,
		// type and mode are unchanged (fail closed).
		{"unhashed efi file same metadata", efiResult("vfat", dir("/boot/efi"), with(shim, unhash), grub), "/boot/efi/EFI/debian/shimx64.efi", ChangeNotHashed},
		{"unhashed efi file, owner and times only", efiResult("vfat", dir("/boot/efi"), with(shim, func(r *fimscan.Record) { meta(r); unhash(r) }), grub), "/boot/efi/EFI/debian/shimx64.efi", ChangeNotHashed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustDiff(t, b, tc.scan, usable())
			if tc.name == "fstype change not relaxed" {
				if len(rep.Deviations) != 2 {
					t.Fatalf("got %+v", rep.Deviations)
				}
				d0, d1 := rep.Deviations[0], rep.Deviations[1]
				if string(d0.Path) != "/boot/efi" || d0.Changes != ChangeFSType || d0.Class != ClassCritical {
					t.Fatalf("fstype deviation: %s %b %v", d0.Path, d0.Changes, d0.Class)
				}
				if d1.Changes&ChangeOwner == 0 || d1.Class != ClassCritical {
					t.Fatalf("relaxation applied despite fstype change: %b", d1.Changes)
				}
				return
			}
			if tc.changes == 0 {
				if len(rep.Deviations) != 0 {
					t.Fatalf("got %+v", rep.Deviations)
				}
				return
			}
			if len(rep.Deviations) != 1 || string(rep.Deviations[0].Path) != tc.path || rep.Deviations[0].Changes != tc.changes {
				t.Fatalf("got %+v", rep.Deviations)
			}
		})
	}
}

func TestDiffVfatRelaxationNeedsScannedRoot(t *testing.T) {
	shim := file("/boot/efi/EFI/debian/shimx64.efi", 1)
	b := mustBaseline(t, efiResult("vfat", dir("/boot/efi"), shim))
	meta := func(r *fimscan.Record) { r.UID, r.GID, r.Mode, r.Inode, r.Mtime, r.Ctime = 1000, 1000, 0o700, 9, 5, 5 }
	// The same metadata change as "owner, perms, inode, times ignored", but
	// /boot/efi is not a scanned root: D5 does not relax it.
	scan := efiResult("vfat", dir("/boot/efi"), with(shim, meta))
	for i := range scan.Roots {
		if scan.Roots[i].Pattern == efiRoot {
			scan.Roots[i].State = fimscan.RootSkipped
		}
	}
	rep := mustDiff(t, b, scan, usable())
	want := ChangeMode | ChangeOwner | ChangeInode | ChangeTimes
	if len(rep.Deviations) != 1 || rep.Deviations[0].Changes != want {
		t.Fatalf("got %+v, want changes %b", rep.Deviations, want)
	}
}

func TestDiffEFIFSTypeChangeMergesAndOrders(t *testing.T) {
	b := mustBaseline(t, efiResult("vfat", dir("/boot"), dir("/boot/efi"), file("/boot/z", 1)))
	// Record at /boot/efi changes too: the fstype flag joins its deviation.
	rep := mustDiff(t, b, efiResult("ext4", dir("/boot"), with(dir("/boot/efi"), func(r *fimscan.Record) { r.Size = 1 }), file("/boot/z", 2)), usable())
	if len(rep.Deviations) != 2 || string(rep.Deviations[0].Path) != "/boot/efi" || rep.Deviations[0].Changes != ChangeSize|ChangeFSType {
		t.Fatalf("got %+v", rep.Deviations)
	}
	// No record at /boot/efi: the deviation is inserted in path order.
	b = mustBaseline(t, efiResult("vfat", file("/boot/a", 1), file("/boot/z", 1)))
	rep = mustDiff(t, b, efiResult("", file("/boot/a", 2), file("/boot/z", 2)), usable())
	var got []string
	for _, d := range rep.Deviations {
		got = append(got, string(d.Path))
	}
	if want := []string{"/boot/a", "/boot/efi", "/boot/z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// A partial scan that does not report the mount proves nothing.
	p := efiResult("", file("/boot/a", 1), file("/boot/z", 1))
	p.Partial = []fimscan.Reason{fimscan.ReasonMountLimit}
	if rep := mustDiff(t, b, p, usable()); len(rep.Deviations) != 0 {
		t.Fatalf("partial without mount: %+v", rep.Deviations)
	}
}

func TestDiffRejects(t *testing.T) {
	b := mustBaseline(t, result(file("/etc/a", 1)))
	other := result(file("/etc/a", 1))
	other.ProfileID = "fim-other-v1"
	big := result()
	big.Records = make([]fimscan.Record, MaxEntries+1)
	tooManyMounts := result()
	tooManyMounts.Mounts = make([]fimscan.Mount, MaxMounts+1)
	tests := []struct {
		name string
		b    *Baseline
		scan *fimscan.Result
		want error
	}{
		{"nil baseline", nil, result(), ErrInvalidInput},
		{"nil scan", b, nil, ErrInvalidInput},
		{"profile", b, other, ErrProfileMismatch},
		{"records over limit", b, big, ErrLimit},
		{"mounts over limit", b, tooManyMounts, ErrLimit},
		{"long path", b, result(file("/etc/"+strings.Repeat("x", MaxPathBytes), 1)), ErrLimit},
		{"deep path", b, result(file("/etc"+strings.Repeat("/x", MaxPathDepth), 1)), ErrLimit},
		{"duplicate", b, result(file("/etc/a", 1), file("/etc/a", 2)), ErrInvalidInput},
		{"bad path", b, result(file("/etc//a", 1)), ErrInvalidInput},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if rep, err := Diff(tc.b, tc.scan, usable()); !errors.Is(err, tc.want) || rep != nil {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDiffDeterministic(t *testing.T) {
	baseRecs := []fimscan.Record{dir("/etc"), file("/etc/a", 1), file("/etc/b", 1), file("/etc/c", 1),
		file("/usr/bin/ls", 1), symlink("/etc/l", "x"), file("/etc/\xff", 1)}
	scanRecs := []fimscan.Record{dir("/etc"), file("/etc/a", 2), file("/etc/c", 1), file("/etc/d", 1),
		file("/usr/local/bin/ls", 1), symlink("/etc/l", "y"), file("/etc/\xfe", 1), file("/etc/A", 1)}
	b := mustBaseline(t, result(baseRecs...))
	want := mustDiff(t, b, result(scanRecs...), usable())
	for i := 1; i < len(want.Deviations); i++ {
		if bytes.Compare(want.Deviations[i-1].Path, want.Deviations[i].Path) >= 0 {
			t.Fatal("deviations not sorted by raw path bytes")
		}
	}
	rng := rand.New(rand.NewPCG(3, 4))
	for range 20 {
		bs := append([]fimscan.Record(nil), baseRecs...)
		ss := append([]fimscan.Record(nil), scanRecs...)
		rng.Shuffle(len(bs), func(i, j int) { bs[i], bs[j] = bs[j], bs[i] })
		rng.Shuffle(len(ss), func(i, j int) { ss[i], ss[j] = ss[j], ss[i] })
		b2 := mustBaseline(t, result(bs...))
		if b2.Digest() != b.Digest() {
			t.Fatal("digest depends on order")
		}
		if got := mustDiff(t, b2, result(ss...), usable()); !reflect.DeepEqual(got, want) {
			t.Fatal("diff depends on record order")
		}
	}
}

func TestDiffOutputIsCopy(t *testing.T) {
	b := mustBaseline(t, result(file("/etc/a", 1)))
	d := b.Digest()
	scan := result(file("/etc/a", 2))
	rep := mustDiff(t, b, scan, usable())
	rep.Deviations[0].Old.Path[1] = 'x'
	rep.Deviations[0].Path[1] = 'x'
	scan.Records[0].Path[1] = 'y'
	if b.Digest() != d || string(b.Entries()[0].Path) != "/etc/a" || string(rep.Deviations[0].New.Path) != "/etc/a" {
		t.Fatal("output aliases baseline or scan memory")
	}
}
