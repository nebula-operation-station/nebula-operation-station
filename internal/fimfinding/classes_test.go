// SPDX-License-Identifier: AGPL-3.0-or-later

package fimfinding

import (
	"errors"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integritystore"
)

// testRoots are the profile roots the cases assume: /etc and /usr/bin are
// watched, /boot holds critical paths only.
var testRoots = []fimscan.Root{{Pattern: "/etc"}, {Pattern: "/usr/bin"}, {Pattern: "/boot"}}

// Short names for the classes under test.
const (
	cPathChanged = integritystore.ClassCriticalPathChanged
	cSetIDNew    = integritystore.ClassSetIDNew
	cOwnerMode   = integritystore.ClassOwnerModeChanged
	cEtc         = integritystore.ClassEtcChanged
	cScanPartial = integritystore.ClassScanPartial
)

// rec returns a record of the given path, type and mode.
func rec(p string, typ fimscan.Type, mode uint32) *fimscan.Record {
	return &fimscan.Record{Path: []byte(p), Type: typ, Mode: mode, Size: 1, Inode: 7, Mtime: 1, Ctime: 1}
}

// file returns a regular file record.
func file(p string, mode uint32) *fimscan.Record { return rec(p, fimscan.TypeFile, mode) }

// dev returns a deviation of path p.
func dev(p string, kind fimbaseline.Kind, ch fimbaseline.Change, class fimbaseline.Class,
	rules fimbaseline.Rule, old, nw *fimscan.Record) fimbaseline.Deviation {
	return fimbaseline.Deviation{Path: []byte(p), Kind: kind, Changes: ch, Class: class, Rules: rules, Old: old, New: nw}
}

const (
	critical = fimbaseline.ClassCritical
	normal   = fimbaseline.ClassNormal
)

func TestClassesMapsDeviationRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		d        fimbaseline.Deviation
		want     []integritystore.Class
		wantSev  integritystore.Severity
		wantFail error
	}{
		{
			name: "critical content change in etc is critical and etc-changed",
			d: dev("/etc/sudoers", fimbaseline.KindChanged, fimbaseline.ChangeContent, critical,
				fimbaseline.RuleFixedPath, file("/etc/sudoers", 0o440), file("/etc/sudoers", 0o440)),
			want: []integritystore.Class{cPathChanged, cEtc}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "removed critical path is critical-path-changed only",
			d: dev("/etc/sudoers", fimbaseline.KindRemoved, 0, critical,
				fimbaseline.RuleFixedPath, file("/etc/sudoers", 0o440), nil),
			want: []integritystore.Class{cPathChanged}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "added critical path outside etc and usr roots",
			d: dev("/boot/new.cfg", fimbaseline.KindAdded, fimbaseline.ChangeNotHashed, critical,
				fimbaseline.RuleFixedPath, nil, file("/boot/new.cfg", 0o644)),
			want: []integritystore.Class{cPathChanged}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "new setuid file is setid-new",
			d: dev("/usr/bin/newsu", fimbaseline.KindAdded, 0, critical,
				fimbaseline.RuleSetID, nil, file("/usr/bin/newsu", 0o4755)),
			want: []integritystore.Class{cPathChanged, cSetIDNew, cEtc}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "setgid bit added to an existing file is setid-new",
			d: dev("/usr/bin/tool", fimbaseline.KindChanged, fimbaseline.ChangeMode, critical,
				fimbaseline.RuleSetID, file("/usr/bin/tool", 0o755), file("/usr/bin/tool", 0o2755)),
			want: []integritystore.Class{cPathChanged, cSetIDNew, cOwnerMode, cEtc}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "permission change of a file that already had setuid is not setid-new",
			d: dev("/usr/bin/su", fimbaseline.KindChanged, fimbaseline.ChangeMode, critical,
				fimbaseline.RuleSetID, file("/usr/bin/su", 0o4755), file("/usr/bin/su", 0o4775)),
			want: []integritystore.Class{cPathChanged, cOwnerMode, cEtc}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "owner change in etc is owner-mode-changed",
			d: dev("/etc/motd", fimbaseline.KindChanged, fimbaseline.ChangeOwner, normal, 0,
				file("/etc/motd", 0o644), file("/etc/motd", 0o644)),
			want: []integritystore.Class{cOwnerMode, cEtc}, wantSev: integritystore.SeverityHigh,
		},
		{
			name: "mode change in usr bin is owner-mode-changed",
			d: dev("/usr/bin/ls", fimbaseline.KindChanged, fimbaseline.ChangeMode, normal, 0,
				file("/usr/bin/ls", 0o755), file("/usr/bin/ls", 0o700)),
			want: []integritystore.Class{cOwnerMode, cEtc}, wantSev: integritystore.SeverityHigh,
		},
		{
			name: "owner change of a critical path escalates to critical",
			d: dev("/etc/sudoers", fimbaseline.KindChanged, fimbaseline.ChangeOwner, critical,
				fimbaseline.RuleFixedPath, file("/etc/sudoers", 0o440), file("/etc/sudoers", 0o440)),
			want: []integritystore.Class{cPathChanged, cOwnerMode, cEtc}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "new non-critical file in etc is etc-changed",
			d: dev("/etc/new.conf", fimbaseline.KindAdded, fimbaseline.ChangeNotHashed, normal, 0,
				nil, file("/etc/new.conf", 0o644)),
			want: []integritystore.Class{cEtc}, wantSev: integritystore.SeverityHigh,
		},
		{
			name: "times-only change in etc is etc-changed",
			d: dev("/etc/hostname", fimbaseline.KindChanged, fimbaseline.ChangeTimes, normal, 0,
				file("/etc/hostname", 0o644), file("/etc/hostname", 0o644)),
			want: []integritystore.Class{cEtc}, wantSev: integritystore.SeverityHigh,
		},
		{
			name: "content change in a watched usr root is etc-changed",
			d: dev("/usr/bin/foo", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
				file("/usr/bin/foo", 0o755), file("/usr/bin/foo", 0o755)),
			want: []integritystore.Class{cEtc}, wantSev: integritystore.SeverityHigh,
		},
		{
			name: "efi file-system type change is a critical path change",
			d: dev("/boot/efi", fimbaseline.KindChanged, fimbaseline.ChangeFSType, critical,
				fimbaseline.RuleFixedPath, rec("/boot/efi", fimscan.TypeDir, 0o755), rec("/boot/efi", fimscan.TypeDir, 0o755)),
			want: []integritystore.Class{cPathChanged}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "efi mount without a baseline record is a critical path change",
			d: dev("/boot/efi", fimbaseline.KindChanged, fimbaseline.ChangeFSType, critical,
				fimbaseline.RuleFixedPath, nil, rec("/boot/efi", fimscan.TypeDir, 0o755)),
			want: []integritystore.Class{cPathChanged}, wantSev: integritystore.SeverityCritical,
		},
		{
			name: "change outside etc and usr roots has no row and fails",
			d: dev("/opt/app/run.sh", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
				file("/opt/app/run.sh", 0o755), file("/opt/app/run.sh", 0o755)),
			wantFail: ErrNotCovered,
		},
		{
			name: "removed non-critical path has no row and fails",
			d: dev("/etc/old.conf", fimbaseline.KindRemoved, 0, normal, 0,
				file("/etc/old.conf", 0o644), nil),
			wantFail: ErrNotCovered,
		},
		{
			name: "changed record with no change bit is invalid input",
			d: dev("/etc/motd", fimbaseline.KindChanged, 0, normal, 0,
				file("/etc/motd", 0o644), file("/etc/motd", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "added record that has a baseline side is invalid input",
			d: dev("/etc/new.conf", fimbaseline.KindAdded, 0, normal, 0,
				file("/etc/new.conf", 0o644), file("/etc/new.conf", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "removed record with change bits is invalid input",
			d: dev("/etc/old.conf", fimbaseline.KindRemoved, fimbaseline.ChangeContent, normal, 0,
				file("/etc/old.conf", 0o644), nil),
			wantFail: ErrInvalidInput,
		},
		{
			name: "record path differing from the deviation path is invalid input",
			d: dev("/etc/a", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
				file("/etc/a", 0o644), file("/etc/b", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "changed without both records and without an efi change is invalid input",
			d: dev("/etc/a", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
				nil, file("/etc/a", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name:     "unknown kind is invalid input",
			d:        dev("/etc/a", 0, fimbaseline.ChangeContent, normal, 0, file("/etc/a", 0o644), file("/etc/a", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "unknown class is invalid input",
			d: dev("/etc/a", fimbaseline.KindChanged, fimbaseline.ChangeContent, 9, 0,
				file("/etc/a", 0o644), file("/etc/a", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "normal class with rules is invalid input",
			d: dev("/etc/a", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal,
				fimbaseline.RuleFixedPath, file("/etc/a", 0o644), file("/etc/a", 0o644)),
			wantFail: ErrInvalidInput,
		},
		{
			name: "critical class without rules is invalid input",
			d: dev("/etc/sudoers", fimbaseline.KindChanged, fimbaseline.ChangeContent, critical, 0,
				file("/etc/sudoers", 0o440), file("/etc/sudoers", 0o440)),
			wantFail: ErrInvalidInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Classes(tt.d, testRoots)
			if tt.wantFail != nil {
				if !errors.Is(err, tt.wantFail) {
					t.Fatalf("Classes error = %v, want %v", err, tt.wantFail)
				}
				return
			}
			if err != nil {
				t.Fatalf("Classes: %v", err)
			}
			want := slices.Clone(tt.want)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Fatalf("classes = %v, want %v", got, want)
			}
			// The reported finding carries the highest severity of the set.
			f := findingsOf(t, tt.d, true)
			if len(f) != 1 || f[0].Severity != tt.wantSev || !slices.Contains(tt.want, f[0].Class) {
				t.Fatalf("findings = %+v, want severity %s", f, tt.wantSev)
			}
		})
	}
}

// findingsOf runs Findings for one deviation in a report of the given
// completeness and fails the test on error.
func findingsOf(t *testing.T, d fimbaseline.Deviation, complete bool) []Finding {
	t.Helper()
	f, err := Findings(&fimbaseline.Report{Complete: complete, Deviations: []fimbaseline.Deviation{d}}, testRoots)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	return f
}

func TestFindingsPartialScanAddsScanPartialFirst(t *testing.T) {
	t.Parallel()
	d := dev("/etc/sudoers", fimbaseline.KindChanged, fimbaseline.ChangeContent, critical,
		fimbaseline.RuleFixedPath, file("/etc/sudoers", 0o440), file("/etc/sudoers", 0o440))
	got, err := Findings(&fimbaseline.Report{Complete: false, Deviations: []fimbaseline.Deviation{d}}, testRoots)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Class != cScanPartial || got[0].Severity != integritystore.SeverityMedium || got[0].Path != nil {
		t.Fatalf("first finding = %+v, want scan-partial (medium) without path", got[0])
	}
	if got[1].Class != cPathChanged || got[1].Severity != integritystore.SeverityCritical {
		t.Fatalf("second finding = %+v, want critical-path-changed (critical)", got[1])
	}
}

func TestFindingsEmptyPartialReportIsScanPartialOnly(t *testing.T) {
	t.Parallel()
	got, err := Findings(&fimbaseline.Report{Complete: false}, testRoots)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 1 || got[0].Class != cScanPartial || got[0].Severity != integritystore.SeverityMedium {
		t.Fatalf("findings = %+v, want one scan-partial (medium)", got)
	}
}

func TestFindingsEmptyCompleteReportHasNoFindings(t *testing.T) {
	t.Parallel()
	got, err := Findings(&fimbaseline.Report{Complete: true}, testRoots)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

func TestFindingsUncoveredDeviationFailsWholeReport(t *testing.T) {
	t.Parallel()
	ok := dev("/etc/motd", fimbaseline.KindChanged, fimbaseline.ChangeOwner, normal, 0,
		file("/etc/motd", 0o644), file("/etc/motd", 0o644))
	bad := dev("/opt/app/run.sh", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
		file("/opt/app/run.sh", 0o755), file("/opt/app/run.sh", 0o755))
	_, err := Findings(&fimbaseline.Report{Complete: true, Deviations: []fimbaseline.Deviation{ok, bad}}, testRoots)
	if !errors.Is(err, ErrNotCovered) {
		t.Fatalf("Findings error = %v, want ErrNotCovered", err)
	}
}

func TestFindingsNilReportIsInvalidInput(t *testing.T) {
	t.Parallel()
	if _, err := Findings(nil, testRoots); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Findings(nil) error = %v, want ErrInvalidInput", err)
	}
}

func TestFindingsPathSeverityIsTheHighestClass(t *testing.T) {
	t.Parallel()
	// /etc/sudoers matches critical-path-changed (critical) and etc-changed
	// (high); the critical one must win.
	d := dev("/etc/sudoers", fimbaseline.KindChanged, fimbaseline.ChangeContent, critical,
		fimbaseline.RuleFixedPath, file("/etc/sudoers", 0o440), file("/etc/sudoers", 0o440))
	got := findingsOf(t, d, true)
	if len(got) != 1 || got[0].Class != cPathChanged || got[0].Severity != integritystore.SeverityCritical {
		t.Fatalf("findings = %+v, want critical-path-changed (critical)", got)
	}
	if string(got[0].Path) != "/etc/sudoers" {
		t.Fatalf("path = %q", got[0].Path)
	}
}

func TestGlobRootIsNotAWatchedUsrRoot(t *testing.T) {
	t.Parallel()
	roots := []fimscan.Root{{Pattern: "/usr/*/bin"}}
	d := dev("/usr/x/bin/tool", fimbaseline.KindChanged, fimbaseline.ChangeContent, normal, 0,
		file("/usr/x/bin/tool", 0o755), file("/usr/x/bin/tool", 0o755))
	if _, err := Classes(d, roots); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("Classes error = %v, want ErrNotCovered", err)
	}
}

// FuzzClasses feeds arbitrary deviation fields. Whatever the input, no call
// panics, a returned class is known to integritystore, and the finding
// carries a known severity.
func FuzzClasses(f *testing.F) {
	f.Add([]byte("/etc/sudoers"), uint8(2), uint16(1), uint8(critical), uint8(1), uint8(3), uint16(0o4755), uint16(0o755), uint8(0))
	f.Add([]byte("/usr/bin/su"), uint8(1), uint16(0), uint8(normal), uint8(0), uint8(0), uint16(0), uint16(0o2755), uint8(8))
	f.Add([]byte("/etc/motd"), uint8(3), uint16(0), uint8(0), uint8(0), uint8(0), uint16(0), uint16(0), uint8(0))
	f.Add([]byte("/boot/efi"), uint8(2), uint16(1<<9), uint8(critical), uint8(1), uint8(2), uint16(0o755), uint16(0o755), uint8(0))
	f.Fuzz(func(t *testing.T, path []byte, kind uint8, changes uint16, class uint8, rules uint8,
		recFlags uint8, oldMode, newMode uint16, reportFlags uint8) {
		d := fimbaseline.Deviation{
			Path:    path,
			Kind:    fimbaseline.Kind(kind),
			Changes: fimbaseline.Change(changes),
			Class:   fimbaseline.Class(class),
			Rules:   fimbaseline.Rule(rules),
		}
		typ := fimscan.Type(recFlags%5 + 0)
		if recFlags&1 != 0 {
			d.Old = rec(string(path), typ, uint32(oldMode))
		}
		if recFlags&2 != 0 {
			d.New = rec(string(path), fimscan.TypeFile, uint32(newMode))
		}
		if recFlags&4 != 0 && d.New != nil {
			d.New.Path = []byte("/etc/other")
		}
		classes, err := Classes(d, testRoots)
		if err == nil {
			if len(classes) == 0 {
				t.Fatal("no error and no class")
			}
			for _, c := range classes {
				if _, err := c.Severity(); err != nil {
					t.Fatalf("unknown class %q returned", c)
				}
			}
		}
		rep := &fimbaseline.Report{Complete: reportFlags&1 == 0, Deviations: []fimbaseline.Deviation{d}}
		findings, err := Findings(rep, testRoots)
		if err != nil {
			return
		}
		for _, fd := range findings {
			sev, err := fd.Class.Severity()
			if err != nil || sev != fd.Severity {
				t.Fatalf("finding %+v: class/severity mismatch (%v)", fd, err)
			}
		}
	})
}
