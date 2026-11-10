// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

const (
	testDevice = "core-sw-01"
	testRead   = ReadCBSVLANs
)

var testTime = time.Date(2026, 11, 10, 12, 0, 0, 123456789, time.UTC)

// newSpool returns a writer spool over a freshly provisioned directory.
func newSpool(t *testing.T) *Spool {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, spoolDirMode); err != nil {
		t.Fatal(err)
	}
	now := testTime
	var mu sync.Mutex
	return &Spool{Dir: dir, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Millisecond)
		return now
	}}
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func mustWrite(t *testing.T, s *Spool, device, read string, payload string) string {
	t.Helper()
	name, err := s.Write(context.Background(), device, read, 3, false, []byte(payload))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return name
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteThenTakeRoundTrip(t *testing.T) {
	s := newSpool(t)
	s.Now = fixedNow(testTime)
	ctx := context.Background()
	name, err := s.Write(ctx, testDevice, testRead, 7, true, []byte(` {"vlans": [1, 2]} `))
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("%s-%s-%d-", testDevice, testRead, testTime.UnixNano())
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") || strings.Contains(name, "/") {
		t.Fatalf("name %q does not follow <device>-<read>-<nanos>-<random>.json", name)
	}
	fi, err := os.Lstat(filepath.Join(s.Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != spoolFileMode {
		t.Fatalf("file mode %v, want %v", fi.Mode(), os.FileMode(spoolFileMode))
	}
	names, err := s.List(ctx)
	if err != nil || len(names) != 1 || names[0] != name {
		t.Fatalf("List = %v, %v; want [%s]", names, err, name)
	}
	taken, err := s.Take(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	rec := taken.Record
	if rec.DeviceID != testDevice || rec.Read != testRead || rec.TrustGeneration != 7 || !rec.Incomplete ||
		!rec.ObservedAt.Equal(testTime) || string(rec.Data) != `{"vlans":[1,2]}` {
		t.Fatalf("record = %+v", rec)
	}
	// Taking does not consume: the file stays until the caller confirms.
	if _, err := os.Lstat(filepath.Join(s.Dir, name)); err != nil {
		t.Fatalf("file removed before confirmation: %v", err)
	}
	if err := taken.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dirNames(t, s.Dir); len(got) != 0 {
		t.Fatalf("spool not empty after confirm: %v", got)
	}
}

func TestWriteKeepsHTMLCharactersVerbatim(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, testRead, `{"d":"a<b>&c"}`)
	taken, err := s.Take(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if string(taken.Record.Data) != `{"d":"a<b>&c"}` {
		t.Fatalf("data = %s", taken.Record.Data)
	}
}

func TestCrashBeforeRenameLeavesNoVisibleFile(t *testing.T) {
	s := newSpool(t)
	crash := errors.New("simulated crash")
	var tmpSeen string
	beforeRename = func(dir *os.File, tmp string) error {
		tmpSeen = tmp
		// The temp file is complete and synced but must not be listed.
		names, err := s.List(context.Background())
		if err != nil || len(names) != 0 {
			t.Errorf("List before rename = %v, %v", names, err)
		}
		return crash
	}
	t.Cleanup(func() { beforeRename = nil })
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, crash) {
		t.Fatalf("Write err = %v, want simulated crash", err)
	}
	if !strings.HasPrefix(tmpSeen, ".tmp-") {
		t.Fatalf("temp name %q is not hidden", tmpSeen)
	}
	if got := dirNames(t, s.Dir); len(got) != 0 {
		t.Fatalf("failed write left files: %v", got)
	}
}

func TestLeftoverTempFileIsNeverImported(t *testing.T) {
	s := newSpool(t)
	// A crash after the temp file is written leaves it behind.
	tmp := ".tmp-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if err := os.WriteFile(filepath.Join(s.Dir, tmp), []byte(`{}`), spoolFileMode); err != nil {
		t.Fatal(err)
	}
	names, err := s.List(context.Background())
	if err != nil || len(names) != 0 {
		t.Fatalf("List = %v, %v; want empty", names, err)
	}
	if _, err := s.Take(context.Background(), tmp); !errors.Is(err, ErrBadName) {
		t.Fatalf("Take(temp) err = %v, want ErrBadName", err)
	}
}

func TestWriteRejectsOversizePayload(t *testing.T) {
	s := newSpool(t)
	for _, read := range []string{ReadCBSMACTable, ReadPANOSSecurityRules} {
		limit, ok := ReadLimit(read)
		if !ok {
			t.Fatalf("no limit for %s", read)
		}
		atLimit := `{"a":"` + strings.Repeat("a", limit-8) + `"}`
		name, err := s.Write(context.Background(), testDevice, read, 1, false, []byte(atLimit))
		if err != nil {
			t.Fatalf("%s: payload at the limit refused: %v", read, err)
		}
		if _, err := s.Take(context.Background(), name); err != nil {
			t.Fatalf("%s: record at the limit not readable: %v", read, err)
		}
		over := `{"a":"` + strings.Repeat("a", limit-7) + `"}`
		if _, err := s.Write(context.Background(), testDevice, read, 1, false, []byte(over)); !errors.Is(err, ErrOversize) {
			t.Fatalf("%s: oversize err = %v, want ErrOversize", read, err)
		}
	}
}

func TestReadLimitsComeFromContract(t *testing.T) {
	cases := map[string]int{
		ReadCBSVersion:         netdevcontract.MaxCBSCommandOutputBytes,
		ReadCBSVLANs:           netdevcontract.MaxCBSCommandOutputBytes,
		ReadCBSInterfaces:      netdevcontract.MaxCBSCommandOutputBytes,
		ReadCBSMACTable:        netdevcontract.MaxCBSCommandOutputBytes,
		ReadCBSLLDP:            netdevcontract.MaxCBSCommandOutputBytes,
		ReadPANOSZones:         netdevcontract.MaxPANOSResponseBytes,
		ReadPANOSObjects:       netdevcontract.MaxPANOSResponseBytes,
		ReadPANOSSecurityRules: netdevcontract.MaxPANOSResponseBytes,
		ReadPANOSNATRules:      netdevcontract.MaxPANOSResponseBytes,
		ReadPANOSRuleHitCounts: netdevcontract.MaxPANOSResponseBytes,
	}
	for read, want := range cases {
		if got, ok := ReadLimit(read); !ok || got != want {
			t.Errorf("ReadLimit(%s) = %d, %v; want %d", read, got, ok, want)
		}
	}
	if len(readLimits) != len(cases) {
		t.Errorf("readLimits has %d reads, test covers %d", len(readLimits), len(cases))
	}
	for _, bad := range []string{"", "facts", "CBS_VLANS", "cbs-vlans", "cbs_vlans/../x"} {
		if _, ok := ReadLimit(bad); ok {
			t.Errorf("ReadLimit(%q) accepted", bad)
		}
	}
}

func TestWriteRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		device  string
		read    string
		gen     uint64
		payload string
		want    error
	}{
		{"bad device", "Core_SW", testRead, 1, `{}`, ErrInvalidRecord},
		{"device with slash", "a/b", testRead, 1, `{}`, ErrInvalidRecord},
		{"long device", strings.Repeat("a", netdevcontract.MaxDeviceIDBytes+1), testRead, 1, `{}`, ErrInvalidRecord},
		{"unknown read", testDevice, "cbs_config", 1, `{}`, ErrUnknownRead},
		{"zero generation", testDevice, testRead, 0, `{}`, ErrInvalidRecord},
		{"generation over max", testDevice, testRead, netdevcontract.MaxTrustGeneration + 1, `{}`, ErrInvalidRecord},
		{"empty payload", testDevice, testRead, 1, ``, ErrInvalidRecord},
		{"invalid json", testDevice, testRead, 1, `{"a":`, ErrInvalidRecord},
		{"null payload", testDevice, testRead, 1, `null`, ErrInvalidRecord},
		{"invalid utf-8", testDevice, testRead, 1, "{\"a\":\"\xff\"}", ErrInvalidRecord},
		{"two values", testDevice, testRead, 1, `{} {}`, ErrInvalidRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSpool(t)
			if _, err := s.Write(context.Background(), tc.device, tc.read, tc.gen, false, []byte(tc.payload)); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := dirNames(t, s.Dir); len(got) != 0 {
				t.Fatalf("rejected write left files: %v", got)
			}
		})
	}
}

func TestWriteRequiresInjectedClock(t *testing.T) {
	s := newSpool(t)
	s.Now = nil
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); err == nil {
		t.Fatal("Write without Now succeeded")
	}
	s.Now = fixedNow(time.Unix(0, 0))
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Write at the epoch err = %v, want ErrInvalidRecord", err)
	}
}

func TestWriteHonoursCancelledContext(t *testing.T) {
	s := newSpool(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Write(ctx, testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestSymlinkedSpoolDirRefused(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, testRead, `{}`)
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(s.Dir, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(base, "parent")
	if err := os.Symlink(filepath.Dir(s.Dir), parentLink); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{link, filepath.Join(parentLink, filepath.Base(s.Dir))} {
		evil := &Spool{Dir: dir, Now: s.Now}
		ctx := context.Background()
		if _, err := evil.Write(ctx, testDevice, testRead, 1, false, []byte(`{}`)); !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: Write err = %v, want ErrSymlink", dir, err)
		}
		if _, err := evil.List(ctx); !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: List err = %v, want ErrSymlink", dir, err)
		}
		if _, err := evil.Take(ctx, name); !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: Take err = %v, want ErrSymlink", dir, err)
		}
		if err := evil.Discard(ctx, name); !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: Discard err = %v, want ErrSymlink", dir, err)
		}
	}
	if got := dirNames(t, s.Dir); len(got) != 1 {
		t.Fatalf("spool changed through a symlink: %v", got)
	}
}

func TestRelativeSpoolDirRefused(t *testing.T) {
	s := &Spool{Dir: "spool", Now: fixedNow(testTime)}
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("relative Dir accepted")
	}
}

func TestSymlinkedSpoolFileRefused(t *testing.T) {
	s := newSpool(t)
	ctx := context.Background()
	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("A", randomChars))
	if err := os.Symlink(victim, filepath.Join(s.Dir, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ctx); !errors.Is(err, ErrSymlink) {
		t.Fatalf("List err = %v, want ErrSymlink", err)
	}
	_, err := s.Take(ctx, name)
	if !errors.Is(err, ErrSymlink) || !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take err = %v, want ErrSymlink and ErrInvalidRecord", err)
	}
	if err := s.Discard(ctx, name); !errors.Is(err, ErrSymlink) {
		t.Fatalf("Discard err = %v, want ErrSymlink", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("symlink target touched: %v", err)
	}
}

func TestTakeRejectsNonRegularFile(t *testing.T) {
	s := newSpool(t)
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("B", randomChars))
	if err := syscall.Mkfifo(filepath.Join(s.Dir, name), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(context.Background(), name); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take(fifo) err = %v, want ErrInvalidRecord", err)
	}
}

func TestTakeRejectsOversizeFile(t *testing.T) {
	s := newSpool(t)
	limit, _ := ReadLimit(testRead)
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("C", randomChars))
	big := bytes.Repeat([]byte(" "), limit+maxRecordOverhead+1)
	if err := os.WriteFile(filepath.Join(s.Dir, name), big, spoolFileMode); err != nil {
		t.Fatal(err)
	}
	_, err := s.Take(context.Background(), name)
	if !errors.Is(err, ErrOversize) || !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take err = %v, want ErrOversize and ErrInvalidRecord", err)
	}
}

func TestTakeRejectsOversizeData(t *testing.T) {
	s := newSpool(t)
	limit, _ := ReadLimit(testRead)
	// The file fits the record limit but its data exceeds the read limit.
	data := `{"a":"` + strings.Repeat("a", limit-7) + `"}`
	raw := fmt.Sprintf(`{"device_id":%q,"read":%q,"trust_generation":1,"observed_at":%q,"incomplete":false,"data":%s}`,
		testDevice, testRead, testTime.Format(time.RFC3339Nano), data)
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("D", randomChars))
	if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(raw), spoolFileMode); err != nil {
		t.Fatal(err)
	}
	_, err := s.Take(context.Background(), name)
	if !errors.Is(err, ErrOversize) || !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take err = %v, want ErrOversize and ErrInvalidRecord", err)
	}
}

func TestTakeRejectsWrongFileMode(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, testRead, `{}`)
	if err := os.Chmod(filepath.Join(s.Dir, name), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(context.Background(), name); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take err = %v, want ErrInvalidRecord", err)
	}
}

func TestTakeRejectsIdentityNotMatchingFileName(t *testing.T) {
	s := newSpool(t)
	s.Now = fixedNow(testTime)
	name := mustWrite(t, s, testDevice, testRead, `{}`)
	random := strings.TrimSuffix(name[strings.LastIndexByte(name, '-')+1:], ".json")
	renames := map[string]string{
		"device":   fmt.Sprintf("%s-%s-%d-%s.json", "other-sw", testRead, testTime.UnixNano(), random),
		"read":     fmt.Sprintf("%s-%s-%d-%s.json", testDevice, ReadCBSLLDP, testTime.UnixNano(), random),
		"observed": fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano()+1, random),
		"prefix":   fmt.Sprintf("%s-%s-%d-%s.json", "x-"+testDevice, testRead, testTime.UnixNano(), random),
	}
	cur := name
	for what, next := range renames {
		if err := os.Rename(filepath.Join(s.Dir, cur), filepath.Join(s.Dir, next)); err != nil {
			t.Fatal(err)
		}
		cur = next
		if _, err := s.Take(context.Background(), next); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("%s renamed: Take err = %v, want ErrInvalidRecord", what, err)
		}
	}
}

func TestTakeRejectsMalformedRecord(t *testing.T) {
	ts := testTime.Format(time.RFC3339Nano)
	good := func(extra string) string {
		return fmt.Sprintf(`{"device_id":%q,"read":%q,"trust_generation":1,"observed_at":%q,"incomplete":false,"data":{}%s}`, testDevice, testRead, ts, extra)
	}
	cases := map[string]string{
		"unknown field":   good(`,"secret":"x"`),
		"duplicate key":   good(`,"read":"cbs_lldp"`),
		"trailing data":   good(``) + `{}`,
		"not an object":   `[]`,
		"null field":      strings.Replace(good(``), `"incomplete":false`, `"incomplete":null`, 1),
		"missing field":   strings.Replace(good(``), `"incomplete":false,`, ``, 1),
		"null data":       strings.Replace(good(``), `"data":{}`, `"data":null`, 1),
		"scalar data":     strings.Replace(good(``), `"data":{}`, `"data":1`, 1),
		"zero generation": strings.Replace(good(``), `"trust_generation":1`, `"trust_generation":0`, 1),
		"string gen":      strings.Replace(good(``), `"trust_generation":1`, `"trust_generation":"1"`, 1),
		"bad utf-8":       strings.Replace(good(``), `"data":{}`, "\"data\":{\"a\":\"\xff\"}", 1),
		"empty":           ``,
	}
	for what, raw := range cases {
		t.Run(what, func(t *testing.T) {
			s := newSpool(t)
			name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("E", randomChars))
			if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(raw), spoolFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Take(context.Background(), name); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Take err = %v, want ErrInvalidRecord", err)
			}
		})
	}
	// The well-formed control record is accepted.
	s := newSpool(t)
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("F", randomChars))
	if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(good(``)), spoolFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(context.Background(), name); err != nil {
		t.Fatalf("control record refused: %v", err)
	}
}

func TestFileNameGrammarIsStrict(t *testing.T) {
	r := strings.Repeat("A", randomChars)
	n := testTime.UnixNano()
	good := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, n, r)
	if _, err := parseSpoolName(good); err != nil {
		t.Fatalf("good name refused: %v", err)
	}
	bad := []string{
		"",
		"../" + good,
		"x/" + good,
		good + ".tmp",
		".tmp-" + r,
		fmt.Sprintf("%s-%s-%d-%s.JSON", testDevice, testRead, n, r),
		fmt.Sprintf("%s-%s-%d-%s.json", "Core-SW", testRead, n, r),
		fmt.Sprintf("%s-%s-%d-%s.json", "-core", testRead, n, r),
		fmt.Sprintf("%s-%s-%d-%s.json", "core-", testRead, n, r),
		fmt.Sprintf("%s-%s-%d-%s.json", strings.Repeat("a", netdevcontract.MaxDeviceIDBytes+1), testRead, n, r),
		fmt.Sprintf("%s-%s-%d-%s.json", testDevice, "cbs_config", n, r),
		fmt.Sprintf("%s-%s-0%d-%s.json", testDevice, testRead, n, r),
		fmt.Sprintf("%s-%s-0-%s.json", testDevice, testRead, r),
		fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, n, r[1:]),
		fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, n, strings.ToLower(r)),
		fmt.Sprintf("%s-%s-%d-%s1.json", testDevice, testRead, n, r[1:]),
		fmt.Sprintf("%s-%s-99999999999999999999-%s.json", testDevice, testRead, r),
		fmt.Sprintf("%s-%s-%d-%s.json\n", testDevice, testRead, n, r),
	}
	for _, name := range bad {
		if _, err := parseSpoolName(name); !errors.Is(err, ErrBadName) {
			t.Errorf("parseSpoolName(%q) err = %v, want ErrBadName", name, err)
		}
	}
	s := newSpool(t)
	for _, name := range bad {
		if _, err := s.Take(context.Background(), name); !errors.Is(err, ErrBadName) {
			t.Errorf("Take(%q) err = %v, want ErrBadName", name, err)
		}
		if err := s.Discard(context.Background(), name); !errors.Is(err, ErrBadName) {
			t.Errorf("Discard(%q) err = %v, want ErrBadName", name, err)
		}
	}
}

func TestReplayedFileIsRejected(t *testing.T) {
	s := newSpool(t)
	ctx := context.Background()
	name := mustWrite(t, s, testDevice, testRead, `{"n":1}`)
	raw, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	taken, err := s.Take(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := taken.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	// An attacker with write access to the spool replays the consumed file.
	if err := os.WriteFile(filepath.Join(s.Dir, name), raw, spoolFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, name); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replayed name err = %v, want ErrReplayed", err)
	}
	if err := s.Discard(ctx, name); err != nil {
		t.Fatal(err)
	}

	// An older observation of the same device and read is a replay too.
	newer := mustWrite(t, s, testDevice, testRead, `{"n":2}`)
	older := &Spool{Dir: s.Dir, Now: fixedNow(testTime.Add(-time.Hour))}
	oldName := mustWrite(t, older, testDevice, testRead, `{"n":0}`)
	taken, err = s.Take(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	if err := taken.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(ctx, oldName); !errors.Is(err, ErrReplayed) {
		t.Fatalf("older observation err = %v, want ErrReplayed", err)
	}
	// Other reads of the same device are independent.
	other := &Spool{Dir: s.Dir, Now: fixedNow(testTime.Add(-time.Hour))}
	otherName := mustWrite(t, other, testDevice, ReadCBSLLDP, `{}`)
	if _, err := s.Take(ctx, otherName); err != nil {
		t.Fatalf("independent read refused: %v", err)
	}
}

func TestSameInstantDifferentFilesAreNotReplays(t *testing.T) {
	s := newSpool(t)
	s.Now = fixedNow(testTime)
	ctx := context.Background()
	a := mustWrite(t, s, testDevice, testRead, `{}`)
	b := mustWrite(t, s, testDevice, testRead, `{}`)
	for _, name := range []string{a, b} {
		taken, err := s.Take(ctx, name)
		if err != nil {
			t.Fatalf("Take(%s): %v", name, err)
		}
		if err := taken.Confirm(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfirmRefusesSwappedFile(t *testing.T) {
	s := newSpool(t)
	ctx := context.Background()
	name := mustWrite(t, s, testDevice, testRead, `{"n":1}`)
	taken, err := s.Take(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the entry with a different file after the take.
	path := filepath.Join(s.Dir, name)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{}`), spoolFileMode); err != nil {
		t.Fatal(err)
	}
	if err := taken.Confirm(ctx); !errors.Is(err, ErrChanged) {
		t.Fatalf("Confirm err = %v, want ErrChanged", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("swapped file removed: %v", err)
	}
	// A failed confirmation does not advance the replay watermark.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := taken.Confirm(ctx); err == nil {
		t.Fatal("Confirm of a vanished file succeeded")
	}
	s2 := &Spool{Dir: s.Dir, Now: fixedNow(testTime)}
	again := mustWrite(t, s2, testDevice, testRead, `{}`)
	if _, err := s.Take(ctx, again); err != nil {
		t.Fatalf("watermark advanced by a failed confirm: %v", err)
	}
}

func TestDiscardRemovesCondemnedFile(t *testing.T) {
	s := newSpool(t)
	name := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("G", randomChars))
	if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(`garbage`), spoolFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(context.Background(), name); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Take err = %v", err)
	}
	if err := s.Discard(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if got := dirNames(t, s.Dir); len(got) != 0 {
		t.Fatalf("Discard left %v", got)
	}
}

func TestListOrdersByObservedAt(t *testing.T) {
	s := newSpool(t)
	ctx := context.Background()
	// Unix nanos of different digit counts sort numerically, not lexically.
	times := []time.Time{
		time.Unix(0, 10_000_000_000).UTC(),
		time.Unix(0, 9_999_999_999).UTC(),
		testTime,
		testTime.Add(-time.Second),
	}
	byTime := map[string]time.Time{}
	for _, ts := range times {
		w := &Spool{Dir: s.Dir, Now: fixedNow(ts)}
		byTime[mustWrite(t, w, testDevice, testRead, `{}`)] = ts
	}
	names, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(times) {
		t.Fatalf("List = %v", names)
	}
	for i := 1; i < len(names); i++ {
		if !byTime[names[i-1]].Before(byTime[names[i]]) {
			t.Fatalf("List not ordered by observed_at: %v", names)
		}
	}
}

func TestListSkipsForeignEntries(t *testing.T) {
	s := newSpool(t)
	name := mustWrite(t, s, testDevice, testRead, `{}`)
	if err := os.WriteFile(filepath.Join(s.Dir, "README"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	sub := fmt.Sprintf("%s-%s-%d-%s.json", testDevice, testRead, testTime.UnixNano(), strings.Repeat("H", randomChars))
	if err := os.Mkdir(filepath.Join(s.Dir, sub), 0o700); err != nil {
		t.Fatal(err)
	}
	names, err := s.List(context.Background())
	if err != nil || len(names) != 1 || names[0] != name {
		t.Fatalf("List = %v, %v; want [%s]", names, err, name)
	}
}

func TestConcurrentWritersNeverCollide(t *testing.T) {
	s := newSpool(t)
	s.Now = fixedNow(testTime) // worst case: every write in the same nanosecond
	const writers, perWriter = 8, 10
	var wg sync.WaitGroup
	names := make(chan string, writers*perWriter)
	errs := make(chan error, writers*perWriter)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				name, err := s.Write(context.Background(), testDevice, testRead, 1, false, fmt.Appendf(nil, `{"w":%d,"i":%d}`, w, i))
				if err != nil {
					errs <- err
					continue
				}
				names <- name
			}
		}()
	}
	wg.Wait()
	close(names)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Write: %v", err)
	}
	seen := map[string]bool{}
	for n := range names {
		if seen[n] {
			t.Fatalf("duplicate name %s", n)
		}
		seen[n] = true
	}
	listed, err := s.List(context.Background())
	if err != nil || len(listed) != writers*perWriter {
		t.Fatalf("List = %d names, %v; want %d", len(listed), err, writers*perWriter)
	}
	for _, n := range listed {
		taken, err := s.Take(context.Background(), n)
		if err != nil {
			t.Fatalf("Take(%s): %v", n, err)
		}
		if err := taken.Confirm(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWriteNeverOverwritesExistingName(t *testing.T) {
	s := newSpool(t)
	s.Now = fixedNow(testTime)
	fixed := strings.Repeat("Z", randomChars)
	randomText = func() string { return fixed }
	t.Cleanup(func() { randomText = defaultRandomText })
	first := mustWrite(t, s, testDevice, testRead, `{"n":1}`)
	if _, err := s.Write(context.Background(), testDevice, testRead, 1, false, []byte(`{"n":2}`)); !errors.Is(err, ErrExists) {
		t.Fatalf("second write err = %v, want ErrExists", err)
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, first))
	if err != nil || !bytes.Contains(raw, []byte(`{"n":1}`)) {
		t.Fatalf("existing file overwritten: %s, %v", raw, err)
	}
	if got := dirNames(t, s.Dir); len(got) != 1 {
		t.Fatalf("failed write left files: %v", got)
	}
}
