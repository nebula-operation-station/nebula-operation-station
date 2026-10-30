// SPDX-License-Identifier: AGPL-3.0-or-later
package hostmetrics

import (
	"encoding/base64"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func metricsDoc(cpu, load, mem, disk string) []byte {
	return []byte(`{"format":"host-metrics-v1","phase":"done","cpu":"` + b64(cpu) +
		`","load":"` + b64(load) + `","mem":"` + b64(mem) + `","disk":"` + b64(disk) + `"}`)
}

func fsDoc(mounts string) []byte {
	return []byte(`{"format":"fs-list-v1","phase":"done","mounts":"` + b64(mounts) + `"}`)
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestParseMetricsFixtures(t *testing.T) {
	for _, tc := range []struct {
		file string
		cpu  CPUStat
		load LoadStat
		mem  MemStat
		disk DiskStat
	}{
		{
			file: "debian-metrics.json",
			cpu:  CPUStat{Available: true, Percent: 12.5},
			load: LoadStat{Available: true, Min1: 0.42, Min5: 0.38, Min15: 0.33},
			mem:  MemStat{Available: true, UsedBytes: 3221225472, TotalBytes: 16106127360},
			disk: DiskStat{Available: true, Mount: "/", UsedBytes: 128849018880, TotalBytes: 315926315008, Percent: 100.0 * 128849018880 / 315926315008},
		},
		{
			file: "ubuntu-metrics.json",
			cpu:  CPUStat{Available: true, Percent: 3.0},
			load: LoadStat{Available: true, Min1: 0.19, Min5: 0.67, Min15: 1.50},
			mem:  MemStat{Available: true, UsedBytes: 2485444608, TotalBytes: 8326938624},
			disk: DiskStat{Available: true, Mount: "/", UsedBytes: 38061268992, TotalBytes: 40483942400, Percent: 100.0 * 38061268992 / 40483942400},
		},
		{
			file: "proxmox-metrics.json",
			cpu:  CPUStat{Available: true, Percent: 22.0},
			load: LoadStat{Available: true, Min1: 1.25, Min5: 1.10, Min15: 0.95},
			mem:  MemStat{Available: true, UsedBytes: 137438953472, TotalBytes: 257698037752},
			disk: DiskStat{Available: true, Mount: "/var/lib/vz", UsedBytes: 644245094400, TotalBytes: 1099511627776, Percent: 100.0 * 644245094400 / 1099511627776},
		},
	} {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			m, err := ParseMetrics(raw)
			if err != nil {
				t.Fatalf("ParseMetrics: %v", err)
			}
			if m.Phase != "done" {
				t.Errorf("phase = %q, want done", m.Phase)
			}
			if m.CPU != tc.cpu {
				t.Errorf("cpu = %+v, want %+v", m.CPU, tc.cpu)
			}
			if m.Load != tc.load {
				t.Errorf("load = %+v, want %+v", m.Load, tc.load)
			}
			if m.Mem != tc.mem {
				t.Errorf("mem = %+v, want %+v", m.Mem, tc.mem)
			}
			if m.Disk.Available != tc.disk.Available || m.Disk.Mount != tc.disk.Mount ||
				m.Disk.UsedBytes != tc.disk.UsedBytes || m.Disk.TotalBytes != tc.disk.TotalBytes ||
				!approx(m.Disk.Percent, tc.disk.Percent) {
				t.Errorf("disk = %+v, want %+v", m.Disk, tc.disk)
			}
		})
	}
}

func TestParseFilesystemsFixtures(t *testing.T) {
	for _, tc := range []struct {
		file    string
		want    []Mount
		fullest string
	}{
		{
			file: "debian-fs.json",
			want: []Mount{
				{FSType: "ext4", Mount: "/", SizeBytes: 315926315008, UsedBytes: 128849018880, Percent: 100.0 * 128849018880 / 315926315008},
				{FSType: "ext4", Mount: "/boot", SizeBytes: 1030792192, UsedBytes: 241172480, Percent: 100.0 * 241172480 / 1030792192},
			},
			fullest: "/",
		},
		{
			file: "ubuntu-fs.json",
			want: []Mount{
				{FSType: "ext4", Mount: "/", SizeBytes: 40483942400, UsedBytes: 38061268992, Percent: 100.0 * 38061268992 / 40483942400},
				{FSType: "ext4", Mount: "/boot", SizeBytes: 923156480, UsedBytes: 122290176, Percent: 100.0 * 122290176 / 923156480},
				{FSType: "vfat", Mount: "/boot/efi", SizeBytes: 109395456, UsedBytes: 6399488, Percent: 100.0 * 6399488 / 109395456},
				{FSType: "ext4", Mount: "/data/sftp/upload/hermes-out/Musik", SizeBytes: 315926315008, UsedBytes: 20870414336, Percent: 100.0 * 20870414336 / 315926315008},
			},
			fullest: "/",
		},
		{
			file: "proxmox-fs.json",
			want: []Mount{
				{FSType: "ext4", Mount: "/", SizeBytes: 1099511627776, UsedBytes: 219902325555, Percent: 20},
				{FSType: "ext4", Mount: "/boot", SizeBytes: 1030792192, UsedBytes: 241172480, Percent: 100.0 * 241172480 / 1030792192},
				{FSType: "xfs", Mount: "/var/lib/vz", SizeBytes: 1099511627776, UsedBytes: 644245094400, Percent: 100.0 * 644245094400 / 1099511627776},
			},
			fullest: "/var/lib/vz",
		},
	} {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			fs, err := ParseFilesystems(raw)
			if err != nil {
				t.Fatalf("ParseFilesystems: %v", err)
			}
			if !fs.Available {
				t.Fatalf("available = false, want true")
			}
			if len(fs.Mounts) != len(tc.want) {
				t.Fatalf("got %d mounts %+v, want %d", len(fs.Mounts), fs.Mounts, len(tc.want))
			}
			for i := range tc.want {
				if fs.Mounts[i].FSType != tc.want[i].FSType || fs.Mounts[i].Mount != tc.want[i].Mount ||
					fs.Mounts[i].SizeBytes != tc.want[i].SizeBytes || fs.Mounts[i].UsedBytes != tc.want[i].UsedBytes ||
					!approx(fs.Mounts[i].Percent, tc.want[i].Percent) {
					t.Errorf("mount[%d] = %+v, want %+v", i, fs.Mounts[i], tc.want[i])
				}
			}
			best, ok := fs.Fullest()
			if !ok || best.Mount != tc.fullest {
				t.Errorf("fullest = %q (ok=%v), want %q", best.Mount, ok, tc.fullest)
			}
		})
	}
}

func TestParseMetricsUnavailableDistinctFromZero(t *testing.T) {
	// Empty fields are unavailable; real zeros are available.
	m, err := ParseMetrics(metricsDoc("", "", "", ""))
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}
	if m.CPU.Available || m.Load.Available || m.Mem.Available || m.Disk.Available {
		t.Errorf("empty doc: %+v, want all unavailable", m)
	}

	m, err = ParseMetrics(metricsDoc("0.0", "0 0 0", "0 1000", "/\t0\t1000"))
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}
	if !m.CPU.Available || m.CPU.Percent != 0 {
		t.Errorf("cpu = %+v, want available 0", m.CPU)
	}
	if !m.Load.Available || m.Load.Min1 != 0 || m.Load.Min5 != 0 || m.Load.Min15 != 0 {
		t.Errorf("load = %+v, want available zeros", m.Load)
	}
	if !m.Mem.Available || m.Mem.UsedBytes != 0 || m.Mem.TotalBytes != 1000 {
		t.Errorf("mem = %+v, want available used=0 total=1000", m.Mem)
	}
	if !m.Disk.Available || m.Disk.UsedBytes != 0 || m.Disk.TotalBytes != 1000 || m.Disk.Percent != 0 {
		t.Errorf("disk = %+v, want available used=0 total=1000", m.Disk)
	}
}

func TestParseMetricsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		doc     []byte
		wantErr bool
	}{
		{"bad json", []byte(`{"format":"host-metrics-v1"`), true},
		{"wrong format", []byte(`{"format":"host-metrics-v2","phase":"done"}`), true},
		{"unknown phase", []byte(`{"format":"host-metrics-v1","phase":"weird"}`), true},
		{"bad base64", []byte(`{"format":"host-metrics-v1","phase":"done","cpu":"!!!"}`), true},
		{"non-utf8", []byte(`{"format":"host-metrics-v1","phase":"done","disk":"` + b64("/\t1\t2") + `","mem":"` + base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe}) + `"}`), true},
		// A malformed number in one field is unavailable, not an error.
		{"cpu not a number", metricsDoc("abc", "0 0 0", "1 2", "/\t1\t2"), false},
		{"cpu out of range", metricsDoc("101", "", "", ""), false},
		{"cpu negative", metricsDoc("-1", "", "", ""), false},
		{"cpu inf", metricsDoc("1e400", "", "", ""), false},
		{"load wrong count", metricsDoc("", "0 0", "", ""), false},
		{"mem used over total", metricsDoc("", "", "2000 1000", ""), false},
		{"mem total zero", metricsDoc("", "", "0 0", ""), false},
		{"disk wrong fields", metricsDoc("", "", "", "/\t1"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseMetrics(tc.doc)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseMetrics = %+v, want error", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMetrics: %v", err)
			}
			want := Metrics{Phase: "done"}
			if tc.name == "cpu not a number" {
				want.Load = LoadStat{Available: true}
				want.Mem = MemStat{Available: true, UsedBytes: 1, TotalBytes: 2}
				want.Disk = DiskStat{Available: true, Mount: "/", UsedBytes: 1, TotalBytes: 2, Percent: 50}
			}
			if m != want {
				t.Errorf("metrics = %+v, want %+v", m, want)
			}
		})
	}
}

func TestParseMetricsOversizeRejected(t *testing.T) {
	huge := strings.Repeat("a", maxRawSize+1)
	if _, err := ParseMetrics(metricsDoc(huge, "", "", "")); err == nil {
		t.Fatal("oversize cpu accepted, want error")
	}
}

func TestParseMetricsRejectsUnsafeMount(t *testing.T) {
	for _, mount := range []string{"/a\nb", "/a\x7fb", "/a\rb", "	/x", "/a\x00b"} {
		m, err := ParseMetrics(metricsDoc("", "", "", mount+"\t1\t2"))
		if err != nil {
			t.Fatalf("ParseMetrics(%q): %v", mount, err)
		}
		if m.Disk.Available {
			t.Errorf("mount %q accepted, want unavailable", mount)
		}
	}
}

func TestParseFilesystemsUnavailableVsEmpty(t *testing.T) {
	// No mount lines at all: df produced nothing => unavailable.
	fs, err := ParseFilesystems(fsDoc(""))
	if err != nil {
		t.Fatalf("ParseFilesystems: %v", err)
	}
	if fs.Available || len(fs.Mounts) != 0 {
		t.Errorf("empty doc = %+v, want unavailable and no mounts", fs)
	}

	// Only virtual filesystems: available, but the real list is empty.
	fs, err = ParseFilesystems(fsDoc("proc\t/proc\t0\t0\ntmpfs\t/run\t1000\t10\nsysfs\t/sys\t0\t0"))
	if err != nil {
		t.Fatalf("ParseFilesystems: %v", err)
	}
	if !fs.Available {
		t.Errorf("virtual-only doc available = false, want true")
	}
	if len(fs.Mounts) != 0 {
		t.Errorf("virtual-only doc = %+v, want no real mounts", fs.Mounts)
	}
}

func TestParseFilesystemsExcludesPseudoByExplicitList(t *testing.T) {
	// Each fstype in the explicit list must be dropped even with size > 0.
	for fstype := range pseudoFilesystems {
		fs, err := ParseFilesystems(fsDoc(fstype + "\t/mnt\t1000\t10"))
		if err != nil {
			t.Fatalf("ParseFilesystems(%s): %v", fstype, err)
		}
		if len(fs.Mounts) != 0 {
			t.Errorf("fstype %s kept, want dropped: %+v", fstype, fs.Mounts)
		}
	}
	// A real fstype not in the list must be kept.
	for _, fstype := range []string{"ext4", "xfs", "btrfs", "zfs", "vfat", "ntfs"} {
		fs, err := ParseFilesystems(fsDoc(fstype + "\t/mnt\t1000\t10"))
		if err != nil {
			t.Fatalf("ParseFilesystems(%s): %v", fstype, err)
		}
		if len(fs.Mounts) != 1 {
			t.Errorf("fstype %s dropped, want kept: %+v", fstype, fs.Mounts)
		}
	}
}

func TestParseFilesystemsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		doc     []byte
		wantErr bool
	}{
		{"bad json", []byte(`{"format":"fs-list-v1"`), true},
		{"wrong format", []byte(`{"format":"fs-list-v2","phase":"done"}`), true},
		{"unknown phase", []byte(`{"format":"fs-list-v1","phase":"weird"}`), true},
		{"bad base64", []byte(`{"format":"fs-list-v1","phase":"done","mounts":"!!!"}`), true},
		// Malformed lines are dropped and make the listing unavailable.
		{"short line", fsDoc("ext4\t/\t1000"), false},
		{"long line", fsDoc("ext4\t/\t1000\t10\textra"), false},
		{"size zero", fsDoc("ext4\t/\t0\t10"), false},
		{"used over size", fsDoc("ext4\t/\t1000\t2000"), false},
		{"non-numeric size", fsDoc("ext4\t/\tbig\t10"), false},
		{"unsafe mount", fsDoc("ext4\t/a\nb\t1000\t10"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := ParseFilesystems(tc.doc)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseFilesystems = %+v, want error", fs)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFilesystems: %v", err)
			}
			if fs.Available || len(fs.Mounts) != 0 {
				t.Errorf("malformed listing = %+v, want unavailable and no mounts", fs)
			}
		})
	}
}

func TestParseFilesystemsTooManyMounts(t *testing.T) {
	var lines []string
	for i := 0; i < maxMounts+1; i++ {
		lines = append(lines, "ext4	/mnt"+string(rune('a'+i%26))+"	1000	10")
	}
	if _, err := ParseFilesystems(fsDoc(strings.Join(lines, "\n"))); err == nil {
		t.Fatal("too many mounts accepted, want error")
	}
}

func TestParseFilesystemsOversizeRejected(t *testing.T) {
	huge := strings.Repeat("ext4\t/x\t1000\t10\n", maxRawSize)
	if _, err := ParseFilesystems(fsDoc(huge)); err == nil {
		t.Fatal("oversize mounts accepted, want error")
	}
}

func TestMemPercent(t *testing.T) {
	if got := (MemStat{}).Percent(); got != 0 {
		t.Errorf("unavailable percent = %v, want 0", got)
	}
	if got := (MemStat{Available: true, UsedBytes: 500, TotalBytes: 1000}).Percent(); !approx(got, 50) {
		t.Errorf("percent = %v, want 50", got)
	}
}

func TestFullestEmpty(t *testing.T) {
	if _, ok := (Filesystems{}).Fullest(); ok {
		t.Error("Fullest on empty = ok, want false")
	}
}

func TestParsersBoundDocumentsBeforeUnmarshal(t *testing.T) {
	// Invalid JSON makes the size error prove rejection precedes unmarshalling.
	doc := []byte(strings.Repeat("!", 8<<20))
	if _, err := ParseMetrics(doc); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversize metrics: %v, want size rejection", err)
	}
	if _, err := ParseFilesystems(doc); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversize filesystems: %v, want size rejection", err)
	}
}

func TestDecodeTextBoundsEncodedInputBeforeDecoding(t *testing.T) {
	for _, limit := range []int{maxReasonLen, maxRawSize} {
		// Invalid base64 distinguishes the size guard from the decoder error.
		field := strings.Repeat("!", base64.StdEncoding.EncodedLen(limit)+1)
		if _, err := decodeText(field, limit); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("limit %d: %v, want size rejection", limit, err)
		}
		text := strings.Repeat("x", limit)
		if got, err := decodeText(b64(text), limit); err != nil || got != text {
			t.Errorf("limit %d: boundary value rejected: %v", limit, err)
		}
		// The encoded length alone cannot catch padding at the decoded boundary.
		if _, err := decodeText(b64(text+"x"), limit); err == nil {
			t.Errorf("limit %d: oversized decoded value accepted", limit)
		}
	}
}

func TestParseMetricsMalformedPreservesValidReadings(t *testing.T) {
	valid := []string{"25", "1 2 3", "1 2", "/\t1\t2"}
	want := Metrics{Phase: "done", CPU: CPUStat{Available: true, Percent: 25},
		Load: LoadStat{Available: true, Min1: 1, Min5: 2, Min15: 3},
		Mem:  MemStat{Available: true, UsedBytes: 1, TotalBytes: 2},
		Disk: DiskStat{Available: true, Mount: "/", UsedBytes: 1, TotalBytes: 2, Percent: 50}}
	for i, values := range [][]string{
		{"abc", "NaN", "Inf", "-1", "101"},
		{"0 0", "NaN 0 0", "0 -1 0", "0 0 1048577"},
		{"0 0", "3 2", "-1 2", "1 4611686018427387905"},
		{"/\t1", "/\t3\t2", "/\t-1\t2", "/\t1\t4611686018427387905"},
	} {
		for _, value := range values {
			fields := append([]string(nil), valid...)
			fields[i] = value
			m, err := ParseMetrics(metricsDoc(fields[0], fields[1], fields[2], fields[3]))
			if err != nil {
				t.Fatalf("field %d value %q: %v", i, value, err)
			}
			expected := want
			switch i {
			case 0:
				expected.CPU = CPUStat{}
			case 1:
				expected.Load = LoadStat{}
			case 2:
				expected.Mem = MemStat{}
			case 3:
				expected.Disk = DiskStat{}
			}
			if m != expected {
				t.Errorf("field %d value %q: got %+v, want %+v", i, value, m, expected)
			}
		}
	}
}

func TestParseFilesystemsMalformedRowsPreserveValidMounts(t *testing.T) {
	for _, row := range []string{
		"ext4\t/bad\t1000", "ext4\t/bad\t0\t0", "ext4\t/bad\t1000\t2000",
		"ext4\t/bad\tbig\t10", "ext4\t/bad\t1000\t-1", "tmpfs\t/run\tbad\t0",
		"tmpfs\t/run\t1000\t10\textra",
	} {
		fs, err := ParseFilesystems(fsDoc("ext4\t/good\t1000\t10\n" + row + "\nxfs\t/also-good\t2000\t0"))
		if err != nil {
			t.Fatalf("row %q: %v", row, err)
		}
		if fs.Available || len(fs.Mounts) != 2 {
			t.Fatalf("row %q: %+v, want incomplete listing with two valid mounts", row, fs)
		}
		if fs.Mounts[0] != (Mount{FSType: "ext4", Mount: "/good", SizeBytes: 1000, UsedBytes: 10, Percent: 1}) ||
			fs.Mounts[1] != (Mount{FSType: "xfs", Mount: "/also-good", SizeBytes: 2000}) {
			t.Errorf("row %q: valid mounts changed: %+v", row, fs.Mounts)
		}
	}
}
