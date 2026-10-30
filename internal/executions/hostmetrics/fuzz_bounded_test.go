// SPDX-License-Identifier: AGPL-3.0-or-later

package hostmetrics

import (
	"math"
	"os"
	"testing"
)

// hostFuzzSeeds returns the golden result documents named by the caller,
// used to seed the fuzz corpora with realistic host output. A missing
// committed fixture is a test setup failure, so it panics.
func hostFuzzSeeds(names ...string) [][]byte {
	var seeds [][]byte
	for _, n := range names {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			panic("missing golden fuzz seed " + n + ": " + err.Error())
		}
		seeds = append(seeds, b)
	}
	return seeds
}

// FuzzParseMetricsBounds feeds arbitrary bytes to the host.metrics parser
// and asserts the result stays within its bounds: no panic, a known
// phase, every available reading inside its range, and an unavailable
// reading indistinguishable from nothing (zero), never a guessed value.
func FuzzParseMetricsBounds(f *testing.F) {
	for _, s := range hostFuzzSeeds("debian-metrics.json", "proxmox-metrics.json", "ubuntu-metrics.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"host-metrics-v1","phase":"precheck","reason":"no /proc/stat"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMetrics(b)
		if err != nil {
			return
		}
		if m.Phase != "done" && m.Phase != "precheck" {
			t.Fatalf("unknown phase %q", m.Phase)
		}
		if len(m.Reason) > maxReasonLen {
			t.Fatalf("reason is %d bytes, bound is %d", len(m.Reason), maxReasonLen)
		}
		if m.CPU.Available {
			if fuzzFloatOutsideRange(m.CPU.Percent, 100) {
				t.Fatalf("cpu percent %v outside [0, 100]", m.CPU.Percent)
			}
		} else if m.CPU.Percent != 0 {
			t.Fatalf("unavailable cpu carries percent %v", m.CPU.Percent)
		}
		if m.Load.Available {
			for _, v := range []float64{m.Load.Min1, m.Load.Min5, m.Load.Min15} {
				if fuzzFloatOutsideRange(v, maxLoad) {
					t.Fatalf("load value %v outside [0, %d]", v, maxLoad)
				}
			}
		} else if m.Load.Min1 != 0 || m.Load.Min5 != 0 || m.Load.Min15 != 0 {
			t.Fatalf("unavailable load carries %v %v %v", m.Load.Min1, m.Load.Min5, m.Load.Min15)
		}
		if m.Mem.Available {
			if m.Mem.TotalBytes == 0 || m.Mem.TotalBytes > maxBytes || m.Mem.UsedBytes > m.Mem.TotalBytes {
				t.Fatalf("mem used %d / total %d violates its bounds", m.Mem.UsedBytes, m.Mem.TotalBytes)
			}
		} else if m.Mem.UsedBytes != 0 || m.Mem.TotalBytes != 0 {
			t.Fatalf("unavailable mem carries %d / %d", m.Mem.UsedBytes, m.Mem.TotalBytes)
		}
		if m.Disk.Available {
			if !printable(m.Disk.Mount, maxMountLen) {
				t.Fatalf("disk mount %q violates its bounds", m.Disk.Mount)
			}
			if m.Disk.TotalBytes == 0 || m.Disk.TotalBytes > maxBytes || m.Disk.UsedBytes > m.Disk.TotalBytes {
				t.Fatalf("disk used %d / total %d violates its bounds", m.Disk.UsedBytes, m.Disk.TotalBytes)
			}
			if fuzzFloatOutsideRange(m.Disk.Percent, 100) {
				t.Fatalf("disk percent %v outside [0, 100]", m.Disk.Percent)
			}
		} else if m.Disk.Mount != "" || m.Disk.UsedBytes != 0 || m.Disk.TotalBytes != 0 || m.Disk.Percent != 0 {
			t.Fatalf("unavailable disk carries %+v", m.Disk)
		}
	})
}

// FuzzParseFilesystemsBounds feeds arbitrary bytes to the filesystem.list
// parser and asserts the result stays within its bounds: no panic, at
// most maxMounts real mounts, every mount inside its patterns and
// ranges, and virtual filesystems never reported as real storage.
func FuzzParseFilesystemsBounds(f *testing.F) {
	for _, s := range hostFuzzSeeds("debian-fs.json", "proxmox-fs.json", "ubuntu-fs.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"fs-list-v1","phase":"precheck","reason":"no df"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fs, err := ParseFilesystems(b)
		if err != nil {
			return
		}
		if fs.Phase != "done" && fs.Phase != "precheck" {
			t.Fatalf("unknown phase %q", fs.Phase)
		}
		if len(fs.Reason) > maxReasonLen {
			t.Fatalf("reason is %d bytes, bound is %d", len(fs.Reason), maxReasonLen)
		}
		if len(fs.Mounts) > maxMounts {
			t.Fatalf("filesystem list has %d mounts, bound is %d", len(fs.Mounts), maxMounts)
		}
		for _, m := range fs.Mounts {
			if !printable(m.FSType, maxFSTypeLen) || pseudoFilesystems[m.FSType] {
				t.Fatalf("mount fstype %q violates its bounds or is virtual", m.FSType)
			}
			if !printable(m.Mount, maxMountLen) {
				t.Fatalf("mount point %q violates its bounds", m.Mount)
			}
			if m.SizeBytes == 0 || m.SizeBytes > maxBytes || m.UsedBytes > m.SizeBytes {
				t.Fatalf("mount used %d / size %d violates its bounds", m.UsedBytes, m.SizeBytes)
			}
			if fuzzFloatOutsideRange(m.Percent, 100) {
				t.Fatalf("mount percent %v outside [0, 100]", m.Percent)
			}
		}
	})
}

func fuzzFloatOutsideRange(v, max float64) bool {
	return math.IsNaN(v) || v < 0 || v > max
}

func TestFuzzFloatRangeRejectsNonfinite(t *testing.T) {
	for _, max := range []float64{100, maxLoad} {
		for _, tc := range []struct {
			name    string
			value   float64
			outside bool
		}{
			{"NaN", math.NaN(), true},
			{"positive infinity", math.Inf(1), true},
			{"negative infinity", math.Inf(-1), true},
			{"negative", -1, true},
			{"above maximum", max + 1, true},
			{"zero", 0, false},
			{"maximum", max, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := fuzzFloatOutsideRange(tc.value, max); got != tc.outside {
					t.Errorf("range [0, %v], value %v: outside = %v, want %v", max, tc.value, got, tc.outside)
				}
			})
		}
	}
}
