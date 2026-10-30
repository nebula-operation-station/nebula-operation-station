// SPDX-License-Identifier: AGPL-3.0-or-later

package gpuhost

import (
	"math"
	"os"
	"strings"
	"testing"
)

// gpuFuzzSeeds returns the golden result documents named by the caller,
// used to seed the fuzz corpora with realistic host output. A missing
// committed fixture is a test setup failure, so it panics.
func gpuFuzzSeeds(names ...string) [][]byte {
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

// FuzzParsePCIInventory feeds arbitrary bytes to the pci.inventory parser.
// The parser must never panic, must keep the device list within its
// bound, and must keep every kept device inside its patterns: a line
// that is not an NVIDIA display or 3D controller is dropped, not
// guessed.
func FuzzParsePCIInventory(f *testing.F) {
	for _, s := range gpuFuzzSeeds("pci-a6000x2.json", "pci-none.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"pci-inventory-v1","phase":"precheck","reason":"no lspci"}`))
	f.Add([]byte(`{"format":"pci-inventory-v1","phase":"done","present":false}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		inv, err := ParsePCIInventory(b)
		if err != nil {
			return
		}
		if len(inv.Devices) > maxDevices {
			t.Fatalf("inventory has %d devices, bound is %d", len(inv.Devices), maxDevices)
		}
		for _, d := range inv.Devices {
			if !slotRe.MatchString(d.Slot) {
				t.Fatalf("slot %q is not an lspci slot with domain", d.Slot)
			}
			if !isGPUClass(d.Class) {
				t.Fatalf("class %q is not an NVIDIA display or 3D controller", d.Class)
			}
			if !isNVIDIA(d.Vendor) || !printable(d.Vendor, maxNameLen) {
				t.Fatalf("vendor %q violates its bounds", d.Vendor)
			}
			if !printable(d.Device, maxNameLen) {
				t.Fatalf("device %q violates its bounds", d.Device)
			}
		}
	})
}

// FuzzParseGPUStatus feeds arbitrary bytes to the gpu.status parser. The
// parser must never panic, must keep the GPU list within its bound, and
// must keep every metric inside its range: a metric nvidia-smi reported
// as [N/A] is nil (unavailable), never a guessed zero.
func FuzzParseGPUStatus(f *testing.F) {
	for _, s := range gpuFuzzSeeds("gpu-a6000x2.json", "gpu-nodriver.json", "gpu-none.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"gpu-status-v1","phase":"precheck","reason":"no nvidia-smi"}`))
	f.Add([]byte(`{"format":"gpu-status-v1","phase":"done","present":false}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ParseGPUStatus(b)
		if err != nil {
			return
		}
		if len(st.GPUs) > maxGPUs {
			t.Fatalf("status has %d GPUs, bound is %d", len(st.GPUs), maxGPUs)
		}
		for _, g := range st.GPUs {
			if g.Index < 0 || g.Index > maxIndex {
				t.Fatalf("GPU index %d outside [0, %d]", g.Index, maxIndex)
			}
			if !uuidRe.MatchString(g.UUID) {
				t.Fatalf("UUID %q is not an NVIDIA GPU UUID", g.UUID)
			}
			if !nvidiaBusRe.MatchString(g.PCIBusID) {
				t.Fatalf("bus ID %q is not an nvidia-smi pci.bus_id", g.PCIBusID)
			}
			if !printable(g.Name, maxNameLen) {
				t.Fatalf("name %q violates its bounds", g.Name)
			}
			if g.UtilPercent != nil && (*g.UtilPercent < 0 || *g.UtilPercent > maxUtil) {
				t.Fatalf("utilization %d outside [0, %d]", *g.UtilPercent, maxUtil)
			}
			for _, m := range []*int{g.MemoryUsedMiB, g.MemoryTotalMiB} {
				if m != nil && (*m < 0 || *m > maxMemoryMiB) {
					t.Fatalf("memory %d MiB outside [0, %d]", *m, maxMemoryMiB)
				}
			}
			if g.TemperatureC != nil && (*g.TemperatureC < 0 || *g.TemperatureC > maxTempC) {
				t.Fatalf("temperature %d outside [0, %d]", *g.TemperatureC, maxTempC)
			}
			if g.PowerW != nil && fuzzFloatOutsideRange(*g.PowerW, maxPowerW) {
				t.Fatalf("power %v W outside [0, %v]", *g.PowerW, maxPowerW)
			}
		}
	})
}

func fuzzFloatOutsideRange(v, max float64) bool {
	return math.IsNaN(v) || v < 0 || v > max
}

func TestFuzzFloatRangeRejectsNonfinite(t *testing.T) {
	for _, max := range []float64{maxPowerW} {
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

// FuzzParseGPUStatusUnavailable builds valid payloads so unavailable metrics
// cannot escape the oracle through malformed input or a dropped GPU row.
func FuzzParseGPUStatusUnavailable(f *testing.F) {
	const metricCount = 5
	// Seed every availability combination, including real zeros and all [N/A].
	for mask := uint8(0); mask < 1<<metricCount; mask++ {
		f.Add(mask)
	}
	f.Fuzz(func(t *testing.T, mask uint8) {
		fields := []string{
			"0", "GPU-673e42ea-5685-7487-4d7e-045c914a4d51",
			"00000000:65:00.0", "NVIDIA RTX A6000",
			"0", "0", "0", "0", "0",
		}
		for i := 0; i < metricCount; i++ {
			if mask&(1<<i) != 0 {
				fields[4+i] = "[N/A]"
			}
		}
		st, err := ParseGPUStatus(gpuDoc(strings.Join(fields, ", ")))
		if err != nil || len(st.GPUs) != 1 {
			t.Fatalf("valid GPU with availability mask %05b was rejected: %+v, %v", mask, st, err)
		}
		g := st.GPUs[0]
		unavailable := []bool{
			g.UtilPercent == nil, g.MemoryUsedMiB == nil,
			g.MemoryTotalMiB == nil, g.TemperatureC == nil, g.PowerW == nil,
		}
		for i, got := range unavailable {
			want := mask&(1<<i) != 0
			if got != want {
				t.Errorf("metric column %d (%q): nil = %v, want %v", 4+i, fields[4+i], got, want)
			}
		}
	})
}
