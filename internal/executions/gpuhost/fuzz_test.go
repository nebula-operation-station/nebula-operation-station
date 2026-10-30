// SPDX-License-Identifier: AGPL-3.0-or-later

package gpuhost

import (
	"os"
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
			if g.PowerW != nil && (*g.PowerW < 0 || *g.PowerW > maxPowerW) {
				t.Fatalf("power %v W outside [0, %v]", *g.PowerW, maxPowerW)
			}
		}
	})
}
