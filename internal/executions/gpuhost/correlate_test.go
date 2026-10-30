// SPDX-License-Identifier: AGPL-3.0-or-later

package gpuhost

import "testing"

func TestParseBusID(t *testing.T) {
	for s, want := range map[string]BusID{
		"0000:65:00.0":     {Domain: "0000", Bus: "65", Device: "00", Function: 0},
		"00000000:65:00.0": {Domain: "0000", Bus: "65", Device: "00", Function: 0},
		"65:00":            {Domain: "0000", Bus: "65", Device: "00", Function: -1},
		"65:00.3":          {Domain: "0000", Bus: "65", Device: "00", Function: 3},
		"1234:ab:cd.7":     {Domain: "1234", Bus: "ab", Device: "cd", Function: 7},
	} {
		got, err := ParseBusID(s)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", s, got, err)
		}
	}
	for _, bad := range []string{
		"", "65", "65:00.8", "0000:65:00.", "GGGG:65:00.0",
		"0000:65:00.0.1", " 65:00", "000000000:65:00.0", "0000:65",
	} {
		if _, err := ParseBusID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseHostPCITarget(t *testing.T) {
	for s, want := range map[string]HostPCITarget{
		"0000:65:00":               {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
		"0000:65:00.0":             {Domain: "0000", Bus: "65", Device: "00", FnLo: 0, FnHi: 0},
		"65:00":                    {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
		"65:00.0":                  {Domain: "0000", Bus: "65", Device: "00", FnLo: 0, FnHi: 0},
		"host0:0000:65:00":         {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
		"host1:65:00":              {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
		"pcieRoot1:0000:65:00":     {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
		"0000:65:00.0-0000:65:00.1": {Domain: "0000", Bus: "65", Device: "00", FnLo: 0, FnHi: 1},
		"0000:65:00,subfunction=1": {Domain: "0000", Bus: "65", Device: "00", FnLo: -1, FnHi: -1},
	} {
		got, err := ParseHostPCITarget(s)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", s, got, err)
		}
	}
	for _, bad := range []string{
		"", "65:00.0-65:01", "0000:65:00.1-0000:65:00.0", "0000:65:00-",
		"-0000:65:00", "0000:65:00.0-0000:66:00.0", "host:0000:65:00",
		"0000:65:00.0-",
	} {
		if _, err := ParseHostPCITarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHostPCITargetMatches(t *testing.T) {
	t65, err := ParseHostPCITarget("0000:65:00")
	if err != nil {
		t.Fatal(err)
	}
	t650, _ := ParseHostPCITarget("0000:65:00.0")
	trange, _ := ParseHostPCITarget("0000:65:00.0-0000:65:00.1")
	tshort, _ := ParseHostPCITarget("65:00")

	d650 := BusID{Domain: "0000", Bus: "65", Device: "00", Function: 0}
	d651 := BusID{Domain: "0000", Bus: "65", Device: "00", Function: 1}
	d652 := BusID{Domain: "0000", Bus: "65", Device: "00", Function: 2}
	d860 := BusID{Domain: "0000", Bus: "86", Device: "00", Function: 0}

	if !t65.Matches(d650) || !t65.Matches(d651) {
		t.Error("a whole-device target must match every function")
	}
	if !t650.Matches(d650) || t650.Matches(d651) {
		t.Error("a function target must match only its function")
	}
	if !trange.Matches(d650) || !trange.Matches(d651) || trange.Matches(d652) {
		t.Error("a range target must match only the functions in between")
	}
	if !tshort.Matches(d650) || t65.Matches(d860) {
		t.Error("bus or device mismatch must not match")
	}
}

// a6000Host is the correlation fixture: two RTX A6000 as seen by lspci
// (4-digit domain) and nvidia-smi (8-digit domain).
func a6000Host() (PCIInventory, GPUStatus) {
	inv := PCIInventory{Present: true, Devices: []PCIDevice{
		{Slot: "0000:65:00.0", Class: "3D controller", Vendor: "NVIDIA Corporation [10de]", Device: "GA102 [RTX A6000] [10de:2216]"},
		{Slot: "0000:86:00.0", Class: "3D controller", Vendor: "NVIDIA Corporation [10de]", Device: "GA102 [RTX A6000] [10de:2216]"},
	}}
	st := GPUStatus{Present: true, GPUs: []GPU{
		{Index: 0, UUID: "GPU-673e42ea-5685-7487-4d7e-045c914a4d51", PCIBusID: "00000000:65:00.0", Name: "NVIDIA RTX A6000"},
		{Index: 1, UUID: "GPU-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d", PCIBusID: "00000000:86:00.0", Name: "NVIDIA RTX A6000"},
	}}
	return inv, st
}

func TestGPUsForTarget(t *testing.T) {
	inv, st := a6000Host()
	// The 4-digit lspci domain and the 8-digit nvidia-smi domain must
	// correlate; every common target form refers to the same GPU.
	for _, target := range []string{"0000:65:00", "0000:65:00.0", "65:00", "host0:0000:65:00", "pcieRoot0:0000:65:00"} {
		gpus := GPUsForTarget(inv, st, target)
		if len(gpus) != 1 || gpus[0].Index != 0 {
			t.Errorf("%s: %+v", target, gpus)
		}
	}
	// A whole-device target with two GPU functions returns both.
	inv.Devices = append(inv.Devices, PCIDevice{Slot: "0000:65:00.1", Class: "3D controller", Vendor: "NVIDIA Corporation [10de]", Device: "GA102 [RTX A6000] [10de:2216]"})
	st.GPUs = append(st.GPUs, GPU{Index: 2, UUID: "GPU-99998888-7777-6666-5555-444433332222", PCIBusID: "00000000:65:00.1", Name: "NVIDIA RTX A6000"})
	if gpus := GPUsForTarget(inv, st, "0000:65:00"); len(gpus) != 2 {
		t.Fatalf("%+v", gpus)
	}
	// A PCI device without driver telemetry matches the target but has
	// no GPU to report: empty, not an error.
	inv2 := PCIInventory{Present: true, Devices: []PCIDevice{
		{Slot: "0000:aa:00.0", Class: "3D controller", Vendor: "NVIDIA Corporation [10de]", Device: "GA102 [RTX A6000] [10de:2216]"},
	}}
	if gpus := GPUsForTarget(inv2, st, "0000:aa:00"); len(gpus) != 0 {
		t.Fatalf("%+v", gpus)
	}
	// An invalid target matches nothing and does not panic.
	if gpus := GPUsForTarget(inv, st, "not-a-bus-id"); len(gpus) != 0 {
		t.Fatalf("%+v", gpus)
	}
}

func TestGPUForSlot(t *testing.T) {
	_, st := a6000Host()
	if g, ok := st.GPUForSlot("0000:65:00.0"); !ok || g.Index != 0 {
		t.Fatalf("%+v %v", g, ok)
	}
	if g, ok := st.GPUForSlot("0000:86:00.0"); !ok || g.Index != 1 {
		t.Fatalf("%+v %v", g, ok)
	}
	if _, ok := st.GPUForSlot("0000:aa:00.0"); ok {
		t.Fatal("a slot without a GPU must not match")
	}
	if _, ok := st.GPUForSlot("bad"); ok {
		t.Fatal("an invalid slot must not match")
	}
}
