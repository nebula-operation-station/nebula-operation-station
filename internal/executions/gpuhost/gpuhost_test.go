// SPDX-License-Identifier: AGPL-3.0-or-later

package gpuhost

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// enc base64-encodes a payload the way the action scripts store it.
func enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// gpuDoc wraps GPU CSV lines in a gpu.status result document.
func gpuDoc(gpus string) []byte {
	return []byte(`{"format":"gpu-status-v1","phase":"done","present":true,"gpus":"` + enc(gpus) + `"}`)
}

// pciDoc wraps device lines in a pci.inventory result document.
func pciDoc(devices string) []byte {
	return []byte(`{"format":"pci-inventory-v1","phase":"done","present":true,"devices":"` + enc(devices) + `"}`)
}

// testdata/pci-a6000x2.json is a pci.inventory result from a bare-metal
// node with two RTX A6000 (the Intel devices of the same lspci run must
// not appear).
func TestParseRealPCIInventory(t *testing.T) {
	b, err := os.ReadFile("testdata/pci-a6000x2.json")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ParsePCIInventory(b)
	if err != nil || !inv.Present || len(inv.Devices) != 2 {
		t.Fatalf("%+v %v", inv, err)
	}
	d := inv.Devices[0]
	if d.Slot != "0000:65:00.0" || d.Class != "3D controller" ||
		d.Vendor != "NVIDIA Corporation [10de]" || d.Device != "GA102 [RTX A6000] [10de:2216]" {
		t.Fatalf("%+v", d)
	}
	if inv.Devices[1].Slot != "0000:86:00.0" {
		t.Fatalf("%+v", inv.Devices[1])
	}
}

// testdata/pci-none.json is a pci.inventory result from a host without
// an NVIDIA device: present, empty. Empty is not unavailable.
func TestParsePCIInventoryNone(t *testing.T) {
	b, err := os.ReadFile("testdata/pci-none.json")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ParsePCIInventory(b)
	if err != nil || !inv.Present || inv.Phase != "done" || len(inv.Devices) != 0 {
		t.Fatalf("%+v %v", inv, err)
	}
}

// testdata/gpu-a6000x2.json is a gpu.status result from the same node:
// two GPUs, per-GPU UUID and PCI identity, one of them idle (real zeros).
func TestParseRealGPUStatus(t *testing.T) {
	b, err := os.ReadFile("testdata/gpu-a6000x2.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseGPUStatus(b)
	if err != nil || !st.Present || len(st.GPUs) != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	g := st.GPUs[0]
	if g.Index != 0 || g.UUID != "GPU-673e42ea-5685-7487-4d7e-045c914a4d51" ||
		g.PCIBusID != "00000000:65:00.0" || g.Name != "NVIDIA RTX A6000" ||
		g.UtilPercent == nil || *g.UtilPercent != 12 ||
		g.MemoryUsedMiB == nil || *g.MemoryUsedMiB != 34567 ||
		g.MemoryTotalMiB == nil || *g.MemoryTotalMiB != 49140 ||
		g.TemperatureC == nil || *g.TemperatureC != 45 ||
		g.PowerW == nil || *g.PowerW != 123.45 {
		t.Fatalf("%+v", g)
	}
	g1 := st.GPUs[1]
	if g1.Index != 1 || g1.PCIBusID != "00000000:86:00.0" ||
		g1.UtilPercent == nil || *g1.UtilPercent != 0 ||
		g1.PowerW == nil || *g1.PowerW != 55.10 {
		t.Fatalf("%+v", g1)
	}
}

// testdata/gpu-nodriver.json: nvidia-smi is installed, the driver is not
// loaded. That is unavailable with a reason, not an empty GPU list.
func TestParseGPUStatusDriverMissing(t *testing.T) {
	b, err := os.ReadFile("testdata/gpu-nodriver.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseGPUStatus(b)
	if err != nil || st.Phase != "precheck" || st.Reason == "" || st.Present || len(st.GPUs) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
}

// testdata/gpu-none.json: no nvidia-smi on the host at all.
func TestParseGPUStatusNone(t *testing.T) {
	b, err := os.ReadFile("testdata/gpu-none.json")
	if err != nil {
		t.Fatal(err)
	}
	st, err := ParseGPUStatus(b)
	if err != nil || st.Phase != "done" || st.Present || len(st.GPUs) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
}

// A line that does not fit the fixed 9-field schema is dropped, never
// guessed: bad UUID, short bus id, out-of-range metrics, a non-number,
// a wrong field count, a bidi name.
func TestParseGPUDropsWhatDoesNotFit(t *testing.T) {
	lines := strings.Join([]string{
		"0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, 123.45",
		"1, gpu-upper, 00000000:86:00.0, NVIDIA RTX A6000, 0, 1, 49140, 38, 55.10",
		"2, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 0000:86:00.0, NVIDIA RTX A6000, 0, 1, 49140, 38, 55.10",
		"3, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, 101, 1, 49140, 38, 55.10",
		"4, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, -1, 1, 49140, 38, 55.10",
		"5, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, 5, 1, 99999999, 38, 55.10",
		"6, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, 5, 1, 49140, 300, 55.10",
		"7, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, 5, 1, 49140, 38, not-a-number",
		"8, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000, 5, 1, 49140, 38",
		"9, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:86:00.0, NVIDIA RTX A6000\u202e, 5, 1, 49140, 38, 55.10",
	}, "\n")
	st, err := ParseGPUStatus(gpuDoc(lines))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.GPUs) != 1 || st.GPUs[0].Index != 0 {
		t.Fatalf("%+v", st.GPUs)
	}
}

// [N/A] is an unavailable metric: it stays nil, it is not zero and it
// does not drop the line.
func TestParseGPUPowerUnavailable(t *testing.T) {
	line := "0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, [N/A]"
	st, err := ParseGPUStatus(gpuDoc(line))
	if err != nil || len(st.GPUs) != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	g := st.GPUs[0]
	if g.PowerW != nil || g.UtilPercent == nil || *g.UtilPercent != 12 {
		t.Fatalf("%+v", g)
	}
}

func TestParseGPUCapsTheList(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxGPUs+10; i++ {
		b.WriteString("0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, 123.45\n")
	}
	st, err := ParseGPUStatus(gpuDoc(b.String()))
	if err != nil || len(st.GPUs) != maxGPUs {
		t.Fatalf("%d %v", len(st.GPUs), err)
	}
}

func TestParseGPUStatusOtherResults(t *testing.T) {
	st, err := ParseGPUStatus([]byte(`{"format":"gpu-status-v1","phase":"done","present":false}`))
	if err != nil || st.Present || len(st.GPUs) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	st, err = ParseGPUStatus([]byte(`{"format":"gpu-status-v1","phase":"precheck","reason":"NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver."}`))
	if err != nil || st.Phase != "precheck" || st.Reason == "" {
		t.Fatalf("%+v %v", st, err)
	}
	st, _ = ParseGPUStatus([]byte(`{"format":"gpu-status-v1","phase":"precheck","reason":"a\nb"}`))
	if st.Reason != "" {
		t.Fatalf("reason with a newline kept: %q", st.Reason)
	}
	for _, bad := range []string{
		`{}`,
		`{"format":"docker-ps-v1","phase":"done"}`,
		`{"format":"gpu-status-v1","phase":"later"}`,
		`{"format":"gpu-status-v1","phase":"done","present":true,"gpus":"%%%"}`,
		`not json`,
	} {
		if _, err := ParseGPUStatus([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// A pci.inventory line that is not an NVIDIA display or 3D controller is
// dropped: wrong class, non-NVIDIA vendor, slot without domain, function
// out of range, bidi device, wrong field count.
func TestParsePCIDropsWhatDoesNotFit(t *testing.T) {
	lines := strings.Join([]string{
		"0000:65:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000] [10de:2216]",
		"0000:02:00.0\tVGA compatible controller\tNVIDIA Corporation [10de]\tT40D [10de:1eb8]",
		"0000:86:00.0\tDisplay controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000]",
		"0000:87:00.0\t3D controller\tIntel Corporation [8086]\tUHD Graphics",
		"65:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000]",
		"0000:90:00.9\t3D controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000]",
		"0000:88:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000]\u202e",
		"0000:89:00.0\t3D controller\tNVIDIA Corporation [10de]",
	}, "\n")
	inv, err := ParsePCIInventory(pciDoc(lines))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Devices) != 2 || inv.Devices[0].Slot != "0000:65:00.0" || inv.Devices[1].Slot != "0000:02:00.0" {
		t.Fatalf("%+v", inv.Devices)
	}
}

// A vendor without the pci.ids name is still NVIDIA by its numeric ID.
func TestParsePCIVendorByID(t *testing.T) {
	line := "0000:65:00.0\t3D controller\t[10de]\t[10de:2216]"
	inv, err := ParsePCIInventory(pciDoc(line))
	if err != nil || len(inv.Devices) != 1 {
		t.Fatalf("%+v %v", inv, err)
	}
}

func TestParsePCIInventoryOtherResults(t *testing.T) {
	inv, err := ParsePCIInventory([]byte(`{"format":"pci-inventory-v1","phase":"done","present":false}`))
	if err != nil || inv.Present || len(inv.Devices) != 0 {
		t.Fatalf("%+v %v", inv, err)
	}
	inv, err = ParsePCIInventory([]byte(`{"format":"pci-inventory-v1","phase":"precheck","reason":"lspci failed"}`))
	if err != nil || inv.Phase != "precheck" || inv.Reason != "lspci failed" {
		t.Fatalf("%+v %v", inv, err)
	}
	for _, bad := range []string{
		`{}`,
		`{"format":"gpu-status-v1","phase":"done"}`,
		`{"format":"pci-inventory-v1","phase":"later"}`,
		`{"format":"pci-inventory-v1","phase":"done","present":true,"devices":"%%%"}`,
		`not json`,
	} {
		if _, err := ParsePCIInventory([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
