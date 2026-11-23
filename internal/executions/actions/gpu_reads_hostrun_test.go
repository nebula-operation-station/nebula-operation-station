// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/gpuhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// gpuFixedSlots are the two NVIDIA devices the fake lspci reports, in the
// lspci form; the fake nvidia-smi reports the same bus IDs in its 8-digit
// domain form.
const (
	gpuSlotA = "0000:65:00.0"
	gpuSlotB = "0000:86:00.0"
)

// pciFakeLspci is the fake lspci of the hostrun PCI tests: 200 devices
// that are not GPUs and two NVIDIA devices with quotes, square brackets
// and non-ASCII in their names.
func pciFakeLspci() string {
	var b strings.Builder
	b.WriteString("cat <<'EOF'\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "0000:%02x:00.%d \"Host bridge [0600]\" \"Intel Corporation [8086]\" \"Xeon Device %d [8086:%04x]\" rev 01\n",
			i%256, i%8, i, 0x6f00+i)
	}
	// The second name has a quote inside it; the script's field split
	// cuts such a name at the quote (see the report), so only its slot,
	// class and vendor are asserted.
	b.WriteString(`0000:65:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA102GL [RTX A6000 Ö] [10de:2230]" -ra1 "NVIDIA Corporation [10de]" "Device [1459]"
0000:86:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA102 "Ampere" [RTX A6000] [10de:2216]" rev a1
EOF
`)
	return b.String()
}

// fakeNvidiaSMI8 is the fake nvidia-smi of the hostrun GPU tests: eight
// GPUs, two of them with [N/A] and [Not Supported] fields, in the fixed
// query order.
func fakeNvidiaSMI8() string {
	return `printf '%s\n' \
'0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, 123.45' \
'1, GPU-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d, 00000000:86:00.0, NVIDIA RTX A6000, 0, 1024, 49140, 38, 55.10' \
'2, GPU-00000000-0000-4000-8000-000000000002, 00000000:87:00.0, NVIDIA RTX A6000, [N/A], [N/A], [N/A], [N/A], [N/A]' \
'3, GPU-00000000-0000-4000-8000-000000000003, 00000000:88:00.0, NVIDIA RTX A6000, [Not Supported], [Not Supported], 49140, 40, [Not Supported]' \
'4, GPU-00000000-0000-4000-8000-000000000004, 00000000:89:00.0, NVIDIA RTX A6000, 3, 100, 49140, 41, 60.00' \
'5, GPU-00000000-0000-4000-8000-000000000005, 00000000:8a:00.0, NVIDIA RTX A6000, 4, 200, 49140, 42, 61.00' \
'6, GPU-00000000-0000-4000-8000-000000000006, 00000000:8b:00.0, NVIDIA RTX A6000, 5, 300, 49140, 43, 62.00' \
'7, GPU-00000000-0000-4000-8000-000000000007, 00000000:8c:00.0, NVIDIA RTX A6000, 6, 400, 49140, 44, 63.00'`
}

// hostrunPrelude is the only text in front of the unchanged script: it
// sets PATH to the fake directory first. The fake directory is searched
// before the system directories, as in fakeHost.run.
func hostrunPrelude(path string) string {
	return "PATH='" + path + "'; export PATH\n"
}

// runActionThroughHostrun runs the named action's script as an attached
// run over SSH with PATH set to path, so the result is classified by the
// executor's own rule.
func runActionThroughHostrun(t *testing.T, id, path string, timeout time.Duration) hostrun.Result {
	t.Helper()
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	script := hostrunPrelude(path) + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), serviceRunID, []byte(`{}`), []byte(script), timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// pciPath is the PATH that finds the fake tools first, then the system.
func pciPath(f *fakeHost) string { return f.bin + ":/usr/bin:/bin" }

// TestPCIInventoryThroughHostrunReadsGPUs: the hostrun classifier reports
// the pci.inventory run as a success and gpuhost reads exactly the two
// NVIDIA devices, with their PCI bus IDs, from among 200 other devices.
func TestPCIInventoryThroughHostrunReadsGPUs(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "lspci", pciFakeLspci())
	r := runActionThroughHostrun(t, "pci.inventory", pciPath(f), 30*time.Second)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	inv, err := gpuhost.ParsePCIInventory(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Phase != "done" || !inv.Present || inv.Reason != "" {
		t.Fatalf("phase %q present %v reason %q", inv.Phase, inv.Present, inv.Reason)
	}
	if len(inv.Devices) != 2 {
		t.Fatalf("%d devices, want 2: %+v", len(inv.Devices), inv.Devices)
	}
	if inv.Devices[0].Slot != gpuSlotA || inv.Devices[1].Slot != gpuSlotB {
		t.Fatalf("slots %q %q", inv.Devices[0].Slot, inv.Devices[1].Slot)
	}
	for _, d := range inv.Devices {
		if d.Class != "3D controller" || d.Vendor != "NVIDIA Corporation [10de]" {
			t.Errorf("device %+v", d)
		}
	}
	if !strings.Contains(inv.Devices[0].Device, "RTX A6000 Ö") {
		t.Errorf("non-ASCII device name lost: %q", inv.Devices[0].Device)
	}
}

// TestPCIInventoryThroughHostrunWithoutLspci: a host without lspci is a
// success for the classifier and reports present=false to the parser; it
// is not an empty device list.
func TestPCIInventoryThroughHostrunWithoutLspci(t *testing.T) {
	f := newFakeHost(t, "1")
	bin := filepath.Join(f.dir, "nolspci")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"base64", "head", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skip(tool + " missing")
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	r := runActionThroughHostrun(t, "pci.inventory", bin, 30*time.Second)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	inv, err := gpuhost.ParsePCIInventory(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Phase != "done" || inv.Present || len(inv.Devices) != 0 {
		t.Fatalf("phase %q present %v devices %d; want done, not present, no devices", inv.Phase, inv.Present, len(inv.Devices))
	}
}

// TestGPUStatusThroughHostrunReadsEightGPUs: eight GPUs, with [N/A] and
// [Not Supported] fields, are a success for the classifier; gpuhost reads
// all eight, and the GPUs correlate with the PCI devices by bus ID.
func TestGPUStatusThroughHostrunReadsEightGPUs(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "lspci", pciFakeLspci())
	f.write(t, "nvidia-smi", fakeNvidiaSMI8())
	r := runActionThroughHostrun(t, "gpu.status", pciPath(f), 30*time.Second)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	st, err := gpuhost.ParseGPUStatus(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != "done" || !st.Present {
		t.Fatalf("phase %q present %v reason %q", st.Phase, st.Present, st.Reason)
	}
	if len(st.GPUs) != 8 {
		t.Fatalf("%d GPUs, want 8: %+v", len(st.GPUs), st.GPUs)
	}
	if g := st.GPUs[2]; g.UtilPercent != nil || g.MemoryUsedMiB != nil || g.TemperatureC != nil {
		t.Errorf("[N/A] fields must be unavailable, not zero: %+v", g)
	}
	if g := st.GPUs[3]; g.UtilPercent != nil || g.PowerW != nil || g.MemoryTotalMiB == nil || *g.MemoryTotalMiB != 49140 {
		t.Errorf("[Not Supported] fields must be unavailable: %+v", g)
	}

	// Correlation: the two lspci GPUs find their nvidia-smi entries.
	pci, err := gpuhost.ParsePCIInventory(runActionThroughHostrun(t, "pci.inventory", pciPath(f), 30*time.Second).Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(pci.Devices) != 2 {
		t.Fatalf("%d PCI GPUs, want 2", len(pci.Devices))
	}
	for _, d := range pci.Devices {
		if _, ok := st.GPUForSlot(d.Slot); !ok {
			t.Fatalf("no GPU for slot %s", d.Slot)
		}
	}
	if got := gpuhost.GPUsForTarget(pci, st, "65:00"); len(got) != 1 || got[0].Index != 0 {
		t.Fatalf("GPUsForTarget 65:00 = %+v", got)
	}
}

// TestGPUStatusThroughHostrunDriverMissing: nvidia-smi failing with the
// driver message is a precheck failure that reaches the parser as the
// precheck phase with a reason, not as an empty GPU list.
func TestGPUStatusThroughHostrunDriverMissing(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "nvidia-smi", `echo "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure that the latest NVIDIA driver is installed and running." >&2; exit 9`)
	r := runActionThroughHostrun(t, "gpu.status", pciPath(f), 30*time.Second)
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	st, err := gpuhost.ParseGPUStatus(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != "precheck" || st.Reason == "" || st.Present || st.GPUs != nil {
		t.Fatalf("phase %q reason %q present %v gpus %d; want precheck with reason, not present", st.Phase, st.Reason, st.Present, len(st.GPUs))
	}
	if strings.Contains(st.Reason, "NVIDIA-SMI") || strings.Contains(st.Reason, "couldn't") {
		t.Errorf("host text echoed into the reason: %q", st.Reason)
	}
}

// TestGPUStatusThroughHostrunWithoutNvidiaSMI: a host without nvidia-smi
// is a success with present=false, not an empty GPU list.
func TestGPUStatusThroughHostrunWithoutNvidiaSMI(t *testing.T) {
	f := newFakeHost(t, "1")
	bin := filepath.Join(f.dir, "nonvidia")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"base64", "head", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skip(tool + " missing")
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	r := runActionThroughHostrun(t, "gpu.status", bin, 30*time.Second)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	st, err := gpuhost.ParseGPUStatus(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != "done" || st.Present || len(st.GPUs) != 0 {
		t.Fatalf("phase %q present %v gpus %d; want done, not present", st.Phase, st.Present, len(st.GPUs))
	}
}

// TestGPUStatusThroughHostrunTimesOut: an nvidia-smi that hangs ends as
// execution_timeout with the result missing, and gpuhost has nothing to
// read: the run is not an empty GPU list.
func TestGPUStatusThroughHostrunTimesOut(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "nvidia-smi", `sleep 10`)
	r := runActionThroughHostrun(t, "gpu.status", pciPath(f), 2*time.Second)
	if r.Class != hostrun.ClassExecutionTimeout {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if len(r.Result) != 0 {
		t.Fatalf("result %q after timeout", r.Result)
	}
	if !r.RemoteMayRun {
		t.Errorf("RemoteMayRun = false after a timeout")
	}
}
