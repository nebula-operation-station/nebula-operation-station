// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pci.inventory is a LOW read-only action without parameters and runs
// exactly `lspci -mm -nn -D`; it reports only the NVIDIA display and 3D
// controllers and a host without lspci as such.
func TestPCIInventoryScript(t *testing.T) {
	a, ok := Lookup("pci.inventory")
	if !ok || !a.ReadOnly || len(a.Params) != 0 || a.Retry != RetrySafe || a.Risk != pb.RiskClass_RISK_CLASS_LOW {
		t.Fatalf("pci.inventory %+v", a)
	}
	f := newFakeHost(t, "1")
	f.write(t, "lspci", `echo "$@" >> "`+f.calls+`"
[ -e "`+f.dir+`/lspci-fail" ] && exit 1
printf '%s\n' \
'0000:00:00.0 "Host bridge [0600]" "Intel Corporation [8086]" "Xeon E5-2698 v4 r. CPU Host Bridge"' \
'0000:65:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA102 [RTX A6000] [10de:2216]" rev a1' \
'0000:86:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA102 [RTX A6000] [10de:2216]" rev a1' \
'0000:02:00.0 "Ethernet controller [0200]" "Intel Corporation [8086]" "I210-LM [8086:1533]" rev 03'`)
	code, doc := f.run(t, a.Script)
	if code != 0 || doc["present"] != true {
		t.Fatalf("%d %v", code, doc)
	}
	devs := b64(t, doc, "devices")
	if !strings.Contains(devs, "0000:65:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102 [RTX A6000] [10de:2216]") ||
		!strings.Contains(devs, "0000:86:00.0") ||
		strings.Contains(devs, "Intel") || strings.Contains(devs, "Ethernet") || strings.Contains(devs, "Host bridge") {
		t.Fatalf("devices %q", devs)
	}
	if calls := f.readCalls(t); !strings.Contains(calls, "-mm -nn -D") {
		t.Fatalf("calls %q", calls)
	}

	t.Run("no lspci", func(t *testing.T) {
		f := newFakeHost(t, "1")
		// Only the tools the script needs, so a lspci on this machine
		// stays out of reach.
		for _, tool := range []string{"base64", "head", "tr"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Skip(tool + " missing")
			}
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		code, doc := f.runPath(t, a.Script, f.bin)
		if code != 0 || doc["present"] != false || doc["phase"] != "done" {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("lspci fails", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "lspci", `exit 1`)
		f.touch(t, "lspci-fail")
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || doc["reason"] == "" {
			t.Fatalf("%d %v", code, doc)
		}
	})
}

// gpu.status is a LOW read-only action without parameters and runs the
// fixed nvidia-smi query-gpu command once; a host without the driver is
// reported as such, never as an empty GPU list.
func TestGPUStatusScript(t *testing.T) {
	a, ok := Lookup("gpu.status")
	if !ok || !a.ReadOnly || len(a.Params) != 0 || a.Retry != RetrySafe || a.Risk != pb.RiskClass_RISK_CLASS_LOW {
		t.Fatalf("gpu.status %+v", a)
	}
	f := newFakeHost(t, "1")
	f.write(t, "nvidia-smi", `echo "$@" >> "`+f.calls+`"
[ -e "`+f.dir+`/no-driver" ] && { echo "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver." >&2; exit 9; }
printf '%s\n' \
'0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, 123.45' \
'1, GPU-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d, 00000000:86:00.0, NVIDIA RTX A6000, 0, 1024, 49140, 38, 55.10'`)
	code, doc := f.run(t, a.Script)
	if code != 0 || doc["present"] != true {
		t.Fatalf("%d %v", code, doc)
	}
	gpus := b64(t, doc, "gpus")
	if !strings.Contains(gpus, "0, GPU-673e42ea-5685-7487-4d7e-045c914a4d51, 00000000:65:00.0, NVIDIA RTX A6000, 12, 34567, 49140, 45, 123.45") ||
		!strings.Contains(gpus, "1, GPU-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d, 00000000:86:00.0, NVIDIA RTX A6000, 0, 1024, 49140, 38, 55.10") {
		t.Fatalf("gpus %q", gpus)
	}
	calls := f.readCalls(t)
	if !strings.Contains(calls, "--query-gpu=index,uuid,pci.bus_id,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw --format=csv,noheader,nounits") {
		t.Fatalf("calls %q", calls)
	}
	if n := strings.Count(calls, "--query-gpu"); n != 1 {
		t.Fatalf("nvidia-smi called %d times: %q", n, calls)
	}

	t.Run("driver missing", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "nvidia-smi", `echo "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver." >&2; exit 9`)
		f.touch(t, "no-driver")
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || !strings.Contains(doc["reason"].(string), "driver") {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("no nvidia-smi", func(t *testing.T) {
		f := newFakeHost(t, "1")
		for _, tool := range []string{"base64", "head", "tr"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Skip(tool + " missing")
			}
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		code, doc := f.runPath(t, a.Script, f.bin)
		if code != 0 || doc["present"] != false || doc["phase"] != "done" {
			t.Fatalf("%d %v", code, doc)
		}
	})
}

func TestPCIInventoryMachineFormat(t *testing.T) {
	a, _ := Lookup("pci.inventory")
	f := newFakeHost(t, "1")
	f.write(t, "lspci", `cat <<'EOF'
0000:01:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "AD102 [GeForce RTX 4090] [2684]" -ra1 "ASUSTeK Computer Inc. [1043]" "Device [8894]"
0000:65:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "GA102GL [RTX A6000] [2230]" -ra1 "NVIDIA Corporation [10de]" "Device [1459]"
0000:66:00.0 "3D controller [0302]" "Device [10de]" "Device [2230]" -ra1 "" ""
0000:01:00.1 "Audio device [0403]" "NVIDIA Corporation [10de]" "Device [22ba]" -ra1 "" ""
0000:02:00.0 "VGA compatible controller [0300]" "Intel Corporation [8086]" "Device [1234]" -r01 "" ""
EOF`)
	code, doc := f.run(t, a.Script)
	if code != 0 || doc["present"] != true {
		t.Fatalf("%d %v", code, doc)
	}
	want := "0000:01:00.0\tVGA compatible controller\tNVIDIA Corporation [10de]\tAD102 [GeForce RTX 4090] [2684]\n" +
		"0000:65:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102GL [RTX A6000] [2230]\n" +
		"0000:66:00.0\t3D controller\tDevice [10de]\tDevice [2230]\n"
	if got := b64(t, doc, "devices"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGPUActionsRejectCaptureOverflow(t *testing.T) {
	for _, action := range []struct{ id, command, field string }{
		{"pci.inventory", "lspci", "devices"},
		{"gpu.status", "nvidia-smi", "gpus"},
	} {
		for _, output := range []struct{ name, body string }{
			{"single line", "head -c 1048577 /dev/zero | tr '\\000' x"},
			{"many lines", "head -c 1048577 /dev/zero | tr '\\000' '\\n'"},
			{"binary", "head -c 1048577 /dev/zero"},
			{"stderr", "head -c 1048577 /dev/zero | tr '\\000' x >&2; exit 9"},
		} {
			if action.id == "pci.inventory" && output.name == "stderr" {
				continue
			} // lspci stderr is discarded.
			t.Run(action.id+"/"+output.name, func(t *testing.T) {
				a, _ := Lookup(action.id)
				f := newFakeHost(t, "1")
				f.write(t, action.command, output.body)
				code, doc := f.run(t, a.Script)
				if code != 10 || doc["phase"] != "precheck" || doc["reason"] != "command output exceeds byte limit" || doc["present"] == true || doc[action.field] != nil {
					t.Fatalf("overflow must be unavailable: code=%d phase=%v reason=%v", code, doc["phase"], doc["reason"])
				}
			})
		}
	}
}

func TestGPUActionsAcceptCaptureAtByteLimit(t *testing.T) {
	for _, action := range []struct{ id, command string }{
		{"pci.inventory", "lspci"},
		{"gpu.status", "nvidia-smi"},
	} {
		t.Run(action.id, func(t *testing.T) {
			a, _ := Lookup(action.id)
			f := newFakeHost(t, "1")
			f.write(t, action.command, `head -c 1048576 /dev/zero | tr '\000' '\n'`)
			code, doc := f.run(t, a.Script)
			if code != 0 || doc["phase"] != "done" || doc["present"] != true {
				t.Fatalf("output at byte limit rejected: %d %v", code, doc)
			}
		})
	}
}
