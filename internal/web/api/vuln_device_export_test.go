// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// deviceSnapshot returns a snapshot holding one device with the given
// record.
func deviceSnapshot(id string, d *api.VulnDevice) api.VulnSnapshot {
	s := api.VulnSnapshot{ID: "inv-dev-" + id, Generation: 3, TakenAt: vt0.Add(-time.Hour)}
	s.Subjects = []api.VulnSubject{{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: id}, Ecosystem: deviceEcosystem(d), Complete: true, Device: d}}
	return s
}

// deviceEcosystem is the vendor ecosystem NOS reads for the device's vendor
// (D2): the Cisco OS train or the Palo Alto PAN-OS ecosystem.
func deviceEcosystem(d *api.VulnDevice) string {
	if d != nil && d.Vendor == "paloalto" {
		return "vendor:paloalto:panos"
	}
	return "vendor:cisco:iosxe"
}

// exportedDevice returns the one device subject of the export.
func exportedDevice(t *testing.T, e *venv) map[string]any {
	t.Helper()
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	if r.code != http.StatusOK {
		t.Fatalf("%d %s", r.code, r.body)
	}
	walkKeys(t, r.json(t))
	subs := r.json(t)["subjects"].([]any)
	if len(subs) != 1 {
		t.Fatalf("%d subjects, want one device: %s", len(subs), r.body)
	}
	return subs[0].(map[string]any)
}

func TestVulnExportDeviceCarriesModelAndFirmwareOnly(t *testing.T) {
	e := newVulnEnv(t)
	e.inv.set(deviceSnapshot("sw01", &api.VulnDevice{Vendor: "cisco", Model: "CBS350-24P-4G", FirmwareVersion: "3.1.1.7", Current: true}))
	d := exportedDevice(t, e)
	if d["subject_kind"] != "device" || d["subject_ref"].(map[string]any)["id"] != "sw01" {
		t.Fatalf("subject %v", d)
	}
	dev := d["device"].(map[string]any)
	if dev["vendor"] != "cisco" || dev["model"] != "CBS350-24P-4G" || dev["firmware_version"] != "3.1.1.7" {
		t.Fatalf("device %v", dev)
	}
	if d["complete"] != true || len(d["components"].([]any)) != 0 {
		t.Fatalf("complete device without packages: %v", d)
	}
	if _, ok := d["running_kernel"]; ok {
		t.Fatalf("device carries a kernel: %v", d)
	}
	if d["ecosystem"] != "vendor:cisco:iosxe" {
		t.Fatalf("device ecosystem %v, want its vendor ecosystem", d["ecosystem"])
	}
}

func TestVulnExportDeviceWithoutVendorEcosystemIsIncomplete(t *testing.T) {
	cases := map[string]struct {
		vendor, eco string
	}{
		"no ecosystem":           {"cisco", ""},
		"host ecosystem":         {"cisco", "debian:bookworm"},
		"other vendor's train":   {"cisco", "vendor:paloalto:panos"},
		"cisco train with space": {"cisco", "vendor:cisco:ios xe"},
		"palo alto wrong train":  {"paloalto", "vendor:paloalto:pan-os"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			s := deviceSnapshot("eco1", &api.VulnDevice{Vendor: c.vendor, Model: "PA-220", FirmwareVersion: "10.2.3", Current: true})
			s.Subjects[0].Ecosystem = c.eco
			e.inv.set(s)
			d := exportedDevice(t, e)
			if d["complete"] != false {
				t.Fatalf("device without its vendor ecosystem can be covered: %v", d)
			}
			if _, ok := d["ecosystem"]; ok {
				t.Fatalf("device exported a foreign ecosystem: %v", d)
			}
		})
	}
}

func TestVulnExportDeviceWithoutFirmwareIsUnknownAndIncomplete(t *testing.T) {
	e := newVulnEnv(t)
	e.inv.set(deviceSnapshot("fw02", &api.VulnDevice{Vendor: "paloalto", Model: "PA-220", Current: true}))
	d := exportedDevice(t, e)
	dev := d["device"].(map[string]any)
	if dev["model"] != "PA-220" || dev["firmware_version"] != "unknown" {
		t.Fatalf("device %v", dev)
	}
	if d["complete"] != false {
		t.Fatalf("device without firmware can be covered: %v", d)
	}
}

func TestVulnExportStaleDeviceRecordIsUnknown(t *testing.T) {
	e := newVulnEnv(t)
	e.inv.set(deviceSnapshot("sw03", &api.VulnDevice{Vendor: "cisco", Model: "CBS350-24P-4G", FirmwareVersion: "3.1.1.7", Current: false}))
	d := exportedDevice(t, e)
	dev := d["device"].(map[string]any)
	if dev["vendor"] != "cisco" || dev["model"] != "unknown" || dev["firmware_version"] != "unknown" {
		t.Fatalf("stale record exported its values: %v", dev)
	}
	if d["complete"] != false {
		t.Fatalf("stale device can be covered: %v", d)
	}
	if _, ok := d["ecosystem"]; ok {
		t.Fatalf("stale device exported its OS train: %v", d)
	}
}

// TestVulnExportDeviceFirmwareAddressLiteralsAreUnknown: an address in the
// firmware version is refused; a private or IPv6 address never is a version.
func TestVulnExportDeviceFirmwareAddressLiteralsAreUnknown(t *testing.T) {
	cases := map[string]string{
		"private ipv4": "10.0.0.7", "lan ipv4": "192.168.1.1", "loopback": "127.0.0.1",
		"ipv6 link-local": "fe80::1", "ipv6 global": "2001:db8::1", "ipv6 loopback": "::1",
		"colon form": "1:2", "literal unknown": "unknown",
	}
	for name, fw := range cases {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(deviceSnapshot("fw10", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: fw, Current: true}))
			d := exportedDevice(t, e)
			dev := d["device"].(map[string]any)
			if dev["firmware_version"] != "unknown" || d["complete"] != false {
				t.Fatalf("firmware %q exported: %v complete %v", fw, dev, d["complete"])
			}
			if r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); strings.Contains(r.body, fw) && fw != "unknown" {
				t.Fatalf("export contains %q: %s", fw, r.body)
			}
		})
	}
}

// TestVulnExportDeviceDottedFirmwareIsAVersion: a dotted version, IPv4-shaped
// or not, is a firmware version and stays exported.
func TestVulnExportDeviceDottedFirmwareIsAVersion(t *testing.T) {
	for _, fw := range []string{"3.1.1.7", "10.2.3", "8.8.8.8"} {
		e := newVulnEnv(t)
		e.inv.set(deviceSnapshot("fw11", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: fw, Current: true}))
		d := exportedDevice(t, e)
		if dev := d["device"].(map[string]any); dev["firmware_version"] != fw || d["complete"] != true {
			t.Fatalf("version %q not exported: %v complete %v", fw, dev, d["complete"])
		}
	}
}

// TestVulnExportDeviceWithImageDigestOrAddressIDIsDropped: a device that
// names an image digest, or whose ID is an address, is not exported at all.
func TestVulnExportDeviceWithImageDigestOrAddressIDIsDropped(t *testing.T) {
	digest := deviceSnapshot("sw07", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true})
	digest.Subjects[0].Ref.ImageDigest = "sha256:" + strings.Repeat("a", 64)
	for name, s := range map[string]api.VulnSnapshot{
		"image digest": digest,
		"ipv4 id":      deviceSnapshot("10.0.0.7", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}),
		"ipv6 id":      deviceSnapshot("fe80::1", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}),
	} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(s)
			r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
			if r.code != http.StatusOK {
				t.Fatalf("%d %s", r.code, r.body)
			}
			if n := len(r.json(t)["subjects"].([]any)); n != 0 {
				t.Fatalf("%d subjects exported: %s", n, r.body)
			}
		})
	}
}

func TestVulnExportRejectsHostileDeviceFields(t *testing.T) {
	hostile := map[string]string{
		"quote and json":  `C9300"}{"x":"y`,
		"secret in model": "PA-220 PASSWORD=hunter2",
		"newline":         "PA\nX",
		"path":            "../../etc/passwd",
		"address":         "10.0.0.7",
		"space":           "C1300 8FE",
		"too long":        strings.Repeat("A", 65),
		"leading hyphen":  "-PA220",
		"html":            "<script>x</script>",
		"fqdn":            "core-sw.lab.example",
		"hyphenated mac":  "00-11-22-33-44-55",
		"ipv6 address":    "fe80::1",
		"ipv4 with port":  "10.0.0.7:22",
	}
	for name, model := range hostile {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(deviceSnapshot("hx01", &api.VulnDevice{Vendor: "paloalto", Model: model, FirmwareVersion: "10.2.3", Current: true}))
			d := exportedDevice(t, e)
			dev := d["device"].(map[string]any)
			if dev["model"] != "unknown" || d["complete"] != false {
				t.Fatalf("hostile model exported: %v %v", dev, d["complete"])
			}
			r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
			for _, bad := range []string{"hunter2", "PASSWORD", "passwd", "10.0.0.7", "<script>", "etc/passwd", `"}{`} {
				if strings.Contains(r.body, bad) {
					t.Fatalf("export contains %q: %s", bad, r.body)
				}
			}
		})
	}
	// A hostile vendor is unknown, the rest of the device is kept.
	e := newVulnEnv(t)
	e.inv.set(deviceSnapshot("hx02", &api.VulnDevice{Vendor: "cisco;rm -rf", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}))
	d := exportedDevice(t, e)
	if dev := d["device"].(map[string]any); dev["vendor"] != "unknown" || dev["model"] != "CBS350" {
		t.Fatalf("hostile vendor: %v", dev)
	}
	if d["complete"] != false {
		t.Fatalf("device with unknown vendor can be covered: %v", d)
	}
}

func TestVulnExportDeviceCarriesNoPackagesOrKernel(t *testing.T) {
	e := newVulnEnv(t)
	s := deviceSnapshot("sw04", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true})
	s.Subjects[0].Ecosystem = "debian:bookworm"
	s.Subjects[0].Components = []api.VulnComponent{comp("openssl", "3.0.15-1")}
	e.inv.set(s)
	d := exportedDevice(t, e)
	if d["complete"] != false || len(d["components"].([]any)) != 0 {
		t.Fatalf("device with packages exported them or stayed complete: %v", d)
	}
	if _, ok := d["ecosystem"]; ok {
		t.Fatalf("device exported a host ecosystem: %v", d)
	}
}

// TestVulnExportDeviceWithPackagesCannotBeCovered: a device whose record
// carries packages is incomplete even though its model and firmware are fine.
func TestVulnExportDeviceWithPackagesCannotBeCovered(t *testing.T) {
	e := newVulnEnv(t)
	s := deviceSnapshot("sw08", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true})
	s.Subjects[0].Components = []api.VulnComponent{comp("openssl", "3.0.15-1")}
	e.inv.set(s)
	if d := exportedDevice(t, e); d["complete"] != false {
		t.Fatalf("device with packages can be covered: %v", d)
	}
}

func TestVulnExportDeviceWithoutRecordIsNotExported(t *testing.T) {
	e := newVulnEnv(t)
	e.inv.set(deviceSnapshot("sw05", nil))
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	if n := len(r.json(t)["subjects"].([]any)); n != 0 {
		t.Fatalf("device without a record exported: %s", r.body)
	}
}

func TestVulnExportDevicePagesAtTheSubjectLimit(t *testing.T) {
	e := newVulnEnv(t)
	s := api.VulnSnapshot{ID: "inv-devs", Generation: 9, TakenAt: vt0.Add(-time.Hour)}
	n := api.MaxSubjectsPerPage + 5
	for i := 0; i < n; i++ {
		s.Subjects = append(s.Subjects, api.VulnSubject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: fmt.Sprintf("d%04d", i)}, Complete: true,
			Device: &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}})
	}
	e.inv.set(s)
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	v := r.json(t)
	if got := len(v["subjects"].([]any)); got != api.MaxSubjectsPerPage || v["next_cursor"] == nil {
		t.Fatalf("first page %d subjects", got)
	}
	r = e.do(t, "GET", "/api/v1/vuln/inventory?cursor="+v["next_cursor"].(string), vulnTok, nil)
	second := r.json(t)["subjects"].([]any)
	if len(second) != 5 {
		t.Fatalf("second page %d subjects", len(second))
	}
	seen := map[string]bool{}
	for _, p := range [][]any{v["subjects"].([]any), second} {
		for _, x := range p {
			m := x.(map[string]any)
			id := m["subject_ref"].(map[string]any)["id"].(string)
			if seen[id] || m["part"] != 1.0 || m["last_part"] != true {
				t.Fatalf("device %s repeated or split: %v", id, m)
			}
			seen[id] = true
		}
	}
	if len(seen) != n {
		t.Fatalf("%d distinct devices, want %d", len(seen), n)
	}
}

func TestVulnExportDeviceNeedsTheInventoryScope(t *testing.T) {
	wo := newVulnEnv(t, vulnToken(serverconfig.ScopeVulnFindingsWrite))
	wo.inv.set(deviceSnapshot("sw06", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}))
	if r := wo.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); r.code != http.StatusForbidden {
		t.Fatalf("token without vuln.inventory.read exported devices: %d %s", r.code, r.body)
	}
}
