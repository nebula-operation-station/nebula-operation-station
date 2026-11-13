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

// TestVulnExportDeviceNonPublicIPv4FirmwareIsUnknown: an IPv4 address from a
// range that is not public (CGNAT and overlay peers such as NetBird, benchmark,
// documentation, reserved, "this network", broadcast) is never a firmware
// version, so the export never carries such an address.
func TestVulnExportDeviceNonPublicIPv4FirmwareIsUnknown(t *testing.T) {
	cases := map[string]string{
		"cgnat low":      "100.64.0.1",
		"cgnat netbird":  "100.110.12.7",
		"cgnat high":     "100.127.255.254",
		"benchmark low":  "198.18.0.1",
		"benchmark high": "198.19.255.1",
		"test-net-1":     "192.0.2.10",
		"test-net-2":     "198.51.100.7",
		"test-net-3":     "203.0.113.9",
		"ietf protocol":  "192.0.0.8",
		"reserved 240/4": "240.0.0.1",
		"broadcast":      "255.255.255.255",
		"this network":   "0.1.2.3",
		"private 172.16": "172.16.5.4",
		"link-local":     "169.254.1.1",
		"multicast":      "224.0.0.9",
	}
	for name, fw := range cases {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(deviceSnapshot("fw12", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: fw, Current: true}))
			d := exportedDevice(t, e)
			dev := d["device"].(map[string]any)
			if dev["firmware_version"] != "unknown" || d["complete"] != false {
				t.Fatalf("non-public address %q exported as firmware: %v complete %v", fw, dev, d["complete"])
			}
			if r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); strings.Contains(r.body, fw) {
				t.Fatalf("export contains %q: %s", fw, r.body)
			}
		})
	}
}

// TestVulnExportDeviceDottedFirmwareIsAVersion: a dotted version, IPv4-shaped
// or not, is a firmware version and stays exported. A public dotted quad such
// as "8.8.8.8" cannot be told from a version by its shape; that residual is
// the documented D3 decision, so it is not asserted here either way.
func TestVulnExportDeviceDottedFirmwareIsAVersion(t *testing.T) {
	for _, fw := range []string{"3.1.1.7", "10.2.3", "10.2.3-h1", "17.06.05", "7.0.3+build.4", "16.9.4a", "21.4-rc2"} {
		e := newVulnEnv(t)
		e.inv.set(deviceSnapshot("fw11", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: fw, Current: true}))
		d := exportedDevice(t, e)
		if dev := d["device"].(map[string]any); dev["firmware_version"] != fw || d["complete"] != true {
			t.Fatalf("version %q not exported: %v complete %v", fw, dev, d["complete"])
		}
	}
}

// TestVulnExportRejectsHostileFirmwareFields: a firmware version is an
// allowlisted version shape. A host label, an FQDN, a MAC in either hyphen or
// dotted form, a bare word, an IPv6 form or anything that is not a version
// is exported as "unknown" and the device is never complete. Only the model
// and firmware version are the subject (ADR 0011 D3).
func TestVulnExportRejectsHostileFirmwareFields(t *testing.T) {
	hostile := map[string]string{
		"fqdn":               "core-sw.lab.example",
		"fqdn with version":  "10.core-sw.lab.example",
		"digit fqdn":         "10.lab2.example",
		"hyphenated mac":     "00-11-22-33-44-55",
		"cisco dotted mac":   "0011.2233.4455",
		"bare 12-hex mac":    "001122334455",
		"bare host label":    "core-sw",
		"letter start":       "v1.2",
		"ipv6 address":       "2001:db8::1",
		"ipv4 with port":     "10.0.0.7:22",
		"quote and json":     `3.1.1"}{"x":"y`,
		"space":              "3.1 PASSWORD=hunter2",
		"newline":            "3.1\nX",
		"path":               "../../etc/passwd",
		"html":               "<script>x</script>",
		"too long":           "1." + strings.Repeat("1", 64),
		"leading hyphen":     "-3.1.1",
		"hyphen digit label": "1-2-3",
		// A host name with digits in a later label or after a separator is
		// a host label, not a version part (ADR 0011 D3).
		"version then host label": "3.1.1.7-core-sw01",
		"version then plus label": "17.3.4+sw1",
		"digit then host label":   "1.core-sw01",
		"digit host name, 4 dots": "10.sw1.lab2.ex3",
		"host label after tilde":  "2.0~lab3",
		"dotted mac, 6 groups":    "00.11.22.33.44.55",
		"dotted mac, 6 hex pairs": "00.1a.2b.3c.4d.5e",
		"empty part":              "3.1.-4",
	}
	for name, fw := range hostile {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(deviceSnapshot("fw13", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: fw, Current: true}))
			d := exportedDevice(t, e)
			dev := d["device"].(map[string]any)
			if dev["firmware_version"] != "unknown" || d["complete"] != false {
				t.Fatalf("hostile firmware %q exported: %v complete %v", fw, dev, d["complete"])
			}
			r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
			for _, bad := range []string{fw, "hunter2", "PASSWORD", "etc/passwd", "<script>"} {
				if strings.Contains(r.body, bad) {
					t.Fatalf("export contains %q: %s", bad, r.body)
				}
			}
		})
	}
}

// TestVulnExportRejectsHostileVendorFields: the vendor slug is refused for a
// host label, an FQDN or a MAC, as well as for a value outside the slug.
func TestVulnExportRejectsHostileVendorFields(t *testing.T) {
	hostile := map[string]string{
		"fqdn":             "core-sw.lab.example",
		"hyphenated mac":   "00-11-22-33-44-55",
		"cisco dotted mac": "0011.2233.4455",
		"ipv4":             "10.0.0.7",
		"upper case":       "Cisco",
		"space":            "cisco ios",
		// A bare host label matches the slug pattern; only a covered vendor
		// is exported (ADR 0011 D2).
		"bare host label":  "core-sw",
		"uncovered vendor": "juniper",
	}
	for name, vendor := range hostile {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			e.inv.set(deviceSnapshot("hv01", &api.VulnDevice{Vendor: vendor, Model: "CBS350", FirmwareVersion: "3.1.1.7", Current: true}))
			d := exportedDevice(t, e)
			dev := d["device"].(map[string]any)
			if dev["vendor"] != "unknown" || d["complete"] != false {
				t.Fatalf("hostile vendor %q exported: %v complete %v", vendor, dev, d["complete"])
			}
			if r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); strings.Contains(r.body, vendor) {
				t.Fatalf("export contains vendor %q: %s", vendor, r.body)
			}
		})
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

// TestVulnExportDeviceFirmwareLengthLimitIs64Bytes: a firmware version of
// exactly 64 bytes is exported; one byte more is refused.
func TestVulnExportDeviceFirmwareLengthLimitIs64Bytes(t *testing.T) {
	for _, c := range []struct {
		fw string
		ok bool
	}{
		{"1." + strings.Repeat("1", 62), true},
		{"1." + strings.Repeat("1", 63), false},
	} {
		e := newVulnEnv(t)
		e.inv.set(deviceSnapshot("fw14", &api.VulnDevice{Vendor: "cisco", Model: "CBS350", FirmwareVersion: c.fw, Current: true}))
		d := exportedDevice(t, e)
		dev := d["device"].(map[string]any)
		if got := dev["firmware_version"] == c.fw; got != c.ok {
			t.Fatalf("firmware of %d bytes exported=%v, want %v: %v", len(c.fw), got, c.ok, dev)
		}
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
