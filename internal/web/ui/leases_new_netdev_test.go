// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// netDevicePreview is a device read lease preview of two devices, approved
// on the CLI only (the browser never offers a device lease).
func netDevicePreview(devices ...executions.ReadGrantPreviewNetDevice) executions.ReadGrantPreview {
	v := leasePreview(0)
	v.Actions = nil
	v.RateProfile = "netdevice"
	v.NetDevices = devices
	v.CLI, v.Options = true, nil
	return v
}

func twoNetDevices() []executions.ReadGrantPreviewNetDevice {
	return []executions.ReadGrantPreviewNetDevice{
		{DeviceID: "sw-1", TrustPin: "SHA256:pinone", TrustGeneration: 1, CredentialVersion: 3, Reads: []string{"cbs_lldp", "cbs_version"}},
		{DeviceID: "sw-2", TrustPin: "SHA256:pintwo", TrustGeneration: 2, CredentialVersion: 4, Reads: []string{"cbs_version"}},
	}
}

// TestNetDevicePreviewListsEveryDeviceAndRead pins that the browser preview
// shows each frozen device with its pin, generation and credential version,
// and each of its reads, as text.
func TestNetDevicePreviewListsEveryDeviceAndRead(t *testing.T) {
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: netDevicePreview(twoNetDevices()...)}, nil))
	if got := strings.Count(page, `<tr class="lease-netdevice">`); got != 2 {
		t.Fatalf("preview lists %d devices, want 2", got)
	}
	for _, want := range []string{
		`<td class="mono">sw-1</td><td class="mono">SHA256:pinone</td><td class="mono">1</td><td class="mono">3</td><td class="mono">cbs_lldp, cbs_version</td>`,
		`<td class="mono">sw-2</td><td class="mono">SHA256:pintwo</td><td class="mono">2</td><td class="mono">4</td><td class="mono">cbs_version</td>`,
		"2 network devices",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("device preview misses %q", want)
		}
	}
}

// TestNetDevicePreviewEscapesUntrustedNames pins that a device name from the
// executor is shown as escaped text, never as markup.
func TestNetDevicePreviewEscapesUntrustedNames(t *testing.T) {
	devices := []executions.ReadGrantPreviewNetDevice{
		{DeviceID: `<img src=x onerror=alert(1)>`, TrustPin: "SHA256:p", TrustGeneration: 1, CredentialVersion: 1, Reads: []string{`<b>cbs_version</b>`}},
	}
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: netDevicePreview(devices...)}, nil))
	if strings.Contains(page, "<img src=x") || strings.Contains(page, "<b>cbs_version") {
		t.Fatal("device name or read rendered as markup")
	}
	if !strings.Contains(page, "&lt;img src=x onerror=alert(1)&gt;") || !strings.Contains(page, "&lt;b&gt;cbs_version&lt;/b&gt;") {
		t.Error("device name or read not shown escaped")
	}
}

// TestNetDevicePreviewOffersNoBrowserApproval pins that a device lease shows
// the CLI approval command and no security key button or WebAuthn scripts.
func TestNetDevicePreviewOffersNoBrowserApproval(t *testing.T) {
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: netDevicePreview(twoNetDevices()...)}, nil))
	m := regexp.MustCompile(`<pre class="mono" id="lease-cli">([^<]*)</pre>`).FindStringSubmatch(page)
	if m == nil || !strings.HasPrefix(m[1], "nebula read-grant approve ") {
		t.Fatalf("device preview misses the CLI approval command: %q", m)
	}
	for _, never := range []string{"schedule-approve", "Approve with security key", "/static/webauthn.js", "/static/schedules.js"} {
		if strings.Contains(page, never) {
			t.Errorf("device preview shows %q", never)
		}
	}
}

// TestNetDeviceCommitIsRefused pins that a browser commit of a device lease
// is refused before the executor is asked to commit it.
func TestNetDeviceCommitIsRefused(t *testing.T) {
	f := &fakeLeases{preview: netDevicePreview(twoNetDevices()...)}
	h := leaseNewHandler(t, f, nil)
	previewThrough(t, h)
	code, body := postLeaseJSON(t, h, "/leases/commit", `{"id":"`+leaseDigest+`","assertion":{"id":"cred"}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "CLI") {
		t.Fatalf("browser commit of a device lease = %d %s, want 400 naming the CLI", code, body)
	}
	if len(f.committed) != 0 {
		t.Fatalf("device lease reached the executor's commit: %v", f.committed)
	}
}

// TestHostPreviewHasNoDeviceSection pins that a host lease preview shows no
// device table.
func TestHostPreviewHasNoDeviceSection(t *testing.T) {
	page := previewThrough(t, leaseNewHandler(t, &fakeLeases{preview: leasePreview(2)}, nil))
	if strings.Contains(page, `lease-netdevice`) || strings.Contains(page, "network devices") {
		t.Error("host preview shows a device section")
	}
}
