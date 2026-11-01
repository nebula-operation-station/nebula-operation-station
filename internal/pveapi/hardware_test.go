// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"testing"
)

const pciPath = "/api2/json/nodes/pve1/hardware/pci"

func TestNodePCIDevicesKeepsOnlyIdentity(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{pciPath: {body: `{"data":[` +
		`{"id":"0000:01:00.0","vendor":"0x10DE","device":"0x1b80","vendor_name":"NVIDIA","iommugroup":1}]}`}})
	got, err := clusterTestClient(t, f).NodePCIDevices(context.Background(), "pve1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available || len(got.Devices) != 1 || got.Devices[0] != (PCIDevice{Address: "0000:01:00.0", Vendor: "10de", Device: "1b80"}) {
		t.Fatalf("devices = %+v", got)
	}
}

func TestNodePCIDevicesUnavailableNotEmpty(t *testing.T) {
	got, err := clusterTestClient(t, newFakePVE(t, map[string]fakeRoute{})).NodePCIDevices(context.Background(), "pve1")
	if err != nil || got.Available || got.Devices != nil {
		t.Fatalf("devices = %+v, %v", got, err)
	}
	if _, err := clusterTestClient(t, newFakePVE(t, map[string]fakeRoute{})).NodePCIDevices(context.Background(), "../etc"); err == nil {
		t.Fatal("invalid node accepted")
	}
}

func TestNodePCIDevicesRejectsHostileEntries(t *testing.T) {
	for name, body := range map[string]string{
		"short address": `{"data":[{"id":"01:00.0","vendor":"0x10de","device":"0x1b80"}]}`,
		"function 8":    `{"data":[{"id":"0000:01:00.8","vendor":"0x10de","device":"0x1b80"}]}`,
		"vendor text":   `{"data":[{"id":"0000:01:00.0","vendor":"nvidia","device":"0x1b80"}]}`,
		"device long":   `{"data":[{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1b800"}]}`,
		"duplicate":     `{"data":[{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1b80"},{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1b80"}]}`,
		"not a list":    `{"data":{}}`,
	} {
		f := newFakePVE(t, map[string]fakeRoute{pciPath: {body: body}})
		if _, err := clusterTestClient(t, f).NodePCIDevices(context.Background(), "pve1"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestNormalizePCIAddress(t *testing.T) {
	for in, want := range map[string]string{"0000:01:00.0": "0000:01:00.0", "01:00.1": "0000:01:00.1", "0000:0A:1F.7": "0000:0a:1f.7"} {
		if got, ok := NormalizePCIAddress(in); !ok || got != want {
			t.Errorf("%q = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"01:00", "01:00.0;02:00.0", "mapping", "", "0000:01:00.0,pcie=1", "x:01:00.0"} {
		if _, ok := NormalizePCIAddress(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}
