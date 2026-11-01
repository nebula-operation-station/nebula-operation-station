// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"fmt"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const pvePCIList = `{"data":[{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1B80","class":"0x030000","vendor_name":"NVIDIA"},` +
	`{"id":"0000:02:00.0","vendor":"0x8086","device":"0x1533","class":"0x020000"}]}`

func hostpciConfig(t *testing.T, e *pveReadEnv, entries string) *pb.PVEGuestConfig {
	t.Helper()
	e.pve.set("/api2/json/nodes/pve1/qemu/100/config", `{"data":{"cores":1,"memory":512,`+entries+`}}`)
	got, err := e.readGuest(pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, 100)
	if err != nil {
		t.Fatal(err)
	}
	c := got.GetGuestConfig()
	if c.GetState() != pveAvail {
		t.Fatalf("config = %v", c)
	}
	if cp := c.GetCapabilities(); cp.GetLiveMigration() != "no" || cp.GetRamSnapshots() != "no" {
		t.Fatalf("passthrough not reflected in capabilities: %v", cp)
	}
	return c
}

func TestReadPVEGuestConfigResolvesHostPCIIdentity(t *testing.T) {
	e := guestPveEnv(t)
	e.pve.set("/api2/json/nodes/pve1/hardware/pci", pvePCIList)
	c := hostpciConfig(t, e, `"hostpci0":"0000:01:00.0,pcie=1","hostpci1":"02:00.0"`)
	var rows []string
	for _, h := range c.GetHostpci() {
		rows = append(rows, fmt.Sprintf("%s=%s>%s", h.GetId(), h.GetDevice(), h.GetTarget()))
	}
	want := "hostpci0=PCI-10de:1b80:01:00.0>0000:01:00.0 hostpci1=PCI-8086:1533:02:00.0>0000:02:00.0"
	if strings.Join(rows, " ") != want {
		t.Fatalf("hostpci = %v\nwant %s", rows, want)
	}
}

// Any entry that cannot be resolved to one exact listed function drops the
// whole list, so a partial list never looks complete.
func TestReadPVEGuestConfigHostPCIAllOrNothing(t *testing.T) {
	for name, tc := range map[string]struct{ list, entries string }{
		"all functions":     {pvePCIList, `"hostpci0":"0000:01:00.0","hostpci1":"02:00"`},
		"device list":       {pvePCIList, `"hostpci0":"01:00.0;02:00.0"`},
		"resource mapping":  {pvePCIList, `"hostpci0":"mapping=gpu"`},
		"not on node":       {pvePCIList, `"hostpci0":"0000:03:00.0"`},
		"list unreadable":   {"", `"hostpci0":"0000:01:00.0"`},
		"hostile list":      {`{"data":[{"id":"<script>","vendor":"0x10de","device":"0x1b80"}]}`, `"hostpci0":"0000:01:00.0"`},
		"bad vendor":        {`{"data":[{"id":"0000:01:00.0","vendor":"10de;rm","device":"0x1b80"}]}`, `"hostpci0":"0000:01:00.0"`},
		"duplicate address": {`{"data":[{"id":"0000:01:00.0","vendor":"0x10de","device":"0x1b80"},{"id":"0000:01:00.0","vendor":"0x1","device":"0x2"}]}`, `"hostpci0":"0000:01:00.0"`},
	} {
		t.Run(name, func(t *testing.T) {
			e := guestPveEnv(t)
			if tc.list != "" {
				e.pve.set("/api2/json/nodes/pve1/hardware/pci", tc.list)
			}
			c := hostpciConfig(t, e, tc.entries)
			if len(c.GetHostpci()) != 0 {
				t.Fatalf("hostpci = %v", c.GetHostpci())
			}
			if strings.Contains(c.String(), "<script>") {
				t.Fatal("hostile value passed")
			}
		})
	}
}
