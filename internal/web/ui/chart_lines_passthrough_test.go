// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// configPVEStore adds the stored guest config read, per VMID.
type configPVEStore struct {
	plainPVEStore
	byVMID map[uint64]pveinventory.GuestConfig
}

func (s *configPVEStore) GetGuestConfig(_ context.Context, remoteID string, vmid, generation uint64) (pveinventory.GuestConfig, error) {
	c, ok := s.byVMID[vmid]
	if !ok || remoteID != "lab" || generation != 1 {
		return pveinventory.GuestConfig{}, pveinventory.ErrGuestNotFound
	}
	return c, nil
}

// passCfg is a guest config with the given hostpci devices, observed age
// before linesNow.
func passCfg(age time.Duration, devs ...pvecontract.HostPCI) pveinventory.GuestConfig {
	return pveinventory.GuestConfig{HostPCI: devs, ObservedAt: linesNow.Add(-age)}
}

var (
	gpuA6000  = pvecontract.HostPCI{ID: "hostpci0", Device: "PCI-10de:2230:65:00.0", Target: "0000:65:00.0"}
	nicIntel  = pvecontract.HostPCI{ID: "hostpci1", Device: "PCI-8086:1521:03:00.0", Target: "0000:03:00.0"}
	gpuSecond = pvecontract.HostPCI{ID: "hostpci2", Device: "PCI-10de:2204:b3:00.0", Target: "0000:b3:00.0"}
)

func TestChartPassthroughLineOnNode(t *testing.T) {
	store := &configPVEStore{byVMID: map[uint64]pveinventory.GuestConfig{
		101: passCfg(time.Minute, gpuA6000, nicIntel, gpuSecond),
	}}
	body := backupBody(t, store, backupTree(2))
	if got := strings.Count(body, "chart__line--gpu"); got != 2 {
		t.Errorf("passthrough GPU lines = %d, want 2 (NVIDIA only, one per device)", got)
	}
	for _, want := range []string{
		"NVIDIA 10de:2230 (65:00.0) → vm101 (101) · passthrough, no host telemetry",
		"NVIDIA 10de:2204 (b3:00.0) → vm101 (101)",
		`title="hostpci0 PCI-10de:2230:65:00.0"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing %q", want)
		}
	}
	if strings.Contains(body, "8086:1521") {
		t.Error("a non-NVIDIA passthrough device must not be shown as a GPU")
	}
	if strings.Contains(body, "util ") {
		t.Error("a passed-through GPU must never imply host driver telemetry")
	}
	if !hostNodeHas(body, "chart__node--neutral") {
		t.Error("a passthrough line has no level and must not raise the border")
	}
}

func TestChartPassthroughLineHiddenWithoutSource(t *testing.T) {
	// No config read on the store, no stored config, a config without
	// NVIDIA devices: no line.
	if body := backupBody(t, plainPVEStore{}, backupTree(1)); strings.Contains(body, "chart__line--gpu") {
		t.Error("passthrough line rendered although the store has no config read")
	}
	store := &configPVEStore{byVMID: map[uint64]pveinventory.GuestConfig{102: passCfg(time.Minute, nicIntel)}}
	if body := backupBody(t, store, backupTree(2)); strings.Contains(body, "chart__line--gpu") {
		t.Error("passthrough line rendered without an NVIDIA hostpci device")
	}
}

func TestChartPassthroughLineStale(t *testing.T) {
	store := &configPVEStore{byVMID: map[uint64]pveinventory.GuestConfig{101: passCfg(25*time.Hour, gpuA6000)}}
	body := backupBody(t, store, backupTree(1))
	if !strings.Contains(body, "chart__line--gpu chart__line--stale") || !strings.Contains(body, "· config stale") {
		t.Error("an old guest config should make the passthrough line stale")
	}
}

func TestChartPassthroughLineEscapesGuestName(t *testing.T) {
	tree := backupTree(1)
	tree.Roots[0].Children[0].Name = `<img src=x onerror=alert(1)>`
	store := &configPVEStore{byVMID: map[uint64]pveinventory.GuestConfig{101: passCfg(time.Minute, gpuA6000)}}
	body := backupBody(t, store, tree)
	if strings.Contains(body, "<img src=x") {
		t.Error("guest name rendered as markup")
	}
	if !strings.Contains(body, "→ &lt;img src=x onerror=alert(1)&gt; (101)") {
		t.Error("guest name not escaped in the passthrough line")
	}
}
