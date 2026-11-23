// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"os"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

var convertAt = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// parseFixture parses a package.list_installed text fixture of osdebian.
func parseFixture(t *testing.T, name string, distro vulnver.Distro) osdebian.InstalledInventory {
	t.Helper()
	data, err := os.ReadFile("../executions/osdebian/testdata/installed/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return osdebian.ParseInstalled(data, osdebian.ReadStatus{}, distro)
}

// findComponent returns the stored component of source, or false.
func findComponent(r Read, source string) (Component, bool) {
	for _, c := range r.Components {
		if c.Source == source {
			return c, true
		}
	}
	return Component{}, false
}

func TestEcosystemMapsDebianAndUbuntu(t *testing.T) {
	tests := []struct {
		name, id, ver, code, eco string
		distro                   vulnver.Distro
	}{
		{"debian 12", "debian", "12", "bookworm", "debian:bookworm", vulnver.DistroDebian},
		{"ubuntu 24.04", "ubuntu", "24.04", "noble", "ubuntu:24.04", vulnver.DistroUbuntu},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eco, distro := Ecosystem(tc.id, tc.ver, tc.code)
			if eco != tc.eco || distro != tc.distro {
				t.Fatalf("Ecosystem = %q %d, want %q %d", eco, distro, tc.eco, tc.distro)
			}
		})
	}
}

func TestEcosystemRefusesUnsupportedOrMalformedRelease(t *testing.T) {
	tests := []struct {
		name, id, ver, code string
	}{
		{"alpine", "alpine", "3.19", ""},
		{"fedora", "fedora", "40", "forty"},
		{"empty id", "", "12", "bookworm"},
		{"debian without codename", "debian", "12", ""},
		{"debian uppercase codename", "debian", "12", "Bookworm"},
		{"debian one-letter codename", "debian", "12", "b"},
		{"debian codename with dash", "debian", "12", "book-worm"},
		{"ubuntu without version", "ubuntu", "", "noble"},
		{"ubuntu one-digit minor", "ubuntu", "24.4", "noble"},
		{"ubuntu three digits", "ubuntu", "024.04", "noble"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eco, distro := Ecosystem(tc.id, tc.ver, tc.code)
			if eco != "" || distro != 0 {
				t.Fatalf("Ecosystem = %q %d, want empty and 0", eco, distro)
			}
		})
	}
}

func TestFromInstalledDebian12StoresCompleteRead(t *testing.T) {
	inv := parseFixture(t, "debian12.txt", vulnver.DistroDebian)
	if !inv.Complete {
		t.Fatalf("fixture not complete: %s", inv.Reason)
	}
	r := FromInstalled("host-1", "exec-1", convertAt, "debian:bookworm", inv)
	if !r.Complete || r.Reason != "" {
		t.Fatalf("read complete=%v reason=%q, want complete", r.Complete, r.Reason)
	}
	if r.HostID != "host-1" || r.ExecutionID != "exec-1" || !r.ReadAt.Equal(convertAt) {
		t.Fatalf("header = %q %q %v", r.HostID, r.ExecutionID, r.ReadAt)
	}
	if r.Ecosystem != "debian:bookworm" {
		t.Fatalf("ecosystem = %q", r.Ecosystem)
	}
	if r.Kernel.Release != "6.1.0-26-amd64" || r.Kernel.State != string(inv.RunningKernel.State) ||
		r.Kernel.Source != inv.RunningKernel.Source || r.Kernel.Version != inv.RunningKernel.Version {
		t.Fatalf("kernel = %+v, want it from RunningKernel %+v", r.Kernel, inv.RunningKernel)
	}
	c, ok := findComponent(r, "jansson")
	if !ok || c.SourceVersion != "2.14-2" || len(c.Binaries) != 1 ||
		c.Binaries[0] != (Binary{Name: "libjansson4", Version: "2.14-2+b1", Arch: "amd64"}) {
		t.Fatalf("jansson component = %+v, ok %v", c, ok)
	}
	if c, ok := findComponent(r, "glibc"); !ok || len(c.Binaries) != 2 {
		t.Fatalf("glibc component = %+v, ok %v; want both architectures", c, ok)
	}
	if c, ok := findComponent(r, "linux"); !ok || c.SourceVersion != "6.1.112-1" {
		t.Fatalf("linux component = %+v, ok %v", c, ok)
	}
	for _, c := range r.Components {
		if vulnver.NeverVersionBasis(c.Source) {
			t.Fatalf("never-basis source stored as component: %q", c.Source)
		}
	}
	if _, ok := findComponent(r, "linux-signed-amd64"); ok {
		t.Fatalf("linux-signed-amd64 stored as component")
	}
}

func TestFromInstalledKeepsLowestSourceVersion(t *testing.T) {
	inv := osdebian.InstalledInventory{
		Complete: true,
		Packages: []osdebian.InstalledPackage{
			{Name: "libfoo1", Arch: "amd64", Version: "1.0-2", Source: "foo", SourceVersion: "1.0-2"},
			{Name: "foo-bin", Arch: "amd64", Version: "1.0-1", Source: "foo", SourceVersion: "1.0-1"},
		},
	}
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	c, ok := findComponent(r, "foo")
	if !ok || c.SourceVersion != "1.0-1" || len(c.Binaries) != 2 {
		t.Fatalf("foo component = %+v, ok %v; want lowest version 1.0-1 with both binaries", c, ok)
	}
	if !r.Complete {
		t.Fatalf("read partial: %q", r.Reason)
	}
}

func TestFromInstalledMissingBasisMakesReadPartial(t *testing.T) {
	inv := osdebian.InstalledInventory{
		Complete: true,
		Packages: []osdebian.InstalledPackage{
			{Name: "good", Arch: "amd64", Version: "1.0", Source: "good", SourceVersion: "1.0"},
			{Name: "bad", Arch: "amd64", Version: "1.0", Source: "bad", SourceVersion: ""},
		},
	}
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	if r.Complete {
		t.Fatalf("read with a source without basis is complete")
	}
	if r.Reason != ReasonNoBasis {
		t.Fatalf("reason = %q, want the fixed %q", r.Reason, ReasonNoBasis)
	}
	if _, ok := findComponent(r, "bad"); ok {
		t.Fatalf("source without basis stored")
	}
	if _, ok := findComponent(r, "good"); !ok {
		t.Fatalf("other source dropped with the failing one")
	}
	if r.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1 binary", r.Dropped)
	}
}

func TestFromInstalledNeverStoresKernelMetaOrSignedSources(t *testing.T) {
	inv := osdebian.InstalledInventory{
		Complete: true,
		Packages: []osdebian.InstalledPackage{
			{Name: "linux-image-amd64", Arch: "amd64", Version: "6.1.112-1", Source: "linux-signed-amd64", SourceVersion: "6.1.112+1"},
			{Name: "linux-image-6.1.0-26-amd64", Arch: "amd64", Version: "6.1.112-1", Source: "linux-signed-amd64", SourceVersion: "6.1.112+1"},
			{Name: "linux-meta", Arch: "all", Version: "6.1.112", Source: "linux-meta", SourceVersion: "6.1.112"},
			{Name: "linux-latest", Arch: "all", Version: "1", Source: "linux-latest", SourceVersion: "1"},
		},
	}
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	if len(r.Components) != 0 {
		t.Fatalf("components = %+v, want none", r.Components)
	}
	if !r.Complete {
		t.Fatalf("read partial: %q", r.Reason)
	}
}

func TestFromInstalledWithoutEcosystemIsPartialAndStoresNoComponents(t *testing.T) {
	inv := parseFixture(t, "debian12.txt", vulnver.DistroDebian)
	for _, eco := range []string{"", "alpine:3.19", "debian:Bookworm"} {
		r := FromInstalled("h", "e", convertAt, eco, inv)
		if r.Complete {
			t.Fatalf("ecosystem %q: read complete", eco)
		}
		if r.Reason != ReasonNoEcosystem {
			t.Fatalf("ecosystem %q: reason = %q, want %q", eco, r.Reason, ReasonNoEcosystem)
		}
		if r.Ecosystem != "" || len(r.Components) != 0 {
			t.Fatalf("ecosystem %q: stored ecosystem %q and %d components", eco, r.Ecosystem, len(r.Components))
		}
	}
}

func TestFromInstalledKeepsPartialInventoryPartial(t *testing.T) {
	inv := parseFixture(t, "debian12.txt", vulnver.DistroDebian)
	inv.Complete = false
	inv.Reason = osdebian.ReasonTruncated
	inv.Dropped = 3
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	if r.Complete || r.Reason != osdebian.ReasonTruncated || r.Dropped != 3 {
		t.Fatalf("read complete=%v reason=%q dropped=%d", r.Complete, r.Reason, r.Dropped)
	}
	if _, ok := findComponent(r, "jansson"); !ok {
		t.Fatalf("partial inventory lost its packages")
	}
}

func TestFromInstalledIncompleteWithoutReasonStillPartial(t *testing.T) {
	inv := osdebian.InstalledInventory{Complete: false}
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	if r.Complete || r.Reason == "" {
		t.Fatalf("read complete=%v reason=%q, want partial with a reason", r.Complete, r.Reason)
	}
}

func TestFromInstalledClampsDroppedToLimit(t *testing.T) {
	inv := osdebian.InstalledInventory{Complete: false, Reason: osdebian.ReasonMalformed, Dropped: MaxDropped + 7}
	r := FromInstalled("h", "e", convertAt, "debian:bookworm", inv)
	if r.Dropped != MaxDropped {
		t.Fatalf("dropped = %d, want %d", r.Dropped, MaxDropped)
	}
	if err := validateRead(r, convertAt); err != nil {
		t.Fatalf("clamped read rejected: %v", err)
	}
}

func TestFromInstalledReasonsAreFixedText(t *testing.T) {
	for _, reason := range []string{ReasonNoEcosystem, ReasonNoBasis, ReasonIncomplete} {
		if len(reason) > MaxReasonBytes {
			t.Fatalf("reason %q longer than %d bytes", reason, MaxReasonBytes)
		}
	}
}
