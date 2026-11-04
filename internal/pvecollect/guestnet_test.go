// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

func validGuestNetRecord() GuestNetRecord {
	return GuestNetRecord{
		Version:      GuestNetVersion,
		Remote:       "pve-lab",
		ObservedUnix: 1_700_000_000,
		NICs: []GuestNIC{
			{VMID: 101, Kind: pvecontract.GuestQEMU, Index: 0, Bridge: "vmbr0", VLAN: 30, MAC: "bc:24:11:00:00:01"},
			{VMID: 101, Kind: pvecontract.GuestQEMU, Index: 1, Bridge: "vnet10", MAC: "bc:24:11:00:00:02"},
			{VMID: 200, Kind: pvecontract.GuestLXC, Index: 0, Bridge: "vmbr1", VLAN: 4094, MAC: "bc:24:11:00:00:03"},
		},
	}
}

func TestGuestNetAcceptsPVEBridgeNames(t *testing.T) {
	for _, bridge := range []string{"vmbr0.100", "br-lan", "0vmbr", "vnet_1", "abcdefghijklmno"} {
		rec := validGuestNetRecord()
		rec.NICs[0].Bridge = bridge
		raw, err := MarshalGuestNet(rec)
		if err != nil {
			t.Fatalf("bridge %q rejected: %v", bridge, err)
		}
		got, err := DecodeGuestNet(raw)
		if err != nil || got.NICs[0].Bridge != bridge {
			t.Fatalf("bridge %q did not round trip: %+v, %v", bridge, got, err)
		}
	}
}

func TestGuestNICTapNameFollowsProxmoxNaming(t *testing.T) {
	for _, tc := range []struct {
		nic  GuestNIC
		want string
	}{
		{GuestNIC{VMID: 101, Kind: pvecontract.GuestQEMU, Index: 0}, "tap101i0"},
		{GuestNIC{VMID: 101, Kind: pvecontract.GuestQEMU, Index: 31}, "tap101i31"},
		{GuestNIC{VMID: 200, Kind: pvecontract.GuestLXC, Index: 3}, "veth200i3"},
	} {
		if got := tc.nic.Tap(); got != tc.want {
			t.Errorf("Tap(%+v) = %q, want %q", tc.nic, got, tc.want)
		}
	}
}

func TestGuestNetRoundTripIsCanonical(t *testing.T) {
	rec := validGuestNetRecord()
	// Unsorted input is accepted and published in canonical order.
	rec.NICs[0], rec.NICs[2] = rec.NICs[2], rec.NICs[0]
	raw, err := MarshalGuestNet(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeGuestNet(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := validGuestNetRecord()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if strings.Contains(string(raw), "tap") {
		t.Fatalf("tap name must be derived, not carried: %s", raw)
	}
}

func TestGuestNetValidationRejectsMalformedRecords(t *testing.T) {
	long := make([]GuestNIC, MaxGuestNetNICs+1)
	for i := range long {
		long[i] = GuestNIC{VMID: uint64(100 + i/MaxGuestNetNICIndex), Kind: pvecontract.GuestQEMU, Index: i % MaxGuestNetNICIndex, MAC: "bc:24:11:00:00:01"}
	}
	for name, mutate := range map[string]func(*GuestNetRecord){
		"version":          func(r *GuestNetRecord) { r.Version = 2 },
		"remote empty":     func(r *GuestNetRecord) { r.Remote = "" },
		"remote slash":     func(r *GuestNetRecord) { r.Remote = "../x" },
		"observed zero":    func(r *GuestNetRecord) { r.ObservedUnix = 0 },
		"vmid low":         func(r *GuestNetRecord) { r.NICs[0].VMID = pvecontract.MinVMID - 1 },
		"vmid high":        func(r *GuestNetRecord) { r.NICs[0].VMID = pvecontract.MaxVMID + 1 },
		"kind":             func(r *GuestNetRecord) { r.NICs[0].Kind = "docker" },
		"index negative":   func(r *GuestNetRecord) { r.NICs[0].Index = -1 },
		"index high":       func(r *GuestNetRecord) { r.NICs[0].Index = MaxGuestNetNICIndex },
		"bridge comma":     func(r *GuestNetRecord) { r.NICs[0].Bridge = "vmbr0,tag=5" },
		"bridge long":      func(r *GuestNetRecord) { r.NICs[0].Bridge = "vmbr0123456789ab" },
		"bridge control":   func(r *GuestNetRecord) { r.NICs[0].Bridge = "vmbr\x1b0" },
		"bridge dot":       func(r *GuestNetRecord) { r.NICs[0].Bridge = "." },
		"bridge dotdot":    func(r *GuestNetRecord) { r.NICs[0].Bridge = ".." },
		"bridge slash":     func(r *GuestNetRecord) { r.NICs[0].Bridge = "br/0" },
		"bridge space":     func(r *GuestNetRecord) { r.NICs[0].Bridge = "br 0" },
		"bridge colon":     func(r *GuestNetRecord) { r.NICs[0].Bridge = "vmbr0:1" },
		"bridge non-ascii": func(r *GuestNetRecord) { r.NICs[0].Bridge = "brü" },
		"vlan negative":    func(r *GuestNetRecord) { r.NICs[0].VLAN = -1 },
		"vlan high":        func(r *GuestNetRecord) { r.NICs[0].VLAN = pvecontract.MaxVLAN + 1 },
		"mac empty":        func(r *GuestNetRecord) { r.NICs[0].MAC = "" },
		"mac upper":        func(r *GuestNetRecord) { r.NICs[0].MAC = "BC:24:11:00:00:01" },
		"mac dashes":       func(r *GuestNetRecord) { r.NICs[0].MAC = "bc-24-11-00-00-01" },
		"mac zero":         func(r *GuestNetRecord) { r.NICs[0].MAC = "00:00:00:00:00:00" },
		"mac multicast":    func(r *GuestNetRecord) { r.NICs[0].MAC = "01:00:5e:00:00:01" },
		"duplicate netN":   func(r *GuestNetRecord) { r.NICs[1].Index = 0 },
		"too many nics":    func(r *GuestNetRecord) { r.NICs = long },
		"nics nil allowed": nil,
	} {
		t.Run(name, func(t *testing.T) {
			rec := validGuestNetRecord()
			if mutate == nil {
				rec.NICs = nil
				if _, err := MarshalGuestNet(rec); err != nil {
					t.Fatalf("a remote without guest NICs is valid: %v", err)
				}
				return
			}
			mutate(&rec)
			if _, err := MarshalGuestNet(rec); !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("marshal err = %v, want ErrGuestNetInvalid", err)
			}
		})
	}
}

func TestDecodeGuestNetRejectsHostileDocuments(t *testing.T) {
	good, err := MarshalGuestNet(validGuestNetRecord())
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown field":   strings.Replace(string(good), `"version"`, `"tap":"x","version"`, 1),
		"nested unknown":  strings.Replace(string(good), `"bridge"`, `"tap":"tap999i0","bridge"`, 1),
		"trailing data":   string(good) + `{}`,
		"invalid utf8":    strings.Replace(string(good), "vmbr0", "vmbr\xff", 1),
		"not an object":   `[]`,
		"empty":           ``,
		"oversize":        `{"version":1,"remote":"` + strings.Repeat("a", MaxGuestNetBytes) + `"}`,
		"vlan as string":  strings.Replace(string(good), `"vlan":30`, `"vlan":"30"`, 1),
		"mac uppercase":   strings.Replace(string(good), "bc:24:11:00:00:01", "BC:24:11:00:00:01", 1),
		"duplicate nic":   strings.Replace(string(good), `"index":1`, `"index":0`, 1),
		"vmid fractional": strings.Replace(string(good), `"vmid":200`, `"vmid":200.5`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGuestNet([]byte(raw)); !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("decode err = %v, want ErrGuestNetInvalid", err)
			}
		})
	}
}
