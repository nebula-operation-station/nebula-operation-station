// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

var fuzzGuestNetMAC = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)

// multicastOctet reports whether the first octet of mac has the group bit set.
func multicastOctet(mac string) bool {
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err != nil || b&1 != 0
}

// checkGuestNetOracle asserts the decoder's success contract on rec: every
// named bound holds, NICs are strictly ordered by (VMID, Index), validating
// the decoded value changes nothing, and a re-encode round trip is exact.
func checkGuestNetOracle(t *testing.T, rec GuestNetRecord) {
	t.Helper()
	if rec.Version != GuestNetVersion || !pvecontract.ValidRemoteID(rec.Remote) || rec.ObservedUnix <= 0 {
		t.Fatalf("accepted header version=%d remote=%q observed=%d", rec.Version, rec.Remote, rec.ObservedUnix)
	}
	if len(rec.NICs) > MaxGuestNetNICs {
		t.Fatalf("accepted %d nics (max %d)", len(rec.NICs), MaxGuestNetNICs)
	}
	for i, n := range rec.NICs {
		if i > 0 && compareGuestNIC(rec.NICs[i-1], n) >= 0 {
			t.Fatalf("nic %d not strictly ordered after nic %d", i, i-1)
		}
		if n.VMID < pvecontract.MinVMID || n.VMID > pvecontract.MaxVMID {
			t.Fatalf("nic %d: vmid %d accepted", i, n.VMID)
		}
		if n.Kind != pvecontract.GuestQEMU && n.Kind != pvecontract.GuestLXC {
			t.Fatalf("nic %d: kind %q accepted", i, n.Kind)
		}
		if n.Index < 0 || n.Index >= MaxGuestNetNICIndex {
			t.Fatalf("nic %d: index %d accepted", i, n.Index)
		}
		if n.Bridge != "" && !pvecontract.ValidBridgeName(n.Bridge) {
			t.Fatalf("nic %d: bridge %q accepted", i, n.Bridge)
		}
		if n.VLAN < 0 || n.VLAN > pvecontract.MaxVLAN {
			t.Fatalf("nic %d: vlan %d accepted", i, n.VLAN)
		}
		if !fuzzGuestNetMAC.MatchString(n.MAC) || n.MAC == "00:00:00:00:00:00" || multicastOctet(n.MAC) {
			t.Fatalf("nic %d: mac %q accepted", i, n.MAC)
		}
	}
	again, err := ValidateGuestNet(rec)
	if err != nil || !reflect.DeepEqual(again, rec) {
		t.Fatalf("validation of a decoded record changed it (%v)", err)
	}
	raw, err := MarshalGuestNet(rec)
	if err != nil {
		t.Fatalf("re-encode of an accepted record: %v", err)
	}
	back, err := DecodeGuestNet(raw)
	if err != nil {
		t.Fatalf("decode of re-encoded record: %v", err)
	}
	if !reflect.DeepEqual(back, rec) {
		t.Fatalf("round trip changed the value: %+v -> %+v", rec, back)
	}
}

// FuzzDecodeGuestNet feeds arbitrary bytes to the guest NIC record decoder.
// It must never panic and must reject with ErrGuestNetInvalid only; an
// accepted record satisfies every named bound and round-trips exactly.
func FuzzDecodeGuestNet(f *testing.F) {
	good, err := MarshalGuestNet(validGuestNetRecord())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	empty, err := MarshalGuestNet(GuestNetRecord{Version: GuestNetVersion, Remote: "pve-lab", ObservedUnix: 1})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(empty)
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":[]}`))
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":[{"vmid":101,"kind":"qemu","index":0,"vlan":0,"mac":"bc:24:11:00:00:01","bridge":"vmbr0\u0000"}]}`))
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":[{"vmid":101,"kind":"qemu","index":0,"vlan":4095,"mac":"bc:24:11:00:00:01"}]}`))
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":[{"vmid":1e9,"kind":"lxc","index":0,"vlan":0,"mac":"bc:24:11:00:00:01"}]}`))
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":[{"vmid":101,"kind":"qemu","index":0,"vlan":0,"mac":"bc:24:11:00:00:01"},{"vmid":101,"kind":"qemu","index":0,"vlan":0,"mac":"bc:24:11:00:00:02"}]}`))
	f.Add([]byte(`{"version":1,"remote":"pve-lab","observed_unix":1,"nics":null}`))
	f.Add([]byte(strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200)))
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := DecodeGuestNet(data)
		if err != nil {
			if !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("decode error %v does not wrap ErrGuestNetInvalid", err)
			}
			return
		}
		checkGuestNetOracle(t, rec)
	})
}
