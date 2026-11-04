// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

// Guest NIC enrichment for the traffic map (ADR 0009 D1, tier 2): the
// collector publishes, per remote, each guest NIC's bridge, VLAN tag and
// MAC; the host-side tap device is derived from the guest identity. The
// server only imports these spool files and never reads Proxmox itself.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

const (
	// GuestNetVersion is the current guest NIC record format.
	GuestNetVersion = 1
	// MaxGuestNetBytes bounds one encoded guest NIC record.
	MaxGuestNetBytes = 4 << 20
	// MaxGuestNetNICs bounds the NICs in one record (all guests of a remote).
	MaxGuestNetNICs = 16384
	// MaxGuestNetNICIndex is one past the highest netN index Proxmox
	// accepts (net0 … net31).
	MaxGuestNetNICIndex = 32
)

// ErrGuestNetInvalid means a guest NIC record failed decoding or validation.
var ErrGuestNetInvalid = errors.New("pvecollect: invalid guest nic record")

var (
	guestNetMACRe = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
)

// GuestNetRecord is one remote's guest NIC snapshot as written by the
// collector into the spool.
type GuestNetRecord struct {
	Version      int    `json:"version"`
	Remote       string `json:"remote"`
	ObservedUnix int64  `json:"observed_unix"`
	// NICs are sorted by VMID and Index; (VMID, Index) is unique.
	NICs []GuestNIC `json:"nics"`
}

// GuestNIC is one guest netN device from the guest configuration.
type GuestNIC struct {
	VMID uint64                `json:"vmid"`
	Kind pvecontract.GuestKind `json:"kind"`
	// Index is N of netN.
	Index int `json:"index"`
	// Bridge is the Linux bridge or SDN vnet, "" when the NIC has none.
	Bridge string `json:"bridge,omitempty"`
	// VLAN is the 802.1Q tag, 0 when untagged.
	VLAN int `json:"vlan"`
	// MAC is the lowercase unicast aa:bb:cc:dd:ee:ff MAC.
	MAC string `json:"mac"`
}

// Tap returns the host-side device Proxmox creates for the NIC:
// tap<vmid>i<n> for QEMU guests and veth<vmid>i<n> for containers. It is
// derived from the guest identity and never read from a record.
func (n GuestNIC) Tap() string {
	prefix := "tap"
	if n.Kind == pvecontract.GuestLXC {
		prefix = "veth"
	}
	return prefix + strconv.FormatUint(n.VMID, 10) + "i" + strconv.Itoa(n.Index)
}

// ValidateGuestNet validates rec and returns a copy with the NICs in
// canonical order. It never mutates rec.
func ValidateGuestNet(rec GuestNetRecord) (GuestNetRecord, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	if rec.Version != GuestNetVersion {
		add("version must be %d", GuestNetVersion)
	}
	if !pvecontract.ValidRemoteID(rec.Remote) {
		add("remote is malformed")
	}
	if rec.ObservedUnix <= 0 {
		add("observed_unix must be positive")
	}
	if len(rec.NICs) > MaxGuestNetNICs {
		add("too many nics (%d > %d)", len(rec.NICs), MaxGuestNetNICs)
		return GuestNetRecord{}, guestNetError(p)
	}
	nics := slices.Clone(rec.NICs)
	slices.SortFunc(nics, compareGuestNIC)
	for i, n := range nics {
		validateGuestNIC(n, add)
		if i > 0 && compareGuestNIC(nics[i-1], n) == 0 {
			add("vmid %d net%d is duplicated", n.VMID, n.Index)
		}
	}
	if len(p) > 0 {
		return GuestNetRecord{}, guestNetError(p)
	}
	rec.NICs = nics
	return rec, nil
}

func compareGuestNIC(a, b GuestNIC) int {
	if a.VMID != b.VMID {
		if a.VMID < b.VMID {
			return -1
		}
		return 1
	}
	return a.Index - b.Index
}

// validateGuestNIC reports problems without echoing host-supplied text.
func validateGuestNIC(n GuestNIC, add func(format string, args ...any)) {
	if n.VMID < pvecontract.MinVMID || n.VMID > pvecontract.MaxVMID {
		add("vmid %d out of range", n.VMID)
	}
	where := fmt.Sprintf("vmid %d net%d", n.VMID, n.Index)
	if n.Kind != pvecontract.GuestQEMU && n.Kind != pvecontract.GuestLXC {
		add("%s: kind is unknown", where)
	}
	if n.Index < 0 || n.Index >= MaxGuestNetNICIndex {
		add("vmid %d: nic index out of range", n.VMID)
	}
	// Bridge names follow PVE's bridge-id alphabet (pvecontract.ValidBridgeName),
	// so VLAN sub-interfaces ("vmbr0.100") and dashed names ("br-lan") pass.
	if n.Bridge != "" && !pvecontract.ValidBridgeName(n.Bridge) {
		add("%s: bridge is malformed", where)
	}
	if n.VLAN < 0 || n.VLAN > pvecontract.MaxVLAN {
		add("%s: vlan out of range", where)
	}
	if !guestNetMACRe.MatchString(n.MAC) {
		add("%s: mac is malformed", where)
	} else if n.MAC == "00:00:00:00:00:00" {
		add("%s: mac is zero", where)
	} else if b, _ := strconv.ParseUint(n.MAC[:2], 16, 8); b&1 != 0 {
		add("%s: mac is not unicast", where)
	}
}

func guestNetError(problems []string) error {
	return fmt.Errorf("%w: %v", ErrGuestNetInvalid, problems)
}

// MarshalGuestNet validates rec and returns its canonical JSON encoding.
func MarshalGuestNet(rec GuestNetRecord) ([]byte, error) {
	v, err := ValidateGuestNet(rec)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("pvecollect: marshal guest nic record: %w", err)
	}
	if len(raw) > MaxGuestNetBytes {
		return nil, fmt.Errorf("%w: %d bytes exceed %d", ErrGuestNetInvalid, len(raw), MaxGuestNetBytes)
	}
	return raw, nil
}

// DecodeGuestNet strictly decodes and validates an untrusted record: size
// bound, valid UTF-8, exactly one JSON object, no unknown fields.
func DecodeGuestNet(raw []byte) (GuestNetRecord, error) {
	if len(raw) > MaxGuestNetBytes {
		return GuestNetRecord{}, fmt.Errorf("%w: %d bytes exceed %d", ErrGuestNetInvalid, len(raw), MaxGuestNetBytes)
	}
	if !utf8.Valid(raw) {
		return GuestNetRecord{}, fmt.Errorf("%w: not valid UTF-8", ErrGuestNetInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec GuestNetRecord
	if err := dec.Decode(&rec); err != nil {
		// The decoder's message can quote host-chosen keys; do not echo it.
		return GuestNetRecord{}, fmt.Errorf("%w: malformed JSON document", ErrGuestNetInvalid)
	}
	if dec.More() {
		return GuestNetRecord{}, fmt.Errorf("%w: trailing data", ErrGuestNetInvalid)
	}
	return ValidateGuestNet(rec)
}
