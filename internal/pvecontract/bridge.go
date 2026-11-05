// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

// MaxBridgeNameBytes is the longest Linux interface name (IFNAMSIZ-1).
const MaxBridgeNameBytes = 15

// ValidBridgeName reports whether s is a bridge or SDN vnet name as Proxmox
// VE stores it in a guest's netN "bridge=" option. PVE's pve-bridge-id
// format allows [-_.A-Za-z0-9]; the kernel limits interface names to
// IFNAMSIZ-1 bytes and rejects "." and "..". The result is therefore a
// strict subset of Linux ifname rules (no '/', ':', whitespace, control or
// non-ASCII bytes), so names such as "vmbr0.100" or "br-lan" are valid.
func ValidBridgeName(s string) bool {
	if len(s) == 0 || len(s) > MaxBridgeNameBytes || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}
