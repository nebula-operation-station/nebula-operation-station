// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vuln/exportconform"
)

// The client mirror must classify every value of the shared conformance table
// (internal/vuln/exportconform) as the server does: the server runs the same
// table in internal/web/api.

func TestClientVendorMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Vendor {
		t.Run(c.Name, func(t *testing.T) {
			if got := deviceVendorOK(c.Value); got != c.OK {
				t.Fatalf("deviceVendorOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}

func TestClientModelMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Model {
		t.Run(c.Name, func(t *testing.T) {
			if got := deviceModelOK(c.Value); got != c.OK {
				t.Fatalf("deviceModelOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}

func TestClientFirmwareMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Firmware {
		t.Run(c.Name, func(t *testing.T) {
			if got := deviceFirmwareOK(c.Value); got != c.OK {
				t.Fatalf("deviceFirmwareOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}
