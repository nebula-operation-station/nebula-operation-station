// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vuln/exportconform"
)

// The server must classify every value of the shared conformance table
// (internal/vuln/exportconform) as the table says. The client mirror runs the
// same table in internal/vulnagent/nosclient.

func TestServerVendorMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Vendor {
		t.Run(c.Name, func(t *testing.T) {
			if got := vendorOK(c.Value); got != c.OK {
				t.Fatalf("vendorOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}

func TestServerModelMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Model {
		t.Run(c.Name, func(t *testing.T) {
			if got := modelCodeOK(c.Value); got != c.OK {
				t.Fatalf("modelCodeOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}

func TestServerFirmwareMatchesConformanceTable(t *testing.T) {
	for _, c := range exportconform.Firmware {
		t.Run(c.Name, func(t *testing.T) {
			if got := deviceFirmwareOK(c.Value); got != c.OK {
				t.Fatalf("deviceFirmwareOK(%q) = %v, want %v", c.Value, got, c.OK)
			}
		})
	}
}
