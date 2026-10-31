// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzListQemu feeds hostile bodies to ListQemu (parseGuestList via the do
// path). The do path sanitizes (does not reject) invalid UTF-8, so the asserted
// rejections are the size limit and the per-page count limit.
func FuzzListQemu(f *testing.F) {
	for _, name := range []string{"pve8/qemu_pve1.json", "pve8/qemu_pve2.json"} {
		f.Add(wrapData(readFuzzFixture(f, name)))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		guests, err := c.ListQemu(ctx, "pve1")
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, func() {
			if len(guests) > MaxObjectsPerPage {
				t.Fatalf("guest list %d exceeds MaxObjectsPerPage %d", len(guests), MaxObjectsPerPage)
			}
		})
	})
}

// FuzzListLxc is the LXC twin of FuzzListQemu.
func FuzzListLxc(f *testing.F) {
	for _, name := range []string{"pve8/lxc_pve1.json", "pve8/lxc_pve2.json"} {
		f.Add(wrapData(readFuzzFixture(f, name)))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		guests, err := c.ListLxc(ctx, "pve1")
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, func() {
			if len(guests) > MaxObjectsPerPage {
				t.Fatalf("guest list %d exceeds MaxObjectsPerPage %d", len(guests), MaxObjectsPerPage)
			}
		})
	})
}

// FuzzListNodes feeds hostile bodies to ListNodes (the node-list parser).
func FuzzListNodes(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/nodes.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		nodes, err := c.ListNodes(ctx)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, func() {
			if len(nodes) > MaxObjectsPerPage {
				t.Fatalf("node list %d exceeds MaxObjectsPerPage %d", len(nodes), MaxObjectsPerPage)
			}
		})
	})
}
