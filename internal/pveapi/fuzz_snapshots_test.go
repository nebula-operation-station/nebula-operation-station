// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzListSnapshots feeds hostile bodies to ListSnapshots (the get path, which
// rejects invalid UTF-8 at the body level) and asserts the per-guest snapshot
// count limit holds on success.
func FuzzListSnapshots(f *testing.F) {
	for _, name := range []string{"snapshot_qemu_pve8.json", "snapshot_qemu_pve9.json", "snapshot_lxc.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		list, err := c.ListSnapshots(ctx, "pve1", "qemu", 100)
		assertFuzzInvariants(t, data, MaxResponseBytes, true, err, func() {
			if len(list.Snapshots) > MaxSnapshotsPerGuest {
				t.Fatalf("snapshots %d exceeds MaxSnapshotsPerGuest %d", len(list.Snapshots), MaxSnapshotsPerGuest)
			}
		})
	})
}
