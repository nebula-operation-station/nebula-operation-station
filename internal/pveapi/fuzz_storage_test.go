// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzListStorages feeds hostile bodies to ListStorages (the get path, which
// rejects invalid UTF-8 at the body level) and asserts the per-remote storage
// count limit holds on success.
func FuzzListStorages(f *testing.F) {
	for _, name := range []string{"storage_pve8.json", "storage_pve9.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		list, err := c.ListStorages(ctx, "pve1")
		assertFuzzInvariants(t, data, MaxResponseBytes, true, err, func() {
			if len(list.Storages) > MaxStoragesPerRemote {
				t.Fatalf("storages %d exceeds MaxStoragesPerRemote %d", len(list.Storages), MaxStoragesPerRemote)
			}
		})
	})
}
