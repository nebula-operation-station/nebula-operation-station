// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzNodeTasks feeds hostile bodies to NodeTasks (the clusterGet + decodeData
// path, which rejects invalid UTF-8). NodeTasks paginates in taskPageSize
// chunks up to maxTaskScan; the catch-all server serves the same hostile body
// to every page, so the scan is always bounded. The task count limit is
// asserted on success.
func FuzzNodeTasks(f *testing.F) {
	for _, name := range []string{"tasklist_pve8.json", "tasklist_pve9.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		list, err := c.NodeTasks(ctx, "pve1", TaskFilter{})
		assertFuzzInvariants(t, data, DefaultMaxBody, true, err, func() {
			if len(list.Tasks) > MaxTaskLimit {
				t.Fatalf("tasks %d exceeds MaxTaskLimit %d", len(list.Tasks), MaxTaskLimit)
			}
		})
	})
}
