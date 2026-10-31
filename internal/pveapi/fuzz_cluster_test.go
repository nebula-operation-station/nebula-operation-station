// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzClusterStatus feeds hostile bodies to ClusterStatus (the clusterGet +
// decodeData path, which rejects invalid UTF-8 at the body level) and asserts
// the online-node count limit holds on success.
func FuzzClusterStatus(f *testing.F) {
	for _, name := range []string{"cluster_status_pve8.json", "cluster_status_pve9.json", "cluster_status_standalone.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		st, err := c.ClusterStatus(ctx)
		assertFuzzInvariants(t, data, DefaultMaxBody, true, err, func() {
			if st.NodesOnline > maxClusterNodes {
				t.Fatalf("NodesOnline %d exceeds maxClusterNodes %d", st.NodesOnline, maxClusterNodes)
			}
		})
	})
}

// FuzzHAStatus feeds hostile bodies to HAStatus, which reads two endpoints
// (resources and status); the catch-all server serves the same hostile body to
// both. The body-level size and UTF-8 limits are asserted.
func FuzzHAStatus(f *testing.F) {
	for _, name := range []string{"ha_status_pve8.json", "ha_status_pve9.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.HAStatus(ctx)
		assertFuzzInvariants(t, data, DefaultMaxBody, true, err, nil)
	})
}
