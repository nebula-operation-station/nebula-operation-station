// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
)

// FuzzReadBackups feeds hostile bodies to ReadBackups, which uses the stricter
// getJSON + strictJSON path (single JSON document, no duplicate keys, bounded
// depth). The backup client has a larger 4 MiB response limit. The catch-all
// server serves the same hostile body to the catalog and jobs endpoints.
func FuzzReadBackups(f *testing.F) {
	for _, name := range []string{"content-vzdump-pve8.json", "jobs-pve8.json"} {
		f.Add(readFuzzFixture(f, name))
	}
	body := &atomic.Value{}
	body.Store([]byte(`{"data":[]}`))
	fs := newFuzzServer(f, func(string) []byte {
		b, _ := body.Load().([]byte)
		return b
	})
	c, err := NewBackupClient(fs.url()+"/api2/json", http.DefaultClient, func() string {
		return testToken
	})
	if err != nil {
		f.Fatalf("NewBackupClient: %v", err)
	}
	opts := BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "vzdump"}},
		Scope:   ReadScope{FullContent: true},
	}
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.ReadBackups(ctx, opts)
		assertFuzzInvariants(t, data, int(defaultMaxResponseBytes), false, err, nil)
	})
}
