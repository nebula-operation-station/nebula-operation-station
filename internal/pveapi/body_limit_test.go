// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// jsonBody returns a valid JSON envelope of exactly n bytes.
func jsonBody(t *testing.T, n int) string {
	t.Helper()
	const pre, post = `{"data":"`, `"}`
	if n < len(pre)+len(post) {
		t.Fatalf("body size %d too small", n)
	}
	return pre + strings.Repeat("x", n-len(pre)-len(post)) + post
}

// TestReadPathsEnforceTheirBodyLimit serves a body exactly at and one byte
// over each read path's limit over HTTP: general reads (do, get,
// clusterGet) at DefaultMaxBody, ReadBackups' getJSON at the backup
// default, and every path at a MaxBody override. A path that used the
// wrong limit fails here.
func TestReadPathsEnforceTheirBodyLimit(t *testing.T) {
	ctx := context.Background()
	paths := map[string]func(c *Client) error{
		"do":         func(c *Client) error { _, err := c.do(ctx, "/nodes"); return err },
		"get":        func(c *Client) error { var v any; return c.get(ctx, "/nodes", &v) },
		"clusterGet": func(c *Client) error { _, _, err := c.clusterGet(ctx, "/cluster/status"); return err },
		"getJSON":    func(c *Client) error { var v any; return c.getJSON(ctx, "/nodes", nil, &v) },
	}
	defaults := map[string]int{
		"do":         DefaultMaxBody,
		"get":        DefaultMaxBody,
		"clusterGet": DefaultMaxBody,
		"getJSON":    int(defaultMaxResponseBytes),
	}
	for name, call := range paths {
		for _, override := range []int64{0, 128} {
			limit := defaults[name]
			if override > 0 {
				limit = int(override)
			}
			for _, tc := range []struct {
				size int
				over bool
			}{{limit, false}, {limit + 1, true}} {
				t.Run(fmt.Sprintf("%s/override=%d/size=%d", name, override, tc.size), func(t *testing.T) {
					body := jsonBody(t, tc.size)
					srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(body))
					}))
					defer srv.Close()
					c, err := NewClient(srv.Client(), srv.URL+apiRoot, func(context.Context) (string, error) { return "t", nil })
					if err != nil {
						t.Fatal(err)
					}
					c.MaxBody = override
					err = call(c)
					if tc.over && err == nil {
						t.Fatalf("body of %d bytes over limit %d accepted", tc.size, limit)
					}
					if !tc.over && err != nil {
						t.Fatalf("body of %d bytes at limit %d refused: %v", tc.size, limit, err)
					}
				})
			}
		}
	}
}
