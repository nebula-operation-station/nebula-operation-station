// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// chartRegistryReads records how the chart asks for private digests. With
// block it ignores WithCacheOnly and waits for its context to end, like an
// implementation that would call the executor for every host.
type chartRegistryReads struct {
	*fakeRegistryReads
	block bool

	mu        sync.Mutex
	hosts     []string
	cacheOnly []bool
	deadline  []bool
}

func (c *chartRegistryReads) ResolveImageUpdates(ctx context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates {
	_, hasDeadline := ctx.Deadline()
	c.mu.Lock()
	c.hosts = append(c.hosts, registrymeta.ReadHost(ctx))
	c.cacheOnly = append(c.cacheOnly, registrymeta.CacheOnly(ctx))
	c.deadline = append(c.deadline, hasDeadline)
	c.mu.Unlock()
	if c.block {
		<-ctx.Done()
		return u
	}
	return c.fakeRegistryReads.ResolveImageUpdates(ctx, u)
}

// privateChartHandler serves the chart for n hosts, each running one
// private image whose check_updates status is "unknown".
func privateChartHandler(t *testing.T, n int, r ui.RegistryReads) *ui.Handler {
	t.Helper()
	observed := time.Unix(1791960000, 0)
	const img = "registry.corp.example/team/app:1.0"
	ops := &chartOps{fakeOps: &fakeOps{}, states: map[string]executions.OpsState{},
		docker: map[string]executions.LastResultRow{}, dockerUp: map[string]executions.LastResultRow{}}
	var hosts []inventory.Host
	for i := range n {
		id := fmt.Sprintf("h%02d", i)
		hosts = append(hosts, inventory.Host{ID: id, DisplayName: id, Environment: inventory.EnvProd, Criticality: inventory.CriticalityLow})
		ops.states[id] = executions.OpsState{State: "READY", Reason: "ok", ObservedAt: observed}
		ops.docker[id] = executions.LastResultRow{Result: dockerListDoc(t,
			listLine("b1b1b1b1b1b1", "app", img, "running", "Up 1 day", "", "", "", "")), FinishedAt: observed}
		ops.dockerUp[id] = executions.LastResultRow{Result: checkUpdatesDoc(t,
			updateLine(img, "unknown", "", "authentication required")), FinishedAt: observed}
	}
	return newTestHandler(t, ui.Options{
		Hosts:         func(context.Context) ([]inventory.Host, error) { return hosts, nil },
		Operations:    ops,
		RegistryReads: r,
		Log:           slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin:  "https://nebula.example",
	})
}

// TestChartPrivateDigestsAreCacheOnlyPerHost: the chart asks for private
// digests from the cache only (no executor read on render), names each
// host for the per-host caps, bounds the calls with a deadline, and shows
// the digest the executor read.
func TestChartPrivateDigestsAreCacheOnlyPerHost(t *testing.T) {
	r := &chartRegistryReads{fakeRegistryReads: newFakeRegistryReads()}
	page := getBody(t, privateChartHandler(t, 3, r).Handler(), "/inventory/chart")
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Equal(r.hosts, []string{"h00", "h01", "h02"}) {
		t.Fatalf("hosts = %v", r.hosts)
	}
	for i := range r.hosts {
		if !r.cacheOnly[i] || !r.deadline[i] {
			t.Fatalf("call %d: cache-only %v, deadline %v", i, r.cacheOnly[i], r.deadline[i])
		}
	}
	for _, want := range []string{"executor-read digest", "sha256:dddddddddddd"} {
		if !strings.Contains(page, want) {
			t.Errorf("chart misses %q", want)
		}
	}
}

// TestChartRegistryResolveHasOneDeadline: even an implementation that
// blocks on every call cannot hold the page longer than one overall
// deadline, and the hosts after it are not asked at all.
func TestChartRegistryResolveHasOneDeadline(t *testing.T) {
	r := &chartRegistryReads{fakeRegistryReads: newFakeRegistryReads(), block: true}
	h := privateChartHandler(t, 20, r).Handler()
	start := time.Now()
	getBody(t, h, "/inventory/chart")
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("chart took %s with a blocking registry caller", d)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hosts) != 1 {
		t.Fatalf("registry caller asked for %d hosts after the deadline passed, want 1", len(r.hosts))
	}
}
