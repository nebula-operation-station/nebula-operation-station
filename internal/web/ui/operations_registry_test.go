// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// checkUpdatesExec is a finished docker.check_updates execution: each host
// reported the given private images as unknown.
func checkUpdatesExec(hosts map[string][]string) executions.Execution {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	e := executions.Execution{ID: opID, ActionID: "docker.check_updates", State: "finished", CreatedAt: time.Unix(1791960000, 0)}
	ids := make([]string, 0, len(hosts))
	for id := range hosts {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		var lines strings.Builder
		for _, img := range hosts[id] {
			lines.WriteString(img + "\tunknown\t\tauthentication required\n")
		}
		res := fmt.Sprintf(`{"format":"docker-updates-v1","phase":"done","images":%d,"lines":"%s"}`, len(hosts[id]), enc(lines.String()))
		e.Hosts = append(e.Hosts, executions.Host{HostID: id, State: "finished", Class: "success", Result: []byte(res)})
	}
	return e
}

// TestExecutionDetailPrivateDigestsAreCacheOnlyPerHost: the execution
// detail page asks for private digests from the cache only, names the host
// whose result each call resolves and bounds the calls with a deadline,
// like the chart.
func TestExecutionDetailPrivateDigestsAreCacheOnlyPerHost(t *testing.T) {
	const img = "registry.corp.example/team/app:1.0"
	r := &chartRegistryReads{fakeRegistryReads: newFakeRegistryReads()}
	f := &fakeOps{exec: checkUpdatesExec(map[string][]string{"a": {img}, "b": {img}})}
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Operations: f, RegistryReads: r}).Handler()
	page := getBody(t, h, "/operations/"+opID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Equal(r.hosts, []string{"a", "b"}) {
		t.Fatalf("hosts = %v, want each result charged to its own host", r.hosts)
	}
	for i := range r.hosts {
		if !r.cacheOnly[i] || !r.deadline[i] {
			t.Fatalf("call %d: cache-only %v, deadline %v", i, r.cacheOnly[i], r.deadline[i])
		}
	}
	if !strings.Contains(page, "executor-read digest") {
		t.Error("page misses the executor-read digest")
	}
}

// TestExecutionDetailRegistryResolveHasOneDeadline: a caller that blocks
// on every call cannot hold the page past one overall deadline.
func TestExecutionDetailRegistryResolveHasOneDeadline(t *testing.T) {
	r := &chartRegistryReads{fakeRegistryReads: newFakeRegistryReads(), block: true}
	hosts := map[string][]string{}
	for i := range 20 {
		hosts[fmt.Sprintf("h%02d", i)] = []string{"registry.corp.example/team/app:1.0"}
	}
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Operations: &fakeOps{exec: checkUpdatesExec(hosts)}, RegistryReads: r}).Handler()
	start := time.Now()
	getBody(t, h, "/operations/"+opID)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("execution page took %s with a blocking registry caller", d)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hosts) != 1 {
		t.Fatalf("registry caller asked for %d hosts after the deadline passed, want 1", len(r.hosts))
	}
}

// countingExecutor is the executor's registry API for a real DigestReader:
// it counts calls, and listing blocks until release is closed so a
// synchronous call during a render would be seen.
type countingExecutor struct {
	release chan struct{}

	mu     sync.Mutex
	listed int
	reads  []string
}

func (c *countingExecutor) ListPrivateRegistries(ctx context.Context, _ *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	c.mu.Lock()
	c.listed++
	c.mu.Unlock()
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.ListPrivateRegistriesResponse{Registries: []*pb.PrivateRegistryInfo{{
		RegistryId: "corp", RegistryOrigin: "https://registry.corp.example", Repositories: []string{"team/app"},
		ConfigVersion: 1, CredentialVersion: 1, ConfigDigest: strings.Repeat("a", 64), CredentialId: strings.Repeat("b", 32),
	}}}, nil
}

func (c *countingExecutor) ReadPrivateRegistry(_ context.Context, in *pb.ReadPrivateRegistryRequest, _ ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, in.GetTag())
	return &pb.ReadPrivateRegistryResponse{RegistryId: in.GetRegistryId(), Repository: in.GetRepository(),
		Digest: "sha256:" + strings.Repeat("3", 64)}, nil
}

// readerRegistryReads is ui.RegistryReads over a real DigestReader, as the
// server wires it.
type readerRegistryReads struct {
	*fakeRegistryReads
	reader *registrymeta.DigestReader
}

func (r *readerRegistryReads) ResolveImageUpdates(ctx context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates {
	out, err := dockerhost.ResolvePrivateDigestsWith(ctx, u, r.reader)
	if err != nil {
		return u
	}
	return out
}

// TestExecutionDetailIssuesNoExecutorReadsAndChargesEachHost: rendering an
// execution with the server's DigestReader makes no executor call while
// the page renders; the background reads it queued are charged to the
// host whose result named the image, so each host gets its own per-host
// cap of distinct tags (a shared bucket would allow the cap once).
func TestExecutionDetailIssuesNoExecutorReadsAndChargesEachHost(t *testing.T) {
	var tags []string
	for i := range registrymeta.MaxHostTagsPerRepository + 1 {
		tags = append(tags, fmt.Sprintf("registry.corp.example/team/app:%d", i))
	}
	hostB := make([]string, 0, len(tags))
	for i := range tags {
		hostB = append(hostB, fmt.Sprintf("registry.corp.example/team/app:b%d", i))
	}
	exec := &countingExecutor{release: make(chan struct{})}
	reader := registrymeta.NewDigestReader(exec, nil)
	r := &readerRegistryReads{fakeRegistryReads: newFakeRegistryReads(), reader: reader}
	f := &fakeOps{exec: checkUpdatesExec(map[string][]string{"a": tags, "b": hostB})}
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Operations: f, RegistryReads: r}).Handler()

	page := getBody(t, h, "/operations/"+opID)
	exec.mu.Lock()
	reads := len(exec.reads)
	exec.mu.Unlock()
	if reads != 0 {
		t.Fatalf("render issued %d executor reads", reads)
	}
	if strings.Contains(page, strings.Repeat("3", 64)) {
		t.Fatal("render shows a digest it cannot have read")
	}
	close(exec.release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := reader.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	var a, b int
	for _, tag := range exec.reads {
		if strings.HasPrefix(tag, "b") {
			b++
		} else {
			a++
		}
	}
	if a != registrymeta.MaxHostTagsPerRepository || b != registrymeta.MaxHostTagsPerRepository {
		t.Fatalf("background reads: host a %d, host b %d, want %d each", a, b, registrymeta.MaxHostTagsPerRepository)
	}
}
