// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
)

const id1 = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"

func newRunner(t *testing.T, nmap string) *runner {
	t.Helper()
	s := discoveryjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{s.JobsDir(), s.ResultsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return &runner{spool: s, nmap: nmap, timeout: 20 * time.Second, now: time.Now, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func fakeNmap(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nmap")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWritesResults(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	r := newRunner(t, fakeNmap(t, `printf '%s\n' "$@" > `+argsFile+`
cat <<'X'
<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="web.lan" type="PTR"/></hostnames></host><runstats><finished exit="success"/></runstats></nmaprun>
X
`))
	j := discoveryjob.Job{Format: discoveryjob.JobFormat, ID: id1, Mode: discoveryjob.ModePing, Targets: []string{"10.0.0.0/24"}, CreatedAt: 1}
	if err := r.spool.WriteJob(j); err != nil {
		t.Fatal(err)
	}
	bad := "11111111-2222-4333-8444-555555555555"
	_ = os.WriteFile(filepath.Join(r.spool.JobsDir(), bad+".json"), []byte(`{"format":"x"}`), 0o640)
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := r.spool.ReadResult(id1)
	if err != nil || !res.OK || len(res.Hosts) != 1 || res.Hosts[0].Hostname != "web.lan" {
		t.Fatalf("%+v %v", res, err)
	}
	args, _ := os.ReadFile(argsFile)
	if got := strings.Fields(string(args)); got[len(got)-1] != "10.0.0.0/24" || got[0] != "--privileged" {
		t.Fatalf("args %q", got)
	}
	res, err = r.spool.ReadResult(bad)
	if err != nil || res.OK || !strings.Contains(res.Error, "invalid job") {
		t.Fatalf("%+v %v", res, err)
	}
	// Nothing left to do: a second run changes nothing.
	if err := r.runAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunFailures(t *testing.T) {
	j := discoveryjob.Job{Format: discoveryjob.JobFormat, ID: id1, Mode: discoveryjob.ModePing, Targets: []string{"10.0.0.1"}, CreatedAt: 1}
	for name, c := range map[string]struct {
		nmap, want string
	}{
		"missing": {"/nonexistent/nmap", "nmap is not installed"},
		"exit":    {"echo 'QUITTING! bad' >&2; exit 1", "nmap failed: QUITTING! bad"},
		"garbage": {"echo '<nope'", "not valid XML"},
		"slow":    {"sleep 30", "longer than"},
	} {
		t.Run(name, func(t *testing.T) {
			nmap := c.nmap
			if !strings.HasPrefix(nmap, "/") {
				nmap = fakeNmap(t, c.nmap+"\n")
			}
			r := newRunner(t, nmap)
			r.timeout = 2 * time.Second
			res := r.run(context.Background(), j)
			if res.OK || !strings.Contains(res.Error, c.want) {
				t.Fatalf("%+v", res)
			}
		})
	}
}

// With nmap installed, a real ping scan of the loopback address finds it.
func TestRealNmap(t *testing.T) {
	nmap, err := exec.LookPath("nmap")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("needs nmap and root (raw sockets)")
	}
	r := newRunner(t, nmap)
	j := discoveryjob.Job{Format: discoveryjob.JobFormat, ID: id1, Mode: discoveryjob.ModePorts, Ports: "1", Targets: []string{"127.0.0.1"}, CreatedAt: 1}
	res := r.run(context.Background(), j)
	if !res.OK || len(res.Hosts) != 1 || res.Hosts[0].Address != "127.0.0.1" || len(res.Hosts[0].Ports) != 1 {
		t.Fatalf("%+v", res)
	}
}

// In a container, discovery keeps running and answers jobs as they come.
func TestWatchAnswersLaterJobs(t *testing.T) {
	r := newRunner(t, fakeNmap(t, `echo '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'`+"\n"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.watch(ctx, 20*time.Millisecond); close(done) }()
	time.Sleep(50 * time.Millisecond)
	j := discoveryjob.Job{Format: discoveryjob.JobFormat, ID: id1, Mode: discoveryjob.ModePing, Targets: []string{"10.0.0.1"}, CreatedAt: 1}
	if err := r.spool.WriteJob(j); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if res, err := r.spool.ReadResult(id1); err == nil {
			if !res.OK {
				t.Fatalf("%+v", res)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no result")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
