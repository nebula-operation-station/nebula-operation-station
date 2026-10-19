// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-discovery runs the Nmap scans the server queued in the
// discovery spool and writes their results back (spec 12, M9-2). It is a
// one-shot systemd service with only CAP_NET_RAW; it holds no credentials,
// opens no database and listens on nothing. Every job is validated again
// here and turned into fixed Nmap arguments; nothing from the job reaches
// Nmap as a free-form option.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
)

// Defaults.
const (
	defaultSpool   = "/var/lib/nebula/discovery"
	defaultNmap    = "/usr/bin/nmap"
	defaultTimeout = time.Hour
	keepResults    = 7 * 24 * time.Hour
	maxRounds      = 100
	maxStderr      = 4 << 10
)

type runner struct {
	spool   discoveryjob.Spool
	nmap    string
	timeout time.Duration
	now     func() time.Time
	log     *slog.Logger
}

func main() {
	spool := flag.String("spool", defaultSpool, "discovery spool directory (jobs/ and results/)")
	nmap := flag.String("nmap", defaultNmap, "path of the nmap binary")
	timeout := flag.Duration("timeout", defaultTimeout, "time limit per scan")
	watch := flag.Duration("watch", 0, "keep running and look for queued jobs at this interval (containers; systemd starts it per job instead)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	r := &runner{spool: discoveryjob.Spool{Dir: *spool}, nmap: *nmap, timeout: *timeout, now: time.Now, log: log}
	if *watch <= 0 {
		if err := r.runAll(context.Background()); err != nil {
			log.Error("discovery", "error", err)
			os.Exit(1)
		}
		return
	}
	if *watch < time.Second {
		log.Error("discovery", "error", "-watch must be at least 1s")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r.watch(ctx, *watch)
}

// watch answers queued jobs until ctx ends; an error is logged and the
// next round tries again.
func (r *runner) watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := r.runAll(ctx); err != nil {
			r.log.Error("discovery", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runAll answers every pending job, then looks again (jobs queued while
// scanning), and prunes old results.
func (r *runner) runAll(ctx context.Context) error {
	defer r.spool.PruneResults(keepResults, r.now())
	for round := 0; round < maxRounds; round++ {
		jobs, bad, err := r.spool.PendingJobs()
		if err != nil {
			return err
		}
		if len(jobs) == 0 && len(bad) == 0 {
			return nil
		}
		for id, e := range bad {
			r.log.Warn("invalid job", "job", id, "error", e)
			now := r.now().Unix()
			if err := r.spool.WriteResult(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: id, StartedAt: now, FinishedAt: now,
				Error: "invalid job: " + e.Error()}); err != nil {
				return err
			}
		}
		for _, j := range jobs {
			res := r.run(ctx, j)
			if err := r.spool.WriteResult(res); err != nil {
				return err
			}
			r.log.Info("scan finished", "job", j.ID, "ok", res.OK, "hosts", len(res.Hosts))
		}
	}
	return errors.New("jobs keep arriving; stopped after many rounds")
}

// boundedBuffer keeps the first max bytes written to it.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

// run scans one job and returns its result.
func (r *runner) run(ctx context.Context, j discoveryjob.Job) discoveryjob.Result {
	res := discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: j.ID, StartedAt: r.now().Unix()}
	fail := func(msg string) discoveryjob.Result {
		res.FinishedAt, res.Error, res.Hosts = r.now().Unix(), msg, nil
		return res
	}
	args, err := j.Args()
	if err != nil {
		return fail("invalid job: " + err.Error())
	}
	if st, err := os.Stat(r.nmap); err != nil || !st.Mode().IsRegular() {
		return fail("nmap is not installed (install the nmap package on the Nebula machine)")
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.nmap, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	stderr := &boundedBuffer{max: maxStderr}
	cmd.Stderr = stderr
	// Kill the whole process group on timeout, so no child keeps the
	// output pipe open.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fail("could not start nmap")
	}
	if err := cmd.Start(); err != nil {
		return fail("could not start nmap: " + err.Error())
	}
	hosts, perr := discoveryjob.ParseNmapXML(out)
	_, _ = io.Copy(io.Discard, out) // let nmap finish writing
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return fail(fmt.Sprintf("the scan took longer than %s and was stopped", r.timeout))
	case werr != nil:
		msg := strings.TrimSpace(stderr.buf.String())
		if msg == "" {
			msg = werr.Error()
		}
		return fail("nmap failed: " + msg)
	case perr != nil:
		return fail(perr.Error())
	}
	res.FinishedAt, res.OK, res.Hosts = r.now().Unix(), true, hosts
	return res
}
