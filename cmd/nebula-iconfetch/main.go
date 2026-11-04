// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-iconfetch fetches the icon URLs the server queued in the
// icon spool and writes sanitized icons back (ADR 0009 D6, TM16). It is a
// one-shot service like nebula-discovery: it holds no credentials, opens
// no database or vault and listens on nothing. Every job is validated
// again here; the URL policy and dial-time address checks are
// internal/iconfetch's, the image sanitizer is internal/iconstore's. The
// server re-validates and re-sanitizes everything it reads back.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconfetch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

// Defaults and limits.
const (
	defaultSpool = "/var/lib/nebula/iconfetch"
	keepResults  = 24 * time.Hour
	maxRounds    = 100
	// maxJobsPerRound bounds the work of one round, so a flood of jobs
	// cannot keep the helper fetching forever.
	maxJobsPerRound = 64
)

// fetchFunc fetches an icon URL (iconfetch.Client.Fetch in production).
type fetchFunc func(ctx context.Context, rawURL string) ([]byte, error)

type runner struct {
	spool iconjob.Spool
	allow []string
	fetch fetchFunc
	now   func() time.Time
	log   *slog.Logger
}

func main() {
	spool := flag.String("spool", defaultSpool, "icon spool directory (jobs/ and results/)")
	allow := flag.String("allow", strings.Join(iconfetch.DefaultAllowlist(), ","), "comma-separated icon host allowlist")
	watch := flag.Duration("watch", 0, "keep running and look for queued jobs at this interval (containers; systemd starts it per job instead)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	hosts := splitAllow(*allow)
	if len(hosts) == 0 {
		log.Error("iconfetch", "error", "-allow is empty")
		os.Exit(2)
	}
	client := iconfetch.New(iconfetch.Config{Allow: hosts})
	r := &runner{spool: iconjob.Spool{Dir: *spool}, allow: hosts, fetch: client.Fetch, now: time.Now, log: log}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *watch <= 0 {
		if err := r.runAll(ctx); err != nil {
			log.Error("iconfetch", "error", err)
			os.Exit(1)
		}
		return
	}
	if *watch < time.Second {
		log.Error("iconfetch", "error", "-watch must be at least 1s")
		os.Exit(2)
	}
	r.watch(ctx, *watch)
}

// splitAllow parses the -allow flag.
func splitAllow(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// watch answers queued jobs until ctx ends; an error is logged and the
// next round tries again.
func (r *runner) watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := r.runAll(ctx); err != nil {
			r.log.Error("iconfetch", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runAll answers every pending job, then looks again (jobs queued while
// fetching), and prunes old results.
func (r *runner) runAll(ctx context.Context) error {
	defer r.spool.PruneResults(keepResults, r.now())
	for round := 0; round < maxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs, bad, err := r.spool.PendingJobs()
		if err != nil {
			return err
		}
		if len(jobs) == 0 && len(bad) == 0 {
			return nil
		}
		for id, e := range bad {
			r.log.Warn("invalid job", "job", id, "error", e.Error())
			now := r.now().Unix()
			if err := r.spool.WriteResult(iconjob.Result{Format: iconjob.ResultFormat, Job: id, StartedAt: now, FinishedAt: now,
				Error: iconjob.CleanError("invalid job: " + e.Error())}); err != nil {
				return err
			}
		}
		if len(jobs) > maxJobsPerRound {
			jobs = jobs[:maxJobsPerRound]
		}
		for _, j := range jobs {
			res := r.run(ctx, j)
			if err := r.spool.WriteResult(res); err != nil {
				return err
			}
			r.log.Info("icon fetched", "job", j.ID, "key", j.Key, "ok", res.OK, "sha256", res.SHA256, "error", res.Error)
		}
	}
	return errors.New("jobs keep arriving; stopped after many rounds")
}

// run fetches and sanitizes one job and returns its result.
func (r *runner) run(ctx context.Context, j iconjob.Job) iconjob.Result {
	res := iconjob.Result{Format: iconjob.ResultFormat, Job: j.ID, StartedAt: r.now().Unix()}
	fail := func(msg string) iconjob.Result {
		res.FinishedAt, res.Error = r.now().Unix(), iconjob.CleanError(msg)
		return res
	}
	if _, err := iconfetch.ValidateURL(j.URL, r.allow); err != nil {
		return fail(err.Error())
	}
	body, err := r.fetch(ctx, j.URL)
	if err != nil {
		return fail(err.Error())
	}
	ic, err := iconstore.Sanitize(body)
	if err != nil {
		return fail(err.Error())
	}
	res.FinishedAt, res.OK = r.now().Unix(), true
	res.SHA256, res.PNG64, res.PNG128 = ic.SHA256, ic.PNG64, ic.PNG128
	return res
}
