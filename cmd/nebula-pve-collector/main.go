// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command nebula-pve-collector is the PVE collector of ADR 0006 (P1-10).
// It runs as its own Unix user (the pve-collector peercred role),
// schedules typed read requests over the executor socket and writes
// sanitized observations to the spool. It never talks to a PVE endpoint
// itself, opens no network listener, touches no database and holds no
// credentials: the executor owns the PVE connections and every response
// is sanitized before it reaches the spool.
//
// With -live (the default) it also serves the server's live want-list
// (<spool>/requests/live.json) with on-demand provider metrics reads under
// approved read-grant leases and publishes the samples to <spool>/live/
// (ADR 0006 P1-37). The server never reads Proxmox itself.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

// Defaults follow the deployment conventions of the other services
// (socket under /run/nebula, state under /var/lib/nebula).
const (
	defaultSocket       = "/run/nebula/executor.sock"
	defaultExecutorUser = "nebula-executor"
	defaultSpool        = "/var/lib/nebula/pve"
	defaultInterval     = time.Minute
	defaultLive         = true
)

// errLoopStopped means a service loop returned while the service was
// still running.
var errLoopStopped = errors.New("loop stopped unexpectedly")

// options are the parsed command-line flags.
type options struct {
	socket       string
	executorUser string
	spoolDir     string
	interval     time.Duration
	once         bool
	live         bool
}

func main() {
	var o options
	flag.StringVar(&o.socket, "socket", defaultSocket, "executor Unix socket path")
	flag.StringVar(&o.executorUser, "executor-user", defaultExecutorUser, "OS user the executor runs as (peercred check)")
	flag.StringVar(&o.spoolDir, "spool", defaultSpool, "spool directory for observations (also holds requests/ and live/)")
	flag.DurationVar(&o.interval, "interval", defaultInterval, "base collection interval per remote")
	flag.BoolVar(&o.once, "once", false, "run a single collection pass and exit")
	flag.BoolVar(&o.live, "live", defaultLive, "serve the server's live want-list (requests/ -> live/)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(o, log); err != nil {
		log.Error("nebula-pve-collector: fatal", "error", err)
		os.Exit(1)
	}
}

func run(o options, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, err := executorclient.NewPVECollector(ctx, executorclient.Options{
		SocketPath:   o.socket,
		ExecutorUser: o.executorUser,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	spool, err := pvecollect.NewSpool(o.spoolDir)
	if err != nil {
		return err
	}

	defer spool.Close()

	c, err := pvecollect.New(client, spool, pvecollect.Config{Interval: o.interval})
	if err != nil {
		return err
	}

	if o.once {
		rep, err := c.PollOnce(ctx)
		if err != nil {
			log.Error("collection pass failed", "remotes", rep.Remotes, "polled", rep.Polled, "skipped", rep.Skipped, "failed", rep.Failed, "errors", rep.Errors, "error", err)
			return err
		}
		log.Info("collection pass done", "remotes", rep.Remotes, "polled", rep.Polled, "skipped", rep.Skipped, "failed", rep.Failed, "errors", rep.Errors)
		return nil
	}

	loops := []namedLoop{{name: "collector", run: c.Run}}
	h, err := openLive(o.spoolDir, o.live)
	if err != nil {
		return err
	}
	if h != nil {
		// Closed after runLoops returned: the watcher has stopped and
		// removed its samples by then.
		defer h.Close()
		w, err := pvecollect.NewLiveWatcher(client, h, pvecollect.LiveWatcherConfig{Log: log})
		if err != nil {
			return err
		}
		loops = append(loops, namedLoop{name: "live", run: w.Run})
	}

	log.Info("nebula-pve-collector: starting", "socket", o.socket, "spool", o.spoolDir, "interval", o.interval.String(), "live", h != nil)
	if err := runLoops(ctx, loops); err != nil {
		return err
	}
	log.Info("nebula-pve-collector: stopped")
	return nil
}

// openLive opens the collector side of the live handoff under root,
// creating requests/ and live/ with their shared modes. It returns nil,
// nil when live reads are disabled and then creates nothing.
func openLive(root string, enabled bool) (*pvecollect.LiveHandoff, error) {
	if !enabled {
		return nil, nil
	}
	h, err := pvecollect.NewLiveHandoff(root)
	if err != nil {
		return nil, fmt.Errorf("open live handoff %s: %w", root, err)
	}
	return h, nil
}

// loop is one long-running service loop. It returns nil once ctx is done.
type loop func(ctx context.Context) error

// namedLoop is a loop with a name for errors.
type namedLoop struct {
	name string
	run  loop
}

// runLoops runs all loops concurrently until ctx is done and waits for all
// of them. A loop that fails, or returns while ctx is still live, stops the
// others; its error is returned so the service exits non-zero.
func runLoops(ctx context.Context, loops []namedLoop) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(loops))
	for _, l := range loops {
		go func() {
			err := l.run(ctx)
			if err == nil && ctx.Err() == nil {
				err = errLoopStopped
			}
			if err != nil {
				err = fmt.Errorf("%s: %w", l.name, err)
			}
			errs <- err
		}()
	}
	var first error
	for range loops {
		if err := <-errs; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}
