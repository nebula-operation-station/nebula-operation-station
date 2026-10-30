// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command nebula-pve-collector is the PVE collector of ADR 0006 (P1-10).
// It runs as its own Unix user (the pve-collector peercred role),
// schedules typed read requests over the executor socket and writes
// sanitized observations to the spool. It never talks to a PVE endpoint
// itself, opens no network listener, touches no database and holds no
// credentials: the executor owns the PVE connections and every response
// is sanitized before it reaches the spool.
package main

import (
	"context"
	"flag"
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
)

func main() {
	socket := flag.String("socket", defaultSocket, "executor Unix socket path")
	executorUser := flag.String("executor-user", defaultExecutorUser, "OS user the executor runs as (peercred check)")
	spoolDir := flag.String("spool", defaultSpool, "spool directory for observations")
	interval := flag.Duration("interval", defaultInterval, "base collection interval per remote")
	once := flag.Bool("once", false, "run a single collection pass and exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*socket, *executorUser, *spoolDir, *interval, *once, log); err != nil {
		log.Error("nebula-pve-collector: fatal", "error", err)
		os.Exit(1)
	}
}

func run(socket, executorUser, spoolDir string, interval time.Duration, once bool, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, err := executorclient.NewPVECollector(ctx, executorclient.Options{
		SocketPath:   socket,
		ExecutorUser: executorUser,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	spool, err := pvecollect.NewSpool(spoolDir)
	if err != nil {
		return err
	}

	defer spool.Close()

	c, err := pvecollect.New(client, spool, pvecollect.Config{Interval: interval})
	if err != nil {
		return err
	}

	if once {
		rep, err := c.PollOnce(ctx)
		if err != nil {
			log.Error("collection pass failed", "remotes", rep.Remotes, "polled", rep.Polled, "skipped", rep.Skipped, "failed", rep.Failed, "errors", rep.Errors, "error", err)
			return err
		}
		log.Info("collection pass done", "remotes", rep.Remotes, "polled", rep.Polled, "skipped", rep.Skipped, "failed", rep.Failed, "errors", rep.Errors)
		return nil
	}

	log.Info("nebula-pve-collector: starting", "socket", socket, "spool", spoolDir, "interval", interval.String())
	if err := c.Run(ctx); err != nil {
		return err
	}
	log.Info("nebula-pve-collector: stopped")
	return nil
}
