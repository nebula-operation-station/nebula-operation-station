// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Command nebula-netdev-collector is the network device collector of ADR
// 0010 D4 (ND-14). It runs as its own Unix user (the netdev-collector
// peercred role), schedules typed reads over the executor socket and
// writes the sanitized results to its spool. It never talks to a device
// itself, opens no network listener, touches no database and holds no
// credentials: the executor owns the device sessions, parses and redacts
// every result. Logs carry device ids, read names and failure codes,
// never a payload or an executor error text.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
)

// Defaults follow the deployment conventions of the other services
// (socket under /run/nebula, state under /var/lib/nebula).
const (
	defaultSocket       = "/run/nebula/executor.sock"
	defaultExecutorUser = "nebula-executor"
	defaultSpool        = "/var/lib/nebula/netdev"
	defaultInterval     = netdevcollect.DefaultInterval
	// minInterval and maxInterval bound -interval: how often the poll loop
	// looks for due reads. The per-read cadence and its 15 min floor are
	// fixed in internal/netdevcollect; a tick above the floor would only
	// delay reads.
	minInterval = time.Second
	maxInterval = netdevcollect.MinReadInterval
)

// errRunAsRoot means the collector was started as root; it must run as
// its own unprivileged user.
var errRunAsRoot = errors.New("nebula-netdev-collector: refusing to run as root")

// options are the parsed command-line flags.
type options struct {
	socket       string
	executorUser string
	spoolDir     string
	interval     time.Duration
}

// collectorClient is the executor client the collector uses.
type collectorClient interface {
	netdevcollect.Client
	Close() error
}

// deps are the process-level dependencies, injected for tests.
type deps struct {
	geteuid   func() int
	newClient func(ctx context.Context, o executorclient.Options) (collectorClient, error)
	newSpool  func(dir string) netdevcollect.SpoolWriter
	now       func() time.Time
	rand      func() float64
}

// productionDeps are the real dependencies.
func productionDeps() deps {
	return deps{
		geteuid: os.Geteuid,
		newClient: func(ctx context.Context, o executorclient.Options) (collectorClient, error) {
			c, err := executorclient.New(ctx, o)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		newSpool: func(dir string) netdevcollect.SpoolWriter {
			return &netdevcollect.Spool{Dir: dir, Now: time.Now}
		},
		now:  time.Now,
		rand: rand.Float64,
	}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	o, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Error("nebula-netdev-collector: bad flags", "error", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o, log, productionDeps()); err != nil {
		log.Error("nebula-netdev-collector: fatal", "error", err)
		stop()
		os.Exit(1)
	}
}

// parseFlags parses and validates the command line.
func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("nebula-netdev-collector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.socket, "socket", defaultSocket, "executor Unix socket path")
	fs.StringVar(&o.executorUser, "executor-user", defaultExecutorUser, "OS user the executor runs as (peercred check)")
	fs.StringVar(&o.spoolDir, "spool", defaultSpool, "spool directory for read results")
	fs.DurationVar(&o.interval, "interval", defaultInterval, "how often to look for due reads (1s to 15m)")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	switch {
	case fs.NArg() != 0:
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case !filepath.IsAbs(o.socket):
		return options{}, errors.New("-socket must be an absolute path")
	case !filepath.IsAbs(o.spoolDir):
		return options{}, errors.New("-spool must be an absolute path")
	case o.executorUser == "":
		return options{}, errors.New("-executor-user must not be empty")
	case o.interval < minInterval || o.interval > maxInterval:
		return options{}, fmt.Errorf("-interval must be between %v and %v", minInterval, maxInterval)
	}
	return o, nil
}

// run connects to the executor and polls until ctx is done; then it waits
// for the reads in flight to be spooled and returns nil.
func run(ctx context.Context, o options, log *slog.Logger, d deps) error {
	if d.geteuid() == 0 {
		return errRunAsRoot
	}
	client, err := d.newClient(ctx, executorclient.Options{SocketPath: o.socket, ExecutorUser: o.executorUser})
	if err != nil {
		return fmt.Errorf("connect to executor: %w", err)
	}
	defer client.Close()

	p := &netdevcollect.Poller{
		Client:   client,
		Spool:    d.newSpool(o.spoolDir),
		Now:      d.now,
		Rand:     d.rand,
		Log:      log,
		Interval: o.interval,
	}
	log.Info("nebula-netdev-collector: starting", "socket", o.socket, "spool", o.spoolDir, "interval", o.interval.String())
	if err := p.Run(ctx); err != nil {
		return err
	}
	log.Info("nebula-netdev-collector: stopped")
	return nil
}
