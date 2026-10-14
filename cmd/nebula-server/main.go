// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-server serves the web UI, inventory and planning
// (Milestone 1). It loads its configuration from a JSON file (flags
// override the file), opens the server database, connects to the
// executor over the SO_PEERCRED Unix socket and serves the UI on the
// configured address until it receives a termination signal.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// DefaultConfigPath is the default location of the server configuration
// file.
const DefaultConfigPath = "/etc/nebula/server.json"

// shutdownTimeout bounds the graceful HTTP shutdown after a signal.
const shutdownTimeout = 10 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "nebula-server:", err)
		os.Exit(1)
	}
}

// run parses the flags and configuration, opens the server database and
// the executor connection, and serves the web UI until ctx is cancelled.
// It returns the configuration error before opening anything else, and
// nil after a clean shutdown.
func run(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("nebula-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath  string
		showVersion bool
	)
	fs.StringVar(&configPath, "config", DefaultConfigPath, "path to the server configuration file")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	serverconfig.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Fprintln(stderr, version.String())
		return nil
	}

	cfg, err := serverconfig.LoadWithFlags(configPath, fs)
	if err != nil {
		return err
	}
	// Every record carries the non-secret config attributes; the token
	// is never part of them.
	log := serverconfig.NewLogger(stderr, cfg)

	db, err := serverdb.Open(filepath.Join(cfg.DataDir, "server.db"))
	if err != nil {
		return fmt.Errorf("open server database: %w", err)
	}
	defer db.Close()

	// An unreachable executor is not fatal: the dashboard shows
	// "Executor unavailable" until it comes back. A locked executor is
	// the normal state and is reported on the dashboard as such.
	var client *executorclient.Client
	client, err = executorclient.New(ctx, executorclient.Options{
		SocketPath:   cfg.ExecutorSocket,
		ExecutorUser: cfg.ExecutorUser,
	})
	if err != nil {
		log.Warn("executor unreachable at startup; the dashboard will show 'Executor unavailable'", "error", err)
	} else {
		defer client.Close()
	}

	// A nil *executorclient.Client must not be wrapped in the
	// StatusProvider interface: a typed nil would not compare equal to
	// nil, and the dashboard would then call it.
	var status ui.StatusProvider
	if client != nil {
		status = client
	}

	store := inventory.New(db)
	hostNames := func(ctx context.Context) []string {
		hosts, err := store.List(ctx)
		if err != nil {
			log.Error("list hosts", "error", err)
			return nil
		}
		names := make([]string, 0, len(hosts))
		for _, h := range hosts {
			name := h.DisplayName
			if name == "" {
				name = h.ID
			}
			names = append(names, name)
		}
		return names
	}

	h, err := ui.New(ui.Options{
		PublicOrigin: cfg.PublicOrigin,
		Status:       status,
		HostNames:    hostNames,
		Log:          log,
	})
	if err != nil {
		return err
	}
	srv, err := h.Server()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	// The logger already carries cfg.LogAttrs() (never the token); add
	// the address actually bound.
	log.Info("started", "listen", ln.Addr().String(), "version", version.String())

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shCtx); err != nil {
			log.Error("graceful shutdown", "error", err)
		}
		return nil
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	}
}
