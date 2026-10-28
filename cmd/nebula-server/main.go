// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-server serves the web UI, inventory and planning. It
// loads its configuration from a JSON file (flags override the file),
// opens the server database, connects to the executor over the
// SO_PEERCRED Unix socket (retrying in the background until it is up) and
// serves the UI behind the WebAuthn login (internal/web/auth) on the
// configured address until it receives a termination signal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// DefaultConfigPath is the default location of the server configuration
// file.
const DefaultConfigPath = "/etc/nebula/server.json"

// shutdownTimeout bounds the graceful HTTP shutdown after a signal.
const shutdownTimeout = 10 * time.Second

// pruneInterval is how often expired web sessions are deleted.
const pruneInterval = time.Hour

// hostKeyPollInterval is how often the server asks the executor for
// blocked hosts to notify.
const hostKeyPollInterval = 30 * time.Second

// expireInterval is how often pending operations whose approval window has
// ended are marked expired.
const expireInterval = time.Minute

func pruneSessions(ctx context.Context, s *auth.Store, log *slog.Logger) {
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.Prune(ctx); err != nil {
				log.Error("prune sessions", "error", err)
			} else if n > 0 {
				log.Info("pruned expired sessions", "count", n)
			}
		}
	}
}

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
		notifyTest  bool
		exportDir   string
		apiToken    string
	)
	fs.StringVar(&configPath, "config", DefaultConfigPath, "path to the server configuration file")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.BoolVar(&notifyTest, "notify-test", false, "send a test notification to every configured provider and exit")
	fs.StringVar(&exportDir, "export-actions", "", "write the built-in action scripts into this (new) directory, print the `nebula artifact trust` commands and exit")
	fs.StringVar(&apiToken, "api-token", "", "create a read-only API token `NAME:SCOPE[,SCOPE]`, print it and its server.json entry, and exit")
	serverconfig.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Fprintln(stderr, version.String())
		return nil
	}
	if exportDir != "" {
		return exportActions(exportDir, stderr)
	}
	if apiToken != "" {
		return newAPIToken(apiToken, stderr)
	}

	cfg, err := serverconfig.LoadWithFlags(configPath, fs)
	if err != nil {
		return err
	}
	// Every record carries the non-secret config attributes; the token
	// is never part of them.
	log := serverconfig.NewLogger(stderr, cfg)

	notifier := notify.New(cfg.Notifications, nil, log)
	if notifyTest {
		if !notifier.Enabled() {
			return errors.New("no notification provider configured")
		}
		tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		e := notify.Event{Kind: notify.KindTest, Reason: "If you read this, notifications from this Nebula server work.", Time: time.Now()}
		if n := notifier.Notify(tctx, e); n == 0 {
			return errors.New("no provider accepted the test notification (see the log)")
		}
		fmt.Fprintln(stderr, "test notification sent")
		return nil
	}

	db, err := serverdb.Open(filepath.Join(cfg.DataDir, "server.db"))
	if err != nil {
		return fmt.Errorf("open server database: %w", err)
	}
	defer db.Close()
	// Audit lines are also kept in server.db for the History page (M10-1).
	audit := auditlog.New(db, cfg.AuditHashChain)
	log = slog.New(auditlog.NewHandler(log.Handler(), audit))

	// An unreachable executor is not fatal: the server connects in the
	// background (and pages show "Executor unavailable" until then). A
	// locked executor is the normal state after a reboot.
	exec := &lazyExecutor{}
	connCtx, stopConnect := context.WithCancel(ctx)
	defer stopConnect()
	go exec.connect(connCtx, executorclient.Options{SocketPath: cfg.ExecutorSocket, ExecutorUser: cfg.ExecutorUser}, log)
	defer exec.close()

	// Web sessions (M2): every page except login, setup and static assets
	// needs one; logins are verified by the executor.
	sessions := auth.NewStore(db, nil)
	go pruneSessions(connCtx, sessions, log)
	login, err := auth.New(auth.Options{Executor: exec, Sessions: sessions, Log: log})
	if err != nil {
		return err
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
	hostKeys := func(ctx context.Context) ([]*pb.HostKeyPin, error) {
		resp, err := exec.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
		if err != nil {
			return nil, err
		}
		return resp.GetHosts(), nil
	}
	// securityKeys and totpStatus back the settings page ("Sign-in and
	// security keys" and "Recovery"); both are read-only RPCs.
	securityKeys := func(ctx context.Context) ([]*pb.WebAuthnCredential, error) {
		resp, err := exec.ListWebAuthnCredentials(ctx, &pb.ListWebAuthnCredentialsRequest{})
		if err != nil {
			return nil, err
		}
		return resp.GetCredentials(), nil
	}
	totpStatus := func(ctx context.Context) (*pb.GetTOTPStatusResponse, error) {
		return exec.GetTOTPStatus(ctx, &pb.GetTOTPStatusRequest{})
	}

	// Host key mismatches notify (spec 13: always sent, cannot be muted).
	watcher := &notify.HostKeyWatcher{Notifier: notifier, List: hostKeys, DB: db, Interval: hostKeyPollInterval, Log: log}
	go watcher.Run(connCtx)
	// A locked executor after a restart pauses all runs (spec 13).
	lockWatcher := &notify.ExecutorWatcher{Notifier: notifier, Interval: hostKeyPollInterval, Log: log,
		Unlocked: func(ctx context.Context) (bool, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			st, err := exec.GetStatus(ctx, &pb.GetStatusRequest{})
			if err != nil {
				return false, err
			}
			return st.GetUnlocked(), nil
		}}
	go lockWatcher.Run(connCtx)

	// Operations (M4): planned here, decided and run by the executor.
	ops := executions.New(connCtx, exec, db, store, log)
	ops.SetNotifier(notifier)
	// Runbooks (M7-2) are planned like built-in actions.
	rb := runbooks.New(db)
	ops.SetRunbooks(rb)
	// Modules (M7-5): the executor verifies their signatures.
	mods := modules.New(db, exec)
	ops.SetModules(mods)
	if err := ops.Resume(connCtx); err != nil {
		log.Error("resume executions", "error", err)
	}
	// Scheduled read-only checks run under executor-held schedule grants.
	go ops.RunSchedules(connCtx)

	// Expire pending operations whose approval window ended (issue #71): the
	// executor drops the permit when the window closes but the server only
	// learns it here. Run once at startup, then once a minute.
	if _, err := ops.ExpirePending(connCtx, time.Now()); err != nil {
		log.Error("expire pending operations", "error", err)
	}
	go func() {
		t := time.NewTicker(expireInterval)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-t.C:
			}
			if _, err := ops.ExpirePending(connCtx, time.Now()); err != nil {
				log.Error("expire pending operations", "error", err)
			}
		}
	}()

	// Network assets, IPAM and discovery (M9). nebula-discovery runs the
	// scans; the server only queues jobs and reads results.
	hostAddrs := ipam.FromInventory(store.List)
	ipamStore := ipam.New(db, hostAddrs)
	disc := discovery.New(db, discoveryjob.Spool{Dir: cfg.DiscoveryDir}, ipamStore, hostAddrs, log)
	go disc.Run(connCtx)

	h, err := ui.New(ui.Options{
		PublicOrigin: cfg.PublicOrigin,
		Status:       exec,
		HostNames:    hostNames,
		Hosts:        store.List,
		HostKeys:     hostKeys,
		Inventory:    store,
		Operations:   ops,
		Pins:         store,
		Schedules:    ops,
		Runbooks:     rb,
		Trust:        exec,
		Modules:      mods,
		LastResult:   ops.LastResult,
		Network:      ipamStore,
		Discovery:    disc,
		Events:       exec,
		Audit:        audit,
		Repin:        exec,
		Enroll:       exec,
		SecurityKeys: securityKeys,
		TOTPStatus:   totpStatus,
		Log:          log,
	})
	if err != nil {
		return err
	}
	// Security middleware first (headers, origin check, body limit), then
	// the session check, then the pages. The read-only API (spec 13), when
	// enabled, authenticates with tokens instead of sessions.
	root := http.NewServeMux()
	root.Handle("/", login.Wrap(h.Handler()))
	if cfg.API.Enabled {
		a, err := api.New(api.Options{Tokens: cfg.API.Tokens, Hosts: store.List, Operations: ops, Log: log})
		if err != nil {
			return err
		}
		root.Handle(api.Prefix, a)
		log.Info("read-only API enabled", "tokens", len(cfg.API.Tokens))
	}
	srv, err := middleware.NewServer(middleware.Options{PublicOrigin: cfg.PublicOrigin}, root)
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
