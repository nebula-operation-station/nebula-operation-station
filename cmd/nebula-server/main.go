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
	"database/sql"
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
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/live"
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

// cliApproveInterval is how often the server asks the executor for the
// permit state of pending operations: an approval made on the executor host
// (nebula approve, hardened path) is recorded and dispatched only when the
// server asks (issue #78). The check does not contact the executor while no
// operation is pending.
const cliApproveInterval = 10 * time.Second

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

// pveRemoteStateText renders the executor's PVE remote state for the UI.
func pveRemoteStateText(s pb.PVERemoteState) string {
	switch s {
	case pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE:
		return "active"
	case pb.PVERemoteState_PVE_REMOTE_STATE_BLOCKED:
		return "blocked"
	default:
		return "—"
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
	return runServer(ctx, args, stderr, vulnHooks{})
}

// vulnHooks lets tests observe and speed up the vulnerability wiring of
// runServer; the zero value is production.
type vulnHooks struct {
	// sweepInterval and notifyInterval replace vulnSweepInterval and
	// vulnNotifyInterval when positive.
	sweepInterval, notifyInterval time.Duration
	// sink replaces the notify providers when set.
	sink vulnnotify.Sink
	// started is called with the service before its loops start.
	started func(v *vulnService, notifying bool)
}

// runServer is run with the vulnerability test hooks.
func runServer(ctx context.Context, args []string, stderr io.Writer, vh vulnHooks) error {
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
	defer exec.close()
	// Background loops run under connCtx and in bg (each joins the
	// goroutines it starts itself), and the operation dispatchers under
	// ops. On return run cancels connCtx and waits for bg, then for the
	// dispatchers (bg's schedules may start one), before exec and db
	// close, so none of them logs or uses the database after run.
	connCtx, stopConnect := context.WithCancel(ctx)
	var bg sync.WaitGroup
	var ops *executions.Service
	defer func() {
		stopConnect()
		bg.Wait()
		if ops != nil {
			ops.Wait()
		}
	}()
	bg.Go(func() {
		exec.connect(connCtx, executorclient.Options{SocketPath: cfg.ExecutorSocket, ExecutorUser: cfg.ExecutorUser}, log)
	})

	// Web sessions (M2): every page except login, setup and static assets
	// needs one; logins are verified by the executor.
	sessions := auth.NewStore(db, nil)
	bg.Go(func() { pruneSessions(connCtx, sessions, log) })
	login, err := auth.New(auth.Options{Executor: exec, Sessions: sessions, Log: log})
	if err != nil {
		return err
	}

	store := inventory.New(db)

	// PVE remotes (ADR 0006, P1-13): the pages read only the inventory
	// stored on the server; the registry metadata (approved endpoints,
	// trust pin, state) comes from the executor's ListPVERemotes RPC.
	pveStore := pveinventory.New(db)
	pveRemotes := func(ctx context.Context) ([]ui.PVERemoteMeta, error) {
		resp, err := exec.ListPVERemotes(ctx, &pb.ListPVERemotesRequest{})
		if err != nil {
			return nil, err
		}
		infos := resp.GetRemotes()
		metas := make([]ui.PVERemoteMeta, 0, len(infos))
		for _, info := range infos {
			meta := ui.PVERemoteMeta{
				RemoteID:        info.GetRemoteId(),
				Name:            info.GetName(),
				TrustPin:        info.GetTrustPin(),
				TrustGeneration: info.GetTrustGeneration(),
				State:           pveRemoteStateText(info.GetState()),
			}
			switch info.GetKind() {
			case pb.PVERemoteKind_PVE_REMOTE_KIND_CLUSTER:
				meta.Kind = "cluster"
			case pb.PVERemoteKind_PVE_REMOTE_KIND_STANDALONE:
				meta.Kind = "standalone"
			}
			for _, ep := range info.GetEndpoints() {
				meta.Endpoints = append(meta.Endpoints, ui.PVEEndpoint{Host: ep.GetHost(), Port: int(ep.GetPort())})
			}
			metas = append(metas, meta)
		}
		return metas, nil
	}

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
	bg.Go(func() { watcher.Run(connCtx) })
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
	bg.Go(func() { lockWatcher.Run(connCtx) })

	// Operations (M4): planned here, decided and run by the executor.
	ops = executions.New(connCtx, exec, db, store, log)
	ops.SetNotifier(notifier)
	// Runbooks (M7-2) are planned like built-in actions.
	rb := runbooks.New(db)
	ops.SetRunbooks(rb)
	// Deploy profiles (ADR 0008 PV-04): versioned, secret-free presets.
	deployProfiles := deployprofile.New(db)
	// Modules (M7-5): the executor verifies their signatures.
	mods := modules.New(db, exec)
	ops.SetModules(mods)
	if err := ops.Resume(connCtx); err != nil {
		log.Error("resume executions", "error", err)
	}
	// Scheduled read-only checks run under executor-held schedule grants.
	bg.Go(func() { ops.RunSchedules(connCtx) })
	// Batches (ADR 0007): planned here with the executor's credential
	// versions (GetBatchCredentialVersions), approved once on the batch
	// page; also the staged post-enrollment plan of a deployment. Proposing
	// and approving are refused unless the executor advertises batch
	// execution at that moment (deployBatches).
	batches, batchPages, err := newBatches(connCtx, serverBatchExecutor{client: lazyBatchRPC(exec)}, db, store, ops, log)
	if err != nil {
		return err
	}
	// Approved members are handed to the executor one at a time, after
	// newBatches reconciled what the previous process left dispatched.
	runner := &batchRunner{batches: batches.Batches, exec: serverBatchExecutor{client: lazyBatchRPC(exec)}, hosts: store, actions: ops, log: log}
	bg.Go(func() { runner.run(connCtx, batchRunInterval) })

	// Expire pending operations whose approval window ended (issue #71): the
	// executor drops the permit when the window closes but the server only
	// learns it here. Run once at startup, then once a minute.
	if _, err := ops.ExpirePending(connCtx, time.Now()); err != nil {
		log.Error("expire pending operations", "error", err)
	}
	bg.Go(func() {
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
	})

	// Record approvals made on the executor host (issue #78): the check
	// contacts the executor only while at least one operation is pending.
	bg.Go(func() {
		t := time.NewTicker(cliApproveInterval)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-t.C:
			}
			if n, err := ops.CheckCLIApprovals(connCtx, time.Now()); err != nil {
				log.Error("check CLI approvals", "error", err)
			} else if n > 0 {
				log.Info("recorded CLI approvals", "count", n)
			}
		}
	})

	// Network assets, IPAM and discovery (M9). nebula-discovery runs the
	// scans; the server only queues jobs and reads results.
	hostAddrs := ipam.FromInventory(store.List)
	ipamStore := ipam.New(db, hostAddrs)
	disc := discovery.New(db, discoveryjob.Spool{Dir: cfg.DiscoveryDir}, ipamStore, hostAddrs, log)
	bg.Go(func() { disc.Run(connCtx) })

	// Traffic retention (traffic.retention_days): one value for every
	// traffic store the server opens — the ingest store that prunes,
	// the connections pages and the traffic map.
	retention, err := trafficRetention(cfg)
	if err != nil {
		return err
	}
	// Traffic map data (ADR 0009 TM12): net.facts results go into the
	// traffic store; own addresses and MACs come only from the inventory
	// and the IPAM assets linked to managed hosts.
	traffic, err := newTrafficIngest(db, store.List, ipamStore.Assets, log, time.Now, retention)
	if err != nil {
		return err
	}
	bg.Go(func() { traffic.run(connCtx, trafficCheckInterval) })

	// PVE spool import (ADR 0006, P1-10): the collector's observations
	// and guest NIC records; without it /pve and the chart stay empty and
	// the spool only grows.
	imports, err := newPVEImport(db, cfg.PVESpoolDir, retention, log)
	if err != nil {
		return err
	}
	bg.Go(func() { imports.run(connCtx) })

	// Vulnerability management (ADR 0011, ticket vu14w): the findings
	// store on server.db and its sweeps (ResumeCompleting at startup, then
	// Prune periodically) always, so stored findings keep their retention.
	// The D9 notifications through the notify providers (run events,
	// staleness ticks, Flush, last Flush on shutdown) run only when
	// vulnerability management is in use (the API enabled with a vuln
	// token): an install without Hermes gets no vulnerability alerts. The
	// delivered staleness alerts survive restarts in the data directory.
	var vulnSink vulnnotify.Sink = notifier
	if vh.sink != nil {
		vulnSink = vh.sink
	}
	vuln, err := newVulnService(db, vulnSink, log, nil)
	if err != nil {
		return err
	}
	vuln.statePath = filepath.Join(cfg.DataDir, vulnNotifyStateFile)
	_, hasVulnToken := cfg.API.VulnToken()
	vulnNotifying := cfg.API.Enabled && hasVulnToken
	sweepEvery, notifyEvery := vulnSweepInterval, vulnNotifyInterval
	if vh.sweepInterval > 0 {
		sweepEvery = vh.sweepInterval
	}
	if vh.notifyInterval > 0 {
		notifyEvery = vh.notifyInterval
	}
	if vh.started != nil {
		vh.started(vuln, vulnNotifying)
	}
	bg.Go(func() { vuln.runSweeps(connCtx, sweepEvery) })
	if vulnNotifying {
		bg.Go(func() { vuln.runEvents(connCtx) })
		bg.Go(func() { vuln.runNotify(connCtx, notifyEvery) })
	}
	isAdmin := vulnAdmin(exec)
	// Vulnerability agent LLM settings (ADR 0011 A1.8): the settings
	// section (maintainer, fresh assertion, audited in the write
	// transaction) and the agent's read under /api/v1/vuln/agent-config.
	agentCfg, vulnAgent, err := newVulnAgentWiring(db, audit, isAdmin, exec, log)
	if err != nil {
		return err
	}

	h, err := ui.New(withBatchPlanner(ui.Options{
		PublicOrigin:   cfg.PublicOrigin,
		Status:         exec,
		HostNames:      hostNames,
		Hosts:          store.List,
		HostKeys:       hostKeys,
		Inventory:      store,
		Operations:     ops,
		Pins:           store,
		Schedules:      ops,
		Leases:         ops,
		Runbooks:       rb,
		DeployProfiles: deployProfiles,
		Trust:          exec,
		BuiltinTrust:   exec,
		Modules:        mods,
		LastResult:     ops.LastResult,
		Network:        ipamStore,
		Discovery:      disc,
		PVE:            pveStore,
		PVEChart:       func(ctx context.Context) (pveinventory.Tree, error) { return pveStore.ChartTree(ctx, time.Now()) },
		PVERemotes:     pveRemotes,
		Events:         exec,
		Audit:          audit,
		Repin:          exec,
		Enroll:         exec,
		// Typed guest power and snapshots (ADR 0006 P2-01, WA-05): the
		// server proposes, relays the user's security key assertion and
		// commits; the executor dispatches only an approved permit at its
		// own risk floor (decision WA-05 variant (a), 2026-11-07).
		GuestPower:    exec,
		GuestSnapshot: exec,
		// Deployments (ADR 0008 section 6, PV-08): provisioning on the
		// executor, enrollment through the PV-06 join flow, the static
		// address from the IPAM. The staged plan (bootstrap modules,
		// runbooks) runs as one batch (ADR 0007). The planner probes the
		// executor (ui.DeployBatchProbe): an executor without batches
		// (no batch authority, or no credential-version read) ends such
		// a run at "joined" (enrolled, plan not run) and says so.
		// DeployBatches and ContainerBatches: withBatchPlanner.
		Deploy:       exec,
		DeployJoin:   &pveinventory.GuestJoinFlow{Store: pveStore, Executor: exec},
		DeployIPAM:   ipamStore,
		SecurityKeys: securityKeys,
		TOTPStatus:   totpStatus,
		// Findings pages over the real store.
		Vuln:      vulnPages{v: vuln, admin: isAdmin},
		VulnAgent: vulnAgent,
		// Private registry reads (ADR 0006, cu06 part 1, G13): registry
		// read leases on the lease pages and executor-read digests of
		// private images in docker.check_updates results. The credential
		// stays in the executor.
		RegistryReads: newServerRegistryReads(exec, time.Now, log),
		Log:           log,
	}, batches))
	if err != nil {
		return err
	}
	// Security middleware first (headers, origin check, body limit), then
	// the session check, then the pages. The read-only API (spec 13), when
	// enabled, authenticates with tokens instead of sessions.
	// Live org-chart values (ADR 0006 P1-37): SSE behind the same
	// session check as the pages.
	chartTree := func(ctx context.Context) (pveinventory.Tree, error) { return pveStore.ChartTree(ctx, time.Now()) }
	lc, err := newLiveChart(exec, store, chartTree, live.PeekSession(login.PeekRegistered), log)
	if err != nil {
		return err
	}
	// One collector, one spool root: the live handoff lives next to the
	// imported directories.
	lc.handoffRoot = cfg.PVESpoolDir
	bg.Go(func() { lc.run(connCtx) })
	// Software catalog (ADR 0009 TM17): admin pages behind the session.
	// Icon changes go through the icon service (TM16); results of the
	// one-shot nebula-iconfetch are imported in the background.
	iconService, err := newIconWiring(db, cfg.DataDir, defaultIconSpool, log)
	if err != nil {
		return err
	}
	bg.Go(func() { iconService.run(connCtx, iconImportInterval) })
	softwarePages, err := softwarePagesWith(db, log, iconService)
	if err != nil {
		return err
	}
	// Connections tab of the host and asset pages (ADR 0009 TM20).
	connPages, err := newConnectionsPages(db, store, ipamStore, log, retention)
	if err != nil {
		return err
	}
	pages := http.NewServeMux()
	pages.Handle("/", h.Handler())
	lc.handler.Register(pages)
	batchPages.Register(pages)
	softwarePages.Register(pages)
	connPages.Register(pages)
	// Findings export (ADR 0011 D9): admin only, audited, streamed.
	pages.Handle("GET "+vulnExportPath, vulnExport{v: vuln, admin: isAdmin, audit: audit, log: log})
	// Attack-path pages (ADR 0011 D10): admin only by the export's rule.
	if err := mountAttackPaths(pages, cfg.PublicOrigin, isAdmin, log); err != nil {
		return err
	}

	var apiHandler http.Handler
	if cfg.API.Enabled {
		a, err := api.New(api.Options{Tokens: cfg.API.Tokens, Hosts: store.List, Operations: ops, Log: log})
		if err != nil {
			return err
		}
		apiHandler = a
		log.Info("read-only API enabled", "tokens", len(cfg.API.Tokens))
		// Vulnerability agent API (ADR 0011 D3, D5) under /api/v1/vuln/,
		// only for the one vuln token, from its allowed addresses.
		vh, err := newVulnAPI(cfg.API, vuln, vulnInventory{now: time.Now}, agentCfg, log)
		if err != nil {
			return err
		}
		if vh != nil {
			apiHandler = api.Mount(a, vh)
			log.Info("vulnerability agent API enabled")
		}
	}
	// Traffic map (ADR 0009 TM19): page, frame and model behind the session; renderer modules under /static/.
	if err := mountTrafficMap(pages, cfg.PublicOrigin, db, store.List, ipamStore, log, retention); err != nil {
		return err
	}
	srv, err := webServer(cfg.PublicOrigin, login, pages, apiHandler)
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
	bg.Go(func() {
		serveErr <- srv.Serve(ln)
	})

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

// batchRPC is the executor client's batch surface: the planner's calls
// (executions.BatchExecutor) and the credential-version read.
// executorclient.Client satisfies it.
type batchRPC interface {
	executions.BatchExecutor
	executorclient.BatchCredentialReader
	// RunBatchMember runs one approved member (batchRunner).
	RunBatchMember(ctx context.Context, in *pb.RunBatchMemberRequest, opts ...grpc.CallOption) (*pb.RunBatchMemberResponse, error)
	// GetRollout reads which batch stage the executor has open.
	GetRollout(ctx context.Context, in *pb.GetRolloutRequest, opts ...grpc.CallOption) (*pb.GetRolloutResponse, error)
	// ListContainerRecreations lists the recorded container updates a
	// docker.compose_rollback member is bound to (executions.RecreationLister).
	ListContainerRecreations(ctx context.Context, in *pb.ListContainerRecreationsRequest, opts ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error)
}

// lazyBatchRPC returns the server's executor client once it is connected,
// nil before.
func lazyBatchRPC(l *lazyExecutor) func() batchRPC {
	return func() batchRPC {
		if c := l.c.Load(); c != nil {
			return c
		}
		return nil
	}
}

// serverBatchExecutor serves the batch planner from an executor
// connection that may come up after the server: while client returns nil
// every call fails with errNotConnected.
type serverBatchExecutor struct {
	client func() batchRPC
}

func (s serverBatchExecutor) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	if c := s.client(); c != nil {
		return c.ListHostKeys(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) ProposeBatch(ctx context.Context, in *pb.ProposeBatchRequest, opts ...grpc.CallOption) (*pb.ProposeBatchResponse, error) {
	if c := s.client(); c != nil {
		return c.ProposeBatch(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) CommitBatch(ctx context.Context, in *pb.CommitBatchRequest, opts ...grpc.CallOption) (*pb.CommitBatchResponse, error) {
	if c := s.client(); c != nil {
		return c.CommitBatch(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) GetBatchStatus(ctx context.Context, in *pb.GetBatchStatusRequest, opts ...grpc.CallOption) (*pb.GetBatchStatusResponse, error) {
	if c := s.client(); c != nil {
		return c.GetBatchStatus(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) GetBatchCredentialVersions(ctx context.Context, in *pb.GetBatchCredentialVersionsRequest, opts ...grpc.CallOption) (*pb.GetBatchCredentialVersionsResponse, error) {
	if c := s.client(); c != nil {
		return c.GetBatchCredentialVersions(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) RunBatchMember(ctx context.Context, in *pb.RunBatchMemberRequest, opts ...grpc.CallOption) (*pb.RunBatchMemberResponse, error) {
	if c := s.client(); c != nil {
		return c.RunBatchMember(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) GetRollout(ctx context.Context, in *pb.GetRolloutRequest, opts ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	if c := s.client(); c != nil {
		return c.GetRollout(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (s serverBatchExecutor) ListContainerRecreations(ctx context.Context, in *pb.ListContainerRecreationsRequest, opts ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error) {
	if c := s.client(); c != nil {
		return c.ListContainerRecreations(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// batchProbeTimeout bounds the executor probe before a batch is proposed
// or approved.
const batchProbeTimeout = 10 * time.Second

// deployBatches is the batch planner gated on the executor: every
// proposal and approval, from the batch pages and from the deployment
// run, first asks the executor whether it runs batches end to end
// (executorclient.BatchesAvailable) and is refused fail-closed unless it
// says so at that moment. It also serves the deployment run's probe
// (ui.DeployBatchProbe). Reads (list, view, refresh, skip) are not gated.
type deployBatches struct {
	*executions.Batches
	exec serverBatchExecutor
}

// BatchesAvailable reports whether the executor runs batches end to end
// (executorclient.BatchesAvailable: it must advertise batch execution, not
// only serve credential versions); not connected is an error, not false.
func (d deployBatches) BatchesAvailable(ctx context.Context) (bool, error) {
	return executorclient.BatchesAvailable(ctx, d.exec)
}

// ProposalsGated reports that ProposeBatch probes the executor itself
// (ui.DeployBatchGate), so a deployment run does not probe a second time.
func (d deployBatches) ProposalsGated() bool { return true }

// requireExecution refuses unless the executor runs batches now: a
// missing capability is executions.ErrBatchExecutionUnavailable, any
// probe failure executions.ErrBatchExecutionUnknown. The probe has its
// own short deadline so it never consumes the caller's call budget.
func (d deployBatches) requireExecution(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, batchProbeTimeout)
	defer cancel()
	avail, err := d.BatchesAvailable(pctx)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", executions.ErrBatchExecutionUnknown, err)
	case !avail:
		return executions.ErrBatchExecutionUnavailable
	}
	return nil
}

// ProposeBatch proposes req only if the executor runs batches.
func (d deployBatches) ProposeBatch(ctx context.Context, user string, req executions.BatchRequest) (executions.BatchCreated, error) {
	if err := d.requireExecution(ctx); err != nil {
		return executions.BatchCreated{}, err
	}
	return d.Batches.ProposeBatch(ctx, user, req)
}

// ApproveBatch relays the approval only if the executor runs batches, so
// a batch proposed while it did is not approved after it stopped.
func (d deployBatches) ApproveBatch(ctx context.Context, user, id string, assertion []byte) error {
	if err := d.requireExecution(ctx); err != nil {
		return err
	}
	return d.Batches.ApproveBatch(ctx, user, id, assertion)
}

// withBatchPlanner gives the UI the gated batch planner b for both the
// staged deployment plan (DeployBatches) and the container update
// controls (ContainerBatches, cu04): one planner, one execution gate.
func withBatchPlanner(o ui.Options, b deployBatches) ui.Options {
	o.DeployBatches = b
	o.ContainerBatches = b
	return o
}

// newBatches builds the batch planner with the executor's credential
// versions, reconciles batches left by the previous process (before
// anything is dispatched) and parses the batch pages.
func newBatches(ctx context.Context, exec serverBatchExecutor, db *sql.DB, hosts executions.Hosts, acts executions.ActionResolver, log *slog.Logger) (deployBatches, *ui.BatchPages, error) {
	b, err := executions.NewBatches(executions.BatchOptions{
		Exec: exec, DB: db, Hosts: hosts, Log: log, Actions: acts,
		// Compose rollbacks bind the executor's recorded update (cu04).
		Recreations: exec,
		CredentialVersion: func(ctx context.Context, ref string) (uint64, error) {
			return executorclient.CredentialVersion(ctx, exec, ref)
		},
	})
	if err != nil {
		return deployBatches{}, nil, fmt.Errorf("batch planner: %w", err)
	}
	if n, err := b.ReconcileBatches(ctx); err != nil {
		log.Error("reconcile batches", "error", err)
	} else if n > 0 {
		log.Info("reconciled batches", "members", n)
	}
	gated := deployBatches{Batches: b, exec: exec}
	pages, err := ui.NewBatchPages(gated, log)
	if err != nil {
		return deployBatches{}, nil, fmt.Errorf("batch pages: %w", err)
	}
	return gated, pages, nil
}
