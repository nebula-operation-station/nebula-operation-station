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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	"slices"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
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
	// Deploy profiles (ADR 0008 PV-04): versioned, secret-free presets.
	deployProfiles := deployprofile.New(db)
	// Modules (M7-5): the executor verifies their signatures.
	mods := modules.New(db, exec)
	ops.SetModules(mods)
	if err := ops.Resume(connCtx); err != nil {
		log.Error("resume executions", "error", err)
	}
	// Scheduled read-only checks run under executor-held schedule grants.
	go ops.RunSchedules(connCtx)
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
	go (&batchRunner{batches: batches.Batches, exec: serverBatchExecutor{client: lazyBatchRPC(exec)}, hosts: store, actions: ops, log: log}).
		run(connCtx, batchRunInterval)

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

	// Record approvals made on the executor host (issue #78): the check
	// contacts the executor only while at least one operation is pending.
	go func() {
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
	}()

	// Network assets, IPAM and discovery (M9). nebula-discovery runs the
	// scans; the server only queues jobs and reads results.
	hostAddrs := ipam.FromInventory(store.List)
	ipamStore := ipam.New(db, hostAddrs)
	disc := discovery.New(db, discoveryjob.Spool{Dir: cfg.DiscoveryDir}, ipamStore, hostAddrs, log)
	go disc.Run(connCtx)

	h, err := ui.New(ui.Options{
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
		// Deployments (ADR 0008 section 6, PV-08): provisioning on the
		// executor, enrollment through the PV-06 join flow, the static
		// address from the IPAM. The staged plan (bootstrap modules,
		// runbooks) runs as one batch (ADR 0007). The planner probes the
		// executor (ui.DeployBatchProbe): an executor without batches
		// (no batch authority, or no credential-version read) ends such
		// a run at "joined" (enrolled, plan not run) and says so.
		Deploy:        exec,
		DeployJoin:    &pveinventory.GuestJoinFlow{Store: pveStore, Executor: exec},
		DeployIPAM:    ipamStore,
		DeployBatches: batches,
		SecurityKeys:  securityKeys,
		TOTPStatus:    totpStatus,
		Log:           log,
	})
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
	go lc.run(connCtx)
	// Software catalog (ADR 0009 TM17): admin pages behind the session.
	softwarePages, err := newSoftwarePages(db, log)
	if err != nil {
		return err
	}
	pages := http.NewServeMux()
	pages.Handle("/", h.Handler())
	lc.handler.Register(pages)
	batchPages.Register(pages)
	softwarePages.Register(pages)

	var apiHandler http.Handler
	if cfg.API.Enabled {
		a, err := api.New(api.Options{Tokens: cfg.API.Tokens, Hosts: store.List, Operations: ops, Log: log})
		if err != nil {
			return err
		}
		apiHandler = a
		log.Info("read-only API enabled", "tokens", len(cfg.API.Tokens))
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

// batchRunInterval is how often the server hands the next approved batch
// members to the executor.
const batchRunInterval = 5 * time.Second

// batchRunner hands the members of approved batches to the executor one at
// a time (ADR 0007 E11/E13). It only decides when: the executor takes
// everything that runs from its frozen plan and enforces claims, stage
// gates, dependencies, same-host ordering, trust, risk and credential
// versions. Each member is recorded as dispatched before the call, so a
// server crash leaves it unknown (ReconcileBatches), never redispatched;
// its result is recorded with the server's stop policy. One goroutine runs
// it, so at most one member is in flight from this server.
type batchRunner struct {
	batches *executions.Batches
	exec    serverBatchExecutor
	hosts   executions.Hosts
	actions executions.ActionResolver
	log     *slog.Logger
}

// run hands members to the executor every interval until ctx ends.
func (r *batchRunner) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runOnce advances every approved batch with planned members as far as
// the executor allows now. It returns the number of members handed over.
func (r *batchRunner) runOnce(ctx context.Context) int {
	if r.exec.client() == nil {
		return 0
	}
	list, err := r.batches.ListBatches(ctx)
	if err != nil {
		r.log.Error("batch runner: list batches", "error", err)
		return 0
	}
	n := 0
	for _, b := range list {
		if ctx.Err() != nil {
			return n
		}
		if b.State != "approved" || b.Counts.Planned == 0 || b.Counts.Dispatched > 0 {
			continue
		}
		n += r.runBatch(ctx, b.ID)
	}
	return n
}

// runBatch hands the batch's planned members over in plan order until one
// must wait (a later stage, a closed gate) or the batch stops.
func (r *batchRunner) runBatch(ctx context.Context, id string) int {
	n := 0
	for ctx.Err() == nil {
		v, err := r.batches.Batch(ctx, id)
		if err != nil {
			r.log.Error("batch runner: read batch", "batch", id, "error", err)
			return n
		}
		if v.State != "approved" || v.Counts.Dispatched > 0 {
			return n
		}
		i := slices.IndexFunc(v.Members, func(m executions.BatchMemberView) bool { return m.Outcome == executions.OutcomePlanned })
		if i < 0 {
			return n
		}
		m := v.Members[i]
		if !r.stageOpen(ctx, v, m) {
			return n
		}
		if !r.runMember(ctx, v, m) {
			return n
		}
		n++
	}
	return n
}

// stageOpen reports whether the executor has the member's stage open. The
// first stage is open from approval; a later stage behind an automatic
// gate opens as earlier stages complete (the executor's own rollout
// decides); a manual gate waits for the admin. Any doubt waits.
func (r *batchRunner) stageOpen(ctx context.Context, v executions.BatchView, m executions.BatchMemberView) bool {
	if m.Stage <= 1 {
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, batchProbeTimeout)
	defer cancel()
	resp, err := r.exec.GetRollout(cctx, &pb.GetRolloutRequest{ExecutionDigest: v.Digest})
	if err != nil {
		r.log.Warn("batch runner: read rollout", "batch", v.ID, "error", err)
		return false
	}
	return int(resp.GetRollout().GetOpenStage()) >= m.Stage
}

// memberInputs returns the exact script of a member, its run timeout and
// its host's endpoints; an error means the member cannot be handed over as
// approved.
func (r *batchRunner) memberInputs(ctx context.Context, m executions.BatchMemberView) (script []byte, timeout time.Duration, eps []string, err error) {
	a, ok := actions.Lookup(m.ActionID)
	if !ok || a.Version != m.ModuleVersion {
		if r.actions == nil {
			return nil, 0, nil, errors.New("the action is not available on this server")
		}
		var found bool
		a, found, err = r.actions.Action(ctx, m.ActionID, m.ModuleVersion)
		if err != nil || !found || a.ID != m.ActionID || a.Version != m.ModuleVersion {
			return nil, 0, nil, errors.New("the action at the approved version is not available on this server")
		}
	}
	if sum := sha256.Sum256(a.Script); hex.EncodeToString(sum[:]) != m.ArtifactSHA256 {
		return nil, 0, nil, errors.New("the action's script differs from the approved artifact")
	}
	h, err := r.hosts.Get(ctx, m.HostID)
	if err != nil {
		return nil, 0, nil, errors.New("the host is not in the inventory")
	}
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		eps = append(eps, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	if len(eps) == 0 {
		return nil, 0, nil, errors.New("the host has no endpoint")
	}
	return a.Script, a.Timeout, eps, nil
}

// runMember marks the member dispatched, hands it to the executor and
// records its result. It reports whether the batch may continue now.
func (r *batchRunner) runMember(ctx context.Context, v executions.BatchView, m executions.BatchMemberView) bool {
	script, timeout, eps, inErr := r.memberInputs(ctx, m)
	if err := r.batches.MarkDispatched(ctx, v.ID, m.MemberID); err != nil {
		if !errors.Is(err, executions.ErrBatchNotDispatchable) && !errors.Is(err, executions.ErrBatchMemberFinal) {
			r.log.Error("batch runner: mark dispatched", "batch", v.ID, "member", m.MemberID, "error", err)
		}
		return false
	}
	res := executions.MemberResult{Outcome: executions.OutcomeFailed}
	if inErr != nil {
		// Nothing reaches the executor: the member fails closed and the
		// stop policy applies.
		res.Detail = "not executed: " + inErr.Error()
	} else {
		secs := uint32(min(timeout, hostrunMaxAttached) / time.Second)
		// Shutdown cancels the run; its outcome is then unknown.
		resp, err := r.exec.RunBatchMember(ctx, &pb.RunBatchMemberRequest{BatchDigest: v.Digest, MemberId: m.MemberID,
			Endpoints: eps, TimeoutSeconds: secs, Artifact: script})
		res = batchMemberResult(resp, err)
	}
	if err := r.batches.RecordOutcome(context.WithoutCancel(ctx), v.ID, m.MemberID, res); err != nil {
		r.log.Error("batch runner: record outcome", "batch", v.ID, "member", m.MemberID, "error", err)
		return false
	}
	r.log.Info("audit", "kind", "batch_member_handed_over", "batch", v.ID, "member", m.MemberID, "outcome", res.Outcome,
		"unreachable", res.Unreachable)
	return res.Outcome == executions.OutcomeSuccess
}

// hostrunMaxAttached is the executor's limit for one member run (members
// run attached).
const hostrunMaxAttached = 10 * time.Minute

// batchMemberResult maps the executor's answer to the server's member
// result. A refusal status means nothing ran (the executor refuses only
// before the claim); a transport failure means the outcome is unknown.
func batchMemberResult(resp *pb.RunBatchMemberResponse, err error) executions.MemberResult {
	if err != nil {
		st := status.Convert(err)
		switch st.Code() {
		case codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition, codes.PermissionDenied, codes.Unimplemented,
			codes.AlreadyExists, codes.Unauthenticated, codes.ResourceExhausted, codes.OutOfRange:
			return executions.MemberResult{Outcome: executions.OutcomeFailed, Detail: "not executed: the executor refused: " + st.Message()}
		}
		return executions.MemberResult{Outcome: executions.OutcomeUnknown, Detail: "the executor's answer was lost; the member may have run and is never redispatched"}
	}
	detail := resp.GetClass()
	if d := resp.GetDetail(); d != "" {
		detail += ": " + d
	}
	switch resp.GetOutcome() {
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS:
		return executions.MemberResult{Outcome: executions.OutcomeSuccess, Detail: detail}
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE:
		return executions.MemberResult{Outcome: executions.OutcomeFailed, Unreachable: resp.GetUnreachable(), Detail: detail}
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED:
		return executions.MemberResult{Outcome: executions.OutcomeFailed, Detail: "not executed: " + detail}
	}
	return executions.MemberResult{Outcome: executions.OutcomeUnknown, Detail: detail}
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

// newBatches builds the batch planner with the executor's credential
// versions, reconciles batches left by the previous process (before
// anything is dispatched) and parses the batch pages.
func newBatches(ctx context.Context, exec serverBatchExecutor, db *sql.DB, hosts executions.Hosts, acts executions.ActionResolver, log *slog.Logger) (deployBatches, *ui.BatchPages, error) {
	b, err := executions.NewBatches(executions.BatchOptions{
		Exec: exec, DB: db, Hosts: hosts, Log: log, Actions: acts,
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
