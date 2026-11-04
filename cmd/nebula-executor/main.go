// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-executor holds all credentials and authorizes every
// privileged action. It serves gRPC on a Unix socket only and never opens a
// network listener.
//
// Scope so far: authorization, permits, WebAuthn registration and verification,
// executor-side risk floor, keyring.
// SSH execution arrives in Milestone 4.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fsguard"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nebula-executor:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dataDir       = flag.String("data-dir", "/var/lib/nebula/executor", "private executor state (mode 0700)")
		socketPath    = flag.String("socket", "/run/nebula/executor.sock", "Unix socket path")
		socketGroup   = flag.String("socket-group", "nebula-rpc", "group owning the socket file ('' to skip)")
		serverUser    = flag.String("server-user", "nebula-server", "OS user of nebula-server")
		adminUsers    = flag.String("admin-users", "", "comma-separated OS users allowed to unlock and approve")
		collectorUser = flag.String("pve-collector-user", defaultPveCollectorUser, "OS user of nebula-pve-collector (gets the pve-collector role; '' disables it)")
		rpID          = flag.String("rp-id", "", "WebAuthn RP ID: the fixed hostname Nebula is served under")
		hardened      = flag.Bool("hardened", false, "require `nebula approve` for HIGH and CRITICAL")
		sessionMin    = flag.Int("session-minutes", int(permit.DefaultSessionLength/time.Minute), "privileged session length in minutes (15–240)")
		trustDir      = flag.String("builtin-trust-dir", "", "built-in trust store (default <data-dir>/trust)")
		bundleDir     = flag.String("builtin-bundle-dir", defaultBuiltinBundleDir, "locally verified NOS release bundle that `nebula artifact trust-builtins` reviews")
		showVersion   = flag.Bool("version", false, "print version and exit")
		origins       stringList
	)
	flag.Var(&origins, "origin", "allowed WebAuthn origin, e.g. https://nebula.example.org (repeatable)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return nil
	}

	sessionLength, err := sessionLengthFromMinutes(*sessionMin)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Make the process non-dumpable: no core dumps and no ptrace by other
	// processes of the same UID.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", err)
	}

	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run as root; run as the dedicated nebula-executor user")
	}
	if *rpID == "" || len(origins) == 0 {
		return fmt.Errorf("-rp-id and at least one -origin are required")
	}
	if *adminUsers == "" {
		return fmt.Errorf("-admin-users is required")
	}

	if err := fsguard.CheckPrivateDir(*dataDir); err != nil {
		return err
	}
	// executor.db: spent execution IDs and WebAuthn signature counters.
	// Permits and the privileged session are never stored, so this process
	// starts with none, whatever happened before the restart.
	db, err := executordb.Open(*dataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	pruned, err := db.PruneExecutions(time.Now())
	if err != nil {
		return err
	}
	// Signed events (M10-1): every audit line is also appended to the
	// event chain in executor.db, signed with the event key.
	eventKey, created, err := events.LoadOrCreateKey(*dataDir)
	if err != nil {
		return err
	}
	chain := events.NewChain(db, eventKey)
	// The key is registered before the handler goes live, so no event is
	// ever signed by a key the chain does not know yet (review m102, F4).
	added, previous, err := db.RegisterEventKey(chain.PublicKey())
	if err != nil {
		return err
	}
	log = slog.New(events.NewHandler(log.Handler(), chain))
	if created || added {
		attrs := []any{"kind", "event_key_created", "fingerprint", events.Fingerprint(chain.PublicKey())}
		if previous != nil {
			attrs = append(attrs, "previous", events.Fingerprint(previous))
		}
		log.Info("audit", attrs...)
	}

	keysDir := filepath.Join(*dataDir, "keys")
	if err := fsguard.EnsurePrivateDir(keysDir); err != nil {
		return err
	}

	uidRoles, err := resolveRoles(*serverUser, *adminUsers, *collectorUser, log)
	if err != nil {
		return err
	}
	policy := peercred.NewPolicy(uidRoles, executor.MethodRoles())

	creds, err := executor.LoadCredentials(db, *dataDir, log)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		log.Warn("no WebAuthn credentials registered; browser approval is unavailable, `nebula approve` still works; register one with `nebula webauthn code`")
	}
	if db.Created() && len(creds) > 0 {
		log.Warn("executor.db was created and WebAuthn credentials were imported from the legacy credentials file: stored signature counters and spent execution IDs are gone (deleted file or restore without executor.db)")
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: *rpID, Origins: origins, Counters: db}, creds)
	if err != nil {
		return err
	}

	mode := permit.ModeStandard
	if *hardened {
		mode = permit.ModeHardened
	}
	// The guest power, snapshot and backup/migration floors (node, remote,
	// destination node and linked hosts of a guest) are part of the
	// authority's policy, so they are enforced again on approval and run
	// authorization; the service binds its targets in the same bindings
	// (SetPveGuestPowerBindings below).
	powerBindings := &executor.PveGuestPowerBindings{}
	risk, err := executor.NewExecutorRiskPolicy(db, powerBindings)
	if err != nil {
		return err
	}
	auth, err := permit.New(permit.Options{
		Mode:          mode,
		Verifier:      verifier,
		Store:         db,
		RiskPolicy:    risk,
		Schedules:     db,
		SessionLength: sessionLength,
		Audit:         executor.AuditLogger(log),
	})
	if err != nil {
		return err
	}
	reg, err := webauthnreg.New(webauthnreg.Config{
		RPID: *rpID, Origins: origins, Audit: executor.RegistrationAuditLogger(log),
	}, verifier, db)
	if err != nil {
		return err
	}
	keys := keyring.New(keysDir)
	svc := executor.NewService(auth, keys, db, reg, log)
	svc.SetPveGuestPowerBindings(powerBindings)
	svc.SetEventKey(chain.PublicKey())
	svc.SetBackupDirs(*dataDir, keysDir)
	// Built-in trust (ADR 0007 E16): commits record exact artifact trust
	// in executor.db, the same entries the risk policy reads.
	setupBuiltinTrust(svc, *dataDir, *trustDir, *bundleDir, db, log)
	// Batch approval (ADR 0007 E19b): the batch RPCs, including the
	// credential-version read the server binds into every plan, are served
	// only with an authority wired.
	// Every admin user may review and approve batches from the CLI, as
	// the role table allows. The production batch dispatcher is wired with
	// it (RunBatchMember), so the executor advertises batch execution.
	batchAuth, err := setupBatchAuthority(svc, batchConfig{
		Mode: mode, Verifier: verifier, Risk: risk, Source: db, Store: db,
		Session: auth.Session, AdminUIDs: batchAdminUIDs(uidRoles), Audit: executor.AuditLogger(log),
	})
	if err != nil {
		return err
	}

	lis, err := peercred.Listen(peercred.ListenOptions{Path: *socketPath, Mode: 0o660, Group: *socketGroup})
	if err != nil {
		return err
	}
	srv := executor.NewGRPCServer(svc, policy, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Durable runs (spec 07): reconciled in the background, also those
	// left open by an earlier process, once the keyring is unlocked.
	go svc.Reconcile(ctx, reconcileInterval)
	// Open PVE mutation steps (ADR 0008): observed and identified through
	// the task list with the read token while the vault is unlocked; a
	// step is never redispatched.
	go svc.ReconcilePVEMutations(ctx, reconcileInterval)
	go func() {
		<-ctx.Done()
		keys.Lock()
		auth.Lock("shutdown")
		batchAuth.Lock()
		srv.GracefulStop()
	}()

	log.Info("started", "version", version.String(), "socket", *socketPath, "mode", modeName(mode),
		"rp_id", *rpID, "webauthn_credentials", len(creds), "locked", true,
		"permits", 0, "spent_execution_ids_pruned", pruned)
	return srv.Serve(lis)
}

// reconcileInterval is how often open durable runs are checked.
const reconcileInterval = 15 * time.Second

// defaultPveCollectorUser is the OS user that install.sh, the Debian
// package and the container image create for nebula-pve-collector.
const defaultPveCollectorUser = "nebula-pve-collector"

func resolveRoles(serverUser, adminUsers, collectorUser string, log *slog.Logger) (map[uint32][]peercred.Role, error) {
	return resolveRolesWith(peercred.LookupUID, uint32(os.Getuid()), serverUser, adminUsers, collectorUser, log)
}

// resolveRolesWith maps OS users to peercred roles. The server, every
// admin and the pve-collector need distinct dedicated UIDs. A collector
// user that does not exist (an install that predates the collector) leaves
// the pve-collector role unassigned; any other lookup failure, or a
// collector UID shared with root, the executor, the server or an admin,
// stops the start.
func resolveRolesWith(lookup func(string) (uint32, error), self uint32, serverUser, adminUsers, collectorUser string, log *slog.Logger) (map[uint32][]peercred.Role, error) {
	roles := map[uint32][]peercred.Role{}

	suid, err := lookup(serverUser)
	if err != nil {
		return nil, fmt.Errorf("server user %q: %w", serverUser, err)
	}
	if suid == 0 || suid == self {
		return nil, fmt.Errorf("server user must be a dedicated non-root user distinct from the executor")
	}
	roles[suid] = []peercred.Role{peercred.RoleServer}

	for _, name := range strings.Split(adminUsers, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		uid, err := lookup(name)
		if err != nil {
			return nil, fmt.Errorf("admin user %q: %w", name, err)
		}
		if uid == suid {
			return nil, fmt.Errorf("admin user %q must not be the server user", name)
		}
		if uid == self {
			return nil, fmt.Errorf("admin user %q must not be the executor user", name)
		}
		if uid == 0 {
			return nil, fmt.Errorf("root cannot be an admin user; use a personal account")
		}
		roles[uid] = []peercred.Role{peercred.RoleAdmin}
	}

	collectorUser = strings.TrimSpace(collectorUser)
	if collectorUser == "" {
		log.Info("pve-collector role disabled: -pve-collector-user is empty")
		return roles, nil
	}
	cuid, err := lookup(collectorUser)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		log.Warn("pve-collector user not found; the pve-collector role is not assigned", "user", collectorUser)
		return roles, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pve-collector user %q: %w", collectorUser, err)
	}
	switch {
	case cuid == 0:
		return nil, fmt.Errorf("pve-collector user %q must not be root", collectorUser)
	case cuid == self:
		return nil, fmt.Errorf("pve-collector user %q must not be the executor user", collectorUser)
	case len(roles[cuid]) > 0:
		return nil, fmt.Errorf("pve-collector user %q must be a dedicated user, not the server or an admin user", collectorUser)
	}
	roles[cuid] = []peercred.Role{peercred.RolePVECollector}
	return roles, nil
}

func modeName(m permit.Mode) string {
	if m == permit.ModeHardened {
		return "hardened"
	}
	return "standard"
}
