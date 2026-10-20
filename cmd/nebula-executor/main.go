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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
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
		dataDir     = flag.String("data-dir", "/var/lib/nebula/executor", "private executor state (mode 0700)")
		socketPath  = flag.String("socket", "/run/nebula/executor.sock", "Unix socket path")
		socketGroup = flag.String("socket-group", "nebula-rpc", "group owning the socket file ('' to skip)")
		serverUser  = flag.String("server-user", "nebula-server", "OS user of nebula-server")
		adminUsers  = flag.String("admin-users", "", "comma-separated OS users allowed to unlock and approve")
		rpID        = flag.String("rp-id", "", "WebAuthn RP ID: the fixed hostname Nebula is served under")
		hardened    = flag.Bool("hardened", false, "require `nebula approve` for HIGH and CRITICAL")
		sessionMin  = flag.Int("session-minutes", 60, "privileged session length")
		showVersion = flag.Bool("version", false, "print version and exit")
		origins     stringList
	)
	flag.Var(&origins, "origin", "allowed WebAuthn origin, e.g. https://nebula.example.org (repeatable)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return nil
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
	log = slog.New(events.NewHandler(log.Handler(), chain))
	if created {
		log.Info("audit", "kind", "event_key_created", "fingerprint", events.Fingerprint(chain.PublicKey()))
	}

	keysDir := filepath.Join(*dataDir, "keys")
	if err := fsguard.EnsurePrivateDir(keysDir); err != nil {
		return err
	}

	uidRoles, err := resolveRoles(*serverUser, *adminUsers)
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
	risk, err := riskpolicy.New(db)
	if err != nil {
		return err
	}
	auth, err := permit.New(permit.Options{
		Mode:          mode,
		Verifier:      verifier,
		Store:         db,
		RiskPolicy:    risk,
		Schedules:     db,
		SessionLength: time.Duration(*sessionMin) * time.Minute,
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
	svc.SetEventKey(chain.PublicKey())

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
	go func() {
		<-ctx.Done()
		keys.Lock()
		auth.Lock("shutdown")
		srv.GracefulStop()
	}()

	log.Info("started", "version", version.String(), "socket", *socketPath, "mode", modeName(mode),
		"rp_id", *rpID, "webauthn_credentials", len(creds), "locked", true,
		"permits", 0, "spent_execution_ids_pruned", pruned)
	return srv.Serve(lis)
}

// reconcileInterval is how often open durable runs are checked.
const reconcileInterval = 15 * time.Second

func resolveRoles(serverUser, adminUsers string) (map[uint32][]peercred.Role, error) {
	self := uint32(os.Getuid())
	roles := map[uint32][]peercred.Role{}

	suid, err := peercred.LookupUID(serverUser)
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
		uid, err := peercred.LookupUID(name)
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
	return roles, nil
}

func modeName(m permit.Mode) string {
	if m == permit.ModeHardened {
		return "hardened"
	}
	return "standard"
}
