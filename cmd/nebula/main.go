// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula is the admin CLI. It talks directly to nebula-executor over
// its Unix socket; the web server never sees what is typed here.
//
//	nebula status
//	nebula unlock
//	nebula lock
//	nebula pending
//	nebula approve <digest-prefix>
//	nebula artifact trust|untrust|list
//	nebula host probe|pin|unpin|keys|test|criticality|clear|list
//	nebula webauthn code|list|remove
//	nebula totp setup|status|remove
//	nebula pve remote add|rotate-token|remove|repin|list
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"net"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

const usage = `usage: nebula <command>

commands:
  status              show executor state
  unlock              decrypt the SSH keys and the vault (asks for the passphrase)
  lock                wipe keys, end the privileged session, revoke all permits
  pending             list permits waiting for approval
  approve <digest>    approve a pending permit (hardened path); a unique prefix is enough
  approve --stage N DIGEST | approve --skip HOST DIGEST
                      open the next stage of a rollout, or skip a host (hardened path)
  schedule pending | approve <digest> | list | revoke <grant-id>
                      schedule grants: standing permission for LOW read-only checks
  artifact trust --action ID --version X.Y.Z --risk LEVEL [--label TEXT] FILE
                      trust a script for one action; LEVEL becomes its minimum risk
  artifact untrust --action ID --version X.Y.Z SHA256
  artifact list       list trusted artifacts (anything else needs at least HIGH)
  signer add --name NAME FILE | list | remove SHA256:FINGERPRINT
                      module signers (ssh-ed25519); adding one is CRITICAL (type the fingerprint)
  module confirm-signer MODULE SHA256:FINGERPRINT
                      accept a new signer for a module after reviewing it
  module pack [--archive OUT.tar.gz] DIR
                      write DIR/module.lock.json from module.yaml (to sign), or the archive to import
  backup [--out FILE] [--full] [--no-encrypt] [--pre-upgrade]
                      run with sudo: an age-encrypted backup of server and executor data (never a secret in plaintext)
  restore [--identity FILE] ARCHIVE
                      run with sudo: CRITICAL; restore a backup (the current data is kept aside)
  events [--after N] [--limit N] [--json] | key | verify
                      the executor's signed event chain (verified here with the event key)
  host enroll-script --from ADDR[,ADDR] [--user nebula] [--key REF] [--no-sudo]
                      print a script to run on a new host: user, restricted key, sudo
  host probe ENDPOINT...
                      show the SSH host key of endpoints (sends no credential)
  host pin [--user U] [--key REF] [--known-hosts FILE] [--criticality LEVEL] HOST ENDPOINT...
                      pin a host's key after you confirmed the fingerprint
  host unpin HOST     remove a pin (needed to re-pin a changed or blocked host)
  host keys           list pinned host keys and blocked hosts
  host test HOST ENDPOINT...
                      connect to a pinned host and log in (keys must be unlocked)
  host criticality HOST [SHA256:FINGERPRINT] LEVEL
                      set the executor's criticality of a host, bound to its key
  host clear HOST     remove a host record (unrecorded hosts count as HIGH)
  host list           list host criticality records
  webauthn code [--user NAME] [--label TEXT]
                      one-time code to register a security key in the web UI
  webauthn list       list registered WebAuthn credentials
  webauthn remove ID  remove a credential (locks the executor)
  totp setup [--account LABEL]
                      set up TOTP recovery for the web login (asks for a code to confirm)
  totp status         show TOTP recovery and whether a recovery is pending
  totp remove         remove TOTP recovery
  totp finish-recovery
                      confirm the key registered after a recovery login (ends the recovery)
  vault init          create the secret vault (passphrase of at least 32 characters)
  vault status        show whether the vault exists and is unlocked
  secret set ID       store a secret (value from the terminal or stdin; never an argument)
  secret list         list secret IDs and versions (never values)
  secret rm ID        delete a secret
  pve remote add <id> --kind cluster|standalone --endpoint host:port [...]
                      register a PVE remote: probe, confirm the fingerprint, store the token
  pve remote rotate-token <id> --purpose read|action
                      validate the new token first; the old one stays until it is validated
  pve remote remove <id>
                      disable, revoke dependent grants, delete the vault secrets, tombstone
  pve remote repin <id>
                      re-pin the trust identity after a certificate change
  pve remote list     metadata only (never secrets)
  version             print version

environment:
  NEBULA_EXECUTOR_SOCKET   default /run/nebula/executor.sock
  NEBULA_EXECUTOR_USER     default nebula-executor (the socket must be served by this user)`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(64)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "nebula:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	if cmd == "version" {
		fmt.Println(version.String())
		return nil
	}
	// Packing a module is the author's step; it needs no executor.
	if cmd == "module" && len(args) > 0 && args[0] == "pack" {
		return modulePack(args[1:], os.Stdout)
	}
	// Backup and restore run as root (sudo): they read or write the server's
	// data themselves; backup talks to the executor as the admin who ran
	// sudo.
	switch cmd {
	case "backup":
		return backupCmd(args, os.Stdin, os.Stdout)
	case "restore":
		return restoreCmd(args, os.Stdin, os.Stdout)
	case "pve":
		// PVE administration authenticates the local admin through peer credentials.
		return pveCmd(args, os.Stdin, ttyPrompter, os.Stdout)
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch cmd {
	case "status":
		return status(ctx, c)
	case "unlock":
		return unlock(ctx, c)
	case "lock":
		if _, err := c.Lock(ctx, &pb.LockRequest{}); err != nil {
			return err
		}
		fmt.Println("locked: keys wiped, session ended, permits revoked")
		return nil
	case "pending":
		return pending(ctx, c)
	case "approve":
		if len(args) > 1 && strings.HasPrefix(args[0], "--") {
			return gateCmd(ctx, c, args, os.Stdin, os.Stdout)
		}
		if len(args) != 1 {
			return errors.New("usage: nebula approve <digest-prefix>")
		}
		return approve(ctx, c, args[0], os.Stdin, os.Stdout)
	case "schedule":
		return scheduleCmd(ctx, c, args, os.Stdin, os.Stdout)
	case "artifact":
		return artifactCmd(ctx, c, args)
	case "signer":
		return signerCmd(ctx, c, args, os.Stdin, os.Stdout)
	case "module":
		return moduleCmd(ctx, c, args, os.Stdin, os.Stdout)
	case "events":
		return eventsCmd(ctx, c, args, os.Stdout)
	case "host":
		return hostCmd(ctx, c, args)
	case "webauthn":
		return webauthnCmd(ctx, c, args)
	case "totp":
		return totpCmd(ctx, c, args)
	case "vault":
		return vaultCmd(ctx, c, args, ttyPrompter, os.Stdout)
	case "secret":
		return secretCmd(ctx, c, args, func() ([]byte, error) { return readSecretValue(os.Stdin, ttyPrompter) }, os.Stdin, os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(64)
		return nil
	}
}

// dialExecutor connects to the executor socket. Who serves the socket is
// verified before anything is sent, the unlock passphrase in particular.
func dialExecutor() (*grpc.ClientConn, error) {
	sock := envOr("NEBULA_EXECUTOR_SOCKET", "/run/nebula/executor.sock")
	execUser := envOr("NEBULA_EXECUTOR_USER", "nebula-executor")
	wantUID, err := peercred.LookupUID(execUser)
	if err != nil {
		return nil, fmt.Errorf("executor user %q: %w", execUser, err)
	}
	return grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, sock, wantUID)
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)),
	)
}

func status(ctx context.Context, c pb.ExecutorServiceClient) error {
	s, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		return err
	}
	fmt.Printf("unlocked:           %v\n", s.GetUnlocked())
	fmt.Printf("credentials:        %s\n", strings.Join(s.GetLoadedCredentialRefs(), ", "))
	fmt.Printf("privileged session: %v", s.GetPrivilegedSessionActive())
	if s.GetPrivilegedSessionActive() {
		fmt.Printf(" (until %s)", time.Unix(s.GetPrivilegedSessionExpiryUnix(), 0).Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Printf("mode:               %s\n", map[bool]string{true: "hardened", false: "standard"}[s.GetHardenedMode()])
	fmt.Printf("permits:            %d pending, %d approved\n", s.GetPendingPermits(), s.GetApprovedPermits())
	fmt.Printf("vault:              %s\n", vaultStateText(s.GetVaultState()))
	return nil
}

func unlock(ctx context.Context, c pb.ExecutorServiceClient) error {
	return unlockWith(ctx, c, ttyPrompter, os.Stdout)
}

func pending(ctx context.Context, c pb.ExecutorServiceClient) error {
	resp, err := c.ListPending(ctx, &pb.ListPendingRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetPermits()) == 0 {
		fmt.Println("no pending permits")
		return nil
	}
	for _, p := range resp.GetPermits() {
		r := p.GetRequest()
		fmt.Printf("%s  %-9s %-32s %3d targets  expires %s\n",
			p.GetExecutionDigest()[:16], shortRisk(r.GetRiskClass()), r.GetActionId(),
			len(r.GetResolvedTargets()), time.Unix(p.GetApprovalExpiryUnix(), 0).Format("15:04:05"))
	}
	return nil
}

func approve(ctx context.Context, c pb.ExecutorServiceClient, prefix string, in io.Reader, out io.Writer) error {
	if len(prefix) < 8 {
		return errors.New("give at least 8 characters of the digest")
	}
	resp, err := c.ListPending(ctx, &pb.ListPendingRequest{})
	if err != nil {
		return err
	}
	var match *pb.PendingPermit
	for _, p := range resp.GetPermits() {
		if strings.HasPrefix(p.GetExecutionDigest(), prefix) {
			if match != nil {
				return errors.New("prefix is ambiguous")
			}
			match = p
		}
	}
	if match == nil {
		return errors.New("no pending permit with that prefix")
	}

	// Everything shown here comes from the executor, not from the web UI.
	r := match.GetRequest()
	fmt.Fprintln(out, "Approve this execution? (as seen by the executor)")
	fmt.Fprintf(out, "  digest         %s\n", match.GetExecutionDigest())
	fmt.Fprintf(out, "  risk           %s\n", shortRisk(r.GetRiskClass()))
	fmt.Fprintf(out, "  action         %s @ %s\n", r.GetActionId(), r.GetModuleVersion())
	fmt.Fprintf(out, "  artifact       sha256:%s\n", r.GetArtifactSha256())
	printSafetyScanner(out, match)
	printScriptPreview(out, match)
	fmt.Fprintf(out, "  parameters     sha256:%s\n", r.GetParametersHash())
	fmt.Fprintf(out, "                 %s\n", displaySafe(match.GetCanonicalParameters(), canonical.MaxParametersSize))
	fmt.Fprintf(out, "  stage plan     sha256:%s\n", r.GetStagePlanHash())
	for i, st := range match.GetStagePlan() {
		fmt.Fprintf(out, "    stage %d %-20s %d hosts, max failed %d, max unreachable %d, continue %s\n", i+1,
			displaySafe([]byte(st.GetName()), 40), len(st.GetHostIds()), st.GetMaxFailed(), st.GetMaxUnreachable(),
			displaySafe([]byte(st.GetContinueMode()), 10))
		for _, h := range st.GetHostIds() {
			fmt.Fprintf(out, "      %s\n", displaySafe([]byte(h), 64))
		}
	}
	fmt.Fprintf(out, "  credentials    %s\n", strings.Join(r.GetCredentialRefs(), ", "))
	fmt.Fprintf(out, "  permit expiry  %s\n", time.Unix(r.GetExpiryUnix(), 0).Format(time.RFC3339))
	fmt.Fprintf(out, "  targets (%d):\n", len(r.GetResolvedTargets()))
	for _, t := range r.GetResolvedTargets() {
		fmt.Fprintf(out, "    %-32s %s\n", t.GetHostId(), t.GetHostKeyFingerprint())
	}

	br := bufio.NewReader(in)
	typed := 0
	if r.GetRiskClass() == pb.RiskClass_RISK_CLASS_CRITICAL {
		fmt.Fprint(out, "CRITICAL: type the number of targets to approve: ")
		line, _ := br.ReadString('\n')
		typed, err = strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return errors.New("not a number; nothing approved")
		}
	} else {
		fmt.Fprint(out, "Type 'yes' to approve: ")
		line, _ := br.ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not approved")
		}
	}
	if _, err := c.ApproveCLI(ctx, &pb.ApproveCLIRequest{ExecutionDigest: match.GetExecutionDigest(), TypedTargetCount: uint32(typed)}); err != nil {
		return err
	}
	fmt.Fprintln(out, "approved")
	return nil
}

// printSafetyScanner shows the executor's Safety Scanner verdict for the
// permit's artifact: each finding (category, line, excerpt) or "no
// findings". All of it is host data, so it goes through displaySafe. When
// the executor has not scanned these bytes (no artifact preview), it says
// so instead of claiming "no findings".
func printSafetyScanner(out io.Writer, p *pb.PendingPermit) {
	if len(p.GetArtifactPreview()) == 0 {
		fmt.Fprintln(out, "  safety scanner not scanned by the executor (artifact bytes not part of the proposal)")
		return
	}
	f := p.GetScannerFindings()
	if len(f) == 0 {
		fmt.Fprintln(out, "  safety scanner no findings")
		return
	}
	fmt.Fprintln(out, "  safety scanner")
	for _, x := range f {
		fmt.Fprintf(out, "    %s at line %d: %s\n",
			displaySafe([]byte(x.GetCategory()), 64), x.GetLine(),
			displaySafe([]byte(x.GetExcerpt()), 160))
	}
}

// printScriptPreview shows the first lines of the artifact the executor
// holds (at most 40 lines / 4 KiB, cut by the executor), as text.
func printScriptPreview(out io.Writer, p *pb.PendingPermit) {
	preview := p.GetArtifactPreview()
	if len(preview) == 0 {
		return
	}
	fmt.Fprintln(out, "  script (first 40 lines)")
	for _, line := range strings.Split(string(preview), "\n") {
		if line == "" {
			continue
		}
		fmt.Fprintf(out, "    %s\n", displaySafe([]byte(line), 4096))
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// displaySafe renders bytes for a terminal. The approval screen passes the
// full parameter size limit so nothing is ever cut off; canonical JSON sorts
// keys, so truncation would let a proposer hide trailing members.: printable runes as they are,
// everything else (control characters, C1 codes such as CSI, invalid UTF-8)
// escaped, so that crafted parameters cannot rewrite the approval screen.
func displaySafe(b []byte, limit int) string {
	var sb strings.Builder
	for i, r := range string(b) {
		if i >= limit {
			sb.WriteString(fmt.Sprintf(" ... [%d more bytes]", len(b)-i))
			break
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func shortRisk(r pb.RiskClass) string {
	return strings.TrimPrefix(r.String(), "RISK_CLASS_")
}
