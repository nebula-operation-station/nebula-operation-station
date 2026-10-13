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
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"net"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
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
  unlock              decrypt the SSH keys into the executor (asks for the passphrase)
  lock                wipe keys, end the privileged session, revoke all permits
  pending             list permits waiting for approval
  approve <digest>    approve a pending permit (hardened path); a unique prefix is enough
  artifact trust --action ID --version X.Y.Z --risk LEVEL [--label TEXT] FILE
                      trust a script for one action; LEVEL becomes its minimum risk
  artifact untrust --action ID --version X.Y.Z SHA256
  artifact list       list trusted artifacts (anything else needs at least HIGH)
  host probe ENDPOINT...
                      show the SSH host key of endpoints (sends no credential)
  host pin [--user U] [--key REF] [--known-hosts FILE] HOST ENDPOINT...
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
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	if cmd == "version" {
		fmt.Println(version.String())
		return nil
	}
	sock := envOr("NEBULA_EXECUTOR_SOCKET", "/run/nebula/executor.sock")
	execUser := envOr("NEBULA_EXECUTOR_USER", "nebula-executor")
	wantUID, err := peercred.LookupUID(execUser)
	if err != nil {
		return fmt.Errorf("executor user %q: %w", execUser, err)
	}
	// Verify who serves the socket before sending anything, the unlock
	// passphrase in particular.
	conn, err := grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, sock, wantUID)
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)),
	)
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
		if len(args) != 1 {
			return errors.New("usage: nebula approve <digest-prefix>")
		}
		return approve(ctx, c, args[0])
	case "artifact":
		return artifactCmd(ctx, c, args)
	case "host":
		return hostCmd(ctx, c, args)
	case "webauthn":
		return webauthnCmd(ctx, c, args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(64)
		return nil
	}
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
	return nil
}

func unlock(ctx context.Context, c pb.ExecutorServiceClient) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unlock needs a terminal: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, "Executor passphrase: ")
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return err
	}
	resp, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: pass})
	clear(pass)
	if err != nil {
		return err
	}
	fmt.Printf("unlocked: %s\n", strings.Join(resp.GetLoadedCredentialRefs(), ", "))
	return nil
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

func approve(ctx context.Context, c pb.ExecutorServiceClient, prefix string) error {
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
	fmt.Println("Approve this execution? (as seen by the executor)")
	fmt.Printf("  digest         %s\n", match.GetExecutionDigest())
	fmt.Printf("  risk           %s\n", shortRisk(r.GetRiskClass()))
	fmt.Printf("  action         %s @ %s\n", r.GetActionId(), r.GetModuleVersion())
	fmt.Printf("  artifact       sha256:%s\n", r.GetArtifactSha256())
	fmt.Printf("  parameters     sha256:%s\n", r.GetParametersHash())
	fmt.Printf("                 %s\n", displaySafe(match.GetCanonicalParameters(), canonical.MaxParametersSize))
	fmt.Printf("  stage plan     sha256:%s\n", r.GetStagePlanHash())
	fmt.Printf("  credentials    %s\n", strings.Join(r.GetCredentialRefs(), ", "))
	fmt.Printf("  permit expiry  %s\n", time.Unix(r.GetExpiryUnix(), 0).Format(time.RFC3339))
	fmt.Printf("  targets (%d):\n", len(r.GetResolvedTargets()))
	for _, t := range r.GetResolvedTargets() {
		fmt.Printf("    %-32s %s\n", t.GetHostId(), t.GetHostKeyFingerprint())
	}

	in := bufio.NewReader(os.Stdin)
	typed := 0
	if r.GetRiskClass() == pb.RiskClass_RISK_CLASS_CRITICAL {
		fmt.Print("CRITICAL: type the number of targets to approve: ")
		line, _ := in.ReadString('\n')
		typed, err = strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return errors.New("not a number; nothing approved")
		}
	} else {
		fmt.Print("Type 'yes' to approve: ")
		line, _ := in.ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not approved")
		}
	}
	if _, err := c.ApproveCLI(ctx, &pb.ApproveCLIRequest{ExecutionDigest: match.GetExecutionDigest(), TypedTargetCount: uint32(typed)}); err != nil {
		return err
	}
	fmt.Println("approved")
	return nil
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
