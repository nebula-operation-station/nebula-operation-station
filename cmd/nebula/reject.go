// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// rejectUsage is the usage line of `nebula reject` (spec 07 v29-07-01).
const rejectUsage = "usage: nebula reject <digest-prefix> [--reason <text>]"

// rejectMinPrefix is the shortest digest prefix that selects a pending permit,
// as for `nebula approve`.
const rejectMinPrefix = 8

// rejectCmd is `nebula reject <digest-prefix> [--reason <text>]`: it rejects
// one pending execution permit or batch plan on the executor host (ADR 0007
// amendment R2, spec 05 and 07 v29-07-01). It runs over the admin socket and
// needs no privileged session and no security key, because rejecting only
// removes authority. It first shows the executor's own view of the proposal,
// as `nebula approve` does, and rejects only after the admin typed 'yes'. The
// executor decides; its refusal is returned unchanged. The reason is
// optional, checked with the executor's own rules, and stays on this host:
// the server records "rejected on the executor host".
func rejectCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	prefix, reason, err := parseRejectArgs(args)
	if err != nil {
		return err
	}
	if len(prefix) < rejectMinPrefix {
		return fmt.Errorf("give at least %d characters of the digest", rejectMinPrefix)
	}
	resp, err := c.ListPending(ctx, &pb.ListPendingRequest{})
	if err != nil {
		return fmt.Errorf("list pending permits: %w", err)
	}
	var match *pb.PendingPermit
	for _, p := range resp.GetPermits() {
		if strings.HasPrefix(p.GetExecutionDigest(), prefix) {
			if match != nil {
				return errors.New("prefix is ambiguous; nothing rejected")
			}
			match = p
		}
	}

	// Everything shown here comes from the executor, not from the web UI.
	var digest, question string
	if match != nil {
		digest = match.GetExecutionDigest()
		printRejectPermit(out, match)
		question = "Type 'yes' to reject: "
	} else {
		// A full digest that is no pending permit may be a pending batch
		// plan, rejected as a whole (spec 07); a prefix never selects one.
		if _, err := canonical.ParseDigest(prefix); err != nil {
			return errors.New("no pending proposal with that prefix")
		}
		v, err := reviewBatch(ctx, c, prefix)
		if err != nil {
			return fmt.Errorf("no pending proposal with that digest, or the executor's view of it cannot be shown: %w", err)
		}
		if v.rev.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
			return fmt.Errorf("batch is not pending (%s); nothing rejected", strings.TrimPrefix(v.rev.GetState().String(), "PERMIT_STATE_"))
		}
		digest = prefix
		fmt.Fprintln(out, "Reject this batch? (as seen by the executor)")
		printBatch(out, v)
		question = fmt.Sprintf("\nReject all %d members of this batch? Type 'yes' to reject: ", len(v.plan.Members))
	}
	if reason != "" {
		fmt.Fprintf(out, "  reason         %s\n", displaySafe([]byte(reason), permit.MaxRejectReasonBytes))
	}
	fmt.Fprintln(out, "  rejecting is final: this digest can then be approved neither here nor in the browser")
	fmt.Fprint(out, question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not rejected")
	}
	if _, err := c.RejectPending(ctx, &pb.RejectPendingRequest{Digest: digest, Reason: reason}); err != nil {
		return fmt.Errorf("reject %s: %w", digest, err)
	}
	fmt.Fprintln(out, "rejected")
	return nil
}

// printRejectPermit shows the executor's view of a pending permit before a
// rejection. All of it is proposer or host data and is escaped.
func printRejectPermit(out io.Writer, p *pb.PendingPermit) {
	r := p.GetRequest()
	fmt.Fprintln(out, "Reject this execution? (as seen by the executor)")
	fmt.Fprintf(out, "  digest         %s\n", safe(p.GetExecutionDigest()))
	fmt.Fprintf(out, "  risk           %s\n", shortRisk(r.GetRiskClass()))
	fmt.Fprintf(out, "  action         %s @ %s\n", safe(r.GetActionId()), safe(r.GetModuleVersion()))
	fmt.Fprintf(out, "  artifact       sha256:%s\n", safe(r.GetArtifactSha256()))
	fmt.Fprintf(out, "  parameters     %s\n", displaySafe(p.GetCanonicalParameters(), canonical.MaxParametersSize))
	fmt.Fprintf(out, "  permit expiry  %s\n", time.Unix(r.GetExpiryUnix(), 0).Format(time.RFC3339))
	fmt.Fprintf(out, "  targets (%d):\n", len(r.GetResolvedTargets()))
	for _, t := range r.GetResolvedTargets() {
		fmt.Fprintf(out, "    %-32s %s\n", displaySafe([]byte(t.GetHostId()), 64), displaySafe([]byte(t.GetHostKeyFingerprint()), 128))
	}
}

// parseRejectArgs reads `<digest-prefix> [--reason <text>]` with the flag
// before or after the digest, and the form --reason=<text>. The reason is
// checked with the executor's own rules (spec 07 "Reason"), so a reason the
// executor would refuse is refused before the confirmation.
func parseRejectArgs(args []string) (prefix, reason string, err error) {
	haveReason := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--reason":
			if i+1 >= len(args) || haveReason {
				return "", "", errors.New(rejectUsage)
			}
			i++
			reason, haveReason = args[i], true
		case strings.HasPrefix(a, "--reason="):
			if haveReason {
				return "", "", errors.New(rejectUsage)
			}
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case strings.HasPrefix(a, "-"):
			return "", "", errors.New(rejectUsage)
		case prefix == "":
			prefix = a
		default:
			return "", "", errors.New(rejectUsage)
		}
	}
	if prefix == "" {
		return "", "", errors.New(rejectUsage)
	}
	if haveReason && reason == "" {
		return "", "", errors.New("--reason needs a text; leave it out for no reason")
	}
	if _, err := permit.ValidateRejectReason(reason); err != nil {
		return "", "", fmt.Errorf("reason: %w", err)
	}
	return prefix, reason, nil
}
