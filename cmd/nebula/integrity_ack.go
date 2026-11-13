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

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// isOfflineIntegrityCmd says args are `integrity verify ...`, which needs
// no executor; status and ack talk to the local executor socket.
func isOfflineIntegrityCmd(args []string) bool {
	return len(args) > 0 && args[0] == "verify"
}

// integrityExecutorCmd runs `nebula integrity status` and
// `nebula integrity ack FINDING` against the local executor (ADR 0015 D4,
// Q4; spec 06). The executor allows the ack only for the admin UID.
func integrityExecutorCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "status":
		return integrityStatus(ctx, c, out)
	case len(args) == 2 && args[0] == "ack":
		return integrityAck(ctx, c, args[1], in, out)
	default:
		return errors.New(integrityUsage)
	}
}

func integrityStatus(ctx context.Context, c pb.ExecutorServiceClient, out io.Writer) error {
	st, err := c.GetIntegrityStatus(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil {
		return err
	}
	switch {
	case st.GetLocked():
		fmt.Fprintf(out, "integrity: LOCKED since %s: unlock and all mutation and read-grant dispatch are refused\n",
			unixText(st.GetLockedSinceUnix()))
	case !st.GetConfigured():
		fmt.Fprintln(out, "integrity: the periodic I1 check is not configured on this executor")
	default:
		fmt.Fprintln(out, "integrity: no open locking finding")
	}
	if st.GetRunning() {
		fmt.Fprintln(out, "a check is running now")
	}
	if r := st.GetLastRun(); r != nil {
		fmt.Fprintf(out, "last run: %s, %s", unixText(r.GetStartedUnix()), safeText(r.GetState()))
		if !r.GetComplete() {
			fmt.Fprintf(out, " (incomplete: %s; never clean)", safeText(r.GetIncomplete()))
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  release %s, manifest sha256:%s\n", safeText(r.GetReleaseVersion()), safeText(r.GetManifestSha256()))
		fmt.Fprintf(out, "  files %d, different %d, missing %d, extra %d, unreadable %d, locking %d (%d runs total)\n",
			r.GetFiles(), r.GetDifferent(), r.GetMissing(), r.GetExtra(), r.GetUnreadable(), r.GetLocking(), st.GetTotalRuns())
		for _, d := range r.GetDeviations() {
			lock := ""
			if d.GetLocks() {
				lock = "  [locks]"
			}
			fmt.Fprintf(out, "    %-9s %-10s %s%s\n", safeText(d.GetStatus()), safeText(d.GetClass()), safeText(d.GetPath()), lock)
		}
		if n := r.GetDeviationsOmitted(); n > 0 {
			fmt.Fprintf(out, "    ... %d more deviations not listed\n", n)
		}
	} else {
		fmt.Fprintln(out, "last run: none yet")
	}
	if fs := st.GetFindings(); len(fs) > 0 {
		fmt.Fprintf(out, "open findings (%d); clear each with `nebula integrity ack FINDING` after reinstalling or admitting a new signed release:\n", len(fs))
		for _, f := range fs {
			printIntegrityFinding(out, f, "  ")
		}
	}
	fmt.Fprintf(out, "note: %s\n", safeText(st.GetNote()))
	return nil
}

func integrityAck(ctx context.Context, c pb.ExecutorServiceClient, id string, in io.Reader, out io.Writer) error {
	st, err := c.GetIntegrityStatus(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil {
		return err
	}
	var match *pb.IntegrityFinding
	for _, f := range st.GetFindings() {
		if f.GetId() == id {
			match = f
		}
	}
	if match == nil {
		return errors.New("no open integrity finding with this id; see `nebula integrity status`")
	}
	// Everything shown comes from the executor.
	fmt.Fprintln(out, "Acknowledge this integrity finding? (as seen by the executor)")
	printIntegrityFinding(out, match, "  ")
	fmt.Fprintln(out, "This clears only this finding. It deletes, restores and rolls back nothing;")
	fmt.Fprintln(out, "a later check that finds the same deviation locks again. Reinstall or admit")
	fmt.Fprintln(out, "a new signed release first; `nebula integrity verify --offline` from another")
	fmt.Fprintln(out, "machine is the check that does not depend on this machine's software.")
	fmt.Fprintf(out, "note: %s\n", integrity.RootCompromiseNote)
	fmt.Fprint(out, "Type 'yes' to acknowledge: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not acknowledged")
	}
	resp, err := c.AckIntegrityFinding(ctx, &pb.AckIntegrityFindingRequest{FindingId: match.GetId()})
	if err != nil {
		return err
	}
	if resp.GetLocked() {
		fmt.Fprintf(out, "acknowledged %s; %d findings still open, unlock and dispatch stay refused\n",
			safeText(resp.GetFinding().GetId()), resp.GetRemaining())
		return nil
	}
	fmt.Fprintf(out, "acknowledged %s; no open locking finding, `nebula unlock` is possible again\n", safeText(resp.GetFinding().GetId()))
	return nil
}

func printIntegrityFinding(out io.Writer, f *pb.IntegrityFinding, indent string) {
	fmt.Fprintf(out, "%s%s  %s\n", indent, safeText(f.GetId()), safeText(f.GetCause()))
	switch f.GetCause() {
	case "deviation":
		reason := ""
		if f.GetReason() != "" {
			reason = " (" + safeText(f.GetReason()) + ")"
		}
		fmt.Fprintf(out, "%s  %s %s%s: %s\n", indent, safeText(f.GetClass()), safeText(f.GetStatus()), reason, safeText(f.GetPath()))
	case "deviations-omitted":
		fmt.Fprintf(out, "%s  %d further locking deviations not listed individually\n", indent, f.GetCount())
	case "state-unreadable":
		fmt.Fprintf(out, "%s  the stored check state could not be read; an earlier open lock cannot be ruled out\n", indent)
	}
	fmt.Fprintf(out, "%s  first seen %s, last seen %s\n", indent, unixText(f.GetFirstSeenUnix()), unixText(f.GetLastSeenUnix()))
}

func unixText(sec int64) string {
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
