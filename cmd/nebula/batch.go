// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Local batch approval (ADR 0007, E14). Everything shown here comes from the
// executor over its admin socket, never from the web UI; the executor checks
// the configured admin UID from peer credentials on every call.

const batchUsage = "usage: nebula batch review DIGEST | approve DIGEST | stage N DIGEST | skip MEMBER DIGEST (full 64-hex batch digest)"

// maxGateMemberIDBytes bounds a member ID typed for a skip; the executor
// applies the same bound.
const maxGateMemberIDBytes = 256

// batchCmd runs `nebula batch ...`.
func batchCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	if len(args) < 2 {
		return errors.New(batchUsage)
	}
	switch {
	case args[0] == "review" && len(args) == 2:
		return batchReviewCmd(ctx, c, args[1], out)
	case args[0] == "approve" && len(args) == 2:
		return batchApprove(ctx, c, args[1], in, out)
	case args[0] == "stage" && len(args) == 3:
		n, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil || n < 2 || n > canonical.MaxBatchStages {
			return fmt.Errorf("stage must be a number from 2 to %d", canonical.MaxBatchStages)
		}
		return batchGate(ctx, c, args[2], &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: uint32(n)}, in, out)
	case args[0] == "skip" && len(args) == 3:
		id := args[1]
		if id == "" || len(id) > maxGateMemberIDBytes || displaySafe([]byte(id), maxGateMemberIDBytes) != id {
			return errors.New("not a valid member ID")
		}
		return batchGate(ctx, c, args[2], &pb.Gate{Kind: pb.GateKind_GATE_KIND_SKIP_HOST, HostId: id}, in, out)
	}
	return errors.New(batchUsage)
}

// verifiedBatch is the executor's review after the CLI checked that it is
// complete and self-consistent: the canonical bytes hash to the requested
// digest, the typed plan lists the same members in the same order, and every
// member's parameters match its bound parameter hash.
type verifiedBatch struct {
	digest string
	plan   canonical.Batch
	rev    *pb.ReviewBatchResponse
}

// reviewBatch fetches and verifies the executor's complete frozen plan.
func reviewBatch(ctx context.Context, c pb.ExecutorServiceClient, digest string) (verifiedBatch, error) {
	want, err := canonical.ParseDigest(digest)
	if err != nil {
		return verifiedBatch{}, fmt.Errorf("batch digest: %w", err)
	}
	rev, err := c.ReviewBatch(ctx, &pb.ReviewBatchRequest{BatchDigest: digest})
	if err != nil {
		return verifiedBatch{}, err
	}
	plan, _, got, err := canonical.ParseBatch(rev.GetCanonicalBatch(), time.Now())
	if err != nil {
		return verifiedBatch{}, fmt.Errorf("executor plan: %w", err)
	}
	if got != want || rev.GetBatchDigest() != digest {
		return verifiedBatch{}, errors.New("the executor's plan does not match the requested digest; nothing approved")
	}
	n := len(plan.Members)
	typed := rev.GetPlan().GetMembers()
	if len(typed) != n || len(rev.GetMemberParameters()) != n || len(rev.GetMemberFindings()) != n {
		return verifiedBatch{}, errors.New("the executor's view is incomplete; nothing approved")
	}
	for i, m := range plan.Members {
		if typed[i].GetMemberId() != m.MemberID || typed[i].GetExecutionId() != m.Request.ExecutionID {
			return verifiedBatch{}, fmt.Errorf("member %d: typed plan does not match the canonical plan; nothing approved", i+1)
		}
		ph, err := canonical.HashParameters(rev.GetMemberParameters()[i])
		if err != nil || ph != m.Request.ParametersHash {
			return verifiedBatch{}, fmt.Errorf("member %d: parameters do not match their hash; nothing approved", i+1)
		}
	}
	return verifiedBatch{digest: digest, plan: plan, rev: rev}, nil
}

// printBatch shows the complete plan: totals, every member with its exact
// targets, executor risk, version/hash, parameters, credentials and scanner
// findings, then every stage, gate and dependency. Nothing is truncated; all
// proposer and host-author text is escaped.
func printBatch(out io.Writer, v verifiedBatch) {
	p, rev := v.plan, v.rev
	hosts := map[string]struct{}{}
	for _, m := range p.Members {
		for _, t := range m.Request.ResolvedTargets {
			hosts[t.HostID] = struct{}{}
		}
		if pt := m.ProviderTarget; pt != nil {
			hosts[fmt.Sprintf("%s/%s/%d", pt.RemoteID, pt.Node, pt.VMID)] = struct{}{}
		}
	}
	fmt.Fprintln(out, "Batch plan (as seen by the executor)")
	fmt.Fprintf(out, "  digest         %s\n", v.digest)
	fmt.Fprintf(out, "  batch          %s (%s)\n", safe(p.BatchID), safe(p.BatchVersion))
	fmt.Fprintf(out, "  risk           %s (executor)\n", shortRisk(rev.GetRisk()))
	fmt.Fprintf(out, "  state          %s\n", strings.TrimPrefix(rev.GetState().String(), "PERMIT_STATE_"))
	if rev.GetApprovedBy() != "" {
		fmt.Fprintf(out, "  approved by    %s\n", safe(rev.GetApprovedBy()))
	}
	if rev.GetApprovalExpiryUnix() != 0 {
		fmt.Fprintf(out, "  approve before %s\n", time.Unix(rev.GetApprovalExpiryUnix(), 0).Format(time.RFC3339))
	}
	fmt.Fprintf(out, "  runs until     %s\n", time.Unix(p.ExpiryUnix, 0).Format(time.RFC3339))
	fmt.Fprintf(out, "  stage plan     sha256:%s\n", safe(p.StagePlanHash))
	fmt.Fprintf(out, "  totals         %d members, %d stages, %d dependencies, %d hosts\n",
		len(p.Members), len(p.StagePlan.Stages), len(p.StagePlan.Dependencies), len(hosts))
	for i, m := range p.Members {
		r := m.Request
		fmt.Fprintf(out, "\n  member %d/%d  %s\n", i+1, len(p.Members), safe(m.MemberID))
		fmt.Fprintf(out, "    risk         %s (executor)\n", shortRisk(rev.GetPlan().GetMembers()[i].GetRisk()))
		fmt.Fprintf(out, "    action       %s @ %s\n", safe(r.ActionID), safe(r.ModuleVersion))
		fmt.Fprintf(out, "    execution    %s\n", safe(r.ExecutionID))
		fmt.Fprintf(out, "    artifact     sha256:%s\n", safe(r.ArtifactSHA256))
		fmt.Fprintf(out, "    parameters   sha256:%s\n", safe(r.ParametersHash))
		fmt.Fprintf(out, "                 %s\n", displaySafe(rev.GetMemberParameters()[i], canonical.MaxParametersSize))
		creds := make([]string, 0, len(m.CredentialVersions))
		for _, cv := range m.CredentialVersions {
			creds = append(creds, fmt.Sprintf("%s v%d", safe(cv.Reference), cv.Version))
		}
		fmt.Fprintf(out, "    credentials  %s\n", strings.Join(creds, ", "))
		for _, h := range m.PreconditionHashes {
			fmt.Fprintf(out, "    precondition %s\n", safe(h))
		}
		for _, t := range r.ResolvedTargets {
			fmt.Fprintf(out, "    target       %s  %s\n", safe(t.HostID), safe(t.HostKeyFingerprint))
		}
		if pt := m.ProviderTarget; pt != nil {
			fmt.Fprintf(out, "    provider     %s %s node %s vmid %d generation %d pin %s trust generation %d\n",
				safe(pt.RemoteID), safe(pt.Kind), safe(pt.Node), pt.VMID, pt.Generation, safe(pt.Pin), pt.TrustGeneration)
			for _, ep := range pt.APIEndpoints {
				fmt.Fprintf(out, "      endpoint   %s\n", safe(ep))
			}
		}
		if ct := m.Container; ct != nil {
			fmt.Fprintf(out, "    container    %s config %s\n", safe(ct.ContainerID), safe(ct.ConfigurationHash))
			fmt.Fprintf(out, "      image      %s -> %s\n", safe(ct.OldImageDigest), safe(ct.NewImageDigest))
		}
		findings := rev.GetMemberFindings()[i].GetFindings()
		if len(findings) == 0 {
			fmt.Fprintln(out, "    safety scanner no findings")
			continue
		}
		fmt.Fprintln(out, "    safety scanner")
		for _, f := range findings {
			fmt.Fprintf(out, "      %s (%s) at line %d: %s\n", displaySafe([]byte(f.GetCategory()), 64),
				shortRisk(f.GetRisk()), f.GetLine(), displaySafe([]byte(f.GetExcerpt()), 160))
		}
	}
	fmt.Fprintln(out)
	for i, st := range p.StagePlan.Stages {
		fmt.Fprintf(out, "  stage %d/%d %s  gate %s, max failed %d, max unreachable %d, %d members\n", i+1, len(p.StagePlan.Stages),
			safe(st.StageID), safe(st.Gate), st.FailureThreshold, st.UnreachableThreshold, len(st.MemberIDs))
		for _, id := range st.MemberIDs {
			fmt.Fprintf(out, "    %s\n", safe(id))
		}
		for _, h := range st.RequiredPostchecks {
			fmt.Fprintf(out, "    postcheck %s\n", safe(h))
		}
	}
	for _, d := range p.StagePlan.Dependencies {
		deps := make([]string, 0, len(d.DependsOn))
		for _, x := range d.DependsOn {
			deps = append(deps, safe(x))
		}
		fmt.Fprintf(out, "  dependency %s after %s\n", safe(d.MemberID), strings.Join(deps, ", "))
	}
}

// safe escapes one bounded label for the terminal.
func safe(s string) string { return displaySafe([]byte(s), len(s)) }

// batchReviewCmd shows the complete plan and, once approved, its rollout.
func batchReviewCmd(ctx context.Context, c pb.ExecutorServiceClient, digest string, out io.Writer) error {
	v, err := reviewBatch(ctx, c, digest)
	if err != nil {
		return err
	}
	printBatch(out, v)
	if v.rev.GetState() == pb.PermitState_PERMIT_STATE_APPROVED {
		r, err := c.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: digest})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\nRollout: stage %d open, next gate needs %s\n", r.GetRollout().GetOpenStage(),
			strings.TrimPrefix(r.GetRollout().GetGateRequirement().String(), "APPROVAL_REQUIREMENT_"))
		printRollout(out, r.GetRollout())
	}
	return nil
}

// batchApprove is `nebula approve <batch digest>`: show the executor's complete
// frozen plan and scanner findings, then approve the digest with one local
// confirmation. No browser session is involved.
func batchApprove(ctx context.Context, c pb.ExecutorServiceClient, digest string, in io.Reader, out io.Writer) error {
	v, err := reviewBatch(ctx, c, digest)
	if err != nil {
		return err
	}
	switch {
	case v.rev.GetRisk() == pb.RiskClass_RISK_CLASS_CRITICAL:
		return errors.New("a batch with CRITICAL members cannot be approved; approve them separately")
	case v.rev.GetState() != pb.PermitState_PERMIT_STATE_PENDING:
		return fmt.Errorf("batch is not pending (%s); nothing approved", strings.TrimPrefix(v.rev.GetState().String(), "PERMIT_STATE_"))
	}
	printBatch(out, v)
	fmt.Fprintf(out, "\nApprove all %d members of this batch? Type 'yes' to approve: ", len(v.plan.Members))
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not approved")
	}
	res, err := c.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: digest})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "approved by %s; stage gates still need their own approval\n", safe(res.GetApprovedBy()))
	return nil
}

// batchGate opens a stage or skips a member of an approved batch after
// showing the executor's rollout. The executor checks the stage order,
// thresholds, dependencies and the admin UID.
func batchGate(ctx context.Context, c pb.ExecutorServiceClient, digest string, g *pb.Gate, in io.Reader, out io.Writer) error {
	if _, err := canonical.ParseDigest(digest); err != nil {
		return fmt.Errorf("batch digest: %w", err)
	}
	r, err := c.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: digest})
	if err != nil {
		return err
	}
	ro := r.GetRollout()
	what := fmt.Sprintf("Open stage %d", g.GetStage())
	if g.GetKind() == pb.GateKind_GATE_KIND_SKIP_HOST {
		known := false
		for _, st := range ro.GetStages() {
			known = known || slices.Contains(st.GetStage().GetHostIds(), g.GetHostId())
		}
		if !known {
			return errors.New("member is not in this batch")
		}
		what = "Skip member " + g.GetHostId() + " (audited; never satisfies a dependency)"
	} else if int(g.GetStage()) > len(ro.GetStages()) {
		return fmt.Errorf("the batch has %d stages", len(ro.GetStages()))
	}
	fmt.Fprintf(out, "%s of this batch? (as seen by the executor)\n  digest  %s\n", what, digest)
	printRollout(out, ro)
	fmt.Fprint(out, "Type 'yes' to approve: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not approved")
	}
	res, err := c.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: digest, Gate: g})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "approved; stage %d of %d is open\n", res.GetRollout().GetOpenStage(), len(res.GetRollout().GetStages()))
	return nil
}
