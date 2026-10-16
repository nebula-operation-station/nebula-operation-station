// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// gateCmd is the hardened gate path: `nebula approve --stage N DIGEST`
// opens stage N of an approved rollout, `nebula approve --skip HOST
// DIGEST` skips a host. What it shows comes from the executor.
func gateCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.Uint("stage", 0, "open this stage")
	skip := fs.String("skip", "", "skip this host")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || (*stage == 0) == (*skip == "") {
		return errors.New("usage: nebula approve --stage N DIGEST | nebula approve --skip HOST DIGEST (full digest)")
	}
	d := fs.Arg(0)
	if _, err := canonical.ParseDigest(d); err != nil {
		return fmt.Errorf("digest: %w", err)
	}
	g := &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: uint32(*stage)}
	what := fmt.Sprintf("Open stage %d", *stage)
	if *skip != "" {
		if !canonical.ValidHostID(*skip) {
			return errors.New("not a valid host ID")
		}
		g = &pb.Gate{Kind: pb.GateKind_GATE_KIND_SKIP_HOST, HostId: *skip}
		what = "Skip host " + *skip
	}
	r, err := c.GetRollout(ctx, &pb.GetRolloutRequest{ExecutionDigest: d})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s of this rollout? (as seen by the executor)\n  digest  %s\n", what, d)
	printRollout(out, r.GetRollout())
	fmt.Fprint(out, "Type 'yes' to approve: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not approved")
	}
	res, err := c.ApproveGateCLI(ctx, &pb.ApproveGateCLIRequest{ExecutionDigest: d, Gate: g})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "approved; stage %d of %d is open\n", res.GetRollout().GetOpenStage(), len(res.GetRollout().GetStages()))
	return nil
}

func printRollout(out io.Writer, r *pb.Rollout) {
	if r.GetAborted() {
		fmt.Fprintln(out, "  ABORTED")
	}
	if r.GetStopped() != "" {
		fmt.Fprintf(out, "  STOPPED: %s\n", displaySafe([]byte(r.GetStopped()), 500))
	}
	for i, st := range r.GetStages() {
		state := "closed"
		switch {
		case st.GetPassed():
			state = "passed"
		case st.GetOpen():
			state = "open"
		}
		p := st.GetStage()
		fmt.Fprintf(out, "  stage %d %-20s %-7s max failed %d, max unreachable %d, continue %s\n", i+1,
			displaySafe([]byte(p.GetName()), 40), state, p.GetMaxFailed(), p.GetMaxUnreachable(), displaySafe([]byte(p.GetContinueMode()), 10))
		outcome := map[string]string{}
		for _, o := range st.GetOutcomes() {
			outcome[o.GetHostId()] = o.GetOutcome()
		}
		for _, h := range p.GetHostIds() {
			o := outcome[h]
			if o == "" {
				o = "-"
			}
			fmt.Fprintf(out, "    %-32s %s\n", displaySafe([]byte(h), 64), displaySafe([]byte(o), 20))
		}
	}
}
