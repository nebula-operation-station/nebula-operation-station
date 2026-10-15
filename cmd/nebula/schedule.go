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
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// scheduleCmd manages schedule grants on the executor host:
//
//	nebula schedule pending
//	nebula schedule approve <digest-prefix>   (hardened mode)
//	nebula schedule list
//	nebula schedule revoke <grant-id>
func scheduleCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	const usage = "usage: nebula schedule pending | approve <digest-prefix> | list | revoke <grant-id>"
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch {
	case args[0] == "pending" && len(args) == 1:
		r, err := c.ListPendingScheduleGrants(ctx, &pb.ListPendingScheduleGrantsRequest{})
		if err != nil {
			return err
		}
		if len(r.GetGrants()) == 0 {
			fmt.Fprintln(out, "no pending schedule grants")
		}
		for _, g := range r.GetGrants() {
			fmt.Fprintf(out, "%s  until %s\n  %s\n", g.GetGrantDigest(), time.Unix(g.GetApprovalExpiryUnix(), 0).Format(time.RFC3339),
				displaySafe(g.GetCanonicalGrant(), canonical.MaxParametersSize))
		}
		return nil
	case args[0] == "approve" && len(args) == 2:
		prefix := args[1]
		if len(prefix) < 8 {
			return errors.New("give at least 8 characters of the digest")
		}
		r, err := c.ListPendingScheduleGrants(ctx, &pb.ListPendingScheduleGrantsRequest{})
		if err != nil {
			return err
		}
		var match *pb.PendingScheduleGrant
		for _, g := range r.GetGrants() {
			if strings.HasPrefix(g.GetGrantDigest(), prefix) {
				if match != nil {
					return errors.New("prefix is ambiguous")
				}
				match = g
			}
		}
		if match == nil {
			return errors.New("no pending schedule grant with that prefix")
		}
		fmt.Fprintln(out, "Approve this schedule grant? (as seen by the executor)")
		fmt.Fprintf(out, "  digest  %s\n  grant   %s\n", match.GetGrantDigest(), displaySafe(match.GetCanonicalGrant(), canonical.MaxParametersSize))
		fmt.Fprintln(out, "It lets the server run these actions on these hosts, at most once per interval, until it expires or you revoke it.")
		fmt.Fprint(out, "Type 'yes' to approve: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not approved")
		}
		g, err := c.ApproveScheduleGrantCLI(ctx, &pb.ApproveScheduleGrantCLIRequest{GrantDigest: match.GetGrantDigest()})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "approved: grant %s until %s\n", g.GetGrant().GetGrantId(), time.Unix(g.GetGrant().GetExpiryUnix(), 0).Format(time.RFC3339))
		return nil
	case args[0] == "list" && len(args) == 1:
		r, err := c.ListScheduleGrants(ctx, &pb.ListScheduleGrantsRequest{})
		if err != nil {
			return err
		}
		for _, g := range r.GetGrants() {
			state := "active until " + time.Unix(g.GetExpiryUnix(), 0).Format(time.RFC3339)
			if g.GetRevokedUnix() != 0 {
				state = "revoked " + time.Unix(g.GetRevokedUnix(), 0).Format(time.RFC3339)
			}
			fmt.Fprintf(out, "%s  %s  by %s\n  %s\n", g.GetGrantId(), state, displaySafe([]byte(g.GetApprovedBy()), 200),
				displaySafe(g.GetCanonicalGrant(), canonical.MaxParametersSize))
		}
		return nil
	case args[0] == "revoke" && len(args) == 2:
		if _, err := c.RevokeScheduleGrant(ctx, &pb.RevokeScheduleGrantRequest{GrantId: args[1]}); err != nil {
			return err
		}
		fmt.Fprintln(out, "revoked")
		return nil
	}
	return errors.New(usage)
}
