// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// readGrantUsage is the usage line of the read-grant subcommand.
const readGrantUsage = "usage: nebula read-grant pending | approve <64-hex digest>"

// readGrantCmd reviews and approves read grants (ADR 0007, E06) on the
// executor host:
//
//	nebula read-grant pending
//	nebula read-grant approve <digest>   (hardened mode; full 64-hex digest)
//
// Everything shown comes from the executor, never from the web UI. Approval
// needs the complete digest: a read grant is standing authority over many
// hosts, so a prefix is not enough.
func readGrantCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, in io.Reader, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "pending":
		return readGrantPending(ctx, c, out)
	case len(args) == 2 && args[0] == "approve":
		return readGrantApprove(ctx, c, args[1], in, out)
	}
	return errors.New(readGrantUsage)
}

func readGrantPending(ctx context.Context, c pb.ExecutorServiceClient, out io.Writer) error {
	r, err := c.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		return readGrantRPCError("list pending read grants", err)
	}
	if len(r.GetGrants()) == 0 {
		fmt.Fprintln(out, "no pending read grants")
		return nil
	}
	for _, g := range r.GetGrants() {
		digest := displaySafe([]byte(g.GetGrantDigest()), 64)
		approveBy := time.Unix(g.GetApprovalExpiryUnix(), 0).Format(time.RFC3339)
		doc, err := decodeReadGrantDoc(g.GetCanonicalGrant())
		if err != nil {
			fmt.Fprintf(out, "%s  unreadable grant document (cannot be approved here)  approve by %s\n", digest, approveBy)
			continue
		}
		fmt.Fprintf(out, "%s  %s  %d hosts  %d actions  expires %s  approve by %s\n",
			digest, readGrantScope(doc), readGrantHostCount(doc), len(doc.Actions),
			time.Unix(doc.ExpiryUnix, 0).Format(time.RFC3339), approveBy)
	}
	return nil
}

func readGrantApprove(ctx context.Context, c pb.ExecutorServiceClient, digest string, in io.Reader, out io.Writer) error {
	if !canonical.ValidSHA256Hex(digest) {
		return errors.New("give the complete digest: 64 lowercase hexadecimal characters")
	}
	r, err := c.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{})
	if err != nil {
		return readGrantRPCError("list pending read grants", err)
	}
	var match *pb.PendingReadGrant
	for _, g := range r.GetGrants() {
		if g.GetGrantDigest() == digest {
			match = g
			break
		}
	}
	if match == nil {
		return errors.New("no pending read grant with that digest")
	}
	doc, err := decodeReadGrantDoc(match.GetCanonicalGrant())
	if err != nil {
		return errors.New("the executor's grant document cannot be displayed completely; nothing approved")
	}

	printReadGrant(out, match, doc)
	fmt.Fprintln(out, "It lets the server run these read actions on these hosts with these credentials,")
	fmt.Fprintln(out, "at most once per interval and within the budget, until it expires or you revoke it.")
	fmt.Fprint(out, "Type 'yes' to approve: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not approved")
	}
	g, err := c.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: match.GetGrantDigest()})
	if err != nil {
		return readGrantRPCError("approve read grant", err)
	}
	fmt.Fprintf(out, "approved: read grant %s until %s\n", displaySafe([]byte(g.GetGrant().GetGrantId()), 64),
		time.Unix(g.GetGrant().GetExpiryUnix(), 0).Format(time.RFC3339))
	return nil
}

// printReadGrant shows the complete grant as the executor holds it: every
// field of the decoded document (every host with its credential version,
// every action, interval, budget, expiry) and then the complete canonical
// document itself, untruncated. All strings go through displaySafe.
func printReadGrant(out io.Writer, p *pb.PendingReadGrant, doc permit.ReadGrantDoc) {
	s := func(v string) string { return displaySafe([]byte(v), permit.MaxReadGrantDocSize) }
	ts := func(u int64) string { return time.Unix(u, 0).Format(time.RFC3339) }

	fmt.Fprintln(out, "Approve this read grant? (as seen by the executor)")
	fmt.Fprintf(out, "  digest        %s\n", s(p.GetGrantDigest()))
	fmt.Fprintf(out, "  format        %s\n", s(doc.Grant))
	fmt.Fprintf(out, "  id            %s\n", s(doc.ID))
	fmt.Fprintf(out, "  issuer        %s\n", s(doc.Issuer))
	fmt.Fprintf(out, "  trigger       %s\n", s(doc.Trigger))
	fmt.Fprintf(out, "  rate profile  %s\n", s(doc.RateProfile))
	fmt.Fprintf(out, "  created       %s\n", ts(doc.CreatedUnix))
	fmt.Fprintf(out, "  expiry        %s\n", ts(doc.ExpiryUnix))
	fmt.Fprintf(out, "  interval      at most once per %s\n", (time.Duration(doc.MinIntervalS) * time.Second).String())
	fmt.Fprintf(out, "  run budget    %d\n", doc.RunBudget)
	fmt.Fprintf(out, "  approve by    %s\n", ts(p.GetApprovalExpiryUnix()))

	fmt.Fprintf(out, "  actions (%d):\n", len(doc.Actions))
	for _, a := range doc.Actions {
		fmt.Fprintf(out, "    %s @ %s  artifact sha256:%s  parameters sha256:%s\n",
			s(a.ActionID), s(a.ModuleVersion), s(a.ArtifactSHA256), s(a.ParametersHash))
	}

	fmt.Fprintf(out, "  hosts (%d):\n", len(doc.Targets))
	bound := make(map[string]bool, len(doc.Credentials))
	for _, t := range doc.Targets {
		fmt.Fprintf(out, "    %s  host key %s\n", s(t.HostID), s(t.HostKeyFingerprint))
		found := false
		for _, cr := range doc.Credentials {
			if cr.HostID == t.HostID {
				found = true
				bound[cr.HostID] = true
				fmt.Fprintf(out, "      credential %s version %s\n", s(cr.CredentialRef), s(cr.CredentialVersion))
			}
		}
		if !found {
			fmt.Fprintln(out, "      credential (none bound in the document)")
		}
	}
	for _, cr := range doc.Credentials {
		if !bound[cr.HostID] {
			fmt.Fprintf(out, "    credential for a host not in the list: %s  %s version %s\n",
				s(cr.HostID), s(cr.CredentialRef), s(cr.CredentialVersion))
		}
	}

	if len(doc.ProviderTargets) > 0 {
		fmt.Fprintf(out, "  provider remotes (%d):\n", len(doc.ProviderTargets))
		for _, pt := range doc.ProviderTargets {
			fmt.Fprintf(out, "    %s  trust pin %s generation %d  credential version %d\n",
				s(pt.RemoteID), s(pt.TrustPin), pt.TrustGeneration, pt.CredentialVersion)
			fmt.Fprintf(out, "      methods %s\n", s(strings.Join(pt.Methods, ", ")))
			for _, m := range pt.MetricsTargets {
				fmt.Fprintf(out, "      metrics %s %s vmid %d generation %d\n", s(m.Node), s(m.Kind), m.VMID, m.Generation)
			}
		}
	}

	fmt.Fprintln(out, "  canonical grant (complete):")
	fmt.Fprintf(out, "    %s\n", displaySafe(p.GetCanonicalGrant(), permit.MaxReadGrantDocSize))
}

// decodeReadGrantDoc decodes the executor's canonical grant for display. It
// is strict: an unknown member, trailing data or an oversized document is
// refused, so nothing the executor would enforce can be missing from the
// approval screen. (The executor validated the document at proposal.)
func decodeReadGrantDoc(raw []byte) (permit.ReadGrantDoc, error) {
	var doc permit.ReadGrantDoc
	if len(raw) == 0 || len(raw) > permit.MaxReadGrantDocSize {
		return doc, errors.New("read grant document size out of range")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, fmt.Errorf("decode read grant: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return doc, errors.New("decode read grant: trailing data")
	}
	return doc, nil
}

// readGrantScope is the one-word scope of a pending grant for the list.
func readGrantScope(doc permit.ReadGrantDoc) string {
	profile := doc.RateProfile
	if profile == "" {
		profile = "ssh"
	}
	return displaySafe([]byte(profile+"/"+doc.Trigger), 64)
}

// readGrantHostCount counts the frozen SSH hosts plus provider remotes.
func readGrantHostCount(doc permit.ReadGrantDoc) int {
	return len(doc.Targets) + len(doc.ProviderTargets)
}

// readGrantRPCError turns an executor error into a fixed message chosen by
// status code; the executor's own error text is not echoed.
func readGrantRPCError(what string, err error) error {
	var msg string
	switch grpcstatus.Code(err) {
	case codes.NotFound:
		msg = "no such pending read grant (expired or already decided)"
	case codes.PermissionDenied, codes.Unauthenticated:
		msg = "permission denied (run as the executor admin)"
	case codes.FailedPrecondition:
		msg = "the executor refused in its current state (locked, recovery, or not in hardened mode)"
	case codes.InvalidArgument:
		msg = "the executor rejected the request as invalid"
	case codes.ResourceExhausted:
		msg = "the executor's response limit was reached"
	case codes.Unavailable, codes.DeadlineExceeded:
		msg = "the executor is not reachable"
	default:
		msg = "the executor returned an error (" + grpcstatus.Code(err).String() + ")"
	}
	return fmt.Errorf("%s: %s", what, msg)
}
