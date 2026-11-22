// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Device read lease lifetimes in days (ADR 0010 D4).
const (
	// netdevLeaseDefaultDays is the lifetime without --days.
	netdevLeaseDefaultDays = 7
	// netdevLeaseMaxDays is the longest lifetime --days accepts.
	netdevLeaseMaxDays = 30
	// netdevLeaseMaxReadsArg bounds the --reads argument before it is split.
	netdevLeaseMaxReadsArg = 512
)

// netdevLease implements `nebula netdev lease <device-id> --reads R[,R...]
// [--days N]` (A1-5, decisions doc section 5, variant B1).
//
// The admin types exactly one device and the read set. The trust pin, trust
// generation and credential version come from the executor's registry
// (ListNetDevices), never from the command line. The CLI proposes the lease
// over the admin socket (ProposeReadGrant; device leases are admin-only),
// then shows the document as the executor holds it in its pending list
// (ListPendingReadGrants) and approves it through ApproveReadGrantCLI only
// after a typed "yes" from a terminal. Release is the existing
// `nebula read-grant revoke`, re-pin, credential rotation, removal or
// expiry; this verb has no revocation path of its own.
func netdevLease(args []string, env netdevEnv) error {
	// The device id comes first, so a flag value can never be taken for it.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return netdevUsageErr()
	}
	id := args[0]
	fs := flag.NewFlagSet("netdev lease", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	readsArg := fs.String("reads", "", "required: comma-separated typed reads of the device family")
	days := fs.Int("days", netdevLeaseDefaultDays, "lifetime in days (1 to 30)")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(netdevUsage))
	}
	if fs.NArg() != 0 {
		return netdevUsageErr()
	}
	reads, err := netdevLeaseReads(*readsArg)
	if err != nil {
		return err
	}
	if *days < 1 || *days > netdevLeaseMaxDays {
		return fmt.Errorf("--days must be 1 to %d", netdevLeaseMaxDays)
	}
	if !env.stdinIsTerminal {
		return errNetdevConfirmNoTerminal
	}
	req := executor.NetDevLeaseRequest{DeviceID: id, Reads: reads, Lifetime: time.Duration(*days) * 24 * time.Hour}

	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()

	// 1. Build the lease from the executor's registry row and propose it;
	// 2. read it back from the executor's pending list.
	ctx, cancel := env.rpcContext(netdevRegistryTimeout)
	dev, err := netdevFind(ctx, c, id)
	if err != nil {
		cancel()
		return err
	}
	now := time.Now
	if env.now != nil {
		now = env.now
	}
	lease, err := executor.NetDevLeaseFromInfo(dev, req, now())
	if err != nil {
		cancel()
		return fmt.Errorf("lease for %s: %w", netdevSafe(id), err)
	}
	proposed, err := c.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: lease.JSON})
	if err != nil {
		cancel()
		return readGrantRPCError("propose device read lease", err)
	}
	if proposed.GetGrantDigest() != lease.Digest {
		cancel()
		return errors.New("the executor recorded a different lease than the one typed; nothing approved")
	}
	pending, err := c.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{})
	cancel()
	if err != nil {
		return readGrantRPCError("list pending read grants", err)
	}
	var match *pb.PendingReadGrant
	for _, g := range pending.GetGrants() {
		if g.GetGrantDigest() == lease.Digest {
			match = g
			break
		}
	}
	if match == nil {
		return errors.New("the proposed lease is not pending at the executor; nothing approved")
	}
	// The executor's pending document must be byte for byte the lease the
	// admin typed: exactly this device and these reads, nothing else.
	if !bytes.Equal(match.GetCanonicalGrant(), lease.JSON) {
		return errors.New("the executor's pending lease differs from the one typed; nothing approved")
	}
	doc, err := decodeReadGrantDoc(match.GetCanonicalGrant())
	if err != nil {
		return errors.New("the executor's lease document cannot be displayed completely; nothing approved")
	}

	// 3. Preview from the executor and typed "yes".
	printReadGrant(env.out, match, doc)
	fmt.Fprintln(env.out, "It lets the collector run these read-only reads on this one device with this")
	fmt.Fprintln(env.out, "credential version, at most once per interval and within the budget, until it")
	fmt.Fprintln(env.out, "expires, the device is re-pinned, its credential rotated or removed, or you revoke it.")
	ok, err := netdevAskYes(env, fmt.Sprintf("Type 'yes' to approve this read lease for %s: ", netdevSafe(id)))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("not approved; the proposal lapses unapproved at %s",
			time.Unix(match.GetApprovalExpiryUnix(), 0).Format(time.RFC3339))
	}

	// 4. Approve on the executor CLI path; its budget starts after the yes.
	actx, acancel := env.rpcContext(netdevRegistryTimeout)
	defer acancel()
	approved, err := c.ApproveReadGrantCLI(actx, &pb.ApproveReadGrantCLIRequest{GrantDigest: lease.Digest})
	if err != nil {
		return readGrantRPCError("approve device read lease", err)
	}
	g := approved.GetGrant()
	gid := displaySafe([]byte(g.GetGrantId()), 64)
	fmt.Fprintf(env.out, "approved: device read lease %s for %s until %s\n", gid, netdevSafe(id),
		time.Unix(g.GetExpiryUnix(), 0).Format(time.RFC3339))
	fmt.Fprintf(env.out, "revoke with: nebula read-grant revoke %s\n", gid)
	return nil
}

// netdevLeaseReads splits --reads into the typed read names. Every name
// must be one of the closed device read set, listed once; the executor's
// lease builder then checks it against the device family.
func netdevLeaseReads(arg string) ([]string, error) {
	if arg == "" {
		return nil, errors.New("--reads is required: one or more typed reads, comma-separated")
	}
	if len(arg) > netdevLeaseMaxReadsArg {
		return nil, errors.New("--reads is too long")
	}
	parts := strings.Split(arg, ",")
	if len(parts) > len(schedgrant.NetDeviceReads()) {
		return nil, fmt.Errorf("--reads names at most %d reads", len(schedgrant.NetDeviceReads()))
	}
	seen := make(map[string]bool, len(parts))
	for _, r := range parts {
		switch {
		case !schedgrant.IsNetDeviceRead(r):
			return nil, fmt.Errorf("--reads: unknown read %q (known: %s)", netdevSafe(r), strings.Join(schedgrant.NetDeviceReads(), ", "))
		case seen[r]:
			return nil, fmt.Errorf("--reads: %s listed twice", r)
		}
		seen[r] = true
	}
	return parts, nil
}
