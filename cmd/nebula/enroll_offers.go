// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// One-step enrollment offers seen from the admin CLI (ADR 0013, EN-13).
// `nebula host offers` lists what ListEnrollOffers returns (never an offer
// ID, salt, script or setup key: the executor does not send them), and
// `nebula host offer-revoke` revokes an offer in any non-final state.
// Both are admin-only: ListEnrollOffers is an admin-role RPC, and
// offer-revoke always lists first, so a non-admin UID (the web server's
// UID may call RevokeEnrollOffer itself) is refused before anything is
// revoked through this CLI.

const offersUsage = `usage: nebula host offers [--json]
       nebula host offer-revoke OFFER
The offers list shows every enrollment offer the executor holds: state, host,
expiry, script SHA-256, the address that downloaded the script, and NetBird
offers that may have left a peer behind (check those in NetBird and delete
them there if the host did not enroll). OFFER is the offer hash from the list
(64 lowercase hex characters, or a unique prefix of at least 8). An offer can
be revoked in every state that is not final, awaiting_approval included.
Both commands need the executor's admin UID.`

const (
	// offerHashLen is the length of a listed offer hash (hex SHA-256).
	offerHashLen = 64
	// minOfferPrefix is the shortest prefix offer-revoke resolves.
	minOfferPrefix = 8
	// Display limits for stored strings shown in the table.
	maxOfferHostDisplay  = 63
	maxOfferAddrDisplay  = 64
	maxOfferStateDisplay = 32
)

// offerFinalStates are the states that cannot be revoked (spec 03).
var offerFinalStates = map[string]bool{"enrolled": true, "expired": true, "revoked": true, "failed": true}

// offerJSON is the --json form of one offer.
type offerJSON struct {
	OfferIDHash    string `json:"offer_id_hash"`
	State          string `json:"state"`
	HostID         string `json:"host_id"`
	SSHUser        string `json:"ssh_user"`
	CredentialRef  string `json:"credential_ref"`
	NetBird        bool   `json:"netbird"`
	Created        string `json:"created"`
	Expires        string `json:"expires"`
	ScriptSHA256   string `json:"script_sha256"`
	Downloaded     string `json:"downloaded,omitempty"`
	ClientAddr     string `json:"client_addr"`
	PeerAddr       string `json:"peer_addr"`
	Probes         int32  `json:"probes"`
	RejectedCodes  int32  `json:"rejected_codes"`
	SetupKeyRecord string `json:"setup_key_record"`
	ShowMismatches int32  `json:"show_mismatches"`
}

// orphanJSON names a NetBird offer that may have left a peer behind.
type orphanJSON struct {
	OfferIDHash string `json:"offer_id_hash"`
	HostID      string `json:"host_id"`
	State       string `json:"state"`
	ClientAddr  string `json:"client_addr"`
	Downloaded  string `json:"downloaded"`
}

// possibleOrphanPeer reports whether a NetBird offer may have left a
// peer in NetBird: its script (which joins NetBird) was downloaded, and
// the offer ended without enrolling the host. The executor does not
// attribute peers here; the operator checks in NetBird.
func possibleOrphanPeer(o *pb.EnrollOfferInfo) bool {
	switch o.GetState() {
	case "failed", "expired", "revoked":
		return o.GetNetbird() && o.GetDownloadedUnix() != 0
	}
	return false
}

func offerTime(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// adminOnly turns the executor's role refusal into a message that names
// the requirement; the gRPC status stays reachable through errors.As.
func adminOnly(cmd string, err error) error {
	if grpcstatus.Code(err) == codes.PermissionDenied {
		return fmt.Errorf("%s needs the executor's admin UID: %w", cmd, err)
	}
	return fmt.Errorf("%s: %w", cmd, err)
}

func hostOffers(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("host offers", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print the offers as one JSON object")
	if err := fs.Parse(args); err != nil {
		return errors.New(offersUsage)
	}
	if fs.NArg() != 0 {
		return errors.New(offersUsage)
	}
	resp, err := c.ListEnrollOffers(ctx, &pb.ListEnrollOffersRequest{})
	if err != nil {
		return adminOnly("host offers", err)
	}
	offers := resp.GetOffers()
	if *asJSON {
		return writeOffersJSON(w, offers)
	}
	if len(offers) == 0 {
		fmt.Fprintln(w, "no enrollment offers")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OFFER\tSTATE\tHOST\tEXPIRES\tSCRIPT SHA-256\tDOWNLOADED FROM")
	var orphans []*pb.EnrollOfferInfo
	for _, o := range offers {
		host := displaySafe([]byte(o.GetHostId()), maxOfferHostDisplay)
		if o.GetNetbird() {
			host += " (netbird)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			displaySafe([]byte(o.GetOfferIdHash()), offerHashLen),
			displaySafe([]byte(o.GetState()), maxOfferStateDisplay),
			host, dashIfEmpty(offerTime(o.GetExpiresUnix())),
			dashIfEmpty(displaySafe([]byte(o.GetScriptSha256()), offerHashLen)),
			downloadAddr(o))
		if possibleOrphanPeer(o) {
			orphans = append(orphans, o)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(orphans) > 0 {
		fmt.Fprintln(w, "\npossible orphan NetBird peers (script downloaded, host not enrolled; check and delete in NetBird):")
		for _, o := range orphans {
			fmt.Fprintf(w, "  %s  %s  %s  downloaded %s from %s\n",
				displaySafe([]byte(o.GetOfferIdHash()), offerHashLen),
				displaySafe([]byte(o.GetHostId()), maxOfferHostDisplay),
				displaySafe([]byte(o.GetState()), maxOfferStateDisplay),
				offerTime(o.GetDownloadedUnix()), downloadAddr(o))
		}
	}
	return nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// downloadAddr is the client address that downloaded the script, with the
// direct peer (a trusted proxy) when it differs.
func downloadAddr(o *pb.EnrollOfferInfo) string {
	client := displaySafe([]byte(o.GetClientAddr()), maxOfferAddrDisplay)
	peer := displaySafe([]byte(o.GetPeerAddr()), maxOfferAddrDisplay)
	switch {
	case client == "" && peer == "":
		return "-"
	case client == "":
		return peer
	case peer == "" || peer == client:
		return client
	}
	return client + " (via " + peer + ")"
}

func writeOffersJSON(w io.Writer, offers []*pb.EnrollOfferInfo) error {
	doc := struct {
		Offers []offerJSON  `json:"offers"`
		Orphan []orphanJSON `json:"possible_orphan_netbird_peers"`
	}{Offers: []offerJSON{}, Orphan: []orphanJSON{}}
	for _, o := range offers {
		doc.Offers = append(doc.Offers, offerJSON{
			OfferIDHash: o.GetOfferIdHash(), State: o.GetState(), HostID: o.GetHostId(),
			SSHUser: o.GetSshUser(), CredentialRef: o.GetCredentialRef(), NetBird: o.GetNetbird(),
			Created: offerTime(o.GetCreatedUnix()), Expires: offerTime(o.GetExpiresUnix()),
			ScriptSHA256: o.GetScriptSha256(), Downloaded: offerTime(o.GetDownloadedUnix()),
			ClientAddr: o.GetClientAddr(), PeerAddr: o.GetPeerAddr(), Probes: o.GetProbes(),
			RejectedCodes: o.GetRejectedCodes(), SetupKeyRecord: o.GetSetupKeyRecord(),
			ShowMismatches: o.GetShowMismatches(),
		})
		if possibleOrphanPeer(o) {
			doc.Orphan = append(doc.Orphan, orphanJSON{OfferIDHash: o.GetOfferIdHash(), HostID: o.GetHostId(),
				State: o.GetState(), ClientAddr: o.GetClientAddr(), Downloaded: offerTime(o.GetDownloadedUnix())})
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// validOfferRef reports whether s is lowercase hex of 8 to 64 characters.
func validOfferRef(s string) bool {
	if len(s) < minOfferPrefix || len(s) > offerHashLen {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func hostOfferRevoke(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New(offersUsage)
	}
	ref := args[0]
	if !validOfferRef(ref) {
		return errors.New("offer-revoke: OFFER must be the offer hash from `nebula host offers` " +
			"(lowercase hex, at least 8 characters)")
	}
	// Listing first is the admin check (ListEnrollOffers is admin-only),
	// resolves a prefix and reports a final state without a revoke call.
	resp, err := c.ListEnrollOffers(ctx, &pb.ListEnrollOffersRequest{})
	if err != nil {
		return adminOnly("host offer-revoke", err)
	}
	var match *pb.EnrollOfferInfo
	for _, o := range resp.GetOffers() {
		if strings.HasPrefix(o.GetOfferIdHash(), ref) {
			if match != nil {
				return errors.New("offer-revoke: the prefix matches more than one offer (ambiguous); give more characters")
			}
			match = o
		}
	}
	hash, from := ref, ""
	switch {
	case match != nil:
		hash, from = match.GetOfferIdHash(), match.GetState()
		if offerFinalStates[from] {
			return fmt.Errorf("offer-revoke: offer %s is already %s; nothing to revoke", hash, displaySafe([]byte(from), maxOfferStateDisplay))
		}
	case len(ref) != offerHashLen:
		return errors.New("offer-revoke: no offer with that prefix")
	}
	// A full hash missing from the list is still sent: the executor is the
	// authority on its offers.
	rr, err := c.RevokeEnrollOffer(ctx, &pb.RevokeEnrollOfferRequest{OfferIdHash: hash})
	if err != nil {
		switch grpcstatus.Code(err) {
		case codes.FailedPrecondition:
			// The offer became final after the list; the executor's
			// message names the state ("offer is already <state>").
			return fmt.Errorf("offer-revoke: offer %s: %s; nothing to revoke", hash,
				displaySafe([]byte(strings.TrimPrefix(grpcstatus.Convert(err).Message(), "revoke enroll offer: ")), 200))
		case codes.NotFound:
			return fmt.Errorf("offer-revoke: no such offer %s", hash)
		}
		return adminOnly("host offer-revoke", err)
	}
	if from != "" {
		fmt.Fprintf(w, "offer %s %s (was %s)\n", hash, displaySafe([]byte(rr.GetState()), maxOfferStateDisplay),
			displaySafe([]byte(from), maxOfferStateDisplay))
	} else {
		fmt.Fprintf(w, "offer %s %s\n", hash, displaySafe([]byte(rr.GetState()), maxOfferStateDisplay))
	}
	return nil
}
