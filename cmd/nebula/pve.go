// SPDX-License-Identifier: AGPL-3.0-or-later

// PVE remote credential custody (ADR 0006, P1-06).
//
// Commands use the peer-credential-authenticated executor socket. The
// executor owns the database, vault, network probes and token validation.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const maxPveConfirmationBytes = 64

const pveUsage = `usage: nebula pve remote add <id> --kind cluster|standalone --endpoint host:port [--endpoint host:port ...] [--name NAME] [--action-token] [--ca-file PATH]
       nebula pve remote rotate-token <id> --purpose read|action
       nebula pve remote remove <id>
       nebula pve remote repin <id> [--ca-file PATH]
       nebula pve remote set-site <id> onsite|offsite
       nebula pve remote list

Runs as a configured local admin through NEBULA_EXECUTOR_SOCKET.
Unlock the executor vault with nebula unlock first. Tokens are
asked without echo; the trust fingerprint must be typed back after
out-of-band comparison. List is metadata only. set-site records
where the remote is; a node reboot is refused for an offsite remote
and for one whose site is not set.

--ca-file (cluster only): a default PVE cluster node serves only its
own certificate, not the cluster CA. Copy /etc/pve/pve-root-ca.pem
from a node out of band (scp over a trusted SSH session, or the
console) and pass it here; every node's certificate must chain to it,
and its fingerprint is the one to type back.

If the executor reports the stored cluster CA as missing or unusable,
restore it with repin --ca-file and type the unchanged current pin as
the new fingerprint; pin, generation and grants stay as they are.`

// maxPveCAFileBytes bounds the --ca-file (the executor enforces the same).
const maxPveCAFileBytes = executor.MaxPveCAFileBytes

// readPveCAFile reads and checks a --ca-file: a regular file of at most
// maxPveCAFileBytes holding exactly one currently valid, self-signed CA
// certificate in PEM. It returns the PEM and its SHA-256 fingerprint.
func readPveCAFile(path string, now time.Time) ([]byte, string, error) {
	// Refuse a FIFO, device or directory before opening it: opening a
	// FIFO blocks until a writer appears. The opened file is checked again.
	if st, err := os.Stat(path); err != nil {
		return nil, "", fmt.Errorf("--ca-file: %w", err)
	} else if !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("--ca-file %s: not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("--ca-file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("--ca-file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("--ca-file %s: not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPveCAFileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("--ca-file: %w", err)
	}
	if len(raw) > maxPveCAFileBytes {
		return nil, "", fmt.Errorf("--ca-file %s: larger than %d bytes", path, maxPveCAFileBytes)
	}
	ca, err := executor.ParsePveSuppliedCA(raw, now)
	if err != nil {
		return nil, "", fmt.Errorf("--ca-file %s: %w", path, err)
	}
	fp := pvetransport.Fingerprint(ca)
	return raw, hex.EncodeToString(fp[:]), nil
}

// pveShowProbe prints the presented chain and, with a CA file, its
// fingerprint, and checks that the executor derived exactly that
// fingerprint as the trust identity.
func pveShowProbe(w io.Writer, res *pb.ProbePVERemoteResponse, caPath, caFP string) error {
	fmt.Fprintln(w, "presented trust identities (compare out of band):")
	for _, ep := range res.Endpoints {
		fmt.Fprintf(w, "  %s:%d  leaf %s\n", ep.Host, ep.Port, ep.LeafFingerprint)
		if ep.CaFingerprint != "" {
			fmt.Fprintf(w, "  %s:%d  ca   %s\n", ep.Host, ep.Port, ep.CaFingerprint)
		}
	}
	if caFP == "" {
		return nil
	}
	fmt.Fprintf(w, "cluster CA from --ca-file %s (every leaf chains to it):\n  ca   %s\n", caPath, caFP)
	if res.GetTrustPin() != caFP {
		return errors.New("the executor reported a trust identity other than the --ca-file; nothing stored")
	}
	return nil
}

// pveEndpointsFlag is a repeatable --endpoint host:port flag.
type pveEndpointsFlag []string

func (f *pveEndpointsFlag) String() string { return strings.Join(*f, ",") }
func (f *pveEndpointsFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

// parsePveEndpoint parses one host:port endpoint.
func parsePveEndpoint(s string) (pvecontract.Endpoint, error) {
	host, portStr, err := splitHostPort(s)
	if err != nil {
		return pvecontract.Endpoint{}, fmt.Errorf("endpoint %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return pvecontract.Endpoint{}, fmt.Errorf("endpoint %q: bad port", s)
	}
	return pvecontract.Endpoint{Host: host, Port: uint16(port)}, nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", errors.New("want host:port")
	}
	return s[:i], s[i+1:], nil
}

// pveAskLine reads one confirmation line (not a secret: fingerprints
// were shown on screen) and returns it trimmed.
func pveAskLine(stdin io.Reader, prompt, what string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	br, ok := stdin.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(stdin, maxPveConfirmationBytes+2)
	}
	raw, err := br.ReadSlice('\n')
	if len(raw) > maxPveConfirmationBytes+1 || (err != nil && !errors.Is(err, io.EOF)) {
		return "", fmt.Errorf("reading %s: confirmation exceeds limit or cannot be read", what)
	}
	if err != nil && len(raw) == 0 {
		return "", fmt.Errorf("reading %s: %w", what, err)
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if len(line) > maxPveConfirmationBytes {
		return "", fmt.Errorf("reading %s: confirmation exceeds limit", what)
	}
	return strings.TrimSpace(line), nil
}

func pveCmd(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	if len(args) < 1 || args[0] != "remote" {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	return pveRemoteCmd(args[1:], bufio.NewReaderSize(stdin, maxPveConfirmationBytes+2), ask, w)
}

func pveRemoteCmd(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	switch args[0] {
	case "add":
		return pveRemoteAdd(args[1:], stdin, ask, w)
	case "rotate-token":
		return pveRemoteRotateToken(args[1:], stdin, ask, w)
	case "remove":
		return pveRemoteRemove(args[1:], stdin, ask, w)
	case "repin":
		return pveRemoteRepin(args[1:], stdin, ask, w)
	case "set-site":
		return pveRemoteSetSite(args[1:], stdin, w)
	case "list":
		return pveRemoteList(args[1:], w)
	}
	return errors.New(strings.TrimSpace(pveUsage))
}

// pveSplitID splits the first bare argument (the remote id) from the
// flag arguments: the flag package stops parsing at the first
// non-flag argument, and the id comes first.
func pveSplitID(args []string) (string, []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			rest := make([]string, 0, len(args)-1)
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return a, rest
		}
	}
	return "", args
}

// pveRemoteAdd implements `nebula pve remote add`.
func pveRemoteAdd(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote add", flag.ContinueOnError)
	var endpoints pveEndpointsFlag
	kind := fs.String("kind", "", "cluster or standalone")
	name := fs.String("name", "", "label for the remote")
	withAction := fs.Bool("action-token", false, "also ask for the action-purpose token")
	caFile := fs.String("ca-file", "", "cluster CA (PEM) copied out of band from /etc/pve/pve-root-ca.pem (cluster only)")
	fs.Var(&endpoints, "endpoint", "endpoint host:port (repeatable)")
	id, flagArgs := pveSplitID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if id == "" || fs.NArg() != 0 || len(endpoints) == 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	k := *kind
	var kindVal pvecontract.Kind
	switch k {
	case "cluster":
		kindVal = pvecontract.KindCluster
	case "standalone":
		kindVal = pvecontract.KindStandalone
	default:
		return errors.New("--kind must be cluster or standalone")
	}
	eps := make([]pvecontract.Endpoint, 0, len(endpoints))
	for _, s := range endpoints {
		ep, err := parsePveEndpoint(s)
		if err != nil {
			return err
		}
		eps = append(eps, ep)
	}
	var caPEM []byte
	caFP := ""
	if *caFile != "" {
		if kindVal != pvecontract.KindCluster {
			return errors.New("--ca-file is only for --kind cluster; a standalone remote is pinned to its own certificate")
		}
		var err error
		if caPEM, caFP, err = readPveCAFile(*caFile, time.Now()); err != nil {
			return err
		}
	}

	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Probe without credentials and show the presented chain.
	res, err := c.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: string(kindVal), Endpoints: pveProtoEndpoints(eps), CaPem: caPEM})
	if err != nil {
		return err
	}
	if err := pveShowProbe(w, res, *caFile, caFP); err != nil {
		return err
	}
	pin := res.GetTrustPin()
	// 2. Typed confirmation of the trust-identity fingerprint.
	confirmed, err := pveAskLine(stdin, "Type the trust fingerprint to confirm: ", "fingerprint")
	if err != nil {
		return err
	}
	if confirmed != pin {
		return errors.New("confirmation does not match the presented trust identity; nothing stored")
	}
	// 3. The tokens, asked without echo, never from argv or env.
	readToken, err := ask("PVE API token for read (USER@REALM!TOKENID=VALUE, not echoed): ")
	if err != nil {
		return err
	}
	defer clear(readToken)
	var actionToken []byte
	if *withAction {
		actionToken, err = ask("PVE API token for action (USER@REALM!TOKENID=VALUE, not echoed): ")
		if err != nil {
			return err
		}
		defer clear(actionToken)
	}
	// 4. Validate against the pinned endpoint, store envelope-encrypted.
	response, err := c.AddPVERemote(ctx, &pb.AddPVERemoteRequest{
		RemoteId: id, Name: *name, Kind: string(kindVal), Endpoints: pveProtoEndpoints(eps),
		ConfirmedPin: confirmed, ReadToken: readToken, ActionToken: actionToken, CaPem: caPEM,
	})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	fmt.Fprintf(w, "remote %s added: %s, pin generation %d, read credential %s@%d\n",
		rm.RemoteId, rm.State, rm.TrustGeneration, rm.ReadRef, rm.ReadVersion)
	return nil
}

// pveRemoteRotateToken implements `nebula pve remote rotate-token`.
func pveRemoteRotateToken(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote rotate-token", flag.ContinueOnError)
	purpose := fs.String("purpose", "", "read or action")
	id, flagArgs := pveSplitID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if id == "" || fs.NArg() != 0 || (*purpose != executor.PvePurposeRead && *purpose != executor.PvePurposeAction) {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	token, err := ask("New PVE API token (USER@REALM!TOKENID=VALUE, not echoed): ")
	if err != nil {
		return err
	}
	defer clear(token)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	response, err := c.RotatePVEToken(ctx, &pb.RotatePVETokenRequest{RemoteId: id, Purpose: *purpose, Token: token})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	creds := rm
	ref, ver := creds.ReadRef, creds.ReadVersion
	if *purpose == executor.PvePurposeAction {
		ref, ver = creds.ActionRef, creds.ActionVersion
	}
	fmt.Fprintf(w, "remote %s: %s credential rotated to %s@%d (the old version was kept until the new one was validated)\n",
		rm.RemoteId, *purpose, ref, ver)
	return nil
}

// pveRemoteRemove implements `nebula pve remote remove`.
func pveRemoteRemove(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote remove", flag.ContinueOnError)
	id, flagArgs := pveSplitID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if id == "" || fs.NArg() != 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	line, err := pveAskLine(stdin, fmt.Sprintf("Type 'yes' to remove remote %s (disable, revoke grants, delete vault secrets, tombstone): ", id), "confirmation")
	if err != nil {
		return err
	}
	if line != "yes" {
		return errors.New("not removed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	response, err := c.RemovePVERemote(ctx, &pb.RemovePVERemoteRequest{RemoteId: id})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	fmt.Fprintf(w, "remote %s removed: %s\n", rm.RemoteId, rm.State)
	return nil
}

// pveRemoteRepin implements `nebula pve remote repin`.
func pveRemoteRepin(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote repin", flag.ContinueOnError)
	caFile := fs.String("ca-file", "", "new cluster CA (PEM) copied out of band from /etc/pve/pve-root-ca.pem (cluster only)")
	id, flagArgs := pveSplitID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if id == "" || fs.NArg() != 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	var caPEM []byte
	caFP := ""
	if *caFile != "" {
		var err error
		if caPEM, caFP, err = readPveCAFile(*caFile, time.Now()); err != nil {
			return err
		}
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	metadata, err := c.ListPVEAdminRemotes(ctx, &pb.ListPVEAdminRemotesRequest{})
	if err != nil {
		return err
	}
	var stored *pb.PVEAdminRemote
	for _, remote := range metadata.GetRemotes() {
		if remote.RemoteId == id {
			stored = remote
			break
		}
	}
	if stored == nil || stored.State == "removed" {
		return fmt.Errorf("remote %s not found", id)
	}
	if caPEM != nil && stored.Kind != string(pvecontract.KindCluster) {
		return errors.New("--ca-file is only for a cluster remote; a standalone remote is pinned to its own certificate")
	}
	res, err := c.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: stored.Kind, Endpoints: stored.Endpoints, CaPem: caPEM})
	if err != nil {
		return err
	}
	if err := pveShowProbe(w, res, *caFile, caFP); err != nil {
		return err
	}

	oldPin, err := pveAskLine(stdin, "Type the current pin from the registry: ", "current pin")
	if err != nil {
		return err
	}
	newConfirmed, err := pveAskLine(stdin, "Type the new trust fingerprint to confirm: ", "fingerprint")
	if err != nil {
		return err
	}
	proposed, err := c.ProposePVERepin(ctx, &pb.ProposePVERepinRequest{RemoteId: id, OldPin: oldPin, ConfirmedNewPin: newConfirmed, CaPem: caPEM})
	if err != nil {
		return err
	}
	proposal := proposed.GetPermit()
	if err := approve(ctx, c, proposal.GetExecutionDigest(), stdin, w); err != nil {
		return err
	}
	response, err := c.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: id, OldPin: oldPin, ConfirmedNewPin: newConfirmed, ExecutionDigest: proposal.GetExecutionDigest(), CaPem: caPEM})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	if rm.TrustPin == stored.TrustPin {
		// A re-pin to the unchanged pin only restores the stored cluster CA.
		fmt.Fprintf(w, "remote %s: stored cluster CA restored from --ca-file (pin %s… and generation %d unchanged)\n", rm.RemoteId, prefix64(rm.TrustPin), rm.TrustGeneration)
		return nil
	}
	fmt.Fprintf(w, "remote %s re-pinned to generation %d (new pin %s…)\n", rm.RemoteId, rm.TrustGeneration, prefix64(rm.TrustPin))
	return nil
}

// pveRemoteSetSite implements `nebula pve remote set-site`.
func pveRemoteSetSite(args []string, stdin io.Reader, w io.Writer) error {
	if len(args) != 2 || strings.HasPrefix(args[0], "-") || (args[1] != "onsite" && args[1] != "offsite") {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	id, site := args[0], args[1]
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	line, err := pveAskLine(stdin, fmt.Sprintf("Type 'yes' to record remote %s as %s: ", id, site), "confirmation")
	if err != nil {
		return err
	}
	if line != "yes" {
		return errors.New("site not changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := c.SetPVERemoteSite(ctx, &pb.SetPVERemoteSiteRequest{RemoteId: id, Site: site})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	fmt.Fprintf(w, "remote %s site: %s\n", rm.RemoteId, rm.Site)
	return nil
}

// pveRemoteList implements `nebula pve remote list` (metadata only).
func pveRemoteList(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	metadata, err := c.ListPVEAdminRemotes(ctx, &pb.ListPVEAdminRemotesRequest{})
	remotes := metadata.GetRemotes()
	if err != nil {
		return err
	}
	if len(remotes) == 0 {
		fmt.Fprintln(w, "no pve remotes")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tSITE\tSTATE\tPIN (GEN)\tENDPOINTS\tREAD CREDENTIAL\tUPDATED")
	for _, r := range remotes {
		eps := make([]string, 0, len(r.Endpoints))
		for _, ep := range r.Endpoints {
			eps = append(eps, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
		}
		cred := fmt.Sprintf("%s@%d", r.ReadRef, r.ReadVersion)
		site := r.Site
		if site == "" {
			site = "unset"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s (gen %d)\t%s\t%s\t%s\n",
			r.RemoteId, r.Kind, site, r.State, prefix64(r.TrustPin), r.TrustGeneration,
			strings.Join(eps, " "), cred, time.Unix(r.UpdatedAtUnix, 0).Format(time.RFC3339))
	}
	return tw.Flush()
}

// prefix64 shows the first 16 hex chars of a 64-char fingerprint.
func prefix64(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func pveProtoEndpoints(eps []pvecontract.Endpoint) []*pb.PVEEndpoint {
	out := make([]*pb.PVEEndpoint, 0, len(eps))
	for _, ep := range eps {
		out = append(out, &pb.PVEEndpoint{Host: ep.Host, Port: uint32(ep.Port)})
	}
	return out
}
