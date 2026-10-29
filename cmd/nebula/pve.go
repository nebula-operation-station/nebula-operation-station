// SPDX-License-Identifier: AGPL-3.0-or-later

// PVE remote credential custody (ADR 0006, P1-06).
//
// Commands use the peer-credential-authenticated executor socket. The
// executor owns the database, vault, network probes and token validation.
package main

import (
	"bufio"
	"context"
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
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const maxPveConfirmationBytes = 64

const pveUsage = `usage: nebula pve remote add <id> --kind cluster|standalone --endpoint host:port [--endpoint host:port ...] [--name NAME] [--action-token]
       nebula pve remote rotate-token <id> --purpose read|action
       nebula pve remote remove <id>
       nebula pve remote repin <id>
       nebula pve remote list

Runs as a configured local admin through NEBULA_EXECUTOR_SOCKET.
Unlock the executor vault with nebula unlock first. Tokens are
asked without echo; the trust fingerprint must be typed back after
out-of-band comparison. List is metadata only.`

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

	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Probe without credentials and show the presented chain.
	res, err := c.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: string(kindVal), Endpoints: pveProtoEndpoints(eps)})
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "presented trust identities (compare out of band):")
	for _, ep := range res.Endpoints {
		fmt.Fprintf(w, "  %s:%d  leaf %s\n", ep.Host, ep.Port, ep.LeafFingerprint)
		if ep.CaFingerprint != "" {
			fmt.Fprintf(w, "  %s:%d  ca   %s\n", ep.Host, ep.Port, ep.CaFingerprint)
		}
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
		ConfirmedPin: confirmed, ReadToken: readToken, ActionToken: actionToken,
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
	res, err := c.ProbePVERemote(ctx, &pb.ProbePVERemoteRequest{Kind: stored.Kind, Endpoints: stored.Endpoints})
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "presented trust identities (compare out of band):")
	for _, ep := range res.Endpoints {
		fmt.Fprintf(w, "  %s:%d  leaf %s\n", ep.Host, ep.Port, ep.LeafFingerprint)
		if ep.CaFingerprint != "" {
			fmt.Fprintf(w, "  %s:%d  ca   %s\n", ep.Host, ep.Port, ep.CaFingerprint)
		}
	}

	oldPin, err := pveAskLine(stdin, "Type the current pin from the registry: ", "current pin")
	if err != nil {
		return err
	}
	newConfirmed, err := pveAskLine(stdin, "Type the new trust fingerprint to confirm: ", "fingerprint")
	if err != nil {
		return err
	}
	proposed, err := c.ProposePVERepin(ctx, &pb.ProposePVERepinRequest{RemoteId: id, OldPin: oldPin, ConfirmedNewPin: newConfirmed})
	if err != nil {
		return err
	}
	proposal := proposed.GetPermit()
	if err := approve(ctx, c, proposal.GetExecutionDigest(), stdin, w); err != nil {
		return err
	}
	response, err := c.CommitPVERepin(ctx, &pb.CommitPVERepinRequest{RemoteId: id, OldPin: oldPin, ConfirmedNewPin: newConfirmed, ExecutionDigest: proposal.GetExecutionDigest()})
	if err != nil {
		return err
	}
	rm := response.GetRemote()
	fmt.Fprintf(w, "remote %s re-pinned to generation %d (new pin %s…)\n", rm.RemoteId, rm.TrustGeneration, prefix64(rm.TrustPin))
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
	fmt.Fprintln(tw, "ID\tKIND\tSTATE\tPIN (GEN)\tENDPOINTS\tREAD CREDENTIAL\tUPDATED")
	for _, r := range remotes {
		eps := make([]string, 0, len(r.Endpoints))
		for _, ep := range r.Endpoints {
			eps = append(eps, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
		}
		cred := fmt.Sprintf("%s@%d", r.ReadRef, r.ReadVersion)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s (gen %d)\t%s\t%s\t%s\n",
			r.RemoteId, r.Kind, r.State, prefix64(r.TrustPin), r.TrustGeneration,
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
