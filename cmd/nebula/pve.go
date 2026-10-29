// SPDX-License-Identifier: AGPL-3.0-or-later

// PVE remote credential custody (ADR 0006, P1-06).
//
// These commands run locally against the executor's data directory and
// need its vault unlocked (the passphrase is asked without echo). They
// must be run as the executor user or root, like `nebula backup`.
//
// TODO(p105): once the P1-05 proto is on main, these commands go
// through the executor's admin-only RPCs (peercred-authenticated)
// instead of opening the executor data directly.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const pveUsage = `usage: nebula pve remote add <id> --kind cluster|standalone --endpoint host:port [--endpoint host:port ...] [--name NAME] [--action-token]
       nebula pve remote rotate-token <id> --purpose read|action
       nebula pve remote remove <id>
       nebula pve remote repin <id>
       nebula pve remote list

Runs locally on the executor host (as the executor user or root) against
NEBULA_EXECUTOR_DATA_DIR (default /var/lib/nebula/executor). Tokens are
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

// pveLocalDB opens the executor database from the data directory.
func pveLocalDB() (*executordb.DB, error) {
	dir := envOr("NEBULA_EXECUTOR_DATA_DIR", "/var/lib/nebula/executor")
	db, err := executordb.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("executor data %s: %w", dir, err)
	}
	return db, nil
}

// pveLocalAdmin opens the executor database and, when the vault is
// locked, unlocks it with the passphrase asked without echo. The caller
// closes the returned DB.
func pveLocalAdmin(ask prompter) (*executor.PveAdmin, *executordb.DB, error) {
	db, err := pveLocalDB()
	if err != nil {
		return nil, nil, err
	}
	v := vault.New(db)
	st, err := v.State()
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if st == vault.StateNotInitialized {
		_ = db.Close()
		return nil, nil, errors.New("the executor vault is not initialized (nebula vault init)")
	}
	if st == vault.StateLocked {
		pass, err := ask("Executor vault passphrase: ")
		if err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		defer clear(pass)
		if err := v.Unlock(pass); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
	}
	return &executor.PveAdmin{
		DB:    db,
		Vault: v,
		Now:   time.Now,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db, nil
}

// pveBy is the local admin identity for the change trail.
func pveBy() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "local-admin"
}

// pveAskLine reads one confirmation line (not a secret: fingerprints
// were shown on screen) and returns it trimmed.
func pveAskLine(stdin io.Reader, prompt, what string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading %s: %w", what, err)
	}
	return strings.TrimSpace(line), nil
}

func pveCmd(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	if len(args) < 1 || args[0] != "remote" {
		return errors.New(pveUsage)
	}
	return pveRemoteCmd(args[1:], stdin, ask, w)
}

func pveRemoteCmd(args []string, stdin io.Reader, ask prompter, w io.Writer) error {
	if len(args) == 0 {
		return errors.New(pveUsage)
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
	return errors.New(pveUsage)
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
		return errors.New(pveUsage)
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

	admin, db, err := pveLocalAdmin(ask)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Probe without credentials and show the presented chain.
	res, err := executor.DefaultPveProbe(ctx, eps)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "presented trust identities (compare out of band):")
	for _, ep := range res.Endpoints {
		fmt.Fprintf(w, "  %s:%d  leaf %s\n", ep.Host, ep.Port, ep.LeafFingerprint)
		if ep.CAFingerprint != "" {
			fmt.Fprintf(w, "  %s:%d  ca   %s\n", ep.Host, ep.Port, ep.CAFingerprint)
		}
	}
	pin, _, err := res.TrustIdentity(kindVal)
	if err != nil {
		return err
	}
	// 2. Typed confirmation of the trust-identity fingerprint.
	confirmed, err := pveAskLine(stdin, "Type the trust fingerprint to confirm: ", "fingerprint")
	if err != nil {
		return err
	}
	if confirmed != pin {
		return errors.New("confirmation does not match the presented trust identity; nothing stored")
	}
	// 3. The tokens, asked without echo, never from argv or env.
	readToken, err := ask("PVE API token for read (user!tokenID!value, not echoed): ")
	if err != nil {
		return err
	}
	defer clear(readToken)
	var actionToken []byte
	if *withAction {
		actionToken, err = ask("PVE API token for action (user!tokenID!value, not echoed): ")
		if err != nil {
			return err
		}
		defer clear(actionToken)
	}
	// 4. Validate against the pinned endpoint, store envelope-encrypted.
	rm, err := admin.AddRemote(ctx, executor.PveAddRemote{
		RemoteID:     id,
		Name:         *name,
		Kind:         kindVal,
		Endpoints:    eps,
		ConfirmedPin: confirmed,
		ReadToken:    readToken,
		ActionToken:  actionToken,
		By:           pveBy(),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "remote %s added: %s, pin generation %d, read credential %s@%d\n",
		rm.RemoteID, rm.State, rm.TrustGeneration, rm.Credentials.ReadRef, rm.Credentials.ReadVersion)
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
		return errors.New(pveUsage)
	}
	admin, db, err := pveLocalAdmin(ask)
	if err != nil {
		return err
	}
	defer db.Close()
	token, err := ask("New PVE API token (user!tokenID!value, not echoed): ")
	if err != nil {
		return err
	}
	defer clear(token)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rm, err := admin.RotateToken(ctx, executor.PveRotateToken{
		RemoteID: id, Purpose: *purpose, Token: token, By: pveBy(),
	})
	if err != nil {
		return err
	}
	creds := rm.Credentials
	ref, ver := creds.ReadRef, creds.ReadVersion
	if *purpose == executor.PvePurposeAction {
		ref, ver = creds.ActionRef, creds.ActionVersion
	}
	fmt.Fprintf(w, "remote %s: %s credential rotated to %s@%d (the old version was kept until the new one was validated)\n",
		rm.RemoteID, *purpose, ref, ver)
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
		return errors.New(pveUsage)
	}
	admin, db, err := pveLocalAdmin(ask)
	if err != nil {
		return err
	}
	defer db.Close()
	line, err := pveAskLine(stdin, fmt.Sprintf("Type 'yes' to remove remote %s (disable, revoke grants, delete vault secrets, tombstone): ", id), "confirmation")
	if err != nil {
		return err
	}
	if line != "yes" {
		return errors.New("not removed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rm, err := admin.RemoveRemote(ctx, executor.PveRemove{RemoteID: id, By: pveBy()})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "remote %s removed: %s\n", rm.RemoteID, rm.State)
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
		return errors.New(pveUsage)
	}
	admin, db, err := pveLocalAdmin(ask)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stored, ok, err := db.GetRemote(id)
	if err != nil {
		return err
	}
	if !ok || stored.State == executordb.StateRemoved {
		return fmt.Errorf("remote %s not found", id)
	}
	res, err := executor.DefaultPveProbe(ctx, stored.Endpoints)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "presented trust identities (compare out of band):")
	for _, ep := range res.Endpoints {
		fmt.Fprintf(w, "  %s:%d  leaf %s\n", ep.Host, ep.Port, ep.LeafFingerprint)
		if ep.CAFingerprint != "" {
			fmt.Fprintf(w, "  %s:%d  ca   %s\n", ep.Host, ep.Port, ep.CAFingerprint)
		}
	}
	if _, _, err := res.TrustIdentity(stored.Kind); err != nil {
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
	rm, err := admin.Repin(ctx, executor.PveRepin{
		RemoteID: id, OldPin: oldPin, ConfirmedNewPin: newConfirmed, By: pveBy(),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "remote %s re-pinned to generation %d (new pin %s…)\n", rm.RemoteID, rm.TrustGeneration, prefix64(rm.TrustPin))
	return nil
}

// pveRemoteList implements `nebula pve remote list` (metadata only).
func pveRemoteList(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("pve remote list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(pveUsage)
	}
	db, err := pveLocalDB()
	if err != nil {
		return err
	}
	defer db.Close()
	admin := &executor.PveAdmin{DB: db}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remotes, err := admin.ListRemotes(ctx)
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
		cred := fmt.Sprintf("%s@%d", r.Credentials.ReadRef, r.Credentials.ReadVersion)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s (gen %d)\t%s\t%s\t%s\n",
			r.RemoteID, r.Kind, r.State, prefix64(r.TrustPin), r.TrustGeneration,
			strings.Join(eps, " "), cred, r.UpdatedAt.Format(time.RFC3339))
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
