// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Module signers (M7-5, spec 10). Adding a signer is CRITICAL: every
// module it signs runs at its declared risk, so the fingerprint must be
// typed in full after comparing it with the author's.

func signerCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: nebula signer add --name NAME FILE | list | remove SHA256:FINGERPRINT")
	}
	switch args[0] {
	case "add":
		return signerAdd(ctx, c, args[1:], stdin, w)
	case "list":
		r, err := c.ListSigners(ctx, &pb.ListSignersRequest{})
		if err != nil {
			return err
		}
		if len(r.GetSigners()) == 0 {
			fmt.Fprintln(w, "no trusted signers")
		}
		for _, s := range r.GetSigners() {
			fmt.Fprintf(w, "%s  %s  added %s by %s\n", s.GetFingerprint(), displaySafe([]byte(s.GetName()), 100),
				time.Unix(s.GetAddedUnix(), 0).UTC().Format(time.RFC3339), displaySafe([]byte(s.GetAddedBy()), 64))
		}
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: nebula signer remove SHA256:FINGERPRINT")
		}
		r, err := c.RemoveSigner(ctx, &pb.RemoveSignerRequest{Fingerprint: args[1]})
		if err != nil {
			return err
		}
		if !r.GetRemoved() {
			return errors.New("no such signer")
		}
		fmt.Fprintf(w, "removed; %d trust entries of its modules removed\n", r.GetTrustEntriesRemoved())
		return nil
	default:
		return fmt.Errorf("unknown signer command %q", args[0])
	}
}

func signerAdd(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("signer add", flag.ContinueOnError)
	name := fs.String("name", "", "who the key belongs to, e.g. \"Nebula releases\"")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *name == "" {
		return errors.New("usage: nebula signer add --name NAME FILE (an ssh-ed25519 .pub file)")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return fmt.Errorf("not an SSH public key: %w", err)
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return errors.New("only ssh-ed25519 signing keys are accepted")
	}
	fp := ssh.FingerprintSHA256(key)
	fmt.Fprintln(w, "Trust this module signer on the executor? (CRITICAL)")
	fmt.Fprintf(w, "  key          %s\n", fp)
	fmt.Fprintf(w, "  comment      %s\n", displaySafe([]byte(comment), 100))
	fmt.Fprintf(w, "  name         %s\n", displaySafe([]byte(*name), 100))
	fmt.Fprintln(w, "Every module this key signs will run at its declared risk instead of HIGH.")
	fmt.Fprintln(w, "Compare the fingerprint with the one the author gave you on another channel,")
	fmt.Fprint(w, "then type it in full to confirm: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != fp {
		return errors.New("fingerprint not confirmed; nothing added")
	}
	r, err := c.AddSigner(ctx, &pb.AddSignerRequest{PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), Name: *name})
	if err != nil {
		return err
	}
	if r.GetFingerprint() != fp {
		return fmt.Errorf("executor reported %q, expected %s", r.GetFingerprint(), fp)
	}
	fmt.Fprintf(w, "trusted signer %s\n", fp)
	return nil
}

func moduleCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	if len(args) != 3 || args[0] != "confirm-signer" {
		return errors.New("usage: nebula module confirm-signer MODULE SHA256:FINGERPRINT")
	}
	if _, err := c.ConfirmModuleSigner(ctx, &pb.ConfirmModuleSignerRequest{Module: args[1], Fingerprint: args[2]}); err != nil {
		return err
	}
	fmt.Fprintf(w, "module %s: future versions must be signed by %s\n", args[1], args[2])
	return nil
}
