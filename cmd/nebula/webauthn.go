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

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// WebAuthn credentials (H03). Registration itself happens in the browser;
// the executor host only issues the one-time code and manages the list.

func webauthnCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nebula webauthn code|list|remove")
	}
	switch args[0] {
	case "code":
		return webauthnCode(ctx, c, args[1:], os.Stdout)
	case "list":
		return webauthnList(ctx, c, os.Stdout)
	case "remove":
		return webauthnRemove(ctx, c, args[1:], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown webauthn command %q", args[0])
	}
}

func webauthnCode(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("webauthn code", flag.ContinueOnError)
	user := fs.String("user", "admin", "account name shown by the authenticator")
	label := fs.String("label", "", "label of the new credential, e.g. \"YubiKey 5 blue\"")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: nebula webauthn code [--user NAME] [--label TEXT]")
	}
	resp, err := c.CreateRegistrationCode(ctx, &pb.CreateRegistrationCodeRequest{UserName: *user, Label: *label})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "One-time registration code (valid until %s, single use):\n\n    %s\n\n",
		time.Unix(resp.GetExpiryUnix(), 0).Format("15:04:05"), displaySafe([]byte(resp.GetCode()), 64))
	fmt.Fprintln(w, "Enter it in the Nebula web UI under \"Register security key\" and touch the new key.")
	fmt.Fprintln(w, "If keys are registered already, one of them must confirm the new one.")
	fmt.Fprintln(w, "Then check with `nebula webauthn list` that exactly the expected key was added;")
	fmt.Fprintln(w, "remove anything you do not recognise with `nebula webauthn remove`.")
	return nil
}

func webauthnList(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	resp, err := c.ListWebAuthnCredentials(ctx, &pb.ListWebAuthnCredentialsRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetCredentials()) == 0 {
		fmt.Fprintln(w, "no WebAuthn credentials: create a registration code with `nebula webauthn code`")
		return nil
	}
	for _, cr := range resp.GetCredentials() {
		// The full ID: credential IDs are chosen by the authenticator, so a
		// shortened form could be made to collide with another credential.
		fmt.Fprintf(w, "%s\n    %s  user %s  label %q  by %s\n",
			displaySafe([]byte(cr.GetCredentialId()), 1400), time.Unix(cr.GetCreatedAtUnix(), 0).Format("2006-01-02 15:04"),
			displaySafe([]byte(cr.GetUserName()), 64), displaySafe([]byte(cr.GetLabel()), 200),
			displaySafe([]byte(cr.GetCreatedBy()), 200))
	}
	return nil
}

func webauthnRemove(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	if len(args) != 1 || len(args[0]) < 8 {
		return errors.New("usage: nebula webauthn remove <credential ID, or a unique prefix of at least 8 characters>")
	}
	resp, err := c.ListWebAuthnCredentials(ctx, &pb.ListWebAuthnCredentialsRequest{})
	if err != nil {
		return err
	}
	// An exact ID always wins, so no credential can be shadowed by another
	// whose ID merely starts with it.
	var match *pb.WebAuthnCredential
	for _, cr := range resp.GetCredentials() {
		if cr.GetCredentialId() == args[0] {
			match = cr
		}
	}
	if match == nil {
		for _, cr := range resp.GetCredentials() {
			if strings.HasPrefix(cr.GetCredentialId(), args[0]) {
				if match != nil {
					return errors.New("prefix is ambiguous; give the full ID from `nebula webauthn list`")
				}
				match = cr
			}
		}
	}
	if match == nil {
		return errors.New("no credential with that prefix")
	}
	fmt.Fprintf(w, "Remove credential %s (%s, %q, registered %s by %s)?\n",
		displaySafe([]byte(match.GetCredentialId()), 1400), displaySafe([]byte(match.GetUserName()), 64), displaySafe([]byte(match.GetLabel()), 200),
		time.Unix(match.GetCreatedAtUnix(), 0).Format("2006-01-02 15:04"), displaySafe([]byte(match.GetCreatedBy()), 200))
	fmt.Fprintln(w, "This also locks the executor: the privileged session ends, every permit is revoked")
	fmt.Fprintln(w, "and pending registrations are cancelled.")
	fmt.Fprint(w, "Type 'yes' to remove: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not removed")
	}
	r, err := c.RemoveWebAuthnCredential(ctx, &pb.RemoveWebAuthnCredentialRequest{CredentialId: match.GetCredentialId()})
	if err != nil {
		return err
	}
	if !r.GetRemoved() {
		return errors.New("credential was already gone")
	}
	fmt.Fprintln(w, "removed; executor locked")
	return nil
}
