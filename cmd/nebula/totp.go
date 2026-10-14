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

// TOTP recovery (M2, spec 05). Set up here, on the executor host; used on
// the web login page when no security key is at hand. A recovery login
// gives a reading session only: privileged work needs a newly registered
// security key first.

const totpUsage = `usage: nebula totp setup [--account LABEL]
       nebula totp status
       nebula totp remove
       nebula totp finish-recovery   (confirm the key registered after a recovery login)`

func totpCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string) error {
	if len(args) == 0 {
		return errors.New(totpUsage)
	}
	switch args[0] {
	case "setup":
		return totpSetup(ctx, c, args[1:], os.Stdin, os.Stdout)
	case "status":
		return totpStatus(ctx, c, os.Stdout)
	case "remove":
		return totpRemove(ctx, c, os.Stdin, os.Stdout)
	case "finish-recovery":
		return totpFinishRecovery(ctx, c, os.Stdin, os.Stdout)
	default:
		return errors.New(totpUsage)
	}
}

func totpSetup(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("totp setup", flag.ContinueOnError)
	fs.SetOutput(w)
	account := fs.String("account", "admin", "label shown in the authenticator app")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(totpUsage)
	}
	b, err := c.BeginTOTPSetup(ctx, &pb.BeginTOTPSetupRequest{Account: *account})
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "New TOTP recovery secret (replaces an earlier one once confirmed).")
	fmt.Fprintln(w, "Add it to an authenticator app that is NOT on the same device as your security key:")
	fmt.Fprintf(w, "\n    secret: %s\n    uri:    %s\n\n", displaySafe([]byte(b.GetSecretBase32()), 64), displaySafe([]byte(b.GetUri()), 400))
	fmt.Fprintln(w, "For a QR code: qrencode -t ansiutf8 '<uri>'. Then clear the terminal.")
	fmt.Fprint(w, "Enter the current 6-digit code from the app: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	code := strings.TrimSpace(line)
	if _, err := c.ConfirmTOTPSetup(ctx, &pb.ConfirmTOTPSetupRequest{Code: code}); err != nil {
		return fmt.Errorf("not activated: %w", err)
	}
	fmt.Fprintln(w, "TOTP recovery is active. A recovery login opens a reading session only;")
	fmt.Fprintln(w, "privileged work then needs a newly registered security key (`nebula webauthn code`).")
	return nil
}

func totpStatus(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	s, err := c.GetTOTPStatus(ctx, &pb.GetTOTPStatusRequest{})
	if err != nil {
		return err
	}
	switch {
	case !s.GetConfigured():
		fmt.Fprintln(w, "TOTP recovery: not set up (`nebula totp setup`)")
	case !s.GetActivated():
		fmt.Fprintln(w, "TOTP recovery: set up but not confirmed (run `nebula totp setup` again)")
	default:
		fmt.Fprintln(w, "TOTP recovery: active")
	}
	if s.GetRecoveryPending() {
		fmt.Fprintf(w, "Recovery pending since %s: register a new security key (`nebula webauthn code`) to allow privileged work again.\n",
			time.Unix(s.GetRecoveryPendingSinceUnix(), 0).Format("2006-01-02 15:04"))
	}
	return nil
}

func totpRemove(ctx context.Context, c pb.ExecutorServiceClient, stdin io.Reader, w io.Writer) error {
	fmt.Fprint(w, "Remove TOTP recovery? Sessions opened with it end. Type 'yes': ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not removed")
	}
	r, err := c.RemoveTOTP(ctx, &pb.RemoveTOTPRequest{})
	if err != nil {
		return err
	}
	if !r.GetRemoved() {
		fmt.Fprintln(w, "TOTP recovery was not set up")
		return nil
	}
	fmt.Fprintln(w, "TOTP recovery removed")
	return nil
}

// totpFinishRecovery ends a pending recovery. The admin picks, on the
// executor host, the credential they registered after the recovery login;
// a compromised server could have registered one of its own with the code
// the admin typed into the browser, so nothing is chosen automatically.
func totpFinishRecovery(ctx context.Context, c pb.ExecutorServiceClient, stdin io.Reader, w io.Writer) error {
	st, err := c.GetTOTPStatus(ctx, &pb.GetTOTPStatusRequest{})
	if err != nil {
		return err
	}
	if !st.GetRecoveryPending() {
		return errors.New("no recovery is pending")
	}
	since := st.GetRecoveryPendingSinceUnix()
	list, err := c.ListWebAuthnCredentials(ctx, &pb.ListWebAuthnCredentialsRequest{})
	if err != nil {
		return err
	}
	var fresh []*pb.WebAuthnCredential
	for _, cr := range list.GetCredentials() {
		if cr.GetCreatedAtUnix() >= since {
			fresh = append(fresh, cr)
		}
	}
	if len(fresh) == 0 {
		return errors.New("no security key was registered since the recovery login; run `nebula webauthn code` and register your new key first")
	}
	fmt.Fprintf(w, "Security keys registered since the recovery login (%s):\n", time.Unix(since, 0).UTC().Format(time.RFC3339))
	for _, cr := range fresh {
		fmt.Fprintf(w, "  %s  label %q  user %s  aaguid %s  at %s\n", displaySafe([]byte(cr.GetCredentialId()), 100),
			displaySafe([]byte(cr.GetLabel()), 64), displaySafe([]byte(cr.GetUserName()), 64), displaySafe([]byte(cr.GetAaguid()), 40),
			time.Unix(cr.GetCreatedAtUnix(), 0).UTC().Format(time.RFC3339))
	}
	if len(fresh) > 1 {
		fmt.Fprintln(w, "More than one key: if one is not yours, the web server may be compromised. Remove it with `nebula webauthn remove ID`.")
	}
	fmt.Fprint(w, "Type the first 8 or more characters of YOUR new key's ID: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	prefix := strings.TrimSpace(line)
	if len(prefix) < 8 {
		return errors.New("type at least 8 characters; nothing changed")
	}
	var match *pb.WebAuthnCredential
	for _, cr := range fresh {
		if strings.HasPrefix(cr.GetCredentialId(), prefix) {
			if match != nil {
				return errors.New("the prefix matches more than one key; type more characters")
			}
			match = cr
		}
	}
	if match == nil {
		return errors.New("no key with that ID; nothing changed")
	}
	if _, err := c.FinishRecovery(ctx, &pb.FinishRecoveryRequest{CredentialId: match.GetCredentialId()}); err != nil {
		return err
	}
	fmt.Fprintln(w, "recovery finished: privileged work is possible again with this key")
	return nil
}
