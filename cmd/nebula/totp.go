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
       nebula totp remove`

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
