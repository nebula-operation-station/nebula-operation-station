// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// prompter asks for a secret without echo.
type prompter func(prompt string) ([]byte, error)

// ttyPrompter reads from /dev/tty so that secrets never come from argv
// or a pipe by accident.
func ttyPrompter(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("this needs a terminal: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return b, err
}

const vaultUsage = `usage: nebula vault init | status
       nebula secret set ID   (value from the terminal, or from stdin if stdin is not a terminal)
       nebula secret list
       nebula secret rm ID`

func vaultStateText(s pb.VaultState) string {
	switch s {
	case pb.VaultState_VAULT_STATE_NOT_INITIALIZED:
		return "not initialized"
	case pb.VaultState_VAULT_STATE_LOCKED:
		return "locked"
	case pb.VaultState_VAULT_STATE_UNLOCKED:
		return "unlocked"
	}
	return "unknown"
}

// unlockWith implements `nebula unlock` (spec 06, one unlock): the
// passphrase is tried on the SSH keys and the vault; only a part it does
// not fit is asked for again, once.
func unlockWith(ctx context.Context, c pb.ExecutorServiceClient, ask prompter, w io.Writer) error {
	pass, err := ask("Executor passphrase: ")
	if err != nil {
		return err
	}
	resp, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: pass})
	clear(pass)
	if err != nil {
		return err
	}
	if !resp.GetKeysUnlocked() && resp.GetKeysWrongPassphrase() {
		p, err := ask("SSH key passphrase (the first one did not fit): ")
		if err != nil {
			return err
		}
		r, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: p, Scope: pb.UnlockScope_UNLOCK_SCOPE_KEYS})
		clear(p)
		if err != nil {
			return fmt.Errorf("SSH keys: %w", err)
		}
		resp.KeysUnlocked, resp.LoadedCredentialRefs, resp.KeysError = r.GetKeysUnlocked(), r.GetLoadedCredentialRefs(), r.GetKeysError()
	}
	if resp.GetVaultWrongPassphrase() {
		p, err := ask("Vault passphrase (the first one did not fit): ")
		if err != nil {
			return err
		}
		r, err := c.Unlock(ctx, &pb.UnlockRequest{Passphrase: p, Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT})
		clear(p)
		if err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		resp.VaultState = r.GetVaultState()
	}
	if resp.GetKeysUnlocked() {
		fmt.Fprintf(w, "keys:  unlocked (%s)\n", strings.Join(resp.GetLoadedCredentialRefs(), ", "))
	} else {
		fmt.Fprintf(w, "keys:  locked (%s)\n", displaySafe([]byte(resp.GetKeysError()), 200))
	}
	fmt.Fprintf(w, "vault: %s\n", vaultStateText(resp.GetVaultState()))
	return nil
}

func vaultCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, ask prompter, w io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "init":
		p1, err := ask("New vault passphrase (at least 32 characters, generated): ")
		if err != nil {
			return err
		}
		defer clear(p1)
		p2, err := ask("Repeat: ")
		if err != nil {
			return err
		}
		defer clear(p2)
		if !bytes.Equal(p1, p2) {
			return errors.New("the passphrases differ")
		}
		if _, err := c.InitVault(ctx, &pb.InitVaultRequest{Passphrase: p1}); err != nil {
			return err
		}
		fmt.Fprintln(w, "vault initialized and unlocked.")
		fmt.Fprintln(w, "Tip: use the same generated passphrase as for the SSH keys, then `nebula unlock` asks only once.")
		return nil
	case len(args) == 1 && args[0] == "status":
		s, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "vault: %s\n", vaultStateText(s.GetVaultState()))
		return nil
	}
	return errors.New(vaultUsage)
}

// readSecretValue reads a value from stdin when it is a pipe or file
// (one trailing newline is removed) and otherwise asks without echo.
func readSecretValue(stdin *os.File, ask prompter) ([]byte, error) {
	if fi, err := stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		return readValue(stdin)
	}
	return ask("Secret value: ")
}

func readValue(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10+2))
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b, nil
}

func secretCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, value func() ([]byte, error), stdin io.Reader, w io.Writer) error {
	switch {
	case len(args) == 2 && args[0] == "set":
		v, err := value()
		if err != nil {
			return err
		}
		defer clear(v)
		r, err := c.SetSecret(ctx, &pb.SetSecretRequest{Id: args[1], Value: v})
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "secret %s stored (version %d)\n", args[1], r.GetVersion())
		return nil
	case len(args) == 1 && args[0] == "list":
		r, err := c.ListSecrets(ctx, &pb.ListSecretsRequest{})
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "vault: %s\n", vaultStateText(r.GetVaultState()))
		if len(r.GetSecrets()) == 0 {
			fmt.Fprintln(w, "no secrets")
			return nil
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tVERSION\tUPDATED\tBY")
		for _, s := range r.GetSecrets() {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", displaySafe([]byte(s.GetId()), 64), s.GetVersion(),
				time.Unix(s.GetUpdatedAtUnix(), 0).Format(time.RFC3339), displaySafe([]byte(s.GetUpdatedBy()), 200))
		}
		return tw.Flush()
	case len(args) == 2 && args[0] == "rm":
		fmt.Fprintf(w, "Type 'yes' to delete secret %s: ", displaySafe([]byte(args[1]), 64))
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("not deleted")
		}
		if _, err := c.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: args[1]}); err != nil {
			return err
		}
		fmt.Fprintf(w, "secret %s deleted\n", displaySafe([]byte(args[1]), 64))
		return nil
	}
	return errors.New(vaultUsage)
}
