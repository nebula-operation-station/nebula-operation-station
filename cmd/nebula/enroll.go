// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Enrollment helper (spec 08). `nebula host enroll-script` prints a POSIX
// shell script that the admin reviews and runs as root on the new host
// (console or an existing admin login). Nebula never logs in with a
// password: the script installs Nebula's key for a dedicated user,
// restricted to Nebula's addresses, and prints the host key fingerprints
// for `nebula host pin`. The script itself is rendered by
// internal/enrollscript.

const enrollUsage = `usage: nebula host enroll-script --from ADDR[,ADDR...] [--user nebula] [--key nebula-default] [--no-sudo]
ADDR are the IP addresses or CIDR ranges Nebula connects from (they go into
the key's from= option; use IPs, not host names). Without --no-sudo the user
gets NOPASSWD sudo, which is effectively root (spec 08)`

func hostEnrollScript(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("host enroll-script", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	from := fs.String("from", "", "comma-separated IP addresses or CIDR ranges Nebula connects from")
	user := fs.String("user", "nebula", "user to create on the host")
	ref := fs.String("key", "nebula-default", "keyring reference of the key to install")
	noSudo := fs.Bool("no-sudo", false, "do not grant sudo (read-only actions only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *from == "" {
		return errors.New(enrollUsage)
	}
	o := enrollscript.Options{User: *user, KeyRef: *ref, Sudo: !*noSudo}
	if !enrollscript.ValidUser(o.User) {
		return fmt.Errorf("--user %q is not a valid non-root user name", o.User)
	}
	if !enrollscript.ValidKeyRef(o.KeyRef) {
		return fmt.Errorf("--key %q is not a valid keyring reference", o.KeyRef)
	}
	for _, a := range strings.Split(*from, ",") {
		a = strings.TrimSpace(a)
		if !enrollscript.ValidAddress(a) {
			return fmt.Errorf("--from %q is neither an IP address nor a CIDR range", a)
		}
		o.From = append(o.From, a)
	}
	resp, err := c.GetSSHPublicKey(ctx, &pb.GetSSHPublicKeyRequest{CredentialRef: o.KeyRef})
	if err != nil {
		return err
	}
	// The script re-encodes the parsed key: nothing the executor returns
	// besides the key itself reaches the script.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.GetAuthorizedKey()))
	if err != nil {
		return fmt.Errorf("executor returned an unusable key: %w", err)
	}
	o.Key = pub
	script, err := enrollscript.Render(o)
	if err != nil {
		return err
	}
	_, err = w.Write(script)
	return err
}
