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
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// SSH host key enrollment (H05). Pins are made here, on the executor host,
// after the admin compared the fingerprint, never from the web UI.

const hostKeysUsage = `usage: nebula host enroll-script --from ADDR[,ADDR...] [--user nebula] [--key nebula-default] [--no-sudo]
       nebula host probe ENDPOINT...
       nebula host pin [--user nebula] [--key nebula-default] [--known-hosts FILE] HOST ENDPOINT...
       nebula host unpin HOST
       nebula host keys
       nebula host test HOST ENDPOINT...
ENDPOINT is host, host:port or [v6addr]:port, in the order the executor tries them.
Compare a probed fingerprint on the host console with
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub (not with ssh-keyscan, which asks the
same network the probe did)`

func hostProbe(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	if len(args) == 0 {
		return errors.New(hostKeysUsage)
	}
	for _, ep := range args {
		p, err := c.ProbeHostKey(ctx, &pb.ProbeHostKeyRequest{Endpoint: ep})
		if err != nil {
			fmt.Fprintf(w, "%-40s error: %s\n", displaySafe([]byte(ep), 300), displaySafe([]byte(err.Error()), 300))
			continue
		}
		fmt.Fprintf(w, "%-40s %-20s %s\n", displaySafe([]byte(p.GetEndpoint()), 300), displaySafe([]byte(p.GetKeyType()), 40),
			displaySafe([]byte(p.GetFingerprint()), 60))
	}
	return nil
}

func hostPin(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("host pin", flag.ContinueOnError)
	fs.SetOutput(w)
	user := fs.String("user", "nebula", "SSH user on the host")
	keyRef := fs.String("key", "nebula-default", "keyring reference of the key for this host")
	knownHosts := fs.String("known-hosts", "", "take the key from this OpenSSH known_hosts file instead of probing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New(hostKeysUsage)
	}
	host, epArgs := fs.Arg(0), fs.Args()[1:]
	eps := make([]sshtransport.Endpoint, len(epArgs))
	for i, a := range epArgs {
		ep, err := sshtransport.ParseEndpoint(a)
		if err != nil {
			return err
		}
		eps[i] = ep
	}

	var (
		authorized, fp string
		source         pb.HostKeySource
	)
	if *knownHosts != "" {
		data, err := readLimited(*knownHosts, sshtransport.MaxKnownHostsSize)
		if err != nil {
			return err
		}
		m, err := sshtransport.ImportKnownHosts(data, eps)
		if err != nil {
			return err
		}
		authorized = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(m.Key)))
		fp, source = sshtransport.Fingerprint(m.Key), pb.HostKeySource_HOST_KEY_SOURCE_KNOWN_HOSTS
		fmt.Fprintf(w, "%s in %s:\n    %s %s\n", host, displaySafe([]byte(*knownHosts), 300), m.Key.Type(), fp)
		for _, ep := range eps {
			mark := "no entry (must present the same key)"
			for _, got := range m.Endpoints {
				if got == ep {
					mark = "listed"
				}
			}
			fmt.Fprintf(w, "    %-40s %s\n", ep, mark)
		}
		if m.Ignored > 0 {
			fmt.Fprintf(w, "    (%d entries ignored: wildcards, CA keys or weak keys)\n", m.Ignored)
		}
	} else {
		// Every endpoint must present the same key: it is pinned per host.
		for _, ep := range eps {
			p, err := c.ProbeHostKey(ctx, &pb.ProbeHostKeyRequest{Endpoint: ep.String()})
			if err != nil {
				return fmt.Errorf("probe %s: %w", ep, err)
			}
			if fp != "" && p.GetFingerprint() != fp {
				return fmt.Errorf("%s presents %s, %s presented %s: the endpoints are not the same host (or one is intercepted); nothing pinned",
					ep, displaySafe([]byte(p.GetFingerprint()), 60), eps[0], fp)
			}
			authorized, fp = p.GetAuthorizedKey(), p.GetFingerprint()
			fmt.Fprintf(w, "%-40s %-20s %s\n", ep, displaySafe([]byte(p.GetKeyType()), 40), displaySafe([]byte(fp), 60))
		}
		source = pb.HostKeySource_HOST_KEY_SOURCE_PROBE
		fmt.Fprintln(w, "Compare this fingerprint with the output of, on the host's console:")
		fmt.Fprintln(w, "    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub   (or the ecdsa/rsa key of that type)")
	}
	fmt.Fprintf(w, "Pin %s for host %s, log in as %q with key %q? Type 'yes': ", displaySafe([]byte(fp), 60),
		displaySafe([]byte(host), 63), displaySafe([]byte(*user), 32), displaySafe([]byte(*keyRef), 64))
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not pinned")
	}
	r, err := c.PinHostKey(ctx, &pb.PinHostKeyRequest{
		HostId: host, AuthorizedKey: authorized, ExpectedFingerprint: fp,
		SshUser: *user, CredentialRef: *keyRef, Source: source,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "pinned: %s %s\n", displaySafe([]byte(r.GetPin().GetHostId()), 63), displaySafe([]byte(r.GetPin().GetFingerprint()), 60))
	fmt.Fprintf(w, "next: nebula host test %s %s\n", displaySafe([]byte(host), 63), strings.Join(epArgs, " "))
	return nil
}

func readLimited(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}

func findPin(ctx context.Context, c pb.ExecutorServiceClient, host string) (*pb.HostKeyPin, error) {
	resp, err := c.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return nil, err
	}
	for _, p := range resp.GetHosts() {
		if p.GetHostId() == host {
			return p, nil
		}
	}
	return nil, fmt.Errorf("host %s has no pinned key", displaySafe([]byte(host), 63))
}

func hostUnpin(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, w io.Writer) error {
	if len(args) != 1 {
		return errors.New(hostKeysUsage)
	}
	p, err := findPin(ctx, c, args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Remove the pin of %s: %s %s?\n", displaySafe([]byte(p.GetHostId()), 63),
		displaySafe([]byte(p.GetKeyType()), 40), displaySafe([]byte(p.GetFingerprint()), 60))
	if p.GetBlocked() {
		fmt.Fprintf(w, "The host is blocked: %s presented %s on %s.\n", displaySafe([]byte(p.GetBlockedEndpoint()), 300),
			displaySafe([]byte(orNone(p.GetBlockedFingerprint())), 60), time.Unix(p.GetBlockedAtUnix(), 0).Format("2006-01-02 15:04"))
		fmt.Fprintln(w, "Only re-pin after checking the new key on the host's console: a changed key is")
		fmt.Fprintln(w, "either a reinstalled host or someone in between.")
	}
	fmt.Fprintln(w, "The host cannot be reached until it is pinned again.")
	fmt.Fprint(w, "Type 'yes' to remove: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not removed")
	}
	r, err := c.UnpinHostKey(ctx, &pb.UnpinHostKeyRequest{HostId: p.GetHostId(), ExpectedFingerprint: p.GetFingerprint()})
	if err != nil {
		return err
	}
	if !r.GetRemoved() {
		return errors.New("pin was already gone")
	}
	fmt.Fprintln(w, "pin removed")
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "no key of the pinned type"
	}
	return s
}

func hostKeys(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	resp, err := c.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetHosts()) == 0 {
		fmt.Fprintln(w, "no pinned host keys: pin hosts with `nebula host pin`")
		return nil
	}
	for _, p := range resp.GetHosts() {
		state := "ok"
		if p.GetBlocked() {
			state = "BLOCKED: " + displaySafe([]byte(p.GetBlockedEndpoint()), 300) + " presented " +
				displaySafe([]byte(orNone(p.GetBlockedFingerprint())), 60)
		}
		fmt.Fprintf(w, "%-32s %-20s %s\n    %s@ key %s  %s %s by %s  %s\n", displaySafe([]byte(p.GetHostId()), 63),
			displaySafe([]byte(p.GetKeyType()), 40), displaySafe([]byte(p.GetFingerprint()), 60),
			displaySafe([]byte(p.GetSshUser()), 32), displaySafe([]byte(p.GetCredentialRef()), 64),
			strings.ToLower(strings.TrimPrefix(p.GetSource().String(), "HOST_KEY_SOURCE_")),
			time.Unix(p.GetPinnedAtUnix(), 0).Format("2006-01-02"), displaySafe([]byte(p.GetPinnedBy()), 64), state)
	}
	return nil
}

func hostTest(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	if len(args) < 2 {
		return errors.New(hostKeysUsage)
	}
	r, err := c.TestConnection(ctx, &pb.TestConnectionRequest{HostId: args[0], Endpoints: args[1:]})
	if err != nil {
		return err
	}
	for _, a := range r.GetAttempts() {
		// Error texts can carry host-supplied strings (algorithm lists).
		fmt.Fprintf(w, "  %-40s %-9s %s\n", displaySafe([]byte(a.GetEndpoint()), 300), displaySafe([]byte(a.GetStage()), 16),
			displaySafe([]byte(a.GetError()), 300))
	}
	if r.GetOk() {
		fmt.Fprintf(w, "ok: connected and authenticated via %s\n", displaySafe([]byte(r.GetEndpoint()), 300))
		return nil
	}
	return fmt.Errorf("%s: %s", displaySafe([]byte(r.GetFailureClass()), 40), displaySafe([]byte(r.GetDetail()), 500))
}
