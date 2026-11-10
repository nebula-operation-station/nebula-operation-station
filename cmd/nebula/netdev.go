// SPDX-License-Identifier: AGPL-3.0-or-later

// Network device administration (ADR 0010, ND-11).
//
// Commands use the peer-credential-authenticated executor socket. The
// executor owns the registry, the vault, the credential-free probe and the
// credential validation. A device credential enters only through the
// non-echoing terminal prompter or, when stdin is not a terminal, through
// an explicit --secret-fd; never through argv or the environment, and it is
// never printed.
package main

import (
	"bufio"
	"bytes"
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

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const netdevUsage = `usage: nebula netdev probe --family cbs|panos --endpoint <ip-or-name> [--port N]
       nebula netdev add <device-id> --family cbs|panos --endpoint <ip-or-name> [--port N] [--label TEXT] [--username NAME] [--no-credential] [--secret-fd N]
       nebula netdev credential set <device-id> [--username NAME] [--secret-fd N]
       nebula netdev credential rotate <device-id> [--username NAME] [--secret-fd N]
       nebula netdev repin <device-id>
       nebula netdev block <device-id> [--reason TEXT]
       nebula netdev unblock <device-id>
       nebula netdev remove <device-id>
       nebula netdev list

Runs as a configured local admin through NEBULA_EXECUTOR_SOCKET.
Unlock the executor vault with nebula unlock first.

probe and add contact the device without any credential and show the
family, the endpoint and the presented trust fingerprint (SSH host key
for cbs, TLS certificate for panos). Compare the fingerprint out of band;
add registers the device only after you type "yes". add, repin, unblock
and remove read that "yes" from a terminal on stdin only; a piped "yes"
is refused.

The read credential (CBS password, PAN-OS API key) is asked without echo
on the terminal. It is never accepted as an argument or from the
environment. Alternatively pass --secret-fd N to read it once from an
already open file descriptor N (3 or higher) that is a regular file or a
pipe; anything else is refused before the executor is contacted. The
descriptor is closed after reading.

Examples:
  nebula netdev probe --family cbs --endpoint <switch-ip>
  nebula netdev add <device-id> --family panos --endpoint <firewall-ip> --label <label>
  nebula netdev credential rotate <device-id> --secret-fd 3 3< <file>
  nebula netdev list`

// Limits enforced by this file.
const (
	// maxNetdevSecretBytes bounds a credential read from --secret-fd.
	maxNetdevSecretBytes = 16 << 10
	// maxNetdevConfirmationBytes bounds one typed confirmation line.
	maxNetdevConfirmationBytes = 64
	// maxNetdevFactBytes bounds one untrusted probe fact on screen.
	maxNetdevFactBytes = 256
	// maxNetdevFactNames bounds how many TLS DNS names are shown.
	maxNetdevFactNames = 16
	// minNetdevSecretFD is the lowest descriptor --secret-fd accepts:
	// 0 carries the confirmations, 1 and 2 are output.
	minNetdevSecretFD = 3
)

// Default ports per family (ADR 0010: CBS over SSH, PAN-OS over HTTPS).
const (
	netdevDefaultPortCBS   = 22
	netdevDefaultPortPANOS = 443
)

// RPC budgets. Each one starts after the human steps that precede it, so
// reading a fingerprint, typing "yes", entering the credential or
// approving the permit never consumes the time of the next call.
const (
	// netdevDeviceTimeout bounds one call during which the executor
	// contacts the device (probe, register, credential validation, re-pin).
	netdevDeviceTimeout = 2 * time.Minute
	// netdevRegistryTimeout bounds one registry-only call.
	// It also bounds the permit lookup and, separately, the ApproveCLI
	// call of a re-pin.
	netdevRegistryTimeout = 30 * time.Second
)

// errNetdevNoTerminal is returned when a credential is needed, stdin is
// not a terminal and no --secret-fd was given.
var errNetdevNoTerminal = errors.New("stdin is not a terminal: the credential is asked without echo on a terminal, or pass --secret-fd N")

// errNetdevConfirmNoTerminal is returned when a command needs a typed
// "yes" and stdin is not a terminal: a piped "yes" is never a confirmation.
var errNetdevConfirmNoTerminal = errors.New("stdin is not a terminal: the typed 'yes' must come from a person at a terminal")

// errNetdevSecretFD is returned when --secret-fd does not name an open
// regular file or pipe.
var errNetdevSecretFD = errors.New("--secret-fd must name an open regular file or pipe")

// netdevEnv is everything a netdev command touches outside the process.
type netdevEnv struct {
	// in carries typed confirmations (never a secret).
	in *bufio.Reader
	// stdinIsTerminal tells whether stdin is a terminal.
	stdinIsTerminal bool
	// ask reads a secret without echo.
	ask prompter
	// openFD validates the descriptor named by --secret-fd and takes it
	// over; it runs before the executor is dialled.
	openFD func(fd int) (io.ReadCloser, error)
	// out receives results; prompts go to promptOut.
	out       io.Writer
	promptOut io.Writer
	// dial connects to the executor; the returned func closes it.
	dial func() (pb.ExecutorServiceClient, func(), error)
	// now is the clock the RPC deadlines are computed from.
	now func() time.Time
}

// rpcContext returns a context for one RPC phase, with its deadline taken
// from the injected clock at the moment the phase starts.
func (e netdevEnv) rpcContext(d time.Duration) (context.Context, context.CancelFunc) {
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	return context.WithDeadline(context.Background(), now().Add(d))
}

// netdevOpenSecretFD validates fd before anything else is opened by this
// command and takes it over. Only a regular file or a pipe is accepted: a
// socket, a closed descriptor or a runtime-internal descriptor (epoll,
// eventfd) is refused, so a number the caller did not redirect can never
// resolve to the executor connection or the netpoller.
func netdevOpenSecretFD(fd int) (io.ReadCloser, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("--secret-fd %d: not an open descriptor: %w", fd, errNetdevSecretFD)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFIFO:
	default:
		return nil, fmt.Errorf("--secret-fd %d: %w", fd, errNetdevSecretFD)
	}
	// Anonymous inodes (epoll, eventfd, ...) can report a regular mode.
	if link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil && strings.HasPrefix(link, "anon_inode:") {
		return nil, fmt.Errorf("--secret-fd %d: %w", fd, errNetdevSecretFD)
	}
	f := os.NewFile(uintptr(fd), "secret-fd")
	if f == nil {
		return nil, fmt.Errorf("--secret-fd %d: not an open descriptor: %w", fd, errNetdevSecretFD)
	}
	return f, nil
}

// defaultNetdevEnv is the environment of the real command.
func defaultNetdevEnv() netdevEnv {
	return netdevEnv{
		in:              bufio.NewReader(os.Stdin),
		stdinIsTerminal: term.IsTerminal(int(os.Stdin.Fd())),
		ask:             ttyPrompter,
		openFD:          netdevOpenSecretFD,
		now:             time.Now,
		out:             os.Stdout,
		promptOut:       os.Stderr,
		dial: func() (pb.ExecutorServiceClient, func(), error) {
			conn, err := dialExecutor()
			if err != nil {
				return nil, nil, err
			}
			return pb.NewExecutorServiceClient(conn), func() { _ = conn.Close() }, nil
		},
	}
}

func netdevUsageErr() error { return errors.New(strings.TrimSpace(netdevUsage)) }

// netdevCmd implements `nebula netdev`.
func netdevCmd(args []string, env netdevEnv) error {
	if len(args) == 0 {
		return netdevUsageErr()
	}
	switch args[0] {
	case "probe":
		return netdevProbe(args[1:], env)
	case "add":
		return netdevAdd(args[1:], env)
	case "credential":
		if len(args) < 2 {
			return netdevUsageErr()
		}
		switch args[1] {
		case "set":
			return netdevCredential(args[2:], env, false)
		case "rotate":
			return netdevCredential(args[2:], env, true)
		}
		return netdevUsageErr()
	case "repin":
		return netdevRepin(args[1:], env)
	case "block":
		return netdevBlock(args[1:], env)
	case "unblock":
		return netdevConfirmed(args[1:], env, "unblock")
	case "remove":
		return netdevConfirmed(args[1:], env, "remove")
	case "list":
		return netdevList(args[1:], env)
	}
	return netdevUsageErr()
}

// netdevParse parses flags around one optional leading device id.
func netdevParse(fs *flag.FlagSet, args []string, wantID bool) (string, error) {
	fs.SetOutput(io.Discard)
	id := ""
	flagArgs := args
	if wantID {
		id, flagArgs = pveSplitID(args)
		if id == "" {
			return "", netdevUsageErr()
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return "", fmt.Errorf("%w\n%s", err, strings.TrimSpace(netdevUsage))
	}
	if fs.NArg() != 0 {
		return "", netdevUsageErr()
	}
	return id, nil
}

// netdevTarget holds the probe flags shared by probe and add.
type netdevTarget struct {
	family, endpoint *string
	port             *uint
}

func netdevTargetFlags(fs *flag.FlagSet) netdevTarget {
	return netdevTarget{
		family:   fs.String("family", "", "cbs or panos"),
		endpoint: fs.String("endpoint", "", "private IP literal or host name"),
		port:     fs.Uint("port", 0, "port (default 22 for cbs, 443 for panos)"),
	}
}

func (t netdevTarget) request() (*pb.ProbeNetDeviceRequest, error) {
	var def uint
	switch *t.family {
	case "cbs":
		def = netdevDefaultPortCBS
	case "panos":
		def = netdevDefaultPortPANOS
	default:
		return nil, errors.New("--family must be cbs or panos")
	}
	if *t.endpoint == "" {
		return nil, errors.New("--endpoint is required")
	}
	port := *t.port
	if port == 0 {
		port = def
	}
	if port > 65535 {
		return nil, errors.New("--port must be 1..65535")
	}
	return &pb.ProbeNetDeviceRequest{Family: *t.family, Endpoint: *t.endpoint, Port: uint32(port)}, nil
}

// netdevSecretSource reads the credential: from --secret-fd when given,
// else from the non-echoing terminal prompter; never from a pipe on stdin.
type netdevSecretSource struct {
	fd *int
	// r is the descriptor taken over by check, before any dial.
	r io.ReadCloser
}

func netdevSecretFlag(fs *flag.FlagSet) *netdevSecretSource {
	return &netdevSecretSource{fd: fs.Int("secret-fd", -1, "read the credential once from this open descriptor (3 or higher)")}
}

// check validates the source and, for --secret-fd, takes the descriptor
// over. It must run before the executor is dialled, so that the number
// can only name what the caller redirected. The caller defers close.
func (s *netdevSecretSource) check(env netdevEnv) error {
	if *s.fd == -1 {
		if !env.stdinIsTerminal {
			return errNetdevNoTerminal
		}
		return nil
	}
	if *s.fd < minNetdevSecretFD {
		return fmt.Errorf("--secret-fd must be %d or higher (0 carries the confirmations)", minNetdevSecretFD)
	}
	if s.r != nil {
		return nil
	}
	r, err := env.openFD(*s.fd)
	if err != nil {
		return err
	}
	s.r = r
	return nil
}

// close releases a descriptor that was taken over but not read.
func (s *netdevSecretSource) close() {
	if s.r != nil {
		_ = s.r.Close()
		s.r = nil
	}
}

// read returns the credential; the caller clears it.
func (s *netdevSecretSource) read(env netdevEnv, prompt string) ([]byte, error) {
	if *s.fd == -1 {
		if !env.stdinIsTerminal {
			return nil, errNetdevNoTerminal
		}
		b, err := env.ask(prompt)
		if err != nil {
			clear(b)
			return nil, fmt.Errorf("read credential: %w", err)
		}
		if len(b) == 0 {
			return nil, errors.New("empty credential; nothing stored")
		}
		return b, nil
	}
	r := s.r
	if r == nil {
		return nil, fmt.Errorf("--secret-fd %d: not validated before use", *s.fd)
	}
	s.r = nil
	raw, err := io.ReadAll(io.LimitReader(r, maxNetdevSecretBytes+3))
	cerr := r.Close()
	if err != nil {
		clear(raw)
		return nil, fmt.Errorf("--secret-fd %d: read failed", *s.fd)
	}
	if cerr != nil {
		clear(raw)
		return nil, fmt.Errorf("--secret-fd %d: close failed", *s.fd)
	}
	v := raw
	if c, ok := bytes.CutSuffix(v, []byte("\r\n")); ok {
		v = c
	} else {
		v = bytes.TrimSuffix(v, []byte("\n"))
	}
	if len(v) > maxNetdevSecretBytes {
		clear(raw)
		return nil, fmt.Errorf("--secret-fd %d: credential larger than %d bytes", *s.fd, maxNetdevSecretBytes)
	}
	if len(v) == 0 {
		clear(raw)
		return nil, errors.New("empty credential; nothing stored")
	}
	return v, nil
}

// netdevAskYes asks for a typed "yes"; anything else (also "y" or "YES")
// is a refusal. It is read only from a terminal on stdin.
func netdevAskYes(env netdevEnv, prompt string) (bool, error) {
	if !env.stdinIsTerminal {
		return false, errNetdevConfirmNoTerminal
	}
	fmt.Fprint(env.promptOut, prompt)
	raw, err := env.in.ReadSlice('\n')
	if len(raw) > maxNetdevConfirmationBytes+1 || (err != nil && !errors.Is(err, io.EOF)) {
		return false, errors.New("reading confirmation: exceeds limit or cannot be read")
	}
	if err != nil && len(raw) == 0 {
		return false, fmt.Errorf("reading confirmation: %w", err)
	}
	line := strings.TrimSpace(strings.TrimSuffix(string(raw), "\n"))
	return line == "yes", nil
}

// netdevSafe renders one untrusted or executor-returned field for the
// terminal.
func netdevSafe(v string) string { return displaySafe([]byte(v), maxNetdevFactBytes) }

// netdevShowProbe prints what the device presented. All facts are
// untrusted device output and go through displaySafe.
func netdevShowProbe(w io.Writer, family string, res *pb.ProbeNetDeviceResponse) {
	s := netdevSafe
	fmt.Fprintln(w, "probe (no credential sent; compare the fingerprint out of band):")
	fmt.Fprintf(w, "  family       %s\n", s(family))
	if res.GetResolvedFrom() != "" {
		fmt.Fprintf(w, "  endpoint     %s:%d (resolved from %s)\n", s(res.GetEndpointIp()), res.GetPort(), s(res.GetResolvedFrom()))
	} else {
		fmt.Fprintf(w, "  endpoint     %s:%d\n", s(res.GetEndpointIp()), res.GetPort())
	}
	fmt.Fprintf(w, "  pin kind     %s\n", s(res.GetPinKind()))
	fmt.Fprintf(w, "  fingerprint  sha256:%s\n", s(res.GetObservedPin()))
	f := res.GetFacts()
	if v := f.GetSshServerVersion(); v != "" {
		fmt.Fprintf(w, "  ssh version  %s\n", s(v))
	}
	if v := f.GetSshHostKeyType(); v != "" {
		fmt.Fprintf(w, "  host key     %s\n", s(v))
	}
	if v := f.GetTlsSubject(); v != "" {
		fmt.Fprintf(w, "  tls subject  %s\n", s(v))
	}
	for i, n := range f.GetTlsDnsNames() {
		if i == maxNetdevFactNames {
			fmt.Fprintf(w, "  tls dns      ... [%d more]\n", len(f.GetTlsDnsNames())-i)
			break
		}
		fmt.Fprintf(w, "  tls dns      %s\n", s(n))
	}
	if v := f.GetTlsNotAfterUnix(); v != 0 {
		fmt.Fprintf(w, "  tls expires  %s\n", time.Unix(v, 0).UTC().Format(time.RFC3339))
	}
	if v := f.GetTlsCaFingerprint(); v != "" {
		fmt.Fprintf(w, "  tls ca       sha256:%s\n", s(v))
	}
}

// netdevProbe implements `nebula netdev probe`.
func netdevProbe(args []string, env netdevEnv) error {
	fs := flag.NewFlagSet("netdev probe", flag.ContinueOnError)
	t := netdevTargetFlags(fs)
	if _, err := netdevParse(fs, args, false); err != nil {
		return err
	}
	req, err := t.request()
	if err != nil {
		return err
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := env.rpcContext(netdevDeviceTimeout)
	defer cancel()
	res, err := c.ProbeNetDevice(ctx, req)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	netdevShowProbe(env.out, req.Family, res)
	return nil
}

// netdevAdd implements `nebula netdev add`: probe without a credential,
// show the probe, typed "yes", register, then (unless --no-credential)
// ask for the read credential and store it.
func netdevAdd(args []string, env netdevEnv) error {
	fs := flag.NewFlagSet("netdev add", flag.ContinueOnError)
	t := netdevTargetFlags(fs)
	label := fs.String("label", "", "display name")
	username := fs.String("username", "", "device account name (not a secret)")
	noCred := fs.Bool("no-credential", false, "register only; set the credential later")
	src := netdevSecretFlag(fs)
	id, err := netdevParse(fs, args, true)
	if err != nil {
		return err
	}
	req, err := t.request()
	if err != nil {
		return err
	}
	// Refuse a missing terminal or a bad --secret-fd before contacting
	// anything.
	if !env.stdinIsTerminal {
		return errNetdevConfirmNoTerminal
	}
	if !*noCred {
		if err := src.check(env); err != nil {
			return err
		}
		defer src.close()
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()

	// 1. Probe without credentials and show what was presented.
	pctx, pcancel := env.rpcContext(netdevDeviceTimeout)
	res, err := c.ProbeNetDevice(pctx, req)
	pcancel()
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	netdevShowProbe(env.out, req.Family, res)
	// 2. Typed "yes" after out-of-band comparison.
	ok, err := netdevAskYes(env, fmt.Sprintf("Type 'yes' to register %s with this fingerprint: ", id))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not confirmed; nothing registered")
	}
	// 3. The read credential, never from argv or env; read before the
	// registration so a failed read leaves nothing behind.
	var secret []byte
	if !*noCred {
		if secret, err = src.read(env, "Read credential (not echoed): "); err != nil {
			return fmt.Errorf("nothing registered: %w", err)
		}
		defer clear(secret)
	}
	// 4. Register with the pin the admin confirmed. The budget starts
	// only now, after the human steps.
	rctx, rcancel := env.rpcContext(netdevDeviceTimeout)
	defer rcancel()
	reg, err := c.RegisterNetDevice(rctx, &pb.RegisterNetDeviceRequest{
		DeviceId: id, Family: req.Family, Label: *label, Endpoint: req.Endpoint, Port: req.Port,
		PinKind: res.GetPinKind(), ConfirmedPin: res.GetObservedPin(), Confirm: "yes",
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	d := reg.GetDevice()
	fmt.Fprintf(env.out, "device %s registered: %s %s:%d, pin generation %d\n",
		netdevSafe(d.GetDeviceId()), netdevSafe(d.GetFamily()), netdevSafe(d.GetEndpointIp()), d.GetPort(), d.GetTrustGeneration())
	if *noCred {
		fmt.Fprintf(env.out, "no credential stored; run nebula netdev credential set %s\n", netdevSafe(d.GetDeviceId()))
		return nil
	}
	// 5. Store the credential (the executor validates it against the
	// device first), with its own budget.
	cctx, ccancel := env.rpcContext(netdevDeviceTimeout)
	defer ccancel()
	cr, err := c.SetNetDeviceCredential(cctx, &pb.SetNetDeviceCredentialRequest{DeviceId: id, Username: *username, Secret: secret})
	if err != nil {
		return fmt.Errorf("device registered, credential not stored: %w", err)
	}
	fmt.Fprintf(env.out, "device %s: read credential stored, version %d\n", netdevSafe(cr.GetDevice().GetDeviceId()), cr.GetDevice().GetCredentialVersion())
	return nil
}

// netdevFind returns the live device with id from the registry.
func netdevFind(ctx context.Context, c pb.ExecutorServiceClient, id string) (*pb.NetDeviceInfo, error) {
	res, err := c.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	for _, d := range res.GetDevices() {
		if d.GetDeviceId() == id {
			return d, nil
		}
	}
	return nil, fmt.Errorf("device %s not found", id)
}

// netdevCredential implements `nebula netdev credential set|rotate`.
func netdevCredential(args []string, env netdevEnv, rotate bool) error {
	fs := flag.NewFlagSet("netdev credential", flag.ContinueOnError)
	username := fs.String("username", "", "device account name (not a secret)")
	src := netdevSecretFlag(fs)
	id, err := netdevParse(fs, args, true)
	if err != nil {
		return err
	}
	if err := src.check(env); err != nil {
		return err
	}
	defer src.close()
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	var expected int64
	if rotate {
		lctx, lcancel := env.rpcContext(netdevRegistryTimeout)
		d, err := netdevFind(lctx, c, id)
		lcancel()
		if err != nil {
			return err
		}
		expected = d.GetCredentialVersion()
	}
	secret, err := src.read(env, "Read credential (not echoed): ")
	if err != nil {
		return err
	}
	defer clear(secret)
	// The budget starts after the credential was entered.
	ctx, cancel := env.rpcContext(netdevDeviceTimeout)
	defer cancel()
	if rotate {
		res, err := c.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{
			DeviceId: id, ExpectedCredentialVersion: expected, Username: *username, Secret: secret,
		})
		if err != nil {
			return fmt.Errorf("rotate credential: %w", err)
		}
		d := res.GetDevice()
		fmt.Fprintf(env.out, "device %s: read credential rotated from version %d to %d\n", netdevSafe(d.GetDeviceId()), expected, d.GetCredentialVersion())
		return nil
	}
	res, err := c.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: id, Username: *username, Secret: secret})
	if err != nil {
		return fmt.Errorf("set credential: %w", err)
	}
	d := res.GetDevice()
	fmt.Fprintf(env.out, "device %s: read credential stored, version %d\n", netdevSafe(d.GetDeviceId()), d.GetCredentialVersion())
	return nil
}

// netdevRepin implements `nebula netdev repin`: probe the stored
// endpoint, show the old and the new fingerprint, typed "yes", propose,
// approve the HIGH permit, commit.
func netdevRepin(args []string, env netdevEnv) error {
	fs := flag.NewFlagSet("netdev repin", flag.ContinueOnError)
	id, err := netdevParse(fs, args, true)
	if err != nil {
		return err
	}
	if !env.stdinIsTerminal {
		return errNetdevConfirmNoTerminal
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	lctx, lcancel := env.rpcContext(netdevDeviceTimeout)
	stored, err := netdevFind(lctx, c, id)
	if err != nil {
		lcancel()
		return err
	}
	res, err := c.ProbeNetDevice(lctx, &pb.ProbeNetDeviceRequest{Family: stored.GetFamily(), Endpoint: stored.GetEndpointIp(), Port: stored.GetPort()})
	lcancel()
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	netdevShowProbe(env.out, stored.GetFamily(), res)
	fmt.Fprintf(env.out, "  stored pin   sha256:%s (generation %d)\n", displaySafe([]byte(stored.GetTrustPin()), maxNetdevFactBytes), stored.GetTrustGeneration())
	if res.GetObservedPin() == stored.GetTrustPin() {
		return errors.New("the device presents the stored pin; nothing to re-pin")
	}
	ok, err := netdevAskYes(env, fmt.Sprintf("Type 'yes' to replace the pin of %s with the new fingerprint: ", id))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not confirmed; pin unchanged")
	}
	oldPin, newPin := stored.GetTrustPin(), res.GetObservedPin()
	// Each phase gets its own budget, started after the human step before it.
	pctx, pcancel := env.rpcContext(netdevDeviceTimeout)
	proposed, err := c.ProposeNetDeviceRepin(pctx, &pb.ProposeNetDeviceRepinRequest{DeviceId: id, OldPin: oldPin, ConfirmedNewPin: newPin})
	pcancel()
	if err != nil {
		return fmt.Errorf("propose re-pin: %w", err)
	}
	digest := proposed.GetPermit().GetExecutionDigest()
	// The permit lookup and the ApproveCLI call get separate registry
	// budgets; the second starts only after the typed approval.
	lpctx, lpcancel := env.rpcContext(netdevRegistryTimeout)
	err = approvePhased(lpctx, func() (context.Context, context.CancelFunc) {
		return env.rpcContext(netdevRegistryTimeout)
	}, c, digest, env.in, env.out)
	lpcancel()
	if err != nil {
		return err
	}
	cctx, ccancel := env.rpcContext(netdevDeviceTimeout)
	defer ccancel()
	committed, err := c.CommitNetDeviceRepin(cctx, &pb.CommitNetDeviceRepinRequest{DeviceId: id, OldPin: oldPin, ConfirmedNewPin: newPin, ExecutionDigest: digest})
	if err != nil {
		return fmt.Errorf("commit re-pin: %w", err)
	}
	d := committed.GetDevice()
	fmt.Fprintf(env.out, "device %s re-pinned to generation %d (new pin %s)\n", netdevSafe(d.GetDeviceId()), d.GetTrustGeneration(), prefix64(netdevSafe(d.GetTrustPin())))
	return nil
}

// netdevBlock implements `nebula netdev block`.
func netdevBlock(args []string, env netdevEnv) error {
	fs := flag.NewFlagSet("netdev block", flag.ContinueOnError)
	reason := fs.String("reason", "", "short admin note (no secrets)")
	id, err := netdevParse(fs, args, true)
	if err != nil {
		return err
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := env.rpcContext(netdevRegistryTimeout)
	defer cancel()
	res, err := c.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: id, Reason: *reason})
	if err != nil {
		return fmt.Errorf("block: %w", err)
	}
	fmt.Fprintf(env.out, "device %s blocked\n", netdevSafe(res.GetDevice().GetDeviceId()))
	return nil
}

// netdevConfirmed implements `nebula netdev unblock|remove`, both behind a
// typed "yes".
func netdevConfirmed(args []string, env netdevEnv, op string) error {
	fs := flag.NewFlagSet("netdev "+op, flag.ContinueOnError)
	id, err := netdevParse(fs, args, true)
	if err != nil {
		return err
	}
	if !env.stdinIsTerminal {
		return errNetdevConfirmNoTerminal
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	what := "allow dials to " + id + " again"
	if op == "remove" {
		what = "remove " + id + " (disable, revoke authority, delete its vault entries, tombstone the id)"
	}
	ok, err := netdevAskYes(env, fmt.Sprintf("Type 'yes' to %s: ", what))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("not confirmed; device %s unchanged", id)
	}
	ctx, cancel := env.rpcContext(netdevRegistryTimeout)
	defer cancel()
	if op == "remove" {
		res, err := c.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: id, Confirm: "yes"})
		if err != nil {
			return fmt.Errorf("remove: %w", err)
		}
		fmt.Fprintf(env.out, "device %s removed\n", netdevSafe(res.GetDevice().GetDeviceId()))
		return nil
	}
	res, err := c.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: id, Confirm: "yes"})
	if err != nil {
		return fmt.Errorf("unblock: %w", err)
	}
	fmt.Fprintf(env.out, "device %s unblocked\n", netdevSafe(res.GetDevice().GetDeviceId()))
	return nil
}

// netdevList implements `nebula netdev list` (metadata only).
func netdevList(args []string, env netdevEnv) error {
	fs := flag.NewFlagSet("netdev list", flag.ContinueOnError)
	if _, err := netdevParse(fs, args, false); err != nil {
		return err
	}
	c, done, err := env.dial()
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := env.rpcContext(netdevRegistryTimeout)
	defer cancel()
	res, err := c.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	if len(res.GetDevices()) == 0 {
		fmt.Fprintln(env.out, "no network devices")
		return nil
	}
	s := func(v string) string { return displaySafe([]byte(v), 64) }
	tw := tabwriter.NewWriter(env.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tFAMILY\tLABEL\tENDPOINT\tPIN (GEN)\tSTATE\tCREDENTIAL\tUPDATED")
	for _, d := range res.GetDevices() {
		state := "active"
		if d.GetBlocked() {
			state = "blocked"
			if d.GetBlockReason() != "" {
				state += " (" + s(d.GetBlockReason()) + ")"
			}
		}
		cred := "none"
		switch {
		case d.GetCredentialMissing():
			cred = "missing"
		case d.GetCredentialVersion() > 0:
			cred = "v" + strconv.FormatInt(d.GetCredentialVersion(), 10)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s:%d\t%s %s (gen %d)\t%s\t%s\t%s\n",
			s(d.GetDeviceId()), s(d.GetFamily()), s(d.GetLabel()), s(d.GetEndpointIp()), d.GetPort(),
			s(d.GetPinKind()), prefix64(s(d.GetTrustPin())), d.GetTrustGeneration(), state, cred,
			time.Unix(d.GetUpdatedAtUnix(), 0).UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}
