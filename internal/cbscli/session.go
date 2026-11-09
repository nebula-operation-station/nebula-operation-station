// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cbscli is the executor's CLI session driver for Cisco Business
// (CBS) switches (ADR 0010 D3, ticket ND-05). It speaks SSH through
// internal/sshtransport only (pinned host key, key mismatch and
// authentication failure are hard stops there) and drives one interactive
// shell session per device:
//
//  1. read the login text up to the first recognised EXEC prompt within a
//     bounded deadline; an optional pinned banner digest must match;
//  2. send "terminal datadump" (paging off) and require empty output;
//  3. send commands from the fixed phase-1 read allowlist, at most two per
//     second, each reading to the same prompt under a byte, line and time
//     cap.
//
// Any other prompt (pager, confirmation, in-band login, configuration
// mode, a different host name or privilege) aborts the session; the driver
// never answers one. Everything the device sends is untrusted: output must
// be valid UTF-8 with printable characters, tabs and CR LF line ends only,
// and device text never appears in errors. After any failure the session
// is broken and the transport is closed.
package cbscli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Sentinel errors callers can branch on with errors.Is. Errors from the
// transport keep their sshtransport class (sshtransport.ClassOf).
var (
	// ErrDeviceBusy: a session to the device is already open on this Driver.
	ErrDeviceBusy = errors.New("cbscli: a session to this device is already open")
	// ErrUnexpectedPrompt: the device waits for input the driver never gives.
	ErrUnexpectedPrompt = errors.New("cbscli: unexpected prompt")
	// ErrBannerChanged: the login text differs from the pinned digest.
	ErrBannerChanged = errors.New("cbscli: login banner changed")
	// ErrDatadump: "terminal datadump" was not accepted.
	ErrDatadump = errors.New("cbscli: terminal datadump not accepted")
	// ErrOutputTooLarge: the output is over its byte cap.
	ErrOutputTooLarge = errors.New("cbscli: output over byte cap")
	// ErrLineTooLong: an output line is over MaxLineBytes.
	ErrLineTooLong = errors.New("cbscli: output line too long")
	// ErrTooManyLines: a configuration is over MaxConfigLines.
	ErrTooManyLines = errors.New("cbscli: too many configuration lines")
	// ErrMalformedOutput: invalid UTF-8, control or non-printing characters.
	ErrMalformedOutput = errors.New("cbscli: malformed output")
	// ErrUnexpectedEcho: the device did not echo the command line exactly.
	ErrUnexpectedEcho = errors.New("cbscli: unexpected command echo")
	// ErrTimeout: no prompt within the deadline.
	ErrTimeout = errors.New("cbscli: timeout waiting for prompt")
	// ErrSessionClosed: the device closed the session before the prompt.
	ErrSessionClosed = errors.New("cbscli: session closed by device")
	// ErrSessionBroken: an earlier failure ended the session.
	ErrSessionBroken = errors.New("cbscli: session broken by an earlier failure")
)

// Timing and size limits of ADR 0010 D3. The connect timeout (10 s) is
// sshtransport.ConnectTimeout.
const (
	// PromptTimeout bounds the wait for the first prompt after login.
	PromptTimeout = 10 * time.Second
	// CommandTimeout bounds one command from send to prompt.
	CommandTimeout = 60 * time.Second
	// MinCommandInterval spaces commands: two per second at most.
	MinCommandInterval = 500 * time.Millisecond
	// PromptSettle is how long the device must stay quiet before the last
	// unterminated line is judged as a prompt, so prompt-like text inside
	// streaming output does not end a read early.
	PromptSettle = 250 * time.Millisecond
	// MaxBannerBytes caps the login text before the first prompt.
	MaxBannerBytes = 16 << 10

	datadumpCommand = "terminal datadump"
	readChunkBytes  = 32 << 10
	ptyColumns      = 511
)

// Options tune one session.
type Options struct {
	// ExpectBanner, if set, is the BannerDigest recorded earlier for the
	// device; a session whose login text differs is refused.
	ExpectBanner *[sha256.Size]byte
}

// Driver opens CBS sessions, at most one per device (Target.HostID) at a
// time. The zero value is ready to use.
type Driver struct {
	// Transport dials the device (pinned key, spec 08 policy).
	Transport sshtransport.Config
	// Now is the clock for the command rate limit; nil uses time.Now.
	Now func() time.Time

	mu   sync.Mutex
	open map[string]struct{}

	// Unexported tunables, zero means the package constant. Only tests
	// shorten them.
	promptTimeout  time.Duration
	commandTimeout time.Duration
	settle         time.Duration
	sleep          func(context.Context, time.Duration) error
}

func orDefault(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func (d *Driver) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Driver) wait(ctx context.Context, dur time.Duration) error {
	if d.sleep != nil {
		return d.sleep(ctx, dur)
	}
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (d *Driver) acquire(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, busy := d.open[id]; busy {
		return false
	}
	if d.open == nil {
		d.open = map[string]struct{}{}
	}
	d.open[id] = struct{}{}
	return true
}

func (d *Driver) release(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.open, id)
}

// Session is an open shell on one device with paging disabled. Its methods
// are safe for concurrent use; commands run one at a time.
type Session struct {
	d      *Driver
	hostID string
	client *sshtransport.Client
	sess   *ssh.Session
	stdin  io.Writer
	out    chan []byte
	done   chan struct{}

	prompt string
	banner [sha256.Size]byte

	mu        sync.Mutex
	broken    error
	lastSend  time.Time
	closeOnce sync.Once
}

// Open connects to t with signer, starts a shell, waits for the first
// prompt, checks the banner and disables paging. A host key mismatch or an
// authentication failure is returned with its sshtransport class and no
// other endpoint is tried.
func (d *Driver) Open(ctx context.Context, t sshtransport.Target, signer ssh.Signer, opts Options) (*Session, error) {
	if t.HostID == "" {
		return nil, errors.New("cbscli: open: host ID is required")
	}
	if !d.acquire(t.HostID) {
		return nil, fmt.Errorf("cbscli: open %s: %w", t.HostID, ErrDeviceBusy)
	}
	cl, err := d.Transport.Dial(ctx, t, signer)
	if err != nil {
		d.release(t.HostID)
		return nil, fmt.Errorf("cbscli: open %s: %w", t.HostID, err)
	}
	s := &Session{d: d, hostID: t.HostID, client: cl, done: make(chan struct{})}
	if err := s.start(ctx, opts); err != nil {
		s.Close()
		return nil, fmt.Errorf("cbscli: open %s: %w", t.HostID, err)
	}
	return s, nil
}

func (s *Session) start(ctx context.Context, opts Options) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	s.sess = sess
	modes := ssh.TerminalModes{ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty("vt100", 0, ptyColumns, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout: %w", err)
	}
	s.stdin = stdin
	s.out = make(chan []byte)
	go s.reader(stdout)
	// Stderr stays nil: x/crypto/ssh discards it.
	if err := sess.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	pctx, cancel := context.WithTimeout(ctx, orDefault(s.d.promptTimeout, PromptTimeout))
	defer cancel()
	raw, prompt, err := s.readToPrompt(pctx, "", MaxBannerBytes)
	if err != nil {
		return fmt.Errorf("first prompt: %w", err)
	}
	text, err := normalize(raw)
	if err != nil {
		return fmt.Errorf("banner: %w", err)
	}
	s.banner = sha256.Sum256([]byte(text))
	if opts.ExpectBanner != nil && *opts.ExpectBanner != s.banner {
		return ErrBannerChanged
	}
	s.prompt = prompt

	out, err := s.exec(ctx, datadumpCommand, MaxCommandOutputBytes, false)
	if err != nil {
		return fmt.Errorf("%s: %w", datadumpCommand, err)
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("%w: device answered with %d bytes", ErrDatadump, len(out))
	}
	return nil
}

// reader copies the device output to s.out until EOF or Close.
func (s *Session) reader(r io.Reader) {
	defer close(s.out)
	buf := make([]byte, readChunkBytes)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			select {
			case s.out <- bytes.Clone(buf[:n]):
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Prompt is the EXEC prompt the session locked onto.
func (s *Session) Prompt() string { return s.prompt }

// BannerDigest is the SHA-256 of the login text before the first prompt
// (CR LF folded to LF), for pinning in Options.ExpectBanner.
func (s *Session) BannerDigest() [sha256.Size]byte { return s.banner }

// Run sends one allowlisted command and returns its output: the lines
// between the command echo and the next prompt, with LF line ends. A
// command not on the allowlist is refused without sending anything; every
// other failure breaks the session.
func (s *Session) Run(ctx context.Context, c Command) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return nil, fmt.Errorf("cbscli: %s: %w", s.hostID, ErrSessionBroken)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("cbscli: %s: %w", s.hostID, err)
	}
	out, err := s.exec(ctx, c.text, c.outputCap(), c.config)
	if err != nil {
		s.broken = err
		s.Close()
		return nil, fmt.Errorf("cbscli: %s: %q: %w", s.hostID, c.text, err)
	}
	return []byte(out), nil
}

// exec sends line and reads its output under the rate limit, the command
// deadline and the caps.
func (s *Session) exec(ctx context.Context, line string, limit int, config bool) (string, error) {
	if !s.lastSend.IsZero() {
		if w := s.lastSend.Add(MinCommandInterval).Sub(s.d.now()); w > 0 {
			if err := s.d.wait(ctx, w); err != nil {
				return "", err
			}
		}
	}
	cctx, cancel := context.WithTimeout(ctx, orDefault(s.d.commandTimeout, CommandTimeout))
	defer cancel()
	// A blocked write (full window) is released by closing the session.
	stop := context.AfterFunc(cctx, func() { s.sess.Close() })
	defer stop()

	if _, err := io.WriteString(s.stdin, line+"\n"); err != nil {
		if cctx.Err() != nil {
			return "", ctxErr(cctx)
		}
		return "", fmt.Errorf("send: %w", err)
	}
	s.lastSend = s.d.now()

	// Echo line, output, and the unterminated prompt line.
	raw, _, err := s.readToPrompt(cctx, s.prompt, len(line)+2+limit+MaxLineBytes)
	if err != nil {
		return "", err
	}
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 || string(bytes.TrimSuffix(raw[:nl], []byte("\r"))) != line {
		return "", ErrUnexpectedEcho
	}
	body := raw[nl+1:]
	if len(body) > limit {
		return "", fmt.Errorf("%w: more than %d bytes", ErrOutputTooLarge, limit)
	}
	text, err := normalize(body)
	if err != nil {
		return "", err
	}
	if config && strings.Count(text, "\n") > MaxConfigLines {
		return "", fmt.Errorf("%w: more than %d", ErrTooManyLines, MaxConfigLines)
	}
	return text, nil
}

func ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, ctx.Err())
	}
	return ctx.Err()
}

// readToPrompt reads until the device has gone quiet with an unterminated
// last line that is the prompt want (or, with want empty, any recognised
// EXEC prompt). It returns everything before that line and the prompt.
// limit caps all bytes read, including the prompt line.
func (s *Session) readToPrompt(ctx context.Context, want string, limit int) ([]byte, string, error) {
	var buf []byte
	tail := func() ([]byte, int) {
		i := bytes.LastIndexByte(buf, '\n')
		return buf[i+1:], i
	}
	idle := time.NewTimer(orDefault(s.d.settle, PromptSettle))
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			if t, _ := tail(); looksInteractive(string(t)) {
				return nil, "", fmt.Errorf("%w (no answer sent)", ErrUnexpectedPrompt)
			}
			return nil, "", ctxErr(ctx)
		case b, ok := <-s.out:
			if !ok {
				if ctx.Err() != nil {
					return nil, "", ctxErr(ctx)
				}
				return nil, "", ErrSessionClosed
			}
			buf = append(buf, b...)
			if len(buf) > limit {
				return nil, "", fmt.Errorf("%w: more than %d bytes", ErrOutputTooLarge, limit)
			}
			if t, _ := tail(); len(t) > MaxLineBytes+1 {
				return nil, "", fmt.Errorf("%w: unterminated line over %d bytes", ErrLineTooLong, MaxLineBytes)
			}
			idle.Reset(orDefault(s.d.settle, PromptSettle))
		case <-idle.C:
			t, i := tail()
			if p, ok := parsePrompt(string(t)); ok && (want == "" || p == want) {
				return buf[:i+1], p, nil
			}
			if looksInteractive(string(t)) {
				return nil, "", fmt.Errorf("%w (no answer sent)", ErrUnexpectedPrompt)
			}
			// Mid-line pause: wait for more data or the deadline.
		}
	}
}

// normalize checks raw device text and folds CR LF to LF. Only valid UTF-8
// with printable characters, tabs and line ends passes; a bare CR, escape
// sequences, other control and format characters are refused. Every line
// is at most MaxLineBytes.
func normalize(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("%w: invalid UTF-8", ErrMalformedOutput)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, r := range text {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			return "", fmt.Errorf("%w: character %U", ErrMalformedOutput, r)
		}
	}
	for line := range strings.SplitSeq(text, "\n") {
		if len(line) > MaxLineBytes {
			return "", fmt.Errorf("%w: %d bytes, limit %d", ErrLineTooLong, len(line), MaxLineBytes)
		}
	}
	return text, nil
}

// Close ends the session and the connection and frees the device for the
// next Open. It is idempotent; nothing is sent to the device.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		if s.sess != nil {
			s.sess.Close()
		}
		err = s.client.Close()
		s.d.release(s.hostID)
	})
	return err
}
