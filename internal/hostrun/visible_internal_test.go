// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
)

// runVisible reports "not running" only for exit 0 with the confirmation
// line, "running" only for a plain exit 1, and ErrVisibilityUnknown for
// everything else.
func TestRunVisibleMapsOutcomes(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	for name, tc := range map[string]struct {
		cmd     string
		running bool
		unknown bool
	}{
		"confirmed gone":        {cmd: "echo '" + visibleNone + "'"},
		"running":               {cmd: "exit 1", running: true},
		"exit 0 without line":   {cmd: "true", unknown: true},
		"exit 0 other output":   {cmd: "echo '" + visibleNone + "'; echo more", unknown: true},
		"exit 3":                {cmd: "exit 3", unknown: true},
		"exit 2":                {cmd: "exit 2", unknown: true},
		"exit 127 (no command)": {cmd: "nebula-no-such-command", unknown: true},
		"signal":                {cmd: "kill -KILL $$", unknown: true},
		"signal after line":     {cmd: "echo '" + visibleNone + "'; kill -TERM $$", unknown: true},
		// Output is bounded: a host that floods stdout or stderr is
		// "cannot tell", whatever its exit status.
		"stdout flood":                {cmd: "yes", unknown: true},
		"stdout flood, exit 1":        {cmd: "head -c 16777216 /dev/zero; exit 1", unknown: true},
		"stdout flood after line":     {cmd: "echo '" + visibleNone + "'; head -c 16777216 /dev/zero", unknown: true},
		"stderr flood":                {cmd: "yes >&2", unknown: true},
		"stderr flood, exit 1":        {cmd: "head -c 16777216 /dev/zero >&2; exit 1", unknown: true},
		"stderr flood, then line":     {cmd: "head -c 16777216 /dev/zero >&2; echo '" + visibleNone + "'", unknown: true},
		"stderr one over the limit":   {cmd: "head -c 257 /dev/zero >&2; echo '" + visibleNone + "'", unknown: true},
		"stderr at the limit":         {cmd: "head -c 256 /dev/zero >&2; echo '" + visibleNone + "'"},
		"stderr at the limit, exit 1": {cmd: "head -c 256 /dev/zero >&2; exit 1", running: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			running, err := runVisible(context.Background(), sshSession{s}, tc.cmd)
			if tc.unknown {
				if !errors.Is(err, ErrVisibilityUnknown) {
					t.Fatalf("running %v err %v, want ErrVisibilityUnknown", running, err)
				}
				return
			}
			if err != nil || running != tc.running {
				t.Fatalf("running %v err %v, want %v", running, err, tc.running)
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if _, err := runVisible(ctx, sshSession{s}, "sleep 30"); !errors.Is(err, ErrVisibilityUnknown) {
			t.Fatalf("err %v, want ErrVisibilityUnknown", err)
		}
	})
	t.Run("no exit status", func(t *testing.T) {
		if _, err := runVisible(context.Background(), newFakeSession(nil, nil, &ssh.ExitMissingError{}), "x"); !errors.Is(err, ErrVisibilityUnknown) {
			t.Fatalf("err %v, want ErrVisibilityUnknown", err)
		}
	})
}

// fakeSession prints out on stdout and errOut on stderr in chunks, then
// returns err. With untilClosed it then keeps the session open until it
// is closed, like a host that keeps streaming.
type fakeSession struct {
	out, errOut    []byte
	err            error
	untilClosed    bool
	stdout, stderr io.Writer
	closeOnce      sync.Once
	closed         chan struct{}
	notClosed      bool
}

func newFakeSession(out, errOut []byte, err error) *fakeSession {
	return &fakeSession{out: out, errOut: errOut, err: err, closed: make(chan struct{})}
}

func (f *fakeSession) RunWith(_ string, stdout, stderr io.Writer) error {
	f.stdout, f.stderr = stdout, stderr
	for _, w := range []struct {
		w io.Writer
		b []byte
	}{{stdout, f.out}, {stderr, f.errOut}} {
		for b := w.b; len(b) > 0; {
			n := min(len(b), 32<<10)
			if k, err := w.w.Write(b[:n]); err != nil || k != n {
				return fmt.Errorf("write: %d %v", k, err)
			}
			b = b[n:]
		}
	}
	if f.untilClosed {
		select {
		case <-f.closed:
		case <-time.After(5 * time.Second):
			f.notClosed = true
		}
	}
	return f.err
}

func (f *fakeSession) Close() error { f.closeOnce.Do(func() { close(f.closed) }); return nil }

// A host that streams far more than the limit is "cannot tell" even with
// exactly the confirmation line on stdout and exit 0. runVisible keeps at
// most visibleMaxOutput bytes per stream, keeps draining (a writer error
// would stall the session) and closes the session as soon as the limit is
// passed, so the host stops sending.
func TestRunVisibleBoundsOutput(t *testing.T) {
	line := []byte(visibleNone + "\n")
	flood := bytes.Repeat([]byte("x"), 16<<20)
	for name, f := range map[string]*fakeSession{
		"stdout":            newFakeSession(append(append([]byte(nil), line...), flood...), nil, nil),
		"stderr":            newFakeSession(line, flood, nil),
		"stderr, one over":  newFakeSession(line, flood[:visibleMaxOutput+1], nil),
		"stdout, exit info": newFakeSession(flood, nil, &ssh.ExitMissingError{}),
	} {
		t.Run(name, func(t *testing.T) {
			f.untilClosed = true
			running, err := runVisible(context.Background(), f, "x")
			if running || !errors.Is(err, ErrVisibilityUnknown) {
				t.Fatalf("running %v err %v, want ErrVisibilityUnknown", running, err)
			}
			if f.notClosed {
				t.Fatal("session not closed on too much output")
			}
			for _, w := range []io.Writer{f.stdout, f.stderr} {
				if n := len(w.(*cappedWriter).bytes()); n > visibleMaxOutput {
					t.Fatalf("kept %d bytes, limit %d", n, visibleMaxOutput)
				}
			}
		})
	}
	// Below the limit the stderr content does not matter.
	f := newFakeSession(line, bytes.Repeat([]byte("w"), visibleMaxOutput), nil)
	if running, err := runVisible(context.Background(), f, "x"); running || err != nil {
		t.Fatalf("running %v err %v, want not running", running, err)
	}
	if got := string(f.stdout.(*cappedWriter).bytes()); got != visibleNone+"\n" {
		t.Fatalf("stdout %q", got)
	}
}
