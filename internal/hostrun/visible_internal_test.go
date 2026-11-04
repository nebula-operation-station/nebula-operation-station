// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	} {
		t.Run(name, func(t *testing.T) {
			s, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			running, err := runVisible(context.Background(), s, tc.cmd)
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
		if _, err := runVisible(ctx, s, "sleep 30"); !errors.Is(err, ErrVisibilityUnknown) {
			t.Fatalf("err %v, want ErrVisibilityUnknown", err)
		}
	})
	t.Run("no exit status", func(t *testing.T) {
		if _, err := runVisible(context.Background(), fakeOutput{err: &ssh.ExitMissingError{}}, "x"); !errors.Is(err, ErrVisibilityUnknown) {
			t.Fatalf("err %v, want ErrVisibilityUnknown", err)
		}
	})
}

type fakeOutput struct{ err error }

func (f fakeOutput) Output(string) ([]byte, error) { return nil, f.err }
func (fakeOutput) Close() error                    { return nil }
