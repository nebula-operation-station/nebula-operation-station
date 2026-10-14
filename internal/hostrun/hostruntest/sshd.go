// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostruntest is an in-process SSH server for tests that runs exec
// requests with /bin/sh on the test machine, like a managed host would.
package hostruntest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Server is a running test SSH server.
type Server struct {
	Addr    string
	HostKey ssh.Signer
	// Commands are the exec commands received, in order.
	mu       sync.Mutex
	commands []string
}

// Commands returns the exec commands received so far.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// Start serves until the test ends. authorized is the only accepted user key.
func Start(t *testing.T, authorized ssh.PublicKey) *Server {
	t.Helper()
	s, stop, err := Serve(authorized)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return s
}

// Serve starts a server on a loopback port; stop ends it. For test
// programs that have no testing.T (the browser harness).
func Serve(authorized ssh.PublicKey) (*Server, func(), error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if authorized != nil && string(k.Marshal()) == string(authorized.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	s := &Server{Addr: ln.Addr().String(), HostKey: hk}
	var wg sync.WaitGroup
	var conns sync.Map
	stop := func() {
		ln.Close()
		conns.Range(func(k, _ any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serve(c, cfg)
			}()
		}
	}()
	return s, stop, nil
}

func (s *Server) serve(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs)
	}
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	var cmd *exec.Cmd
	var once sync.Once
	finished := make(chan struct{})
	for r := range reqs {
		switch r.Type {
		case "exec":
			if len(r.Payload) < 4 {
				_ = r.Reply(false, nil)
				continue
			}
			n := binary.BigEndian.Uint32(r.Payload)
			line := string(r.Payload[4 : 4+n])
			s.mu.Lock()
			s.commands = append(s.commands, line)
			s.mu.Unlock()
			cmd = exec.Command("/bin/sh", "-c", line)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				_ = r.Reply(false, nil)
				return
			}
			_ = r.Reply(true, nil)
			go func() {
				err := cmd.Wait()
				status := 0
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
						msg := ssh.Marshal(struct {
							Signal     string
							CoreDumped bool
							Error      string
							Lang       string
						}{Signal: "KILL"})
						_, _ = ch.SendRequest("exit-signal", false, msg)
						once.Do(func() { close(finished) })
						ch.Close()
						return
					}
					status = ee.ExitCode()
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
				once.Do(func() { close(finished) })
				ch.Close()
			}()
		case "signal":
			if cmd != nil && cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
	// Channel closed by the client: stop the process group.
	if cmd != nil && cmd.Process != nil {
		select {
		case <-finished:
		default:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	_, _ = io.Copy(io.Discard, ch)
}
