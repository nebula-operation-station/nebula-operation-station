// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// SYNTHETIC FIXTURES. The banner, prompt and command output below are made
// up from the shape described in the Cisco CBS CLI guides. They are not lab
// output; replace them with sanitized ND-03 fixtures once those exist.
const (
	synthPrompt = "sw-lab1#"
	synthBanner = "\r\n\r\nSYNTHETIC BANNER - authorised access only\r\n\r\n"
	// synthVersion is the body of "show version" with LF line ends; the
	// fake device sends it with CRLF.
	synthVersion = "\nActive-image: flash://system/images/image_synthetic.bin\n" +
		"  Version: 0.0.0.0\n  Commit: synthetic\n"
	synthVLAN = "\nCreated by: D-Default, S-Static, G-GVRP, R-Radius Assigned VLAN\n\n" +
		"Vlan       Name                   Tagged Ports      UnTagged Ports      Created by\n" +
		"---- ----------------- ------------------ ------------------ ----------------\n" +
		" 1           1                                    gi1-8               D\n"
)

// fakeCBS is a loopback x/crypto/ssh server that plays a CBS switch shell.
type fakeCBS struct {
	banner  string            // sent before the first prompt
	prompt  string            // sent after the banner and after every output
	outputs map[string]string // command -> output (LF), then the prompt
	replies map[string]string // command -> raw bytes after the echo (no prompt added)
	noEcho  bool              // do not echo the command line
	chunk   int               // write in pieces of this many bytes
	silent  bool              // the shell never sends anything

	mu       sync.Mutex
	received []string // command lines (and an unterminated rest at EOF)
	auths    int
	sessions int
	execs    int
	shells   int
	ptys     int
}

func newFakeCBS() *fakeCBS {
	return &fakeCBS{
		banner: synthBanner,
		prompt: synthPrompt,
		outputs: map[string]string{
			"terminal datadump": "",
			"show version":      synthVersion,
			"show vlan":         synthVLAN,
		},
		replies: map[string]string{},
	}
}

func (f *fakeCBS) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

func (f *fakeCBS) counts() (auths, sessions, execs, shells, ptys int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auths, f.sessions, f.execs, f.shells, f.ptys
}

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// start serves f on 127.0.0.1 and returns a target pinned to its host key
// and the client key it authorizes.
func (f *fakeCBS) start(t *testing.T) (sshtransport.Target, ssh.Signer) {
	t.Helper()
	host, client := signer(t), signer(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.auths++
			f.mu.Unlock()
			if string(k.Marshal()) == string(client.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); f.serve(c, cfg) }()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	return sshtransport.Target{
		HostID:    "sw-lab1",
		Endpoints: []sshtransport.Endpoint{{Host: "127.0.0.1", Port: port}},
		User:      "nos-read",
		HostKey:   host.PublicKey(),
	}, client
}

func (f *fakeCBS) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		f.mu.Lock()
		f.sessions++
		f.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ch.Close()
			for r := range creqs {
				f.mu.Lock()
				switch r.Type {
				case "pty-req":
					f.ptys++
					f.mu.Unlock()
					r.Reply(true, nil)
				case "shell":
					f.shells++
					f.mu.Unlock()
					r.Reply(true, nil)
					go f.shell(ch)
				case "exec":
					f.execs++
					f.mu.Unlock()
					r.Reply(false, nil)
				default:
					f.mu.Unlock()
					r.Reply(false, nil)
				}
			}
		}()
	}
}

// pauseMark in a reply makes the fake device pause briefly (shorter than
// the test driver's settle time) at that point.
const pauseMark = "<pause>"

func (f *fakeCBS) write(w io.Writer, s string) {
	if before, after, ok := strings.Cut(s, pauseMark); ok {
		f.write(w, before)
		time.Sleep(5 * time.Millisecond)
		f.write(w, after)
		return
	}
	if f.chunk <= 0 {
		io.WriteString(w, s)
		return
	}
	for len(s) > 0 {
		n := min(f.chunk, len(s))
		if _, err := io.WriteString(w, s[:n]); err != nil {
			return
		}
		s = s[n:]
		time.Sleep(time.Millisecond)
	}
}

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func (f *fakeCBS) shell(ch ssh.Channel) {
	defer ch.Close()
	if f.silent {
		io.Copy(io.Discard, ch)
		return
	}
	f.write(ch, f.banner+f.prompt)
	r := bufio.NewReader(ch)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			cmd := strings.TrimRight(line, "\r\n")
			f.mu.Lock()
			f.received = append(f.received, cmd)
			f.mu.Unlock()
			if err == nil {
				f.answer(ch, cmd)
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *fakeCBS) answer(ch ssh.Channel, cmd string) {
	if !f.noEcho {
		f.write(ch, cmd+"\r\n")
	}
	if raw, ok := f.replies[cmd]; ok {
		f.write(ch, raw)
		return
	}
	if out, ok := f.outputs[cmd]; ok {
		f.write(ch, crlf(out)+f.prompt)
		return
	}
	f.write(ch, "% Unrecognized command\r\n"+f.prompt)
}

// testDriver is a Driver with short timeouts and a sleep that only records
// what the rate limit asked for.
type testDriver struct {
	*Driver
	mu     sync.Mutex
	sleeps []time.Duration
}

func newTestDriver() *testDriver {
	td := &testDriver{}
	td.Driver = &Driver{
		promptTimeout:  2 * time.Second,
		commandTimeout: 2 * time.Second,
		settle:         20 * time.Millisecond,
		sleep: func(_ context.Context, d time.Duration) error {
			td.mu.Lock()
			td.sleeps = append(td.sleeps, d)
			td.mu.Unlock()
			return nil
		},
	}
	return td
}
