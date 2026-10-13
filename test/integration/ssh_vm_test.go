// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Package integration runs the SSH transport against real OpenSSH servers
// (spec 08 / H05: Debian 12, Ubuntu 22.04, Ubuntu 24.04 test VMs). It is
// not part of `make test`; run it from the dev VM with `make
// test-integration` and:
//
//	NEBULA_IT_TARGETS  name=endpoint[,endpoint];name=...
//	                   e.g. "debian12=192.168.0.41;ubuntu2404=192.168.0.43,10.8.0.43"
//	NEBULA_IT_KEY      path of the OpenSSH private key the VMs accept
//	NEBULA_IT_KEY_PASSPHRASE  its passphrase, if any (read from the environment,
//	                   never from the command line)
//	NEBULA_IT_USER     login user on the VMs (default nebula)
//
// Each target gets exactly one failed authentication (a fresh random key) per
// run. Put the dev VM's address into fail2ban `ignoreip` on the test VMs.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

type target struct {
	name      string
	endpoints []sshtransport.Endpoint
}

func config(t *testing.T) ([]target, ssh.Signer, string) {
	t.Helper()
	spec := os.Getenv("NEBULA_IT_TARGETS")
	keyPath := os.Getenv("NEBULA_IT_KEY")
	if spec == "" || keyPath == "" {
		t.Skip("NEBULA_IT_TARGETS and NEBULA_IT_KEY not set")
	}
	user := os.Getenv("NEBULA_IT_USER")
	if user == "" {
		user = "nebula"
	}
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var signer ssh.Signer
	if pass := os.Getenv("NEBULA_IT_KEY_PASSPHRASE"); pass != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(pass))
	} else {
		signer, err = ssh.ParsePrivateKey(pem)
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []target
	for _, part := range strings.Split(spec, ";") {
		name, eps, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			t.Fatalf("NEBULA_IT_TARGETS entry %q is not name=endpoint[,endpoint]", part)
		}
		tg := target{name: name}
		for _, e := range strings.Split(eps, ",") {
			ep, err := sshtransport.ParseEndpoint(strings.TrimSpace(e))
			if err != nil {
				t.Fatal(err)
			}
			tg.endpoints = append(tg.endpoints, ep)
		}
		out = append(out, tg)
	}
	return out, signer, user
}

func closedLocalEndpoint(t *testing.T) sshtransport.Endpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return sshtransport.Endpoint{Host: "127.0.0.1", Port: uint16(p)}
}

func TestRealOpenSSH(t *testing.T) {
	targets, signer, user := config(t)
	var cfg sshtransport.Config
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			// Enrollment: the key every endpoint presents.
			var pin ssh.PublicKey
			for _, ep := range tg.endpoints {
				k, err := cfg.Probe(ctx, ep)
				if err != nil {
					t.Fatalf("probe %s: %v", ep, err)
				}
				if pin != nil && sshtransport.Fingerprint(k) != sshtransport.Fingerprint(pin) {
					t.Fatalf("%s presents another key than %s", ep, tg.endpoints[0])
				}
				pin = k
			}
			t.Logf("%s pinned %s %s", tg.name, pin.Type(), sshtransport.Fingerprint(pin))
			if pin.Type() != ssh.KeyAlgoED25519 {
				t.Errorf("probe chose %s; OpenSSH on current Debian/Ubuntu has an ed25519 host key", pin.Type())
			}

			// Pinned connection, a command, keepalive reply.
			c, err := cfg.Dial(ctx, sshtransport.Target{HostID: tg.name, Endpoints: tg.endpoints, User: user, HostKey: pin}, signer)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			s, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			out, err := s.Output("uname -s")
			s.Close()
			if err != nil || strings.TrimSpace(string(out)) != "Linux" {
				t.Fatalf("uname: %q %v", out, err)
			}
			if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.Fatalf("keepalive: %v", err)
			}
			c.Close()

			// TCP failure on the first endpoint falls back.
			eps := append([]sshtransport.Endpoint{closedLocalEndpoint(t)}, tg.endpoints...)
			c, err = cfg.Dial(ctx, sshtransport.Target{HostID: tg.name, Endpoints: eps, User: user, HostKey: pin}, signer)
			if err != nil {
				t.Fatalf("fallback: %v", err)
			}
			c.Close()

			// A different pin: hard stop before authentication.
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			wrong, _ := ssh.NewPublicKey(pub)
			_, err = cfg.Dial(ctx, sshtransport.Target{HostID: tg.name, Endpoints: tg.endpoints, User: user, HostKey: wrong}, signer)
			if sshtransport.ClassOf(err) != sshtransport.ClassHostKeyMismatch {
				t.Fatalf("wrong pin: %v", err)
			}

			// A key the host does not accept: hard stop, one attempt.
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			stranger, _ := ssh.NewSignerFromKey(k)
			_, err = cfg.Dial(ctx, sshtransport.Target{HostID: tg.name, Endpoints: tg.endpoints, User: user, HostKey: pin}, stranger)
			if sshtransport.ClassOf(err) != sshtransport.ClassAuth {
				t.Fatalf("unknown key: %v", err)
			}
		})
	}
}
