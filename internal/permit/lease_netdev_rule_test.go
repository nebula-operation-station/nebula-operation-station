// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"strings"
	"testing"
)

// approveReadGrantCLI proposes raw and approves it on the executor-local CLI
// path, the only approval path for network device grants (A1-0b).
func approveReadGrantCLI(t *testing.T, e *env, raw []byte) StoredReadGrant {
	t.Helper()
	p, err := e.auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	g, err := e.auth.ApproveReadGrantCLI(p.Digest, "admin")
	if err != nil {
		t.Fatalf("cli approve: %v", err)
	}
	return g
}

// A read grant with network device targets needs executor-local CLI
// approval in every mode (A1-0b): the proposal carries RequireCLI and no
// challenge, CommitReadGrant refuses the digest, and the pending grant stays
// for the CLI.
func TestNetDeviceGrantRequiresCLIInEveryMode(t *testing.T) {
	for name, mode := range map[string]Mode{"standard": ModeStandard, "hardened": ModeHardened} {
		t.Run(name, func(t *testing.T) {
			e, le := newLeaseEnv(t, mode)
			p, err := e.auth.ProposeReadGrant(readGrantRaw(t, netDeviceDocAt(e.clk.Now(), DefaultReadGrantLifetime)))
			if err != nil {
				t.Fatalf("propose: %v", err)
			}
			if p.Requirement != RequireCLI {
				t.Fatalf("requirement %v, want RequireCLI", p.Requirement)
			}
			if len(p.Challenge) != 0 {
				t.Fatalf("device grant got a %d-byte challenge", len(p.Challenge))
			}

			// Any assertion, even one over a well-formed challenge, is refused
			// before it is checked.
			for _, assertion := range [][]byte{nil, e.sign(p.Challenge), e.sign([]byte("forged challenge"))} {
				_, err = e.auth.CommitReadGrant(p.Digest, assertion)
				wantCode(t, err, CodeCLIRequired)
			}
			if _, ok, _ := le.ReadGrant(rgID); ok {
				t.Fatal("device grant stored through CommitReadGrant")
			}
			pending := e.auth.PendingReadGrants()
			if len(pending) != 1 || pending[0].Digest != p.Digest {
				t.Fatalf("pending after refused commit: %+v", pending)
			}

			g, err := e.auth.ApproveReadGrantCLI(p.Digest, "admin")
			if err != nil {
				t.Fatalf("cli approve: %v", err)
			}
			if g.ApprovedBy != "cli:admin" || g.Digest != p.Digest {
				t.Fatalf("stored %+v", g)
			}
			if stored, ok, err := le.ReadGrant(rgID); err != nil || !ok || stored.Digest != p.Digest {
				t.Fatalf("read back: %v %v %q", err, ok, stored.Digest)
			}
			if got := e.auth.PendingReadGrants(); len(got) != 0 {
				t.Fatalf("pending after cli approval: %d", len(got))
			}
		})
	}
}

// Host and PVE provider grants keep their mode-dependent approval: a
// user-verified assertion in standard mode, the CLI in hardened mode.
func TestNonDeviceGrantsKeepModeRequirement(t *testing.T) {
	docs := map[string]func(e *env) ReadGrantDoc{
		"host": func(e *env) ReadGrantDoc { return readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime) },
		"pve":  func(e *env) ReadGrantDoc { return providerDocAt(e.clk.Now(), rgID, 240) },
	}
	for name, mk := range docs {
		t.Run(name+"/standard", func(t *testing.T) {
			e, le := newLeaseEnv(t, ModeStandard)
			p, err := e.auth.ProposeReadGrant(readGrantRaw(t, mk(e)))
			if err != nil {
				t.Fatalf("propose: %v", err)
			}
			if p.Requirement != RequireAssertionVerified || len(p.Challenge) == 0 {
				t.Fatalf("requirement %v challenge %d", p.Requirement, len(p.Challenge))
			}
			g, err := e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
			if err != nil {
				t.Fatalf("commit: %v", err)
			}
			if !strings.HasPrefix(g.ApprovedBy, "webauthn:") {
				t.Fatalf("approved by %q", g.ApprovedBy)
			}
			if _, ok, _ := le.ReadGrant(rgID); !ok {
				t.Fatal("grant not stored")
			}
		})
		t.Run(name+"/hardened", func(t *testing.T) {
			e, le := newLeaseEnv(t, ModeHardened)
			p, err := e.auth.ProposeReadGrant(readGrantRaw(t, mk(e)))
			if err != nil {
				t.Fatalf("propose: %v", err)
			}
			if p.Requirement != RequireCLI || len(p.Challenge) != 0 {
				t.Fatalf("requirement %v challenge %d", p.Requirement, len(p.Challenge))
			}
			_, err = e.auth.CommitReadGrant(p.Digest, e.sign(p.Challenge))
			wantCode(t, err, CodeCLIRequired)
			if _, err := e.auth.ApproveReadGrantCLI(p.Digest, "admin"); err != nil {
				t.Fatalf("cli approve: %v", err)
			}
			if _, ok, _ := le.ReadGrant(rgID); !ok {
				t.Fatal("grant not stored")
			}
		})
	}
}
