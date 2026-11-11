// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func TestFormatNetBirdOfferApprovalShowsAllBoundFields(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.netbirdOfferBinding()
	b.OfferIDHash = strings.Repeat("ab", 32)
	p := offerOps.mustPropose(e, b)
	got, err := FormatNetBirdOfferApproval(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "NetBird offer for host vps01 (risk HIGH): approving creates one setup key\n" +
		"  Permit:             " + p.Digest.String() + "\n" +
		"  Offer ID hash:      " + strings.Repeat("ab", 32) + "\n" +
		"  Host:               vps01\n" +
		"  SSH user:           nebula\n" +
		"  Credential:         nebula-default\n" +
		"  Managed group:      nos-managed (the setup key's only group)\n" +
		"  Ephemeral peer:     no (the peer stays in NetBird while offline)\n" +
		"  Setup key expires:  2026-10-10T13:00:00Z\n" +
		"  Permit expires:     2026-10-10T12:15:00Z\n" +
		"  Approval:           WebAuthn, user verification\n"
	if got != want {
		t.Fatalf("view\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatNetBirdOfferApprovalEphemeralAndHardened(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	b := e.netbirdOfferBinding()
	b.Ephemeral = true
	got, err := FormatNetBirdOfferApproval(offerOps.mustPropose(e, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"Ephemeral peer:     yes (NetBird removes the peer when it goes offline)\n",
		"Approval:           nebula approve (CLI only)\n",
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("view lacks %q:\n%s", w, got)
		}
	}
}

func TestFormatNetBirdPeerDeleteApprovalShowsAllBoundFields(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.netbirdPeerDeleteBinding()
	b.PeerID = "chacbco6lnnbn6cg5s90"
	b.OfferIDHash = strings.Repeat("cd", 32)
	p := peerDeleteOps.mustPropose(e, b)
	got, err := FormatNetBirdPeerDeleteApproval(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "Delete NetBird peer chacbco6lnnbn6cg5s90 (risk HIGH)\n" +
		"  Permit:             " + p.Digest.String() + "\n" +
		"  Peer ID:            chacbco6lnnbn6cg5s90\n" +
		"  Peer name:          \"vps01\"\n" +
		"  NetBird IP:         100.64.12.7\n" +
		"  Offer ID hash:      " + strings.Repeat("cd", 32) + "\n" +
		"  Attribution:        time_window (weaker fallback: the only new peer in the managed group within the offer's time window; check name and IP)\n" +
		"  Permit expires:     2026-10-10T12:15:00Z\n" +
		"  Approval:           WebAuthn, user verification\n"
	if got != want {
		t.Fatalf("view\n got:\n%s\nwant:\n%s", got, want)
	}
}

// TestFormatNetBirdPeerDeleteApprovalEscapesPeerName: the peer name is
// untrusted provider text; anything outside printable ASCII is shown
// escaped, so a look-alike name cannot pass for another peer.
func TestFormatNetBirdPeerDeleteApprovalEscapesPeerName(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.netbirdPeerDeleteBinding()
	b.PeerName = "vps\u043e1 \"x\"" // Cyrillic o and quotes
	b.AttributionMethod = canonical.AttributionSetupKey
	got, err := FormatNetBirdPeerDeleteApproval(peerDeleteOps.mustPropose(e, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		`Peer name:          "vps\u043e1 \"x\""` + "\n",
		"Attribution:        setup_key (the NetBird API names this offer's setup key)\n",
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("view lacks %q:\n%s", w, got)
		}
	}
	if strings.ContainsRune(got, '\u043e') {
		t.Fatal("view shows the raw non-ASCII character")
	}
}

// TestFormatNetBirdApprovalRefusesTamperedPermit: a permit whose binding
// no longer hashes to its digest is never shown.
func TestFormatNetBirdApprovalRefusesTamperedPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	offer := offerOps.mustPropose(e, e.netbirdOfferBinding())
	for name, mut := range map[string]func(*NetBirdOfferPermit){
		"group":     func(p *NetBirdOfferPermit) { p.Binding.ManagedGroup = "All" },
		"ephemeral": func(p *NetBirdOfferPermit) { p.Binding.Ephemeral = true },
		"setup key": func(p *NetBirdOfferPermit) { p.Binding.SetupKeyExpiryUnix++ },
		"invalid":   func(p *NetBirdOfferPermit) { p.Binding.HostID = "vps01\nApproval: none" },
		"zero":      func(p *NetBirdOfferPermit) { *p = NetBirdOfferPermit{} },
	} {
		t.Run("offer/"+name, func(t *testing.T) {
			q := offer
			mut(&q)
			if _, err := FormatNetBirdOfferApproval(q); !errors.Is(err, ErrNetBirdDisplay) {
				t.Fatalf("want ErrNetBirdDisplay, got %v", err)
			}
		})
	}
	del := peerDeleteOps.mustPropose(e, e.netbirdPeerDeleteBinding())
	for name, mut := range map[string]func(*NetBirdPeerDeletePermit){
		"peer id":     func(p *NetBirdPeerDeletePermit) { p.Binding.PeerID = "legitpeer" },
		"peer name":   func(p *NetBirdPeerDeletePermit) { p.Binding.PeerName = "prod-db" },
		"ip":          func(p *NetBirdPeerDeletePermit) { p.Binding.NetBirdIP = "100.64.0.1" },
		"attribution": func(p *NetBirdPeerDeletePermit) { p.Binding.AttributionMethod = canonical.AttributionSetupKey },
		"invalid":     func(p *NetBirdPeerDeletePermit) { p.Binding.PeerName = "x\x1b[2J" },
		"zero":        func(p *NetBirdPeerDeletePermit) { *p = NetBirdPeerDeletePermit{} },
	} {
		t.Run("peer_delete/"+name, func(t *testing.T) {
			q := del
			mut(&q)
			if _, err := FormatNetBirdPeerDeleteApproval(q); !errors.Is(err, ErrNetBirdDisplay) {
				t.Fatalf("want ErrNetBirdDisplay, got %v", err)
			}
		})
	}
}
