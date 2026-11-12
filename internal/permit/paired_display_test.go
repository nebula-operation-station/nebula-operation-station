// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

func TestFormatPairedApprovalShowsAllBoundFields(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	b := e.pairedBinding()
	b.OfferIDHash = strings.Repeat("ab", 32)
	p := e.proposePaired(b)
	got, err := FormatPairedApproval(p, PairedDisplay{
		OfferCreated:    e.clk.Now().Add(-3 * time.Minute),
		DownloadAddress: "::ffff:198.51.100.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "Paired enrollment of host web01 (risk HIGH)\n" +
		"  Permit:           " + p.Digest.String() + "\n" +
		"  Offer ID hash:    " + strings.Repeat("ab", 32) + "\n" +
		"  Host:             web01\n" +
		"  Endpoint:         192.0.2.10:22\n" +
		"  Endpoint to add:  yes, will be added to the inventory host\n" +
		"  SSH user:         nebula\n" +
		"  Credential:       nebula-default\n" +
		"  Host key:         " + fpA + "\n" +
		"  Pairing code:     matches the pairing code from the host (00000-00000-00000-00000-00000)\n" +
		"  Permit expires:   2026-10-10T12:15:00Z\n" +
		"  Offer created:    2026-10-10T11:57:00Z\n" +
		"  Downloaded from:  198.51.100.7\n" +
		"  Approval:         WebAuthn, user verification\n"
	if got != want {
		t.Fatalf("view\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatPairedApprovalExistingEndpointAndUnknownOfferFacts(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	b := e.pairedBinding()
	b.EndpointToAdd = false
	p := e.proposePaired(b)
	for _, addr := range []string{"", "not-an-ip", "198.51.100.7:443", "fe80::1%eth0", "198.51.100.7\n"} {
		got, err := FormatPairedApproval(p, PairedDisplay{DownloadAddress: addr})
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{
			"Endpoint to add:  no (already an inventory endpoint of the host)\n",
			"Offer created:    unknown\n",
			"Downloaded from:  unknown\n",
			"Approval:         nebula approve (CLI only)\n",
		} {
			if !strings.Contains(got, w) {
				t.Fatalf("address %q: view lacks %q:\n%s", addr, w, got)
			}
		}
	}
}

// TestFormatPairedApprovalRefusesTamperedPermit: a permit whose binding
// was changed after proposal no longer hashes to its digest and is not
// shown, so the view can never show values other than the signed ones.
func TestFormatPairedApprovalRefusesTamperedPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := e.proposePaired(e.pairedBinding())
	for name, mut := range map[string]func(*PairedPermit){
		"fingerprint": func(p *PairedPermit) { p.Binding.HostKeyFingerprint = fpB },
		"endpoint":    func(p *PairedPermit) { p.Binding.Endpoint = "192.0.2.99:22" },
		"to add":      func(p *PairedPermit) { p.Binding.EndpointToAdd = false },
		"invalid":     func(p *PairedPermit) { p.Binding.HostID = "web01\nApproval: none" },
		"zero":        func(p *PairedPermit) { *p = PairedPermit{} },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mut(&q)
			if _, err := FormatPairedApproval(q, PairedDisplay{}); !errors.Is(err, ErrPairedDisplay) {
				t.Fatalf("want ErrPairedDisplay, got %v", err)
			}
		})
	}
}
