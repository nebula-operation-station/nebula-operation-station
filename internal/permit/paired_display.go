// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// PairedDisplay carries the offer facts `nebula approve` shows next to the
// bound fields (spec 05 v25-05-01: offer creation time and download
// address). They come from the executor's own offer store and are not part
// of the binding.
type PairedDisplay struct {
	// OfferCreated is the offer's creation time; zero shows "unknown".
	OfferCreated time.Time
	// DownloadAddress is the client address recorded at download; anything
	// that is not a bare IP address is shown as "unknown".
	DownloadAddress string
}

// ErrPairedDisplay reports a permit whose binding does not hash to its
// digest; such a permit is never shown for approval.
var ErrPairedDisplay = errors.New("permit: paired permit binding does not match its digest")

// FormatPairedApproval renders the approval view of a paired enrollment
// permit for `nebula approve`: every bound field, then the offer facts.
// Every bound value is re-validated through its digest first, so the text
// shows exactly what an approval signs and contains no control characters.
func FormatPairedApproval(p PairedPermit, d PairedDisplay) (string, error) {
	sum, err := canonical.PairedEnrollDigest(p.Binding)
	if err != nil {
		return "", fmt.Errorf("format paired permit %s: %w", p.Digest, errors.Join(ErrPairedDisplay, err))
	}
	if subtle.ConstantTimeCompare(sum[:], p.Digest[:]) != 1 {
		return "", fmt.Errorf("format paired permit %s: %w", p.Digest, ErrPairedDisplay)
	}
	b := p.Binding
	toAdd := "no (already an inventory endpoint of the host)"
	if b.EndpointToAdd {
		toAdd = "yes, will be added to the inventory host"
	}
	created := "unknown"
	if !d.OfferCreated.IsZero() {
		created = d.OfferCreated.UTC().Format(time.RFC3339)
	}
	addr := "unknown"
	if a, err := netip.ParseAddr(d.DownloadAddress); err == nil && a.Zone() == "" {
		addr = a.Unmap().String()
	}

	var s strings.Builder
	line := func(label, value string) { fmt.Fprintf(&s, "  %-17s %s\n", label+":", value) }
	fmt.Fprintf(&s, "Paired enrollment of host %s (risk HIGH)\n", b.HostID)
	line("Permit", p.Digest.String())
	line("Offer ID hash", b.OfferIDHash)
	line("Host", b.HostID)
	line("Endpoint", b.Endpoint)
	line("Endpoint to add", toAdd)
	line("SSH user", b.SSHUser)
	line("Credential", b.CredentialRef)
	line("Host key", b.HostKeyFingerprint)
	if b.CodeMatched {
		line("Pairing code", "matches the pairing code from the host ("+b.PairingCode+")")
	}
	line("Permit expires", time.Unix(b.ExpiryUnix, 0).UTC().Format(time.RFC3339))
	line("Offer created", created)
	line("Downloaded from", addr)
	line("Approval", p.Requirement.String())
	return s.String(), nil
}
