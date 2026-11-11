// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// ErrNetBirdDisplay reports a NetBird permit whose binding does not hash to
// its digest; such a permit is never shown for approval.
var ErrNetBirdDisplay = errors.New("permit: NetBird permit binding does not match its digest")

// checkBoundDigest re-validates a binding through its digest, so a view
// shows exactly what an approval signs.
func checkBoundDigest(d canonical.Digest, sum canonical.Digest, err error) error {
	if err != nil {
		return errors.Join(ErrNetBirdDisplay, err)
	}
	if subtle.ConstantTimeCompare(sum[:], d[:]) != 1 {
		return ErrNetBirdDisplay
	}
	return nil
}

func viewLine(s *strings.Builder, label, value string) {
	fmt.Fprintf(s, "  %-19s %s\n", label+":", value)
}

func unixRFC3339(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }

// FormatNetBirdOfferApproval renders the approval view of a NetBird offer
// permit for `nebula approve`: every bound field. The binding is
// re-validated through its digest first, so the text contains no control
// characters and nothing the approval does not sign.
func FormatNetBirdOfferApproval(p NetBirdOfferPermit) (string, error) {
	sum, err := canonical.NetBirdOfferDigest(p.Binding)
	if err := checkBoundDigest(p.Digest, sum, err); err != nil {
		return "", fmt.Errorf("format NetBird offer permit %s: %w", p.Digest, err)
	}
	b := p.Binding
	ephemeral := "no (the peer stays in NetBird while offline)"
	if b.Ephemeral {
		ephemeral = "yes (NetBird removes the peer when it goes offline)"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "NetBird offer for host %s (risk HIGH): approving creates one setup key\n", b.HostID)
	viewLine(&s, "Permit", p.Digest.String())
	viewLine(&s, "Offer ID hash", b.OfferIDHash)
	viewLine(&s, "Host", b.HostID)
	viewLine(&s, "SSH user", b.SSHUser)
	viewLine(&s, "Credential", b.CredentialRef)
	viewLine(&s, "Managed group", b.ManagedGroup+" (the setup key's only group)")
	viewLine(&s, "Ephemeral peer", ephemeral)
	viewLine(&s, "Setup key expires", unixRFC3339(b.SetupKeyExpiryUnix))
	viewLine(&s, "Permit expires", unixRFC3339(b.ExpiryUnix))
	viewLine(&s, "Approval", p.Requirement.String())
	return s.String(), nil
}

// FormatNetBirdPeerDeleteApproval renders the approval view of a NetBird
// peer delete permit for `nebula approve`: every bound field. The peer
// name comes from the NetBird API; it is shown quoted with everything
// outside printable ASCII escaped, so a look-alike name is visible as such.
func FormatNetBirdPeerDeleteApproval(p NetBirdPeerDeletePermit) (string, error) {
	sum, err := canonical.NetBirdPeerDeleteDigest(p.Binding)
	if err := checkBoundDigest(p.Digest, sum, err); err != nil {
		return "", fmt.Errorf("format NetBird peer delete permit %s: %w", p.Digest, err)
	}
	b := p.Binding
	var attribution string
	switch b.AttributionMethod {
	case canonical.AttributionSetupKey:
		attribution = b.AttributionMethod + " (the NetBird API names this offer's setup key)"
	default: // AttributionTimeWindow; the digest check refused anything else
		attribution = b.AttributionMethod + " (weaker fallback: the only new peer in the managed group within the offer's time window; check name and IP)"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "Delete NetBird peer %s (risk HIGH)\n", b.PeerID)
	viewLine(&s, "Permit", p.Digest.String())
	viewLine(&s, "Peer ID", b.PeerID)
	viewLine(&s, "Peer name", strconv.QuoteToASCII(b.PeerName))
	viewLine(&s, "NetBird IP", b.NetBirdIP)
	viewLine(&s, "Offer ID hash", b.OfferIDHash)
	viewLine(&s, "Attribution", attribution)
	viewLine(&s, "Permit expires", unixRFC3339(b.ExpiryUnix))
	viewLine(&s, "Approval", p.Requirement.String())
	return s.String(), nil
}
