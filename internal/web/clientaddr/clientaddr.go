// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientaddr determines the client address of a web request behind
// a reverse proxy (ADR 0013 D7 "Client address behind the reverse proxy").
//
// Only the TCP peer decides whether forwarded headers count: if the peer
// is a configured trusted proxy, the rightmost X-Forwarded-For entry that
// is not itself a trusted proxy is the client address; otherwise every
// forwarded header is ignored and the peer is the client. The Forwarded
// header is never read. A trusted proxy without a usable X-Forwarded-For
// is refused with exactly one sentinel error per class; there is no
// fallback to the peer address.
package clientaddr

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Limits of the X-Forwarded-For header (ADR 0013 E9). Several header lines
// count as one list joined with ", ".
const (
	// DefaultMaxHeaderBytes is the largest combined X-Forwarded-For value
	// accepted from a trusted proxy.
	DefaultMaxHeaderBytes = 1024
	// DefaultMaxEntries is the largest number of comma-separated entries
	// accepted from a trusted proxy, over all header lines together.
	DefaultMaxEntries = 16
)

// headerXFF is the only forwarded header this package reads.
const headerXFF = "X-Forwarded-For"

// Refusals of a trusted proxy's forwarded header. Resolve returns exactly
// one of them, from the first failing check in this order.
var (
	// ErrForwardedMissing: the trusted proxy sent no X-Forwarded-For line.
	ErrForwardedMissing = errors.New("x-forwarded-for missing")
	// ErrForwardedTooLong: the combined header value exceeds the byte
	// limit. Checked before the value is split.
	ErrForwardedTooLong = errors.New("x-forwarded-for too long")
	// ErrForwardedTooManyEntries: the header has more entries than the
	// entry limit. Checked before any entry is parsed.
	ErrForwardedTooManyEntries = errors.New("x-forwarded-for has too many entries")
	// ErrForwardedMalformed: an entry, wherever it stands, is not an IP
	// address after normalisation.
	ErrForwardedMalformed = errors.New("x-forwarded-for entry malformed")
	// ErrForwardedOnlyTrusted: every entry is a trusted proxy.
	ErrForwardedOnlyTrusted = errors.New("x-forwarded-for names only trusted proxies")
)

// Other errors.
var (
	// ErrPeerInvalid: the request's TCP peer address does not parse.
	ErrPeerInvalid = errors.New("peer address invalid")
	// ErrTrustedProxyPrefix: a trusted-proxies entry is a network prefix
	// instead of a single address (startup failure).
	ErrTrustedProxyPrefix = errors.New("trusted proxy must be a single address (bare, /32 or /128); put proxy-only networks into the trusted proxy networks setting")
	// ErrTrustedProxyInvalid: a trusted-proxy entry does not parse
	// (startup failure).
	ErrTrustedProxyInvalid = errors.New("trusted proxy entry invalid")
	// ErrInvalidLimit: a negative header limit was configured.
	ErrInvalidLimit = errors.New("forwarded header limit invalid")
)

// Config is the trusted-proxy configuration. It is fixed when the
// Resolver is built and never changed afterwards.
type Config struct {
	// TrustedProxies are single addresses (bare, /32 or /128) of reverse
	// proxies whose X-Forwarded-For header counts. Any other prefix fails.
	TrustedProxies []string
	// TrustedProxyNetworks are networks that contain reverse proxies and
	// no clients. Each one is logged at startup with that statement.
	TrustedProxyNetworks []string
	// MaxHeaderBytes is the combined X-Forwarded-For byte limit. Zero
	// means DefaultMaxHeaderBytes.
	MaxHeaderBytes int
	// MaxEntries is the X-Forwarded-For entry limit. Zero means
	// DefaultMaxEntries.
	MaxEntries int
}

// Resolver determines client addresses. It is safe for concurrent use.
type Resolver struct {
	single     map[netip.Addr]struct{}
	nets       []netip.Prefix
	maxBytes   int
	maxEntries int
}

// Result is a resolved request: the client address and the TCP peer
// address, both normalised, and whether the client address came from
// X-Forwarded-For.
type Result struct {
	Client    netip.Addr
	Peer      netip.Addr
	Forwarded bool
}

// New validates cfg and builds a Resolver. Every trusted proxy network is
// logged to log as proxy-only. Errors are meant to fail startup.
func New(cfg Config, log *slog.Logger) (*Resolver, error) {
	if cfg.MaxHeaderBytes < 0 || cfg.MaxEntries < 0 {
		return nil, ErrInvalidLimit
	}
	r := &Resolver{
		single:     make(map[netip.Addr]struct{}, len(cfg.TrustedProxies)),
		maxBytes:   cfg.MaxHeaderBytes,
		maxEntries: cfg.MaxEntries,
	}
	if r.maxBytes == 0 {
		r.maxBytes = DefaultMaxHeaderBytes
	}
	if r.maxEntries == 0 {
		r.maxEntries = DefaultMaxEntries
	}
	for i, s := range cfg.TrustedProxies {
		a, err := parseSingle(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxies entry %d: %w", i+1, err)
		}
		r.single[a] = struct{}{}
	}
	for i, s := range cfg.TrustedProxyNetworks {
		p, err := parseNetwork(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy networks entry %d: %w", i+1, err)
		}
		r.nets = append(r.nets, p)
		if log != nil {
			log.Info("trusted proxy network: networks that contain reverse proxies and no clients", "network", p.String())
		}
	}
	return r, nil
}

// parseSingle parses a trusted-proxies entry: a bare address (normalised
// like every other address) or a /32 or /128 prefix.
func parseSingle(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := Normalize(s)
		if err != nil {
			return netip.Addr{}, ErrTrustedProxyInvalid
		}
		return a, nil
	}
	p, err := parsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if p.Bits() != p.Addr().BitLen() {
		return netip.Addr{}, ErrTrustedProxyPrefix
	}
	return p.Addr(), nil
}

// parseNetwork parses a trusted-proxy-networks entry, which must be in
// prefix form.
func parseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, ErrTrustedProxyInvalid
	}
	return parsePrefix(s)
}

// parsePrefix parses a prefix, unmaps an IPv4-mapped IPv6 prefix to its
// IPv4 form and masks it.
func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, ErrTrustedProxyInvalid
	}
	a, bits := p.Addr(), p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, ErrTrustedProxyInvalid
		}
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked(), nil
}

// Normalize parses an address the same way for the TCP peer, every
// X-Forwarded-For entry and every configured trusted proxy: surrounding
// blanks and a port (a.b.c.d:port, [v6]:port) are stripped, an IPv6 zone
// ID is stripped and an IPv4-mapped IPv6 address is unmapped.
func Normalize(s string) (netip.Addr, error) {
	s = strings.Trim(s, " \t")
	if s == "" {
		return netip.Addr{}, errors.New("empty address")
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		ap, perr := netip.ParseAddrPort(s)
		if perr != nil {
			return netip.Addr{}, errors.New("not an IP address")
		}
		a = ap.Addr()
	}
	return a.WithZone("").Unmap(), nil
}

// HasTrustedProxies reports whether any trusted proxy or trusted proxy
// network is configured.
func (r *Resolver) HasTrustedProxies() bool {
	return len(r.single) > 0 || len(r.nets) > 0
}

// trusted reports whether the normalised address a is a trusted proxy.
func (r *Resolver) trusted(a netip.Addr) bool {
	if _, ok := r.single[a]; ok {
		return true
	}
	for _, p := range r.nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolve determines the client address of req. On a refused forwarded
// header the returned Result still carries the peer address (for logging)
// and the error is exactly one of the ErrForwarded* sentinels.
func (r *Resolver) Resolve(req *http.Request) (Result, error) {
	peer, err := Normalize(req.RemoteAddr)
	if err != nil {
		return Result{}, ErrPeerInvalid
	}
	if !r.trusted(peer) {
		return Result{Client: peer, Peer: peer}, nil
	}
	res := Result{Peer: peer}
	client, err := r.forwardedClient(req.Header.Values(headerXFF))
	if err != nil {
		return res, err
	}
	res.Client, res.Forwarded = client, true
	return res, nil
}

// forwardedClient applies the checks in their fixed order: (a) missing,
// (b) byte size before splitting, (c) entry count before parsing, (d)
// every entry parses, (e) the rightmost untrusted entry is the client.
func (r *Resolver) forwardedClient(lines []string) (netip.Addr, error) {
	if len(lines) == 0 {
		return netip.Addr{}, ErrForwardedMissing
	}
	joined := strings.Join(lines, ", ")
	if len(joined) > r.maxBytes {
		return netip.Addr{}, ErrForwardedTooLong
	}
	if strings.Count(joined, ",")+1 > r.maxEntries {
		return netip.Addr{}, ErrForwardedTooManyEntries
	}
	parts := strings.Split(joined, ",")
	addrs := make([]netip.Addr, len(parts))
	for i, p := range parts {
		a, err := Normalize(p)
		if err != nil {
			return netip.Addr{}, ErrForwardedMalformed
		}
		addrs[i] = a
	}
	for i := len(addrs) - 1; i >= 0; i-- {
		if !r.trusted(addrs[i]) {
			return addrs[i], nil
		}
	}
	return netip.Addr{}, ErrForwardedOnlyTrusted
}

// WarnListener logs a startup warning when the enrollment download is
// enabled, no trusted proxy is configured and the listener is on a
// loopback, private, link-local or wildcard address (or a host name):
// then the server is most likely behind a reverse proxy and every client
// shares the proxy's rate-limit bucket.
func (r *Resolver) WarnListener(log *slog.Logger, listen string, enrollEnabled bool) {
	if log == nil || !enrollEnabled || r.HasTrustedProxies() {
		return
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host != "" {
		a, err := Normalize(host)
		if err == nil && !a.IsLoopback() && !a.IsPrivate() && !a.IsUnspecified() &&
			!a.IsLinkLocalUnicast() {
			return
		}
	}
	log.Warn("enrollment download enabled without trusted proxies on a non-public listener: all clients behind a reverse proxy share one rate-limit bucket; configure the trusted proxies setting",
		"listen", listen)
}
