// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// Limits on DNS answers.
const (
	// maxResolvedAddrs bounds how many DNS answers are checked; the rest
	// are ignored and never dialed.
	maxResolvedAddrs = 16
	// maxDialAttempts bounds how many checked addresses are tried.
	maxDialAttempts = 4
)

// ErrAddress marks a connection the dialer refused: a host or port outside
// the policy, or a DNS answer with an internal address.
var ErrAddress = errors.New("icon host address refused")

// Resolver resolves a host name to IP addresses. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// extraReserved are IANA special-purpose IPv4 ranges that
// internal/executions/servicecheck does not list but that an icon source
// on the public Internet never uses.
var extraReserved = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("192.0.0.0/24"), "192.0.0.0/24 (IETF protocol assignments)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "192.0.2.0/24 (documentation)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "198.18.0.0/15 (benchmarking)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "198.51.100.0/24 (documentation)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "203.0.113.0/24 (documentation)"},
}

// forbiddenAddr reports whether the dialer must not connect to addr, with a
// fixed reason. The IPv4 table mirrors reserved() in
// internal/executions/servicecheck (which is unexported) plus extraReserved.
// Like servicecheck, every non-IPv4 address is refused: IPv6 has too many
// ranges that embed or route to IPv4 (NAT64, 6to4, Teredo, mapped) and both
// default icon sources are reachable over IPv4.
func forbiddenAddr(addr netip.Addr) (string, bool) {
	if !addr.IsValid() {
		return "invalid address", true
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return "IPv6 address", true
	}
	o := addr.As4()
	switch {
	case o[0] == 0:
		return "0.0.0.0/8 (this network)", true
	case o[0] == 10:
		return "10.0.0.0/8 (private)", true
	case o[0] == 127:
		return "127.0.0.0/8 (loopback)", true
	case o[0] == 169 && o[1] == 254:
		return "169.254.0.0/16 (link-local, incl. 169.254.169.254 metadata)", true
	case o[0] == 100 && o[1] >= 64 && o[1] <= 127:
		return "100.64.0.0/10 (CGNAT)", true
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
		return "172.16.0.0/12 (private)", true
	case o[0] == 192 && o[1] == 168:
		return "192.168.0.0/16 (private)", true
	case o[0] >= 224:
		return "224.0.0.0/4 and above (multicast/reserved)", true
	}
	for _, r := range extraReserved {
		if r.prefix.Contains(addr) {
			return r.reason, true
		}
	}
	return "", false
}

// dialer resolves the host itself, refuses the whole answer if any address
// is forbidden, and connects only to the addresses it checked. The HTTP
// transport never sees a host name it could resolve again.
type dialer struct {
	resolver Resolver
	allow    []string
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext implements http.Transport.DialContext.
func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("%w: network %q", ErrAddress, network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAddress, err)
	}
	if port != "443" {
		return nil, fmt.Errorf("%w: port %s is not 443", ErrAddress, port)
	}
	// Defence in depth: the request URL already passed ValidateURL.
	if _, err := ValidateURL("https://"+host+"/", d.allow); err != nil {
		return nil, fmt.Errorf("%w: host: %v", ErrAddress, err)
	}
	ips, err := d.resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s has no addresses", ErrAddress, host)
	}
	if len(ips) > maxResolvedAddrs {
		ips = ips[:maxResolvedAddrs]
	}
	for _, ip := range ips {
		if reason, bad := forbiddenAddr(ip); bad {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrAddress, host, reason)
		}
	}
	var lastErr error
	for i, ip := range ips {
		if i == maxDialAttempts {
			break
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(443)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("connect %s: %w", host, lastErr)
}
