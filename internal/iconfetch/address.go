// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netpolicy"
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

// forbiddenAddr reports whether the dialer must not connect to addr, with a
// fixed reason: netpolicy.NonPublic, i.e. everything servicecheck treats as
// internal (every non-mapped IPv6 address included) plus the IANA
// special-purpose ranges. Both default icon sources are reachable over IPv4.
func forbiddenAddr(addr netip.Addr) (string, bool) {
	return netpolicy.NonPublic(addr)
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
