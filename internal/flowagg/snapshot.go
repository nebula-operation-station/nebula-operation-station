// SPDX-License-Identifier: AGPL-3.0-or-later

// Package flowagg turns per-host socket snapshots into hourly flow
// aggregates for the traffic map (ADR 0009, TM05).
//
// The pipeline is pure and has no storage of its own:
//
//  1. A Snapshot lists the TCP/UDP sockets of one reporting host with their
//     cumulative byte counters and the host's listening sockets.
//  2. Diff compares two snapshots of the same host. Counters that went down
//     and sockets that vanished are resets; the result never goes negative
//     and is flagged as a lower bound whenever bytes may have been missed.
//     The first snapshot of a host is only a baseline and counts nothing.
//  3. Classify decides which end of each socket is the server (the end that
//     matches a listener), drops the ephemeral client port and folds the
//     sockets into canonical flow keys.
//  4. Aggregator keeps hourly buckets per flow key, merges the reports of
//     both ends without double counting and answers TopN and overview
//     queries.
//
// Everything a managed host reports is untrusted: snapshots are validated
// against the size limits below before any work is done, and every
// aggregate is bounded.
package flowagg

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits for a single snapshot. A snapshot that exceeds one is rejected as a
// whole.
const (
	// MaxSocketsPerSnapshot bounds the sockets of one host report.
	MaxSocketsPerSnapshot = 65536
	// MaxListenersPerSnapshot bounds the listeners of one host report.
	MaxListenersPerSnapshot = 4096
	// MaxHostIDLen bounds the reporting host identifier in bytes.
	MaxHostIDLen = 255
	// MaxTierLen bounds the source tier name in bytes.
	MaxTierLen = 32
)

// ErrInvalidSnapshot marks a snapshot that fails validation.
var ErrInvalidSnapshot = errors.New("invalid snapshot")

// ErrSnapshotMismatch marks two snapshots that cannot be compared (other
// host, other tier or not strictly later).
var ErrSnapshotMismatch = errors.New("snapshots not comparable")

// Proto is the transport protocol of a socket.
type Proto uint8

// Supported protocols.
const (
	TCP Proto = 6
	UDP Proto = 17
)

// String returns "tcp", "udp" or "proto(N)".
func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("proto(%d)", uint8(p))
}

func (p Proto) valid() bool { return p == TCP || p == UDP }

// Socket is one connected socket as seen by the reporting host. The byte
// counters are cumulative since the socket was created and are counted from
// the local end: BytesSent leaves Local towards Remote.
type Socket struct {
	Proto  Proto
	Local  netip.AddrPort
	Remote netip.AddrPort
	// Cookie optionally identifies the socket instance (for example the
	// kernel socket cookie or inode). Zero means unknown. A different cookie
	// on the same tuple is a new connection. Collectors should send it:
	// without a cookie, a socket closed and reopened on the same tuple
	// between two snapshots looks like one socket, and if its new counters
	// are higher than the old ones the difference counts as plain growth,
	// so bytes are undercounted without a LowerBound flag.
	Cookie        uint64
	BytesSent     uint64
	BytesReceived uint64
}

// Listener is a listening socket. An unspecified address (0.0.0.0 or ::)
// matches every local address with the same port and protocol.
type Listener struct {
	Proto Proto
	Addr  netip.AddrPort
}

// Snapshot is the socket table of one host at one point in time.
type Snapshot struct {
	// Host identifies the reporting host.
	Host string
	// Tier names the data source (for example "socket" or "conntrack").
	// Only reports of the same tier are merged.
	Tier      string
	Time      time.Time
	Sockets   []Socket
	Listeners []Listener
}

// socketID is the identity of a socket across snapshots.
type socketID struct {
	proto  Proto
	cookie uint64
	local  netip.AddrPort
	remote netip.AddrPort
}

func (s Socket) id() socketID {
	return socketID{proto: s.Proto, cookie: s.Cookie, local: s.Local, remote: s.Remote}
}

func compareSocketID(a, b socketID) int {
	if c := cmp.Compare(a.proto, b.proto); c != 0 {
		return c
	}
	if c := a.local.Compare(b.local); c != 0 {
		return c
	}
	if c := a.remote.Compare(b.remote); c != 0 {
		return c
	}
	return cmp.Compare(a.cookie, b.cookie)
}

// normalizeAddrPort unmaps IPv4-mapped IPv6 addresses so that
// [::ffff:10.0.0.1]:22 and 10.0.0.1:22 are the same endpoint.
func normalizeAddrPort(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func normalizeSocket(s Socket) Socket {
	s.Local = normalizeAddrPort(s.Local)
	s.Remote = normalizeAddrPort(s.Remote)
	return s
}

// validName checks host and tier identifiers: non-empty, bounded, valid
// UTF-8 and free of control characters.
func validName(s string, maxLen int) error {
	switch {
	case s == "":
		return errors.New("empty")
	case len(s) > maxLen:
		return fmt.Errorf("longer than %d bytes", maxLen)
	case !utf8.ValidString(s):
		return errors.New("not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("contains control characters")
		}
	}
	return nil
}

// validTier accepts lower-case ASCII letters, digits, '-' and '_'.
func validTier(s string) error {
	if err := validName(s, MaxTierLen); err != nil {
		return err
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return errors.New("only a-z, 0-9, '-' and '_' allowed")
		}
	}
	return nil
}

func validEndpoint(a netip.AddrPort) error {
	switch {
	case !a.IsValid():
		return errors.New("invalid address")
	case a.Port() == 0:
		return errors.New("port 0")
	case a.Addr().Unmap().IsUnspecified():
		return errors.New("unspecified address")
	}
	return nil
}

// Validate checks the snapshot against the package limits. It reports every
// problem as ErrInvalidSnapshot. Two sockets with the same protocol, cookie
// and (unmapped) tuple are a duplicate and rejected.
func (s *Snapshot) Validate() error {
	if err := validName(s.Host, MaxHostIDLen); err != nil {
		return fmt.Errorf("%w: host: %v", ErrInvalidSnapshot, err)
	}
	if err := validTier(s.Tier); err != nil {
		return fmt.Errorf("%w: host %q: tier: %v", ErrInvalidSnapshot, s.Host, err)
	}
	if s.Time.IsZero() {
		return fmt.Errorf("%w: host %q: zero time", ErrInvalidSnapshot, s.Host)
	}
	if len(s.Sockets) > MaxSocketsPerSnapshot {
		return fmt.Errorf("%w: host %q: %d sockets exceed limit %d", ErrInvalidSnapshot, s.Host, len(s.Sockets), MaxSocketsPerSnapshot)
	}
	if len(s.Listeners) > MaxListenersPerSnapshot {
		return fmt.Errorf("%w: host %q: %d listeners exceed limit %d", ErrInvalidSnapshot, s.Host, len(s.Listeners), MaxListenersPerSnapshot)
	}
	seen := make(map[socketID]struct{}, len(s.Sockets))
	for i, sk := range s.Sockets {
		if !sk.Proto.valid() {
			return fmt.Errorf("%w: host %q: socket %d: unsupported protocol %d", ErrInvalidSnapshot, s.Host, i, uint8(sk.Proto))
		}
		if err := validEndpoint(sk.Local); err != nil {
			return fmt.Errorf("%w: host %q: socket %d: local: %v", ErrInvalidSnapshot, s.Host, i, err)
		}
		if err := validEndpoint(sk.Remote); err != nil {
			return fmt.Errorf("%w: host %q: socket %d: remote: %v", ErrInvalidSnapshot, s.Host, i, err)
		}
		id := normalizeSocket(sk).id()
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: host %q: socket %d: duplicate socket", ErrInvalidSnapshot, s.Host, i)
		}
		seen[id] = struct{}{}
	}
	for i, l := range s.Listeners {
		if !l.Proto.valid() {
			return fmt.Errorf("%w: host %q: listener %d: unsupported protocol %d", ErrInvalidSnapshot, s.Host, i, uint8(l.Proto))
		}
		if !l.Addr.IsValid() || l.Addr.Port() == 0 {
			return fmt.Errorf("%w: host %q: listener %d: invalid address", ErrInvalidSnapshot, s.Host, i)
		}
	}
	return nil
}

// SocketDelta is the traffic of one socket between two snapshots, counted
// from the local end like Socket.
type SocketDelta struct {
	// Socket is the socket as seen in the newer snapshot, with IPv4-mapped
	// addresses unmapped.
	Socket   Socket
	Sent     uint64
	Received uint64
	// New is set when the counters start from zero within the interval: the
	// socket did not exist in the previous snapshot, or its counters were
	// reset. New sockets count as one connection.
	New bool
	// Reset is set when the counters went down. The bytes sent between the
	// previous snapshot and the reset are lost.
	Reset bool
}

// Delta is the difference between two snapshots of one host.
type Delta struct {
	Host string
	Tier string
	// From is the time of the previous snapshot, or of the current one if
	// there was none. To is the time of the current snapshot.
	From, To time.Time
	// Baseline is set when there was no previous snapshot. Sockets and
	// Vanished are then empty: lifetime counters have no known start time,
	// so they cannot be assigned to hours and are not counted.
	Baseline bool
	// Sockets holds one entry per socket of the current snapshot, sorted by
	// protocol, local, remote and cookie.
	Sockets []SocketDelta
	// Vanished lists the sockets of the previous snapshot that are gone,
	// sorted like Sockets. They carry no bytes but mark their flows as a
	// lower bound.
	Vanished []Socket
	// LowerBound is set when bytes may be missing: a counter was reset or a
	// socket vanished between the snapshots (its last bytes are unknown).
	LowerBound bool
}

// Diff computes the traffic between prev and cur, which must be snapshots
// of the same host and tier with prev strictly older.
//
// prev may be nil for the first snapshot of a host. The result is then a
// baseline (Delta.Baseline) with no sockets and the zero-length interval
// cur.Time..cur.Time: the cumulative counters of sockets that already
// existed say nothing about when their bytes flowed, and booking them into
// the current hour would count bytes that the other end of the flow
// reported in earlier hours a second time. Traffic is counted from the next
// snapshot on. A socket that appears after the baseline counts from its
// start.
//
// The rules keep every value non-negative: a counter that decreased (reset
// or wrap) counts its current value as the bytes since the reset, and a
// vanished socket contributes nothing. Both cases set Delta.LowerBound.
func Diff(prev, cur *Snapshot) (Delta, error) {
	if cur == nil {
		return Delta{}, fmt.Errorf("%w: no current snapshot", ErrSnapshotMismatch)
	}
	if err := cur.Validate(); err != nil {
		return Delta{}, fmt.Errorf("current snapshot: %w", err)
	}
	d := Delta{Host: cur.Host, Tier: cur.Tier, From: cur.Time, To: cur.Time}
	if prev == nil {
		d.Baseline = true
		return d, nil
	}
	if err := prev.Validate(); err != nil {
		return Delta{}, fmt.Errorf("previous snapshot: %w", err)
	}
	switch {
	case prev.Host != cur.Host:
		return Delta{}, fmt.Errorf("%w: host %q vs %q", ErrSnapshotMismatch, prev.Host, cur.Host)
	case prev.Tier != cur.Tier:
		return Delta{}, fmt.Errorf("%w: host %q: tier %q vs %q", ErrSnapshotMismatch, cur.Host, prev.Tier, cur.Tier)
	case !prev.Time.Before(cur.Time):
		return Delta{}, fmt.Errorf("%w: host %q: previous snapshot is not older", ErrSnapshotMismatch, cur.Host)
	}
	d.From = prev.Time
	old := make(map[socketID]Socket, len(prev.Sockets))
	for _, s := range prev.Sockets {
		s = normalizeSocket(s)
		old[s.id()] = s
	}
	d.Sockets = make([]SocketDelta, 0, len(cur.Sockets))
	matched := 0
	for _, s := range cur.Sockets {
		s = normalizeSocket(s)
		sd := SocketDelta{Socket: s}
		p, ok := old[s.id()]
		switch {
		case !ok:
			sd.Sent, sd.Received, sd.New = s.BytesSent, s.BytesReceived, true
		case s.BytesSent < p.BytesSent || s.BytesReceived < p.BytesReceived:
			// Both counters restart together on a reset; treating them as a
			// pair keeps sent and received consistent.
			sd.Sent, sd.Received, sd.New, sd.Reset = s.BytesSent, s.BytesReceived, true, true
			d.LowerBound = true
		default:
			sd.Sent, sd.Received = s.BytesSent-p.BytesSent, s.BytesReceived-p.BytesReceived
		}
		if ok {
			matched++
		}
		d.Sockets = append(d.Sockets, sd)
	}
	if matched < len(old) {
		// At least one socket vanished; its bytes since prev are unknown.
		d.LowerBound = true
		seen := make(map[socketID]struct{}, len(cur.Sockets))
		for _, s := range cur.Sockets {
			seen[normalizeSocket(s).id()] = struct{}{}
		}
		for id, s := range old {
			if _, ok := seen[id]; !ok {
				d.Vanished = append(d.Vanished, s)
			}
		}
		slices.SortFunc(d.Vanished, func(a, b Socket) int { return compareSocketID(a.id(), b.id()) })
	}
	slices.SortFunc(d.Sockets, func(a, b SocketDelta) int {
		return compareSocketID(a.Socket.id(), b.Socket.id())
	})
	return d, nil
}
