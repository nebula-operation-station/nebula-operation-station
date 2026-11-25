// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	nfresult "github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
)

// Listening ports of a host (ADR 0016 D4): the host's own listening sockets
// from its latest stored net.facts result. Only the result of the host
// itself is read; the sockets it reports to peers are never listeners of
// those peers.
const (
	// NetFactsInterval is the cadence of net.facts reads (ADR 0009 D1,
	// default every 5 minutes).
	NetFactsInterval = 5 * time.Minute
	// ListenerStaleAfter is the age after which a stored result no longer
	// shows the host's listeners: three missed intervals, the same rule as
	// netdevinventory.StaleAfterIntervals.
	ListenerStaleAfter = 3 * NetFactsInterval
)

// ErrListenersUnknown is returned (wrapped, with the reason) when the
// stored facts cannot show the host's listening ports: none stored, stale,
// not of the host, unusable or incomplete. The caller must treat the host's
// listeners as unknown, not as none. A host with many listening ports is
// not unknown: the reader returns all of them and the caller's list limit
// (opsfacts.MaxPortsPerHost) decides what is listed and what is counted.
var ErrListenersUnknown = errors.New("listening ports unknown")

// ListeningPort is one listening port of a host.
type ListeningPort struct {
	// Protocol is "tcp" or "udp".
	Protocol string
	// Port is the listening port, 1 to 65535.
	Port int
}

// ListenerReader reads the listening ports of hosts from their stored
// net.facts results.
type ListenerReader struct {
	// Src reads the latest successful net.facts result of a host.
	Src Source
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// ListenersOf returns the distinct listening ports of host, sorted by
// protocol and port, from the host's latest stored net.facts result, and
// the time that result was finished. A result that is missing, stale,
// incomplete or unusable returns an error wrapping ErrListenersUnknown,
// with the time of that result when there is one. Any other error is a
// failed store read and must fail the caller's read.
func (r ListenerReader) ListenersOf(ctx context.Context, host string) ([]ListeningPort, time.Time, error) {
	res, ok, err := r.Src.LatestNetFacts(ctx, host)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("trafficingest: listeners of %s: %w", host, err)
	}
	if !ok {
		return nil, time.Time{}, unknownListeners("no successful net.facts result")
	}
	if res.Host != host {
		return nil, time.Time{}, unknownListeners("latest result is not the host's own")
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	at := now()
	if res.Finished.IsZero() || res.Finished.After(at.Add(maxResultSkew)) {
		return nil, time.Time{}, unknownListeners("finish time of the result not usable")
	}
	if at.Sub(res.Finished) > ListenerStaleAfter {
		return nil, res.Finished, unknownListeners("latest result older than the freshness limit")
	}
	facts, err := nfresult.Decode(res.Data)
	if err != nil {
		return nil, res.Finished, unknownListeners("latest result does not parse")
	}
	sec := facts.Sections[nfresult.SectionSockets]
	if sec.Status != nfresult.StatusOK || sec.Truncated || sec.Invalid || facts.Sockets.Incomplete {
		// A dropped line may have been a listening socket: incomplete means
		// unknown, not "fewer listeners".
		return nil, res.Finished, unknownListeners("socket table incomplete or unavailable")
	}
	return listeningPorts(facts.Sockets.Entries), res.Finished, nil
}

// unknownListeners wraps ErrListenersUnknown with the reason.
func unknownListeners(reason string) error {
	return fmt.Errorf("%w: %s", ErrListenersUnknown, reason)
}

// listeningPorts returns the distinct listening (protocol, port) pairs of
// socks, sorted by port, then protocol. The socket table decoder bounds the
// number of entries, so the result is bounded too.
func listeningPorts(socks []hostnet.Socket) []ListeningPort {
	var ports []ListeningPort
	seen := map[ListeningPort]bool{}
	for proto, ls := range hostnet.Listeners(socks) {
		for _, x := range ls {
			p := ListeningPort{Protocol: string(proto), Port: int(x.Local.Port())}
			if seen[p] {
				continue
			}
			seen[p] = true
			ports = append(ports, p)
		}
	}
	slices.SortFunc(ports, func(a, b ListeningPort) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})
	return ports
}
