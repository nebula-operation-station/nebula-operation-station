// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	// MaxListenersPerHost bounds the distinct (protocol, port) pairs one
	// host may expose to the ops work list (ADR 0016 D4). A host with more
	// is unknown, never a cut list.
	MaxListenersPerHost = 32
)

// ErrListenersUnknown is returned (wrapped, with the reason) when the
// stored facts cannot show the host's listening ports: none stored, stale,
// not of the host, unusable, incomplete or over MaxListenersPerHost. The
// caller must treat the host's listeners as unknown, not as none.
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
	ports, ok := listeningPorts(facts.Sockets.Entries)
	if !ok {
		return nil, res.Finished, unknownListeners(fmt.Sprintf("more than %d listening ports", MaxListenersPerHost))
	}
	return ports, res.Finished, nil
}

// unknownListeners wraps ErrListenersUnknown with the reason.
func unknownListeners(reason string) error {
	return fmt.Errorf("%w: %s", ErrListenersUnknown, reason)
}

// listeningPorts returns the distinct listening (protocol, port) pairs of
// socks, sorted. ok is false when there are more than MaxListenersPerHost.
func listeningPorts(socks []hostnet.Socket) (ports []ListeningPort, ok bool) {
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
	if len(ports) > MaxListenersPerHost {
		return nil, false
	}
	slices.SortFunc(ports, func(a, b ListeningPort) int {
		if a.Protocol != b.Protocol {
			if a.Protocol < b.Protocol {
				return -1
			}
			return 1
		}
		return a.Port - b.Port
	})
	return ports, true
}
