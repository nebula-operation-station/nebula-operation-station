// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	nfresult "github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
)

// listenerSource is a Source with one canned result for every host.
type listenerSource struct {
	res Result
	ok  bool
	err error
}

func (s listenerSource) LatestNetFacts(context.Context, string) (Result, bool, error) {
	return s.res, s.ok, s.err
}

// listenerNow is the reader's clock in every test.
var listenerNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// listenerReader returns a reader over one result of host-a, finished at
// finished, whose socket table is ss.
func listenerReader(t *testing.T, finished time.Time, ss string) ListenerReader {
	t.Helper()
	doc := netFactsDocWith(t, "host-a", []byte(ss), nil)
	return ListenerReader{
		Src: listenerSource{res: Result{ExecutionID: "e1", Host: "host-a", Finished: finished, Data: doc}, ok: true},
		Now: func() time.Time { return listenerNow },
	}
}

// TestListenersOfFreshFactsOwnListeners: the host's own listening sockets
// are returned sorted by protocol and port, once per (protocol, port); the
// peer side of an established connection is never a listener.
func TestListenersOfFreshFactsOwnListeners(t *testing.T) {
	ss := strings.Join([]string{
		"tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
		"tcp   LISTEN 0 128 [::]:22 [::]:*",
		"tcp   LISTEN 0 511 *:443 *:*",
		"udp   UNCONN 0 0 0.0.0.0:53 0.0.0.0:*",
		"tcp   ESTAB 0 0 10.0.0.5:22 10.0.0.9:50000",
		"tcp   ESTAB 0 0 10.0.0.5:40000 10.0.0.7:5432",
		"udp   UNCONN 0 0 10.0.0.5:51000 10.0.0.8:123",
		"",
	}, "\n")
	finished := listenerNow.Add(-time.Minute)
	got, reportedAt, err := listenerReader(t, finished, ss).ListenersOf(context.Background(), "host-a")
	if err != nil {
		t.Fatalf("ListenersOf: %v", err)
	}
	want := []ListeningPort{{Protocol: "tcp", Port: 22}, {Protocol: "udp", Port: 53}, {Protocol: "tcp", Port: 443}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
	if !reportedAt.Equal(finished) {
		t.Errorf("reportedAt = %v, want %v", reportedAt, finished)
	}
}

// TestListenersOfManyPortsAreNotUnknown: a host with more listening ports
// than the projection lists (40) is still known. All distinct ports are
// returned, sorted by port then protocol, so the projection's cap keeps
// the first MaxPortsPerHost of them and counts the rest.
func TestListenersOfManyPortsAreNotUnknown(t *testing.T) {
	const n = 40
	var lines []string
	for p := n; p >= 1; p-- { // reversed on purpose: the order must come from the reader
		lines = append(lines, fmt.Sprintf("tcp   LISTEN 0 128 0.0.0.0:%d 0.0.0.0:*", 1000+p))
	}
	got, _, err := listenerReader(t, listenerNow.Add(-time.Minute), strings.Join(lines, "\n")+"\n").ListenersOf(context.Background(), "host-a")
	if err != nil {
		t.Fatalf("ListenersOf with %d ports: %v, want the ports, not unknown", n, err)
	}
	if len(got) != n {
		t.Fatalf("got %d ports, want %d", len(got), n)
	}
	for i, p := range got {
		if want := 1001 + i; p.Port != want || p.Protocol != "tcp" {
			t.Fatalf("ports[%d] = %+v, want tcp %d (sorted by port)", i, p, want)
		}
	}
}

// TestListenersOfSortedByPortThenProtocol: the same port on tcp and udp is
// listed twice, tcp first, and ports come in ascending order.
func TestListenersOfSortedByPortThenProtocol(t *testing.T) {
	ss := strings.Join([]string{
		"tcp   LISTEN 0 128 0.0.0.0:443 0.0.0.0:*",
		"udp   UNCONN 0 0 0.0.0.0:443 0.0.0.0:*",
		"udp   UNCONN 0 0 0.0.0.0:53 0.0.0.0:*",
		"tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
		"",
	}, "\n")
	got, _, err := listenerReader(t, listenerNow.Add(-time.Minute), ss).ListenersOf(context.Background(), "host-a")
	if err != nil {
		t.Fatalf("ListenersOf: %v", err)
	}
	want := []ListeningPort{{Protocol: "tcp", Port: 22}, {Protocol: "udp", Port: 53}, {Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 443}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
}

// TestListenersOfStaleOrMissingFactsAreUnknown: facts older than
// ListenerStaleAfter, facts without a successful result, facts of another
// host, a finish time in the future and facts that do not parse all read
// as unknown listeners (ErrListenersUnknown), never as no listeners.
func TestListenersOfStaleOrMissingFactsAreUnknown(t *testing.T) {
	ss := "tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
	fresh := listenerReader(t, listenerNow.Add(-ListenerStaleAfter), ss)
	tests := []struct {
		name   string
		reader func() ListenerReader
		want   bool // true: fresh facts, ports returned
	}{
		{"exactly at the stale limit is fresh", func() ListenerReader { return fresh }, true},
		{"one second older is stale", func() ListenerReader {
			return listenerReader(t, listenerNow.Add(-ListenerStaleAfter-time.Second), ss)
		}, false},
		{"no successful result", func() ListenerReader {
			r := fresh
			r.Src = listenerSource{ok: false}
			return r
		}, false},
		{"result of another host", func() ListenerReader {
			r := fresh
			src := r.Src.(listenerSource)
			src.res.Host = "host-b"
			r.Src = src
			return r
		}, false},
		{"finish time in the future", func() ListenerReader {
			return listenerReader(t, listenerNow.Add(time.Hour), ss)
		}, false},
		{"result does not parse", func() ListenerReader {
			r := fresh
			src := r.Src.(listenerSource)
			src.res.Data = []byte(`{"format":"net-facts-v1","unexpected":true}`)
			r.Src = src
			return r
		}, false},
		{"socket table incomplete", func() ListenerReader {
			return listenerReader(t, listenerNow.Add(-time.Minute), ss+"garbage line\n")
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := tc.reader().ListenersOf(context.Background(), "host-a")
			if tc.want {
				if err != nil || len(got) != 1 {
					t.Fatalf("ports = %v, err = %v; want one port", got, err)
				}
				return
			}
			if !errors.Is(err, ErrListenersUnknown) {
				t.Fatalf("err = %v, want ErrListenersUnknown", err)
			}
			if got != nil {
				t.Errorf("ports = %v, want none", got)
			}
		})
	}
}

// TestListenersOfStoreErrorFails: a failing store read is a real error,
// not unknown listeners; it must stop the read (fail closed).
func TestListenersOfStoreErrorFails(t *testing.T) {
	boom := errors.New("database is locked")
	r := ListenerReader{Src: listenerSource{err: boom}, Now: func() time.Time { return listenerNow }}
	_, _, err := r.ListenersOf(context.Background(), "host-a")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the store error", err)
	}
	if errors.Is(err, ErrListenersUnknown) {
		t.Errorf("a store error must not read as unknown listeners")
	}
}

// TestListenersOfUsesOnlyDecodedSockets: a result of the right shape but
// with a section the decoder marks invalid is unknown; the decoder is the
// only way to read sockets from the stored bytes.
func TestListenersOfUsesOnlyDecodedSockets(t *testing.T) {
	doc := netFactsDocWith(t, "host-a", []byte("tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"),
		map[string]fixtureSection{"sockets": {Status: "failed"}})
	if _, err := nfresult.Decode(doc); err != nil {
		t.Fatalf("fixture must decode: %v", err)
	}
	r := ListenerReader{
		Src: listenerSource{res: Result{Host: "host-a", Finished: listenerNow.Add(-time.Minute), Data: doc}, ok: true},
		Now: func() time.Time { return listenerNow },
	}
	_, _, err := r.ListenersOf(context.Background(), "host-a")
	if !errors.Is(err, ErrListenersUnknown) {
		t.Fatalf("err = %v, want ErrListenersUnknown for a failed sockets section", err)
	}
}
