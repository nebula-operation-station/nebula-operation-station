# Ops work list: listener source (ADR 0016 D4)

Status of this note: implementation note (Claude, uh02s), not a spec.

## What the source is

The listening ports of a host for the ops projection come from the host's
own latest stored `net.facts` result (`ss -tinuaH`, ADR 0009 D1). No new
table is written: the execution record already holds the result.

- `trafficingest.ListenerReader.ListenersOf` reads the latest successful
  result of the host and returns its listening sockets (TCP `LISTEN`, UDP
  unconnected), as distinct (protocol, port) pairs, sorted.
- Only the host's own result counts (the result's host must equal the
  requested host). Sockets that the host reports as peers are never
  listeners, so a peer's view cannot create a port on another host.
- All distinct pairs are returned, sorted by port, then protocol. A host
  with many listening ports is known, not unknown. The list limit is the
  projection's: `opsfacts.MaxPortsPerHost` (32, ADR 0016 D4) lists the first
  ports and `PortsOmitted` counts the rest. The socket section is bounded by
  the decoder (`MaxSection`, 256 KiB), so the list is bounded too.

## Freshness rule

- `NetFactsInterval` is 5 minutes (ADR 0009 D1, default cadence).
- `ListenerStaleAfter` is 3 × `NetFactsInterval` (15 minutes), the same
  three-missed-intervals rule as `netdevinventory.StaleAfterIntervals`.
  A result exactly at the limit is fresh; one second older is stale.

## Unknown listeners

A host whose listeners cannot be shown is **unknown**, not "no ports":

- no successful `net.facts` result,
- latest result older than `ListenerStaleAfter`,
- result of another host, or a finish time in the future,
- result that does not parse, or a socket table that is incomplete or
  unavailable (a dropped line may have been a listener).

These return an error wrapping `trafficingest.ErrListenersUnknown` with the
reason. A failed store read is a different, plain error and fails the read.

`cmd/nebula-server` wraps unknown facts with `opsfacts.ErrListenersUnknown`.
The projection in `internal/opsfacts` then leaves that host's groups out of
the lab part and writes one audit skip for the host (scope `listeners`, rule
`listening ports unknown`). The read succeeds for the other hosts. Any other
listener error still fails the projection (fail-closed).

## Not covered

- The source does not wire the ops projector in `cmd/nebula-server/main.go`
  or `ops.go`; the production wiring of `newOpsVulnListeners` is the follow-up
  ticket uh02, after this change.
- Listeners bound to loopback are listed like any other listener.
