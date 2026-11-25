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
- At most 32 distinct pairs (`MaxListenersPerHost`, ADR 0016 D4). More is
  unknown, not a cut list.

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
  unavailable (a dropped line may have been a listener),
- more than 32 listening ports.

These return an error wrapping `trafficingest.ErrListenersUnknown` with the
reason. A failed store read is a different, plain error and fails the read.

`cmd/nebula-server` maps unknown facts to `errOpsListenersUnknown`. The
projection in `internal/opsfacts` still treats any listener error as a
failed read, so a host with unknown listeners currently fails the work
list. The intended behaviour is that `opsfacts` leaves such a host out of
the lab groups and records an audited skip with the reason. That change is
still open; it is outside this change's paths.

## Not covered

- The source does not wire the ops projector in `cmd/nebula-server/main.go`.
- Listeners bound to loopback are listed like any other listener.
