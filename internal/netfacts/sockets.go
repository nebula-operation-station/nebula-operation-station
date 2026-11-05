// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits for the `ss -tinuaH` text format (ADR 0009 D1/D3, spec 09). The
// document as a whole is bounded by maxInputSize and the socket count by
// maxEntries.
const (
	// maxSocketLineLen bounds one line of `ss` output in bytes. A TCP
	// info line is a few hundred bytes; a socket line with a long
	// users:(...) list (many worker processes sharing one listener) can
	// reach a few KiB. A longer line is dropped as malformed.
	maxSocketLineLen = 16 << 10
	// maxProcessLen bounds the process (command) name kept for a socket.
	// The kernel limits comm to 15 bytes; longer text is not a real
	// command name and is dropped.
	maxProcessLen = 64
	// maxSockAddrLen bounds one "address:port" column: a bracketed IPv6
	// address with zone (maxAddrLen), "%" and an interface name, ":" and
	// a five-digit port, rounded up.
	maxSockAddrLen = maxAddrLen + maxIfNameLen + 10
	// socketColumns is the number of fixed columns of one socket line:
	// Netid, State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port.
	socketColumns = 6
)

// Proto is the transport protocol of a socket ("tcp" or "udp").
type Proto string

// Transport protocols reported by `ss -tu`.
const (
	// ProtoTCP is a TCP socket.
	ProtoTCP Proto = "tcp"
	// ProtoUDP is a UDP socket.
	ProtoUDP Proto = "udp"
)

// socketStates are the state names `ss` prints (sstate_name in
// iproute2). Any other state drops the socket line.
var socketStates = map[string]bool{
	"UNKNOWN":    true,
	"ESTAB":      true,
	"SYN-SENT":   true,
	"SYN-RECV":   true,
	"FIN-WAIT-1": true,
	"FIN-WAIT-2": true,
	"TIME-WAIT":  true,
	"UNCONN":     true,
	"CLOSE-WAIT": true,
	"LAST-ACK":   true,
	"LISTEN":     true,
	"CLOSING":    true,
}

// Socket is one TCP or UDP socket from `ss -tinuaH`.
type Socket struct {
	// Proto is ProtoTCP or ProtoUDP.
	Proto Proto
	// State is the socket state as `ss` prints it (see socketStates),
	// e.g. "LISTEN", "ESTAB", "UNCONN", "TIME-WAIT".
	State string
	// Local is the local address and port. A wildcard printed as "*"
	// (an IPv6 socket without IPV6_V6ONLY, which also accepts IPv4) is
	// stored as [::] with DualStack set. IPv4-mapped IPv6 addresses are
	// stored as IPv4. A link-local IPv6 address carries the bound
	// interface as its zone.
	Local netip.AddrPort
	// Peer is the remote address and port; port 0 stands for "*" (no
	// peer). The same normalisation as for Local applies; a link-local
	// IPv6 peer carries Dev as its zone.
	Peer netip.AddrPort
	// Dev is the interface the socket is bound to, printed by `ss` as
	// "addr%dev:port" (SO_BINDTODEVICE or the IPv6 scope); empty when
	// unbound. Always a valid interface name (see validIfName).
	Dev string
	// DualStack is true when Local was printed as the "*" wildcard.
	DualStack bool
	// DualStackUnknown is true when the dual-stack state of Local cannot
	// be determined: the host prints the legacy iproute2 wildcard form
	// ":::port" for every IPv6 wildcard regardless of V6ONLY (see
	// parseSocketAddr), so a ":::port" socket and a "*" socket on it are
	// ambiguous. When set, DualStack holds the raw printed form and must
	// not be relied on (Listener.Serves does not claim IPv4 for it).
	DualStackUnknown bool
	// Listening is true for a server-side socket: a TCP socket in state
	// LISTEN, or an unconnected UDP socket (state UNCONN, no peer). An
	// unconnected UDP client socket cannot be told apart and is
	// reported as listening too.
	Listening bool
	// BytesAcked is tcp_info "bytes_acked" (bytes sent and acknowledged
	// by the peer). TCP only; zero when absent or not trustworthy.
	BytesAcked uint64
	// BytesReceived is tcp_info "bytes_received". TCP only; zero when
	// absent or not trustworthy.
	BytesReceived uint64
	// Process is the command name of the first process owning the
	// socket, from a users:(("name",pid=...,fd=...)) column when the
	// input has one (`ss -p`). Printable UTF-8, at most maxProcessLen
	// bytes; empty otherwise. The name is cut at the first `",pid=N,fd=N)`,
	// so a comm containing that text is shortened. comm is freely set by
	// the process: Process is a display hint, never an identity.
	Process string
}

// SocketTable is the parsed result of one `ss -tinuaH` document.
type SocketTable struct {
	// Entries holds the valid sockets in host order.
	Entries []Socket
	// Dropped counts lines that were skipped as malformed: socket lines
	// that failed validation, info lines without a socket, and a
	// truncated last line.
	Dropped int
	// Incomplete is true when the host reported data the parser did not
	// keep: a dropped line (Dropped > 0), a dropped counter or process
	// name, or sockets beyond maxEntries. An incomplete table must be
	// presented as such, never as the complete table (spec 09).
	Incomplete bool
}

// ParseSockets parses the text printed by `ss -tinuaH` (optionally with
// -p) and returns the valid sockets. It is ParseSocketTable without the
// completeness information; callers that present the result as the
// host's socket table must use ParseSocketTable.
func ParseSockets(raw []byte) ([]Socket, error) {
	t, err := ParseSocketTable(raw)
	if err != nil {
		return nil, err
	}
	return t.Entries, nil
}

// ParseSocketTable parses the text printed by `ss -tinuaH`.
//
// Every socket line has the columns Netid, State, Recv-Q, Send-Q, Local
// Address:Port and Peer Address:Port, optionally followed by a
// users:((...)) column. With -i each TCP socket line is followed by one
// or more info lines that start with whitespace; from these only
// "bytes_acked:" and "bytes_received:" are kept, unknown keys are
// ignored.
//
// Validation is strict because everything is untrusted host data: lines
// must be UTF-8 without control characters (tab excepted) and at most
// maxSocketLineLen bytes, the netid must be tcp or udp, the state a known
// `ss` state name, the queues decimal, the addresses IP literals (or "*")
// with an optional interface name and a port. A line that fails is
// skipped and counted in Dropped together with its info lines. A
// users:((...)) column that is not well formed as a whole also drops the
// socket: a process can put a newline into its command name and so split
// the line, and neither part may be mistaken for socket data or for an
// info line (see parseProcess for why a split cannot pass). The fixed
// columns cannot be forged through a command name (comm is at most 15
// bytes and every column is validated), and info lines after a dropped
// socket line are skipped.
//
// A counter that is malformed, out of range, repeated, or on an info line
// that is truncated or invalid is dropped (zero). Input that does not end
// in a newline has a truncated last line: a socket line there is dropped,
// an info line there drops the counters of its socket. Every such loss
// sets Incomplete. The caller must therefore pass the output exactly as
// `ss` printed it, final newline included; net.facts carries it as a
// base64 section (ADR 0009 D1), which keeps the bytes unchanged.
//
// Sockets beyond maxEntries are not parsed and set Incomplete rather
// than failing the document: a busy host easily has more sockets, and a
// truncated model must say so instead of silently dropping data (ADR
// 0009 D7, spec 09). Input above maxInputSize is an error; there is no
// other error.
func ParseSocketTable(raw []byte) (SocketTable, error) {
	if len(raw) > maxInputSize {
		return SocketTable{}, fmt.Errorf("socket document exceeds %d bytes", maxInputSize)
	}
	p := socketParser{t: SocketTable{Entries: []Socket{}}, owner: -1}
	rest := raw
	for len(rest) > 0 {
		line := rest
		complete := false
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest, complete = rest[:i], rest[i+1:], true
		} else {
			rest = nil
		}
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			p.infoLine(line, complete)
			continue
		}
		if !p.socketLine(line, complete) {
			break
		}
	}
	// A legacy ":::port" wildcard means the host runs old iproute2, whose
	// dual-stack state cannot be determined: mark the table Incomplete
	// and flag the "*" wildcards as unknown instead of guessing them
	// dual-stack.
	if p.hasLegacyWildcard() {
		p.t.Incomplete = true
		for i := range p.t.Entries {
			if p.t.Entries[i].DualStack {
				p.t.Entries[i].DualStackUnknown = true
			}
		}
	}
	return p.t, nil
}

// hasLegacyWildcard reports whether any socket was printed in the legacy
// ":::port" form, i.e. the host runs old iproute2 whose dual-stack state
// cannot be determined.
func (p *socketParser) hasLegacyWildcard() bool {
	for i := range p.t.Entries {
		if p.t.Entries[i].DualStackUnknown {
			return true
		}
	}
	return false
}

// socketParser holds the state of one ParseSocketTable run.
type socketParser struct {
	t SocketTable
	// owner is the index in t.Entries of the socket the next info line
	// belongs to, or -1.
	owner int
	// skip is true while info lines belong to a dropped socket line;
	// they are skipped without being counted again.
	skip bool
	// acked and received collect the counters of the owner socket.
	acked, received counter
}

// drop records a skipped line; its info lines are skipped as well.
func (p *socketParser) drop() {
	p.t.Dropped++
	p.t.Incomplete = true
	p.owner = -1
	p.skip = true
}

// socketLine parses one socket line. It returns false when parsing must
// stop (entry limit reached).
func (p *socketParser) socketLine(line []byte, complete bool) bool {
	if !complete || len(line) > maxSocketLineLen || !validSocketText(line) {
		p.drop()
		return true
	}
	if len(p.t.Entries) >= maxEntries {
		p.t.Incomplete = true
		return false
	}
	s, lossy, ok := parseSocketLine(string(line))
	if !ok {
		p.drop()
		return true
	}
	if lossy {
		p.t.Incomplete = true
	}
	p.t.Entries = append(p.t.Entries, s)
	p.owner = len(p.t.Entries) - 1
	p.skip = false
	p.acked, p.received = counter{}, counter{}
	return true
}

// infoLine applies one info line (starting with whitespace) to the
// socket it belongs to.
func (p *socketParser) infoLine(line []byte, complete bool) {
	if p.owner < 0 {
		if !p.skip {
			p.drop()
		}
		return
	}
	s := &p.t.Entries[p.owner]
	if s.Proto != ProtoTCP {
		// UDP has no tcp_info; nothing on the line is kept.
		return
	}
	if !complete || len(line) > maxSocketLineLen || !validSocketText(line) {
		// The line may have held (part of) a counter; neither value
		// can be trusted any more.
		p.acked.poison()
		p.received.poison()
	} else {
		for _, tok := range strings.FieldsFunc(string(line), isSocketSpace) {
			if v, ok := strings.CutPrefix(tok, "bytes_acked:"); ok {
				p.acked.set(v)
			} else if v, ok := strings.CutPrefix(tok, "bytes_received:"); ok {
				p.received.set(v)
			}
		}
	}
	if p.acked.bad || p.received.bad {
		p.t.Incomplete = true
	}
	s.BytesAcked = p.acked.value()
	s.BytesReceived = p.received.value()
}

// counter collects one tcp_info byte counter of a socket. A counter that
// is repeated, malformed or possibly truncated is bad and reads as zero.
type counter struct {
	val       uint64
	seen, bad bool
}

// set records the decimal text of the counter.
func (c *counter) set(text string) {
	if c.seen {
		c.bad = true
		return
	}
	c.seen = true
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		c.bad = true
		return
	}
	c.val = v
}

// poison marks the counter as untrustworthy.
func (c *counter) poison() {
	c.seen = true
	c.bad = true
}

// value returns the counter, or zero when it is bad or absent.
func (c *counter) value() uint64 {
	if c.bad {
		return 0
	}
	return c.val
}

// isSocketSpace reports whether r separates columns in `ss` output.
func isSocketSpace(r rune) bool { return r == ' ' || r == '\t' }

// validSocketText reports whether b is UTF-8 without control characters
// other than tab.
func validSocketText(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return utf8.Valid(b)
}

// parseSocketLine parses the columns of one socket line. ok is false
// when the line must be dropped; lossy is true when the process name was
// dropped from a kept socket.
func parseSocketLine(line string) (s Socket, lossy, ok bool) {
	var cols [socketColumns]string
	rest := line
	for i := range cols {
		rest = strings.TrimLeftFunc(rest, isSocketSpace)
		end := strings.IndexFunc(rest, isSocketSpace)
		if end < 0 {
			end = len(rest)
		}
		if end == 0 {
			return Socket{}, false, false
		}
		cols[i], rest = rest[:end], rest[end:]
	}
	rest = strings.TrimFunc(rest, isSocketSpace)

	switch Proto(cols[0]) {
	case ProtoTCP, ProtoUDP:
		s.Proto = Proto(cols[0])
	default:
		return Socket{}, false, false
	}
	if !socketStates[cols[1]] {
		return Socket{}, false, false
	}
	s.State = cols[1]
	if !isQueueLen(cols[2]) || !isQueueLen(cols[3]) {
		return Socket{}, false, false
	}
	local, dev, dual, legacy, ok := parseSocketAddr(cols[4])
	if !ok {
		return Socket{}, false, false
	}
	peer, _, _, _, ok := parseSocketAddr(cols[5])
	if !ok {
		return Socket{}, false, false
	}
	if a := peer.Addr(); dev != "" && a.Zone() == "" && isZoned(a) {
		peer = netip.AddrPortFrom(a.WithZone(dev), peer.Port())
	}
	s.Local, s.Peer, s.Dev, s.DualStack, s.DualStackUnknown = local, peer, dev, dual, legacy
	switch s.Proto {
	case ProtoTCP:
		s.Listening = s.State == "LISTEN"
	case ProtoUDP:
		s.Listening = s.State == "UNCONN" && peer.Port() == 0 && peer.Addr().IsUnspecified()
	}
	name, malformed, lossy := parseProcess(rest)
	if malformed {
		return Socket{}, false, false
	}
	s.Process = name
	return s, lossy, true
}

// isQueueLen reports whether s is a decimal Recv-Q/Send-Q value.
func isQueueLen(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// usersColumn matches a complete users:((...)) column as `ss -p` prints
// it: one or more ("name",pid=N,fd=N) entries separated by commas.
// Submatch 1 is the first name, cut at the first `",pid=N,fd=N)` (a
// name may itself contain quotes). Go regexps run in linear time.
var usersColumn = regexp.MustCompile(
	`^users:\(\("(.*?)",pid=[0-9]{1,10},fd=[0-9]{1,10}\)` +
		`(?:,\(".*?",pid=[0-9]{1,10},fd=[0-9]{1,10}\))*\)$`)

// parseProcess extracts the first command name from the trailing column
// rest of a socket line. Trailing text that is not a users:((...))
// column is ignored. malformed is true when rest starts a users:((...))
// column that does not match usersColumn as a whole (the socket line
// must be dropped); lossy is true when a well-formed column carries a
// name that is not acceptable.
//
// The whole column is checked, not only its ends: a process can put a
// newline into its command name to split the line, and the first part
// of a split line ends inside a name. To pass, that part would have to
// end in `",pid=N,fd=N))` (at least 14 bytes) before the newline, and
// the remainder would have to start with whitespace to pass as an info
// line; comm is at most 15 bytes, so no command name can do both. A
// remainder that does not start with whitespace fails the socket-line
// checks and is dropped.
func parseProcess(rest string) (name string, malformed, lossy bool) {
	if !strings.HasPrefix(rest, "users:((") {
		return "", false, false
	}
	m := usersColumn.FindStringSubmatch(rest)
	if m == nil {
		return "", true, false
	}
	name = m[1]
	if name == "" || len(name) > maxProcessLen || !isPrintable(name) {
		return "", false, true
	}
	return name, false, false
}

// isPrintable reports whether s is valid UTF-8 consisting only of
// printable runes (no controls, no format characters such as bidi
// overrides or zero-width spaces).
func isPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// isZoned reports whether a is an IPv6 address whose scope is an
// interface, so that an interface name is kept as its zone.
func isZoned(a netip.Addr) bool {
	return a.Is6() && (a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast())
}

// parseSocketPort parses the port of an "address:port" column. "*" is
// port 0 (no port).
func parseSocketPort(s string) (uint16, bool) {
	if s == "*" {
		return 0, true
	}
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}

// parseSocketAddr parses one "address:port" column of `ss` output. It
// accepts the forms iproute2 prints:
//
//	10.0.0.1:22  127.0.0.53%lo:53  0.0.0.0:*
//	[::1]:22  [fe80::1]%eth0:22  *:22  *:*      (iproute2 >= 4.x)
//	[fe80::1%eth0]:22  fe80::1%eth0:22  :::22   (zone inside, older forms)
//
// Supported iproute2: 5.x (Debian 12, 5.15) and 6.x (Ubuntu 24.04)
// print the bracketed "[::]:port" form and the "*" wildcard, so the
// dual-stack state is determined. Older iproute2 (<= 4.x) prints
// ":::port" for every IPv6 wildcard regardless of V6ONLY and "*" for
// IPv4 INADDR_ANY, so the dual-stack state cannot be determined; the
// legacy ":::port" form is still accepted but flagged (legacy true) so
// the caller marks the table Incomplete instead of guessing.
//
// dev is the interface name after "%" (or the zone of the address); dual
// is true for the "*" wildcard, returned as [::]; legacy is true for the
// unbracketed ":::port" form. IPv4-mapped addresses are unmapped; a
// link-local IPv6 address carries dev as its zone.
func parseSocketAddr(s string) (ap netip.AddrPort, dev string, dual, legacy, ok bool) {
	if s == "" || len(s) > maxSockAddrLen {
		return netip.AddrPort{}, "", false, false, false
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return netip.AddrPort{}, "", false, false, false
	}
	host := s[:i]
	port, ok := parseSocketPort(s[i+1:])
	if !ok {
		return netip.AddrPort{}, "", false, false, false
	}
	addrText := host
	bracketed := strings.HasPrefix(host, "[")
	if bracketed {
		j := strings.IndexByte(host, ']')
		if j < 0 {
			return netip.AddrPort{}, "", false, false, false
		}
		addrText = host[1:j]
		if after := host[j+1:]; after != "" {
			d, found := strings.CutPrefix(after, "%")
			if !found || !validIfName(d) {
				return netip.AddrPort{}, "", false, false, false
			}
			dev = d
		}
		if strings.ContainsAny(addrText, "[]") {
			return netip.AddrPort{}, "", false, false, false
		}
	} else {
		if strings.ContainsAny(host, "[]") {
			return netip.AddrPort{}, "", false, false, false
		}
		if k := strings.IndexByte(host, '%'); k >= 0 {
			addrText, dev = host[:k], host[k+1:]
			if !validIfName(dev) {
				return netip.AddrPort{}, "", false, false, false
			}
		}
	}
	var a netip.Addr
	if addrText == "*" {
		if bracketed {
			return netip.AddrPort{}, "", false, false, false
		}
		a, dual = netip.IPv6Unspecified(), true
	} else {
		a, ok = parseHostAddr(addrText)
		if !ok || (bracketed && !a.Is6()) {
			return netip.AddrPort{}, "", false, false, false
		}
		if z := a.Zone(); z != "" {
			if dev != "" && dev != z {
				return netip.AddrPort{}, "", false, false, false
			}
			dev = z
		}
		// The unbracketed unspecified-IPv6 form is the legacy
		// iproute2 wildcard (":::port"); its dual-stack state is
		// undetermined.
		legacy = !bracketed && a.Is6() && a.IsUnspecified()
	}
	a = a.WithZone("").Unmap()
	if dev != "" && isZoned(a) {
		a = a.WithZone(dev)
	}
	return netip.AddrPortFrom(a, port), dev, dual, legacy, true
}

// Listener is one listening socket address as returned by Listeners.
type Listener struct {
	// Local is the listening address and port (Socket.Local).
	Local netip.AddrPort
	// Dev is the interface the listener is bound to (Socket.Dev), or
	// empty. A bound listener only accepts connections arriving on Dev.
	Dev string
	// DualStack is true for a "*" listener (Socket.DualStack): an IPv6
	// wildcard without IPV6_V6ONLY that also accepts IPv4. A [::]
	// listener without DualStack (printed by `ss` as "[::]") is IPv6
	// only.
	DualStack bool
	// DualStackUnknown is true when the dual-stack state is undetermined
	// (Socket.DualStackUnknown): the host prints the legacy ":::port"
	// wildcard form, so Serves does not claim IPv4 for a "*" listener.
	DualStackUnknown bool
}

// Serves reports whether a connection with local address:port local
// ends at this listener, i.e. local is the server side (ADR 0009 D3).
// The ports must be equal; the address must be equal, or the listener
// is a wildcard of the same family: 0.0.0.0 serves every IPv4 address,
// [::] every IPv6 address, and [::] with DualStack also every IPv4
// address. An IPv4-mapped local address is treated as IPv4. Dev is not
// checked: the caller must compare it with the interface the connection
// uses when it knows it.
func (l Listener) Serves(local netip.AddrPort) bool {
	if local.Port() == 0 || local.Port() != l.Local.Port() {
		return false
	}
	la, a := l.Local.Addr(), local.Addr().Unmap()
	switch {
	case la == a:
		return true
	case !la.IsUnspecified():
		return false
	case la.Is4():
		return a.Is4()
	case a.Is6():
		return true
	default:
		return a.Is4() && l.DualStack && !l.DualStackUnknown
	}
}

// compareListeners orders listeners by address and port, then Dev, with
// a V6ONLY listener before a dual-stack one.
func compareListeners(a, b Listener) int {
	if c := a.Local.Compare(b.Local); c != 0 {
		return c
	}
	if c := strings.Compare(a.Dev, b.Dev); c != 0 {
		return c
	}
	switch {
	case a.DualStack == b.DualStack:
		return 0
	case b.DualStack:
		return -1
	default:
		return 1
	}
}

// Listeners returns the listening sockets (Socket.Listening) per
// protocol, without duplicates and sorted (compareListeners), for
// server-side detection: a connection whose local address:port is
// served by a listener of the same protocol (Listener.Serves) is the
// server end. Listeners keeps DualStack, so a V6ONLY "[::]:22" and a
// dual-stack "*:22" stay distinguishable, and Dev, so listeners bound to
// the same address:port on different interfaces stay separate entries.
func Listeners(socks []Socket) map[Proto][]Listener {
	out := map[Proto][]Listener{}
	seen := map[Proto]map[Listener]bool{}
	for _, s := range socks {
		if !s.Listening {
			continue
		}
		l := Listener{Local: s.Local, Dev: s.Dev, DualStack: s.DualStack, DualStackUnknown: s.DualStackUnknown}
		if seen[s.Proto] == nil {
			seen[s.Proto] = map[Listener]bool{}
		}
		if seen[s.Proto][l] {
			continue
		}
		seen[s.Proto][l] = true
		out[s.Proto] = append(out[s.Proto], l)
	}
	for _, ls := range out {
		slices.SortFunc(ls, compareListeners)
	}
	return out
}
