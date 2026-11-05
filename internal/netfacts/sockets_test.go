// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestParseSocketsDebian12(t *testing.T) {
	res, err := ParseSocketTable(readFixture(t, "debian12-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Socket{
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("127.0.0.1:323"), Peer: ap("0.0.0.0:0"), Listening: true},
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("0.0.0.0:68"), Peer: ap("0.0.0.0:0"), Listening: true},
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("[::1]:323"), Peer: ap("[::]:0"), Listening: true},
		{Proto: ProtoUDP, State: "ESTAB", Local: ap("[fe80::5054:ff:fe12:3456%ens18]:546"), Peer: ap("[fe80::1%ens18]:547"), Dev: "ens18"},
		{Proto: ProtoTCP, State: "LISTEN", Local: ap("0.0.0.0:22"), Peer: ap("0.0.0.0:0"), Listening: true},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("192.168.178.37:22"), Peer: ap("192.168.178.10:51234"), BytesAcked: 52817, BytesReceived: 7421},
		{Proto: ProtoTCP, State: "TIME-WAIT", Local: ap("192.168.178.37:40122"), Peer: ap("151.101.2.132:443")},
		{Proto: ProtoTCP, State: "LISTEN", Local: ap("[::]:22"), Peer: ap("[::]:0"), Listening: true},
		{Proto: ProtoTCP, State: "LISTEN", Local: ap("[::]:9100"), Peer: ap("[::]:0"), Listening: true, DualStack: true},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("192.168.178.37:9100"), Peer: ap("192.168.178.5:38512"), BytesAcked: 18234568, BytesReceived: 3120},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got\n%+v\nwant\n%+v", res.Entries, want)
	}
}

func TestParseSocketsUbuntu2404WithProcess(t *testing.T) {
	res, err := ParseSocketTable(readFixture(t, "ubuntu2404-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	got := res.Entries
	want := []Socket{
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("127.0.0.54:53"), Peer: ap("0.0.0.0:0"), Listening: true, Process: "systemd-resolve"},
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("127.0.0.53:53"), Peer: ap("0.0.0.0:0"), Dev: "lo", Listening: true, Process: "systemd-resolve"},
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("10.0.0.21:68"), Peer: ap("0.0.0.0:0"), Dev: "ens18", Listening: true, Process: "systemd-network"},
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("[::]:5353"), Peer: ap("[::]:0"), Listening: true, DualStack: true, Process: "avahi-daemon"},
		{Proto: ProtoTCP, State: "LISTEN", Local: ap("127.0.0.53:53"), Peer: ap("0.0.0.0:0"), Dev: "lo", Listening: true, Process: "systemd-resolve"},
		{Proto: ProtoTCP, State: "LISTEN", Local: ap("[::]:22"), Peer: ap("[::]:0"), Listening: true, DualStack: true, Process: "sshd"},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("[2001:db8:10::21]:22"), Peer: ap("[2001:db8:10::99]:60422"), BytesAcked: 6177, BytesReceived: 4892, Process: "sshd"},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.21:58312"), Peer: ap("10.0.0.5:5432"), BytesAcked: 1, Process: "app server"},
		{Proto: ProtoTCP, State: "SYN-SENT", Local: ap("10.0.0.21:44102"), Peer: ap("203.0.113.9:443"), Process: "curl"},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("[fe80::21%ens18]:22"), Peer: ap("[fe80::99%ens18]:41000"), Dev: "ens18", BytesAcked: 10, BytesReceived: 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseSocketsMalformedLinesAreDroppedAndMarked(t *testing.T) {
	res, err := ParseSocketTable(readFixture(t, "malformed-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	want := []Socket{
		// Counters that do not parse are dropped (zero), the socket stays.
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.1:22"), Peer: ap("10.0.0.2:5000")},
		// tcp_info keys on a UDP socket are ignored.
		{Proto: ProtoUDP, State: "UNCONN", Local: ap("10.0.0.1:53"), Peer: ap("0.0.0.0:0"), Listening: true},
		{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.1:22"), Peer: ap("10.0.0.2:50")},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got\n%+v\nwant\n%+v", res.Entries, want)
	}
	// Orphan info line, missing peer, raw netid, unknown state, bad
	// Recv-Q, port out of range, bad zone.
	if res.Dropped != 7 || !res.Incomplete {
		t.Fatalf("Dropped=%d Incomplete=%v, want 7 and true", res.Dropped, res.Incomplete)
	}
}

func TestParseSocketsTruncatedLastLine(t *testing.T) {
	in := "tcp   ESTAB  0      0         10.0.0.1:22   10.0.0.2:5000\n" +
		"\t cubic bytes_acked:100 bytes_received:200\n" +
		"tcp   ESTAB  0      0         10.0.0.1:22   10.0.0.3:600"
	res, err := ParseSocketTable([]byte(in))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	want := []Socket{{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.1:22"), Peer: ap("10.0.0.2:5000"), BytesAcked: 100, BytesReceived: 200}}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	if res.Dropped != 1 || !res.Incomplete {
		t.Fatalf("Dropped=%d Incomplete=%v, want 1 and true", res.Dropped, res.Incomplete)
	}
}

func TestParseSocketsTruncatedInfoLineDropsCounters(t *testing.T) {
	// "bytes_acked:12" may be the cut-off prefix of "bytes_acked:12345".
	in := "tcp   ESTAB  0      0         10.0.0.1:22   10.0.0.2:5000\n" +
		"\t cubic bytes_received:7 bytes_acked:12"
	res, err := ParseSocketTable([]byte(in))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].BytesAcked != 0 || res.Entries[0].BytesReceived != 0 {
		t.Fatalf("got %+v, want one socket with zero counters", res.Entries)
	}
	if !res.Incomplete {
		t.Fatal("truncated info line not marked Incomplete")
	}
}

func TestParseSocketsEmptyInputIsEmptyComplete(t *testing.T) {
	for _, in := range []string{"", "\n", "\n\n"} {
		res, err := ParseSocketTable([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(res.Entries) != 0 || res.Incomplete || res.Dropped != 0 {
			t.Fatalf("%q: got %+v", in, res)
		}
	}
}

func TestParseSocketsOversizeInputIsError(t *testing.T) {
	line := "tcp   ESTAB  0      0         10.0.0.1:22   10.0.0.2:5000\n"
	in := strings.Repeat(line, maxInputSize/len(line)+1)
	if _, err := ParseSocketTable([]byte(in)); err == nil {
		t.Fatal("oversize input accepted")
	}
	if _, err := ParseSockets([]byte(in)); err == nil {
		t.Fatal("oversize input accepted by ParseSockets")
	}
}

func TestParseSocketsEntryLimitTruncatesAndMarks(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxEntries+5; i++ {
		fmt.Fprintf(&b, "tcp ESTAB 0 0 10.0.0.1:22 10.0.%d.%d:5000\n", i/250, i%250+1)
	}
	res, err := ParseSocketTable([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if len(res.Entries) != maxEntries || !res.Incomplete {
		t.Fatalf("got %d entries Incomplete=%v, want %d and true", len(res.Entries), res.Incomplete, maxEntries)
	}
}

func TestParseSocketsExactlyMaxEntriesIsComplete(t *testing.T) {
	// Exactly maxEntries sockets, with the info line on the last entry,
	// must produce a complete table: the limit is "> maxEntries", so the
	// maxEntries-th entry is kept and its info line counted.
	var b strings.Builder
	for i := 0; i < maxEntries; i++ {
		fmt.Fprintf(&b, "tcp ESTAB 0 0 10.0.0.%d:1000 10.0.1.1:80\n", i%250)
		b.WriteString("	 bytes_acked:100 bytes_received:200\n")
	}
	res, err := ParseSocketTable([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if len(res.Entries) != maxEntries {
		t.Fatalf("got %d entries, want %d", len(res.Entries), maxEntries)
	}
	if res.Incomplete {
		t.Fatalf("table Incomplete with exactly maxEntries sockets (info line on the last)")
	}
	if res.Dropped != 0 {
		t.Fatalf("got %d dropped, want 0", res.Dropped)
	}
	last := res.Entries[maxEntries-1]
	if last.BytesAcked != 100 || last.BytesReceived != 200 {
		t.Fatalf("last entry BytesAcked=%d BytesReceived=%d, want 100/200 (info line on the last entry)", last.BytesAcked, last.BytesReceived)
	}
	// One more socket over the limit must make the table incomplete.
	b.WriteString("tcp ESTAB 0 0 10.0.0.99:1000 10.0.1.1:80\n")
	res2, err := ParseSocketTable([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if len(res2.Entries) != maxEntries {
		t.Fatalf("got %d entries, want %d", len(res2.Entries), maxEntries)
	}
	if !res2.Incomplete {
		t.Fatalf("table complete with maxEntries+1 sockets")
	}
}

func TestParseSocketsOverlongLineIsDropped(t *testing.T) {
	long := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 " + strings.Repeat("x", maxSocketLineLen) + "\n"
	info := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.3:5000\n\t cubic bytes_acked:5 " + strings.Repeat("y", maxSocketLineLen) + "\n"
	res, err := ParseSocketTable([]byte(long + info))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	want := []Socket{{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.1:22"), Peer: ap("10.0.0.3:5000")}}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	if res.Dropped != 1 || !res.Incomplete {
		t.Fatalf("Dropped=%d Incomplete=%v", res.Dropped, res.Incomplete)
	}
}

func TestParseSocketsRejectsControlAndInvalidUTF8(t *testing.T) {
	for _, in := range []string{
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 \x1b[31m\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\r\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 \xff\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 \x00\n",
	} {
		res, err := ParseSocketTable([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(res.Entries) != 0 || res.Dropped != 1 || !res.Incomplete {
			t.Fatalf("%q: got %+v", in, res)
		}
	}
}

func TestParseSocketsDuplicateCounterIsDropped(t *testing.T) {
	in := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\n\t cubic bytes_acked:5 bytes_acked:9 bytes_received:3\n"
	res, err := ParseSocketTable([]byte(in))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].BytesAcked != 0 || res.Entries[0].BytesReceived != 3 || !res.Incomplete {
		t.Fatalf("got %+v", res)
	}
}

func TestParseSocketsCounterAtUint64Max(t *testing.T) {
	in := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\n\t bytes_acked:18446744073709551615 bytes_received:18446744073709551616\n"
	res, err := ParseSocketTable([]byte(in))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	s := res.Entries[0]
	if s.BytesAcked != 18446744073709551615 || s.BytesReceived != 0 || !res.Incomplete {
		t.Fatalf("got %+v Incomplete=%v", s, res.Incomplete)
	}
}

func TestParseSocketsProcessName(t *testing.T) {
	cases := []struct {
		users string
		want  string
		lossy bool
	}{
		{`users:(("sshd",pid=1,fd=3))`, "sshd", false},
		{`users:(("nginx",pid=10,fd=6),("nginx",pid=11,fd=6))`, "nginx", false},
		{`users:(("a b c",pid=1,fd=3))`, "a b c", false},
		{`users:(("we"ird",pid=1,fd=3))`, `we"ird`, false},
		{`users:(("` + strings.Repeat("a", maxProcessLen) + `",pid=1,fd=3))`, strings.Repeat("a", maxProcessLen), false},
		{`users:(("` + strings.Repeat("a", maxProcessLen+1) + `",pid=1,fd=3))`, "", true},
		{`users:(("",pid=1,fd=3))`, "", true},
		{`users:(("evil` + "\u202e" + `",pid=1,fd=3))`, "", true},
		{`users:(("x` + "\u200b" + `",pid=1,fd=3))`, "", true},
		{`ino:12345 sk:1`, "", false},
	}
	for _, c := range cases {
		in := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 " + c.users + "\n"
		res, err := ParseSocketTable([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", c.users, err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("%s: got %d entries", c.users, len(res.Entries))
		}
		if res.Entries[0].Process != c.want || res.Incomplete != c.lossy {
			t.Fatalf("%s: Process=%q Incomplete=%v, want %q %v", c.users, res.Entries[0].Process, res.Incomplete, c.want, c.lossy)
		}
	}
}

func TestParseSocketsMalformedUsersColumnDropsSocket(t *testing.T) {
	// A process can split its socket line with a newline in its
	// command name; the broken line and its remainder must not be kept.
	for _, in := range []string{
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"sshd\"\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((sshd,pid=1,fd=3))\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"x\npid=1\",pid=1,fd=3))\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"x\n\tbytes_acked:9\",pid=1,fd=3))\n\t cubic bytes_acked:1\n",
		// The first part has the users:(( prefix, contains `",pid=` and
		// ends in "))", and the remainder is a valid info line: a check
		// of only the column ends would keep the socket with
		// bytes_acked 9.
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"sshd\",pid=1,fd=3),(\"))\n\tbytes_acked:9 \",pid=2,fd=3))\n\t cubic bytes_acked:1\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"sshd\",pid=1,fd=3),(\"))\n\tbytes_acked:9\",pid=2,fd=3))\n",
		// Entry structure is checked, not only the ends.
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"\",pid=))\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"a\",pid=1,fd=3),x))\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"a\",pid=1,fd=3)))\n",
		"tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"a\",pid=,fd=3))\n",
	} {
		res, err := ParseSocketTable([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(res.Entries) != 0 || res.Dropped == 0 || !res.Incomplete {
			t.Fatalf("%q: got %+v", in, res)
		}
	}
}

func TestParseSocketsSplitLineAtCommLimit(t *testing.T) {
	// The longest first part a 15-byte comm can complete:
	// `",pid=1,fd=1))` plus the newline. The column is well formed with
	// an empty name, so the socket stays without a process and the
	// table is Incomplete; the remainder cannot start with whitespace,
	// is dropped as a socket line, and its info lines are skipped.
	in := "tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:((\"\",pid=1,fd=1))\n" +
		"\",pid=4242,fd=3))\n" +
		"\t cubic bytes_acked:9 bytes_received:9\n"
	res, err := ParseSocketTable([]byte(in))
	if err != nil {
		t.Fatalf("ParseSocketTable: %v", err)
	}
	want := []Socket{{Proto: ProtoTCP, State: "ESTAB", Local: ap("10.0.0.1:22"), Peer: ap("10.0.0.2:5000")}}
	if !reflect.DeepEqual(res.Entries, want) || res.Dropped != 1 || !res.Incomplete {
		t.Fatalf("got %+v", res)
	}
}

func TestParseSocketAddr(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		dev    string
		dual   bool
		legacy bool
	}{
		{"0.0.0.0:22", "0.0.0.0:22", "", false, false},
		{"0.0.0.0:*", "0.0.0.0:0", "", false, false},
		{"*:22", "[::]:22", "", true, false},
		{"*:*", "[::]:0", "", true, false},
		{"*%eth0:22", "[::]:22", "eth0", true, false},
		{"[::]:22", "[::]:22", "", false, false},
		{"[::1]:22", "[::1]:22", "", false, false},
		{":::22", "[::]:22", "", false, true},
		{"::1:22", "[::1]:22", "", false, false},
		{"[fe80::1%eth0]:123", "[fe80::1%eth0]:123", "eth0", false, false},
		{"[fe80::1]%eth0:123", "[fe80::1%eth0]:123", "eth0", false, false},
		{"fe80::1%eth0:123", "[fe80::1%eth0]:123", "eth0", false, false},
		{"[ff02::1]%eth0:5353", "[ff02::1%eth0]:5353", "eth0", false, false},
		{"[::]%vmbr0:22", "[::]:22", "vmbr0", false, false},
		{"[2001:db8::1]%eth0:22", "[2001:db8::1]:22", "eth0", false, false},
		{"127.0.0.53%lo:53", "127.0.0.53:53", "lo", false, false},
		{"[::ffff:10.0.0.1]:80", "10.0.0.1:80", "", false, false},
		{"10.0.0.1:65535", "10.0.0.1:65535", "", false, false},
	}
	for _, c := range cases {
		got, dev, dual, legacy, ok := parseSocketAddr(c.in)
		if !ok {
			t.Fatalf("%q rejected", c.in)
		}
		if got != ap(c.want) || dev != c.dev || dual != c.dual || legacy != c.legacy {
			t.Fatalf("%q: got %v dev=%q dual=%v legacy=%v, want %v %q %v %v", c.in, got, dev, dual, legacy, c.want, c.dev, c.dual, c.legacy)
		}
	}
}

func TestParseSocketAddrRejects(t *testing.T) {
	for _, in := range []string{
		"", ":", ":22", "10.0.0.1", "10.0.0.1:", "10.0.0.1:+22", "10.0.0.1:-1",
		"10.0.0.1:022", "10.0.0.1:65536", "10.0.0.1:2a", "10.0.0.1%:22",
		"10.0.0.1%bad;dev:22", "10.0.0.1%" + strings.Repeat("e", 16) + ":22",
		"[10.0.0.1]:22", "[fe80::1:22", "[::1]x:22", "[::1]%:22", "[]:22",
		"[fe80::1%eth0]%eth1:1", "[fe80::1%eth0%x]:1", "[fe80::1%\u202e]:1",
		"1.2.3.4:22:33", "host.example:22", "*:", "**:22", "[*]:22",
		"[::1]]:22", "[[::1]:22", "10.0.0.1%eth0%eth1:22",
		strings.Repeat("1", 200) + ":22",
	} {
		if got, dev, _, _, ok := parseSocketAddr(in); ok {
			t.Fatalf("%q accepted as %v dev=%q", in, got, dev)
		}
	}
}

func TestParseSocketsLegacyWildcardMarksIncomplete(t *testing.T) {
	// A host running old iproute2 prints ":::22" for an IPv6 wildcard
	// regardless of V6ONLY and "*:22" for IPv4 INADDR_ANY. The parser
	// must not guess the dual-stack state: the table is Incomplete, both
	// sockets are flagged, "*:22" is stored as 0.0.0.0:22 (IPv4 only)
	// and ":::22" as [::]:22 without DualStack (IPv6 only).
	const raw = "tcp LISTEN 0 0 :::22 :::*\n" +
		"tcp LISTEN 0 0 *:22 *:*\n"
	tbl, err := ParseSocketTable([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tbl.Incomplete {
		t.Fatalf("table not Incomplete with a legacy :::22 wildcard")
	}
	if e := tbl.Entries[0]; !e.DualStackUnknown || e.DualStack || e.Local != ap("[::]:22") {
		t.Fatalf(":::22 socket = %+v, want [::]:22 flagged, not DualStack", e)
	}
	if e := tbl.Entries[1]; !e.DualStackUnknown || e.DualStack || e.Local != ap("0.0.0.0:22") || e.Peer != ap("0.0.0.0:0") {
		t.Fatalf("*:22 socket = %+v, want 0.0.0.0:22 flagged, not DualStack", e)
	}
	ls := Listeners(tbl.Entries)[ProtoTCP]
	if len(ls) != 2 {
		t.Fatalf("listeners = %+v, want 2", ls)
	}
	var v4, v6 *Listener
	for i := range ls {
		switch ls[i].Local {
		case ap("0.0.0.0:22"):
			v4 = &ls[i]
		case ap("[::]:22"):
			v6 = &ls[i]
		}
	}
	if v4 == nil || v6 == nil || !v4.DualStackUnknown || !v6.DualStackUnknown {
		t.Fatalf("listeners = %+v, want flagged 0.0.0.0:22 and [::]:22", ls)
	}
	// The legacy "*" listener is IPv4 INADDR_ANY: it serves IPv4 only.
	if !v4.Serves(ap("10.0.0.1:22")) {
		t.Fatalf("legacy * listener does not serve IPv4")
	}
	if v4.Serves(ap("[2001:db8::1]:22")) {
		t.Fatalf("legacy * listener claims IPv6")
	}
	// The legacy ":::" listener serves IPv6; IPv4 is never claimed.
	if !v6.Serves(ap("[2001:db8::1]:22")) {
		t.Fatalf("legacy ::: listener does not serve IPv6")
	}
	if v6.Serves(ap("10.0.0.1:22")) {
		t.Fatalf("legacy ::: listener claims IPv4")
	}

	// A V6ONLY [::]:22 stays distinguishable from the legacy :::22.
	const raw2 = "tcp LISTEN 0 0 [::]:22 *:*\n" +
		"tcp LISTEN 0 0 :::22 *:*\n"
	tbl2, err := ParseSocketTable([]byte(raw2))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tbl2.Incomplete {
		t.Fatalf("table2 not Incomplete")
	}
	if tbl2.Entries[0].DualStackUnknown {
		t.Fatalf("V6ONLY [::]:22 wrongly flagged DualStackUnknown")
	}
	if !tbl2.Entries[1].DualStackUnknown {
		t.Fatalf(":::22 socket not flagged")
	}

	// A modern host (bracketed form, no legacy wildcard) is complete and
	// the * listener still claims IPv4.
	const raw3 = "tcp LISTEN 0 0 [::]:22 *:*\n" +
		"tcp LISTEN 0 0 *:22 *:*\n"
	tbl3, err := ParseSocketTable([]byte(raw3))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tbl3.Incomplete {
		t.Fatalf("modern host table wrongly Incomplete")
	}
	var found bool
	for _, l := range Listeners(tbl3.Entries)[ProtoTCP] {
		if l.DualStack && !l.DualStackUnknown && !l.Serves(ap("10.0.0.1:22")) {
			t.Fatalf("modern * listener does not claim IPv4")
		}
		if l.DualStack {
			found = true
		}
	}
	if !found {
		t.Fatalf("no dual-stack * listener found")
	}
}

func TestListeners(t *testing.T) {
	socks, err := ParseSockets(readFixture(t, "debian12-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSockets: %v", err)
	}
	// A second listener on the same address (SO_REUSEPORT) must not
	// duplicate the entry; listeners bound to the same address on
	// different interfaces must stay separate.
	socks = append(socks,
		Socket{Proto: ProtoTCP, State: "LISTEN", Local: ap("[::]:22"), Listening: true},
		Socket{Proto: ProtoUDP, State: "UNCONN", Local: ap("0.0.0.0:67"), Dev: "eth1", Listening: true},
		Socket{Proto: ProtoUDP, State: "UNCONN", Local: ap("0.0.0.0:67"), Dev: "eth0", Listening: true},
	)
	got := Listeners(socks)
	// The fixture has a V6ONLY "[::]:22" and a dual-stack "*:9100"; both
	// are [::] addresses and only DualStack tells them apart.
	want := map[Proto][]Listener{
		ProtoTCP: {
			{Local: ap("0.0.0.0:22")},
			{Local: ap("[::]:22")},
			{Local: ap("[::]:9100"), DualStack: true},
		},
		ProtoUDP: {
			{Local: ap("0.0.0.0:67"), Dev: "eth0"},
			{Local: ap("0.0.0.0:67"), Dev: "eth1"},
			{Local: ap("0.0.0.0:68")},
			{Local: ap("127.0.0.1:323")},
			{Local: ap("[::1]:323")},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if l := Listeners(nil); len(l) != 0 {
		t.Fatalf("Listeners(nil) = %v", l)
	}

	// Server-side detection for the fixture's connections: an IPv4
	// connection on 9100 ends at the dual-stack listener, an IPv4
	// connection to port 22 must not be attributed to the V6ONLY one.
	tcp := got[ProtoTCP]
	v6only, dual := tcp[1], tcp[2]
	cases := []struct {
		l     Listener
		local string
		want  bool
	}{
		{dual, "192.168.178.37:9100", true},
		{dual, "[::ffff:192.168.178.37]:9100", true},
		{dual, "[2001:db8::1]:9100", true},
		{dual, "192.168.178.37:9101", false},
		{v6only, "192.168.178.37:22", false},
		{v6only, "[2001:db8::1]:22", true},
		{tcp[0], "192.168.178.37:22", true},
		{tcp[0], "[2001:db8::1]:22", false},
		{Listener{Local: ap("10.0.0.1:80")}, "10.0.0.1:80", true},
		{Listener{Local: ap("10.0.0.1:80")}, "10.0.0.2:80", false},
		{Listener{Local: ap("[::]:0"), DualStack: true}, "10.0.0.1:0", false},
	}
	for _, c := range cases {
		if g := c.l.Serves(ap(c.local)); g != c.want {
			t.Fatalf("%+v.Serves(%s) = %v, want %v", c.l, c.local, g, c.want)
		}
	}
}

func TestListenerOrderV6OnlyBeforeDualStack(t *testing.T) {
	// On the same port, a V6ONLY "[::]:P" listener and a dual-stack
	// "*:P" listener must be ordered with the V6ONLY one first
	// (compareListeners tiebreak: V6ONLY before DualStack).
	const raw = "tcp LISTEN 0 0 *:22 *:*\n" +
		"tcp LISTEN 0 0 [::]:22 *:*\n"
	tbl, err := ParseSocketTable([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ls := Listeners(tbl.Entries)[ProtoTCP]
	if len(ls) != 2 {
		t.Fatalf("got %d listeners, want 2", len(ls))
	}
	if ls[0].Local != ap("[::]:22") || ls[0].DualStack {
		t.Fatalf("first listener %v dual=%v, want V6ONLY [::]:22", ls[0].Local, ls[0].DualStack)
	}
	if ls[1].Local != ap("[::]:22") || !ls[1].DualStack {
		t.Fatalf("second listener %v dual=%v, want dual-stack *:22", ls[1].Local, ls[1].DualStack)
	}
}

func TestUDPConnectedSocketIsNotListening(t *testing.T) {
	socks, err := ParseSockets([]byte("udp ESTAB 0 0 10.0.0.1:41000 10.0.0.53:53\nudp UNCONN 0 0 10.0.0.1:41001 10.0.0.53:53\n"))
	if err != nil {
		t.Fatalf("ParseSockets: %v", err)
	}
	for _, s := range socks {
		if s.Listening {
			t.Fatalf("%+v marked listening", s)
		}
	}
	if len(socks) != 2 {
		t.Fatalf("got %d sockets", len(socks))
	}
}

// FuzzParseSockets checks the hard bounds of ParseSocketTable on
// arbitrary input: no panic, bounded entry count, every returned field
// within its documented limits, and ParseSockets agreeing with it.
func FuzzParseSockets(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("debian12-ss.txt", "ubuntu2404-ss.txt", "malformed-ss.txt") {
		f.Add(s)
	}
	f.Add([]byte(""))
	f.Add([]byte("tcp ESTAB 0 0 [fe80::1]%eth0:22 [fe80::2]:5000\n\t bytes_acked:1 bytes_received:2\n"))
	f.Add([]byte("udp UNCONN 0 0 *%eth0:53 *:* users:((\"x\",pid=1,fd=2))\n"))
	f.Add([]byte("tcp LISTEN 0 0 fe80::1%eth0:22 :::*\n\t"))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseSocketTable(b)
		if err != nil {
			if len(b) <= maxInputSize {
				t.Fatalf("error on input within size limit: %v", err)
			}
			return
		}
		if len(res.Entries) > maxEntries {
			t.Fatalf("%d entries, bound is %d", len(res.Entries), maxEntries)
		}
		if res.Dropped < 0 || (res.Dropped > 0 && !res.Incomplete) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		for _, s := range res.Entries {
			if s.Proto != ProtoTCP && s.Proto != ProtoUDP {
				t.Fatalf("proto %q", s.Proto)
			}
			if !socketStates[s.State] {
				t.Fatalf("state %q", s.State)
			}
			if !s.Local.IsValid() || !s.Peer.IsValid() {
				t.Fatalf("invalid addr %v %v", s.Local, s.Peer)
			}
			oracleAddr(t, "local", s.Local.Addr())
			oracleAddr(t, "peer", s.Peer.Addr())
			if s.Local.Addr().Is4In6() || s.Peer.Addr().Is4In6() {
				t.Fatalf("mapped address kept: %v %v", s.Local, s.Peer)
			}
			if s.Dev != "" {
				oracleIfName(t, "dev", s.Dev)
			}
			if s.Proto == ProtoUDP && (s.BytesAcked != 0 || s.BytesReceived != 0) {
				t.Fatalf("UDP socket with counters: %+v", s)
			}
			if s.Listening && s.Proto == ProtoTCP && s.State != "LISTEN" {
				t.Fatalf("TCP listener in state %q", s.State)
			}
			if len(s.Process) > maxProcessLen || !utf8.ValidString(s.Process) {
				t.Fatalf("process %q", s.Process)
			}
			for _, r := range s.Process {
				if !unicode.IsPrint(r) {
					t.Fatalf("process %q contains %U", s.Process, r)
				}
			}
		}
		plain, err := ParseSockets(b)
		if err != nil || !reflect.DeepEqual(plain, res.Entries) {
			t.Fatalf("ParseSockets disagrees: %v", err)
		}
	})
}
