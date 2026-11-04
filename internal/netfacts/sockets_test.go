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
	got, err := ParseSockets(readFixture(t, "ubuntu2404-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSockets: %v", err)
	}
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
		{`users:(("evil` + "‮" + `",pid=1,fd=3))`, "", true},
		{`users:(("x` + "​" + `",pid=1,fd=3))`, "", true},
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

func TestParseSocketAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
		dev  string
		dual bool
	}{
		{"0.0.0.0:22", "0.0.0.0:22", "", false},
		{"0.0.0.0:*", "0.0.0.0:0", "", false},
		{"*:22", "[::]:22", "", true},
		{"*:*", "[::]:0", "", true},
		{"*%eth0:22", "[::]:22", "eth0", true},
		{"[::]:22", "[::]:22", "", false},
		{"[::1]:22", "[::1]:22", "", false},
		{":::22", "[::]:22", "", false},
		{"::1:22", "[::1]:22", "", false},
		{"[fe80::1%eth0]:123", "[fe80::1%eth0]:123", "eth0", false},
		{"[fe80::1]%eth0:123", "[fe80::1%eth0]:123", "eth0", false},
		{"fe80::1%eth0:123", "[fe80::1%eth0]:123", "eth0", false},
		{"[ff02::1]%eth0:5353", "[ff02::1%eth0]:5353", "eth0", false},
		{"[::]%vmbr0:22", "[::]:22", "vmbr0", false},
		{"[2001:db8::1]%eth0:22", "[2001:db8::1]:22", "eth0", false},
		{"127.0.0.53%lo:53", "127.0.0.53:53", "lo", false},
		{"[::ffff:10.0.0.1]:80", "10.0.0.1:80", "", false},
		{"10.0.0.1:65535", "10.0.0.1:65535", "", false},
	}
	for _, c := range cases {
		got, dev, dual, ok := parseSocketAddr(c.in)
		if !ok {
			t.Fatalf("%q rejected", c.in)
		}
		if got != ap(c.want) || dev != c.dev || dual != c.dual {
			t.Fatalf("%q: got %v dev=%q dual=%v, want %v %q %v", c.in, got, dev, dual, c.want, c.dev, c.dual)
		}
	}
}

func TestParseSocketAddrRejects(t *testing.T) {
	for _, in := range []string{
		"", ":", ":22", "10.0.0.1", "10.0.0.1:", "10.0.0.1:+22", "10.0.0.1:-1",
		"10.0.0.1:022", "10.0.0.1:65536", "10.0.0.1:2a", "10.0.0.1%:22",
		"10.0.0.1%bad;dev:22", "10.0.0.1%" + strings.Repeat("e", 16) + ":22",
		"[10.0.0.1]:22", "[fe80::1:22", "[::1]x:22", "[::1]%:22", "[]:22",
		"[fe80::1%eth0]%eth1:1", "[fe80::1%eth0%x]:1", "[fe80::1%‮]:1",
		"1.2.3.4:22:33", "host.example:22", "*:", "**:22", "[*]:22",
		"[::1]]:22", "[[::1]:22", "10.0.0.1%eth0%eth1:22",
		strings.Repeat("1", 200) + ":22",
	} {
		if got, dev, _, ok := parseSocketAddr(in); ok {
			t.Fatalf("%q accepted as %v dev=%q", in, got, dev)
		}
	}
}

func TestListeners(t *testing.T) {
	socks, err := ParseSockets(readFixture(t, "ubuntu2404-ss.txt"))
	if err != nil {
		t.Fatalf("ParseSockets: %v", err)
	}
	// A second listener on the same port (SO_REUSEPORT) must not
	// duplicate the entry.
	socks = append(socks, Socket{Proto: ProtoTCP, State: "LISTEN", Local: ap("[::]:22"), Listening: true})
	got := Listeners(socks)
	want := map[Proto][]netip.AddrPort{
		ProtoTCP: {ap("127.0.0.53:53"), ap("[::]:22")},
		ProtoUDP: {ap("10.0.0.21:68"), ap("127.0.0.53:53"), ap("127.0.0.54:53"), ap("[::]:5353")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if l := Listeners(nil); len(l) != 0 {
		t.Fatalf("Listeners(nil) = %v", l)
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
