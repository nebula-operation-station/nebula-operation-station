// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// netFactsCommands is the complete, ordered list of commands net.facts
// runs. Each is read-only; ss has no -p and nothing runs under sudo.
var netFactsCommands = []struct{ section, cmd string }{
	{"addr", "ip -j addr"},
	{"link", "ip -j -d link"},
	{"route", "ip -j route"},
	{"route6", "ip -j -6 route"},
	{"neigh", "ip -j neigh"},
	{"neigh6", "ip -j -6 neigh"},
	{"bridge_vlan", "bridge -j vlan"},
	{"lldp", "lldpcli -f json show neighbors"},
	{"sockets", "ss -tinuaH"},
	{"conntrack", "conntrack -L"},
}

func TestNetFactsAction(t *testing.T) {
	a, ok := Lookup("net.facts")
	if !ok {
		t.Fatal("net.facts is not a built-in action")
	}
	if !a.ReadOnly || a.Durable || len(a.Params) != 0 || len(a.Secrets) != 0 || a.Validate != nil ||
		a.Risk != pb.RiskClass_RISK_CLASS_LOW || a.Retry != RetrySafe || a.Version != "1.0.0" {
		t.Fatalf("net.facts %+v", a)
	}
	if a.Timeout <= 0 || a.Timeout > hostrun.MaxTimeout {
		t.Fatalf("timeout %s", a.Timeout)
	}
}

// The script runs exactly the fixed commands of ADR 0009 D1: no sudo, no
// ss -p (Q3 is open), nothing that writes.
func TestNetFactsScriptRunsOnlyFixedReadCommands(t *testing.T) {
	a, _ := Lookup("net.facts")
	s := string(a.Script)
	var got []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "section ") {
			got = append(got, strings.TrimPrefix(line, "section "))
		}
	}
	var want []string
	for _, c := range netFactsCommands {
		want = append(want, c.section+" "+c.cmd)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("section commands\n got %q\nwant %q", got, want)
	}
	// Check the code, not the comments that explain what is not done.
	var code []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	s = strings.Join(code, "\n")
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`\bsudo\b`),
		regexp.MustCompile(`\bss\s+-[A-Za-z]*p`),
		regexp.MustCompile(`--processes`),
		regexp.MustCompile(`\bconntrack\s+-[A-KM-Za-z]`), // only -L
		regexp.MustCompile(`\bip\b[^\n]*\b(add|del|delete|set|flush|change|replace)\b`),
		regexp.MustCompile(`\bbridge\b[^\n]*\b(add|del|set)\b`),
		regexp.MustCompile(`\blldpcli\b[^\n]*\b(configure|unconfigure|update|pause|resume)\b`),
	} {
		if bad.MatchString(s) {
			t.Errorf("script matches %s", bad)
		}
	}
}

// The script's bounds are the decoder's, and the largest possible
// document fits the executor's result limit.
func TestNetFactsScriptBoundsMatchDecoder(t *testing.T) {
	a, _ := Lookup("net.facts")
	s := string(a.Script)
	for _, want := range []string{
		"section_max=" + strconv.Itoa(netfacts.MaxSection) + "\n",
		"total_max=" + strconv.Itoa(netfacts.MaxTotal) + "\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// Worst case: the whole budget as base64 plus the JSON frame of
	// every section.
	frame := len(`{"format":"net-facts-v1","phase":"done"}`) + 1
	for _, c := range netFactsCommands {
		frame += len(`,"":{"status":"skipped","truncated":false,"data":""}`) + len(c.section)
	}
	if worst := (netfacts.MaxTotal+2)/3*4 + frame; worst > hostrun.MaxResult {
		t.Fatalf("worst-case document %d bytes exceeds %d", worst, hostrun.MaxResult)
	}
}

// netHost is a PATH with stand-ins for the network tools and only the
// real utilities the script needs, so absent tools are really absent.
// mktemp and rm are not among them: the script writes no file.
//
// A missing utility fails the test, so a runner without them cannot
// silently skip every script-level check; NOS_TEST_ALLOW_MISSING_COREUTILS=1
// turns that into a skip for a deliberately minimal local environment.
type netHost struct {
	dir, bin, calls string
}

func newNetHost(t *testing.T) *netHost {
	t.Helper()
	d := t.TempDir()
	h := &netHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"base64", "head", "cat", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			if os.Getenv("NOS_TEST_ALLOW_MISSING_COREUTILS") == "1" {
				t.Skipf("%s not available: %v", tool, err)
			}
			t.Fatalf("%s not available: %v (set NOS_TEST_ALLOW_MISSING_COREUTILS=1 to skip)", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// tool installs a fake command that logs its arguments and prints the
// file out/<name>-<args joined by '_'> if it exists, else nothing.
func (h *netHost) tool(t *testing.T, name, extra string) {
	t.Helper()
	body := "#!/bin/sh\necho \"" + name + " $*\" >> \"" + h.calls + "\"\n" + extra +
		"\nf=\"" + h.dir + "/out/" + name + "-$(echo \"$*\" | tr ' ' '_')\"\n[ -f \"$f\" ] && cat \"$f\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (h *netHost) output(t *testing.T, cmd string, data []byte) {
	t.Helper()
	fields := strings.Fields(cmd)
	p := filepath.Join(h.dir, "out", fields[0]+"-"+strings.Join(fields[1:], "_"))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type netSection struct {
	Status    string `json:"status"`
	Truncated bool   `json:"truncated"`
	Data      string `json:"data"`
}

func (h *netHost) run(t *testing.T) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	a, _ := Lookup("net.facts")
	p := filepath.Join(h.dir, "action.sh")
	if err := os.WriteFile(p, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = h.dir
	cmd.Env = []string{"PATH=" + h.bin, "TMPDIR=" + h.dir}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v (%q)", err, out)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result %q: %v", out, err)
	}
	return out, doc
}

func section(t *testing.T, doc map[string]json.RawMessage, name string) (netSection, []byte) {
	t.Helper()
	var s netSection
	if err := json.Unmarshal(doc[name], &s); err != nil {
		t.Fatalf("section %s: %v", name, err)
	}
	b, err := base64.StdEncoding.DecodeString(s.Data)
	if err != nil {
		t.Fatalf("section %s data: %v", name, err)
	}
	return s, b
}

func allNetTools(t *testing.T, h *netHost) {
	for _, n := range []string{"ip", "bridge", "lldpcli", "ss", "conntrack"} {
		h.tool(t, n, "")
	}
}

func TestNetFactsScriptCarriesOutputUnchanged(t *testing.T) {
	h := newNetHost(t)
	allNetTools(t, h)
	want := map[string][]byte{}
	for _, c := range netFactsCommands {
		data := []byte(`[{"section":"` + c.section + `","text":"a\"b\\c ` + "ä\x01" + `"}]` + "\n")
		if c.section == "sockets" {
			data = []byte("tcp ESTAB 0 0 10.0.0.2:22 10.0.0.9:51000\n\t bytes_acked:10 bytes_received:20\n")
		}
		want[c.section] = data
		h.output(t, c.cmd, data)
	}
	_, doc := h.run(t)
	var format string
	if err := json.Unmarshal(doc["format"], &format); err != nil || format != "net-facts-v1" {
		t.Fatalf("format %q %v", doc["format"], err)
	}
	for _, c := range netFactsCommands {
		s, b := section(t, doc, c.section)
		if s.Status != "ok" || s.Truncated || !bytes.Equal(b, want[c.section]) {
			t.Errorf("%s: %+v %q", c.section, s, b)
		}
	}
	calls, err := os.ReadFile(h.calls)
	if err != nil {
		t.Fatal(err)
	}
	var wantCalls string
	for _, c := range netFactsCommands {
		wantCalls += c.cmd + "\n"
	}
	if string(calls) != wantCalls {
		t.Fatalf("calls\n%s\nwant\n%s", calls, wantCalls)
	}
}

func TestNetFactsScriptOptionalToolsAbsent(t *testing.T) {
	h := newNetHost(t)
	h.tool(t, "ip", "")
	h.tool(t, "ss", "")
	h.output(t, "ip -j addr", []byte("[]\n"))
	_, doc := h.run(t)
	for _, name := range []string{"bridge_vlan", "lldp", "conntrack"} {
		if s, b := section(t, doc, name); s.Status != "absent" || s.Truncated || len(b) != 0 {
			t.Errorf("%s: %+v", name, s)
		}
	}
	if s, b := section(t, doc, "addr"); s.Status != "ok" || string(b) != "[]\n" {
		t.Errorf("addr: %+v %q", s, b)
	}
	// ss printed nothing: an empty, complete ok section.
	if s, b := section(t, doc, "sockets"); s.Status != "ok" || s.Truncated || len(b) != 0 {
		t.Errorf("sockets: %+v %q", s, b)
	}
}

// conntrack without CAP_NET_ADMIN exits non-zero: "failed", never an
// empty ok table, and whatever it printed is not kept.
func TestNetFactsScriptFailedCommandHasNoData(t *testing.T) {
	h := newNetHost(t)
	allNetTools(t, h)
	h.tool(t, "conntrack", `echo "partial" ; echo "conntrack v1.4.7 (conntrack-tools): Operation failed: Operation not permitted" >&2; exit 1`)
	_, doc := h.run(t)
	if s, b := section(t, doc, "conntrack"); s.Status != "failed" || s.Truncated || len(b) != 0 {
		t.Fatalf("conntrack: %+v %q", s, b)
	}
}

func TestNetFactsScriptTruncatesSection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		trunc bool
	}{
		{"below", netfacts.MaxSection - 1, false},
		{"exact", netfacts.MaxSection, false},
		{"one over", netfacts.MaxSection + 1, true},
		{"far over", 3 * netfacts.MaxSection, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newNetHost(t)
			allNetTools(t, h)
			data := bytes.Repeat([]byte("0123456789abcdef\n"), tc.size/17+1)[:tc.size]
			h.output(t, "ss -tinuaH", data)
			_, doc := h.run(t)
			s, b := section(t, doc, "sockets")
			keep := min(tc.size, netfacts.MaxSection)
			if s.Status != "ok" || s.Truncated != tc.trunc || !bytes.Equal(b, data[:keep]) {
				t.Fatalf("%+v len %d", s, len(b))
			}
		})
	}
}

// Every command printing far more than its cap: the document stays below
// the executor's result limit, sections are cut at the remaining budget,
// and once it is spent the remaining commands do not run.
func TestNetFactsScriptTotalBudget(t *testing.T) {
	h := newNetHost(t)
	allNetTools(t, h)
	big := bytes.Repeat([]byte("x"), 2*netfacts.MaxSection)
	for _, c := range netFactsCommands {
		h.output(t, c.cmd, big)
	}
	out, doc := h.run(t)
	if len(out) > hostrun.MaxResult {
		t.Fatalf("document %d bytes", len(out))
	}
	total := 0
	var skipped []string
	for _, c := range netFactsCommands {
		s, b := section(t, doc, c.section)
		total += len(b)
		switch s.Status {
		case "ok":
			if !s.Truncated || len(b) == 0 || len(b) > netfacts.MaxSection {
				t.Errorf("%s: %+v len %d", c.section, s, len(b))
			}
		case "skipped":
			if !s.Truncated || len(b) != 0 {
				t.Errorf("%s: %+v", c.section, s)
			}
			skipped = append(skipped, c.section)
		default:
			t.Errorf("%s: %+v", c.section, s)
		}
	}
	if total != netfacts.MaxTotal {
		t.Errorf("kept %d bytes, want the whole budget %d", total, netfacts.MaxTotal)
	}
	if len(skipped) == 0 || skipped[len(skipped)-1] != "conntrack" {
		t.Errorf("skipped %v", skipped)
	}
	calls, _ := os.ReadFile(h.calls)
	for _, name := range skipped {
		for _, c := range netFactsCommands {
			if c.section == name && strings.Contains(string(calls), c.cmd+"\n") {
				t.Errorf("skipped %s still ran", name)
			}
		}
	}
}

// What the script prints is what the decoder accepts, also when the
// budget cut and skipped sections.
func TestNetFactsScriptOutputDecodes(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "netfacts", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	h := newNetHost(t)
	h.tool(t, "ip", "")
	h.tool(t, "ss", "")
	h.tool(t, "conntrack", `echo "Operation not permitted" >&2; exit 1`)
	h.output(t, "ip -j addr", read("proxmox-addr.json"))
	h.output(t, "ip -j -d link", read("proxmox-link.json"))
	h.output(t, "ip -j route", read("debian12-route.json"))
	h.output(t, "ip -j -6 route", read("ipv6-route.json"))
	h.output(t, "ip -j neigh", read("debian12-neigh.json"))
	h.output(t, "ip -j -6 neigh", []byte("[]\n"))
	h.output(t, "ss -tinuaH", read("debian12-ss.txt"))
	out, _ := h.run(t)
	f, err := netfacts.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if f.Incomplete() || len(f.Addrs.Entries) == 0 || len(f.Sockets.Entries) == 0 ||
		f.Sections[netfacts.SectionConntrack].Status != netfacts.StatusFailed ||
		f.Sections[netfacts.SectionBridgeVLAN].Status != netfacts.StatusAbsent {
		t.Fatalf("%+v", f.Sections)
	}

	big := newNetHost(t)
	allNetTools(t, big)
	for _, c := range netFactsCommands {
		big.output(t, c.cmd, bytes.Repeat([]byte("y"), 2*netfacts.MaxSection))
	}
	out, _ = big.run(t)
	f, err = netfacts.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Incomplete() || f.Sections[netfacts.SectionConntrack].Status != netfacts.StatusSkipped {
		t.Fatalf("%+v", f.Sections)
	}
}

// The script writes no temporary file: it runs without mktemp and rm,
// and TMPDIR stays empty, so a run killed at its timeout leaves nothing
// behind on the host.
func TestNetFactsScriptWritesNoFile(t *testing.T) {
	a, _ := Lookup("net.facts")
	if bytes.Contains(a.Script, []byte("mktemp")) {
		t.Error("script uses mktemp")
	}
	h := newNetHost(t)
	allNetTools(t, h)
	h.output(t, "ip -j addr", []byte("[]\n"))
	tmp := filepath.Join(h.dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.dir, "action.sh")
	if err := os.WriteFile(p, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = h.dir
	cmd.Env = []string{"PATH=" + h.bin, "TMPDIR=" + tmp}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v (%q)", err, out)
	}
	if !bytes.HasPrefix(out, []byte(`{"format":"net-facts-v1","phase":"done"`)) {
		t.Fatalf("result %q", out)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("files left in TMPDIR: %v", left)
	}
}

// On a host booted with ipv6.disable=1, ip -6 exits non-zero with
// EAFNOSUPPORT: both IPv6 sections are "unavailable", and the result is
// complete. Any other ip -6 failure stays "failed".
func TestNetFactsScriptIPv6Disabled(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "netfacts", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	h := newNetHost(t)
	allNetTools(t, h)
	h.tool(t, "ip", `case "$*" in *-6*) echo "partial"; echo "RTNETLINK answers: Address family not supported by protocol" >&2; exit 2 ;; esac`)
	h.output(t, "ip -j addr", read("proxmox-addr.json"))
	h.output(t, "ip -j -d link", read("proxmox-link.json"))
	h.output(t, "ip -j route", read("debian12-route.json"))
	h.output(t, "ip -j neigh", read("debian12-neigh.json"))
	h.output(t, "ss -tinuaH", read("debian12-ss.txt"))
	h.output(t, "bridge -j vlan", []byte("[]\n"))
	out, doc := h.run(t)
	for _, name := range []string{"route6", "neigh6"} {
		if s, b := section(t, doc, name); s.Status != "unavailable" || s.Truncated || len(b) != 0 {
			t.Errorf("%s: %+v %q", name, s, b)
		}
	}
	f, err := netfacts.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if f.Incomplete() || !f.IPv6Unavailable() || len(f.Routes.Entries) == 0 {
		t.Fatalf("%+v", f.Sections)
	}

	// Another failure of ip -6 is not mistaken for disabled IPv6, and the
	// family check is limited to the IPv6 sections.
	o := newNetHost(t)
	allNetTools(t, o)
	o.tool(t, "ip", `case "$*" in *-6*) echo "RTNETLINK answers: Operation not permitted" >&2; exit 2 ;; esac`)
	o.tool(t, "conntrack", `echo "Address family not supported by protocol" >&2; exit 1`)
	_, doc = o.run(t)
	for _, name := range []string{"route6", "neigh6", "conntrack"} {
		if s, _ := section(t, doc, name); s.Status != "failed" {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

// A hostile or wrapped ss cannot smuggle data through fd 3 or 4, which
// the script uses for the exit status.
func TestNetFactsScriptCommandCannotWriteStatus(t *testing.T) {
	h := newNetHost(t)
	allNetTools(t, h)
	h.tool(t, "ss", `echo "9,1:" >&3 2>/dev/null; echo "9,1:" >&4 2>/dev/null; echo "tcp ESTAB 0 0 10.0.0.2:22 10.0.0.9:51000"`)
	_, doc := h.run(t)
	s, b := section(t, doc, "sockets")
	if s.Status != "ok" || string(b) != "tcp ESTAB 0 0 10.0.0.2:22 10.0.0.9:51000\n" {
		t.Fatalf("%+v %q", s, b)
	}
}
