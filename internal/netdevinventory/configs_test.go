// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for config versions, diffs and their retention (ADR 0010 D4
// "Config versions, diff and drift", plan ND-17 part 1).

package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// snap builds a valid snapshot of lines whose raw_digest is raw repeated.
func snap(raw byte, lines ...string) netdevcontract.ConfigSnapshot {
	return netdevcontract.ConfigSnapshot{
		Lines:          lines,
		RawDigest:      strings.Repeat(string(raw), 64),
		RedactedDigest: netdevcontract.RedactedDigestOf(lines),
	}
}

func record(t *testing.T, s *Store, dev string, cfg ConfigKind, at time.Time, c netdevcontract.ConfigSnapshot) RecordConfigResult {
	t.Helper()
	res, err := s.RecordConfig(context.Background(), dev, cfg, testGen(dev), at, "lease-1", c)
	if err != nil {
		t.Fatalf("RecordConfig: %v", err)
	}
	return res
}

func list(t *testing.T, s *Store, dev string, cfg ConfigKind) []ConfigVersion {
	t.Helper()
	vs, err := s.ListConfigVersions(context.Background(), dev, cfg)
	if err != nil {
		t.Fatalf("ListConfigVersions: %v", err)
	}
	return vs
}

func countVersions(t *testing.T, db *sql.DB) int {
	t.Helper()
	return countRows(t, db, `SELECT COUNT(*) FROM netdev_config_versions`)
}

func TestSameRawDigestAddsNoVersion(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	t1, t2, t3, t4 := testBase.Add(-4*time.Hour), testBase.Add(-3*time.Hour), testBase.Add(-2*time.Hour), testBase.Add(-time.Hour)
	a := snap('a', "hostname sw", "vlan 10")
	b := snap('b', "hostname sw", "vlan 10", "vlan 20")

	ra := record(t, s, "sw-core", ConfigRunning, t1, a)
	if !ra.New {
		t.Fatal("first read is not a new version")
	}
	if r := record(t, s, "sw-core", ConfigRunning, t2, a); r.New || r.VersionID != ra.VersionID {
		t.Fatalf("identical read = %+v, want the existing version %d", r, ra.VersionID)
	}
	if n := countVersions(t, db); n != 1 {
		t.Fatalf("versions = %d after identical read, want 1", n)
	}
	vs := list(t, s, "sw-core", ConfigRunning)
	if len(vs) != 1 || !vs[0].FirstSeen.Equal(t1) || !vs[0].LastSeen.Equal(t2) || vs[0].LeaseID != "lease-1" {
		t.Fatalf("version = %+v, want first_seen %v last_seen %v", vs, t1, t2)
	}

	rb := record(t, s, "sw-core", ConfigRunning, t3, b)
	if !rb.New || rb.VersionID == ra.VersionID {
		t.Fatalf("new raw_digest = %+v, want a new version", rb)
	}
	// Returning to A is not a new version; A becomes current again.
	if r := record(t, s, "sw-core", ConfigRunning, t4, a); r.New || r.VersionID != ra.VersionID {
		t.Fatalf("return to A = %+v, want version %d", r, ra.VersionID)
	}
	vs = list(t, s, "sw-core", ConfigRunning)
	if len(vs) != 2 || vs[0].ID != ra.VersionID || vs[1].ID != rb.VersionID {
		t.Fatalf("list = %+v, want A then B", vs)
	}
	// Running and startup are versioned separately.
	if r := record(t, s, "sw-core", ConfigStartup, t4, a); !r.New {
		t.Fatal("first startup read is not a new version")
	}
	if got := len(list(t, s, "sw-core", ConfigStartup)); got != 1 {
		t.Fatalf("startup versions = %d, want 1", got)
	}
}

func TestRawOnlyChangeIsNewVersionWithSameText(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	lines := []string{"<config><address/></config>"}
	record(t, s, "fw-edge", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', lines...))
	r := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-time.Hour), snap('b', lines...))
	if !r.New {
		t.Fatal("a new raw_digest with the same redacted text is not a new version")
	}
	d, err := s.ConfigChangedNotDisplayed(context.Background(), "fw-edge")
	if err != nil || !d.NotDisplayed {
		t.Fatalf("drift = %+v, %v; want not displayed", d, err)
	}
}

func TestSameRawDigestOtherTextIsRefused(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	at := testBase.Add(-2 * time.Hour)
	record(t, s, "sw-core", ConfigRunning, at, snap('a', "hostname sw"))
	_, err := s.RecordConfig(context.Background(), "sw-core", ConfigRunning, testGen("sw-core"), at.Add(time.Hour), "", snap('a', "hostname other"))
	if !errors.Is(err, ErrRedactionMismatch) {
		t.Fatalf("err = %v, want ErrRedactionMismatch", err)
	}
	vs := list(t, s, "sw-core", ConfigRunning)
	if countVersions(t, db) != 1 || !vs[0].LastSeen.Equal(at) {
		t.Fatalf("refused read changed the stored version: %+v", vs)
	}
	v, err := s.GetConfigVersion(context.Background(), "sw-core", vs[0].ID)
	if err != nil || !slices.Equal(v.Lines, []string{"hostname sw"}) {
		t.Fatalf("stored text = %q, %v", v.Lines, err)
	}
}

func linesN(n int, f func(i int) string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func TestRecordConfigRejections(t *testing.T) {
	ok := snap('a', "hostname sw")
	badRaw := ok
	badRaw.RawDigest = strings.Repeat("A", 64)
	badRed := ok
	badRed.RedactedDigest = strings.Repeat("0", 64)
	longLine := strings.Repeat("x", netdevcontract.MaxLineBytes+1)
	// MaxRedactedConfigBytes+1 bytes in lines of at most MaxLineBytes.
	perLine := netdevcontract.MaxLineBytes
	nBig := netdevcontract.MaxRedactedConfigBytes/(perLine+1) + 1
	big := linesN(nBig, func(int) string { return strings.Repeat("y", perLine) })

	cases := []struct {
		name  string
		dev   string
		cfg   ConfigKind
		gen   uint64
		at    time.Time
		lease string
		c     netdevcontract.ConfigSnapshot
		want  error
	}{
		{"unknown device", "sw-none", ConfigRunning, 2, testBase, "", ok, ErrDeviceNotFound},
		{"unknown config", "sw-core", ConfigKind("candidate"), 2, testBase, "", ok, ErrUnknownConfig},
		{"startup on panos", "fw-edge", ConfigStartup, 1, testBase, "", ok, ErrWrongFamily},
		{"other trust generation", "sw-core", ConfigRunning, 3, testBase, "", ok, ErrTrustGenerationChanged},
		{"future", "sw-core", ConfigRunning, 2, testBase.Add(MaxFutureSkew + time.Second), "", ok, ErrFutureObservation},
		{"before window", "sw-core", ConfigRunning, 2, testBase.Add(-ConfigVersionRetention - time.Second), "", ok, ErrObservationTooOld},
		{"lease too long", "sw-core", ConfigRunning, 2, testBase, strings.Repeat("l", MaxLeaseIDBytes+1), ok, ErrInvalidConfig},
		{"lease with newline", "sw-core", ConfigRunning, 2, testBase, "a\nb", ok, ErrInvalidConfig},
		{"no lines", "sw-core", ConfigRunning, 2, testBase, "", snap('a'), ErrInvalidConfig},
		{"raw digest not lowercase hex", "sw-core", ConfigRunning, 2, testBase, "", badRaw, ErrInvalidConfig},
		{"redacted digest mismatch", "sw-core", ConfigRunning, 2, testBase, "", badRed, ErrInvalidConfig},
		{"line over limit", "sw-core", ConfigRunning, 2, testBase, "", snap('a', longLine), ErrInvalidConfig},
		{"control character", "sw-core", ConfigRunning, 2, testBase, "", snap('a', "hostname \x1b[31mred"), ErrInvalidConfig},
		{"invalid utf-8", "sw-core", ConfigRunning, 2, testBase, "", snap('a', "hostname \xff"), ErrInvalidConfig},
		{"lines over limit", "sw-core", ConfigRunning, 2, testBase, "",
			snap('a', linesN(netdevcontract.MaxConfigLines+1, func(i int) string { return fmt.Sprint("vlan ", i) })...), ErrInvalidConfig},
		{"bytes over limit", "sw-core", ConfigRunning, 2, testBase, "", snap('a', big...), ErrInvalidConfig},
	}
	// One store for all cases: every case is refused, so none may leave a
	// version behind for the next.
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.RecordConfig(context.Background(), tc.dev, tc.cfg, tc.gen, tc.at, tc.lease, tc.c)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if n := countVersions(t, db); n != 0 {
				t.Fatalf("refused read stored %d versions", n)
			}
		})
	}
}

func TestRecordConfigAtLimits(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	lines := linesN(netdevcontract.MaxConfigLines, func(i int) string { return fmt.Sprint("vlan ", i) })
	lines[0] = strings.Repeat("z", netdevcontract.MaxLineBytes)
	record(t, s, "sw-core", ConfigRunning, testBase.Add(-ConfigVersionRetention), snap('a', lines...))
	if _, err := s.RecordConfig(context.Background(), "sw-core", ConfigRunning, 2, testBase, strings.Repeat("l", MaxLeaseIDBytes), snap('c', "x")); err != nil {
		t.Fatalf("lease at limit: %v", err)
	}
	record(t, s, "sw-core", ConfigRunning, testBase.Add(MaxFutureSkew), snap('b', "hostname sw"))
}

func TestNewVersionOlderThanCurrentIsRefused(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	at := testBase.Add(-time.Hour)
	record(t, s, "sw-core", ConfigRunning, at, snap('a', "hostname sw"))
	for _, obs := range []time.Time{at, at.Add(-time.Minute)} {
		_, err := s.RecordConfig(context.Background(), "sw-core", ConfigRunning, 2, obs, "", snap('b', "hostname x"))
		if !errors.Is(err, ErrOutOfOrder) {
			t.Fatalf("at %v: err = %v, want ErrOutOfOrder", obs, err)
		}
	}
	// A delayed read of the stored version never moves last_seen back.
	if r := record(t, s, "sw-core", ConfigRunning, at.Add(-time.Minute), snap('a', "hostname sw")); r.New {
		t.Fatal("delayed identical read made a new version")
	}
	vs := list(t, s, "sw-core", ConfigRunning)
	if countVersions(t, db) != 1 || !vs[0].LastSeen.Equal(at) || !vs[0].FirstSeen.Equal(at.Add(-time.Minute)) {
		t.Fatalf("versions = %+v", vs)
	}
}

func TestHostileConfigTextStaysText(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	hostile := []string{
		`interface gi1 description <script>alert(1)</script>`,
		`banner "{{.Secret}}" & '; DROP TABLE x; --`,
		"\tsnmp-server location <redacted:deadbeef>",
	}
	r := record(t, s, "sw-core", ConfigRunning, testBase.Add(-time.Hour), snap('a', hostile...))
	v, err := s.GetConfigVersion(context.Background(), "sw-core", r.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.Lines, hostile) {
		t.Fatalf("lines = %q, want verbatim %q", v.Lines, hostile)
	}
	r2 := record(t, s, "sw-core", ConfigRunning, testBase, snap('b', hostile[:2]...))
	d, err := s.DiffConfigVersions(context.Background(), "sw-core", r.VersionID, r2.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	want := []textdiff.Line{{Op: textdiff.Equal, Text: hostile[0]}, {Op: textdiff.Equal, Text: hostile[1]}, {Op: textdiff.Delete, Text: hostile[2]}}
	if !slices.Equal(d.Lines, want) || d.Normalized {
		t.Fatalf("diff = %+v", d)
	}
}

func TestPANOSHostileXMLStaysOneLinePerElement(t *testing.T) {
	text := `<config><address><entry name="a&#10;  entry[name=&quot;forged&quot;]"><description>&lt;script&gt;x&lt;/script&gt;&#10;line2</description></entry></address></config>`
	lines, ok := NormalizePANOSConfig(text)
	if !ok {
		t.Fatal("well-formed XML not normalized")
	}
	want := []string{
		`config`,
		`  address`,
		`    entry[name="a\n  entry[name=\"forged\"]"]`,
		`      description = "<script>x</script>\nline2"`,
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines = %q, want %q", lines, want)
	}
}

func TestPANOSNormalizationRemovesOrderAndTimestampNoise(t *testing.T) {
	a := `<config><devices><entry name="localhost"><vsys><entry name="vsys1">` +
		`<address admin="nos" dirtyId="3" time="2026/11/09 10:00:00">` +
		`<entry name="web" uuid="u-1"><ip-netmask>10.0.0.1/32</ip-netmask><tag><member>b</member><member>a</member></tag></entry>` +
		`<entry name="db"><ip-netmask>10.0.0.2/32</ip-netmask></entry></address>` +
		`<rulebase><security><rules><entry name="r2"><action>allow</action></entry><entry name="r1"><action>deny</action></entry></rules></security></rulebase>` +
		`</entry></vsys></entry></devices></config>`
	// Same configuration: other sibling order outside the rulebase, other
	// change timestamps and dirty IDs, indentation.
	b := "<config>\n <devices><entry name=\"localhost\"><vsys><entry name=\"vsys1\">\n" +
		`<rulebase><security><rules><entry name="r2"><action>allow</action></entry><entry name="r1"><action>deny</action></entry></rules></security></rulebase>` +
		`<address admin="other" dirtyId="9" time="2026/11/10 11:11:11">` +
		`<entry name="db"><ip-netmask>10.0.0.2/32</ip-netmask></entry>` +
		`<entry uuid="u-1" name="web"><tag><member>a</member><member>b</member></tag><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>` +
		"</entry></vsys></entry></devices>\n</config>"
	// Rule order is meaningful and stays a change.
	c := strings.Replace(b, `<entry name="r2"><action>allow</action></entry><entry name="r1"><action>deny</action></entry>`,
		`<entry name="r1"><action>deny</action></entry><entry name="r2"><action>allow</action></entry>`, 1)

	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	va := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-3*time.Hour), snap('a', a))
	vb := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-2*time.Hour), snap('b', strings.Split(b, "\n")...))
	vc := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-time.Hour), snap('c', strings.Split(c, "\n")...))

	d, err := s.DiffConfigVersions(context.Background(), "fw-edge", va.VersionID, vb.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Normalized || d.Changed || !d.NotDisplayed {
		t.Fatalf("noise-only diff = %+v, want normalized, unchanged, not displayed", d)
	}
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "time") || strings.Contains(l.Text, "dirtyId") || strings.Contains(l.Text, "admin") {
			t.Fatalf("volatile attribute in normalized line %q", l.Text)
		}
	}
	if !slices.ContainsFunc(d.Lines, func(l textdiff.Line) bool { return l.Text == `            entry[name="web" uuid="u-1"]` }) {
		t.Fatalf("uuid not kept: %+v", d.Lines)
	}
	d, err = s.DiffConfigVersions(context.Background(), "fw-edge", vb.VersionID, vc.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Normalized || !d.Changed || d.NotDisplayed {
		t.Fatalf("rule reorder diff = %+v, want a change", d)
	}
}

func TestPANOSNormalizationKeepsSignificantOrderAndAttributes(t *testing.T) {
	const pre = `<config><devices><entry name="localhost"><network>`
	const post = `</network></entry></devices></config>`
	ike := func(enc string) string {
		return pre + `<ike><crypto-profiles><ike-crypto-profiles><entry name="p1"><encryption>` + enc +
			`</encryption><hash><member>sha256</member></hash></entry></ike-crypto-profiles></crypto-profiles></ike>` + post
	}
	ipsec := func(auth string) string {
		return pre + `<ike><crypto-profiles><ipsec-crypto-profiles><entry name="p2"><esp><authentication>` + auth +
			`</authentication></esp></entry></ipsec-crypto-profiles></crypto-profiles></ike>` + post
	}
	seq := func(m string) string {
		return `<config><shared><authentication-sequence><entry name="s"><authentication-profiles>` + m +
			`</authentication-profiles></entry></authentication-sequence></shared></config>`
	}
	attr := func(a string) string {
		return `<config><devices><entry name="localhost"><address><entry name="web"` + a +
			`><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></entry></devices></config>`
	}
	cases := []struct{ name, a, b string }{
		{"ike encryption order", ike(`<member>aes-256-cbc</member><member>3des</member>`), ike(`<member>3des</member><member>aes-256-cbc</member>`)},
		{"ike hash order", strings.Replace(ike(`<member>x</member>`), `<member>sha256</member>`, `<member>sha256</member><member>sha1</member>`, 1),
			strings.Replace(ike(`<member>x</member>`), `<member>sha256</member>`, `<member>sha1</member><member>sha256</member>`, 1)},
		{"ipsec authentication order", ipsec(`<member>sha256</member><member>sha1</member>`), ipsec(`<member>sha1</member><member>sha256</member>`)},
		{"authentication sequence order", seq(`<member>ldap</member><member>local</member>`), seq(`<member>local</member><member>ldap</member>`)},
		{"loc attribute", attr(``), attr(` loc="vsys1"`)},
		{"ptpl attribute", attr(``), attr(` ptpl="tpl-a"`)},
		{"src attribute", attr(` src="tpl"`), attr(``)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, okA := NormalizePANOSConfig(tc.a)
			b, okB := NormalizePANOSConfig(tc.b)
			if !okA || !okB {
				t.Fatal("not normalized")
			}
			if slices.Equal(a, b) {
				t.Fatalf("significant difference dropped: %q", a)
			}
		})
	}
	// Under a visible change elsewhere, the significant one is still shown.
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	x := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', attr(``)))
	y := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-time.Hour),
		snap('b', strings.Replace(attr(` loc="vsys1"`), "10.0.0.1", "10.0.0.9", 1)))
	d, err := s.DiffConfigVersions(context.Background(), "fw-edge", x.VersionID, y.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Normalized || !slices.ContainsFunc(d.Lines, func(l textdiff.Line) bool {
		return l.Op == textdiff.Insert && strings.Contains(l.Text, `loc="vsys1"`)
	}) {
		t.Fatalf("loc change hidden next to a visible change: %+v", d)
	}
}

func TestPANOSNormalizationCappedAtConfigLines(t *testing.T) {
	at := `<config>` + strings.Repeat(`<b/>`, netdevcontract.MaxConfigLines-1) + `</config>`
	if lines, ok := NormalizePANOSConfig(at); !ok || len(lines) != netdevcontract.MaxConfigLines {
		t.Fatalf("at line limit: ok=%v lines=%d", ok, len(lines))
	}
	over := `<config>` + strings.Repeat(`<b/>`, netdevcontract.MaxConfigLines) + `</config>`
	if _, ok := NormalizePANOSConfig(over); ok {
		t.Fatal("normalized output over MaxConfigLines accepted")
	}
}

func TestCBSDiffIsNotNormalized(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	// Order matters on CBS, and XML-looking text is not parsed.
	a := record(t, s, "sw-core", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', "<a>", "vlan 10", "vlan 20"))
	b := record(t, s, "sw-core", ConfigRunning, testBase.Add(-time.Hour), snap('b', "<a>", "vlan 20", "vlan 10"))
	d, err := s.DiffConfigVersions(context.Background(), "sw-core", a.VersionID, b.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Normalized || !d.Changed || d.NotDisplayed {
		t.Fatalf("diff = %+v", d)
	}
	if got := applyDiff(d.Lines, false); !slices.Equal(got, []string{"<a>", "vlan 20", "vlan 10"}) {
		t.Fatalf("new side = %q", got)
	}
}

func TestPANOSMalformedFallsBackToStoredLines(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	a := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', "<config>", "<dropped:mgt-config count=3>", "</config>"))
	b := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-time.Hour), snap('b', "<config><x/></config>"))
	d, err := s.DiffConfigVersions(context.Background(), "fw-edge", a.VersionID, b.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Normalized || !d.Changed {
		t.Fatalf("diff = %+v, want stored lines of both sides", d)
	}
	if got := applyDiff(d.Lines, true); !slices.Equal(got, []string{"<config>", "<dropped:mgt-config count=3>", "</config>"}) {
		t.Fatalf("old side = %q", got)
	}
}

func TestPANOSNormalizationLimits(t *testing.T) {
	deep := strings.Repeat("<a>", netdevcontract.MaxXMLDepth) + strings.Repeat("</a>", netdevcontract.MaxXMLDepth)
	if lines, ok := NormalizePANOSConfig(deep); !ok || len(lines) != netdevcontract.MaxXMLDepth {
		t.Fatalf("depth at limit: ok=%v lines=%d", ok, len(lines))
	}
	tooDeep := "<a>" + deep + "</a>"
	if _, ok := NormalizePANOSConfig(tooDeep); ok {
		t.Fatal("depth over limit normalized")
	}
	if _, ok := NormalizePANOSConfig(`<!DOCTYPE x [<!ENTITY e "boom">]><a>&e;</a>`); ok {
		t.Fatal("DTD normalized")
	}
	if _, ok := NormalizePANOSConfig(`<a><b>` + strings.Repeat("t", netdevcontract.MaxXMLTextBytes+1) + `</b></a>`); ok {
		t.Fatal("text over limit normalized")
	}
	// Few input bytes per element at depth 63 give a rendered text far
	// over MaxNormalizedConfigBytes: refused instead of amplified.
	open := strings.Repeat("<a>", netdevcontract.MaxXMLDepth-1)
	close := strings.Repeat("</a>", netdevcontract.MaxXMLDepth-1)
	wide := open + strings.Repeat("<b/>", netdevcontract.MaxXMLElements-netdevcontract.MaxXMLDepth) + close
	if _, ok := NormalizePANOSConfig(wide); ok {
		t.Fatal("rendered text over MaxNormalizedConfigBytes normalized")
	}
}

// applyDiff returns the old (old=true) or new side of a diff.
func applyDiff(d []textdiff.Line, old bool) []string {
	var out []string
	for _, l := range d {
		if l.Op == textdiff.Equal || (old && l.Op == textdiff.Delete) || (!old && l.Op == textdiff.Insert) {
			out = append(out, l.Text)
		}
	}
	return out
}

func TestDiffAtLineLimitIsCorrectAndBounded(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	n := netdevcontract.MaxConfigLines
	oldL := linesN(n, func(i int) string { return fmt.Sprint("vlan ", i) })
	// More changes than textdiff.MaxEdits: shown as a full replacement of
	// the changed middle, still a correct edit script.
	newL := linesN(n, func(i int) string {
		if i%50 == 0 {
			return fmt.Sprint("vlan ", i, " name changed")
		}
		return fmt.Sprint("vlan ", i)
	})
	a := record(t, s, "sw-core", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', oldL...))
	b := record(t, s, "sw-core", ConfigRunning, testBase.Add(-time.Hour), snap('b', newL...))
	d, err := s.DiffConfigVersions(context.Background(), "sw-core", a.VersionID, b.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Changed || !slices.Equal(applyDiff(d.Lines, true), oldL) || !slices.Equal(applyDiff(d.Lines, false), newL) {
		t.Fatal("diff at the line limit is not a correct edit script")
	}
	if len(d.Lines) > 2*n {
		t.Fatalf("diff has %d lines, more than both sides", len(d.Lines))
	}
}

func TestDiffKeepsTrailingEmptyLine(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	a := record(t, s, "sw-core", ConfigRunning, testBase.Add(-2*time.Hour), snap('a', "x"))
	b := record(t, s, "sw-core", ConfigRunning, testBase.Add(-time.Hour), snap('b', "x", ""))
	d, err := s.DiffConfigVersions(context.Background(), "sw-core", a.VersionID, b.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Changed || d.NotDisplayed {
		t.Fatalf("diff = %+v, want the added empty line", d)
	}
}

func TestDiffRefusesForeignOrMissingVersions(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())
	sw := record(t, s, "sw-core", ConfigRunning, testBase.Add(-time.Hour), snap('a', "hostname sw"))
	fw := record(t, s, "fw-edge", ConfigRunning, testBase.Add(-time.Hour), snap('a', "<config/>"))
	for _, ids := range [][2]int64{{sw.VersionID, fw.VersionID}, {fw.VersionID, sw.VersionID}, {sw.VersionID, 9999}} {
		if _, err := s.DiffConfigVersions(context.Background(), "sw-core", ids[0], ids[1]); !errors.Is(err, ErrConfigVersionNotFound) {
			t.Fatalf("diff %v: err = %v, want ErrConfigVersionNotFound", ids, err)
		}
	}
	if _, err := s.GetConfigVersion(context.Background(), "sw-core", fw.VersionID); !errors.Is(err, ErrConfigVersionNotFound) {
		t.Fatalf("get foreign: err = %v", err)
	}
	if _, err := s.ListConfigVersions(context.Background(), "sw-none", ConfigRunning); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("list unknown device: err = %v", err)
	}
	if _, err := s.ListConfigVersions(context.Background(), "sw-core", "candidate"); !errors.Is(err, ErrUnknownConfig) {
		t.Fatalf("list unknown config: err = %v", err)
	}
	// Running against startup of the same device is a valid comparison.
	st := record(t, s, "sw-core", ConfigStartup, testBase.Add(-time.Hour), snap('b', "hostname sw"))
	d, err := s.DiffConfigVersions(context.Background(), "sw-core", sw.VersionID, st.VersionID)
	if err != nil || d.Changed || !d.NotDisplayed {
		t.Fatalf("running vs startup = %+v, %v", d, err)
	}
}

// markProtected sets the baseline flag or the change binding the way the
// executor-mirroring code of ND-17 part 2 will.
func markProtected(t *testing.T, db *sql.DB, id int64, baseline bool, changeBound *time.Time) {
	t.Helper()
	var cb any
	if changeBound != nil {
		cb = micros(*changeBound)
	}
	if _, err := db.Exec(`UPDATE netdev_config_versions SET baseline = ?, change_bound_at = ? WHERE id = ?`,
		boolInt(baseline), cb, id); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionNeverPrunesBaselineOrChangeBoundVersions(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	start := testBase.Add(-time.Hour)
	base := record(t, s, "sw-core", ConfigRunning, start, snap('1', "v1"))
	bound := record(t, s, "sw-core", ConfigRunning, start.Add(time.Minute), snap('2', "v2"))
	plain := record(t, s, "sw-core", ConfigRunning, start.Add(2*time.Minute), snap('3', "v3"))
	oldBound := record(t, s, "sw-core", ConfigRunning, start.Add(3*time.Minute), snap('4', "v4"))
	markProtected(t, db, base.VersionID, true, nil)

	// 500 days later; one change 10 days ago, one 450 days ago.
	*now = testBase.Add(500 * 24 * time.Hour)
	recent, old := now.Add(-10*24*time.Hour), now.Add(-450*24*time.Hour)
	markProtected(t, db, bound.VersionID, false, &recent)
	markProtected(t, db, oldBound.VersionID, false, &old)
	cur := record(t, s, "sw-core", ConfigRunning, now.Add(-time.Minute), snap('5', "v5"))
	// A re-read of the baseline keeps it the baseline.
	if r := record(t, s, "sw-core", ConfigRunning, *now, snap('1', "v1")); r.New || r.VersionID != base.VersionID {
		t.Fatalf("baseline re-read = %+v", r)
	}
	// Fill past the count limit with unprotected versions.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxConfigVersionsPerDevice + 10 {
		at := micros(now.Add(-time.Duration(i+2) * time.Hour))
		d := fmt.Sprintf("%064x", 1<<20+i)
		if _, err := tx.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
			redacted_text, first_seen, last_seen) VALUES ('sw-core', 'running', ?, ?, 'x', ?, ?)`, d, d, at, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids := configIDs(t, db)
	for id, want := range map[int64]bool{base.VersionID: true, bound.VersionID: true, cur.VersionID: true,
		plain.VersionID: false, oldBound.VersionID: false} {
		if ids[id] != want {
			t.Errorf("version %d kept = %v, want %v", id, ids[id], want)
		}
	}
	if len(ids) != MaxConfigVersionsPerDevice {
		t.Fatalf("kept %d versions, want %d", len(ids), MaxConfigVersionsPerDevice)
	}
	vs := list(t, s, "sw-core", ConfigRunning)
	if vs[0].ID != base.VersionID || !vs[0].Baseline {
		t.Fatalf("current version = %+v, want the baseline", vs[0])
	}
	if i := slices.IndexFunc(vs, func(v ConfigVersion) bool { return v.ID == bound.VersionID }); i < 0 || !vs[i].ChangeBoundAt.Equal(recent) {
		t.Fatalf("change binding not listed: %+v", vs)
	}
}

// fillVersions inserts n unprotected versions of (dev, cfg) directly, the
// newest an hour before at, one hour apart.
func fillVersions(t *testing.T, db *sql.DB, dev string, cfg ConfigKind, at time.Time, n, seed int) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		ts := micros(at.Add(-time.Duration(i+1) * time.Hour))
		d := fmt.Sprintf("%064x", seed+i)
		if _, err := tx.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
			redacted_text, first_seen, last_seen) VALUES (?, ?, ?, ?, 'x', ?, ?)`, dev, string(cfg), d, d, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestEveryReadChangingStaysAtVersionCap(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	start := testBase.Add(-30 * 24 * time.Hour)
	base := record(t, s, "sw-core", ConfigRunning, start, snap('1', "v1"))
	bound := record(t, s, "sw-core", ConfigRunning, start.Add(time.Minute), snap('2', "v2"))
	markProtected(t, db, base.VersionID, true, nil)
	recent := testBase.Add(-24 * time.Hour)
	markProtected(t, db, bound.VersionID, false, &recent)
	startup := record(t, s, "sw-core", ConfigStartup, start.Add(2*time.Minute), snap('3', "s1"))
	// Earlier history up to just under the cap, oldest the hour before start.
	fillVersions(t, db, "sw-core", ConfigRunning, start, MaxConfigVersionsPerDevice-3-20, 1<<20)
	oldest := configMaxID(t, db)

	// A config whose raw digest changes on every read (a counter outside
	// the redaction allowlist), read every minute, without any Prune.
	const reads = 80
	var last RecordConfigResult
	for i := range reads {
		c := netdevcontract.ConfigSnapshot{Lines: []string{"hostname sw"}, RawDigest: fmt.Sprintf("%064x", 1<<24+i),
			RedactedDigest: netdevcontract.RedactedDigestOf([]string{"hostname sw"})}
		last = record(t, s, "sw-core", ConfigRunning, start.Add(time.Duration(10+i)*time.Minute), c)
		if !last.New {
			t.Fatalf("read %d made no new version", i)
		}
		if n := countVersions(t, db); n > MaxConfigVersionsPerDevice {
			t.Fatalf("read %d: %d versions, over the cap %d", i, n, MaxConfigVersionsPerDevice)
		}
	}
	ids := configIDs(t, db)
	if len(ids) != MaxConfigVersionsPerDevice {
		t.Fatalf("kept %d versions, want %d", len(ids), MaxConfigVersionsPerDevice)
	}
	for _, id := range []int64{base.VersionID, bound.VersionID, startup.VersionID, last.VersionID} {
		if !ids[id] {
			t.Errorf("protected or newest version %d was pruned on write", id)
		}
	}
	// The oldest unprotected versions went first: the oldest of the earlier
	// history is gone, every counter version is kept.
	if ids[oldest] {
		t.Error("oldest unprotected version kept")
	}
	for id := last.VersionID - reads + 1; id <= last.VersionID; id++ {
		if !ids[id] {
			t.Errorf("newer version %d pruned before older ones", id)
		}
	}
}

func configMaxID(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`SELECT MAX(id) FROM netdev_config_versions`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestProtectedOverCapAreKeptOnWrite(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	fillVersions(t, db, "sw-core", ConfigRunning, testBase.Add(-time.Hour), MaxConfigVersionsPerDevice+5, 1<<20)
	recent := testBase.Add(-time.Hour)
	if _, err := db.Exec(`UPDATE netdev_config_versions SET change_bound_at = ?`, micros(recent)); err != nil {
		t.Fatal(err)
	}
	r := record(t, s, "sw-core", ConfigRunning, testBase, snap('e', "new"))
	if n := countVersions(t, db); n != MaxConfigVersionsPerDevice+6 {
		t.Fatalf("versions = %d, want every protected version and the new one", n)
	}
	vs := list(t, s, "sw-core", ConfigRunning)
	if len(vs) != MaxConfigVersionsPerDevice+6 || vs[0].ID != r.VersionID {
		t.Fatalf("listed %d versions, want all %d protected ones and the new current first",
			len(vs), MaxConfigVersionsPerDevice+6)
	}
}

// TestWriteCapKeepsOldProtectedOverNewerUnprotected makes the write-path
// cap choose: the baseline, a fresh change binding and the newest version
// of the other config are older than every unprotected filler, so a cap
// without any one protection clause deletes them first. An expired change
// binding is as old and unprotected, so the cap deletes it. Both configs
// are written in turn, so each half of `id IN (?, ?)` is exercised.
func TestWriteCapKeepsOldProtectedOverNewerUnprotected(t *testing.T) {
	for _, tc := range []struct{ written, other ConfigKind }{
		{ConfigRunning, ConfigStartup},
		{ConfigStartup, ConfigRunning},
	} {
		t.Run(string(tc.written), func(t *testing.T) {
			s, db, now := newTestStore(t)
			addDevice(t, s, cbsDevice())
			start := testBase.Add(-60 * 24 * time.Hour)
			base := record(t, s, "sw-core", tc.other, start, snap('1', "v1"))
			fresh := record(t, s, "sw-core", tc.other, start.Add(time.Minute), snap('2', "v2"))
			expired := record(t, s, "sw-core", tc.other, start.Add(2*time.Minute), snap('3', "v3"))
			plain := record(t, s, "sw-core", tc.other, start.Add(3*time.Minute), snap('4', "v4"))
			otherNewest := record(t, s, "sw-core", tc.other, start.Add(4*time.Minute), snap('5', "v5"))
			markProtected(t, db, base.VersionID, true, nil)
			recent := now.Add(-24 * time.Hour)
			markProtected(t, db, fresh.VersionID, false, &recent)
			old := now.Add(-ConfigVersionRetention - time.Hour)
			markProtected(t, db, expired.VersionID, false, &old)

			// Unprotected fillers of the written config, all newer than the
			// versions above (the oldest about 42 days before testBase).
			firstFiller := configMaxID(t, db) + 1
			fillVersions(t, db, "sw-core", tc.written, testBase.Add(-time.Hour), MaxConfigVersionsPerDevice, 1<<20)
			w := record(t, s, "sw-core", tc.written, testBase, snap('e', "new"))

			// 5 + 1000 + 1 versions, 4 protected: the 6 oldest unprotected go,
			// which are expired, plain and the 4 oldest fillers.
			ids := configIDs(t, db)
			if len(ids) != MaxConfigVersionsPerDevice {
				t.Fatalf("kept %d versions, want %d", len(ids), MaxConfigVersionsPerDevice)
			}
			for name, c := range map[string]struct {
				id   int64
				kept bool
			}{
				"baseline":                {base.VersionID, true},
				"fresh change binding":    {fresh.VersionID, true},
				"newest of other config":  {otherNewest.VersionID, true},
				"new version":             {w.VersionID, true},
				"expired change binding":  {expired.VersionID, false},
				"unprotected other":       {plain.VersionID, false},
				"newest deleted filler":   {firstFiller + MaxConfigVersionsPerDevice - 4, false},
				"oldest kept filler":      {firstFiller + MaxConfigVersionsPerDevice - 5, true},
				"newest filler":           {firstFiller, true},
				"oldest filler (deleted)": {firstFiller + MaxConfigVersionsPerDevice - 1, false},
			} {
				if ids[c.id] != c.kept {
					t.Errorf("%s (version %d) kept = %v, want %v", name, c.id, ids[c.id], c.kept)
				}
			}
		})
	}
}

// TestWriteCapCountsAndDeletesOnlyTheWrittenDevice writes one version over
// the cap of device A while device B holds older versions, protected and
// not: the cap deletes exactly A's oldest unprotected version, and B's
// versions are neither deleted nor counted against A's cap.
func TestWriteCapCountsAndDeletesOnlyTheWrittenDevice(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())
	start := testBase.Add(-60 * 24 * time.Hour)
	// Device B: older than every version of A, so an unscoped cap would
	// delete them first.
	bBase := record(t, s, "fw-edge", ConfigRunning, start, snap('1', "<b1/>"))
	bBound := record(t, s, "fw-edge", ConfigRunning, start.Add(time.Minute), snap('2', "<b2/>"))
	bPlain := record(t, s, "fw-edge", ConfigRunning, start.Add(2*time.Minute), snap('3', "<b3/>"))
	bNewest := record(t, s, "fw-edge", ConfigRunning, start.Add(3*time.Minute), snap('4', "<b4/>"))
	markProtected(t, db, bBase.VersionID, true, nil)
	recent := testBase.Add(-24 * time.Hour)
	markProtected(t, db, bBound.VersionID, false, &recent)

	// Device A: exactly the cap of unprotected history, then one new version.
	firstFiller := configMaxID(t, db) + 1
	fillVersions(t, db, "sw-core", ConfigRunning, testBase.Add(-time.Hour), MaxConfigVersionsPerDevice, 1<<20)
	w := record(t, s, "sw-core", ConfigRunning, testBase, snap('e', "new"))

	ids := configIDs(t, db)
	for _, id := range []int64{bBase.VersionID, bBound.VersionID, bPlain.VersionID, bNewest.VersionID} {
		if !ids[id] {
			t.Errorf("version %d of the other device deleted by a write to sw-core", id)
		}
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_config_versions WHERE device_id = 'sw-core'`); n != MaxConfigVersionsPerDevice {
		t.Fatalf("sw-core keeps %d versions, want %d", n, MaxConfigVersionsPerDevice)
	}
	if !ids[w.VersionID] || ids[firstFiller+MaxConfigVersionsPerDevice-1] || !ids[firstFiller+MaxConfigVersionsPerDevice-2] {
		t.Fatal("write did not delete exactly the oldest unprotected version of sw-core")
	}
}

// TestWriteCapChangeBindingBoundaryIsInclusive pins the change-binding
// cutoff of the write-path cap to Prune's configProtected: a binding exactly
// ConfigVersionRetention old protects its version, one a second older does
// not.
func TestWriteCapChangeBindingBoundaryIsInclusive(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	start := testBase.Add(-60 * 24 * time.Hour)
	atCutoff := record(t, s, "sw-core", ConfigRunning, start, snap('1', "v1"))
	before := record(t, s, "sw-core", ConfigRunning, start.Add(time.Minute), snap('2', "v2"))
	cutoff := now.Add(-ConfigVersionRetention)
	markProtected(t, db, atCutoff.VersionID, false, &cutoff)
	beforeCutoff := cutoff.Add(-time.Second)
	markProtected(t, db, before.VersionID, false, &beforeCutoff)

	firstFiller := configMaxID(t, db) + 1
	fillVersions(t, db, "sw-core", ConfigRunning, testBase.Add(-time.Hour), MaxConfigVersionsPerDevice-1, 1<<20)
	w := record(t, s, "sw-core", ConfigRunning, testBase, snap('e', "new"))

	// 2 + 999 + 1 versions, 2 protected (atCutoff, new): the 2 oldest
	// unprotected go, which are the expired binding and the oldest filler.
	ids := configIDs(t, db)
	if len(ids) != MaxConfigVersionsPerDevice {
		t.Fatalf("kept %d versions, want %d", len(ids), MaxConfigVersionsPerDevice)
	}
	for name, c := range map[string]struct {
		id   int64
		kept bool
	}{
		"binding at cutoff":    {atCutoff.VersionID, true},
		"binding 1s before":    {before.VersionID, false},
		"new version":          {w.VersionID, true},
		"oldest filler":        {firstFiller + MaxConfigVersionsPerDevice - 2, false},
		"second oldest filler": {firstFiller + MaxConfigVersionsPerDevice - 3, true},
	} {
		if ids[c.id] != c.kept {
			t.Errorf("%s (version %d) kept = %v, want %v", name, c.id, ids[c.id], c.kept)
		}
	}
}

func TestListKeepsBaselineAndChangeBoundBeyondLimit(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	start := testBase.Add(-60 * 24 * time.Hour)
	base := record(t, s, "sw-core", ConfigRunning, start, snap('1', "v1"))
	bound := record(t, s, "sw-core", ConfigRunning, start.Add(time.Minute), snap('2', "v2"))
	expired := record(t, s, "sw-core", ConfigRunning, start.Add(2*time.Minute), snap('3', "v3"))
	markProtected(t, db, base.VersionID, true, nil)
	recent := testBase.Add(-24 * time.Hour)
	markProtected(t, db, bound.VersionID, false, &recent)
	old := now.Add(-ConfigVersionRetention - time.Hour)
	markProtected(t, db, expired.VersionID, false, &old)
	// More newer versions than the list shows, inserted directly as between
	// two prunes.
	fillVersions(t, db, "sw-core", ConfigRunning, testBase, MaxListedConfigVersions+20, 1<<20)

	vs := list(t, s, "sw-core", ConfigRunning)
	if len(vs) != MaxListedConfigVersions+2 {
		t.Fatalf("listed %d, want the %d newest plus baseline and change-bound", len(vs), MaxListedConfigVersions)
	}
	n := len(vs)
	if vs[n-2].ID != bound.VersionID || vs[n-1].ID != base.VersionID || !vs[n-1].Baseline || !vs[n-2].ChangeBoundAt.Equal(recent) {
		t.Fatalf("list tail = %+v, %+v; want change-bound then baseline", vs[n-2], vs[n-1])
	}
	if slices.ContainsFunc(vs, func(v ConfigVersion) bool { return v.ID == expired.VersionID }) {
		t.Fatal("version with an expired change binding listed beyond the limit")
	}
	for i := 1; i < n; i++ {
		if vs[i].LastSeen.After(vs[i-1].LastSeen) {
			t.Fatalf("list not ordered by last_seen at %d", i)
		}
	}
}
