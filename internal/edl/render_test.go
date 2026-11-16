// SPDX-License-Identifier: AGPL-3.0-or-later

package edl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// wantBody is the rendering of renderInput under any order (sorted, masked,
// deduplicated, single addresses without length).
const wantBody = "81.0.1.0/24\n81.0.1.5\n81.0.2.0/24\n2606:4700::1111\n"

// renderInput holds duplicates, an unmasked network and a host entry.
func renderInput() []netip.Prefix {
	return []netip.Prefix{
		pfx("81.0.2.0/24"),
		pfx("81.0.1.5"),
		pfx("81.0.1.9/24"),
		pfx("2606:4700::1111"),
		pfx("81.0.2.0/24"),
	}
}

// eachPermutation calls fn once for every ordering of xs.
// fn must not retain xs.
func eachPermutation(xs []netip.Prefix, fn func([]netip.Prefix)) {
	var rec func(k int)
	rec = func(k int) {
		if k == len(xs) {
			fn(xs)
			return
		}
		for i := k; i < len(xs); i++ {
			xs[k], xs[i] = xs[i], xs[k]
			rec(k + 1)
			xs[k], xs[i] = xs[i], xs[k]
		}
	}
	rec(0)
}

// TestRenderIsOrderIndependent renders every ordering of the input and
// requires identical bytes and digests.
func TestRenderIsOrderIndependent(t *testing.T) {
	in := renderInput()
	count := 0
	eachPermutation(in, func(p []netip.Prefix) {
		count++
		res, err := Render(p, testRefusals())
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if string(res.Body) != wantBody {
			t.Fatalf("body = %q, want %q", res.Body, wantBody)
		}
		if res.Count != 4 {
			t.Fatalf("Count = %d, want 4", res.Count)
		}
		sum := sha256.Sum256([]byte(wantBody))
		if res.Digest != hex.EncodeToString(sum[:]) {
			t.Fatalf("digest = %s, want SHA-256 of body", res.Digest)
		}
	})
	if count != 120 {
		t.Fatalf("checked %d orderings, want 120", count)
	}
}

// TestRenderDoesNotModifyInput confirms the caller's slice keeps its order.
func TestRenderDoesNotModifyInput(t *testing.T) {
	in := renderInput()
	orig := append([]netip.Prefix(nil), in...)
	if _, err := Render(in, testRefusals()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := range in {
		if in[i] != orig[i] {
			t.Fatalf("input[%d] changed from %v to %v", i, orig[i], in[i])
		}
	}
}

// TestRenderFormatsEntries pins single-address and network text forms.
func TestRenderFormatsEntries(t *testing.T) {
	res, err := Render([]netip.Prefix{pfx("81.0.1.5/32"), pfx("2606:4700::1111/128"), pfx("81.0.2.0/24")}, testRefusals())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := "81.0.1.5\n81.0.2.0/24\n2606:4700::1111\n"
	if string(res.Body) != want {
		t.Fatalf("body = %q, want %q", res.Body, want)
	}
}

// TestRenderMasksNetworks confirms host bits are dropped from networks.
func TestRenderMasksNetworks(t *testing.T) {
	res, err := Render([]netip.Prefix{pfx("81.0.1.9/24")}, testRefusals())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(res.Body) != "81.0.1.0/24\n" {
		t.Fatalf("body = %q, want masked network", res.Body)
	}
}

// TestRenderDeduplicates confirms equal entries after masking appear once.
func TestRenderDeduplicates(t *testing.T) {
	res, err := Render([]netip.Prefix{pfx("81.0.1.0/24"), pfx("81.0.1.9/24"), pfx("81.0.1.0/24")}, testRefusals())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Count != 1 || string(res.Body) != "81.0.1.0/24\n" {
		t.Fatalf("Count = %d body = %q, want one entry", res.Count, res.Body)
	}
}

// TestRenderEmptyList renders no entries as an empty body with the SHA-256 of
// the empty string.
func TestRenderEmptyList(t *testing.T) {
	res, err := Render(nil, testRefusals())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(res.Body) != 0 || res.Count != 0 {
		t.Fatalf("body %q count %d, want empty", res.Body, res.Count)
	}
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if res.Digest != emptyDigest {
		t.Fatalf("digest = %s, want %s", res.Digest, emptyDigest)
	}
}

// TestRenderOutputIsPrintableASCIILines requires only 0x0A and printable ASCII
// and a single trailing newline per line.
func TestRenderOutputIsPrintableASCIILines(t *testing.T) {
	res, err := Render(renderInput(), testRefusals())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	checkPrintableLines(t, res.Body)
}

// checkPrintableLines fails if body has bytes other than LF and printable ASCII,
// or if it does not end with LF when non-empty.
func checkPrintableLines(t *testing.T, body []byte) {
	t.Helper()
	for i, c := range body {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			t.Fatalf("byte %d = 0x%02x is not printable ASCII or LF", i, c)
		}
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		t.Fatalf("body does not end with LF: %q", body)
	}
	if bytes.Contains(body, []byte("\n\n")) {
		t.Fatalf("empty line in body: %q", body)
	}
}

// distinctEntries returns n distinct public host addresses starting at 80.0.0.0.
func distinctEntries(n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		v := uint32(0x50000000) + uint32(i)
		a := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		out = append(out, netip.PrefixFrom(a, 32))
	}
	return out
}

// TestRenderLimit accepts exactly MaxEntries entries and refuses one more,
// with no output in the refused case.
func TestRenderLimit(t *testing.T) {
	res, err := Render(distinctEntries(MaxEntries), testRefusals())
	if err != nil {
		t.Fatalf("Render at limit: %v", err)
	}
	if res.Count != MaxEntries {
		t.Fatalf("Count = %d, want %d", res.Count, MaxEntries)
	}

	over, err := Render(distinctEntries(MaxEntries+1), testRefusals())
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("Render over limit err = %v, want ErrTooManyEntries", err)
	}
	if over.Body != nil || over.Count != 0 || over.Digest != "" {
		t.Fatalf("over-limit render produced output: %+v", over)
	}
}

// TestRenderRefusedEntryProducesNoPartialOutput requires a refusal anywhere
// in the list to fail the whole publish.
func TestRenderRefusedEntryProducesNoPartialOutput(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  error
	}{
		{"special", "10.0.0.1", ErrSpecialRange},
		{"IPAM", "81.10.0.7", ErrIPAMNetwork},
		{"NOS path", "81.20.0.5", ErrNOSPath},
		{"firewall", "81.30.0.0/24", ErrFirewallAddress},
		{"protected", "81.40.1.0/24", ErrProtectedTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := append(renderInput(), pfx(tt.entry))
			res, err := Render(in, testRefusals())
			if !errors.Is(err, tt.want) {
				t.Fatalf("Render err = %v, want %v", err, tt.want)
			}
			if res.Body != nil || res.Count != 0 || res.Digest != "" {
				t.Fatalf("refused render produced output: %+v", res)
			}
		})
	}
}

// TestRenderRefusalErrorNamesEntry checks the error says which entry failed
// and why, without any output.
func TestRenderRefusalErrorNamesEntry(t *testing.T) {
	_, err := Render([]netip.Prefix{pfx("10.9.9.9")}, testRefusals())
	if err == nil || !strings.Contains(err.Error(), "10.9.9.9") {
		t.Fatalf("err = %v, want message naming the entry", err)
	}
}

// FuzzRenderRoundTrip feeds arbitrary line-based input through Render. Every
// output line must read back as an address or prefix, pass Check, and be in
// canonical form; the body must be printable ASCII with LF line ends.
func FuzzRenderRoundTrip(f *testing.F) {
	f.Add("81.0.1.5\n81.0.2.0/24\n2606:4700::1111\n")
	f.Add("")
	f.Add("10.0.0.1\n")
	f.Add("81.0.1.9/24\n81.0.1.0/24")
	f.Add("2606:4700::1111/64\n80.0.0.0/1\n")
	f.Add("fe80::1%eth0\n::ffff:81.0.1.5\n")
	f.Fuzz(func(t *testing.T, in string) {
		r := testRefusals()
		var entries []netip.Prefix
		for _, line := range strings.Split(in, "\n") {
			if p, ok := parseLine(line); ok {
				entries = append(entries, p)
			}
		}
		res, err := Render(entries, r)
		if err != nil {
			return
		}
		checkPrintableLines(t, res.Body)
		if res.Count == 0 {
			if len(res.Body) != 0 {
				t.Fatalf("Count 0 with body %q", res.Body)
			}
			return
		}
		lines := strings.Split(strings.TrimSuffix(string(res.Body), "\n"), "\n")
		if len(lines) != res.Count {
			t.Fatalf("%d lines, Count %d", len(lines), res.Count)
		}
		for _, line := range lines {
			p, ok := parseLine(line)
			if !ok {
				t.Fatalf("line %q does not read back as address or prefix", line)
			}
			if err := Check(p, r); err != nil {
				t.Fatalf("rendered line %q fails Check: %v", line, err)
			}
			if formatEntry(p) != line {
				t.Fatalf("line %q is not canonical (want %q)", line, formatEntry(p))
			}
		}
	})
}

// parseLine reads one rendered line as an address or a prefix. Zones are
// rejected by netip, so they fail here too.
func parseLine(line string) (netip.Prefix, bool) {
	if strings.Contains(line, "/") {
		p, err := netip.ParsePrefix(line)
		return p, err == nil
	}
	a, err := netip.ParseAddr(line)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}
