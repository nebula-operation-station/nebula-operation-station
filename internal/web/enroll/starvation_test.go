// SPDX-License-Identifier: AGPL-3.0-or-later

package enroll

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
)

const garbage = "not-an-ip"

var forwardedSentinels = []error{
	clientaddr.ErrForwardedMissing,
	clientaddr.ErrForwardedTooLong,
	clientaddr.ErrForwardedTooManyEntries,
	clientaddr.ErrForwardedMalformed,
	clientaddr.ErrForwardedOnlyTrusted,
}

// padder hands out distinct well-formed padding entries from
// 198.51.100.0/24 and 2001:db8:1::/48 (bare, with port, bracketed IPv6
// with port; never a zone), none equal to A, C, P or T2.
type padder struct{ n int }

// short returns an IPv4 entry, bare or with a port.
func (p *padder) short() string {
	p.n++ // each variant uses its own padder and far fewer than 254 entries
	if p.n%2 == 0 {
		return fmt.Sprintf("198.51.100.%d", p.n)
	}
	return fmt.Sprintf("198.51.100.%d:%d", p.n, 1000+p.n)
}

// long returns a bracketed IPv6 entry with port (the longest form, at
// most 43 bytes).
func (p *padder) long() string {
	p.n++
	return fmt.Sprintf("[2001:db8:1:ffff:ffff:ffff:ffff:%x]:65535", p.n)
}

// bare6 returns a bare IPv6 entry.
func (p *padder) bare6() string {
	p.n++
	return fmt.Sprintf("2001:db8:1::%x", p.n)
}

func (p *padder) mixed(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			out = append(out, p.short())
		case 1:
			out = append(out, p.bare6())
		default:
			out = append(out, p.long())
		}
	}
	return out
}

func join(e []string) string { return strings.Join(e, ", ") }

// variant is one refused-header class of the starvation test.
type variant struct {
	name       string
	lines      []string // X-Forwarded-For lines as the server sees them
	want       error
	maxEntries int    // 0: production limit
	resolvesTo string // after trimming to the limits; "" for 1 and 8
}

func starvationVariants(t *testing.T) []variant {
	t.Helper()
	var v []variant
	v = append(v, variant{name: "1 missing", want: clientaddr.ErrForwardedMissing})

	{ // 2: one line over 1 KiB, A rightmost.
		p := &padder{}
		var e []string
		for len(join(append(e, addrA))) <= clientaddr.DefaultMaxHeaderBytes {
			e = append(e, p.long())
		}
		v = append(v, variant{name: "2 one line too long", lines: []string{join(append(e, addrA))},
			want: clientaddr.ErrForwardedTooLong, maxEntries: 256, resolvesTo: addrA})
	}
	{ // 3: one line, 16 padding and A (17 entries, under 1 KiB).
		p := &padder{}
		line := join(append(p.mixed(16), addrA))
		v = append(v, variant{name: "3 one line too many", lines: []string{line},
			want: clientaddr.ErrForwardedTooManyEntries, resolvesTo: addrA})
	}
	{ // 4: several lines within the limits each, together over 1 KiB.
		p := &padder{}
		var l1, l2 []string
		for i := 0; i < 13; i++ {
			l1 = append(l1, p.long())
		}
		for i := 0; i < 12; i++ {
			l2 = append(l2, p.long())
		}
		l2 = append(l2, addrA)
		v = append(v, variant{name: "4 lines too long", lines: []string{join(l1), join(l2)},
			want: clientaddr.ErrForwardedTooLong, maxEntries: 256, resolvesTo: addrA})
	}
	{ // 5: several lines within 16 entries each, together 17, under 1 KiB.
		p := &padder{}
		l1 := p.mixed(8)
		l2 := append(p.mixed(8), addrA)
		v = append(v, variant{name: "5 lines too many", lines: []string{join(l1), join(l2)},
			want: clientaddr.ErrForwardedTooManyEntries, resolvesTo: addrA})
	}
	v = append(v,
		variant{name: "6 garbage right", lines: []string{addrA + ", " + garbage},
			want: clientaddr.ErrForwardedMalformed, resolvesTo: addrA},
		variant{name: "7 garbage left", lines: []string{garbage + ", " + addrA},
			want: clientaddr.ErrForwardedMalformed, resolvesTo: addrA},
		variant{name: "8 only trusted", lines: []string{addrT2 + ", " + addrP},
			want: clientaddr.ErrForwardedOnlyTrusted},
	)
	{ // 9: the client sends 15 padding and A, the proxy appends C.
		p := &padder{}
		client := join(append(p.mixed(15), addrA))
		v = append(v, variant{name: "9 appended entry count", lines: []string{client + ", " + addrC},
			want: clientaddr.ErrForwardedTooManyEntries, resolvesTo: addrC})
	}
	{ // 10: the client sends at most 1 KiB, only ", C" takes it over.
		p := &padder{}
		var e []string
		for {
			next := p.long()
			if len(join(append(append(e, next), addrA))) > clientaddr.DefaultMaxHeaderBytes {
				next = p.short()
				if len(join(append(append(e, next), addrA))) > clientaddr.DefaultMaxHeaderBytes {
					break
				}
			}
			e = append(e, next)
		}
		client := join(append(e, addrA))
		if len(client) > clientaddr.DefaultMaxHeaderBytes || len(client+", "+addrC) <= clientaddr.DefaultMaxHeaderBytes {
			t.Fatalf("variant 10 fixture: client part %d bytes", len(client))
		}
		v = append(v, variant{name: "10 appended size", lines: []string{client + ", " + addrC},
			want: clientaddr.ErrForwardedTooLong, maxEntries: 256, resolvesTo: addrC})
	}
	return v
}

func (v variant) config() clientaddr.Config {
	return clientaddr.Config{TrustedProxies: []string{addrP, addrT2}, MaxEntries: v.maxEntries}
}

func entries(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	parts := strings.Split(join(lines), ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func xffRequest(lines []string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, PathPrefix+"x", nil)
	r.RemoteAddr = addrP + ":40000"
	for _, l := range lines {
		r.Header.Add("X-Forwarded-For", l)
	}
	return r
}

// proveReason is the in-package check that the variant is refused for
// exactly its class and would otherwise name A (or C).
func proveReason(t *testing.T, v variant) {
	t.Helper()
	res, err := clientaddr.New(v.config(), nil)
	if err != nil {
		t.Fatal(err)
	}
	maxEntries := v.maxEntries
	if maxEntries == 0 {
		maxEntries = clientaddr.DefaultMaxEntries
	}
	if v.maxEntries != 0 && len(entries(v.lines)) >= v.maxEntries {
		t.Fatalf("%d entries, not below the injected limit %d", len(entries(v.lines)), v.maxEntries)
	}
	_, err = res.Resolve(xffRequest(v.lines))
	if !errors.Is(err, v.want) {
		t.Fatalf("Resolve err = %v, want %v", err, v.want)
	}
	for _, s := range forwardedSentinels {
		if s != v.want && errors.Is(err, s) {
			t.Fatalf("err %v also matches %v", err, s)
		}
	}
	for _, e := range entries(v.lines) {
		if e == garbage {
			continue
		}
		if _, err := clientaddr.Normalize(e); err != nil {
			t.Fatalf("padding entry %q does not normalise: %v", e, err)
		}
	}
	if v.resolvesTo == "" {
		return
	}
	var kept []string
	for _, e := range entries(v.lines) {
		if e != garbage {
			kept = append(kept, e)
		}
	}
	for len(join(kept)) > clientaddr.DefaultMaxHeaderBytes || len(kept) > maxEntries {
		kept = kept[1:]
	}
	got, err := res.Resolve(xffRequest([]string{join(kept)}))
	if err != nil || got.Client.String() != v.resolvesTo {
		t.Fatalf("trimmed header resolves to %v (%v), want %s", got.Client, err, v.resolvesTo)
	}
}

// TestRefusedForwardedHeaderChargesNothing is the refused-header
// starvation test: per class, refused requests neither call the executor,
// nor consume the offer, nor create any bucket, and A, C and the peer keep
// their full allowance.
func TestRefusedForwardedHeaderChargesNothing(t *testing.T) {
	for _, v := range starvationVariants(t) {
		t.Run(v.name, func(t *testing.T) {
			ex := newStub()
			clock := newClock()
			l := NewLimiter(0, clock.now)
			proxied := newServer(t, v.config(), ex, l, nil)
			direct := newServer(t, clientaddr.Config{}, ex, l, nil)

			proveReason(t, v)

			orig := ex.offer()
			for i := 0; i < PerMinute+1; i++ {
				assertUniform404(t, proxied.get(t, PathPrefix+orig, v.lines...))
			}
			if n := ex.callCount(); n != 0 {
				t.Fatalf("executor called %d times", n)
			}
			if n := l.size(); n != 0 {
				t.Fatalf("limiter holds %d buckets after refusals", n)
			}
			if got := proxied.h.ForwardedRefusals(); got != PerMinute+1 {
				t.Fatalf("refusal metric = %d", got)
			}

			assert200(t, proxied.get(t, PathPrefix+orig, addrA))
			for i := 1; i < PerMinute; i++ {
				assert200(t, proxied.get(t, PathPrefix+ex.offer(), addrA))
			}
			assertUniform404(t, proxied.get(t, PathPrefix+ex.offer(), addrA))
			if v.resolvesTo == addrC {
				for i := 0; i < PerMinute; i++ {
					assert200(t, proxied.get(t, PathPrefix+ex.offer(), addrC))
				}
				assertUniform404(t, proxied.get(t, PathPrefix+ex.offer(), addrC))
			}

			for i := 0; i < PerMinute; i++ {
				assert200(t, direct.get(t, PathPrefix+ex.offer()))
				if c := ex.lastCall(); c.client != addrP || c.peer != addrP {
					t.Fatalf("direct call %+v", c)
				}
			}
			assertUniform404(t, direct.get(t, PathPrefix+ex.offer()))
		})
	}
}

// TestRefusalLogCarriesNoPath checks the refusal line of a trusted proxy.
func TestRefusalLogCarriesNoPath(t *testing.T) {
	ex := newStub()
	var buf syncBuffer
	s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), slog.New(slog.NewTextHandler(&buf, nil)))
	id := ex.offer()
	assertUniform404(t, s.get(t, PathPrefix+id))
	out := buf.String()
	if !strings.Contains(out, "x-forwarded-for missing") || strings.Contains(out, id) || strings.Contains(out, PathPrefix) {
		t.Fatalf("log = %q", out)
	}
}
