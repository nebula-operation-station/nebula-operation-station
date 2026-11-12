// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

// TestIntervalSetOpsMatchBruteForce compares normalize, intersect and
// subtract on small port sets with a bitmap.
func TestIntervalSetOpsMatchBruteForce(t *testing.T) {
	const n = 40
	rng := rand.New(rand.NewPCG(1, 2))
	gen := func() ([]ival[port], [n + 2]bool) {
		var bits [n + 2]bool
		var l []ival[port]
		for range rng.IntN(5) {
			a := port(1 + rng.IntN(n))
			b := a + port(rng.IntN(6))
			if b > n {
				b = n
			}
			l = append(l, ival[port]{a, b})
			for p := a; p <= b; p++ {
				bits[p] = true
			}
		}
		return l, bits
	}
	toBits := func(s iset[port]) [n + 2]bool {
		var bits [n + 2]bool
		for i, v := range s {
			if v.lo > v.hi || (i > 0 && s[i-1].hi+1 >= v.lo) {
				t.Fatalf("not normalized: %v", s)
			}
			for p := v.lo; p <= v.hi; p++ {
				bits[p] = true
			}
		}
		return bits
	}
	for range 2000 {
		la, ba := gen()
		lb, bb := gen()
		a, b := normalize(la), normalize(lb)
		if toBits(a) != ba || toBits(b) != bb {
			t.Fatalf("normalize(%v) = %v", la, a)
		}
		w := &work{max: 1 << 20}
		var wi, ws [n + 2]bool
		for p := range ba {
			wi[p] = ba[p] && bb[p]
			ws[p] = ba[p] && !bb[p]
		}
		if got := toBits(intersect(a, b, w)); got != wi {
			t.Fatalf("intersect(%v, %v) wrong", a, b)
		}
		if got := toBits(subtract(a, b, w)); got != ws {
			t.Fatalf("subtract(%v, %v) wrong: %v", a, b, subtract(a, b, w))
		}
	}
}

func TestAddressSetFamilyBoundaries(t *testing.T) {
	a := netip.MustParseAddr
	w := &work{max: 1 << 20}
	v4max := ival[netip.Addr]{a("255.255.255.255"), a("255.255.255.255")}
	v6min := ival[netip.Addr]{a("::"), a("::")}
	// The last IPv4 and the first IPv6 address are not adjacent.
	if got := normalize([]ival[netip.Addr]{v6min, v4max}); len(got) != 2 {
		t.Errorf("normalize across families = %v, want two intervals", got)
	}
	// Complement of all IPv4 is all IPv6.
	all4 := iset[netip.Addr]{addrUniverse[0]}
	if got := subtract(addrUniverse, all4, w); !slices.Equal(got, addrUniverse[1:]) {
		t.Errorf("universe minus IPv4 = %v", got)
	}
	// A hole in the middle.
	hole := iset[netip.Addr]{{a("10.0.0.0"), a("10.255.255.255")}}
	got := subtract(all4, hole, w)
	want := iset[netip.Addr]{{a("0.0.0.0"), a("9.255.255.255")}, {a("11.0.0.0"), a("255.255.255.255")}}
	if !slices.Equal(got, want) {
		t.Errorf("IPv4 minus 10/8 = %v, want %v", got, want)
	}
}

func TestBoxMinusCoversExactly(t *testing.T) {
	a := netip.MustParseAddr
	w := &work{max: 1 << 20}
	target := box{
		from: s("lan"), to: s("dmz", "wan"),
		src: iset[netip.Addr]{{a("10.0.0.0"), a("10.0.255.255")}},
		dst: addrUniverse, svc: fullService(),
	}
	half := target
	half.to = s("dmz")
	rest := target
	rest.to = s("wan")
	if got := covers(target, []box{half}, w); got != notCovered {
		t.Errorf("half: %v, want notCovered", got)
	}
	if got := covers(target, []box{half, rest}, w); got != fullyCovered {
		t.Errorf("both halves: %v, want fullyCovered", got)
	}
	// Covering everything except one tcp port leaves the target uncovered.
	almost := target
	almost.svc = fullService()
	almost.svc[protoTCP] = iset[port]{{1, 442}, {444, 65535}}
	if got := covers(target, []box{almost}, w); got != notCovered {
		t.Errorf("all but tcp/443: %v, want notCovered", got)
	}
	only443 := target
	only443.svc = svcSet{protoTCP: iset[port]{{443, 443}}}
	if got := covers(target, []box{almost, only443}, w); got != fullyCovered {
		t.Errorf("all but 443 plus 443: %v, want fullyCovered", got)
	}
}
