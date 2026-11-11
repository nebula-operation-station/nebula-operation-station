// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// Match space of a security rule for the shadow check: a box over five
// dimensions (from zone, to zone, source address, destination address,
// service). Every dimension is a finite set; a box is the product. A union
// of boxes is kept as a list, and B ⊆ C1 ∪ … ∪ Cn is decided exactly by
// subtracting every Ci from B piece by piece.

// Work limits of the shadow check (ADR 0012 D2 "Limits"). A rule whose
// coverage would need more gives StateCannotDecide "limit reached".
const (
	// MaxPiecesPerRule bounds the uncovered pieces of one rule's match
	// space held at any time.
	MaxPiecesPerRule = 1 << 12
	// MaxShadowWorkPerRule bounds the set operations (in interval and zone
	// comparisons) spent on one rule.
	MaxShadowWorkPerRule = 1 << 22
	// MaxShadowWorkPerSnapshot bounds the set operations of one shadow
	// check run over all rules.
	MaxShadowWorkPerSnapshot = 1 << 27
)

// point is an ordered value with successor and predecessor.
type point[T any] interface {
	Compare(T) int
	Next() T
	Prev() T
}

// port is a destination port; 0 stands for "no port" (protocols other
// than tcp, udp and sctp).
type port uint32

func (p port) Compare(q port) int { return cmp.Compare(p, q) }
func (p port) Next() port         { return p + 1 }
func (p port) Prev() port         { return p - 1 }

type ival[T point[T]] struct{ lo, hi T }

// iset is a sorted list of disjoint, non-adjacent inclusive intervals.
type iset[T point[T]] []ival[T]

// normalize sorts and merges overlapping and adjacent intervals.
func normalize[T point[T]](l []ival[T]) iset[T] {
	if len(l) == 0 {
		return nil
	}
	s := slices.Clone(l)
	slices.SortFunc(s, func(a, b ival[T]) int { return a.lo.Compare(b.lo) })
	out := iset[T]{s[0]}
	for _, v := range s[1:] {
		last := &out[len(out)-1]
		if v.lo.Compare(last.hi) <= 0 || last.hi.Next().Compare(v.lo) == 0 {
			if v.hi.Compare(last.hi) > 0 {
				last.hi = v.hi
			}
			continue
		}
		out = append(out, v)
	}
	return out
}

func intersect[T point[T]](a, b iset[T], w *work) iset[T] {
	var out iset[T]
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		w.add(1)
		lo, hi := a[i].lo, a[i].hi
		if b[j].lo.Compare(lo) > 0 {
			lo = b[j].lo
		}
		if b[j].hi.Compare(hi) < 0 {
			hi = b[j].hi
		}
		if lo.Compare(hi) <= 0 {
			out = append(out, ival[T]{lo, hi})
		}
		if a[i].hi.Compare(b[j].hi) < 0 {
			i++
		} else {
			j++
		}
	}
	return out
}

// subtract returns a \ b. Next and Prev are only taken strictly inside an
// interval of a, so they never leave the domain.
func subtract[T point[T]](a, b iset[T], w *work) iset[T] {
	var out iset[T]
	j := 0
	for _, x := range a {
		cur, done := x.lo, false
		for j < len(b) && b[j].hi.Compare(cur) < 0 {
			w.add(1)
			j++
		}
		for k := j; k < len(b) && b[k].lo.Compare(x.hi) <= 0; k++ {
			w.add(1)
			if b[k].lo.Compare(cur) > 0 {
				out = append(out, ival[T]{cur, b[k].lo.Prev()})
			}
			if b[k].hi.Compare(x.hi) >= 0 {
				done = true
				break
			}
			cur = b[k].hi.Next()
		}
		if !done {
			out = append(out, ival[T]{cur, x.hi})
		}
	}
	return out
}

// Protocols of the service dimension. protoOther is every protocol other
// than tcp, udp and sctp (only service "any" matches it).
const (
	protoTCP = iota
	protoUDP
	protoSCTP
	protoOther
	numProtos
)

func protoIndex(p string) int {
	switch p {
	case "tcp":
		return protoTCP
	case "udp":
		return protoUDP
	case "sctp":
		return protoSCTP
	}
	return protoOther
}

type svcSet [numProtos]iset[port]

func fullService() svcSet {
	var s svcSet
	for p := range numProtos {
		if p == protoOther {
			s[p] = iset[port]{{0, 0}}
		} else {
			s[p] = iset[port]{{1, 65535}}
		}
	}
	return s
}

func (s svcSet) empty() bool {
	for _, l := range s {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

func (s svcSet) intersect(o svcSet, w *work) svcSet {
	var out svcSet
	for p := range numProtos {
		out[p] = intersect(s[p], o[p], w)
	}
	return out
}

func (s svcSet) subtract(o svcSet, w *work) svcSet {
	var out svcSet
	for p := range numProtos {
		out[p] = subtract(s[p], o[p], w)
	}
	return out
}

// Address universe: every IPv4 and every IPv6 address.
var addrUniverse = iset[netip.Addr]{
	{netip.AddrFrom4([4]byte{}), netip.AddrFrom4([4]byte{255, 255, 255, 255})},
	{netip.IPv6Unspecified(), netip.AddrFrom16([16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})},
}

// box is the match space of one rule.
type box struct {
	from, to []string // sorted, distinct
	src, dst iset[netip.Addr]
	svc      svcSet
}

func (b *box) empty() bool {
	return len(b.from) == 0 || len(b.to) == 0 || len(b.src) == 0 || len(b.dst) == 0 || b.svc.empty()
}

func zoneIntersect(a, b []string, w *work) []string {
	var out []string
	w.add(len(a) + len(b))
	for _, z := range a {
		if _, ok := slices.BinarySearch(b, z); ok {
			out = append(out, z)
		}
	}
	return out
}

func zoneSubtract(a, b []string, w *work) []string {
	var out []string
	w.add(len(a) + len(b))
	for _, z := range a {
		if _, ok := slices.BinarySearch(b, z); !ok {
			out = append(out, z)
		}
	}
	return out
}

func (b *box) intersect(c *box, w *work) box {
	return box{
		from: zoneIntersect(b.from, c.from, w),
		to:   zoneIntersect(b.to, c.to, w),
		src:  intersect(b.src, c.src, w),
		dst:  intersect(b.dst, c.dst, w),
		svc:  b.svc.intersect(c.svc, w),
	}
}

// minus returns b \ c as disjoint boxes: for each dimension k, the part of
// b that agrees with c on the dimensions before k and lies outside c on k.
func (b *box) minus(c *box, w *work) []box {
	in := b.intersect(c, w)
	if in.empty() {
		return []box{*b}
	}
	var out []box
	cur := *b
	if z := zoneSubtract(cur.from, c.from, w); len(z) > 0 {
		p := cur
		p.from = z
		out = append(out, p)
	}
	cur.from = in.from
	if z := zoneSubtract(cur.to, c.to, w); len(z) > 0 {
		p := cur
		p.to = z
		out = append(out, p)
	}
	cur.to = in.to
	if s := subtract(cur.src, c.src, w); len(s) > 0 {
		p := cur
		p.src = s
		out = append(out, p)
	}
	cur.src = in.src
	if s := subtract(cur.dst, c.dst, w); len(s) > 0 {
		p := cur
		p.dst = s
		out = append(out, p)
	}
	cur.dst = in.dst
	if s := cur.svc.subtract(c.svc, w); !s.empty() {
		p := cur
		p.svc = s
		out = append(out, p)
	}
	return out
}

// work counts set operations against a per-rule and a shared budget.
type work struct {
	n, max int
	shared *int // remaining shared budget
}

func (w *work) add(n int) {
	w.n += n
	if w.shared != nil {
		*w.shared -= n
	}
}

func (w *work) exhausted() bool {
	return w.n > w.max || (w.shared != nil && *w.shared < 0)
}

// coverage is the result of covers.
type coverage int

const (
	notCovered coverage = iota
	fullyCovered
	coverLimit
)

// covers decides whether target ⊆ ∪ cs.
func covers(target box, cs []box, w *work) coverage {
	if target.empty() {
		return fullyCovered
	}
	rem := []box{target}
	for i := range cs {
		var next []box
		for j := range rem {
			next = append(next, rem[j].minus(&cs[i], w)...)
			if len(next) > MaxPiecesPerRule || w.exhausted() {
				return coverLimit
			}
		}
		rem = next
		if len(rem) == 0 {
			return fullyCovered
		}
	}
	return notCovered
}

// addrSet converts an expanded address field, applying negation.
func addrSet(s netreach.AddrSet, negate bool, w *work) iset[netip.Addr] {
	var set iset[netip.Addr]
	if s.Any {
		set = slices.Clone(addrUniverse)
	} else {
		l := make([]ival[netip.Addr], 0, len(s.Ranges))
		for _, r := range s.Ranges {
			l = append(l, ival[netip.Addr]{r.From, r.To})
		}
		w.add(len(l))
		set = normalize(l)
	}
	if negate {
		return subtract(addrUniverse, set, w)
	}
	return set
}

// serviceSet converts an expanded service field. Application-default is
// not handled here (see shadow.go).
func serviceSet(s netreach.ServiceSet, w *work) svcSet {
	if s.Any {
		return fullService()
	}
	var raw [numProtos][]ival[port]
	for _, p := range s.Ports {
		i := protoIndex(p.Protocol)
		raw[i] = append(raw[i], ival[port]{port(p.From), port(p.To)})
	}
	var out svcSet
	for i := range numProtos {
		w.add(len(raw[i]))
		out[i] = normalize(raw[i])
	}
	return out
}
