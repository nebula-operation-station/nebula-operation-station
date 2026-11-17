// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"path"
	"strings"
)

// errValue reports a value whose form is not fixed by ADR 0015 D7 (d).
var errValue = ErrUnclassifiable

type segKind uint8

const (
	// segMany matches one or more path components (%h, ~, ~name, relative values).
	segMany segKind = iota + 1
	// segPieces matches exactly one component made of literal text and %u/%U.
	segPieces
	// segGlob matches exactly one component with a path.Match glob (Include).
	segGlob
)

// maxPiecesPerComponent bounds the pieces of one path component. Matching
// costs O(pieces × component length), so this bounds the work per component.
// A value with more pieces is not understood (ADR 0015 D7: fail closed).
const maxPiecesPerComponent = 64

// piece is literal text, or a run of %u/%U tokens. A user run matches min or
// more characters: each %u or %U needs one character, and adjacent tokens add
// up, so "%u%u" needs at least two.
type piece struct {
	lit  string
	user bool
	min  int // user only: the minimum number of characters
}

type seg struct {
	kind   segKind
	pieces []piece
	glob   string
}

// entry is one value as a sequence of segments.
type entry struct {
	segs []seg
}

// matchBudget is the fixed work budget of one Set.Match call, counted in
// byte steps (never wall-clock time). Every glob, piece and segment step is
// charged against it. When a call would exceed it, the classification is
// indeterminate and Set.Match answers SSHFile: fail closed, as ADR 0015 D7
// requires for values it cannot classify. The budget bounds the work per
// record path regardless of the configuration and the path.
const matchBudget = 1 << 20

// scratch holds the DP buffers of matchPieces and the work counter of one
// Set.Match call. One call owns one scratch and reuses it for every component
// and value, so matching does not allocate per component. The zero value is a
// fresh budget.
type scratch struct {
	cur, next []bool
	spent     int  // byte steps charged so far, never more than matchBudget
	over      bool // the budget was exhausted; every later charge fails
}

// spend charges n steps against matchBudget. It reports false, and marks the
// scratch over, when the charge would exceed the budget. Once over, every
// charge fails, so callers stop without doing more work.
func (sc *scratch) spend(n int) bool {
	if sc.over {
		return false
	}
	if n < 0 || n > matchBudget-sc.spent {
		sc.over = true
		return false
	}
	sc.spent += n
	return true
}

// buffers returns two cleared buffers of length n, growing the scratch when
// needed.
func (sc *scratch) buffers(n int) ([]bool, []bool) {
	if cap(sc.cur) < n || cap(sc.next) < n {
		sc.cur = make([]bool, n)
		sc.next = make([]bool, n)
	}
	cur, next := sc.cur[:n], sc.next[:n]
	clear(cur)
	clear(next)
	return cur, next
}

// globMatch reports whether name matches the glob pat. path.Match may cost
// O(len(pat) × len(name)) per call, so the call is charged that bound before
// it runs; a glob that does not fit the budget is not run at all.
func globMatch(pat, name string, sc *scratch) bool {
	if !sc.spend((len(pat) + 1) * (len(name) + 1)) {
		return false
	}
	ok, err := path.Match(pat, name)
	return err == nil && ok
}

// matchName reports whether one path component matches a single-component seg.
func (s seg) matchName(name string, sc *scratch) bool {
	switch s.kind {
	case segGlob:
		return globMatch(s.glob, name, sc)
	case segPieces:
		return matchPieces(s.pieces, name, sc)
	default:
		return false
	}
}

// matchPieces reports whether name is matched by the piece sequence. It is a
// position-set DP over the live positions of name. A user run is linear: one
// pass finds the first live position, and the run fills every later one. A
// literal is not linear: it is compared at each live position, which costs up
// to len(name) × len(lit) byte compares, so no bound below the budget is
// claimed for it. Every step is charged against matchBudget, not only the
// compares: each call clears two buffers of len(name)+1 and each piece clears
// next and scans cur, so a piece costs at least 2 × (len(name)+1) steps before
// any compare, and a user run also fills up to len(name)+1 positions. A step
// that does not fit ends the match as indeterminate (the caller sees sc.over
// and answers SSHFile). The number of pieces is capped by
// maxPiecesPerComponent, so no input causes exponential work.
func matchPieces(ps []piece, name string, sc *scratch) bool {
	n := len(name) + 1
	if !sc.spend(2 * n) { // buffers: clear cur and next
		return false
	}
	cur, next := sc.buffers(n)
	cur[0] = true
	for _, p := range ps {
		if !sc.spend(2 * n) { // clear next, scan cur
			return false
		}
		clear(next)
		if p.user {
			first := -1
			for j, ok := range cur {
				if ok {
					first = j
					break
				}
			}
			if first >= 0 {
				if !sc.spend(n) { // fill the live run
					return false
				}
				for k := first + p.min; k <= len(name); k++ {
					next[k] = true
				}
			}
		} else {
			for j, ok := range cur {
				if !ok {
					continue
				}
				if !sc.spend(len(p.lit) + 1) {
					return false
				}
				if strings.HasPrefix(name[j:], p.lit) {
					next[j+len(p.lit)] = true
				}
			}
		}
		cur, next = next, cur
	}
	return cur[len(name)]
}

// run feeds the components of an absolute path through the entry. It reports
// whether they form a complete match, and whether they are a proper prefix of
// one (a directory on or above a hit). The segment states are bit sets: an
// entry has at most maxComponents segments (see userEntry, includeEntry and
// literalEntry), so bit m of a state fits in a uint64 for m ≤ 32.
func (e entry) run(comps []string, sc *scratch) (full, extendable bool) {
	m := len(e.segs)
	last := uint64(1) << m // bit m: the whole entry has matched
	boundary := uint64(1)  // bit i: segs[:i] matched exactly the components so far
	var many uint64        // bit i: segs[i] (segMany) matched one or more, may continue
	for _, c := range comps {
		if !sc.spend(len(e.segs) + 1) {
			return false, false
		}
		var nb, nm uint64
		for i, sg := range e.segs {
			bit := uint64(1) << i
			if boundary&bit != 0 {
				if sg.kind == segMany {
					nm |= bit
				} else if sg.matchName(c, sc) {
					nb |= bit << 1
				}
			}
			if many&bit != 0 {
				nm |= bit
			}
		}
		nb |= nm << 1 // a many segment may end after c
		if nb|nm == 0 {
			return false, false
		}
		boundary, many = nb, nm
	}
	full = boundary&last != 0
	extendable = boundary&(last-1) != 0 || many != 0
	return full, extendable
}

// splitComps splits s (a value without its leading slash) into components,
// at most maxComponents of them. The empty string has none. Empty, "." and
// ".." components are rejected because sshd does not normalise them.
func splitComps(s string) ([]string, error) {
	return splitLimited(s, maxComponents)
}

// splitRecordPath splits a record path (without its leading slash). Record
// paths have their own limit, so a deep but real tree is still classified;
// beyond maxPathComponents the path is refused and Set.Match fails closed.
func splitRecordPath(s string) ([]string, error) {
	return splitLimited(s, maxPathComponents)
}

func splitLimited(s string, limit int) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	comps := strings.Split(s, "/")
	if len(comps) > limit {
		return nil, errValue
	}
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, errValue
		}
	}
	return comps, nil
}

// userPieces compiles one component of a per-user value: %% is a percent
// sign, %u and %U are one name, and any other % token is not understood.
func userPieces(c string) ([]piece, error) {
	var ps []piece
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			ps = append(ps, piece{lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(c); i++ {
		if c[i] != '%' {
			lit.WriteByte(c[i])
			continue
		}
		if i+1 >= len(c) {
			return nil, errValue
		}
		switch c[i+1] {
		case 'u', 'U':
			flush()
			if n := len(ps); n > 0 && ps[n-1].user {
				ps[n-1].min++ // adjacent user tokens need one character each
			} else {
				ps = append(ps, piece{user: true, min: 1})
			}
		case '%':
			lit.WriteByte('%')
		default:
			return nil, errValue
		}
		i++
	}
	flush()
	if len(ps) > maxPiecesPerComponent {
		return nil, errValue
	}
	return ps, nil
}

// userEntry compiles one AuthorizedKeysFile or AuthorizedPrincipalsFile value
// (ADR 0015 D7 (d), "AuthorizedKeysFile expansion"). %h, ~ and ~name, and any
// relative value, start at a home directory that matches one or more
// components; %u and %U match exactly one component.
func userEntry(tok string) (entry, error) {
	var e entry
	rest := ""
	hasRest := false
	if strings.HasPrefix(tok, "/") {
		rest = tok[1:]
		hasRest = true
	} else {
		first, tail, cut := strings.Cut(tok, "/")
		if first == "%h" || strings.HasPrefix(first, "~") {
			if first != "%h" && strings.Contains(first, "%") {
				// A tilde form is a home name: no % token in it.
				return entry{}, errValue
			}
			e.segs = append(e.segs, seg{kind: segMany})
			if cut {
				if tail == "" {
					return entry{}, errValue
				}
				rest, hasRest = tail, true
			}
		} else {
			e.segs = append(e.segs, seg{kind: segMany})
			rest, hasRest = tok, true
		}
	}
	if !hasRest {
		return e, nil
	}
	comps, err := splitComps(rest)
	if err != nil {
		return entry{}, err
	}
	if len(e.segs)+len(comps) > maxComponents {
		return entry{}, errValue
	}
	for _, c := range comps {
		if c == "%h" {
			e.segs = append(e.segs, seg{kind: segMany})
			continue
		}
		ps, err := userPieces(c)
		if err != nil {
			return entry{}, err
		}
		e.segs = append(e.segs, seg{kind: segPieces, pieces: ps})
	}
	return e, nil
}

// literalEntry compiles an absolute path that names exactly one file. Every
// character is literal, including %.
func literalEntry(abs string) (entry, error) {
	comps, err := splitComps(abs[1:])
	if err != nil {
		return entry{}, err
	}
	var e entry
	for _, c := range comps {
		e.segs = append(e.segs, seg{kind: segPieces, pieces: []piece{{lit: c}}})
	}
	return e, nil
}

// daemonEntry compiles TrustedUserCAKeys and RevokedKeys (ADR 0015 D7 (d),
// "daemon-wide"): no % expansion, ~ and ~/ are /root, ~name is not understood,
// and a relative value is relative to /.
func daemonEntry(tok string) (entry, error) {
	var abs string
	switch {
	case tok == "~" || strings.HasPrefix(tok, "~/"):
		abs = "/root" + tok[1:]
	case strings.HasPrefix(tok, "~"):
		return entry{}, errValue
	case strings.HasPrefix(tok, "/"):
		abs = tok
	default:
		abs = "/" + tok
	}
	return literalEntry(abs)
}

// includeEntry compiles one Include value. Relative values are resolved
// against /etc/ssh; glob characters match one component each. Values with %
// or a leading ~ are not understood (ADR 0015 D7: fail closed).
//
// Only the wildcards * and ? are accepted. A bracket expression is not
// understood: path.Match negates with "^" while glob(3) negates with "!",
// and the classes differ in other ways too, so no bracket class is compiled
// (fail closed, ErrUnclassifiable). Backslash and quotes are already
// rejected by validToken, so no escape semantics can differ either.
func includeEntry(tok string) (entry, error) {
	if strings.Contains(tok, "%") || strings.HasPrefix(tok, "~") || strings.ContainsRune(tok, '[') {
		return entry{}, errValue
	}
	abs := tok
	if !strings.HasPrefix(tok, "/") {
		abs = sshdConfigDir + tok
	}
	comps, err := splitComps(abs[1:])
	if err != nil {
		return entry{}, err
	}
	var e entry
	for _, c := range comps {
		if strings.ContainsAny(c, "*?") {
			e.segs = append(e.segs, seg{kind: segGlob, glob: c})
			continue
		}
		e.segs = append(e.segs, seg{kind: segPieces, pieces: []piece{{lit: c}}})
	}
	return e, nil
}
