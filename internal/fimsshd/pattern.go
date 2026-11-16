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

// matchName reports whether one path component matches a single-component seg.
func (s seg) matchName(name string) bool {
	switch s.kind {
	case segGlob:
		ok, err := path.Match(s.glob, name)
		return err == nil && ok
	case segPieces:
		return matchPieces(s.pieces, name)
	default:
		return false
	}
}

// matchPieces reports whether name is matched by the piece sequence. It is a
// position-set DP: each piece costs O(len(name)) for a user run (the smallest
// live position reaches every later one) and O(len(name) × len(lit)) for a
// literal, so with at most maxPiecesPerComponent pieces the work is bounded
// and no input causes exponential work.
func matchPieces(ps []piece, name string) bool {
	cur := make([]bool, len(name)+1)
	cur[0] = true
	for _, p := range ps {
		next := make([]bool, len(name)+1)
		if p.user {
			first := -1
			for j, ok := range cur {
				if ok {
					first = j
					break
				}
			}
			if first >= 0 {
				for k := first + p.min; k <= len(name); k++ {
					next[k] = true
				}
			}
		} else {
			for j, ok := range cur {
				if ok && strings.HasPrefix(name[j:], p.lit) {
					next[j+len(p.lit)] = true
				}
			}
		}
		cur = next
	}
	return cur[len(name)]
}

// run feeds the components of an absolute path through the entry. It reports
// whether they form a complete match, and whether they are a proper prefix of
// one (a directory on or above a hit).
func (e entry) run(comps []string) (full, extendable bool) {
	m := len(e.segs)
	boundary := make([]bool, m+1) // segs[:i] matched exactly the components so far
	many := make([]bool, m)       // segs[i] (segMany) matched one or more, may continue
	boundary[0] = true
	for _, c := range comps {
		nb := make([]bool, m+1)
		nm := make([]bool, m)
		active := false
		for i, sg := range e.segs {
			if boundary[i] {
				if sg.kind == segMany {
					nm[i] = true
				} else if sg.matchName(c) {
					nb[i+1] = true
				}
			}
			if many[i] {
				nm[i] = true
			}
		}
		for i := 0; i < m; i++ {
			if nm[i] {
				nb[i+1] = true // the many segment may end after c
			}
			if nb[i] || nm[i] {
				active = true
			}
		}
		if nb[m] {
			active = true
		}
		if !active {
			return false, false
		}
		boundary, many = nb, nm
	}
	full = boundary[m]
	for i := 0; i < m; i++ {
		if boundary[i] || many[i] {
			extendable = true
		}
	}
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
