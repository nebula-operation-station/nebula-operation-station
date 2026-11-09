// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"fmt"
	"strings"
)

// apkSuffixes lists the apk-tools suffixes in ascending order. Those before
// apkFirstPostRank sort before the plain release, the rest after it.
var apkSuffixes = []string{"alpha", "beta", "pre", "rc", "cvs", "svn", "git", "hg", "p"}

// apkFirstPostRank is the index of the first post-release suffix ("cvs") in
// apkSuffixes; a plain release sorts between "rc" and "cvs".
const apkFirstPostRank = 4

// apkSuffix is one "_name[number]" suffix.
type apkSuffix struct {
	rank int    // index into apkSuffixes
	num  string // digits, possibly empty (= 0)
}

// APKVersion is a parsed Alpine package version:
//
//	number{.number}[letter]{_suffix[number]}[-r<number>]
//
// The commit-hash form "~<hash>" of apk-tools is not accepted; such a
// version is reported as invalid (unknown) rather than ordered by guess.
type APKVersion struct {
	numbers  []string
	letter   byte
	suffixes []apkSuffix
	revision string // digits; empty when absent (= 0)
	raw      string
}

// String returns the version as parsed.
func (v APKVersion) String() string { return v.raw }

// ParseAPK parses an Alpine package version strictly: at most
// MaxVersionLen bytes, lowercase ASCII, the grammar shown on APKVersion,
// suffix names from the apk-tools list.
func ParseAPK(s string) (APKVersion, error) {
	v := APKVersion{raw: s}
	if s == "" {
		return v, fmt.Errorf("apk version: empty: %w", ErrInvalidVersion)
	}
	if len(s) > MaxVersionLen {
		return v, fmt.Errorf("apk version: %d bytes exceeds %d: %w", len(s), MaxVersionLen, ErrInvalidVersion)
	}
	bad := func(why string) (APKVersion, error) {
		return v, fmt.Errorf("apk version %s: %s: %w", quote(s), why, ErrInvalidVersion)
	}
	i := 0
	digits := func() string {
		st := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		return s[st:i]
	}
	// Numeric components.
	for {
		n := digits()
		if n == "" {
			return bad("expected a number")
		}
		v.numbers = append(v.numbers, n)
		if i < len(s) && s[i] == '.' {
			i++
			continue
		}
		break
	}
	// Optional single letter.
	if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		v.letter = s[i]
		i++
	}
	// Suffixes.
	for i < len(s) && s[i] == '_' {
		i++
		st := i
		for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
			i++
		}
		name := s[st:i]
		rank := -1
		for r, known := range apkSuffixes {
			if name == known {
				rank = r
				break
			}
		}
		if rank < 0 {
			return bad("unknown suffix")
		}
		v.suffixes = append(v.suffixes, apkSuffix{rank: rank, num: digits()})
	}
	// Optional revision.
	if strings.HasPrefix(s[i:], "-r") {
		i += 2
		v.revision = digits()
		if v.revision == "" {
			return bad("revision is not a number")
		}
	}
	if i != len(s) {
		return bad("unexpected character")
	}
	return v, nil
}

// CompareAPK compares two Alpine versions with apk-tools' ordering and
// returns -1, 0 or +1. An unparseable version is an error wrapping
// ErrInvalidVersion.
func CompareAPK(a, b string) (int, error) {
	va, err := ParseAPK(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseAPK(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// Compare compares v with w and returns -1, 0 or +1. The rules are those of
// apk-tools, which follow the Gentoo version comparison (PMS §3.3):
//
//  1. the first number numerically;
//  2. further numbers pairwise: if either starts with '0', as strings with
//     trailing zeros removed, otherwise numerically; more numbers win;
//  3. the letter (none < a < … < z);
//  4. suffixes pairwise by rank, then number; if one side has an extra
//     suffix, it wins when that suffix is a post-release suffix (cvs, svn,
//     git, hg, p) and loses otherwise;
//  5. the -r revision numerically (absent = 0).
func (v APKVersion) Compare(w APKVersion) int {
	if c := compareDigits(v.numbers[0], w.numbers[0]); c != 0 {
		return c
	}
	n := min(len(v.numbers), len(w.numbers))
	for k := 1; k < n; k++ {
		a, b := v.numbers[k], w.numbers[k]
		var c int
		if a[0] == '0' || b[0] == '0' {
			c = sign(strings.Compare(strings.TrimRight(a, "0"), strings.TrimRight(b, "0")))
		} else {
			c = compareDigits(a, b)
		}
		if c != 0 {
			return c
		}
	}
	if len(v.numbers) != len(w.numbers) {
		return sign(len(v.numbers) - len(w.numbers))
	}
	if v.letter != w.letter {
		return sign(int(v.letter) - int(w.letter))
	}
	n = min(len(v.suffixes), len(w.suffixes))
	for k := 0; k < n; k++ {
		a, b := v.suffixes[k], w.suffixes[k]
		if a.rank != b.rank {
			return sign(a.rank - b.rank)
		}
		if c := compareDigits(orZero(a.num), orZero(b.num)); c != 0 {
			return c
		}
	}
	switch {
	case len(v.suffixes) > n:
		if v.suffixes[n].rank >= apkFirstPostRank {
			return 1
		}
		return -1
	case len(w.suffixes) > n:
		if w.suffixes[n].rank >= apkFirstPostRank {
			return -1
		}
		return 1
	}
	return compareDigits(orZero(v.revision), orZero(w.revision))
}

func orZero(d string) string {
	if d == "" {
		return "0"
	}
	return d
}
