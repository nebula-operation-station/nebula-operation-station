// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"errors"
	"strings"
	"testing"
)

// nullPolicyDigest pins PolicyDigest(Policy{}), the zero policy whose version
// is DefaultPolicyVersion ("stable-v1"). A change here means the canonical
// encoding changed, which every stored policy_digest would notice.
const nullPolicyDigest = "f7147507593d4ddf5e9e3eeea1960a04f2ef2697a32fd10e8dce7befab91bd58"

func TestCompareTags(t *testing.T) {
	const digestTag = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const bareHex = "0123456789abcdef"
	tests := []struct {
		name      string
		old, new  string
		wantMajor bool
		wantErr   error // nil means comparable
	}{
		{name: "major jump", old: "1.2.3", new: "2.0.0", wantMajor: true},
		{name: "major downgrade", old: "2.0.0", new: "1.9.0", wantMajor: true},
		{name: "minor jump", old: "1.2.3", new: "1.3.0"},
		{name: "patch jump", old: "1.2.3", new: "1.2.4"},
		{name: "same tag", old: "1.2.3", new: "1.2.3"},
		{name: "same tag with variant", old: "1.2.3-alpine", new: "1.2.3-alpine"},
		{name: "downgrade within major", old: "1.3.0", new: "1.2.9"},
		{name: "variant kept across minor", old: "1.2.3-alpine", new: "1.3.0-alpine"},
		{name: "variant kept across major", old: "1.2.3-alpine", new: "2.0.0-alpine", wantMajor: true},
		{name: "v prefix is not a change", old: "v1.2.3", new: "1.2.3"},
		{name: "build metadata is not a change", old: "1.2.3+build7", new: "1.2.3"},
		{name: "short and full form are equal", old: "1.2", new: "1.2.0"},
		{name: "prerelease to release", old: "1.2.3-rc1", new: "1.2.3"},
		{name: "prerelease keeps variant", old: "1.2.3-rc1-alpine", new: "1.2.4-alpine"},
		{name: "prerelease major change", old: "1.2.3-rc1", new: "2.0.0-rc1", wantMajor: true},
		{name: "variant change alpine to slim", old: "1.2.3-alpine", new: "1.2.3-slim", wantErr: ErrVariantChange},
		{name: "variant change added", old: "1.2.3", new: "1.2.4-alpine", wantErr: ErrVariantChange},
		{name: "variant change removed", old: "1.2.3-alpine", new: "1.2.4", wantErr: ErrVariantChange},
		{name: "variant change with major", old: "1.2.3-alpine", new: "2.0.0-slim", wantErr: ErrVariantChange},
		{name: "digest old", old: digestTag, new: "1.2.3", wantErr: ErrNotComparable},
		{name: "digest new", old: "1.2.3", new: digestTag, wantErr: ErrNotComparable},
		{name: "bare hex old", old: bareHex, new: "1.2.3", wantErr: ErrNotComparable},
		{name: "latest old", old: "latest", new: "1.2.3", wantErr: ErrNotComparable},
		{name: "latest new", old: "1.2.3", new: "latest", wantErr: ErrNotComparable},
		{name: "non-version edge", old: "1.2.3", new: "edge", wantErr: ErrNotComparable},
		{name: "non-version main", old: "main", new: "main", wantErr: ErrNotComparable},
		{name: "empty tag", old: "", new: "1.2.3", wantErr: ErrNotComparable},
		{name: "date against version", old: "2024-01-15", new: "1.2.3", wantErr: ErrNotComparable},
		{name: "compact date against version", old: "1.2.3", new: "20240115", wantErr: ErrNotComparable},
		{name: "date against date", old: "2024-01-15", new: "2024-02-20", wantErr: ErrNotComparable},
		{name: "malformed version", old: "1.2.3-", new: "1.2.3", wantErr: ErrNotComparable},
		{name: "too long", old: strings.Repeat("1", maxTagLen+1), new: "1.2.3", wantErr: ErrNotComparable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareTags(tt.old, tt.new, Policy{})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("CompareTags(%q, %q) error = %v, want %v", tt.old, tt.new, err, tt.wantErr)
				}
				for _, tag := range []string{tt.old, tt.new} {
					if tag != "" && strings.Contains(err.Error(), tag) {
						t.Errorf("error %q names a tag; errors must name the rule only", err)
					}
				}
				if got != (TagComparison{}) {
					t.Errorf("refused comparison returned data %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompareTags(%q, %q) error = %v, want nil", tt.old, tt.new, err)
			}
			if got.MajorChange != tt.wantMajor {
				t.Errorf("MajorChange = %v, want %v", got.MajorChange, tt.wantMajor)
			}
			if got.PolicyVersion != DefaultPolicyVersion {
				t.Errorf("PolicyVersion = %q, want %q", got.PolicyVersion, DefaultPolicyVersion)
			}
		})
	}
}

func TestCompareTagsRefusalsAreSentinelErrors(t *testing.T) {
	if errors.Is(ErrVariantChange, ErrNotComparable) || errors.Is(ErrNotComparable, ErrVariantChange) {
		t.Fatal("the two refusal sentinels must be distinct")
	}
	_, err := CompareTags("1.2.3-alpine", "1.2.3-slim", Policy{})
	if errors.Is(err, ErrNotComparable) {
		t.Errorf("variant change must not be reported as not comparable: %v", err)
	}
	_, err = CompareTags("latest", "1.2.3", Policy{})
	if errors.Is(err, ErrVariantChange) {
		t.Errorf("not comparable must not be reported as variant change: %v", err)
	}
}

func TestCompareTagsRecordsPolicy(t *testing.T) {
	p := Policy{Version: "org-2", MaxMajor: 3}
	got, err := CompareTags("1.2.3", "1.3.0", p)
	if err != nil {
		t.Fatalf("CompareTags: %v", err)
	}
	if got.PolicyVersion != "org-2" {
		t.Errorf("PolicyVersion = %q, want org-2", got.PolicyVersion)
	}
	if got.PolicyDigest != PolicyDigest(p) {
		t.Errorf("PolicyDigest = %q, want %q", got.PolicyDigest, PolicyDigest(p))
	}
}

func TestCompareTagsRejectsInvalidPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
	}{
		{name: "overlong version", policy: Policy{Version: strings.Repeat("v", maxPolicyVer+1)}},
		{name: "bad include regex", policy: Policy{Include: []string{"("}}},
		{name: "bad exclude regex", policy: Policy{Exclude: []string{"["}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompareTags("1.2.3", "1.3.0", tt.policy)
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestPolicyDigestOfNullPolicyIsFixed(t *testing.T) {
	if got := PolicyDigest(Policy{}); got != nullPolicyDigest {
		t.Fatalf("PolicyDigest(Policy{}) = %s, want %s", got, nullPolicyDigest)
	}
	// The zero policy and the same policy with its default version written
	// out select identically, so they share one digest.
	if got := PolicyDigest(Policy{Version: DefaultPolicyVersion}); got != nullPolicyDigest {
		t.Fatalf("explicit default version digest = %s, want %s", got, nullPolicyDigest)
	}
}

func TestPolicyDigestEveryFieldChangesDigest(t *testing.T) {
	base := Policy{
		Version:        "v1",
		Include:        []string{"^1\\."},
		Exclude:        []string{"-rc"},
		MaxMajor:       2,
		ExplicitStable: "1.4.0",
		AllowDates:     false,
	}
	seen := map[string]string{PolicyDigest(base): "base"}
	mutations := []struct {
		name string
		p    Policy
	}{
		{name: "version", p: func() Policy { p := base; p.Version = "v2"; return p }()},
		{name: "include", p: func() Policy { p := base; p.Include = []string{"^2\\."}; return p }()},
		{name: "include added", p: func() Policy { p := base; p.Include = []string{"^1\\.", "^2\\."}; return p }()},
		{name: "exclude", p: func() Policy { p := base; p.Exclude = []string{"-beta"}; return p }()},
		{name: "exclude removed", p: func() Policy { p := base; p.Exclude = nil; return p }()},
		{name: "max major", p: func() Policy { p := base; p.MaxMajor = 3; return p }()},
		{name: "explicit stable", p: func() Policy { p := base; p.ExplicitStable = "1.5.0"; return p }()},
		{name: "allow dates", p: func() Policy { p := base; p.AllowDates = true; return p }()},
	}
	for _, m := range mutations {
		d := PolicyDigest(m.p)
		if prev, dup := seen[d]; dup {
			t.Errorf("%s has the same digest as %s", m.name, prev)
		}
		seen[d] = m.name
	}
}

func TestPolicyDigestIsUnambiguousAcrossListBoundaries(t *testing.T) {
	a := PolicyDigest(Policy{Include: []string{"ab"}})
	b := PolicyDigest(Policy{Include: []string{"a", "b"}})
	c := PolicyDigest(Policy{Include: []string{"a b"}})
	if a == b || a == c || b == c {
		t.Fatalf("list boundaries must be part of the encoding: %s %s %s", a, b, c)
	}
	if PolicyDigest(Policy{Include: []string{}}) != PolicyDigest(Policy{}) {
		t.Error("an empty list and a nil list are the same policy")
	}
}

func TestPolicyDigestIsStableAndWellFormed(t *testing.T) {
	p := Policy{Version: "v1", Include: []string{"^1\\."}, MaxMajor: 2}
	d1, d2 := PolicyDigest(p), PolicyDigest(p)
	if d1 != d2 {
		t.Fatalf("digest is not deterministic: %s vs %s", d1, d2)
	}
	if len(d1) != 64 || strings.ToLower(d1) != d1 {
		t.Errorf("digest %q is not 64 lowercase hex characters", d1)
	}
}

// FuzzCompareTags drives CompareTags with arbitrary tag pairs. It must never
// panic; every comparable tag is equal to itself without a major change; and
// comparability and the refusal class are symmetric in the two arguments.
func FuzzCompareTags(f *testing.F) {
	f.Add("1.2.3", "2.0.0")
	f.Add("1.2.3-alpine", "1.2.3-slim")
	f.Add("1.2.3", "latest")
	f.Add("2024-01-15", "1.2.3")
	f.Add("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "1.2.3")
	f.Add("1.2", "1.2.0")
	f.Add("v1.2.3-rc1", "1.2.3")
	f.Add("1.2.3-", "1.2.3")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, a, b string) {
		self, errSelf := CompareTags(a, a, Policy{})
		if errSelf == nil && self.MajorChange {
			t.Fatalf("CompareTags(%q, %q) reports a major change for the same tag", a, a)
		}
		if errSelf != nil && !errors.Is(errSelf, ErrNotComparable) {
			t.Fatalf("CompareTags(%q, %q) = %v; a tag against itself can only be not comparable", a, a, errSelf)
		}

		ab, errAB := CompareTags(a, b, Policy{})
		ba, errBA := CompareTags(b, a, Policy{})
		if (errAB == nil) != (errBA == nil) {
			t.Fatalf("comparability is not symmetric for %q and %q: %v vs %v", a, b, errAB, errBA)
		}
		if errors.Is(errAB, ErrNotComparable) != errors.Is(errBA, ErrNotComparable) ||
			errors.Is(errAB, ErrVariantChange) != errors.Is(errBA, ErrVariantChange) {
			t.Fatalf("refusal class is not symmetric for %q and %q: %v vs %v", a, b, errAB, errBA)
		}
		if errAB == nil {
			if ab.MajorChange != ba.MajorChange {
				t.Fatalf("major change is not symmetric for %q and %q", a, b)
			}
			if ab.PolicyDigest != ba.PolicyDigest || ab.PolicyVersion != ba.PolicyVersion {
				t.Fatalf("policy identity differs for the same policy in both directions")
			}
		}
	})
}
