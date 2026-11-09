// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"errors"
	"testing"
)

// checkOrder asserts the properties of a total preorder on valid inputs:
// results in {-1, 0, 1}, reflexivity, antisymmetry and transitivity.
func checkOrder(t *testing.T, cmp func(a, b string) (int, error), a, b, c string) {
	t.Helper()
	ab, errA := cmp(a, b)
	ba, errB := cmp(b, a)
	if (errA == nil) != (errB == nil) {
		t.Fatalf("validity differs by argument order: %v / %v", errA, errB)
	}
	if errA != nil {
		if !errors.Is(errA, ErrInvalidVersion) {
			t.Fatalf("error does not wrap ErrInvalidVersion: %v", errA)
		}
		return
	}
	if ab < -1 || ab > 1 {
		t.Fatalf("cmp(%q, %q) = %d out of range", a, b, ab)
	}
	if ab != -ba {
		t.Fatalf("antisymmetry: cmp(%q,%q)=%d cmp(%q,%q)=%d", a, b, ab, b, a, ba)
	}
	if aa, _ := cmp(a, a); aa != 0 {
		t.Fatalf("reflexivity: cmp(%q,%q)=%d", a, a, aa)
	}
	bc, err := cmp(b, c)
	if err != nil {
		return
	}
	ac, _ := cmp(a, c)
	if ab <= 0 && bc <= 0 && ac > 0 {
		t.Fatalf("transitivity: %q <= %q <= %q but cmp(a,c)=%d", a, b, c, ac)
	}
	if ab >= 0 && bc >= 0 && ac < 0 {
		t.Fatalf("transitivity: %q >= %q >= %q but cmp(a,c)=%d", a, b, c, ac)
	}
}

func FuzzCompareDpkg(f *testing.F) {
	for _, tc := range dpkgOrderCases {
		f.Add(tc.a, tc.b, "1.0")
	}
	f.Add("1:1.0~~a-1+b1", "1.0-", "~")
	f.Add("0", "00:0-0", "0:0")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, CompareDpkg, a, b, c)
		if v, err := ParseDpkg(a); err == nil {
			if v.String() != a {
				t.Fatalf("round trip %q -> %q", a, v.String())
			}
		}
	})
}

func FuzzCompareAPK(f *testing.F) {
	for _, tc := range apkOrderCases {
		f.Add(tc.a, tc.b, "1.0")
	}
	f.Add("1.0a_rc1_p-r0", "1.00", "1.0.0.0_pre")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, CompareAPK, a, b, c)
	})
}

func FuzzOSVAffected(f *testing.F) {
	f.Add(true, "1.2-3", "0", "1.2-3+deb12u1", "", 2, 1)
	f.Add(false, "3.3.2-r0", "3.3.0-r0", "", "3.3.2-r0", 3, 4)
	f.Fuzz(func(t *testing.T, dpkg bool, version, intro, fixed, other string, k1, k2 int) {
		s := SchemeAPK
		if dpkg {
			s = SchemeDpkg
		}
		r := []Range{{Type: RangeEcosystem, Events: []Event{
			{Kind: EventIntroduced, Version: intro},
			{Kind: EventFixed, Version: fixed},
			{Kind: EventKind(k1), Version: other},
			{Kind: EventKind(k2), Version: version},
		}}}
		affected, err := OSVAffected(s, version, r)
		if err != nil && affected {
			t.Fatal("affected with error")
		}
	})
}

func FuzzSchemeForEcosystem(f *testing.F) {
	f.Add("debian:bookworm")
	f.Add("alpine:3.20")
	f.Fuzz(func(t *testing.T, eco string) {
		s, err := SchemeForEcosystem(eco)
		if err == nil && s != SchemeDpkg && s != SchemeAPK {
			t.Fatalf("SchemeForEcosystem(%q) = %v without error", eco, s)
		}
	})
}

func FuzzRunningKernel(f *testing.F) {
	f.Add(true, debFacts.Release, debFacts.BuildVersion, debSigned.SourceName, debSigned.SourceVersion, debSigned.BuiltUsing, "6.1.115-1")
	f.Add(false, ubuHWEFacts.Release, ubuHWEFacts.BuildVersion, ubuHWE.SourceName, ubuHWE.SourceVersion, ubuHWE.BuiltUsing, "6.8.0-47.47")
	f.Add(true, debUnsignedFacts.Release, debUnsignedFacts.BuildVersion, "linux", "6.1.112-1", "", "6.1.112-1")
	f.Fuzz(func(t *testing.T, debian bool, release, build, source, sourceVersion, builtUsing, fixed string) {
		d := DistroUbuntu
		if debian {
			d = DistroDebian
		}
		facts := KernelFacts{
			Distro:       d,
			Release:      release,
			BuildVersion: build,
			Installed: []Binary{
				{Name: "linux-image-" + release, SourceName: source, SourceVersion: sourceVersion, BuiltUsing: builtUsing},
				{Name: "linux-image-x" + release, SourceName: source, SourceVersion: sourceVersion, BuiltUsing: builtUsing},
			},
		}
		b, err := RunningKernel(facts)
		if err != nil {
			if !errors.Is(err, ErrKernelUnknown) {
				t.Fatalf("error does not wrap ErrKernelUnknown: %v", err)
			}
		} else {
			if !IsKernelSource(b.SourceName) || NeverVersionBasis(b.SourceName) {
				t.Fatalf("basis source %q is not an unsigned kernel source", b.SourceName)
			}
			if _, err := ParseDpkg(b.Version); err != nil {
				t.Fatalf("basis version %q invalid: %v", b.Version, err)
			}
		}
		r, err := KernelStatus(facts, fixed)
		if err != nil && r.State != KernelUnknown {
			t.Fatalf("state %v with error %v", r.State, err)
		}
	})
}

func FuzzSourceVersionBasis(f *testing.F) {
	f.Add("foo", "1.2-3", "1.2-2+deb12u1", true)
	f.Add("openssl", "3.3.2-r1", "3.3.2-r0", false)
	f.Fuzz(func(t *testing.T, source, v1, v2 string, dpkg bool) {
		s := SchemeAPK
		if dpkg {
			s = SchemeDpkg
		}
		installed := []Binary{
			{Name: "a", SourceName: source, SourceVersion: v1},
			{Name: "b", SourceName: source, SourceVersion: v2},
		}
		basis, err := SourceVersionBasis(s, source, installed)
		if err != nil {
			return
		}
		for _, v := range []string{v1, v2} {
			if c, _ := Compare(s, basis.Version, v); c > 0 {
				t.Fatalf("basis %q is not the lowest of %q, %q", basis.Version, v1, v2)
			}
		}
	})
}
