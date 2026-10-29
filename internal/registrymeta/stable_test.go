// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"errors"
	"strings"
	"testing"
)

func TestLatestStable(t *testing.T) {
	// A 64-hex digest for the sha-ignored case.
	digest := "sha256:" + strings.Repeat("a1", 32)

	tests := []struct {
		name    string
		current string
		tags    []string
		policy  Policy
		want    Status
		wantTag string
		wantErr bool
	}{
		{
			name:    "nginx newer available",
			current: "1.26.4",
			tags:    []string{"latest", "stable", "1.27.0", "1.26.4", "1.25.5"},
			want:    StatusNewer,
			wantTag: "1.27.0",
		},
		{
			name:    "nginx up to date",
			current: "1.27.0",
			tags:    []string{"latest", "stable", "1.27.0", "1.26.4", "1.25.5"},
			want:    StatusUpToDate,
			wantTag: "1.27.0",
		},
		{
			name:    "nginx ambiguous floating and full tag",
			current: "1.26.4",
			tags:    []string{"1.27.0", "1.27", "1.26.4"},
			want:    StatusUnknown,
		},
		{
			name:    "nginx alpine newer available",
			current: "1.26.4-alpine",
			tags:    []string{"1.27.0-alpine", "1.27.0", "1.26.4-alpine", "1.26.4", "1.25.5-alpine"},
			want:    StatusNewer,
			wantTag: "1.27.0-alpine",
		},
		{
			name:    "nginx alpine up to date ignores plain variant",
			current: "1.27.0-alpine",
			tags:    []string{"1.27.0-alpine", "1.27.0", "1.26.4-alpine"},
			want:    StatusUpToDate,
			wantTag: "1.27.0-alpine",
		},
		{
			name:    "alpine variant with no alpine tags",
			current: "1.26.4-alpine",
			tags:    []string{"1.27.0", "1.26.4", "latest"},
			want:    StatusUnknown,
		},
		{
			name:    "alpine and alpine3.19 are distinct variants",
			current: "1.26.4-alpine3.19",
			tags:    []string{"1.27.0-alpine3.19", "1.27.0-alpine", "1.26.4-alpine3.19"},
			want:    StatusNewer,
			wantTag: "1.27.0-alpine3.19",
		},
		{
			name:    "postgres major and minor tags",
			current: "16.2",
			tags:    []string{"latest", "17.1", "17.1-alpine", "17", "16.2", "16.2-alpine", "16"},
			want:    StatusNewer,
			wantTag: "17.1",
		},
		{
			name:    "postgres alpine newer",
			current: "16.2-alpine",
			tags:    []string{"17.1-alpine", "17.1", "16.2-alpine", "16.2"},
			want:    StatusNewer,
			wantTag: "17.1-alpine",
		},
		{
			name:    "ollama ignores non-version tags",
			current: "0.4.9",
			tags:    []string{"latest", "0.5.0", "0.4.9", "0.3.0", "rocm", "cuda"},
			want:    StatusNewer,
			wantTag: "0.5.0",
		},
		{
			name:    "litellm ignores main",
			current: "1.39.5",
			tags:    []string{"latest", "1.40.0", "1.39.5", "1.38.0", "main"},
			want:    StatusNewer,
			wantTag: "1.40.0",
		},
		{
			name:    "grafana plain ignores ubuntu variant",
			current: "11.0.5",
			tags:    []string{"latest", "11.1.0", "11.0.5", "10.4.15", "11.1.0-ubuntu"},
			want:    StatusNewer,
			wantTag: "11.1.0",
		},
		{
			name:    "grafana ubuntu variant",
			current: "11.0.5-ubuntu",
			tags:    []string{"11.1.0-ubuntu", "11.1.0", "11.0.5-ubuntu"},
			want:    StatusNewer,
			wantTag: "11.1.0-ubuntu",
		},
		{
			name:    "pre-releases are ignored",
			current: "1.2.3",
			tags:    []string{"1.3.0-rc1", "1.3.0-beta", "1.2.3", "1.2.4"},
			want:    StatusNewer,
			wantTag: "1.2.4",
		},
		{
			name:    "stable of same version is newer than current pre-release",
			current: "1.3.0-rc1",
			tags:    []string{"1.3.0", "1.2.4"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "non-version tags are ignored",
			current: "1.2.0",
			tags:    []string{"latest", "edge", "nightly", "main", "master", "1.3.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "sha and digest tags are ignored",
			current: "1.2.0",
			tags:    []string{digest, "a1b2c3d", "1.3.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "date tags ignored by default",
			current: "1.2.0",
			tags:    []string{"2024-01-15", "2024-02-20", "1.3.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "date tags allowed when current is a date",
			current: "2024-01-15",
			tags:    []string{"2024-01-15", "2024-02-20", "2024-03-01"},
			policy:  Policy{AllowDates: true},
			want:    StatusNewer,
			wantTag: "2024-03-01",
		},
		{
			name:    "date current without AllowDates is unknown",
			current: "2024-01-15",
			tags:    []string{"2024-02-20"},
			want:    StatusUnknown,
		},
		{
			name:    "current not a version is advisory",
			current: "latest",
			tags:    []string{"1.3.0", "1.2.0"},
			want:    StatusUnknown,
			wantTag: "1.3.0",
		},
		{
			name:    "current ahead of the latest stable",
			current: "99.0.0",
			tags:    []string{"1.3.0", "1.2.0"},
			want:    StatusUpToDate,
			wantTag: "1.3.0",
		},
		{
			name:    "v prefix handled",
			current: "1.2.0",
			tags:    []string{"v1.3.0", "v1.2.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "v1.3.0",
		},
		{
			name:    "v prefix and plain are the same version",
			current: "1.2.0",
			tags:    []string{"v1.3.0", "1.3.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "build metadata does not order versions",
			current: "1.2.0",
			tags:    []string{"1.3.0+build5", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0+build5",
		},
		{
			name:    "include restricts to matching tags",
			current: "1.2.0",
			tags:    []string{"2.0.0", "1.5.0", "1.2.0"},
			policy:  Policy{Include: []string{`^1\.`}},
			want:    StatusNewer,
			wantTag: "1.5.0",
		},
		{
			name:    "exclude drops a tag",
			current: "1.2.0",
			tags:    []string{"1.5.0", "1.2.0", "1.5.0-rc1"},
			policy:  Policy{Exclude: []string{`^1\.5\.0$`}},
			want:    StatusUpToDate,
			wantTag: "1.2.0",
		},
		{
			name:    "max major caps the upgrade",
			current: "1.2.0",
			tags:    []string{"2.0.0", "1.5.0", "1.2.0"},
			policy:  Policy{MaxMajor: 1},
			want:    StatusNewer,
			wantTag: "1.5.0",
		},
		{
			name:    "explicit stable target",
			current: "1.2.0",
			tags:    []string{"1.5.0", "1.2.0", "1.4.0"},
			policy:  Policy{ExplicitStable: "1.4.0"},
			want:    StatusNewer,
			wantTag: "1.4.0",
		},
		{
			name:    "explicit stable not in list",
			current: "1.2.0",
			tags:    []string{"1.5.0", "1.2.0"},
			policy:  Policy{ExplicitStable: "9.9.9"},
			want:    StatusUnknown,
		},
		{
			name:    "empty tag list",
			current: "1.2.0",
			tags:    []string{},
			want:    StatusUnknown,
		},
		{
			name:    "empty current is advisory",
			current: "",
			tags:    []string{"1.3.0", "1.2.0"},
			want:    StatusUnknown,
			wantTag: "1.3.0",
		},
		{
			name:    "incomplete tags 1.2 vs 1.2.0 are ambiguous",
			current: "1.1.0",
			tags:    []string{"1.2", "1.2.0"},
			want:    StatusUnknown,
		},
		{
			name:    "numeric not lexical comparison",
			current: "1.9.0",
			tags:    []string{"1.10.0", "1.9.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.10.0",
		},
		{
			name:    "major minor patch ordering",
			current: "1.2.9",
			tags:    []string{"1.3.0", "1.2.10", "1.2.9"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "single component versions",
			current: "1",
			tags:    []string{"2", "1", "3"},
			want:    StatusNewer,
			wantTag: "3",
		},
		{
			name:    "two component versions",
			current: "1.2",
			tags:    []string{"1.3", "1.2", "1.10"},
			want:    StatusNewer,
			wantTag: "1.10",
		},
		{
			name:    "all non-version tags",
			current: "1.2.0",
			tags:    []string{"latest", "edge", "nightly"},
			want:    StatusUnknown,
		},
		{
			name:    "duplicate tags are not ambiguous",
			current: "1.2.0",
			tags:    []string{"1.3.0", "1.3.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "current need not be in the list",
			current: "1.0.0",
			tags:    []string{"1.3.0", "1.2.0"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
		{
			name:    "invalid include regex is an error",
			current: "1.2.0",
			tags:    []string{"1.3.0"},
			policy:  Policy{Include: []string{"["}},
			wantErr: true,
		},
		{
			name:    "too many tags is an error",
			current: "1.2.0",
			tags:    make([]string, maxTags+1),
			wantErr: true,
		},
		{
			name:    "policy version is recorded",
			current: "1.2.0",
			tags:    []string{"1.3.0"},
			policy:  Policy{Version: "my-policy-1"},
			want:    StatusNewer,
			wantTag: "1.3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LatestStable(tt.current, tt.tags, tt.policy)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				if !errors.Is(err, ErrInvalidPolicy) {
					t.Fatalf("want ErrInvalidPolicy, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.want {
				t.Errorf("Status = %v, want %v (reason: %s)", got.Status, tt.want, got.Reason)
			}
			if got.Latest != tt.wantTag {
				t.Errorf("Latest = %q, want %q", got.Latest, tt.wantTag)
			}
			wantVer := tt.policy.Version
			if wantVer == "" {
				wantVer = DefaultPolicyVersion
			}
			if got.PolicyVersion != wantVer {
				t.Errorf("PolicyVersion = %q, want %q", got.PolicyVersion, wantVer)
			}
		})
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		s    Status
		want string
	}{
		{StatusUnknown, "unknown"},
		{StatusUpToDate, "up-to-date"},
		{StatusNewer, "newer"},
		{Status(99), "invalid"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

func TestLatestStableDoesNotMutateInput(t *testing.T) {
	in := []string{"1.2.0", "1.3.0", "latest"}
	snapshot := append([]string(nil), in...)
	if _, err := LatestStable("1.2.0", in, Policy{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := range in {
		if in[i] != snapshot[i] {
			t.Fatalf("input mutated at %d: %q -> %q", i, snapshot[i], in[i])
		}
	}
}

func TestLatestStableRejectsOverflow(t *testing.T) {
	oversized := strings.Repeat("9", 30)
	for _, tag := range []string{oversized + ".0.0", "1." + oversized + ".0", "1.2." + oversized} {
		t.Run(tag, func(t *testing.T) {
			got, err := LatestStable("1.2.3", []string{tag, "1.2.3"}, Policy{})
			if err != nil || got.Status != StatusUpToDate || got.Latest != "1.2.3" {
				t.Fatalf("LatestStable = %+v, %v; want up-to-date 1.2.3", got, err)
			}
			got, err = LatestStable(tag, []string{"1.2.3"}, Policy{})
			if err != nil || got.Status != StatusUnknown || got.Latest != "1.2.3" {
				t.Fatalf("overflow current = %+v, %v; want unknown with advisory 1.2.3", got, err)
			}
		})
	}
}

func TestLatestStablePrereleaseRetainsVariant(t *testing.T) {
	for _, suffix := range []string{"rc1-alpine", "beta.2-alpine3.19", "rc-1-alpine-slim"} {
		variant := suffix[strings.Index(suffix, "alpine"):]
		t.Run(suffix, func(t *testing.T) {
			for _, tc := range []struct {
				tags   []string
				status Status
				latest string
			}{
				{[]string{"2.0.0", "1.3.0-" + variant, "1.4.0-rc2-" + variant}, StatusNewer, "1.3.0-" + variant},
				{[]string{"2.0.0", "1.3.0"}, StatusUnknown, ""},
			} {
				got, err := LatestStable("1.3.0-"+suffix, tc.tags, Policy{})
				if err != nil || got.Status != tc.status || got.Latest != tc.latest {
					t.Fatalf("LatestStable = %+v, %v; want %v %q", got, err, tc.status, tc.latest)
				}
			}
		})
	}
}

func TestLatestStableValidatesDateAndTime(t *testing.T) {
	for _, tag := range []string{
		"2024-02-31", "2023-02-29", "1900-02-29", "2024-04-31", "20240231",
		"2024-03-01T24:00:00", "2024-03-01T12:60:00", "2024-03-01T12:00:60",
		"2024-03-01T", "2024-03-01T12", "2024-03-01T1:02:03", "2024-03-01T12:00",
		"2024-03-01Txx:00:00", "2024-03-01T12:00:00junk", "2024-03-01T12:00:00.5Z",
		"2024-03-01T999999999999999999999999:00:00",
	} {
		t.Run(tag, func(t *testing.T) {
			if got := parseTag(tag); got.kind != kindOther {
				t.Fatalf("parseTag(%q).kind = %v; want kindOther", tag, got.kind)
			}
			got, err := LatestStable("2024-02-28", []string{"2024-02-29", tag}, Policy{AllowDates: true})
			if err != nil || got.Status != StatusNewer || got.Latest != "2024-02-29" {
				t.Fatalf("LatestStable = %+v, %v; want newer 2024-02-29", got, err)
			}
			got, err = LatestStable(tag, []string{"2024-02-29"}, Policy{AllowDates: true})
			if err != nil || got.Status != StatusUnknown || got.Latest != "" {
				t.Fatalf("invalid current = %+v, %v; want unknown without a selection", got, err)
			}
		})
	}
	for _, tag := range []string{"20240229", "2000-02-29", "2024-02-29T23:59:59Z", "2024-02-29 23:59:59", "2024-02-29T00:00:00"} {
		t.Run(tag, func(t *testing.T) {
			got, err := LatestStable("1999-01-01", []string{tag}, Policy{AllowDates: true})
			if err != nil || got.Status != StatusNewer || got.Latest != tag {
				t.Fatalf("LatestStable = %+v, %v; want newer %q", got, err, tag)
			}
		})
	}
}
