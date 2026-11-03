// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestBuiltinTrustBannerTrustedHidesBanner(t *testing.T) {
	st := &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "core", TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.0.0", ReleaseSha256: "aa"},
		},
	}
	if v := builtinTrustBanner(st); v != nil {
		t.Fatalf("trusted state: banner %+v, want nil", v)
	}
	if v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{}); v != nil {
		t.Fatalf("unspecified state: banner %+v, want nil", v)
	}
}

func TestBuiltinTrustBannerUntrustedListsAffectedVersions(t *testing.T) {
	st := &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			// New module: nothing trusted yet.
			{Name: "netprobe", ReleaseVersion: "2.1.0", ReleaseSha256: "bb"},
			// Changed: a different version is trusted.
			{Name: "core", TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.1.0", ReleaseSha256: "cc"},
			// Unchanged: this exact version is trusted.
			{Name: "facts", TrustedVersion: "3.0.0", TrustedSha256: "dd", ReleaseVersion: "3.0.0", ReleaseSha256: "dd"},
			// Removed from the release: not affected.
			{Name: "oldmod", TrustedVersion: "0.9.0", TrustedSha256: "ee"},
		},
	}
	v := builtinTrustBanner(st)
	if v == nil {
		t.Fatal("untrusted state: banner nil, want non-nil")
	}
	if v.Kind != "untrusted" {
		t.Errorf("Kind %q, want untrusted", v.Kind)
	}
	if v.Command != "nebula artifact trust-builtins" {
		t.Errorf("Command %q, want the local CLI command", v.Command)
	}
	if v.Headline == "" {
		t.Error("headline empty")
	}
	// Lease-replacement guidance (ADR 0007 E17).
	if !strings.Contains(v.Detail, "lease") {
		t.Errorf("Detail %q does not explain lease replacement", v.Detail)
	}
	want := []builtinTrustEntryView{
		{Name: "netprobe", Version: "2.1.0"},
		{Name: "core", Version: "1.1.0", Trusted: "1.0.0"},
	}
	if len(v.Affected) != len(want) {
		t.Fatalf("Affected %v, want %v", v.Affected, want)
	}
	for i := range want {
		if v.Affected[i] != want[i] {
			t.Errorf("Affected[%d] %+v, want %+v", i, v.Affected[i], want[i])
		}
	}
}

func TestBuiltinTrustBannerUnavailableIsDistinct(t *testing.T) {
	untrusted := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
	})
	v := builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE,
	})
	if v == nil {
		t.Fatal("unavailable state: banner nil, want non-nil")
	}
	if v.Kind != "unavailable" {
		t.Errorf("Kind %q, want unavailable", v.Kind)
	}
	if v.Command != "" || len(v.Affected) != 0 {
		t.Errorf("unavailable banner must name no command or versions, got %+v", v)
	}
	if v.Headline == untrusted.Headline {
		t.Error("unavailable and untrusted banners share the same headline")
	}
	// Unreachable is not a trust verdict.
	if strings.Contains(v.Headline, "untrusted") || strings.Contains(v.Detail, "untrusted") {
		t.Errorf("unavailable banner claims the built-ins are untrusted: %+v", v)
	}
}
