// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRegistryReadMethodsAreTheClosedMetadataSet(t *testing.T) {
	want := []string{"tag_digest", "list_tags"}
	if got := RegistryReadMethods(); !slices.Equal(got, want) {
		t.Fatalf("RegistryReadMethods() = %v, want %v", got, want)
	}
	for _, m := range want {
		if !IsRegistryReadMethod(m) {
			t.Errorf("%s not accepted", m)
		}
	}
	// No blob fetch, pull, push, login or catalog is representable.
	for _, m := range []string{"", "TAG_DIGEST", "tag_digest ", "blob", "pull", "push", "login", "catalog", "manifest_get"} {
		if IsRegistryReadMethod(m) {
			t.Errorf("%q accepted", m)
		}
	}
	got := RegistryReadMethods()
	got[0] = "pull"
	if IsRegistryReadMethod("pull") {
		t.Fatal("closed set mutated through RegistryReadMethods")
	}
}

func TestRegistryReadProfileLimits(t *testing.T) {
	if RegistryReadProfile != "registry" {
		t.Fatalf("profile %q", RegistryReadProfile)
	}
	if RegistryMinInterval != 15*time.Minute {
		t.Fatalf("floor %v", RegistryMinInterval)
	}
	if RegistryDefaultRunBudget != 24 || RegistryMaxRunBudget != 240 {
		t.Fatalf("budgets %d/%d", RegistryDefaultRunBudget, RegistryMaxRunBudget)
	}
	if RegistryReadMaxLifetime != 7*24*time.Hour {
		t.Fatalf("lifetime %v", RegistryReadMaxLifetime)
	}
}

func TestValidRegistryIdentifiers(t *testing.T) {
	for _, id := range []string{"ghcr", "harbor-1", "a", strings.Repeat("a", 32)} {
		if !ValidRegistryID(id) {
			t.Errorf("registry id %q rejected", id)
		}
	}
	for _, id := range []string{"", "-a", "Harbor", "a_b", "a.b", strings.Repeat("a", 33), "a/b"} {
		if ValidRegistryID(id) {
			t.Errorf("registry id %q accepted", id)
		}
	}
	for _, r := range []string{"team/app", "app", "a/b/c", "my-org/my_app.v2"} {
		if !ValidRegistryRepository(r) {
			t.Errorf("repository %q rejected", r)
		}
	}
	for _, r := range []string{"", "Team/app", "/app", "app/", "a//b", "app:latest", "app@sha256:00", "../app",
		"a b", strings.Repeat("a", 256)} {
		if ValidRegistryRepository(r) {
			t.Errorf("repository %q accepted", r)
		}
	}
}
