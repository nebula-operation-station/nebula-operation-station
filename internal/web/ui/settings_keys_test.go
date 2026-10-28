// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestKeyViewsMarksCurrentSessionKey checks the table marks exactly the key
// the current session used, and marks nothing without a session credential.
func TestKeyViewsMarksCurrentSessionKey(t *testing.T) {
	creds := []*pb.WebAuthnCredential{
		{CredentialId: "aaa", Label: "one"},
		{CredentialId: "bbb", Label: "two"},
	}
	views := keyViews(creds, "bbb")
	if views[0].Current || !views[1].Current {
		t.Fatalf("current marker wrong: %+v", views)
	}
	views = keyViews(creds, "")
	if views[0].Current || views[1].Current {
		t.Fatal("current marker set without a session credential")
	}
}

// TestKeyViewsShowsIDsAndCommands checks the table shows a short credential
// ID, the short AAGUID hex, an em dash for a missing label, and the exact
// remove command with the full credential ID.
func TestKeyViewsShowsIDsAndCommands(t *testing.T) {
	long := "abcdefghijklmnopqrstuv"
	views := keyViews([]*pb.WebAuthnCredential{
		{CredentialId: "abc123", Label: "short", Aaguid: "051d0464864e8f06b775a07a915b3b2c", CreatedAtUnix: 1750000000},
		{CredentialId: long, Aaguid: ""},
	}, "")
	if views[0].ShortID != "abc123" {
		t.Errorf("short ID %q, want abc123", views[0].ShortID)
	}
	if views[0].AAGUID != "051d0464" {
		t.Errorf("AAGUID %q, want 051d0464", views[0].AAGUID)
	}
	if views[0].RemoveCmd != "nebula webauthn remove abc123" {
		t.Errorf("remove command %q", views[0].RemoveCmd)
	}
	if views[0].Label != "short" {
		t.Errorf("label %q, want short", views[0].Label)
	}
	if string(views[0].Registered) == "" {
		t.Error("registered date not rendered")
	}
	if views[1].ShortID != "abcdefgh…stuv" {
		t.Errorf("short ID %q, want abcdefgh…stuv", views[1].ShortID)
	}
	if views[1].RemoveCmd != "nebula webauthn remove "+long {
		t.Errorf("remove command %q", views[1].RemoveCmd)
	}
	if views[1].AAGUID != "" {
		t.Errorf("AAGUID %q, want empty", views[1].AAGUID)
	}
	if views[1].Label != "—" {
		t.Errorf("label %q, want an em dash", views[1].Label)
	}
}

// TestKeyViewsEmptyList checks an empty credential list yields an empty,
// non-nil table so the template can show a "no keys" line.
func TestKeyViewsEmptyList(t *testing.T) {
	views := keyViews(nil, "")
	if views == nil || len(views) != 0 {
		t.Fatalf("views %v, want empty non-nil", views)
	}
}
