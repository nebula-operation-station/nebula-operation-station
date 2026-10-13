// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func cred(id byte) WebAuthnCredential {
	return WebAuthnCredential{
		ID: []byte{id, 0xaa}, PublicKey: []byte{0xa5, 0x01, 0x02}, UserHandle: bytes.Repeat([]byte{id}, 16),
		UserName: "axel", Label: "YubiKey", AAGUID: bytes.Repeat([]byte{1}, 16),
		AttestationFormat: "packed", CreatedBy: "code:admin:uid1000",
	}
}

func TestCredentialsDurableAndUnique(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	if err := db.AddWebAuthnCredential(cred(1)); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWebAuthnCredential(cred(1)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate ID: %v", err)
	}
	c2 := cred(2)
	c2.AAGUID, c2.UserHandle = nil, nil
	if err := db.AddWebAuthnCredential(c2); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openT(t, dir)
	list, err := db.ListWebAuthnCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !bytes.Equal(list[0].ID, cred(1).ID) || list[0].Label != "YubiKey" ||
		!list[0].CreatedAt.Equal(t0.Truncate(1e9)) || len(list[1].AAGUID) != 0 {
		t.Fatalf("unexpected list: %+v", list)
	}
	removed, err := db.RemoveWebAuthnCredential(cred(1).ID)
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if removed, _ := db.RemoveWebAuthnCredential(cred(1).ID); removed {
		t.Fatal("second remove reported success")
	}
}

func TestCredentialValidation(t *testing.T) {
	db := openT(t, privateDir(t))
	for name, mut := range map[string]func(*WebAuthnCredential){
		"empty id":        func(c *WebAuthnCredential) { c.ID = nil },
		"long id":         func(c *WebAuthnCredential) { c.ID = make([]byte, 1024) },
		"no key":          func(c *WebAuthnCredential) { c.PublicKey = nil },
		"long handle":     func(c *WebAuthnCredential) { c.UserHandle = make([]byte, 65) },
		"bad aaguid":      func(c *WebAuthnCredential) { c.AAGUID = []byte{1, 2} },
		"no user":         func(c *WebAuthnCredential) { c.UserName = "" },
		"escape in label": func(c *WebAuthnCredential) { c.Label = "a\x1b[2J" },
		"long label":      func(c *WebAuthnCredential) { c.Label = strings.Repeat("x", 201) },
		"no creator":      func(c *WebAuthnCredential) { c.CreatedBy = "" },
	} {
		c := cred(3)
		mut(&c)
		if err := db.AddWebAuthnCredential(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// The initial counter is stored with the credential, and never for an ID
// that is already registered (a registrant must not be able to raise the
// counter of someone else's credential).
func TestCredentialCounterIsAtomic(t *testing.T) {
	db := openT(t, privateDir(t))
	c := cred(4)
	c.SignCount = 9
	if err := db.AddWebAuthnCredential(c); err != nil {
		t.Fatal(err)
	}
	evil := cred(4)
	evil.SignCount = 0xffffffff
	if err := db.AddWebAuthnCredential(evil); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate: %v", err)
	}
	counters, err := db.LoadCounters()
	if err != nil {
		t.Fatal(err)
	}
	if got := counters[string(c.ID)]; got != 9 {
		t.Fatalf("counter %d, want 9", got)
	}
}
