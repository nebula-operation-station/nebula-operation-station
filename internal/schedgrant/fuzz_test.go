// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// FuzzParse feeds arbitrary bytes to Parse, the executor's check of a grant
// document that comes from the server and is therefore untrusted. A
// rejection must wrap ErrInvalid; an acceptance must satisfy every limit
// and return the hash of its canonical form.
func FuzzParse(f *testing.F) {
	seed, err := json.Marshal(valid())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	for _, mutate := range refusedDocCases() {
		d := valid()
		mutate(&d)
		b, err := json.Marshal(d)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, s := range refusedRawCases(f) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, canon, hash, err := Parse(raw, now)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("rejection does not wrap ErrInvalid: %v", err)
			}
			return
		}
		checkAccepted(t, d, canon, hash)
	})
}

// checkAccepted asserts every invariant of an accepted grant at now.
func checkAccepted(t *testing.T, d Doc, canon []byte, hash string) {
	t.Helper()
	want, err := canonical.HashParameters(canon)
	if err != nil {
		t.Fatalf("canonical bytes do not hash: %v", err)
	}
	if hash != want {
		t.Fatalf("hash %s is not the SHA-256 of the canonical bytes %s", hash, want)
	}
	if _, _, h, err := Parse(canon, now); err != nil || h != hash {
		t.Fatalf("reparse hash %s, err %v; want %s", h, err, hash)
	}
	if len(d.Actions) < 1 || len(d.Actions) > MaxActions {
		t.Fatalf("%d actions", len(d.Actions))
	}
	if len(d.Targets) < 1 || len(d.Targets) > MaxTargets {
		t.Fatalf("%d targets", len(d.Targets))
	}
	if d.MinIntervalS < int64(MinInterval/time.Second) || d.MinIntervalS > int64(MaxInterval/time.Second) {
		t.Fatalf("interval %d s outside limits", d.MinIntervalS)
	}
	lo := now.Add(MinLifetime).Unix()
	hi := now.Add(MaxLifetime).Unix()
	if d.ExpiryUnix < lo || d.ExpiryUnix > hi {
		t.Fatalf("expiry %d outside [%d, %d]", d.ExpiryUnix, lo, hi)
	}
	actions := map[string]bool{}
	for _, a := range d.Actions {
		key := a.ActionID + "@" + a.ModuleVersion
		if actions[key] {
			t.Fatalf("action %s listed twice", key)
		}
		actions[key] = true
	}
	hosts := map[string]bool{}
	for _, tg := range d.Targets {
		if hosts[tg.HostID] {
			t.Fatalf("host %s listed twice", tg.HostID)
		}
		hosts[tg.HostID] = true
	}
}
