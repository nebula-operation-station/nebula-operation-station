// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"errors"
	"testing"
)

func TestTOTPLifecycle(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	if _, err := db.GetTOTP(); !errors.Is(err, ErrNoTOTP) {
		t.Fatalf("no secret: %v", err)
	}
	if err := db.UseTOTPStep(5); !errors.Is(err, ErrTOTPReplay) {
		t.Fatalf("use without secret: %v", err)
	}
	secret := bytes.Repeat([]byte{7}, 20)
	if err := db.SetTOTP(secret, "admin:uid1000"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTOTP([]byte{1}, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short secret: %v", err)
	}
	got, err := db.GetTOTP()
	if err != nil || !bytes.Equal(got.Secret, secret) || got.Activated || got.LastStep != 0 {
		t.Fatalf("get: %+v %v", got, err)
	}
	if err := db.UseTOTPStep(100); err != nil {
		t.Fatal(err)
	}
	for _, step := range []int64{100, 99} {
		if err := db.UseTOTPStep(step); !errors.Is(err, ErrTOTPReplay) {
			t.Fatalf("step %d reused: %v", step, err)
		}
	}
	db.Close()
	db = openT(t, dir)
	got, _ = db.GetTOTP()
	if !got.Activated || got.LastStep != 100 {
		t.Fatalf("after restart: %+v", got)
	}
	if err := db.UseTOTPStep(100); !errors.Is(err, ErrTOTPReplay) {
		t.Fatal("replay after restart")
	}
	// A new secret starts over, not activated.
	if err := db.SetTOTP(bytes.Repeat([]byte{8}, 20), "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetTOTP(); got.Activated || got.LastStep != 0 {
		t.Fatalf("reset: %+v", got)
	}
	if removed, err := db.RemoveTOTP(); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
}

func TestRecoveryPending(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	if _, ok, err := db.RecoveryPending(); err != nil || ok {
		t.Fatalf("initial: %v %v", ok, err)
	}
	if err := db.SetRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openT(t, dir)
	since, ok, err := db.RecoveryPending()
	if err != nil || !ok || !since.Equal(t0.Truncate(1e9)) {
		t.Fatalf("after restart: %v %v %v", since, ok, err)
	}
	if err := db.ClearRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.RecoveryPending(); ok {
		t.Fatal("still pending")
	}
}
