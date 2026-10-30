// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

func TestScheduleGrantsAndClaims(t *testing.T) {
	db := openT(t, privateDir(t))
	now := time.Unix(1792000000, 0)
	// Keep the grant active through both sides of the interval boundary.
	g := permit.StoredGrant{ID: "00000000-0000-4000-8000-000000000001", Digest: strings.Repeat("a", 64), Doc: []byte(`{}`),
		ApprovedBy: "webauthn:x", CreatedAt: now, ExpiresAt: now.Add(2 * time.Hour)}
	if err := db.SaveScheduleGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveScheduleGrant(g); err == nil {
		t.Fatal("grant stored twice")
	}
	got, ok, err := db.ScheduleGrant(g.ID)
	if err != nil || !ok || got.Digest != g.Digest || !got.RevokedAt.IsZero() || !got.ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	claim := func(at time.Time) bool {
		ok, err := db.ClaimScheduleRun(g.ID, "core.facts", "web", at, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !claim(now) || claim(now.Add(59*time.Minute)) || !claim(now.Add(time.Hour)) || claim(now.Add(time.Hour)) {
		t.Fatal("interval not enforced")
	}
	if ok, _ := db.ClaimScheduleRun(g.ID, "core.facts", "db", now, time.Hour); !ok {
		t.Fatal("another host shares the interval")
	}
	if ok, err := db.RevokeScheduleGrant(g.ID, now); err != nil || !ok {
		t.Fatal(err)
	}
	if ok, _ := db.RevokeScheduleGrant(g.ID, now); ok {
		t.Fatal("revoked twice")
	}
	all, err := db.ScheduleGrants()
	if err != nil || len(all) != 1 || all[0].RevokedAt.IsZero() {
		t.Fatalf("%+v %v", all, err)
	}
}
