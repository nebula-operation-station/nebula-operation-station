// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func memberRun(id, member string) Run {
	return Run{ExecutionID: id, HostID: "web-1", Digest: strings.Repeat("d", 64), Endpoints: []string{"10.0.0.1:22"},
		Fingerprint: "SHA256:x", Timeout: 30 * time.Minute, MemberID: member, ActionID: "docker.compose_update"}
}

// A batch member's durable run keeps its member and action ID (migration
// 0020), so it can be found by batch digest and member ID after a restart.
func TestRunKeepsMemberAndAction(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	r := memberRun("00000000-0000-4000-9000-000000000001", "m-01")
	if err := db.CreateRun(r); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateRun(Run{ExecutionID: "00000000-0000-4000-9000-000000000002", HostID: "web-1", Digest: strings.Repeat("e", 64),
		Endpoints: []string{"10.0.0.1:22"}, Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openT(t, dir)
	got, err := db.GetRun(r.ExecutionID, r.HostID)
	if err != nil || got.MemberID != "m-01" || got.ActionID != "docker.compose_update" {
		t.Fatalf("run %+v %v", got, err)
	}
	byMember, err := db.RunByMember(r.Digest, "m-01")
	if err != nil || byMember.ExecutionID != r.ExecutionID {
		t.Fatalf("by member %+v %v", byMember, err)
	}
	classic, err := db.GetRun("00000000-0000-4000-9000-000000000002", "web-1")
	if err != nil || classic.MemberID != "" || classic.ActionID != "" {
		t.Fatalf("classic run %+v %v", classic, err)
	}
}

func TestRunByMemberRefusesUnknownAndMalformed(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.CreateRun(memberRun("00000000-0000-4000-9000-000000000001", "m-01")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][2]string{
		"other member": {strings.Repeat("d", 64), "m-02"},
		"other batch":  {strings.Repeat("f", 64), "m-01"},
		"empty member": {strings.Repeat("d", 64), ""},
	} {
		if _, err := db.RunByMember(c[0], c[1]); !errors.Is(err, ErrNoRun) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestCreateRunRefusesOversizeMemberOrAction(t *testing.T) {
	db := openT(t, privateDir(t))
	r := memberRun("00000000-0000-4000-9000-000000000001", strings.Repeat("m", maxRunMemberID+1))
	if err := db.CreateRun(r); err == nil {
		t.Fatal("oversize member ID stored")
	}
	r = memberRun("00000000-0000-4000-9000-000000000002", "m-01")
	r.ActionID = strings.Repeat("a", maxRunActionID+1)
	if err := db.CreateRun(r); err == nil {
		t.Fatal("oversize action ID stored")
	}
}
