// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Table test for defaultSpoolOwnership with an injected group lookup. It
// exercises the production ownership rule (nebula-rpc group resolution,
// egid fallback, fail-closed on lookup errors) without depending on the
// host's group database.

package pvecollect

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"testing"
)

// TestDefaultSpoolOwnership checks the production spool ownership rule
// with an injected group lookup and supplementary group list, so the test
// is independent of the host's groups.
func TestDefaultSpoolOwnership(t *testing.T) {
	uid := uint32(os.Geteuid())
	egid := uint32(os.Getegid())
	// A GID different from the process's effective GID, so the group's GID
	// is distinguishable from the egid fallback on every host.
	sharedGID := egid + 1
	if sharedGID == 0 {
		sharedGID = 1
	}
	lookupErr := errors.New("group database unavailable")
	getgroupsErr := errors.New("cannot read supplementary groups")
	cases := []struct {
		name string
		// group is the answer the injected group lookup returns together
		// with lookupErr.
		group *user.Group
		// lookupErr is the error the injected group lookup returns.
		lookupErr error
		// supplementary is the GID list the injected supplementary group
		// lookup returns, together with supplementaryErr.
		supplementary    []int
		supplementaryErr error
		// wantUID and wantGID are the expected ownership; wantErr means
		// the lookup must fail closed.
		wantUID, wantGID uint32
		wantErr          bool
	}{
		{
			name:    "group exists and is the primary group",
			group:   &user.Group{Name: spoolGroupName, Gid: strconv.FormatUint(uint64(egid), 10)},
			wantUID: uid,
			wantGID: egid,
		},
		{
			name:          "group exists and is a supplementary group",
			group:         &user.Group{Name: spoolGroupName, Gid: strconv.FormatUint(uint64(sharedGID), 10)},
			supplementary: []int{int(sharedGID)},
			wantUID:       uid,
			wantGID:       sharedGID,
		},
		{
			name:    "group exists but the process is not a member",
			group:   &user.Group{Name: spoolGroupName, Gid: strconv.FormatUint(uint64(sharedGID), 10)},
			wantUID: uid,
			wantGID: egid,
		},
		{
			name:      "group missing falls back to the effective GID",
			lookupErr: user.UnknownGroupError(spoolGroupName),
			wantUID:   uid,
			wantGID:   egid,
		},
		{
			name:      "group lookup error fails closed",
			lookupErr: lookupErr,
			wantErr:   true,
		},
		{
			name:    "group with an unparsable GID fails closed",
			group:   &user.Group{Name: spoolGroupName, Gid: "not-a-gid"},
			wantErr: true,
		},
		{
			name:             "supplementary group read error fails closed",
			group:            &user.Group{Name: spoolGroupName, Gid: strconv.FormatUint(uint64(sharedGID), 10)},
			supplementaryErr: getgroupsErr,
			wantErr:          true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origLookup := spoolGroupLookup
			spoolGroupLookup = func(string) (*user.Group, error) { return c.group, c.lookupErr }
			t.Cleanup(func() { spoolGroupLookup = origLookup })
			origGroups := spoolSupplementaryGroups
			spoolSupplementaryGroups = func() ([]int, error) { return c.supplementary, c.supplementaryErr }
			t.Cleanup(func() { spoolSupplementaryGroups = origGroups })

			gotUID, gotGID, err := defaultSpoolOwnership()
			if c.wantErr {
				if err == nil {
					t.Fatalf("ownership = %d:%d, want a failure", gotUID, gotGID)
				}
				return
			}
			if err != nil {
				t.Fatalf("ownership lookup: %v", err)
			}
			if gotUID != c.wantUID || gotGID != c.wantGID {
				t.Fatalf("ownership = %d:%d, want %d:%d", gotUID, gotGID, c.wantUID, c.wantGID)
			}
		})
	}
}
