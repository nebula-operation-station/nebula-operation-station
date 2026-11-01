// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestSessionRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	checkPVEAdminRPC(t, "GetSessionState", (*Client).GetSessionState)
}

// GetSessionState reports the executor's authoritative session state end to
// end: inactive before the session, active with the executor-configured
// duration (default 60 minutes) and a positive remaining time afterwards.
func TestGetSessionStateEndToEnd(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()

	st, err := c.GetSessionState(h.ctx(), &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetActive() || st.GetExpiryUnix() != 0 || st.GetRemainingSeconds() != 0 {
		t.Fatalf("inactive state = %+v, want inactive", st)
	}
	if st.GetDurationSeconds() != 3600 {
		t.Fatalf("duration = %d, want the executor's default 3600s", st.GetDurationSeconds())
	}

	h.openSession(c)
	st, err = c.GetSessionState(h.ctx(), &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetActive() || st.GetExpiryUnix() <= 0 || st.GetDurationSeconds() != 3600 {
		t.Fatalf("active state = %+v, want active with 3600s duration", st)
	}
	if st.GetRemainingSeconds() <= 0 || st.GetRemainingSeconds() > 3600 {
		t.Fatalf("remaining = %d, want in (0, 3600]", st.GetRemainingSeconds())
	}
}
