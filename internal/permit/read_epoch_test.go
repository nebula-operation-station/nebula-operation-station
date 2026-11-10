// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import "testing"

// TestReadDispatchEpochFollowsReadPause: ReadDispatchEpoch refuses exactly
// while reads are paused (lock until ResumeReadDispatch) or recovery is
// pending, reports a storage failure as such, and a lock moves the epoch.
func TestReadDispatchEpochFollowsReadPause(t *testing.T) {
	e, store := newLeaseEnv(t, ModeStandard)
	first, err := e.auth.ReadDispatchEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := e.auth.ReadDispatchEpoch(); err != nil || again != first {
		t.Fatalf("stable epoch: %d %v, want %d", again, err, first)
	}
	e.auth.Lock("test")
	_, err = e.auth.ReadDispatchEpoch()
	wantCode(t, err, CodeLeaseInactive)

	store.mu.Lock()
	store.recovering = true
	store.mu.Unlock()
	// Recovery pending: unlock cannot resume and the epoch stays refused.
	if err := e.auth.ResumeReadDispatch(); err == nil {
		t.Fatal("resumed during recovery")
	}
	_, err = e.auth.ReadDispatchEpoch()
	wantCode(t, err, CodeLeaseInactive)

	store.mu.Lock()
	store.recovering = false
	store.mu.Unlock()
	// Recovery finished: still paused until local unlock resumes.
	_, err = e.auth.ReadDispatchEpoch()
	wantCode(t, err, CodeLeaseInactive)
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	after, err := e.auth.ReadDispatchEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if after == first {
		t.Fatal("lock and unlock kept the epoch")
	}

	store.mu.Lock()
	store.failRead = true
	store.mu.Unlock()
	_, err = e.auth.ReadDispatchEpoch()
	wantCode(t, err, CodeStorage)
}
