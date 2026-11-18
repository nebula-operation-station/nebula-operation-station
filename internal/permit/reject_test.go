// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func TestRejectReasonLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		ok     bool
		n      int
	}{
		{"empty", "", true, 0},
		{"200 code points", strings.Repeat("ä", 200), true, 200},
		{"201 code points", strings.Repeat("a", 201), false, 0},
		{"over 800 bytes", strings.Repeat("😀", 201), false, 0},
		{"invalid UTF-8", "a\xffb", false, 0},
		{"C0", "a\tb", false, 0},
		{"DEL", "a\x7fb", false, 0},
		{"C1", "a\u0085b", false, 0},
		{"bidi override", "a‮b", false, 0},
		{"bidi isolate", "a⁧b", false, 0},
		{"arabic letter mark", "a؜b", false, 0},
		{"plain text", "wrong host, planned again", true, 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := ValidateRejectReason(tc.reason)
			if tc.ok {
				if err != nil || n != tc.n {
					t.Fatalf("n=%d err=%v, want %d", n, err, tc.n)
				}
				return
			}
			wantCode(t, err, CodeInvalidRequest)
		})
	}
}

func TestRelayedUserLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		role RejectRole
		user string
		ok   bool
	}{
		{"server user", RejectRoleServer, "alice", true},
		{"server user with space", RejectRoleServer, "Alice Admin", true},
		{"server 64 bytes", RejectRoleServer, strings.Repeat("a", 64), true},
		{"server 65 bytes", RejectRoleServer, strings.Repeat("a", 65), false},
		{"server empty", RejectRoleServer, "", false},
		{"server tab", RejectRoleServer, "a\tb", false},
		{"server nbsp", RejectRoleServer, "a b", false},
		{"server ideographic space", RejectRoleServer, "a　b", false},
		{"server line separator", RejectRoleServer, "a b", false},
		{"server bidi", RejectRoleServer, "a‏b", false},
		{"server invalid UTF-8", RejectRoleServer, "a\xc0", false},
		{"admin empty", RejectRoleAdmin, "", true},
		{"admin with user", RejectRoleAdmin, "alice", false},
		{"unknown role", RejectRole("reader"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRelayedUser(tc.role, tc.user)
			if tc.ok != (err == nil) {
				t.Fatalf("err=%v, want ok=%v", err, tc.ok)
			}
			if err != nil {
				wantCode(t, err, CodeInvalidRequest)
			}
		})
	}
}

// memRejectionMarkers is a minimal RejectionStore for this package's tests.
type memRejectionMarkers struct {
	rows map[canonical.Digest]Rejection
}

func (m *memRejectionMarkers) RejectedProposal(d canonical.Digest) (Rejection, bool, error) {
	r, ok := m.rows[d]
	return r, ok, nil
}
func (m *memRejectionMarkers) RejectedBatchID(string) (bool, error) { return false, nil }
func (m *memRejectionMarkers) CommitRejection(r Rejection, _ []ExecutionBinding) error {
	m.rows[r.Digest] = r
	return nil
}

// A marker answers before the in-memory lookup: even with a stale pending
// entry still in memory, both approval paths refuse with permit_rejected.
func TestApprovalRefusesMarkedDigestEvenWithStaleEntry(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	markers := &memRejectionMarkers{rows: map[canonical.Digest]Rejection{}}
	e.auth.rejections = markers
	p := e.propose(e.request(canonical.RiskMedium))
	markers.rows[p.Digest] = Rejection{Digest: p.Digest}
	if st, ok := e.auth.PermitState(p.Digest); !ok || st != StatePending {
		t.Fatal("stale entry must still be in memory for this test")
	}
	_, err := e.auth.ApproveCLI(p.Digest, 0, "admin")
	wantCode(t, err, CodeRejected)
	e.openSession()
	_, err = e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0)
	wantCode(t, err, CodeRejected)
}

func TestPlaceholderCountsUntilWindowEndAndLock(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.auth.rejections = &memRejectionMarkers{rows: map[canonical.Digest]Rejection{}}
	p := e.propose(e.request(canonical.RiskMedium))
	tx := e.auth.BeginReject()
	tx.Finish(p.Digest, p.ApprovalExpiry)
	if n := e.auth.pendingCountLocked(); n != 1 {
		tx.End()
		t.Fatalf("pending count with placeholder = %d, want 1", n)
	}
	tx.End()
	if len(e.auth.Pending()) != 0 {
		t.Fatal("placeholder visible as a pending permit")
	}
	e.clk.Add(ApprovalWindow + time.Second)
	e.auth.mu.Lock()
	e.auth.gcLocked(e.clk.Now())
	n := e.auth.pendingCountLocked()
	e.auth.mu.Unlock()
	if n != 0 {
		t.Fatalf("placeholder outlived its window: %d", n)
	}

	q := e.propose(e.request(canonical.RiskMedium))
	tx = e.auth.BeginReject()
	tx.Finish(q.Digest, q.ApprovalExpiry)
	tx.End()
	e.auth.Lock("test")
	e.auth.mu.Lock()
	n = e.auth.pendingCountLocked()
	e.auth.mu.Unlock()
	if n != 0 {
		t.Fatalf("lock kept the placeholder: %d", n)
	}
}
