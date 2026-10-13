// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// memStore is an in-memory Store for tests. The real implementation is
// internal/executordb, whose tests cover durability.
type memStore struct {
	mu      sync.Mutex
	ids     map[string]canonical.Digest
	expires map[string]time.Time
	failErr error // returned by every call while set
}

func newMemStore() *memStore {
	return &memStore{ids: map[string]canonical.Digest{}, expires: map[string]time.Time{}}
}

func (m *memStore) BindExecution(id string, d canonical.Digest, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	if _, ok := m.ids[id]; ok {
		return ErrExecutionBound
	}
	m.ids[id] = d
	m.expires[id] = expiresAt
	return nil
}

func (m *memStore) LookupExecution(id string) (canonical.Digest, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return canonical.Digest{}, false, m.failErr
	}
	d, ok := m.ids[id]
	return d, ok, nil
}

func (m *memStore) setFail(err error) { m.mu.Lock(); m.failErr = err; m.mu.Unlock() }

// memCounters is an in-memory webauthnverify.CounterStore for tests.
type memCounters struct {
	mu      sync.Mutex
	c       map[string]uint32
	saveErr error // returned by SaveCounter while set
}

func newMemCounters() *memCounters { return &memCounters{c: map[string]uint32{}} }

func (m *memCounters) LoadCounters() (map[string]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint32, len(m.c))
	for k, v := range m.c {
		out[k] = v
	}
	return out, nil
}

func (m *memCounters) SaveCounter(id []byte, n uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	if n > m.c[string(id)] {
		m.c[string(id)] = n
	}
	return nil
}

func (m *memCounters) setSaveErr(err error) { m.mu.Lock(); m.saveErr = err; m.mu.Unlock() }

var _ webauthnverify.CounterStore = (*memCounters)(nil)

func TestNewRequiresStore(t *testing.T) {
	v, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: newMemCounters()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Verifier: v, RiskPolicy: newFakePolicy()}); err == nil {
		t.Fatal("authority without a persistent store accepted")
	}
}

func TestExecutionIDIsPersistedBeforeProposeReturns(t *testing.T) {
	store := newMemStore()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, newMemCounters())
	r := e.request(canonical.RiskMedium)
	p := e.propose(r)

	d, ok, err := store.LookupExecution(r.ExecutionID)
	if err != nil || !ok {
		t.Fatalf("execution ID not in the store after Propose: ok=%v err=%v", ok, err)
	}
	if d != p.Digest {
		t.Fatalf("stored digest %s, permit digest %s", d, p.Digest)
	}
	if got := store.expires[r.ExecutionID]; !got.Equal(time.Unix(r.ExpiryUnix, 0)) {
		t.Fatalf("stored expiry %v, want request expiry %v", got, time.Unix(r.ExpiryUnix, 0))
	}
}

// restart builds a fresh authority on the same stores: everything in memory
// is gone, everything persistent survives.
func restart(t *testing.T, store *memStore, counters *memCounters) *env {
	t.Helper()
	return newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
}

func TestSpentExecutionIDSurvivesRestart(t *testing.T) {
	store, counters := newMemStore(), newMemCounters()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	r := e.request(canonical.RiskMedium)
	e.propose(r)

	e2 := restart(t, store, counters)
	// Identical re-proposal: the permit died with the old process, so the
	// execution has ended and must not be revived.
	_, err := e2.auth.Propose(r, params)
	wantCode(t, err, CodeExecutionIDReused)

	// Same ID, different content: rejected as well.
	r2 := r
	r2.ResolvedTargets = r2.ResolvedTargets[:1]
	_, err = e2.auth.Propose(r2, params)
	wantCode(t, err, CodeExecutionIDReused)

	// A new execution ID works normally after the restart.
	e2.propose(e2.request(canonical.RiskMedium))
}

func TestRestartRevokesPendingAndApprovedPermits(t *testing.T) {
	store, counters := newMemStore(), newMemCounters()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	e.openSession()
	pending := e.propose(e.request(canonical.RiskMedium))
	approved := e.propose(e.request(canonical.RiskLow))
	if approved.State != StateApproved {
		t.Fatalf("LOW permit in session should be approved, got %v", approved.State)
	}

	e2 := restart(t, store, counters)
	if p, a := e2.auth.Counts(); p != 0 || a != 0 {
		t.Fatalf("after restart: %d pending, %d approved; want 0/0", p, a)
	}
	if active, _ := e2.auth.Session(); active {
		t.Fatal("privileged session survived a restart")
	}
	wantCode(t, e2.auth.Authorize(approved.Digest, goodRun("dockerflux", fpA)), CodeNotFound)
	_, err := e2.auth.ApproveCLI(pending.Digest, 2, "admin")
	wantCode(t, err, CodeNotFound)
}

func TestStoreFailureFailsClosed(t *testing.T) {
	store := newMemStore()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, newMemCounters())
	store.setFail(errors.New("disk full"))

	r := e.request(canonical.RiskMedium)
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeStorage)
	if p, a := e.auth.Counts(); p != 0 || a != 0 {
		t.Fatalf("permit created although the binding was not persisted: %d/%d", p, a)
	}

	// Once the store works again the same execution ID can be proposed:
	// nothing was bound, in memory or on disk.
	store.setFail(nil)
	e.propose(r)
}

func TestStoreErrorDetailIsNotExposed(t *testing.T) {
	store := newMemStore()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, newMemCounters())
	store.setFail(errors.New("open /var/lib/nebula/executor/executor.db: input/output error"))
	_, err := e.auth.Propose(e.request(canonical.RiskMedium), params)
	wantCode(t, err, CodeStorage)
	if got := err.Error(); got != string(CodeStorage)+": executor state store unavailable" {
		t.Fatalf("error leaks store details to the caller: %q", got)
	}
	// The detail goes to the audit log instead.
	found := false
	for _, ev := range e.evts {
		if ev.Code == CodeStorage && ev.Detail != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("storage failure not recorded in the audit trail")
	}
}

// A sign counter that cannot be stored is an executor fault: the approval
// fails closed with storage_error, the detail stays in the audit log, and it
// does not count towards the three failed approvals that discard a permit.
func TestCounterStoreFailureIsAStorageError(t *testing.T) {
	const detail = "write /var/lib/nebula/executor/executor.db: input/output error"
	counters := newMemCounters()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, newMemStore(), counters)
	e.cred.Counter = 5
	e.openSession()

	p := e.propose(e.request(canonical.RiskMedium))
	e.cred.Counter = 6
	assertion := e.sign(p.Challenge)
	counters.setSaveErr(errors.New(detail))
	for i := 0; i < MaxFailedAssertions+1; i++ {
		_, err := e.auth.SubmitAssertion(p.Digest, assertion, 0)
		wantCode(t, err, CodeStorage)
		if got := err.Error(); got != string(CodeStorage)+": executor state store unavailable" {
			t.Fatalf("error leaks store details to the caller: %q", got)
		}
	}
	if pending, _ := e.auth.Counts(); pending != 1 {
		t.Fatalf("store failures discarded the permit (%d pending)", pending)
	}

	// Once the store works again the same approval goes through.
	counters.setSaveErr(nil)
	got, err := e.auth.SubmitAssertion(p.Digest, assertion, 0)
	if err != nil {
		t.Fatalf("approval after store recovery: %v", err)
	}
	if got.State != StateApproved {
		t.Fatalf("state %v, want approved", got.State)
	}

	// Privileged session: same rule.
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	e.cred.Counter = 7
	counters.setSaveErr(errors.New(detail))
	_, err = e.auth.CompleteSession(e.sign(ch))
	wantCode(t, err, CodeStorage)
	if got := err.Error(); got != string(CodeStorage)+": executor state store unavailable" {
		t.Fatalf("session error leaks store details to the caller: %q", got)
	}

	storageEvents := 0
	e.evtMu.Lock()
	for _, ev := range e.evts {
		if ev.Code == CodeStorage && ev.Detail != "" {
			storageEvents++
		}
		if ev.Code == CodeAssertionRejected {
			t.Errorf("store failure audited as assertion_rejected: %+v", ev)
		}
	}
	e.evtMu.Unlock()
	if storageEvents != MaxFailedAssertions+2 {
		t.Fatalf("%d storage events in the audit trail, want %d", storageEvents, MaxFailedAssertions+2)
	}
}
