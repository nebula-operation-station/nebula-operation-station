// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify

import (
	"errors"
	"sync"
	"testing"

	"github.com/descope/virtualwebauthn"
)

// memCounters is an in-memory CounterStore for tests; internal/executordb
// provides the durable implementation.
type memCounters struct {
	mu      sync.Mutex
	c       map[string]uint32
	saves   int
	failErr error
	loadErr error
}

func newMemCounters() *memCounters { return &memCounters{c: map[string]uint32{}} }

func (m *memCounters) LoadCounters() (map[string]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	out := make(map[string]uint32, len(m.c))
	for k, v := range m.c {
		out[k] = v
	}
	return out, nil
}

func (m *memCounters) SaveCounter(id []byte, n uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	m.saves++
	if n > m.c[string(id)] {
		m.c[string(id)] = n
	}
	return nil
}

func (m *memCounters) get(id []byte) uint32 { m.mu.Lock(); defer m.mu.Unlock(); return m.c[string(id)] }

func TestNewRequiresCounterStore(t *testing.T) {
	if _, err := New(Config{RPID: rpID, Origins: []string{origin}}, nil); err == nil {
		t.Fatal("verifier without a counter store accepted")
	}
}

func TestNewFailsWhenCountersCannotBeLoaded(t *testing.T) {
	m := newMemCounters()
	m.loadErr = errors.New("database is locked")
	if _, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: m}, nil); err == nil {
		t.Fatal("verifier started without its stored counters")
	}
}

func TestCounterPersistedOnSuccess(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	f.cred.Counter = 5
	c := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c), c, Requirement{}); err != nil {
		t.Fatal(err)
	}
	if got := m.get(f.cred.ID); got != 5 {
		t.Fatalf("stored counter %d, want 5", got)
	}
}

func TestCounterNotPersistedOnFailure(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	f.cred.Counter = 5
	other := f.rp
	other.Origin = "https://evil.example.org"
	c := challenge(t)
	if _, err := f.v.Verify(f.sign(other, c), c, Requirement{}); err == nil {
		t.Fatal("assertion from a foreign origin accepted")
	}
	if m.saves != 0 {
		t.Fatalf("counter stored for a rejected assertion (%d saves)", m.saves)
	}
}

func TestZeroCounterNeedsNoWrite(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	c := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c), c, Requirement{}); err != nil {
		t.Fatal(err)
	}
	if m.saves != 0 {
		t.Fatalf("counter 0 written to the store (%d saves)", m.saves)
	}
}

func TestStoredCounterSurvivesRestart(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	f.cred.Counter = 5
	c1 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c1), c1, Requirement{}); err != nil {
		t.Fatal(err)
	}

	// Restart: a new verifier, the credential file still says 0.
	v2, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: m},
		[]Credential{{ID: f.cred.ID, PublicKey: f.cred.Key.AttestationData(), SignCount: 0}})
	if err != nil {
		t.Fatal(err)
	}
	c2 := challenge(t)
	if _, err := v2.Verify(f.sign(f.rp, c2), c2, Requirement{}); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("counter 5 accepted again after restart: %v", err)
	}
	f.cred.Counter = 6
	c3 := challenge(t)
	if _, err := v2.Verify(f.sign(f.rp, c3), c3, Requirement{}); err != nil {
		t.Fatalf("increased counter rejected after restart: %v", err)
	}
}

func TestHigherOfFileAndStoredCounterWins(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	// The store knows 2, the credential file records 7: the higher wins.
	m.mu.Lock()
	m.c[string(f.cred.ID)] = 2
	m.mu.Unlock()
	v := newFixtureWithCred(t, m, f, 7)
	f.cred.Counter = 6
	c := challenge(t)
	if _, err := v.Verify(f.sign(f.rp, c), c, Requirement{}); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("counter 6 accepted although the credential file records 7: %v", err)
	}
}

// newFixtureWithCred builds a second verifier for f's credential with the
// given file counter on store m.
func newFixtureWithCred(t *testing.T, m *memCounters, f *fixture, fileCount uint32) *Verifier {
	t.Helper()
	v, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: m},
		[]Credential{{ID: f.cred.ID, PublicKey: f.cred.Key.AttestationData(), SignCount: fileCount}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCounterSaveFailureRejectsAssertion(t *testing.T) {
	m := newMemCounters()
	f := newFixtureWith(t, virtualwebauthn.AuthenticatorOptions{}, m, 0)
	f.cred.Counter = 5
	m.failErr = errors.New("disk full")
	c1 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c1), c1, Requirement{}); !errors.Is(err, ErrCounterStore) {
		t.Fatalf("assertion accepted although its counter could not be stored: %v", err)
	}
	// The in-memory counter did not advance either: once the store works,
	// the same counter value is accepted (it was never consumed).
	m.failErr = nil
	c2 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c2), c2, Requirement{}); err != nil {
		t.Fatalf("counter consumed by a failed verification: %v", err)
	}
	if got := m.get(f.cred.ID); got != 5 {
		t.Fatalf("stored counter %d, want 5", got)
	}
}
