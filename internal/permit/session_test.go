// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

func TestSessionLengthDefaultAndRange(t *testing.T) {
	for _, tc := range []struct {
		length time.Duration
		want   time.Duration
	}{
		{0, 60 * time.Minute},
		{15 * time.Minute, 15 * time.Minute},
		{90 * time.Minute, 90 * time.Minute},
		{240 * time.Minute, 240 * time.Minute},
		{-time.Nanosecond, 0},
		{15*time.Minute - time.Nanosecond, 0},
		{240*time.Minute + time.Nanosecond, 0},
		{time.Duration(1<<63 - 1), 0},
	} {
		t.Run(tc.length.String(), func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			a, err := New(Options{Verifier: e.auth.verifier, Store: newMemStore(), RiskPolicy: e.risk, Now: e.clk.Now, SessionLength: tc.length})
			if tc.want == 0 {
				if err == nil {
					t.Fatal("invalid session length accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e.auth = a
			e.openSession()
			active, until := a.Session()
			if !active || !until.Equal(e.clk.Now().Add(tc.want)) {
				t.Fatalf("session = %v, %v; want duration %v", active, until, tc.want)
			}
			e.clk.Add(tc.want)
			if active, _ := a.Session(); active {
				t.Fatal("session active at expiry")
			}
		})
	}
}

func TestOneUVExtendsOrReopensWithoutAccumulatingTime(t *testing.T) {
	for _, mode := range []Mode{ModeStandard, ModeHardened} {
		for _, elapsed := range []time.Duration{10 * time.Minute, DefaultSessionLength - time.Second, DefaultSessionLength, 2 * DefaultSessionLength} {
			t.Run(fmt.Sprintf("mode%d/elapsed%s", mode, elapsed), func(t *testing.T) {
				e := newEnv(t, mode, virtualwebauthn.AuthenticatorOptions{})
				e.openSession()
				e.clk.Add(elapsed)
				ch, _, err := e.auth.BeginSession()
				if err != nil {
					t.Fatal(err)
				}
				e.clk.Add(time.Second)
				assertion := e.sign(ch)
				until, err := e.auth.CompleteSession(assertion)
				if err != nil {
					t.Fatal(err)
				}
				if want := e.clk.Now().Add(DefaultSessionLength); !until.Equal(want) {
					t.Fatalf("expiry = %v, want approval time + duration = %v", until, want)
				}
				_, err = e.auth.CompleteSession(assertion)
				wantCode(t, err, CodeNoChallenge)
			})
		}
	}
}

func TestSessionChallengeReplacementAndApprovalIsolation(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	first, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 32 || bytes.Equal(first, second) {
		t.Fatal("session challenges must be fresh 32-byte values")
	}
	_, err = e.auth.CompleteSession(e.sign(first))
	wantCode(t, err, CodeAssertionRejected)
	_, err = e.auth.CompleteSession(e.sign(second))
	wantCode(t, err, CodeNoChallenge)

	e.openSession()
	p := e.propose(e.request(canonical.RiskHigh))
	_, _, err = e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.CompleteSession(e.sign(p.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.SubmitAssertion(p.Digest, e.sign(ch), 0)
	wantCode(t, err, CodeAssertionRejected)
}

func TestFailedSessionExtensionLeavesExistingExpiry(t *testing.T) {
	for _, failure := range []string{"no-uv", "malformed", "expired", "storage"} {
		t.Run(failure, func(t *testing.T) {
			counters := newMemCounters()
			e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, newMemStore(), counters)
			e.openSession()
			_, before := e.auth.Session()
			ch, _, err := e.auth.BeginSession()
			if err != nil {
				t.Fatal(err)
			}
			want := CodeAssertionRejected
			switch failure {
			case "no-uv":
				e.dev.Options.UserNotVerified = true
			case "expired":
				e.clk.Add(SessionChallengeTTL)
				want = CodeExpired
			case "storage":
				e.cred.Counter = 1
				counters.setSaveErr(errors.New("counter unavailable"))
				want = CodeStorage
			}
			assertion := e.sign(ch)
			if failure == "malformed" {
				assertion = []byte(`{}`)
			}
			_, err = e.auth.CompleteSession(assertion)
			wantCode(t, err, want)
			if active, after := e.auth.Session(); !active || !before.Equal(after) {
				t.Fatalf("failed extension changed session: %v, %v", active, after)
			}
			_, err = e.auth.CompleteSession(assertion)
			wantCode(t, err, CodeNoChallenge)
		})
	}
}

func TestSessionActivityDoesNotExtendAndLockRevokes(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	_, before := e.auth.Session()
	p := e.propose(e.request(canonical.RiskHigh))
	e.clk.Add(time.Minute)
	if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0); err != nil {
		t.Fatal(err)
	}
	if _, after := e.auth.Session(); !after.Equal(before) {
		t.Fatal("mutation approval extended session")
	}
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, after := e.auth.Session(); !after.Equal(before) {
		t.Fatal("beginning extension extended session")
	}
	e.auth.Lock("test")
	_, err = e.auth.CompleteSession(e.sign(ch))
	wantCode(t, err, CodeNoChallenge)
	e.openSession()
	if _, ok := e.auth.PermitState(p.Digest); ok {
		t.Fatal("reopening session resurrected revoked permit")
	}
}

// sessionCounters pauses successful verification at its durable counter update.
// Channels make clock/lock races deterministic without sleeps or network access.
type sessionCounters struct {
	*memCounters
	entered chan struct{}
	release chan struct{}
}

func (s *sessionCounters) SaveCounter(id []byte, n uint32) error {
	close(s.entered)
	<-s.release
	return s.memCounters.SaveCounter(id, n)
}

func sessionWithPausedVerification(t *testing.T) (*env, *sessionCounters, []byte) {
	t.Helper()
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	counters := &sessionCounters{memCounters: newMemCounters(), entered: make(chan struct{}), release: make(chan struct{})}
	v, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: counters}, []webauthnverify.Credential{{ID: e.cred.ID, PublicKey: e.cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	e.auth.verifier = v
	e.cred.Counter = 1
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	return e, counters, e.sign(ch)
}

func TestSessionExpiryDuringVerificationFailsClosed(t *testing.T) {
	e, counters, assertion := sessionWithPausedVerification(t)
	done := make(chan error, 1)
	go func() { _, err := e.auth.CompleteSession(assertion); done <- err }()
	<-counters.entered
	e.clk.Add(SessionChallengeTTL)
	close(counters.release)
	wantCode(t, <-done, CodeExpired)
	if active, _ := e.auth.Session(); active {
		t.Fatal("expired challenge opened session")
	}
	_, err := e.auth.CompleteSession(assertion)
	wantCode(t, err, CodeNoChallenge)
}

func TestSessionDurationStartsAfterVerification(t *testing.T) {
	e, counters, assertion := sessionWithPausedVerification(t)
	type result struct {
		until time.Time
		err   error
	}
	done := make(chan result, 1)
	go func() { until, err := e.auth.CompleteSession(assertion); done <- result{until, err} }()
	<-counters.entered
	e.clk.Add(time.Minute)
	close(counters.release)
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if want := e.clk.Now().Add(DefaultSessionLength); !got.until.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got.until, want)
	}
}

func TestSessionLockDuringVerificationEndsSession(t *testing.T) {
	e, counters, assertion := sessionWithPausedVerification(t)
	approved := make(chan error, 1)
	go func() { _, err := e.auth.CompleteSession(assertion); approved <- err }()
	<-counters.entered
	locked := make(chan struct{})
	go func() { e.auth.Lock("test"); close(locked) }()
	close(counters.release)
	if err := <-approved; err != nil {
		t.Fatal(err)
	}
	<-locked
	if active, until := e.auth.Session(); active || !until.IsZero() {
		t.Fatalf("session survived lock: %v, %v", active, until)
	}
	_, err := e.auth.CompleteSession(assertion)
	wantCode(t, err, CodeNoChallenge)
}

func TestConcurrentSessionCompletionConsumesOneAssertion(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	ch, _, err := e.auth.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	assertion := e.sign(ch)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := e.auth.CompleteSession(assertion); results <- err })
	}
	wg.Wait()
	close(results)
	var successes, consumed int
	for err := range results {
		if err == nil {
			successes++
		} else if CodeOf(err) == CodeNoChallenge {
			consumed++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("successes=%d consumed=%d", successes, consumed)
	}
}

func TestSessionAuditIncludesPolicyAndDenials(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	e.openSession()
	_, err := e.auth.CompleteSession([]byte(`{}`))
	wantCode(t, err, CodeNoChallenge)
	var opened, extended, denied bool
	for _, ev := range e.evts {
		switch ev.Kind {
		case "session_opened", "session_extended":
			if !strings.Contains(ev.Detail, "duration=1h0m0s") || !strings.Contains(ev.Detail, "expiry="+e.clk.Now().Add(DefaultSessionLength).Format(time.RFC3339Nano)) {
				t.Fatalf("session audit lacks policy: %+v", ev)
			}
			opened = opened || ev.Kind == "session_opened"
			extended = extended || ev.Kind == "session_extended"
		case "rejected":
			denied = denied || ev.Code == CodeNoChallenge
		}
	}
	if !opened || !extended || !denied {
		t.Fatalf("audit opened=%v extended=%v denied=%v", opened, extended, denied)
	}
}

func TestSessionChallengeBindsOperationDurationDeadlineAndNonce(t *testing.T) {
	nonce := [32]byte{1}
	expiry := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	base := sessionChallenge(nonce, DefaultSessionLength, expiry)
	otherNonce := nonce
	otherNonce[0]++
	for _, other := range [][]byte{
		sessionChallenge(otherNonce, DefaultSessionLength, expiry),
		sessionChallenge(nonce, 15*time.Minute, expiry),
		sessionChallenge(nonce, DefaultSessionLength, expiry.Add(time.Nanosecond)),
	} {
		if bytes.Equal(base, other) {
			t.Fatal("session challenge did not bind all policy inputs")
		}
	}
	// An execution challenge with identical nonce/deadline inputs has its
	// own preimage, so signing it cannot extend a session.
	preimage := append([]byte(nil), nonce[:]...)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(DefaultSessionLength))
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(expiry.UnixNano()))
	otherOperation := sha256.Sum256(append([]byte("nebula-execution-v1\x00"), preimage...))
	if bytes.Equal(base, otherOperation[:]) {
		t.Fatal("session challenge lacks operation separation")
	}
}
