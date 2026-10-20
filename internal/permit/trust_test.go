// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// M7-4: trusting an artifact from the browser needs the session and a
// user-verified assertion over a challenge bound to exactly what is
// trusted; each request is single use.
func TestBrowserTrust(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	_, err := e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "x")
	wantCode(t, err, CodeSessionRequired)
	e.openSession()
	for _, bad := range []struct{ action, version string }{{"Runbook", "1.0.0"}, {"runbook.hello", "1.0"}} {
		_, err := e.auth.BeginTrust(artifact, bad.action, bad.version, canonical.RiskLow, "")
		wantCode(t, err, CodeInvalidRequest)
	}
	_, err = e.auth.BeginTrust(nil, "runbook.hello", "1.0.0", canonical.RiskLow, "")
	wantCode(t, err, CodeArtifactMismatch)

	tr, err := e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "runbook hello v1")
	if err != nil || tr.SHA256 != hexSum(artifact) || len(tr.Challenge) != 32 {
		t.Fatalf("%+v %v", tr, err)
	}
	// Another request has another challenge: an assertion for one cannot
	// commit the other.
	other, _ := e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskMedium, "")
	_, _, err = e.auth.CommitTrust(other.ID, e.sign(tr.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	_, _, err = e.auth.CommitTrust(other.ID, e.sign(other.Challenge))
	wantCode(t, err, CodeNotFound) // consumed by the failed attempt

	// Without user verification it is refused.
	e.dev.Options.UserNotVerified = true
	_, _, err = e.auth.CommitTrust(tr.ID, e.sign(tr.Challenge))
	wantCode(t, err, CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false

	tr, _ = e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "runbook hello v1")
	got, by, err := e.auth.CommitTrust(tr.ID, e.sign(tr.Challenge))
	if err != nil || got.ActionID != "runbook.hello" || got.Risk != canonical.RiskLow || got.Label != "runbook hello v1" || by[:9] != "webauthn:" {
		t.Fatalf("%+v %s %v", got, by, err)
	}
	_, _, err = e.auth.CommitTrust(tr.ID, e.sign(tr.Challenge))
	wantCode(t, err, CodeNotFound)

	// Requests expire and go with Lock.
	tr, _ = e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "")
	e.clk.Add(ApprovalWindow)
	_, _, err = e.auth.CommitTrust(tr.ID, e.sign(tr.Challenge))
	wantCode(t, err, CodeNotFound)
	e.openSession()
	tr, _ = e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "")
	e.auth.Lock("test")
	_, _, err = e.auth.CommitTrust(tr.ID, e.sign(tr.Challenge))
	wantCode(t, err, CodeNotFound)
}

func TestBrowserTrustIsCLIOnlyInHardenedMode(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	_, err := e.auth.BeginTrust(artifact, "runbook.hello", "1.0.0", canonical.RiskLow, "")
	wantCode(t, err, CodeCLIRequired)
}
