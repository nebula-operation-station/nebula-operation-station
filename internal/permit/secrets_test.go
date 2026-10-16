// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Decision 4 of the M7 plan: a run that uses vault secrets is at least
// MEDIUM, so a session click alone never approves it.
func TestSecretsRaiseTheFloorToMedium(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	withSecret := []byte(`{"nebula_secrets":{"token":"app.token"}}`)
	r := e.request(canonical.RiskLow)
	r.ParametersHash, _ = canonical.HashParameters(withSecret)
	_, err := e.auth.Propose(r, withSecret)
	wantCode(t, err, CodeInvalidRequest)
	r2 := e.request(canonical.RiskLow)
	r2.ParametersHash = r.ParametersHash
	res, err := e.auth.ProposeAtLeastMinimum(r2, withSecret)
	if err != nil || res.Permit.Request.RiskClass != canonical.RiskMedium || res.Permit.State != StatePending {
		t.Fatalf("%v %v", res.Permit.Request.RiskClass, err)
	}
	for _, bad := range []string{`{"nebula_secrets":{"Token":"a"}}`, `{"nebula_secrets":[]}`, `{"nebula_secrets":{"a":"../b"}}`} {
		r := e.request(canonical.RiskHigh)
		r.ParametersHash, _ = canonical.HashParameters([]byte(bad))
		_, err := e.auth.Propose(r, []byte(bad))
		wantCode(t, err, CodeInvalidRequest)
	}
	if refs, err := SecretRefs([]byte(`{"a":"b"}`)); err != nil || refs != nil {
		t.Fatal(refs, err)
	}
	if f, ok := secretFloor([]byte(" ")); ok || f != "" {
		t.Fatal("empty parameters use secrets")
	}
}
