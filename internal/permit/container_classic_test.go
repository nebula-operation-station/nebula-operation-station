// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

var batchOnlyContainerActions = []string{"docker.update", "docker.rollback", "docker.compose_rollback"}

// Container mutations bind per-container plans and run only as batch
// members; the classic permit refuses them by action ID at every risk, on
// the plain, raising and staged proposal paths.
func TestContainerMutationRefusedOnClassicPath(t *testing.T) {
	for _, action := range batchOnlyContainerActions {
		for _, risk := range []canonical.Risk{canonical.RiskLow, canonical.RiskMedium, canonical.RiskHigh, canonical.RiskCritical} {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			e.openSession()
			r := e.request(risk)
			r.ActionID = action
			_, err := e.auth.Propose(r, params)
			wantCode(t, err, CodeActionMismatch)
			_, err = e.auth.ProposeAtLeastMinimum(r, params)
			wantCode(t, err, CodeActionMismatch)
			_, err = e.auth.ProposeStaged(r, params, []byte(`{}`), true)
			wantCode(t, err, CodeActionMismatch)
		}
	}
}

// docker.compose_update 1.0.0 stays a classic action until cu02 replaces it.
func TestComposeUpdateV1StaysOnClassicPath(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	r := e.request(canonical.RiskMedium)
	r.ActionID = "docker.compose_update"
	if _, err := e.auth.Propose(r, params); err != nil {
		t.Fatalf("classic docker.compose_update refused: %v", err)
	}
}

// No schedule or read grant may cover a container mutation, whatever risk
// its module declares.
func TestContainerMutationCannotBeGranted(t *testing.T) {
	for _, action := range batchOnlyContainerActions {
		e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
		e.withSchedules(t, ModeStandard)
		e.openSession()
		// The fake risk policy rates every action LOW: only the action
		// rule refuses.
		if _, err := e.auth.ProposeScheduleGrant(e.grantDoc("00000000-0000-4000-8000-0000000000ab")); err != nil {
			t.Fatalf("baseline grant refused: %v", err)
		}
		var doc schedgrant.Doc
		if err := json.Unmarshal(e.grantDoc(grantID), &doc); err != nil {
			t.Fatal(err)
		}
		doc.Actions[0].ActionID = action
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.auth.ProposeScheduleGrant(raw)
		wantCode(t, err, CodeGrantInvalid)
	}
}
