// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

const appToken = "tok-0815-not-for-logs"

var secretScript = []byte(`printf '{"len":%d}' "$(wc -c < "$NEBULA_SECRETS_DIR/token")"; echo "token is $(cat "$NEBULA_SECRETS_DIR/token")" >&2`)

func (h *harness) proposeSecretRun(host runHost, params []byte, risk pb.RiskClass) (*pb.ProposeExecutionResponse, error) {
	ph, err := canonical.HashParameters(params)
	if err != nil {
		h.t.Fatal(err)
	}
	req := &pb.ExecutionRequest{
		ExecutionId: fmt.Sprintf("00000000-0000-4000-8000-%012d", execCounter.Add(1)),
		ActionId:    "test.run", ModuleVersion: "1.0.0", ArtifactSha256: hexSum(secretScript), ParametersHash: ph,
		CredentialRefs: []string{credRef}, RiskClass: risk, StagePlanHash: stageplan.SingleStageHash,
		ExpiryUnix: time.Now().Add(time.Hour).Unix(), ResolvedTargets: []*pb.Target{{HostId: host.id, HostKeyFingerprint: host.fp}},
	}
	return h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: params, Artifact: secretScript})
}

// M7-3 (spec 06): a run's secrets come from the executor's vault, reach the
// host only as private files on a tmpfs, and never come back in output.
func TestM7_SecretsReachOnlyTheHost(t *testing.T) {
	rt, err := os.MkdirTemp("/dev/shm", "xdg")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	h := newHarness(t, harnessOptions{})
	h.unlock()
	if _, err := h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "app.token", Value: []byte(appToken)}); err != nil {
		t.Fatal(err)
	}
	host := h.pinnedRunHost("sechost")
	h.openSession()
	params := []byte(`{"nebula_secrets":{"token":"app.token"}}`)

	// Malformed mappings are refused at the proposal.
	for _, bad := range []string{`{"nebula_secrets":{"Token":"app.token"}}`, `{"nebula_secrets":{"token":"../x"}}`, `{"nebula_secrets":"app.token"}`, `{"nebula_secrets":{}}`} {
		if _, err := h.proposeSecretRun(host, []byte(bad), riskHigh); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	p, err := h.proposeSecretRun(host, params, riskHigh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
	run := &pb.RunAttachedRequest{Run: &pb.AuthorizeRunRequest{ExecutionDigest: p.GetExecutionDigest(), HostId: host.id, HostKeyFingerprint: host.fp,
		ActionId: "test.run", ModuleVersion: "1.0.0", Artifact: secretScript, ParametersJson: params, CredentialRef: credRef}, Endpoints: []string{host.endpoint}}
	r, err := h.client.RunAttached(h.ctx(), run)
	if err != nil {
		t.Fatal(err)
	}
	if r.GetClass() != "success" || string(r.GetResult()) != fmt.Sprintf(`{"len":%d}`, len(appToken)) {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(string(r.GetLog()), appToken) || !strings.Contains(string(r.GetLog()), "[secret token redacted]") {
		t.Fatalf("log %q", r.GetLog())
	}
	if strings.Contains(h.logs.String(), appToken) {
		t.Fatal("the executor logged the secret")
	}
	entries, _ := os.ReadDir(rt)
	if len(entries) != 0 {
		t.Fatalf("secrets left on the host: %v", entries)
	}

	// A durable run gets the same redaction when the executor collects its
	// result and log (review m73, finding 1), and leaves nothing behind.
	p3, err := h.proposeSecretRun(host, params, riskHigh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p3.GetExecutionDigest(), AssertionJson: h.sign(p3.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
	dr := durableReq(p3.GetExecutionDigest(), host, secretScript)
	dr.Run.ParametersJson = params
	ds, err := h.client.StartDurable(h.ctx(), dr)
	if err != nil {
		t.Fatal(err)
	}
	st := h.reconcileUntil(ds.GetRun().GetExecutionId(), host.id)
	if st.GetClass() != "success" || string(st.GetResult()) != fmt.Sprintf(`{"len":%d}`, len(appToken)) {
		t.Fatalf("durable: %+v", st)
	}
	if strings.Contains(string(st.GetLog()), appToken) || !strings.Contains(string(st.GetLog()), "[secret token redacted]") {
		t.Fatalf("durable log %q", st.GetLog())
	}
	if strings.Contains(h.logs.String(), appToken) {
		t.Fatal("the executor logged the secret (durable)")
	}

	// A secret the vault does not hold refuses the run before the host is
	// used.
	missing := []byte(`{"nebula_secrets":{"token":"no.such"}}`)
	p2, err := h.proposeSecretRun(host, missing, riskHigh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p2.GetExecutionDigest(), AssertionJson: h.sign(p2.GetChallenge())}); err != nil {
		t.Fatal(err)
	}
	run.Run.ExecutionDigest, run.Run.ParametersJson = p2.GetExecutionDigest(), missing
	n := len(host.srv.Commands())
	_, err = h.client.RunAttached(h.ctx(), run)
	wantCode(t, err, codes.FailedPrecondition, "secret_unavailable")
	if len(host.srv.Commands()) != n {
		t.Fatal("the host was contacted")
	}
}
