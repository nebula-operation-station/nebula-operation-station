// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

type fakeRepin struct {
	proposeErr, submitErr, commitErr error
	requirement                      pb.ApprovalRequirement
	submitted                        *pb.SubmitAssertionRequest
	committed                        *pb.CommitRepinRequest
}

func (f *fakeRepin) ProposeRepin(_ context.Context, in *pb.ProposeRepinRequest, _ ...grpc.CallOption) (*pb.ProposeRepinResponse, error) {
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	return &pb.ProposeRepinResponse{
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: strings.Repeat("a", 64), RiskClass: pb.RiskClass_RISK_CLASS_HIGH,
			ApprovalRequirement: f.requirement, RequestOptionsJson: []byte(`{"publicKey":{"challenge":"abc"}}`)},
		Pin: &pb.HostKeyPin{HostId: in.GetHostId(), Fingerprint: "SHA256:old", Blocked: true, BlockedFingerprint: "SHA256:<new>",
			BlockedEndpoint: "10.0.0.5:22", BlockedAtUnix: 1791960000},
	}, nil
}

func (f *fakeRepin) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	f.submitted = in
	return &pb.SubmitAssertionResponse{}, f.submitErr
}

func (f *fakeRepin) CommitRepin(_ context.Context, in *pb.CommitRepinRequest, _ ...grpc.CallOption) (*pb.CommitRepinResponse, error) {
	f.committed = in
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitRepinResponse{Pin: &pb.HostKeyPin{HostId: in.GetHostId(), Fingerprint: "SHA256:new"}}, nil
}

func repinHandler(t *testing.T, f ui.Repinner) http.Handler {
	t.Helper()
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Repin: f,
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:old", Blocked: true, BlockedFingerprint: "SHA256:new", BlockedEndpoint: "10.0.0.5:22"}}, nil
		}}).Handler()
}

func TestRepinFlow(t *testing.T) {
	f := &fakeRepin{requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED}
	h := repinHandler(t, f)
	page := getBody(t, h, "/dashboard")
	if !strings.Contains(page, `class="button repin-start" data-host="web"`) || !strings.Contains(page, "/static/repin.js") {
		t.Fatal("dashboard has no re-pin control")
	}
	code, body := postJSON(t, h, "/hostkeys/repin/propose", `{"host":"web"}`)
	var p map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || p["presented"] != "SHA256:<new>" || p["risk"] != "HIGH" ||
		p["requirement"] != "key" || p["options"] == nil {
		t.Fatalf("%d %s", code, body)
	}
	code, body = postJSON(t, h, "/hostkeys/repin/commit", `{"host":"web","digest":"`+strings.Repeat("a", 64)+`","assertion":{"id":"x"},"typed_count":0}`)
	if code != 200 || !strings.Contains(body, "SHA256:new") || f.submitted == nil || f.committed.GetHostId() != "web" {
		t.Fatalf("%d %s", code, body)
	}
	// Approved with `nebula approve`: commit without an assertion.
	f.submitted = nil
	if code, _ := postJSON(t, h, "/hostkeys/repin/commit", `{"host":"web","digest":"`+strings.Repeat("a", 64)+`"}`); code != 200 || f.submitted != nil {
		t.Fatalf("cli commit %d", code)
	}
}

func TestRepinErrorsAreSafe(t *testing.T) {
	for name, tc := range map[string]struct {
		f          *fakeRepin
		path, body string
		code       int
		want, not  string
	}{
		"not blocked": {f: &fakeRepin{proposeErr: status.Error(codes.FailedPrecondition, "host_not_blocked: the host is not blocked")},
			path: "/hostkeys/repin/propose", body: `{"host":"web"}`, code: http.StatusConflict, want: "host_not_blocked"},
		"executor down": {f: &fakeRepin{proposeErr: status.Error(codes.Unavailable, "dial unix /run/nebula/executor.sock")},
			path: "/hostkeys/repin/propose", body: `{"host":"web"}`, code: http.StatusBadGateway, want: "executor unavailable", not: "executor.sock"},
		"bad host":   {f: &fakeRepin{}, path: "/hostkeys/repin/propose", body: `{"host":"-x;y"}`, code: http.StatusBadRequest, want: "invalid host"},
		"bad digest": {f: &fakeRepin{}, path: "/hostkeys/repin/commit", body: `{"host":"web","digest":"zz"}`, code: http.StatusBadRequest, want: "invalid digest"},
		"bad key": {f: &fakeRepin{submitErr: status.Error(codes.PermissionDenied, "assertion_invalid: signature")},
			path: "/hostkeys/repin/commit", body: `{"host":"web","digest":"` + strings.Repeat("a", 64) + `","assertion":{}}`,
			code: http.StatusForbidden, want: "security key not accepted", not: "signature"},
		"key changed": {f: &fakeRepin{commitErr: status.Error(codes.FailedPrecondition, "repin_key_changed: the endpoint now presents SHA256:z")},
			path: "/hostkeys/repin/commit", body: `{"host":"web","digest":"` + strings.Repeat("a", 64) + `"}`, code: http.StatusConflict, want: "repin_key_changed"},
		"probe failed": {f: &fakeRepin{commitErr: status.Error(codes.Unavailable, "repin_probe_failed: nothing changed")},
			path: "/hostkeys/repin/commit", body: `{"host":"web","digest":"` + strings.Repeat("a", 64) + `"}`, code: http.StatusConflict, want: "nothing changed"},
	} {
		t.Run(name, func(t *testing.T) {
			code, body := postJSON(t, repinHandler(t, tc.f), tc.path, tc.body)
			if code != tc.code || !strings.Contains(body, tc.want) || (tc.not != "" && strings.Contains(body, tc.not)) {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
}

func TestRepinDisabledWithoutExecutorSupport(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org",
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Blocked: true}}, nil
		}}).Handler()
	if strings.Contains(getBody(t, h, "/dashboard"), "repin-start") {
		t.Fatal("re-pin control without Repin")
	}
	if code, _ := postJSON(t, h, "/hostkeys/repin/propose", `{"host":"web"}`); code != http.StatusNotFound {
		t.Fatalf("%d", code)
	}
}
