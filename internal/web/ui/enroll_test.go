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

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

type fakeEnroll struct {
	proposed  *pb.ProposeEnrollRequest
	committed *pb.CommitEnrollRequest
	submitted *pb.SubmitAssertionRequest
	commitErr error
}

func (f *fakeEnroll) ProposeEnroll(_ context.Context, in *pb.ProposeEnrollRequest, _ ...grpc.CallOption) (*pb.ProposeEnrollResponse, error) {
	f.proposed = in
	out := &pb.ProposeEnrollResponse{Permit: &pb.ProposeExecutionResponse{ExecutionDigest: strings.Repeat("b", 64),
		RiskClass: pb.RiskClass_RISK_CLASS_HIGH, ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		RequestOptionsJson: []byte(`{"publicKey":{"challenge":"abc"}}`)}}
	for _, h := range in.GetHosts() {
		out.Hosts = append(out.Hosts, &pb.EnrollHost{HostId: h.GetHostId(), Endpoint: h.GetEndpoint(), SshUser: "nebula",
			CredentialRef: "nebula-default", Fingerprint: "SHA256:<fp>", KeyType: "ssh-ed25519"})
	}
	return out, nil
}

func (f *fakeEnroll) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	f.submitted = in
	return &pb.SubmitAssertionResponse{}, nil
}

func (f *fakeEnroll) CommitEnroll(_ context.Context, in *pb.CommitEnrollRequest, _ ...grpc.CallOption) (*pb.CommitEnrollResponse, error) {
	f.committed = in
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitEnrollResponse{Results: []*pb.EnrollResult{{HostId: "new", Pinned: true, Fingerprint: "SHA256:x", LoginOk: true}}}, nil
}

type enrollInventory struct{ hosts []inventory.Host }

func (e enrollInventory) Create(context.Context, inventory.Host, inventory.CreateOptions) (inventory.Host, error) {
	return inventory.Host{}, nil
}
func (e enrollInventory) Get(_ context.Context, id string) (inventory.Host, error) {
	for _, h := range e.hosts {
		if h.ID == id {
			return h, nil
		}
	}
	return inventory.Host{}, inventory.ErrHostNotFound
}
func (e enrollInventory) Update(context.Context, inventory.Host) (inventory.Host, error) {
	return inventory.Host{}, nil
}
func (e enrollInventory) Delete(context.Context, string) error { return nil }

func enrollHandler(t *testing.T, f ui.Enroller) http.Handler {
	t.Helper()
	inv := enrollInventory{hosts: []inventory.Host{
		{ID: "new", DisplayName: "<i>New</i>", Endpoints: []inventory.Endpoint{{Address: "10.0.0.9"}, {Address: "fd00::9", Port: 2222}}},
		{ID: "web", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}}},
	}}
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Enroll: f, Inventory: inv,
		Hosts: func(context.Context) ([]inventory.Host, error) { return inv.hosts, nil },
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:web"}}, nil
		}}).Handler()
}

func TestEnrollPageListsUnpinnedHosts(t *testing.T) {
	h := enrollHandler(t, &fakeEnroll{})
	page := getBody(t, h, "/inventory/enroll")
	if !strings.Contains(page, `data-host="new"`) || strings.Contains(page, `data-host="web"`) ||
		!strings.Contains(page, "&lt;i&gt;New&lt;/i&gt;") || !strings.Contains(page, "[fd00::9]:2222") || !strings.Contains(page, "10.0.0.9:22") {
		t.Fatal(page)
	}
	if !strings.Contains(getBody(t, h, "/inventory"), `href="/inventory/enroll"`) {
		t.Fatal("inventory does not link the enrollment")
	}
}

func TestEnrollFlow(t *testing.T) {
	f := &fakeEnroll{}
	h := enrollHandler(t, f)
	code, body := postJSON(t, h, "/inventory/enroll/propose", `{"hosts":[{"host":"new","endpoint":"[fd00::9]:2222","ssh_user":"nebula","credential":""}]}`)
	var p map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || p["digest"] == nil || p["risk"] != "HIGH" || p["options"] == nil ||
		f.proposed.GetHosts()[0].GetEndpoint() != "[fd00::9]:2222" {
		t.Fatalf("%d %s", code, body)
	}
	code, body = postJSON(t, h, "/inventory/enroll/commit", `{"digest":"`+strings.Repeat("b", 64)+`","hosts":[{"host":"new","endpoint":"[fd00::9]:2222","ssh_user":"nebula","credential":"nebula-default","fingerprint":"SHA256:x"}],"assertion":{"id":"k"}}`)
	if code != 200 || !strings.Contains(body, `"pinned":true`) || f.submitted == nil || f.committed.GetHosts()[0].GetFingerprint() != "SHA256:x" {
		t.Fatalf("%d %s", code, body)
	}
}

func TestEnrollRefusesWhatIsNotInTheInventory(t *testing.T) {
	for name, tc := range map[string]struct {
		body, want string
	}{
		"unknown host":     {`{"hosts":[{"host":"ghost","endpoint":"10.0.0.1:22"}]}`, "not in the inventory"},
		"foreign endpoint": {`{"hosts":[{"host":"new","endpoint":"192.0.2.1:22"}]}`, "not one of its endpoints"},
		"empty":            {`{"hosts":[]}`, "1 to 50"},
		"bad id":           {`{"hosts":[{"host":"-x","endpoint":"10.0.0.9:22"}]}`, "invalid host"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeEnroll{}
			code, body := postJSON(t, enrollHandler(t, f), "/inventory/enroll/propose", tc.body)
			if code != http.StatusBadRequest || !strings.Contains(body, tc.want) || f.proposed != nil {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
	f := &fakeEnroll{commitErr: status.Error(codes.PermissionDenied, "parameters_mismatch: parameters do not hash")}
	code, body := postJSON(t, enrollHandler(t, f), "/inventory/enroll/commit", `{"digest":"`+strings.Repeat("b", 64)+`","hosts":[{"host":"new","endpoint":"10.0.0.9:22","fingerprint":"SHA256:x"}]}`)
	if code != http.StatusConflict || !strings.Contains(body, "parameters_mismatch") {
		t.Fatalf("%d %s", code, body)
	}
}
