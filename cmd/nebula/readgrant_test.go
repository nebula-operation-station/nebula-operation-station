// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeReadGrants struct {
	pb.ExecutorServiceClient
	pending    []*pb.PendingReadGrant
	approved   []string
	approveErr error
	listCalls  int
}

func (f *fakeReadGrants) ListPendingReadGrants(context.Context, *pb.ListPendingReadGrantsRequest, ...grpc.CallOption) (*pb.ListPendingReadGrantsResponse, error) {
	f.listCalls++
	return &pb.ListPendingReadGrantsResponse{Grants: f.pending}, nil
}

func (f *fakeReadGrants) ApproveReadGrantCLI(_ context.Context, in *pb.ApproveReadGrantCLIRequest, _ ...grpc.CallOption) (*pb.ApproveReadGrantCLIResponse, error) {
	if f.approveErr != nil {
		return nil, f.approveErr
	}
	f.approved = append(f.approved, in.GetGrantDigest())
	return &pb.ApproveReadGrantCLIResponse{Grant: &pb.ReadGrant{GrantId: "11111111-2222-4333-8444-555555555555", ExpiryUnix: 1900000000}}, nil
}

const (
	testRGDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testRGExpiry = int64(1900000000)
)

// testReadGrantDoc builds a read-grant-v2 document with n hosts (each with
// its own credential version) and two actions.
func testReadGrantDoc(t *testing.T, n int) []byte {
	t.Helper()
	doc := permit.ReadGrantDoc{
		Grant: "read-grant-v2", ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Issuer: "alice",
		CreatedUnix: 1800000000, ExpiryUnix: testRGExpiry, Trigger: "scheduled",
		Actions: []permit.ReadGrantAction{
			{ActionID: "core.disk_usage", ModuleVersion: "1.2.3", ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)},
			{ActionID: "core.uptime", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("c", 64), ParametersHash: strings.Repeat("d", 64)},
		},
		MinIntervalS: 900, RunBudget: 96, RateProfile: "ordinary",
	}
	for i := range n {
		host := fmt.Sprintf("host-%03d", i)
		doc.Targets = append(doc.Targets, canonical.Target{HostID: host, HostKeyFingerprint: fmt.Sprintf("SHA256:hostkey%03d", i)})
		doc.Credentials = append(doc.Credentials, permit.ReadGrantCredential{HostID: host, CredentialRef: "default", CredentialVersion: fmt.Sprintf("SHA256:credver%03d", i)})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadGrantPendingListsEveryGrant(t *testing.T) {
	f := &fakeReadGrants{pending: []*pb.PendingReadGrant{
		{GrantDigest: testRGDigest, CanonicalGrant: testReadGrantDoc(t, 3), ApprovalExpiryUnix: 1800000300},
		{GrantDigest: strings.Repeat("f", 64), CanonicalGrant: []byte("{\"grant\":\"x\x1b[2J\""), ApprovalExpiryUnix: 1800000300},
	}}
	var out bytes.Buffer
	if err := readGrantCmd(context.Background(), f, []string{"pending"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		testRGDigest, "ordinary/scheduled", "3 hosts", "2 actions",
		"expires " + time.Unix(testRGExpiry, 0).Format(time.RFC3339),
		strings.Repeat("f", 64) + "  unreadable grant document",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pending output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("control character in output: %q", got)
	}

	out.Reset()
	if err := readGrantCmd(context.Background(), &fakeReadGrants{}, []string{"pending"}, nil, &out); err != nil || !strings.Contains(out.String(), "no pending read grants") {
		t.Fatalf("empty list: %v %q", err, out.String())
	}
}

func TestReadGrantApproveShowsEveryHostBeforePrompt(t *testing.T) {
	const hosts = 40
	f := &fakeReadGrants{pending: []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: testReadGrantDoc(t, hosts), ApprovalExpiryUnix: 1800000300}}}
	var out bytes.Buffer
	if err := readGrantCmd(context.Background(), f, []string{"approve", testRGDigest}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.approved) != 1 || f.approved[0] != testRGDigest {
		t.Fatalf("approved = %v", f.approved)
	}
	got := out.String()
	prompt := strings.Index(got, "Type 'yes' to approve")
	if prompt < 0 {
		t.Fatalf("no prompt:\n%s", got)
	}
	before := got[:prompt]
	wants := []string{
		"digest        " + testRGDigest,
		"expiry        " + time.Unix(testRGExpiry, 0).Format(time.RFC3339),
		"at most once per 15m0s", "run budget    96",
		"core.disk_usage @ 1.2.3", "artifact sha256:" + strings.Repeat("a", 64), "parameters sha256:" + strings.Repeat("b", 64),
		"core.uptime @ 1.0.0", "hosts (40):", "canonical grant (complete):",
	}
	for i := range hosts {
		wants = append(wants,
			fmt.Sprintf("host-%03d  host key SHA256:hostkey%03d", i, i),
			fmt.Sprintf("credential default version SHA256:credver%03d", i))
	}
	for _, w := range wants {
		if !strings.Contains(before, w) {
			t.Errorf("approval screen lacks %q before the prompt", w)
		}
	}
	// The complete canonical document is shown, untruncated.
	if !strings.Contains(before, string(f.pending[0].GetCanonicalGrant())) || strings.Contains(before, "more bytes]") {
		t.Error("canonical grant not shown completely")
	}
	if !strings.Contains(got, "approved: read grant 11111111-2222-4333-8444-555555555555") {
		t.Errorf("no confirmation:\n%s", got)
	}
}

func TestReadGrantApproveRefusesWrongDigest(t *testing.T) {
	f := &fakeReadGrants{pending: []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: testReadGrantDoc(t, 1)}}}
	for _, bad := range []string{
		testRGDigest[:8],              // prefix
		testRGDigest[:63],             // one short
		testRGDigest + "0",            // one long
		strings.ToUpper(testRGDigest), // not lowercase
		strings.Repeat("g", 64),       // not hex
		"",                            // empty
		strings.Repeat("e", 64),       // well formed, not pending
	} {
		var out bytes.Buffer
		if err := readGrantCmd(context.Background(), f, []string{"approve", bad}, strings.NewReader("yes\n"), &out); err == nil {
			t.Errorf("digest %q accepted", bad)
		}
		if strings.Contains(out.String(), "Type 'yes'") {
			t.Errorf("digest %q reached the prompt", bad)
		}
	}
	if len(f.approved) != 0 {
		t.Fatalf("approved %v", f.approved)
	}
	// Malformed digests are refused before the executor is asked.
	if f.listCalls != 1 {
		t.Errorf("ListPendingReadGrants called %d times, want 1 (only the well-formed unknown digest)", f.listCalls)
	}
	for _, bad := range [][]string{nil, {"approve"}, {"approve", testRGDigest, "x"}, {"pending", "x"}, {"list"}} {
		if err := readGrantCmd(context.Background(), f, bad, strings.NewReader("yes\n"), &bytes.Buffer{}); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestReadGrantDeclinedPromptApprovesNothing(t *testing.T) {
	for _, answer := range []string{"no\n", "\n", "y\n", "YES\n", ""} {
		f := &fakeReadGrants{pending: []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: testReadGrantDoc(t, 2)}}}
		var out bytes.Buffer
		if err := readGrantCmd(context.Background(), f, []string{"approve", testRGDigest}, strings.NewReader(answer), &out); err == nil {
			t.Errorf("answer %q: no error", answer)
		}
		if len(f.approved) != 0 {
			t.Errorf("answer %q approved %v", answer, f.approved)
		}
	}
}

func TestReadGrantApproveRefusesUndisplayableGrant(t *testing.T) {
	for name, doc := range map[string][]byte{
		"unknown member": []byte(`{"grant":"read-grant-v2","hidden":"x"}`),
		"trailing data":  append(testReadGrantDoc(t, 1), []byte(` {}`)...),
		"not json":       []byte("not json"),
		"empty":          nil,
	} {
		f := &fakeReadGrants{pending: []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: doc}}}
		var out bytes.Buffer
		if err := readGrantCmd(context.Background(), f, []string{"approve", testRGDigest}, strings.NewReader("yes\n"), &out); err == nil || len(f.approved) != 0 {
			t.Errorf("%s: approved (err %v)", name, err)
		}
	}
}

func TestReadGrantApproveDoesNotEchoExecutorErrors(t *testing.T) {
	const secretish = "internal detail \x1b[2J from executor"
	f := &fakeReadGrants{
		pending:    []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: testReadGrantDoc(t, 1)}},
		approveErr: grpcstatus.Error(codes.FailedPrecondition, secretish),
	}
	err := readGrantCmd(context.Background(), f, []string{"approve", testRGDigest}, strings.NewReader("yes\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), "internal detail") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("executor text echoed: %q", err)
	}
}
