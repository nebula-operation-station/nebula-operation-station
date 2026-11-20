// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeReject is the executor as `nebula reject` sees it over the admin
// socket: the pending permits, a batch review and RejectPending, each
// rejection recorded.
type fakeReject struct {
	pb.ExecutorServiceClient
	pending   []*pb.PendingPermit
	review    *pb.ReviewBatchResponse
	rejected  []*pb.RejectPendingRequest
	rejectErr error
}

func (f *fakeReject) ListPending(context.Context, *pb.ListPendingRequest, ...grpc.CallOption) (*pb.ListPendingResponse, error) {
	return &pb.ListPendingResponse{Permits: f.pending}, nil
}

func (f *fakeReject) ReviewBatch(_ context.Context, in *pb.ReviewBatchRequest, _ ...grpc.CallOption) (*pb.ReviewBatchResponse, error) {
	if f.review == nil || in.GetBatchDigest() != f.review.GetBatchDigest() {
		return nil, grpcstatus.Error(codes.NotFound, "batch approval not found")
	}
	return f.review, nil
}

func (f *fakeReject) RejectPending(_ context.Context, in *pb.RejectPendingRequest, _ ...grpc.CallOption) (*pb.RejectPendingResponse, error) {
	if f.rejectErr != nil {
		return nil, f.rejectErr
	}
	f.rejected = append(f.rejected, in)
	return &pb.RejectPendingResponse{State: pb.PermitState_PERMIT_STATE_REJECTED}, nil
}

func runReject(f pb.ExecutorServiceClient, args []string, answer string) (string, error) {
	var out bytes.Buffer
	err := rejectCmd(context.Background(), f, args, strings.NewReader(answer), &out)
	return out.String(), err
}

// A pending permit found by a unique prefix is shown as the executor sees it
// and rejected by its full digest with the reason, after 'yes'. The admin
// path relays no user name (spec 07: relayed_user is empty for the admin UID).
func TestRejectShowsExecutorViewAndRejectsAfterYes(t *testing.T) {
	p := approvePermit()
	f := &fakeReject{pending: []*pb.PendingPermit{p}}
	out, err := runReject(f, []string{"abababab", "--reason", "wrong host group"}, "yes\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(f.rejected) != 1 {
		t.Fatalf("rejected %d times, want 1", len(f.rejected))
	}
	got := f.rejected[0]
	if got.GetDigest() != p.GetExecutionDigest() || got.GetReason() != "wrong host group" || got.GetRelayedUser() != "" {
		t.Fatalf("RejectPending request = %v", got)
	}
	for _, want := range []string{
		"as seen by the executor",
		p.GetExecutionDigest(),
		"core.facts @ 1.0.0",
		"web-01",
		"SHA256:AAAA",
		"wrong host group",
		"Type 'yes' to reject",
		"rejected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
}

// The reason may come first and in the --reason=TEXT form; without a reason
// the request carries none.
func TestRejectArgumentForms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		reason string
	}{
		{"no reason", []string{"abababab"}, ""},
		{"reason first", []string{"--reason", "dup", "abababab"}, "dup"},
		{"reason equals", []string{"abababab", "--reason=dup run"}, "dup run"},
		{"200 characters", []string{"abababab", "--reason", strings.Repeat("ä", 200)}, strings.Repeat("ä", 200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReject{pending: []*pb.PendingPermit{approvePermit()}}
			if out, err := runReject(f, tc.args, "yes\n"); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if len(f.rejected) != 1 || f.rejected[0].GetReason() != tc.reason {
				t.Fatalf("rejected = %v, want one with reason %q", f.rejected, tc.reason)
			}
		})
	}
}

// Nothing is rejected, and the executor is never asked to reject, for
// malformed arguments, a reason outside the spec 07 limits, a prefix that is
// too short, ambiguous or unknown, or a confirmation other than 'yes'.
func TestRejectRefusalsRejectNothing(t *testing.T) {
	other := approvePermit()
	other.ExecutionDigest = "abababab" + strings.Repeat("cd", 28)
	for _, tc := range []struct {
		name    string
		args    []string
		answer  string
		pending []*pb.PendingPermit
		want    string
	}{
		{"no digest", nil, "yes\n", nil, "usage"},
		{"two digests", []string{"abababab", "cdcdcdcd"}, "yes\n", nil, "usage"},
		{"unknown flag", []string{"--yes", "abababab"}, "yes\n", nil, "usage"},
		{"reason without text", []string{"abababab", "--reason"}, "yes\n", nil, "usage"},
		{"empty reason", []string{"abababab", "--reason="}, "yes\n", nil, "needs a text"},
		{"reason 201 characters", []string{"abababab", "--reason", strings.Repeat("x", 201)}, "yes\n", nil, "200 characters"},
		{"reason over 800 bytes", []string{"abababab", "--reason", strings.Repeat("😀", 201)}, "yes\n", nil, "800 bytes"},
		{"reason with escape", []string{"abababab", "--reason", "ok\x1b[2J"}, "yes\n", nil, "control"},
		{"reason with newline", []string{"abababab", "--reason", "a\nb"}, "yes\n", nil, "control"},
		{"reason with bidi", []string{"abababab", "--reason", "a\u202eb"}, "yes\n", nil, "control"},
		{"reason invalid utf-8", []string{"abababab", "--reason", "a\xffb"}, "yes\n", nil, "UTF-8"},
		{"short prefix", []string{"abababa"}, "yes\n", nil, "at least 8"},
		{"unknown prefix", []string{"efefefef"}, "yes\n", nil, "no pending proposal"},
		{"ambiguous prefix", []string{"abababab"}, "yes\n", []*pb.PendingPermit{approvePermit(), other}, "ambiguous"},
		{"no confirmation", []string{"abababab"}, "\n", nil, "not rejected"},
		{"other answer", []string{"abababab"}, "y\n", nil, "not rejected"},
		{"closed input", []string{"abababab"}, "", nil, "not rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending := tc.pending
			if pending == nil {
				pending = []*pb.PendingPermit{approvePermit()}
			}
			f := &fakeReject{pending: pending}
			_, err := runReject(f, tc.args, tc.answer)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if len(f.rejected) != 0 {
				t.Fatalf("RejectPending was called: %v", f.rejected)
			}
		})
	}
}

// The executor's answer is final: a refusal (already approved, already
// rejected, not found) reaches the admin unchanged and is not reported as a
// rejection.
func TestRejectReturnsExecutorRefusal(t *testing.T) {
	f := &fakeReject{
		pending:   []*pb.PendingPermit{approvePermit()},
		rejectErr: grpcstatus.Error(codes.FailedPrecondition, "permit_already_approved"),
	}
	out, err := runReject(f, []string{"abababab"}, "yes\n")
	if err == nil || !strings.Contains(err.Error(), "permit_already_approved") {
		t.Fatalf("err = %v, want the executor's refusal", err)
	}
	if strings.HasSuffix(strings.TrimSpace(out), "rejected") {
		t.Fatalf("a refused call printed success:\n%s", out)
	}
}

// Host data on the confirmation screen and the admin's own reason are
// rendered as text: no terminal escape or bidi override reaches the screen.
func TestRejectEscapesUntrustedText(t *testing.T) {
	p := approvePermit()
	p.Request.ActionId = "core.facts\x1b[2J"
	p.Request.ResolvedTargets[0].HostId = "web-01\u202e"
	p.Request.ResolvedTargets[0].HostKeyFingerprint = "SHA256:\x1b]0;x\x07"
	f := &fakeReject{pending: []*pb.PendingPermit{p}}
	out, err := runReject(f, []string{"abababab"}, "no\n")
	if err == nil {
		t.Fatal("rejected without 'yes'")
	}
	if strings.ContainsAny(out, "\x1b\x07\u202e") {
		t.Fatalf("raw control or bidi character on screen: %q", out)
	}
}

// A full batch digest is not a pending permit: the executor's complete batch
// plan is shown and the batch is rejected as a whole by its digest. A prefix
// never selects a batch, and a batch that is not pending is refused locally.
func TestRejectBatchByFullDigest(t *testing.T) {
	rev := batchReview(t, 2, canonical.RiskHigh)
	f := &fakeReject{review: rev}
	out, err := runReject(f, []string{rev.GetBatchDigest(), "--reason", "superseded"}, "yes\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(f.rejected) != 1 || f.rejected[0].GetDigest() != rev.GetBatchDigest() || f.rejected[0].GetReason() != "superseded" {
		t.Fatalf("rejected = %v", f.rejected)
	}
	for _, want := range []string{"host-000", "host-001", "member-0", "Reject all 2 members"} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}

	f = &fakeReject{review: rev}
	if _, err := runReject(f, []string{rev.GetBatchDigest()[:16]}, "yes\n"); err == nil || len(f.rejected) != 0 {
		t.Fatalf("a prefix rejected a batch: %v %v", err, f.rejected)
	}

	approved := batchReview(t, 2, canonical.RiskHigh)
	approved.State = pb.PermitState_PERMIT_STATE_APPROVED
	f = &fakeReject{review: approved}
	if _, err := runReject(f, []string{approved.GetBatchDigest()}, "yes\n"); err == nil || !strings.Contains(err.Error(), "not pending") || len(f.rejected) != 0 {
		t.Fatalf("a non-pending batch was rejected: %v %v", err, f.rejected)
	}
}

// A full digest the executor knows neither as a pending permit nor as a batch
// is refused without asking the executor to reject: the admin always sees
// the executor's view before a rejection.
func TestRejectUnknownFullDigestRejectsNothing(t *testing.T) {
	f := &fakeReject{}
	_, err := runReject(f, []string{strings.Repeat("ef", 32)}, "yes\n")
	if err == nil || len(f.rejected) != 0 {
		t.Fatalf("err = %v, rejected = %v", err, f.rejected)
	}
}
