// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the executor client, part 2: the error mapping (acceptance
// criterion 3) and the end-to-end typed errors (acceptance criterion 4).
// The harness lives in client_test.go.

package executorclient

import (
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// --- Acceptance criterion 3: typed errors, errors.Is. ---

func TestMapErrorPermitCodes(t *testing.T) {
	cases := []struct {
		code     permit.Code
		sentinel error
	}{
		{permit.CodeInvalidRequest, ErrInvalidRequest},
		{permit.CodeExecutionIDReused, ErrExecutionIDReused},
		{permit.CodeSessionRequired, ErrSessionRequired},
		{permit.CodeNotFound, ErrPermitNotFound},
		{permit.CodeWrongState, ErrPermitWrongState},
		{permit.CodeExpired, ErrPermitExpired},
		{permit.CodeCLIRequired, ErrCLIApprovalRequired},
		{permit.CodeTypedCountMismatch, ErrTypedCountMismatch},
		{permit.CodeAssertionRejected, ErrAssertionRejected},
		{permit.CodeTargetNotPermitted, ErrPolicyBlocked},
		{permit.CodeHostAlreadyRun, ErrPolicyBlocked},
		{permit.CodeArtifactMismatch, ErrPolicyBlocked},
		{permit.CodeParametersMismatch, ErrPolicyBlocked},
		{permit.CodeActionMismatch, ErrPolicyBlocked},
		{permit.CodeCredentialMismatch, ErrPolicyBlocked},
		{permit.CodeLimit, ErrLimitExceeded},
		{permit.CodeNoChallenge, ErrNoChallenge},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			// The executor sends permit failures as "code: detail" status
			// messages (see internal/executor toStatus).
			err := mapError(status.Error(codes.FailedPrecondition, string(tc.code)+": something went wrong"))
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %T", err)
			}
			if e.Code != string(tc.code) {
				t.Fatalf("code = %q, want %q", e.Code, tc.code)
			}
			if e.Detail != "something went wrong" {
				t.Fatalf("detail = %q, want %q", e.Detail, "something went wrong")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tc.sentinel)
			}
		})
	}
}

func TestMapErrorServiceCodes(t *testing.T) {
	if err := mapError(status.Error(codes.FailedPrecondition, "vault_locked: run `nebula unlock` on the executor host")); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := mapError(status.Error(codes.FailedPrecondition, "credential_unavailable: "+credRef)); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("want ErrCredentialUnavailable, got %v", err)
	}
}

func TestMapErrorFallsBackToGRPCCode(t *testing.T) {
	cases := []struct {
		code     codes.Code
		msg      string
		sentinel error
	}{
		{codes.InvalidArgument, "request is required", ErrInvalidRequest},
		{codes.NotFound, "gone", ErrPermitNotFound},
		{codes.AlreadyExists, "taken", ErrExecutionIDReused},
		{codes.ResourceExhausted, "full", ErrLimitExceeded},
		{codes.FailedPrecondition, "no code prefix", ErrPrecondition},
		{codes.PermissionDenied, "uid 123 may not call /nebula.executor.v1.ExecutorService/AuthorizeRun", ErrPermissionDenied},
		{codes.Unauthenticated, "keyring: passphrase does not decrypt every key", ErrUnauthenticated},
		{codes.DeadlineExceeded, "context deadline exceeded", ErrDeadlineExceeded},
		{codes.Unavailable, "connection error", ErrUnavailable},
		{codes.Canceled, "context canceled", ErrCanceled},
		{codes.Internal, "cannot create challenge", ErrInternal},
		{codes.Unknown, "mystery", ErrInternal},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			err := mapError(status.Error(tc.code, tc.msg))
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tc.sentinel)
			}
		})
	}
}

func TestMapErrorNilAndPlain(t *testing.T) {
	if mapError(nil) != nil {
		t.Fatal("mapError(nil) != nil")
	}
	if err := mapError(errors.New("boom")); !errors.Is(err, ErrInternal) {
		t.Fatalf("want ErrInternal, got %v", err)
	}
}

func TestPolicyBlockedGrouping(t *testing.T) {
	blocked := []permit.Code{
		permit.CodeTargetNotPermitted, permit.CodeHostAlreadyRun, permit.CodeArtifactMismatch,
		permit.CodeParametersMismatch, permit.CodeActionMismatch, permit.CodeCredentialMismatch,
	}
	for _, c := range blocked {
		err := mapError(status.Error(codes.PermissionDenied, string(c)+": detail"))
		if !errors.Is(err, ErrPolicyBlocked) {
			t.Errorf("%s: want ErrPolicyBlocked, got %v", c, err)
		}
	}
	notBlocked := []struct {
		code     permit.Code
		sentinel error
	}{
		{permit.CodeSessionRequired, ErrSessionRequired},
		{permit.CodeNotFound, ErrPermitNotFound},
	}
	for _, tc := range notBlocked {
		err := mapError(status.Error(codes.FailedPrecondition, string(tc.code)+": detail"))
		if errors.Is(err, ErrPolicyBlocked) {
			t.Errorf("%s: must not match ErrPolicyBlocked", tc.code)
		}
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("%s: want %v", tc.code, tc.sentinel)
		}
	}
}

// --- Acceptance criterion 4: the server branches on these errors. ---

func TestLockedAuthorizeRun(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	if _, err := c.AuthorizeRun(h.ctx(), run(unknownDigest, "dockerflux", fpA)); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

func TestLowRiskRequiresSession(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	_, err := h.propose(c, h.request(pb.RiskClass_RISK_CLASS_LOW))
	if !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("want ErrSessionRequired, got %v", err)
	}
}

func TestUnknownDigestNotFound(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	h.unlock(c)
	_, err := c.AuthorizeRun(h.ctx(), run(unknownDigest, "dockerflux", fpA))
	if !errors.Is(err, ErrPermitNotFound) {
		t.Fatalf("want ErrPermitNotFound, got %v", err)
	}
}

func TestExecutionIDReused(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	r := h.request(pb.RiskClass_RISK_CLASS_MEDIUM)
	if _, err := h.propose(c, r); err != nil {
		t.Fatalf("first propose: %v", err)
	}
	r2 := proto.Clone(r).(*pb.ExecutionRequest)
	r2.ArtifactSha256 = strings.Repeat("d", 64)
	_, err := h.propose(c, r2)
	if !errors.Is(err, ErrExecutionIDReused) {
		t.Fatalf("want ErrExecutionIDReused, got %v", err)
	}
}

func TestFullFlowApproveAndAuthorize(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	p, err := h.propose(c, h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	h.openSession(c)
	if _, err := c.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge()),
	}); err != nil {
		t.Fatalf("submit assertion: %v", err)
	}
	h.unlock(c)

	if _, err := c.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA)); err != nil {
		t.Fatalf("authorize run: %v", err)
	}
	// The same host cannot be authorized twice.
	_, err = c.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA))
	if !errors.Is(err, ErrPolicyBlocked) {
		t.Fatalf("second run for the same host: want ErrPolicyBlocked, got %v", err)
	}
	// A tampered artifact is blocked.
	tampered := run(p.GetExecutionDigest(), "strompi", fpB)
	tampered.Artifact = append([]byte{}, script...)
	tampered.Artifact[0] ^= 1
	_, err = c.AuthorizeRun(h.ctx(), tampered)
	if !errors.Is(err, ErrPolicyBlocked) {
		t.Fatalf("tampered artifact: want ErrPolicyBlocked, got %v", err)
	}
	// The other host with the right artifact is still allowed.
	if _, err := c.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "strompi", fpB)); err != nil {
		t.Fatalf("authorize second host: %v", err)
	}
}

func TestMissingRoleDenied(t *testing.T) {
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	c := h.client()
	_, err := h.propose(c, h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("want ErrPermissionDenied, got %v", err)
	}
}
