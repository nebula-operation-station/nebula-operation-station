// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// Failure codes that the client defines itself. The permit codes come from
// internal/permit; codeVaultLocked and codeCredentialUnavailable are
// produced by the executor RPC layer (internal/executor).
const (
	codeVaultLocked        = "vault_locked"
	codeCredentialMissing  = "credential_unavailable"
	codePolicyBlocked      = "policy_blocked"
	codePreconditionFailed = "precondition_failed"
	codePermissionDenied   = "permission_denied"
	codeUnauthenticated    = "unauthenticated"
	codeDeadlineExceeded   = "deadline_exceeded"
	codeUnavailable        = "unavailable"
	codeCanceled           = "canceled"
	codeInternal           = "internal"
)

// Typed errors callers branch on with errors.Is.
var (
	// ErrLocked: the executor's vault is locked; run `nebula unlock` on the
	// executor host.
	ErrLocked = &Error{Code: codeVaultLocked}
	// ErrSessionRequired: the executor needs an active privileged session.
	ErrSessionRequired = &Error{Code: string(permit.CodeSessionRequired)}
	// ErrPolicyBlocked: the executor refused the run for policy reasons: the
	// target is not in the permit, the host was already authorized, the
	// artifact, parameters, action or credential does not match the
	// approved request, or the executor's minimum risk for the host is now
	// above the approved risk.
	ErrPolicyBlocked = &Error{Code: codePolicyBlocked}
	// ErrPermitNotFound: no permit with that digest exists.
	ErrPermitNotFound = &Error{Code: string(permit.CodeNotFound)}
	// ErrPermitExpired: the permit or its approval window has expired.
	ErrPermitExpired = &Error{Code: string(permit.CodeExpired)}
	// ErrPermitWrongState: the permit is in the wrong state for the call.
	ErrPermitWrongState = &Error{Code: string(permit.CodeWrongState)}
	// ErrExecutionIDReused: the execution ID is bound to another request or
	// has already ended.
	ErrExecutionIDReused = &Error{Code: string(permit.CodeExecutionIDReused)}
	// ErrLimitExceeded: the executor hit a resource limit.
	ErrLimitExceeded = &Error{Code: string(permit.CodeLimit)}
	// ErrInvalidRequest: the request is malformed.
	ErrInvalidRequest = &Error{Code: string(permit.CodeInvalidRequest)}
	// ErrCLIApprovalRequired: hardened mode requires `nebula approve`.
	ErrCLIApprovalRequired = &Error{Code: string(permit.CodeCLIRequired)}
	// ErrAssertionRejected: the WebAuthn assertion did not verify.
	ErrAssertionRejected = &Error{Code: string(permit.CodeAssertionRejected)}
	// ErrTypedCountMismatch: the typed target count does not match the permit.
	ErrTypedCountMismatch = &Error{Code: string(permit.CodeTypedCountMismatch)}
	// ErrNoChallenge: no session challenge is pending.
	ErrNoChallenge = &Error{Code: string(permit.CodeNoChallenge)}
	// ErrStorage: the executor could not read or write its state store
	// (executor.db). Nothing was approved. A retry with the same execution
	// ID may get ErrExecutionIDReused if the binding reached the disk
	// before the error; then create a new execution.
	ErrStorage = &Error{Code: string(permit.CodeStorage)}
	// ErrCredentialUnavailable: the requested credential is not loaded.
	ErrCredentialUnavailable = &Error{Code: codeCredentialMissing}
	// ErrPrecondition: the executor state does not allow the call and no
	// more specific code was reported.
	ErrPrecondition = &Error{Code: codePreconditionFailed}
	// ErrPermissionDenied: the executor refused this caller (UID or role).
	ErrPermissionDenied = &Error{Code: codePermissionDenied}
	// ErrUnauthenticated: the executor rejected the caller's credentials.
	ErrUnauthenticated = &Error{Code: codeUnauthenticated}
	// ErrDeadlineExceeded: the per-call timeout fired.
	ErrDeadlineExceeded = &Error{Code: codeDeadlineExceeded}
	// ErrUnavailable: the executor socket is not reachable.
	ErrUnavailable = &Error{Code: codeUnavailable}
	// ErrCanceled: the caller's context was canceled.
	ErrCanceled = &Error{Code: codeCanceled}
	// ErrInternal: the executor reported an internal error.
	ErrInternal = &Error{Code: codeInternal}
)

// Error is a typed executor failure. Code is the stable failure code the
// executor reported (a permit code, a service-level code, or a client-side
// code for transport failures); Detail is the human-readable part.
type Error struct {
	Code   string
	Detail string
	cause  error // the underlying gRPC error, if any
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// Unwrap returns the underlying gRPC error.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether e matches target. A failure with one of the
// policy-block codes matches ErrPolicyBlocked; any failure matches the
// sentinel with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	if e.Code == t.Code {
		return true
	}
	return t.Code == codePolicyBlocked && policyBlockedCodes[e.Code]
}

// policyBlockedCodes are the permit codes the executor maps to
// codes.PermissionDenied: the run does not match the approved permit or the
// permit does not cover it.
var policyBlockedCodes = map[string]bool{
	string(permit.CodeTargetNotPermitted): true,
	string(permit.CodeHostAlreadyRun):     true,
	string(permit.CodeArtifactMismatch):   true,
	string(permit.CodeParametersMismatch): true,
	string(permit.CodeActionMismatch):     true,
	string(permit.CodeCredentialMismatch): true,
	string(permit.CodeRiskAboveApproval):  true,
}

// knownCodes are the failure codes the executor may send in a status message.
var knownCodes = func() map[string]bool {
	m := make(map[string]bool, 20)
	for _, c := range []string{
		string(permit.CodeInvalidRequest),
		string(permit.CodeExecutionIDReused),
		string(permit.CodeSessionRequired),
		string(permit.CodeNotFound),
		string(permit.CodeWrongState),
		string(permit.CodeExpired),
		string(permit.CodeCLIRequired),
		string(permit.CodeTypedCountMismatch),
		string(permit.CodeAssertionRejected),
		string(permit.CodeTargetNotPermitted),
		string(permit.CodeHostAlreadyRun),
		string(permit.CodeArtifactMismatch),
		string(permit.CodeParametersMismatch),
		string(permit.CodeActionMismatch),
		string(permit.CodeCredentialMismatch),
		string(permit.CodeLimit),
		string(permit.CodeNoChallenge),
		string(permit.CodeStorage),
		string(permit.CodeRiskAboveApproval),
		codeVaultLocked,
		codeCredentialMissing,
	} {
		m[c] = true
	}
	return m
}()

// mapError converts a gRPC error into a typed *Error. The executor sends
// permit failures as "<code>: <detail>" status messages; those are parsed
// first. Anything else is classified by the gRPC status code.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	st := status.Convert(err)
	if st.Code() == codes.OK {
		return nil
	}
	msg := st.Message()
	if code, detail, ok := splitCode(msg); ok {
		return &Error{Code: code, Detail: detail, cause: err}
	}
	e := &Error{cause: err}
	switch st.Code() {
	case codes.InvalidArgument:
		e.Code, e.Detail = string(permit.CodeInvalidRequest), msg
	case codes.NotFound:
		e.Code, e.Detail = string(permit.CodeNotFound), msg
	case codes.AlreadyExists:
		e.Code, e.Detail = string(permit.CodeExecutionIDReused), msg
	case codes.ResourceExhausted:
		e.Code, e.Detail = string(permit.CodeLimit), msg
	case codes.FailedPrecondition:
		e.Code, e.Detail = codePreconditionFailed, msg
	case codes.PermissionDenied:
		e.Code, e.Detail = codePermissionDenied, msg
	case codes.Unauthenticated:
		e.Code, e.Detail = codeUnauthenticated, msg
	case codes.DeadlineExceeded:
		e.Code, e.Detail = codeDeadlineExceeded, msg
	case codes.Unavailable:
		e.Code, e.Detail = codeUnavailable, msg
	case codes.Canceled:
		e.Code, e.Detail = codeCanceled, msg
	default:
		e.Code, e.Detail = codeInternal, msg
	}
	return e
}

// splitCode parses "<code>: <detail>" status messages. Only known codes are
// recognized, so arbitrary status text is never mistaken for a code.
func splitCode(msg string) (code, detail string, ok bool) {
	if knownCodes[msg] {
		return msg, "", true
	}
	i := strings.IndexByte(msg, ':')
	if i <= 0 {
		return "", "", false
	}
	code = msg[:i]
	if !knownCodes[code] {
		return "", "", false
	}
	return code, strings.TrimPrefix(msg[i+1:], " "), true
}
