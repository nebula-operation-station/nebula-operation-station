// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

// recordingRegistrySetter forwards to the real service and records what
// setupRegistryReads wired.
type recordingRegistrySetter struct {
	*executor.Service
	wired executor.RegistryReadAuthorizer
}

func (r *recordingRegistrySetter) SetRegistryReadAuthorizer(a executor.RegistryReadAuthorizer) {
	r.wired = a
	r.Service.SetRegistryReadAuthorizer(a)
}

func registryTestRead() executor.RegistryRead {
	return executor.RegistryRead{RegistryID: "corp", Method: "tag_digest", Repository: "team/app",
		ConfigDigest: strings.Repeat("a", 64), ConfigVersion: 1, CredentialID: strings.Repeat("b", 32), CredentialVersion: 1}
}

// TestSetupRegistryReadsWiresLeaseProfile: the shipped executor wires the
// lease-backed authorizer instead of the fail-closed default; it obeys the
// read pause and, with reads resumed, refuses a read no lease covers.
func TestSetupRegistryReadsWiresLeaseProfile(t *testing.T) {
	e := newExecutorUnderTest(t)
	rec := &recordingRegistrySetter{Service: e.svc}
	setupRegistryReads(rec)
	checkLeaseAuthorizer(t, e, rec)
}

// TestWireServedServiceWiresRegistryReads: main's service wiring (the
// function run calls on the service it serves) installs the lease-backed
// registry read authorizer, not the fail-closed default.
func TestWireServedServiceWiresRegistryReads(t *testing.T) {
	e := newExecutorUnderTest(t)
	rec := &recordingRegistrySetter{Service: e.svc}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wireServedService(rec, &executor.PveGuestPowerBindings{}, pub, dir, dir)
	checkLeaseAuthorizer(t, e, rec)
}

// checkLeaseAuthorizer checks that rec.wired is the production lease
// authorizer: paused until read dispatch resumes, then refusing a read no
// lease covers.
func checkLeaseAuthorizer(t *testing.T, e *executorUnderTest, rec *recordingRegistrySetter) {
	t.Helper()
	if rec.wired == nil {
		t.Fatal("no registry read authorizer wired")
	}
	_, err := rec.wired.AuthorizeRegistryRead(registryTestRead())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "paused") {
		t.Fatalf("before read dispatch resumes: %v", err)
	}
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	_, err = rec.wired.AuthorizeRegistryRead(registryTestRead())
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "no approved registry read lease") {
		t.Fatalf("without a lease: %v", err)
	}
	if strings.Contains(status.Convert(err).Message(), "no read-grant profile") {
		t.Fatal("the fail-closed default is still wired")
	}
}
