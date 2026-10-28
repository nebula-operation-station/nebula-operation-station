// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestMethodRolesServerReadAccess pins the read-only access the web server
// needs for the Settings page (issue #72): the server role may list the
// registered WebAuthn credentials and read the TOTP status, and nothing
// else in the WebAuthn/TOTP area. The server already sees credential IDs
// in the request options of logins and privileged sessions (decision 37);
// labels, AAGUIDs and creation data are not secrets, and the TOTP status
// is a boolean.
func TestMethodRolesServerReadAccess(t *testing.T) {
	const serverUID, adminUID uint32 = 10001, 10002
	policy := peercred.NewPolicy(
		map[uint32][]peercred.Role{
			serverUID: {peercred.RoleServer},
			adminUID:  {peercred.RoleAdmin},
		},
		MethodRoles(),
	)

	allowed := []string{
		pb.ExecutorService_ListWebAuthnCredentials_FullMethodName,
		pb.ExecutorService_GetTOTPStatus_FullMethodName,
	}
	for _, method := range allowed {
		if _, ok := policy.Allowed(serverUID, method); !ok {
			t.Errorf("server role may not call %s, want allowed", method)
		}
		if _, ok := policy.Allowed(adminUID, method); !ok {
			t.Errorf("admin role may not call %s, want allowed", method)
		}
	}

	// The rest of the WebAuthn and TOTP area stays admin-only: the server
	// may neither create codes, remove credentials, nor set up or remove
	// TOTP.
	for _, method := range []string{
		pb.ExecutorService_CreateRegistrationCode_FullMethodName,
		pb.ExecutorService_RemoveWebAuthnCredential_FullMethodName,
		pb.ExecutorService_BeginTOTPSetup_FullMethodName,
		pb.ExecutorService_ConfirmTOTPSetup_FullMethodName,
		pb.ExecutorService_RemoveTOTP_FullMethodName,
	} {
		if _, ok := policy.Allowed(serverUID, method); ok {
			t.Errorf("server role may call %s, want admin-only", method)
		}
	}
}
