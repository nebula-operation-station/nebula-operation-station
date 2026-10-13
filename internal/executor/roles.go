// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// MethodRoles is the single source of truth for who may call what on the
// executor socket. A method missing here is denied for everyone. Changing
// this table is a security-relevant change (see AGENTS.md, protected paths).
func MethodRoles() map[string][]peercred.Role {
	server := peercred.RoleServer
	admin := peercred.RoleAdmin
	return map[string][]peercred.Role{
		pb.ExecutorService_GetStatus_FullMethodName:                 {server, admin},
		pb.ExecutorService_ProposeExecution_FullMethodName:          {server},
		pb.ExecutorService_SubmitAssertion_FullMethodName:           {server},
		pb.ExecutorService_BeginPrivilegedSession_FullMethodName:    {server},
		pb.ExecutorService_CompletePrivilegedSession_FullMethodName: {server},
		pb.ExecutorService_AuthorizeRun_FullMethodName:              {server},
		pb.ExecutorService_Unlock_FullMethodName:                    {admin},
		pb.ExecutorService_Lock_FullMethodName:                      {server, admin},
		pb.ExecutorService_ListPending_FullMethodName:               {admin},
		pb.ExecutorService_ApproveCLI_FullMethodName:                {admin},
		pb.ExecutorService_TrustArtifact_FullMethodName:             {admin},
		pb.ExecutorService_UntrustArtifact_FullMethodName:           {admin},
		pb.ExecutorService_ListTrustedArtifacts_FullMethodName:      {admin},
		pb.ExecutorService_SetHostCriticality_FullMethodName:        {admin},
		pb.ExecutorService_ListHostCriticality_FullMethodName:       {admin},
		pb.ExecutorService_CreateRegistrationCode_FullMethodName:    {admin},
		pb.ExecutorService_BeginRegistration_FullMethodName:         {server},
		pb.ExecutorService_FinishRegistration_FullMethodName:        {server},
		pb.ExecutorService_ListWebAuthnCredentials_FullMethodName:   {admin},
		pb.ExecutorService_RemoveWebAuthnCredential_FullMethodName:  {admin},
	}
}
