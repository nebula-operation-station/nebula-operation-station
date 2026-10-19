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
		pb.ExecutorService_RunAttached_FullMethodName:               {server},
		pb.ExecutorService_StartDurable_FullMethodName:              {server},
		pb.ExecutorService_GetRun_FullMethodName:                    {server},
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
		pb.ExecutorService_BeginLogin_FullMethodName:                {server},
		pb.ExecutorService_FinishLogin_FullMethodName:               {server},
		pb.ExecutorService_CheckCredential_FullMethodName:           {server},
		pb.ExecutorService_BeginTOTPSetup_FullMethodName:            {admin},
		pb.ExecutorService_ConfirmTOTPSetup_FullMethodName:          {admin},
		pb.ExecutorService_RemoveTOTP_FullMethodName:                {admin},
		pb.ExecutorService_GetTOTPStatus_FullMethodName:             {admin},
		pb.ExecutorService_RecoveryLogin_FullMethodName:             {server},
		pb.ExecutorService_FinishRecovery_FullMethodName:            {admin},
		pb.ExecutorService_ProbeHostKey_FullMethodName:              {admin},
		pb.ExecutorService_PinHostKey_FullMethodName:                {admin},
		pb.ExecutorService_UnpinHostKey_FullMethodName:              {admin},
		pb.ExecutorService_ListHostKeys_FullMethodName:              {server, admin},
		pb.ExecutorService_ProposeRepin_FullMethodName:              {server},
		pb.ExecutorService_CommitRepin_FullMethodName:               {server},
		pb.ExecutorService_ProposeEnroll_FullMethodName:             {server},
		pb.ExecutorService_CommitEnroll_FullMethodName:              {server},
		pb.ExecutorService_TestConnection_FullMethodName:            {admin},
		pb.ExecutorService_GetSSHPublicKey_FullMethodName:           {admin},
		pb.ExecutorService_InitVault_FullMethodName:                 {admin},
		pb.ExecutorService_SetSecret_FullMethodName:                 {admin},
		pb.ExecutorService_ListSecrets_FullMethodName:               {admin},
		pb.ExecutorService_DeleteSecret_FullMethodName:              {admin},
		pb.ExecutorService_BeginGate_FullMethodName:                 {server},
		pb.ExecutorService_CommitGate_FullMethodName:                {server},
		pb.ExecutorService_AbortRollout_FullMethodName:              {server},
		pb.ExecutorService_GetRollout_FullMethodName:                {server, admin},
		pb.ExecutorService_ApproveGateCLI_FullMethodName:            {admin},
		pb.ExecutorService_BeginTrustArtifact_FullMethodName:        {server},
		pb.ExecutorService_CommitTrustArtifact_FullMethodName:       {server},
		pb.ExecutorService_GetArtifactTrust_FullMethodName:          {server, admin},
		pb.ExecutorService_ProposeScheduleGrant_FullMethodName:      {server},
		pb.ExecutorService_CommitScheduleGrant_FullMethodName:       {server},
		pb.ExecutorService_ListPendingScheduleGrants_FullMethodName: {admin},
		pb.ExecutorService_ApproveScheduleGrantCLI_FullMethodName:   {admin},
		pb.ExecutorService_ListScheduleGrants_FullMethodName:        {server, admin},
		pb.ExecutorService_RevokeScheduleGrant_FullMethodName:       {server, admin},
		pb.ExecutorService_RunScheduled_FullMethodName:              {server},
	}
}
