// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
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
		pb.ExecutorService_GetSessionState_FullMethodName:           {server, admin},
		pb.ExecutorService_AuthorizeRun_FullMethodName:              {server},
		pb.ExecutorService_RunAttached_FullMethodName:               {server},
		pb.ExecutorService_StartDurable_FullMethodName:              {server},
		pb.ExecutorService_GetRun_FullMethodName:                    {server},
		pb.ExecutorService_Unlock_FullMethodName:                    {admin},
		pb.ExecutorService_Lock_FullMethodName:                      {server, admin},
		pb.ExecutorService_ListPending_FullMethodName:               {admin},
		pb.ExecutorService_ApproveCLI_FullMethodName:                {admin},
		pb.ExecutorService_GetPermitState_FullMethodName:            {server, admin},
		pb.ExecutorService_TrustArtifact_FullMethodName:             {admin},
		pb.ExecutorService_UntrustArtifact_FullMethodName:           {admin},
		pb.ExecutorService_ListTrustedArtifacts_FullMethodName:      {admin},
		pb.ExecutorService_SetHostCriticality_FullMethodName:        {admin},
		pb.ExecutorService_ListHostCriticality_FullMethodName:       {admin},
		pb.ExecutorService_CreateRegistrationCode_FullMethodName:    {admin},
		pb.ExecutorService_BeginRegistration_FullMethodName:         {server},
		pb.ExecutorService_FinishRegistration_FullMethodName:        {server},
		pb.ExecutorService_ListWebAuthnCredentials_FullMethodName:   {server, admin},
		pb.ExecutorService_RemoveWebAuthnCredential_FullMethodName:  {admin},
		pb.ExecutorService_BeginLogin_FullMethodName:                {server},
		pb.ExecutorService_FinishLogin_FullMethodName:               {server},
		pb.ExecutorService_CheckCredential_FullMethodName:           {server},
		pb.ExecutorService_BeginTOTPSetup_FullMethodName:            {admin},
		pb.ExecutorService_ConfirmTOTPSetup_FullMethodName:          {admin},
		pb.ExecutorService_RemoveTOTP_FullMethodName:                {admin},
		pb.ExecutorService_GetTOTPStatus_FullMethodName:             {server, admin},
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
		// Join of a provisioned PVE guest (ADR 0008 section 4, PV-06): the
		// normal enrollment approval, proposed and committed by the server.
		pb.ExecutorService_ProposeGuestJoin_FullMethodName: {server},
		pb.ExecutorService_CommitGuestJoin_FullMethodName:  {server},
		pb.ExecutorService_TestConnection_FullMethodName:   {admin},
		// The server may read the executor's SSH public key (never the
		// private key): it needs the key's SHA-256 fingerprint as the
		// credential_version of a read-grant-v2 proposal (ADR 0007, E06).
		pb.ExecutorService_GetSSHPublicKey_FullMethodName:           {server, admin},
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
		pb.ExecutorService_RegisterModule_FullMethodName:            {server},
		pb.ExecutorService_AddSigner_FullMethodName:                 {admin},
		pb.ExecutorService_RemoveSigner_FullMethodName:              {admin},
		pb.ExecutorService_ConfirmModuleSigner_FullMethodName:       {admin},
		pb.ExecutorService_ListSigners_FullMethodName:               {server, admin},
		pb.ExecutorService_ProposeScheduleGrant_FullMethodName:      {server},
		pb.ExecutorService_CommitScheduleGrant_FullMethodName:       {server},
		pb.ExecutorService_ListPendingScheduleGrants_FullMethodName: {admin},
		pb.ExecutorService_ApproveScheduleGrantCLI_FullMethodName:   {admin},
		pb.ExecutorService_ListScheduleGrants_FullMethodName:        {server, admin},
		pb.ExecutorService_RevokeScheduleGrant_FullMethodName:       {server, admin},
		pb.ExecutorService_RunScheduled_FullMethodName:              {server},
		pb.ExecutorService_ProposeReadGrant_FullMethodName:          {server},
		pb.ExecutorService_CommitReadGrant_FullMethodName:           {server},
		pb.ExecutorService_ListPendingReadGrants_FullMethodName:     {admin},
		pb.ExecutorService_ApproveReadGrantCLI_FullMethodName:       {admin},
		// The pve-collector may list approved read grants (metadata,
		// read-only): it checks on-demand live requests against the
		// read-grant leases itself, so a server-supplied target list never
		// widens what is read (autopilot lv00, lv02/lv04). It may not
		// propose, commit, approve, revoke or run a grant.
		pb.ExecutorService_ListReadGrants_FullMethodName:  {server, admin, peercred.RolePVECollector},
		pb.ExecutorService_RevokeReadGrant_FullMethodName: {server, admin},
		pb.ExecutorService_RunReadGrant_FullMethodName:    {server},
		// Batch read grants (ADR 0007, E19b). The server proposes and relays a
		// user-verified assertion; only the admin reviews and approves. The
		// server can never approve a batch.
		pb.ExecutorService_ProposeBatch_FullMethodName:    {server},
		pb.ExecutorService_CommitBatch_FullMethodName:     {server},
		pb.ExecutorService_ReviewBatch_FullMethodName:     {admin},
		pb.ExecutorService_ApproveBatchCLI_FullMethodName: {admin},
		pb.ExecutorService_GetBatchStatus_FullMethodName:  {server, admin},
		// Read-only: credential versions/fingerprints for batch plans, no
		// key material.
		pb.ExecutorService_GetBatchCredentialVersions_FullMethodName: {server, admin},
		// Runs one approved, claimable batch member; the executor takes
		// everything that runs from the frozen plan (ADR 0007 E11).
		pb.ExecutorService_RunBatchMember_FullMethodName: {server},
		// Built-in trust (ADR 0007, E19c). Review and commit are local-admin
		// only; the server may read the trust status, nothing else. There is
		// no server bulk trust.
		pb.ExecutorService_ReviewBuiltinTrust_FullMethodName:    {admin},
		pb.ExecutorService_CommitBuiltinTrust_FullMethodName:    {admin},
		pb.ExecutorService_UnpinBuiltinVersion_FullMethodName:   {admin},
		pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName: {server, admin},
		pb.ExecutorService_ListEvents_FullMethodName:            {server, admin},
		pb.ExecutorService_BackupExecutor_FullMethodName:        {admin},
		// PVE provider reads (ADR 0006, P1-05). The entries are final:
		// pve-collector may call ONLY these two methods (plus ListReadGrants,
		// see the read-grant entries above); server may list the
		// remotes (metadata); admin may call both. The server never calls
		// ReadPVE: it writes poll requests to the spool and the pve-collector
		// schedules the reads. Remote management (add/rotate/remove/repin) is
		// not part of this surface.
		pb.ExecutorService_ProbePVERemote_FullMethodName:      {admin},
		pb.ExecutorService_AddPVERemote_FullMethodName:        {admin},
		pb.ExecutorService_RotatePVEToken_FullMethodName:      {admin},
		pb.ExecutorService_RemovePVERemote_FullMethodName:     {admin},
		pb.ExecutorService_ListPVEAdminRemotes_FullMethodName: {admin},
		pb.ExecutorService_SetPVERemoteSite_FullMethodName:    {admin},
		pb.ExecutorService_ProposePVERepin_FullMethodName:     {admin},
		pb.ExecutorService_CommitPVERepin_FullMethodName:      {admin},
		// Typed guest power actions (ADR 0006 P2-01): server and admin
		// may propose (the executor binds the exact guest and sets the
		// risk). Server and admin may commit (decision WA-05 variant (a),
		// 2026-11-07, like guest provisioning below; before: admin only),
		// which dispatches the action only with a permit approved for
		// exactly this execution under the normal approval semantics (the
		// user's security key assertion, user-verified from HIGH, or the
		// CLI in hardened mode). The server can never approve.
		pb.ExecutorService_ProposePVEGuestPower_FullMethodName: {server, admin},
		pb.ExecutorService_CommitPVEGuestPower_FullMethodName:  {server, admin},
		// Typed guest snapshots (ADR 0006 P2-01): exactly like guest
		// power, with the same commit decision (before: admin only).
		pb.ExecutorService_ProposePVEGuestSnapshot_FullMethodName: {server, admin},
		pb.ExecutorService_CommitPVEGuestSnapshot_FullMethodName:  {server, admin},
		// Guest provisioning (ADR 0008 section 3, amendment 2026-11-03,
		// variant B like guest join): server and admin may propose; server
		// and admin may commit, which runs the provisioning only with a
		// permit approved under the normal approval semantics (MEDIUM
		// presence, HIGH user verification, hardened HIGH via CLI). The
		// server starts the run after the WebAuthn approval.
		pb.ExecutorService_ProposePVEGuestProvision_FullMethodName: {server, admin},
		pb.ExecutorService_CommitPVEGuestProvision_FullMethodName:  {server, admin},

		pb.ExecutorService_ListPVERemotes_FullMethodName: {server, admin, peercred.RolePVECollector},
		pb.ExecutorService_ReadPVE_FullMethodName:        {peercred.RolePVECollector, admin},

		// Private registries (ADR 0006, P1-32). Credentials enter only
		// through the admin methods; the server can list metadata and ask
		// for typed reads, but can never supply, rotate or read a
		// credential (no server credential exception).
		pb.ExecutorService_AddPrivateRegistry_FullMethodName:              {admin},
		pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName: {admin},
		pb.ExecutorService_RemovePrivateRegistry_FullMethodName:           {admin},
		pb.ExecutorService_ListPrivateRegistries_FullMethodName:           {server, admin},
		pb.ExecutorService_ReadPrivateRegistry_FullMethodName:             {server, admin},
	}
}

// ValidateReadPVERequest validates a ReadPVE request (ADR 0006, P1-05) and
// returns a codes.InvalidArgument status error for malformed requests.
// ReadPVE (pve_read.go) calls it before anything else; the rules are final:
//
//   - remote_id must be a well-formed slug (pvecontract.ValidRemoteID);
//   - method must be one of the ten typed read methods;
//   - guest methods (GUEST_CONFIG, GUEST_AGENT, SNAPSHOTS, BACKUPS)
//     require a guest parameter with vmid >= 1;
//   - NODES takes an optional node parameter with a valid PVE node name;
//   - remote methods (GUESTS, STORAGE, CLUSTER, TASKS) take no parameter;
//   - METRICS requires a metrics parameter naming one exact metrics target
//     (permit.ProviderMetricsTarget: node, kind node/qemu/lxc, VMID and
//     local guest generation; a node target has VMID 0 and generation 0).
func ValidateReadPVERequest(req *pb.ReadPVERequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "read pve: request is nil")
	}
	if !pvecontract.ValidRemoteID(req.RemoteId) {
		return status.Error(codes.InvalidArgument, "read pve: malformed remote_id")
	}
	switch req.Method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		switch req.Params.(type) {
		case *pb.ReadPVERequest_Guest, *pb.ReadPVERequest_Metrics:
			return status.Error(codes.InvalidArgument, "read pve: nodes method takes only a node parameter")
		}
		if p := req.GetNode(); p != nil && !pvecontract.ValidNodeName(p.Node) {
			return status.Error(codes.InvalidArgument, "read pve: malformed node name")
		}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG,
		pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT,
		pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS,
		pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		if p := req.GetGuest(); p == nil || p.Vmid < 1 {
			return status.Error(codes.InvalidArgument, "read pve: guest method requires a guest parameter with vmid >= 1")
		}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS,
		pb.PVEReadMethod_PVE_READ_METHOD_STORAGE,
		pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER,
		pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
		if req.Params != nil {
			return status.Error(codes.InvalidArgument, "read pve: method takes no parameter")
		}
	case pb.PVEReadMethod_PVE_READ_METHOD_METRICS:
		p := req.GetMetrics()
		if p == nil || !pveMetricsTarget(p).Valid() {
			return status.Error(codes.InvalidArgument, "read pve: metrics method requires one exact metrics target")
		}
	default:
		return status.Error(codes.InvalidArgument, "read pve: unknown method")
	}
	return nil
}

// pveReadCredentialVersion returns the read credential version of r when r
// has a valid read credential, using the same condition as ReadPVE
// (pve_read.go): the read reference is the remote's own read vault ID and
// the version is at least 1. Otherwise it returns 0. Only the version
// number leaves this function, never the reference.
func pveReadCredentialVersion(r executordb.PveRemote) int64 {
	if r.Credentials.ReadRef != PveVaultID(r.RemoteID, PvePurposeRead) || r.Credentials.ReadVersion < 1 {
		return 0
	}
	return r.Credentials.ReadVersion
}

// ListPVERemotes returns public registry metadata for server and collector
// reads. Credential references and values are excluded from this surface;
// only the read credential version number is reported.
func (s *Service) ListPVERemotes(ctx context.Context, _ *pb.ListPVERemotesRequest) (*pb.ListPVERemotesResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	rows, err := s.pveAdmin().ListRemotes(ctx)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ListPVERemotesResponse{}
	for _, r := range rows {
		info := &pb.PVERemoteInfo{RemoteId: r.RemoteID, Name: r.Name, TrustPin: r.TrustPin, TrustGeneration: r.TrustGeneration,
			ReadCredentialVersion: pveReadCredentialVersion(r)}
		switch r.Kind {
		case pvecontract.KindCluster:
			info.Kind = pb.PVERemoteKind_PVE_REMOTE_KIND_CLUSTER
		case pvecontract.KindStandalone:
			info.Kind = pb.PVERemoteKind_PVE_REMOTE_KIND_STANDALONE
		}
		switch r.State {
		case "active":
			info.State = pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE
		case "blocked":
			info.State = pb.PVERemoteState_PVE_REMOTE_STATE_BLOCKED
		}
		for _, ep := range r.Endpoints {
			info.Endpoints = append(info.Endpoints, &pb.PVEEndpoint{Host: ep.Host, Port: uint32(ep.Port)})
		}
		out.Remotes = append(out.Remotes, info)
	}
	return out, nil
}
