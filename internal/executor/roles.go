// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
		pb.ExecutorService_ListReadGrants_FullMethodName:            {server, admin},
		pb.ExecutorService_RevokeReadGrant_FullMethodName:           {server, admin},
		pb.ExecutorService_RunReadGrant_FullMethodName:              {server},
		pb.ExecutorService_ListEvents_FullMethodName:                {server, admin},
		pb.ExecutorService_BackupExecutor_FullMethodName:            {admin},
		// PVE provider reads (ADR 0006, P1-05). The entries are final:
		// pve-collector may call ONLY these two methods; server may list the
		// remotes (metadata); admin may call both. The server never calls
		// ReadPVE: it writes poll requests to the spool and the pve-collector
		// schedules the reads. Remote management (add/rotate/remove/repin) is
		// not part of this surface.
		pb.ExecutorService_ProbePVERemote_FullMethodName:      {admin},
		pb.ExecutorService_AddPVERemote_FullMethodName:        {admin},
		pb.ExecutorService_RotatePVEToken_FullMethodName:      {admin},
		pb.ExecutorService_RemovePVERemote_FullMethodName:     {admin},
		pb.ExecutorService_ListPVEAdminRemotes_FullMethodName: {admin},
		pb.ExecutorService_ProposePVERepin_FullMethodName:     {admin},
		pb.ExecutorService_CommitPVERepin_FullMethodName:      {admin},

		pb.ExecutorService_ListPVERemotes_FullMethodName: {server, admin, peercred.RolePVECollector},
		pb.ExecutorService_ReadPVE_FullMethodName:        {peercred.RolePVECollector, admin},
	}
}

// pveNodeLabelRe matches one DNS label of a PVE node name (mirrors
// pvecontract's check).
var pveNodeLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// validPVENodeName reports whether s is a valid PVE node name (DNS host
// name), mirroring pvecontract's check.
func validPVENodeName(s string) bool {
	if s == "" || len(s) > pvecontract.MaxNodeNameBytes {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !pveNodeLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidateReadPVERequest validates a ReadPVE request (ADR 0006, P1-05) and
// returns a codes.InvalidArgument status error for malformed requests. The
// PVE read handlers must call it before anything else (the pveapi wiring
// lands in P1-07); the rules are final:
//
//   - remote_id must be a well-formed slug (pvecontract.ValidRemoteID);
//   - method must be one of the ten typed read methods;
//   - guest methods (GUEST_CONFIG, GUEST_AGENT, SNAPSHOTS, BACKUPS)
//     require a guest parameter with vmid >= 1;
//   - NODES takes an optional node parameter with a valid PVE node name;
//   - remote methods (GUESTS, STORAGE, CLUSTER, TASKS, METRICS) take no
//     parameter.
func ValidateReadPVERequest(req *pb.ReadPVERequest) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "read pve: request is nil")
	}
	if !pvecontract.ValidRemoteID(req.RemoteId) {
		return status.Error(codes.InvalidArgument, "read pve: malformed remote_id")
	}
	switch req.Method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		if _, ok := req.Params.(*pb.ReadPVERequest_Guest); ok {
			return status.Error(codes.InvalidArgument, "read pve: nodes method does not take a guest parameter")
		}
		if p := req.GetNode(); p != nil && !validPVENodeName(p.Node) {
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
		pb.PVEReadMethod_PVE_READ_METHOD_TASKS,
		pb.PVEReadMethod_PVE_READ_METHOD_METRICS:
		if req.GetNode() != nil || req.GetGuest() != nil {
			return status.Error(codes.InvalidArgument, "read pve: method takes no parameter")
		}
	default:
		return status.Error(codes.InvalidArgument, "read pve: unknown method")
	}
	return nil
}

// ListPVERemotes returns public registry metadata for server and collector
// reads. Credential references and values are excluded from this surface.
func (s *Service) ListPVERemotes(ctx context.Context, _ *pb.ListPVERemotesRequest) (*pb.ListPVERemotesResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	rows, err := s.pveAdmin().ListRemotes(ctx)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ListPVERemotesResponse{}
	for _, r := range rows {
		info := &pb.PVERemoteInfo{RemoteId: r.RemoteID, Name: r.Name, TrustPin: r.TrustPin, TrustGeneration: r.TrustGeneration}
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

// ReadPVE (ADR 0006, P1-05) validates the request with the final rules
// (ValidateReadPVERequest) and returns Unimplemented until the pveapi
// wiring lands (P1-07).
func (s *Service) ReadPVE(_ context.Context, in *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
	if err := ValidateReadPVERequest(in); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.Unimplemented, "read pve: not wired yet (P1-07)")
}
