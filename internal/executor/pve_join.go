// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// This file is the join of a provisioned guest (ADR 0008 section 4,
// PV-06). After first boot the guest is enrolled with the normal
// enrollment path (nebula.host_key.enroll, approval at least HIGH,
// committed by CommitGuestJoin); the join only decides how the fingerprint
// the approval binds was established:
//
//   - agent read: the executor reads /etc/ssh/ssh_host_ed25519_key.pub
//     through the QEMU guest agent over the remote's authenticated,
//     pinned PVE channel (bounded in time and size) and the SSH endpoint
//     must present exactly that key. No trust on first use; a different
//     key stops the join.
//   - fingerprint review (the default for vendor cloud images, ADR 0008
//     decision 1): without a usable agent the probed fingerprint is shown
//     for review, as for every other enrollment; the bootstrap module
//     installs qemu-guest-agent afterwards.
//
// The approval binds, next to the normal enrollment entry, the guest
// (remote, node, VMID, generation, name) and the join method, so the
// approver sees whether the key was agent-verified, and the commit
// (CommitGuestJoin) must repeat exactly that binding. The inventory host
// and its link to the guest are created on the server
// (pveinventory.JoinProvisionedGuest) from the committed binding only.
//
// Before the agent is read, the live guest at (node, VMID) must carry the
// provisioned name, so a VMID reused by another guest is never read and
// accepted as agent-verified.

// Join methods reported in PveGuestJoinProposal.Method.
const (
	// PveJoinMethodAgent means the guest agent reported the key and the
	// endpoint presented the same key.
	PveJoinMethodAgent = "agent"
	// PveJoinMethodReview means the operator must review the probed
	// fingerprint.
	PveJoinMethodReview = "review"
)

// Guest join limits.
const (
	// pveJoinHostKeyPath is the only file the join reads through the
	// guest agent.
	pveJoinHostKeyPath = "/etc/ssh/ssh_host_ed25519_key.pub"
	// maxPveAgentHostKeyBytes bounds the agent's answer: one ed25519
	// public key line is about 100 bytes plus a comment.
	maxPveAgentHostKeyBytes = 1024
	// pveAgentReadTimeout bounds the agent read; the join then falls back
	// to fingerprint review.
	pveAgentReadTimeout = 10 * time.Second
)

var (
	// ErrPveJoinInvalid is returned for a malformed join request; nothing
	// is read or proposed.
	ErrPveJoinInvalid = errors.New("executor: invalid guest join request")
	// ErrPveAgentHostKey is returned for guest agent output that is not
	// exactly one plain ed25519 public key line.
	ErrPveAgentHostKey = errors.New("executor: guest agent host key malformed")
	// ErrPveJoinKeyMismatch is returned when the guest's SSH endpoint
	// presents another key than its guest agent reported.
	ErrPveJoinKeyMismatch = errors.New("executor: the guest's SSH endpoint presents another host key than its guest agent reported")
	// ErrPveJoinRefused is returned when the host is already pinned or its
	// key is pinned for another host.
	ErrPveJoinRefused = errors.New("executor: guest join refused")
	// ErrPveJoinUnreachable is returned when the guest's SSH endpoint does
	// not present a usable host key.
	ErrPveJoinUnreachable = errors.New("executor: guest SSH endpoint presents no usable host key")
)

// PveGuestIdentity is the live identity of a guest incarnation.
type PveGuestIdentity struct {
	Name string
	// UUID is the guest's UUID as the node's guest list reports it (the
	// VMID-reuse hint the inventory derives its generations from).
	UUID string
}

// PveGuestAgentReader reads a provisioned guest over the remote's pinned
// API channel. pveGuestAgentAPI is the production implementation.
type PveGuestAgentReader interface {
	// LiveGuest returns the identity of the QEMU guest vmid on node from
	// the node's live guest list (PVE: GET /nodes/{node}/qemu) with the
	// read token; an error means the guest is not there.
	LiveGuest(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, read pveapi.TokenSupplier) (PveGuestIdentity, error)
	// AgentFileRead reads one file inside the guest through the QEMU guest
	// agent (PVE: GET /nodes/{node}/qemu/{vmid}/agent/file-read) with the
	// scoped guest-agent credential, never the read token. It must not
	// return more than maxBytes and must fail on a truncated read; the
	// join checks the size again.
	AgentFileRead(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, path string, maxBytes int, agent pveapi.TokenSupplier) ([]byte, error)
}

// PveGuestAgentCredentials supplies a remote's scoped guest-agent
// credential (a PVE token limited to the guest agent file read of
// provisioned guests). It is separate from the read and action tokens.
// No implementation exists yet: whether such a credential or a spec
// change is the way to an agent-verified join is open (maintainer
// decision), so production joins use fingerprint review.
type PveGuestAgentCredentials interface {
	// AgentToken returns the credential of rm; ok is false when none is
	// configured.
	AgentToken(rm executordb.PveRemote) (tok pveapi.TokenSupplier, ok bool, err error)
}

// PveGuestJoinRequest names the provisioned guest and the host it becomes.
type PveGuestJoinRequest struct {
	RemoteID string
	Node     string
	VMID     uint64
	// Generation is the guest incarnation the server links the host to.
	Generation uint64
	// GuestName is the name the provisioning gave the guest; the live
	// guest must carry it before its agent is read.
	GuestName string
	// GuestUUID is the incarnation's UUID as the inventory recorded it
	// (lowercase); empty disables the agent read.
	GuestUUID string

	HostID string
	// Endpoint is the guest's SSH endpoint (its IPAM address or DHCP lease).
	Endpoint      string
	SSHUser       string
	CredentialRef string
}

// PveGuestJoinProposal is the enrollment proposed for a provisioned guest.
type PveGuestJoinProposal struct {
	// Method is PveJoinMethodAgent or PveJoinMethodReview.
	Method      string
	Fingerprint string
	KeyType     string
	// AgentDetail says, in fixed text, why the agent read was not used.
	AgentDetail string
	// Host is the normalized enrollment entry; CommitGuestJoin takes it
	// as is after approval.
	Host *pb.EnrollHost
	// Guest is the guest binding the approval covers.
	Guest *pb.GuestJoinTarget
	// Permit is the pending enrollment approval.
	Permit *pb.ProposeExecutionResponse
}

// PveGuestJoin proposes the enrollment of provisioned guests.
type PveGuestJoin struct {
	// Service probes the guest, checks the pins and proposes the
	// enrollment.
	Service *Service
	// Mutations is the PVE registry and vault the agent read uses; nil
	// means fingerprint review only.
	Mutations *PveMutations
	// Agent reads the guest's host key; nil means fingerprint review only
	// (the default until the bootstrap module installed the agent).
	Agent PveGuestAgentReader
	// AgentCredentials supplies the scoped guest-agent credential; nil
	// (production today) disables the agent read: every join is a
	// fingerprint review.
	AgentCredentials PveGuestAgentCredentials
}

// ParseAgentHostKey validates guest agent output as exactly one plain
// "ssh-ed25519 base64 [comment]" line (an optional final newline, no
// options, no control characters, valid UTF-8, at most
// maxPveAgentHostKeyBytes) and returns the key. The comment is dropped.
func ParseAgentHostKey(raw []byte) (ssh.PublicKey, error) {
	if len(raw) == 0 || len(raw) > maxPveAgentHostKeyBytes {
		return nil, fmt.Errorf("%w: size %d outside 1..%d", ErrPveAgentHostKey, len(raw), maxPveAgentHostKeyBytes)
	}
	line := bytes.TrimSuffix(raw, []byte("\n"))
	if !utf8.Valid(line) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrPveAgentHostKey)
	}
	for _, r := range string(line) {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return nil, fmt.Errorf("%w: control character", ErrPveAgentHostKey)
		}
	}
	k, _, options, rest, err := ssh.ParseAuthorizedKey(line)
	if err != nil || len(options) != 0 || len(rest) != 0 {
		return nil, fmt.Errorf("%w: not one plain public key line", ErrPveAgentHostKey)
	}
	if k.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%w: key type %s is not ed25519", ErrPveAgentHostKey, k.Type())
	}
	if err := sshtransport.CheckHostKey(k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPveAgentHostKey, err)
	}
	return k, nil
}

// validate checks the request before any I/O.
func (req PveGuestJoinRequest) validate() (enrollEntry, error) {
	switch {
	case !pvecontract.ValidRemoteID(req.RemoteID):
		return enrollEntry{}, fmt.Errorf("%w: remote", ErrPveJoinInvalid)
	case !pvecontract.ValidNodeName(req.Node):
		return enrollEntry{}, fmt.Errorf("%w: node", ErrPveJoinInvalid)
	case req.VMID < pvecontract.MinVMID || req.VMID > pvecontract.MaxVMID:
		return enrollEntry{}, fmt.Errorf("%w: vmid out of range", ErrPveJoinInvalid)
	case req.Generation < 1:
		return enrollEntry{}, fmt.Errorf("%w: generation", ErrPveJoinInvalid)
	case !validDNSName(req.GuestName):
		return enrollEntry{}, fmt.Errorf("%w: guest name", ErrPveJoinInvalid)
	case req.GuestUUID != "" && !pveGuestUUIDRe.MatchString(req.GuestUUID):
		return enrollEntry{}, fmt.Errorf("%w: guest uuid", ErrPveJoinInvalid)
	}
	e, err := normalizeEnroll(&pb.EnrollHost{HostId: req.HostID, Endpoint: req.Endpoint, SshUser: req.SSHUser, CredentialRef: req.CredentialRef})
	if err != nil {
		return enrollEntry{}, fmt.Errorf("%w: %v", ErrPveJoinInvalid, err)
	}
	return e, nil
}

// Propose establishes the guest's host key (agent read when possible,
// otherwise fingerprint review) and proposes its enrollment for approval.
// It never pins anything: Commit pins after approval, re-reading the key
// and pinning only the approved one.
func (j *PveGuestJoin) Propose(ctx context.Context, req PveGuestJoinRequest) (PveGuestJoinProposal, error) {
	s := j.Service
	if s == nil {
		return PveGuestJoinProposal{}, errors.New("executor: pve guest join: Service is required")
	}
	e, err := req.validate()
	if err != nil {
		return PveGuestJoinProposal{}, err
	}
	if _, err := s.keys.Signer(e.Credential); errors.Is(err, keyring.ErrUnknownRef) {
		return PveGuestJoinProposal{}, fmt.Errorf("%w: credential not loaded in the keyring", ErrPveJoinInvalid)
	}
	if _, ok, err := s.db.HostKey(e.HostID); err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: host key store: %w", e.HostID, err)
	} else if ok {
		return PveGuestJoinProposal{}, fmt.Errorf("%w: host %s is already pinned", ErrPveJoinRefused, e.HostID)
	}

	agentKey, detail := j.agentKey(ctx, req)
	k, err := s.probeKey(ctx, e.Endpoint)
	if err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("%w: %s", ErrPveJoinUnreachable, sshtransport.ClassOf(err))
	}
	fp := sshtransport.Fingerprint(k)
	method := PveJoinMethodReview
	if agentKey != nil {
		if !bytes.Equal(agentKey.Marshal(), k.Marshal()) {
			s.log.Error("audit", "kind", "guest_join_key_mismatch", "remote", req.RemoteID, "node", req.Node,
				"vmid", req.VMID, "generation", req.Generation, "host", e.HostID, "endpoint", e.Endpoint,
				"agent", sshtransport.Fingerprint(agentKey), "presented", fp)
			return PveGuestJoinProposal{}, ErrPveJoinKeyMismatch
		}
		method, detail = PveJoinMethodAgent, ""
	} else {
		s.log.Warn("audit", "kind", "guest_join_agent_fallback", "remote", req.RemoteID, "node", req.Node,
			"vmid", req.VMID, "generation", req.Generation, "host", e.HostID, "reason", detail)
	}
	if other, err := s.db.HostByFingerprint(fp); err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: host key store: %w", e.HostID, err)
	} else if other != "" {
		return PveGuestJoinProposal{}, fmt.Errorf("%w: this host key is pinned for %s (re-key cloned guests)", ErrPveJoinRefused, other)
	}
	e.Fingerprint = fp

	b := pveGuestBinding{RemoteID: req.RemoteID, Node: req.Node, VMID: req.VMID, Generation: req.Generation,
		Name: req.GuestName, UUID: req.GuestUUID, JoinMethod: method}
	r, params, err := guestJoinRequest(e, b, s.clock())
	if err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: enroll request: %w", e.HostID, err)
	}
	res, err := s.auth.ProposeAtLeastMinimum(r, params)
	if err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: propose: %w", e.HostID, err)
	}
	resp, err := s.permitResponse(res.Permit)
	if err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: permit: %w", e.HostID, err)
	}
	s.log.Warn("audit", "kind", "guest_join_proposed", "digest", res.Permit.Digest.String(),
		"remote", req.RemoteID, "node", req.Node, "vmid", req.VMID, "generation", req.Generation,
		"host", e.HostID, "fingerprint", fp, "method", method, "risk", string(res.Permit.Request.RiskClass))
	return PveGuestJoinProposal{
		Method: method, Fingerprint: fp, KeyType: k.Type(), AgentDetail: detail,
		Host: &pb.EnrollHost{HostId: e.HostID, Endpoint: e.Endpoint, SshUser: e.User, CredentialRef: e.Credential,
			Fingerprint: fp, KeyType: k.Type()},
		Guest:  b.proto(),
		Permit: resp,
	}, nil
}

// pveGuestUUIDRe is the lowercase guest UUID form the inventory stores.
var pveGuestUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Fixed reasons for the fallback to fingerprint review.
const (
	pveJoinNoReader     = "no guest agent reader configured"
	pveJoinNoCredential = "no scoped guest-agent credential configured for the remote (the read token has no guest file access: ADR 0006, spec 06)"
)

// agentKey tries the bounded agent read. It returns the key, or nil and a
// fixed-text reason; agent output never reaches the reason or the log.
//
// The read token is never used for the agent: ADR 0006 gives neither
// default token guest file access and spec 06 forbids VM.Monitor on the
// read token. The agent read needs a separately configured, scoped
// guest-agent credential (PveGuestJoin.AgentCredentials); without one the
// join always falls back to fingerprint review. The read token is used
// only for the guest list (incarnation identity) under a read grant
// covering "guests".
func (j *PveGuestJoin) agentKey(ctx context.Context, req PveGuestJoinRequest) (ssh.PublicKey, string) {
	if j.Agent == nil || j.Mutations == nil || j.Mutations.DB == nil || j.Mutations.Vault == nil {
		return nil, pveJoinNoReader
	}
	if j.AgentCredentials == nil {
		return nil, pveJoinNoCredential
	}
	s := j.Service
	if err := s.checkNotRecovering(); err != nil {
		return nil, "executor recovery pending"
	}
	if req.GuestUUID == "" {
		return nil, "the provisioned guest has no recorded incarnation identity"
	}
	rm, ok, err := j.Mutations.DB.GetRemote(req.RemoteID)
	switch {
	case err != nil:
		return nil, "remote registry unavailable"
	case !ok || rm.State != executordb.StateActive:
		return nil, "remote not active"
	case rm.Credentials.ReadRef != PveVaultID(rm.RemoteID, PvePurposeRead) || rm.Credentials.ReadVersion < 1:
		return nil, "remote read token not registered"
	}
	agentTok, ok, err := j.AgentCredentials.AgentToken(rm)
	switch {
	case err != nil:
		return nil, "guest-agent credential unavailable"
	case !ok || agentTok == nil:
		return nil, pveJoinNoCredential
	}
	read, err := j.Mutations.readToken(rm)
	if err != nil {
		return nil, "remote read token unavailable"
	}
	// The identity reads use the read token, so they need a read grant
	// like every other read-token request (ReadPVE).
	claim, err := s.auth.AuthorizeProviderRead(permit.ProviderRead{RemoteID: rm.RemoteID, Method: permit.ProviderMethodGuests,
		TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration, CredentialVersion: rm.Credentials.ReadVersion})
	if err != nil {
		return nil, "no read grant covers the guest list"
	}
	actx, cancel := context.WithTimeout(ctx, pveAgentReadTimeout)
	defer cancel()
	// The VMID must hold the provisioned incarnation (name and UUID, the
	// identity the inventory derives its generations from) before and
	// after the read, so neither a reused VMID nor a swap between the
	// calls is read as the provisioned guest.
	if reason := j.sameGuest(actx, rm, req, read, "before"); reason != "" {
		return nil, reason
	}
	raw, err := j.Agent.AgentFileRead(actx, rm, req.Node, req.VMID, pveJoinHostKeyPath, maxPveAgentHostKeyBytes, agentTok)
	if err != nil {
		return nil, "guest agent unavailable"
	}
	if reason := j.sameGuest(actx, rm, req, read, "after"); reason != "" {
		return nil, reason
	}
	if err := claim.Check(); err != nil {
		return nil, "the read grant was revoked during the read"
	}
	k, err := ParseAgentHostKey(raw)
	if err != nil {
		s.log.Warn("audit", "kind", "guest_join_agent_key_malformed", "remote", req.RemoteID, "node", req.Node,
			"vmid", req.VMID, "bytes", len(raw))
		return nil, "guest agent returned no valid ed25519 host key"
	}
	return k, ""
}

// sameGuest checks the live incarnation at (node, VMID) against the
// provisioned guest and returns a fixed reason when it differs.
func (j *PveGuestJoin) sameGuest(ctx context.Context, rm executordb.PveRemote, req PveGuestJoinRequest, read pveapi.TokenSupplier, when string) string {
	live, err := j.Agent.LiveGuest(ctx, rm, req.Node, req.VMID, read)
	if err != nil {
		return "live guest not readable"
	}
	if live.Name != req.GuestName || strings.ToLower(live.UUID) != req.GuestUUID {
		j.Service.log.Warn("audit", "kind", "guest_join_identity_mismatch", "remote", req.RemoteID, "node", req.Node,
			"vmid", req.VMID, "generation", req.Generation, "when", when)
		return "the live guest is not the provisioned guest"
	}
	return ""
}
