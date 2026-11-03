// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// This file is the join of a provisioned guest (ADR 0008 section 4,
// PV-06). After first boot the guest is enrolled with the normal
// enrollment path (nebula.host_key.enroll, approval at least HIGH,
// committed by CommitEnroll); the join only decides how the fingerprint
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
// The inventory host and its link to the guest (remote, node, VMID,
// generation) are created on the server (pveinventory.JoinProvisionedGuest).

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

// PveGuestAgentReader reads one file inside a guest through the QEMU guest
// agent over the remote's pinned API channel (PVE: GET
// /nodes/{node}/qemu/{vmid}/agent/file-read). An implementation must not
// return more than maxBytes; the join checks the size again.
type PveGuestAgentReader interface {
	AgentFileRead(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, path string, maxBytes int, read pveapi.TokenSupplier) ([]byte, error)
}

// PveGuestJoinRequest names the provisioned guest and the host it becomes.
type PveGuestJoinRequest struct {
	RemoteID string
	Node     string
	VMID     uint64
	// Generation is the guest incarnation the server links the host to.
	Generation uint64

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
	// Host is the normalized enrollment entry; CommitEnroll takes it as
	// is after approval.
	Host *pb.EnrollHost
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
	}
	e, err := normalizeEnroll(&pb.EnrollHost{HostId: req.HostID, Endpoint: req.Endpoint, SshUser: req.SSHUser, CredentialRef: req.CredentialRef})
	if err != nil {
		return enrollEntry{}, fmt.Errorf("%w: %v", ErrPveJoinInvalid, err)
	}
	return e, nil
}

// Propose establishes the guest's host key (agent read when possible,
// otherwise fingerprint review) and proposes its enrollment for approval.
// It never pins anything: CommitEnroll pins after approval, re-reading the
// key and pinning only the approved one.
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
	}
	if other, err := s.db.HostByFingerprint(fp); err != nil {
		return PveGuestJoinProposal{}, fmt.Errorf("join %s: host key store: %w", e.HostID, err)
	} else if other != "" {
		return PveGuestJoinProposal{}, fmt.Errorf("%w: this host key is pinned for %s (re-key cloned guests)", ErrPveJoinRefused, other)
	}
	e.Fingerprint = fp

	r, params, err := enrollRequest([]enrollEntry{e}, s.clock())
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
		Permit: resp,
	}, nil
}

// agentKey tries the bounded agent read. It returns the key, or nil and a
// fixed-text reason; agent output never reaches the reason or the log.
func (j *PveGuestJoin) agentKey(ctx context.Context, req PveGuestJoinRequest) (ssh.PublicKey, string) {
	if j.Agent == nil || j.Mutations == nil || j.Mutations.DB == nil || j.Mutations.Vault == nil {
		return nil, "no guest agent reader configured"
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
	read, err := j.Mutations.readToken(rm)
	if err != nil {
		return nil, "remote read token unavailable"
	}
	actx, cancel := context.WithTimeout(ctx, pveAgentReadTimeout)
	defer cancel()
	raw, err := j.Agent.AgentFileRead(actx, rm, req.Node, req.VMID, pveJoinHostKeyPath, maxPveAgentHostKeyBytes, read)
	if err != nil {
		return nil, "guest agent unavailable"
	}
	k, err := ParseAgentHostKey(raw)
	if err != nil {
		j.Service.log.Warn("audit", "kind", "guest_join_agent_key_malformed", "remote", req.RemoteID, "node", req.Node,
			"vmid", req.VMID, "bytes", len(raw))
		return nil, "guest agent returned no valid ed25519 host key"
	}
	return k, ""
}
