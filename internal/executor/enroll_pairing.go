// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Pairing and paired commit of one-step enrollment offers (ADR 0013 D1
// steps 5 and 6, D3, D4; spec 08 v25-08-01; EN-08 part 2). The executor,
// not the server, decides whether the code matched: it probes the endpoint
// offering only ssh-ed25519, computes the code from the presented key and
// the offer salt and compares in constant time. A match proposes the
// paired enrollment permit; the commit re-probes and pins only the
// approved key.

// pairedPinnedByPrefix marks a pin made by a paired commit. The host key
// store knows only the sources probe and known_hosts, so the pin record
// carries "paired" in pinned_by; the audit records carry source=paired.
const pairedPinnedByPrefix = "paired:"

// errPairingUnavailable is the refusal for an unknown offer or a foreign
// web session: both look the same.
var errPairingUnavailable = status.Error(codes.NotFound, "enrollment offer not available")

// errNoEd25519 is the probe failure of a host that offers no ed25519 host
// key: not a mismatch.
var errNoEd25519 = errors.New("no ed25519 host key")

// ed25519ProbeKey is only used for its type: probing "like" it offers
// exactly ssh-ed25519 as host key algorithm, so the server cannot
// negotiate ECDSA or RSA instead.
var ed25519ProbeKey = func() ssh.PublicKey {
	k, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		// Unreachable: a 32-byte ed25519 key always converts.
		return nil
	}
	return k
}()

// pairedProposal is the paired permit the executor proposed for an
// offer; the commit presents exactly this binding.
type pairedProposal struct {
	digest  canonical.Digest
	binding canonical.PairedEnroll
}

// setPaired remembers the proposal of an offer (process-local, like the
// paired permit itself).
func (st *enrollOfferState) setPaired(h [sha256.Size]byte, p pairedProposal) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.offers == nil {
		st.offers = map[[sha256.Size]byte]*offerEntry{}
	}
	e := st.offers[h]
	if e == nil {
		st.seq++
		e = &offerEntry{seq: st.seq}
		st.offers[h] = e
	}
	e.paired = &p
}

// paired returns the proposal of an offer, nil if none.
func (st *enrollOfferState) paired(h [sha256.Size]byte) *pairedProposal {
	st.mu.Lock()
	defer st.mu.Unlock()
	if e := st.offers[h]; e != nil && e.paired != nil {
		p := *e.paired
		return &p
	}
	return nil
}

// probeEd25519 reads the ed25519 host key of ep, offering only
// ssh-ed25519 as host key algorithm.
func (s *Service) probeEd25519(ctx context.Context, ep sshtransport.Endpoint) (ssh.PublicKey, error) {
	if ed25519ProbeKey == nil {
		return nil, errors.New("ed25519 probe key unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, enrollProbeTimeout)
	defer cancel()
	k, err := s.transport.ProbeAs(ctx, ep, ed25519ProbeKey)
	if err != nil {
		if noEd25519Offered(err) {
			return nil, errNoEd25519
		}
		return nil, err
	}
	if k.Type() != ssh.KeyAlgoED25519 {
		return nil, errNoEd25519
	}
	return k, nil
}

// noEd25519Offered recognizes the host key algorithm negotiation failure
// of a probe offering only ssh-ed25519.
func noEd25519Offered(err error) bool {
	var te *sshtransport.Error
	if !errors.As(err, &te) {
		return false
	}
	for _, a := range te.Attempts {
		var ne *ssh.AlgorithmNegotiationError
		if errors.As(a.Err, &ne) && ne.What == "host key" {
			return true
		}
		if a.Err != nil && strings.Contains(a.Err.Error(), "no common algorithm for host key") {
			return true
		}
	}
	return false
}

// probeDetail is the operator-facing reason of a failed probe.
func probeDetail(err error) string {
	if errors.Is(err, errNoEd25519) {
		return "no ed25519 host key at this endpoint (not a mismatch)"
	}
	return "probe failed: " + string(sshtransport.ClassOf(err)) + " (not a mismatch)"
}

// pairingOffer loads the offer of a submit or commit and checks the
// session binding. Unknown offer and foreign session are the same refusal.
func (s *Service) pairingOffer(op, idHashHex string, binding []byte) ([sha256.Size]byte, executordb.Offer, error) {
	idHash, ok := parseOfferIDHash(idHashHex)
	if !ok {
		return idHash, executordb.Offer{}, status.Errorf(codes.InvalidArgument, "%s: offer ID hash must be 64 lowercase hex characters", op)
	}
	s.sweepOffers()
	o, err := s.db.Offer(idHash)
	if errors.Is(err, executordb.ErrOfferNotFound) {
		return idHash, o, errPairingUnavailable
	}
	if err != nil {
		return idHash, o, s.adminStoreError(op, err)
	}
	if !sessionMatches(o, binding) {
		return idHash, o, errPairingUnavailable
	}
	return idHash, o, nil
}

// endOfferFailed moves an offer from from to failed and drops its
// process-local state; it reports whether this call ended it.
func (s *Service) endOfferFailed(h [sha256.Size]byte, from executordb.OfferState) bool {
	err := s.db.EndOffer(h, from, executordb.OfferFailed)
	if err == nil || errors.Is(err, executordb.ErrOfferWipeIncomplete) {
		s.offers.final(h)
		return true
	}
	s.log.Error("enroll offer: fail offer", "offer", offerLog(h), "err", err)
	return false
}

// offerState re-reads the state of an offer for a response.
func (s *Service) offerState(h [sha256.Size]byte) string {
	o, err := s.db.Offer(h)
	if err != nil {
		return ""
	}
	return string(o.State)
}

// SubmitPairingCode checks a pairing code against the key the endpoint
// presents (server role, creating web session only).
func (s *Service) SubmitPairingCode(ctx context.Context, req *pb.SubmitPairingCodeRequest) (*pb.SubmitPairingCodeResponse, error) {
	const op = "submit pairing code"
	if len(req.GetOfferIdHash()) != 2*sha256.Size {
		return nil, status.Errorf(codes.InvalidArgument, "%s: offer ID hash must be 64 lowercase hex characters", op)
	}
	ep, err := sshtransport.ParseEndpoint(req.GetEndpoint())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: malformed endpoint", op)
	}
	inv := req.GetInventoryEndpoints()
	if len(inv) > sshtransport.MaxEndpoints {
		return nil, status.Errorf(codes.InvalidArgument, "%s: at most %d inventory endpoints", op, sshtransport.MaxEndpoints)
	}
	toAdd := true
	for _, s := range inv {
		p, err := sshtransport.ParseEndpoint(s)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%s: malformed inventory endpoint", op)
		}
		if p.String() == ep.String() {
			toAdd = false
		}
	}
	idHash, o, err := s.pairingOffer(op, req.GetOfferIdHash(), req.GetSessionBinding())
	if err != nil {
		return nil, err
	}
	if o.State != executordb.OfferDownloaded {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: offer is %s, not downloaded", op, o.State)
	}
	if _, pinned, err := s.db.HostKey(o.HostID); err != nil {
		return nil, s.adminStoreError(op, err)
	} else if pinned {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: host is already pinned or blocked; use the re-pin flow", op)
	}
	resp := &pb.SubmitPairingCodeResponse{Endpoint: ep.String(), EndpointToAdd: toAdd,
		RejectedCodes: int32(o.RejectedCodes), Probes: int32(o.Probes), State: string(o.State)}

	// 1. Code format, before any probe.
	code, perr := pairing.Parse(req.GetCode())
	if perr != nil {
		if !o.CodeSubmittedAt.IsZero() {
			return nil, status.Errorf(codes.InvalidArgument, "%s: %v", op, perr)
		}
		n, err := s.db.CountOfferRejectedCode(idHash)
		switch {
		case errors.Is(err, executordb.ErrOfferLimit):
			s.endOfferFailed(idHash, executordb.OfferDownloaded)
			return nil, status.Errorf(codes.FailedPrecondition, "%s: too many malformed codes; create a new offer", op)
		case errors.Is(err, executordb.ErrOfferState), errors.Is(err, executordb.ErrOfferExpired):
			return nil, status.Errorf(codes.FailedPrecondition, "%s: offer no longer accepts codes", op)
		case err != nil:
			return nil, s.adminStoreError(op, err)
		}
		s.log.Warn("audit", "kind", "enroll_code_rejected", "offer", offerLog(idHash), "host", o.HostID,
			"reason", perr.Error(), "rejected_codes", n)
		resp.Outcome, resp.Detail, resp.RejectedCodes = pb.PairingOutcome_PAIRING_OUTCOME_CODE_REJECTED, perr.Error(), int32(n)
		if n >= executordb.OfferMaxRejectedCodes && s.endOfferFailed(idHash, executordb.OfferDownloaded) {
			s.log.Warn("audit", "kind", "enroll_offer_failed", "offer", offerLog(idHash), "reason", "too many malformed codes")
		}
		resp.State = s.offerState(idHash)
		return resp, nil
	}

	// 2. The one well-formed submission, then one counted probe.
	if o.CodeSubmittedAt.IsZero() {
		err := s.db.ClaimOfferSubmission(idHash)
		if errors.Is(err, executordb.ErrOfferState) {
			// A concurrent submission claimed it; continue only if the
			// offer is still waiting for a probe.
			if o, err = s.db.Offer(idHash); err != nil || o.State != executordb.OfferDownloaded || o.CodeSubmittedAt.IsZero() {
				return nil, status.Errorf(codes.FailedPrecondition, "%s: offer no longer accepts codes", op)
			}
		} else if err != nil {
			return nil, s.claimError(op, err)
		}
	}
	n, err := s.db.CountOfferProbe(idHash)
	if errors.Is(err, executordb.ErrOfferLimit) {
		if s.endOfferFailed(idHash, executordb.OfferDownloaded) {
			s.log.Warn("audit", "kind", "enroll_offer_failed", "offer", offerLog(idHash), "reason", "probe limit reached")
		}
		return nil, status.Errorf(codes.ResourceExhausted, "%s: probe limit reached; create a new offer", op)
	}
	if err != nil {
		return nil, s.claimError(op, err)
	}
	resp.Probes = int32(n)

	// 3. Probe, offering only ssh-ed25519.
	k, err := s.probeEd25519(ctx, ep)
	if err != nil {
		resp.Outcome, resp.Detail, resp.State = pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED, probeDetail(err), s.offerState(idHash)
		s.log.Info("audit", "kind", "enroll_probe_failed", "offer", offerLog(idHash), "host", o.HostID,
			"endpoint", ep.String(), "detail", resp.Detail, "probes", n)
		return resp, nil
	}
	fp := sshtransport.Fingerprint(k)
	resp.Fingerprint, resp.KeyType = fp, k.Type()
	want, err := pairing.Compute(o.Salt, k.Marshal())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s: compute code", op)
	}

	// 4. Mismatch: the offer ends; there is no second submission.
	if !pairing.Equal(code, want) {
		s.endOfferFailed(idHash, executordb.OfferDownloaded)
		s.log.Error("audit", "kind", "enroll_code_mismatch", "offer", offerLog(idHash), "host", o.HostID,
			"endpoint", ep.String(), "presented", fp, "key_type", k.Type())
		resp.Outcome, resp.Notify, resp.State = pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH, true, s.offerState(idHash)
		return resp, nil
	}

	// 5. Match: propose the paired enrollment permit.
	if other, err := s.db.HostByFingerprint(fp); err != nil {
		return nil, s.adminStoreError(op, err)
	} else if other != "" {
		if s.endOfferFailed(idHash, executordb.OfferDownloaded) {
			s.log.Warn("audit", "kind", "enroll_offer_failed", "offer", offerLog(idHash), "reason", "host key pinned for another host",
				"presented", fp, "other", other)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "%s: this host key is pinned for %s", op, other)
	}
	if err := s.db.ProposeOfferPairing(idHash); err != nil {
		return nil, s.claimError(op, err)
	}
	p, err := s.auth.ProposePaired(canonical.PairedEnroll{
		OfferIDHash: hex.EncodeToString(idHash[:]), HostID: o.HostID, Endpoint: ep.String(), EndpointToAdd: toAdd,
		SSHUser: o.SSHUser, CredentialRef: o.CredentialRef, HostKeyFingerprint: fp, CodeMatched: true,
		PairingCode: code.String(), ExpiryUnix: s.clock().Add(canonical.MaxPairedEnrollLifetime).Unix(),
	})
	if err != nil {
		if s.endOfferFailed(idHash, executordb.OfferPairingProposed) {
			s.log.Warn("audit", "kind", "enroll_offer_failed", "offer", offerLog(idHash), "reason", "paired permit proposal refused")
		}
		return nil, toStatus(err)
	}
	s.offers.setPaired(idHash, pairedProposal{digest: p.Digest, binding: p.Binding})
	s.log.Warn("audit", "kind", "enroll_paired_proposed", "offer", offerLog(idHash), "host", o.HostID, "endpoint", ep.String(),
		"endpoint_to_add", toAdd, "fingerprint", fp, "digest", p.Digest.String())
	resp.Outcome, resp.State = pb.PairingOutcome_PAIRING_OUTCOME_MATCHED, string(executordb.OfferPairingProposed)
	resp.Permit = &pb.PairedPermitInfo{Digest: p.Digest.String(), Challenge: p.Challenge, Canonical: p.Canonical,
		ApprovalExpiryUnix: p.ApprovalExpiry.Unix()}
	return resp, nil
}

// claimError maps an offer-store refusal of a pairing step.
func (s *Service) claimError(op string, err error) error {
	switch {
	case errors.Is(err, executordb.ErrOfferExpired):
		return status.Errorf(codes.FailedPrecondition, "%s: offer expired", op)
	case errors.Is(err, executordb.ErrOfferState), errors.Is(err, executordb.ErrOfferLimit):
		return status.Errorf(codes.FailedPrecondition, "%s: offer no longer accepts codes", op)
	}
	return s.adminStoreError(op, err)
}

// CommitPairedEnroll pins the key of an approved paired enrollment (server
// role, creating web session only).
func (s *Service) CommitPairedEnroll(ctx context.Context, req *pb.CommitPairedEnrollRequest) (*pb.CommitPairedEnrollResponse, error) {
	const op = "commit paired enroll"
	d, err := canonical.ParseDigest(req.GetPermitDigest())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: %v", op, err)
	}
	idHash, o, err := s.pairingOffer(op, req.GetOfferIdHash(), req.GetSessionBinding())
	if err != nil {
		return nil, err
	}
	if o.State != executordb.OfferPairingProposed {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: offer is %s, not pairing_proposed", op, o.State)
	}
	pp := s.offers.paired(idHash)
	if pp == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s: no paired permit is known for this offer; create a new offer", op)
	}
	if pp.digest != d {
		return nil, status.Errorf(codes.PermissionDenied, "%s: the permit does not belong to this offer", op)
	}
	b := pp.binding
	// The permit authorizes exactly the binding proposed for this offer.
	if _, err := s.auth.ConsumePaired(d, b); err != nil {
		return nil, toStatus(err)
	}
	resp := &pb.CommitPairedEnrollResponse{HostId: b.HostID}
	fail := func(reason string, attrs ...any) {
		if s.endOfferFailed(idHash, executordb.OfferPairingProposed) {
			s.log.Warn("audit", append([]any{"kind", "enroll_offer_failed", "offer", offerLog(idHash), "reason", reason}, attrs...)...)
		}
		resp.State = s.offerState(idHash)
	}
	ep, err := sshtransport.ParseEndpoint(b.Endpoint)
	if err != nil {
		fail("bound endpoint unparsable")
		resp.Error = "the bound endpoint is malformed; nothing pinned"
		return resp, nil
	}

	// Re-probe: pin only if the endpoint still presents the approved key.
	k, err := s.probeEd25519(ctx, ep)
	if err != nil {
		resp.Error = probeDetail(err) + "; nothing pinned (create a new offer)"
		fail("commit probe failed")
		return resp, nil
	}
	if got := sshtransport.Fingerprint(k); got != b.HostKeyFingerprint {
		s.log.Error("audit", "kind", "enroll_key_changed", "offer", offerLog(idHash), "host", b.HostID, "endpoint", b.Endpoint,
			"digest", d.String(), "approved", b.HostKeyFingerprint, "presented", got)
		resp.Error, resp.Notify = "the endpoint now presents "+got+", not the approved key; nothing pinned", true
		fail("key changed before the commit")
		return resp, nil
	}
	by := pairedPinnedByPrefix + d.String()[:16]
	pinned, err := s.db.PinHostKey(executordb.HostKey{HostID: b.HostID, PublicKey: k.Marshal(), User: b.SSHUser,
		CredentialRef: b.CredentialRef, Source: executordb.SourceProbe, PinnedBy: by})
	switch {
	case errors.Is(err, executordb.ErrHostPinned):
		resp.Error = "pinned meanwhile; left as it is"
		fail("host pinned meanwhile")
		return resp, nil
	case errors.Is(err, executordb.ErrInvalid):
		resp.Error = "refused: " + err.Error()
		fail("pin refused")
		return resp, nil
	case err != nil:
		return nil, s.adminStoreError(op, err)
	}
	// The offer completes in the same step; an offer revoked or expired
	// meanwhile gets no pin and adds nothing.
	if err := s.db.CompleteOffer(idHash); err != nil && !errors.Is(err, executordb.ErrOfferWipeIncomplete) {
		if _, _, uerr := s.db.UnpinHostKey(b.HostID, pinned.Fingerprint); uerr != nil {
			s.log.Error("audit", "kind", "store_error", "op", "undo_paired_pin", "host", b.HostID, "detail", uerr.Error())
			return nil, s.adminStoreError(op, uerr)
		}
		s.log.Warn("audit", "kind", "enroll_pin_undone", "offer", offerLog(idHash), "host", b.HostID, "reason", "offer ended before the commit completed")
		resp.Error, resp.State = "the offer ended before the commit completed; nothing pinned", s.offerState(idHash)
		return resp, nil
	}
	s.offers.final(idHash)
	resp.Pinned, resp.Fingerprint, resp.State = true, pinned.Fingerprint, string(executordb.OfferEnrolled)
	s.log.Info("audit", "kind", "host_key_pinned", "by", by, "host", pinned.HostID, "fingerprint", pinned.Fingerprint,
		"user", pinned.User, "credential", pinned.CredentialRef, "source", "paired")
	s.log.Warn("audit", "kind", "host_enrolled", "offer", offerLog(idHash), "host", b.HostID, "endpoint", b.Endpoint,
		"fingerprint", pinned.Fingerprint, "digest", d.String(), "source", "paired")
	if b.EndpointToAdd {
		resp.EndpointAdded = b.Endpoint
		s.log.Warn("audit", "kind", "inventory_endpoint_added", "offer", offerLog(idHash), "host", b.HostID,
			"endpoint", b.Endpoint, "source", "paired")
	}
	// A first login shows that the enrollment script ran on the host. The
	// connection restricts HostKeyAlgorithms to the pinned type.
	if s.keys.Unlocked() {
		lctx, cancel := context.WithTimeout(ctx, enrollProbeTimeout)
		c, err := s.Connect(lctx, b.HostID, pinned.Fingerprint, []sshtransport.Endpoint{ep})
		cancel()
		if err == nil {
			resp.LoginOk = true
			c.Close()
		} else {
			resp.LoginDetail = "login failed: " + string(sshtransport.ClassOf(err)) + " (did the enrollment script run on the host?)"
		}
	}
	return resp, nil
}
