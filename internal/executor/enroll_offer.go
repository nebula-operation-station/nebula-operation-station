// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// One-step enrollment offers (ADR 0013 D1, D2, D7; spec 03 v25-03-02 to
// v25-03-05, EN-08 part 1). The executor creates the offer, keeps only the
// SHA-256 of its ID, renders the script on demand and checks every render
// against a stored hash. The offer store (executordb) holds the offer row;
// the render inputs live in this process (see enrollOfferState).

// Limits of the offer RPCs (E9). The offer store enforces the per-executor
// limits (executordb.OfferMaxLive, OfferMaxLiveNetBird, OfferMaxPerHour)
// and the lifetime; the renderer enforces enrollscript.MaxScriptBytes.
const (
	// EnrollOfferIDBytes is the offer ID entropy: 160 bits from
	// crypto/rand, 32 characters of lowercase base32 without padding.
	EnrollOfferIDBytes = 20
	// EnrollOfferIDLen is the length of an offer ID.
	EnrollOfferIDLen = 32
	// EnrollSessionBindingMinLen and EnrollSessionBindingMaxLen bound the
	// opaque web-session token a request carries.
	EnrollSessionBindingMinLen = 16
	EnrollSessionBindingMaxLen = 64
	// EnrollOfferIndexMax bounds the process-local offer index.
	EnrollOfferIndexMax = 256
	// EnrollNetBirdSetupKeyLifetime is the setup-key expiry bound into a
	// NetBird offer permit, counted from the proposal (ADR 0013 D6: at
	// most 1 h).
	EnrollNetBirdSetupKeyLifetime = time.Hour

	// enrollRevokeAttempts bounds the re-read loop of a revoke racing
	// other state changes.
	enrollRevokeAttempts = 4
	// enrollAddrMaxLen bounds client and peer address literals before
	// parsing.
	enrollAddrMaxLen = 64
	// enrollSessionDomain separates the session-binding digest.
	enrollSessionDomain = "nebula enroll offer session v1\x00"
)

// errOfferUnavailable is the uniform refusal of every script release
// (ADR 0013 D7): unknown, expired, consumed, revoked, failed, malformed,
// foreign session and every internal error look the same.
var errOfferUnavailable = status.Error(codes.NotFound, "enrollment offer not available")

var offerIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EnrollOfferConfig is the executor-local configuration of one-step
// enrollment (EN-06), copied into every offer at creation.
type EnrollOfferConfig struct {
	// Sources are the from= addresses (IPs or CIDRs) Nebula connects from.
	Sources []string
	// NetBird is nil when the NetBird join is not configured.
	NetBird *EnrollOfferNetBird
}

// EnrollOfferNetBird is the NetBird part of EnrollOfferConfig.
type EnrollOfferNetBird struct {
	ManagementURL string
	ManagedGroup  string
	// Clients is the key-passing mode table per NetBird client version.
	Clients []enrollscript.NetBirdClient
}

// SetEnrollOffers validates and installs the enrollment configuration.
// Without it CreateEnrollOffer is refused.
func (s *Service) SetEnrollOffers(c EnrollOfferConfig) error {
	if len(c.Sources) == 0 {
		return errors.New("enroll offers: no source address")
	}
	for _, a := range c.Sources {
		if !enrollscript.ValidAddress(a) {
			return fmt.Errorf("enroll offers: source %q is neither an IP address nor a CIDR range", a)
		}
	}
	cp := EnrollOfferConfig{Sources: slices.Clone(c.Sources)}
	if c.NetBird != nil {
		if !canonical.ValidNetBirdGroup(c.NetBird.ManagedGroup) {
			return errors.New("enroll offers: invalid NetBird managed group")
		}
		nb := enrollscript.NetBirdOptions{ManagementURL: c.NetBird.ManagementURL, SetupKey: enrollscript.SetupKeyPlaceholder,
			Clients: slices.Clone(c.NetBird.Clients)}
		if err := nb.Validate(); err != nil {
			return fmt.Errorf("enroll offers: NetBird: %w", err)
		}
		cp.NetBird = &EnrollOfferNetBird{ManagementURL: nb.ManagementURL, ManagedGroup: c.NetBird.ManagedGroup, Clients: nb.Clients}
	}
	s.offers.mu.Lock()
	defer s.offers.mu.Unlock()
	s.offers.cfg = &cp
	return nil
}

// enrollOfferState holds the process-local part of the offers: the
// configuration and, per offer, the render inputs fixed at creation and
// the hash of the placeholder variant. The offer store of EN-05 has no
// columns for them yet, so they are not durable: after a restart an offer
// created before it can no longer be rendered; a download then fails it
// (enroll_offer_render_inputs_lost) and "Show script" refuses.
type enrollOfferState struct {
	mu     sync.Mutex
	cfg    *EnrollOfferConfig
	seq    uint64
	offers map[[sha256.Size]byte]*offerEntry
}

// offerEntry is one offer of the process-local index.
type offerEntry struct {
	seq    uint64
	render *offerRender // nil once the offer is final
	// paired is the paired permit proposed for the offer (EN-08 part 2);
	// nil before the match and once the offer is final.
	paired *pairedProposal
}

// offerRender are an offer's render inputs, fixed at creation.
type offerRender struct {
	opts    enrollscript.Options
	netbird *enrollscript.NetBirdOptions // SetupKey unset; nil without NetBird
	// group and ephemeral are bound into the NetBird offer permit.
	group     string
	ephemeral bool
	// placeholderSHA is the SHA-256 of the placeholder variant; without
	// NetBird it equals the full render.
	placeholderSHA [sha256.Size]byte
	// showMismatchAudited and showMismatches are the only fields "Show
	// script" writes; nothing reads them for a decision.
	showMismatchAudited bool
	showMismatches      int
}

// render renders the one-step script with the given setup key (ignored
// without NetBird).
func (r *offerRender) render(salt []byte, setupKey string) ([]byte, error) {
	o := enrollscript.OneStepOptions{Options: r.opts, Salt: slices.Clone(salt)}
	o.From = slices.Clone(r.opts.From)
	if r.netbird != nil {
		nb := *r.netbird
		nb.Clients = slices.Clone(r.netbird.Clients)
		nb.SetupKey = setupKey
		o.NetBird = &nb
	}
	b, err := enrollscript.RenderOneStep(o)
	if err != nil {
		return nil, err
	}
	if len(b) > enrollscript.MaxScriptBytes {
		wipe(b)
		return nil, enrollscript.ErrTooLarge
	}
	return b, nil
}

// placeholderKey is the setup-key value of the placeholder variant.
func (r *offerRender) placeholderKey() string {
	if r.netbird == nil {
		return ""
	}
	return enrollscript.SetupKeyPlaceholder
}

func (st *enrollOfferState) config() *EnrollOfferConfig {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.cfg
}

// get returns the render inputs of an offer, nil when unknown or final.
func (st *enrollOfferState) get(h [sha256.Size]byte) *offerRender {
	st.mu.Lock()
	defer st.mu.Unlock()
	if e := st.offers[h]; e != nil {
		return e.render
	}
	return nil
}

// put adds a new offer to the index, dropping the oldest final entries
// beyond EnrollOfferIndexMax.
func (st *enrollOfferState) put(h [sha256.Size]byte, r *offerRender) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.offers == nil {
		st.offers = map[[sha256.Size]byte]*offerEntry{}
	}
	st.seq++
	st.offers[h] = &offerEntry{seq: st.seq, render: r}
	for len(st.offers) > EnrollOfferIndexMax {
		var oldest [sha256.Size]byte
		var found bool
		var min uint64
		for k, e := range st.offers {
			if e.render == nil && (!found || e.seq < min) {
				oldest, min, found = k, e.seq, true
			}
		}
		if !found {
			return
		}
		delete(st.offers, oldest)
	}
}

// final drops the render inputs of an offer that became final.
func (st *enrollOfferState) final(h [sha256.Size]byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if e := st.offers[h]; e != nil {
		e.render, e.paired = nil, nil
	}
}

// remove forgets an offer that was never stored.
func (st *enrollOfferState) remove(h [sha256.Size]byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.offers, h)
}

// index returns the indexed offer hashes in creation order.
func (st *enrollOfferState) index() [][sha256.Size]byte {
	st.mu.Lock()
	defer st.mu.Unlock()
	type kv struct {
		h   [sha256.Size]byte
		seq uint64
	}
	all := make([]kv, 0, len(st.offers))
	for k, e := range st.offers {
		all = append(all, kv{k, e.seq})
	}
	slices.SortFunc(all, func(a, b kv) int { return int(a.seq) - int(b.seq) })
	out := make([][sha256.Size]byte, len(all))
	for i, x := range all {
		out[i] = x.h
	}
	return out
}

// showMismatch records a "Show script" mismatch and reports whether it is
// the first one of the offer (the only one audited).
func (st *enrollOfferState) showMismatch(r *offerRender) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	r.showMismatches++
	first := !r.showMismatchAudited
	r.showMismatchAudited = true
	return first
}

func (st *enrollOfferState) showMismatches(h [sha256.Size]byte) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	if e := st.offers[h]; e != nil && e.render != nil {
		return e.render.showMismatches
	}
	return 0
}

// newOfferID returns a fresh offer ID and its SHA-256.
func newOfferID() (string, [sha256.Size]byte, error) {
	var raw [EnrollOfferIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("offer ID: %w", err)
	}
	id := bytes.ToLower([]byte(offerIDEncoding.EncodeToString(raw[:])))
	return string(id), sha256.Sum256(id), nil
}

// parseOfferID checks the syntax of an offer ID and returns its SHA-256.
func parseOfferID(id string) ([sha256.Size]byte, bool) {
	if len(id) != EnrollOfferIDLen {
		return [sha256.Size]byte{}, false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return [sha256.Size]byte{}, false
		}
	}
	return sha256.Sum256([]byte(id)), true
}

// parseOfferIDHash parses a lowercase hex offer ID hash.
func parseOfferIDHash(s string) ([sha256.Size]byte, bool) {
	var h [sha256.Size]byte
	if len(s) != 2*sha256.Size {
		return h, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(b) != s {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

// sessionDigest is what the offer row stores of a session binding.
func sessionDigest(binding []byte) ([sha256.Size]byte, bool) {
	if len(binding) < EnrollSessionBindingMinLen || len(binding) > EnrollSessionBindingMaxLen {
		return [sha256.Size]byte{}, false
	}
	h := sha256.New()
	h.Write([]byte(enrollSessionDomain))
	h.Write(binding)
	return [sha256.Size]byte(h.Sum(nil)), true
}

// sessionMatches reports whether binding is the creating session's.
func sessionMatches(o executordb.Offer, binding []byte) bool {
	d, ok := sessionDigest(binding)
	return ok && subtle.ConstantTimeCompare(d[:], o.SessionHash[:]) == 1
}

// validOfferAddr reports whether s is an IP literal without zone.
func validOfferAddr(s string) bool {
	if s == "" || len(s) > enrollAddrMaxLen {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

func offerLog(h [sha256.Size]byte) string { return hex.EncodeToString(h[:4]) }

func wipe(b []byte) { clear(b) }

// sweepOffers runs the expiry sweep, audits what it ended and drops the
// render inputs of the expired offers.
func (s *Service) sweepOffers() {
	ids, err := s.db.ExpireOffers()
	for _, h := range ids {
		s.offers.final(h)
		s.log.Warn("audit", "kind", "enroll_offer_expired", "offer", offerLog(h))
	}
	if err != nil && !errors.Is(err, executordb.ErrOfferWipeIncomplete) {
		s.log.Error("enroll offer expiry sweep", "err", err)
	}
}

// failOffer ends an offer from state from as failed and audits kind.
func (s *Service) failOffer(h [sha256.Size]byte, from executordb.OfferState, kind string, attrs ...any) {
	err := s.db.EndOffer(h, from, executordb.OfferFailed)
	if err == nil || errors.Is(err, executordb.ErrOfferWipeIncomplete) {
		s.offers.final(h)
	} else {
		s.log.Error("enroll offer: fail offer", "offer", offerLog(h), "err", err)
	}
	s.log.Warn("audit", append([]any{"kind", kind, "offer", offerLog(h)}, attrs...)...)
}

// CreateEnrollOffer creates a one-step enrollment offer (server role).
func (s *Service) CreateEnrollOffer(ctx context.Context, req *pb.CreateEnrollOfferRequest) (*pb.CreateEnrollOfferResponse, error) {
	cfg := s.offers.config()
	if cfg == nil {
		return nil, status.Error(codes.FailedPrecondition, "create enroll offer: one-step enrollment is not configured on the executor")
	}
	if active, _ := s.auth.Session(); !active {
		return nil, status.Error(codes.FailedPrecondition, "create enroll offer: a privileged session is required")
	}
	host, user, cred := req.GetHostId(), req.GetSshUser(), req.GetCredentialRef()
	if user == "" {
		user = defaultEnrollUser
	}
	if cred == "" {
		cred = defaultEnrollCred
	}
	switch {
	case !canonical.ValidHostID(host):
		return nil, status.Error(codes.InvalidArgument, "create enroll offer: malformed host ID")
	case !enrollscript.ValidUser(user):
		return nil, status.Error(codes.InvalidArgument, "create enroll offer: malformed SSH user")
	case !enrollscript.ValidKeyRef(cred):
		return nil, status.Error(codes.InvalidArgument, "create enroll offer: malformed credential reference")
	case req.GetNetbirdEphemeral() && !req.GetNetbird():
		return nil, status.Error(codes.InvalidArgument, "create enroll offer: ephemeral needs NetBird")
	case req.GetNetbird() && cfg.NetBird == nil:
		return nil, status.Error(codes.FailedPrecondition, "create enroll offer: NetBird is not configured on the executor")
	}
	session, ok := sessionDigest(req.GetSessionBinding())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "create enroll offer: session binding must be %d to %d bytes",
			EnrollSessionBindingMinLen, EnrollSessionBindingMaxLen)
	}
	if _, pinned, err := s.db.HostKey(host); err != nil {
		return nil, s.adminStoreError("create enroll offer", err)
	} else if pinned {
		return nil, status.Error(codes.FailedPrecondition, "create enroll offer: host is already pinned or blocked; use the re-pin flow")
	}
	signer, err := s.keys.Signer(cred)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "create enroll offer: credential not loaded in the keyring")
	}
	r := &offerRender{opts: enrollscript.Options{From: slices.Clone(cfg.Sources), User: user, KeyRef: cred,
		Key: signer.PublicKey(), Sudo: req.GetSudo()}}
	if req.GetNetbird() {
		r.netbird = &enrollscript.NetBirdOptions{ManagementURL: cfg.NetBird.ManagementURL, Clients: slices.Clone(cfg.NetBird.Clients)}
		r.group, r.ephemeral = cfg.NetBird.ManagedGroup, req.GetNetbirdEphemeral()
	}

	s.sweepOffers()
	id, idHash, err := newOfferID()
	if err != nil {
		return nil, status.Error(codes.Internal, "create enroll offer: offer ID")
	}
	var salt [pairing.SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, status.Error(codes.Internal, "create enroll offer: salt")
	}
	placeholder, err := r.render(salt[:], r.placeholderKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "create enroll offer: render: %v", err)
	}
	r.placeholderSHA = sha256.Sum256(placeholder)
	wipe(placeholder)
	n := executordb.NewOffer{IDHash: idHash, Salt: salt, HostID: host, SSHUser: user, CredentialRef: cred,
		SessionHash: session, NetBird: req.GetNetbird()}
	if !n.NetBird {
		// Without NetBird the placeholder variant is the full render.
		n.ScriptSHA256 = r.placeholderSHA
	}
	s.offers.put(idHash, r)
	o, err := s.db.CreateOffer(n)
	clear(salt[:])
	if err != nil {
		s.offers.remove(idHash)
		if errors.Is(err, executordb.ErrOfferLimit) {
			return nil, status.Error(codes.ResourceExhausted, "create enroll offer: offer limit reached")
		}
		return nil, s.adminStoreError("create enroll offer", err)
	}
	resp := &pb.CreateEnrollOfferResponse{OfferId: id, OfferIdHash: hex.EncodeToString(idHash[:]),
		State: string(o.State), ExpiresUnix: o.ExpiresAt.Unix()}
	if len(o.ScriptSHA256) == sha256.Size {
		resp.ScriptSha256 = hex.EncodeToString(o.ScriptSHA256)
	}
	if o.NetBird {
		// The permit must be approved while the offer awaits approval: it
		// expires with the offer, and never later than the permit
		// lifetime on the executor's own clock.
		now := s.clock()
		expiry := min(o.ExpiresAt.Unix(), now.Add(canonical.MaxNetBirdOfferLifetime).Unix())
		p, err := s.auth.ProposeNetBirdOffer(canonical.NetBirdOffer{
			OfferIDHash: hex.EncodeToString(idHash[:]), HostID: host, SSHUser: user, CredentialRef: cred,
			ManagedGroup: r.group, Ephemeral: r.ephemeral,
			SetupKeyExpiryUnix: now.Add(EnrollNetBirdSetupKeyLifetime).Unix(),
			ExpiryUnix:         expiry,
		})
		if err != nil {
			s.failOffer(idHash, executordb.OfferAwaitingApproval, "enroll_offer_failed", "reason", "netbird permit proposal refused")
			return nil, toStatus(err)
		}
		resp.NetbirdPermit = &pb.NetBirdOfferPermitInfo{Digest: p.Digest.String(), Challenge: p.Challenge,
			Canonical: p.Canonical, ApprovalExpiryUnix: p.ApprovalExpiry.Unix()}
	}
	s.log.Warn("audit", "kind", "enroll_offer_created", "offer", offerLog(idHash), "host", host, "ssh_user", user,
		"credential", cred, "netbird", o.NetBird, "state", string(o.State))
	return resp, nil
}

// FetchEnrollScript releases the full script for the download route
// (server role). It consumes the offer exactly once.
func (s *Service) FetchEnrollScript(ctx context.Context, req *pb.FetchEnrollScriptRequest) (*pb.FetchEnrollScriptResponse, error) {
	script, sum, err := s.releaseOfferScript(req.GetOfferId(), nil, false, req.GetClientAddr(), req.GetPeerAddr())
	if err != nil {
		return nil, err
	}
	return &pb.FetchEnrollScriptResponse{Script: script, ScriptSha256: sum}, nil
}

// DownloadEnrollScript releases the full script for the browser download
// (server role, creating session only). It consumes the offer exactly like
// FetchEnrollScript and is refused without consuming for NetBird offers.
func (s *Service) DownloadEnrollScript(ctx context.Context, req *pb.DownloadEnrollScriptRequest) (*pb.DownloadEnrollScriptResponse, error) {
	script, sum, err := s.releaseOfferScript(req.GetOfferId(), req.GetSessionBinding(), true, req.GetClientAddr(), req.GetPeerAddr())
	if err != nil {
		return nil, err
	}
	return &pb.DownloadEnrollScriptResponse{Script: script, ScriptSha256: sum}, nil
}

// releaseOfferScript renders the full script of an open offer, checks it
// against the stored hash and claims the single download. Nothing is
// consumed unless the bytes are returned.
func (s *Service) releaseOfferScript(id string, binding []byte, browser bool, client, peer string) ([]byte, string, error) {
	via := "fetch"
	if browser {
		via = "browser"
	}
	idHash, ok := parseOfferID(id)
	if !ok || !validOfferAddr(client) || !validOfferAddr(peer) {
		return nil, "", errOfferUnavailable
	}
	o, err := s.db.Offer(idHash)
	if err != nil {
		if !errors.Is(err, executordb.ErrOfferNotFound) {
			s.log.Error("enroll offer: read", "offer", offerLog(idHash), "err", err)
		}
		return nil, "", errOfferUnavailable
	}
	if browser {
		if !sessionMatches(o, binding) {
			return nil, "", errOfferUnavailable
		}
		if o.NetBird {
			return nil, "", status.Error(codes.FailedPrecondition, "download enroll script: the browser download is not offered for NetBird offers")
		}
	}
	if o.State != executordb.OfferOpen || !s.clock().Before(o.ExpiresAt) || len(o.Salt) != pairing.SaltSize ||
		len(o.ScriptSHA256) != sha256.Size {
		return nil, "", errOfferUnavailable
	}
	r := s.offers.get(idHash)
	if r == nil {
		s.failOffer(idHash, executordb.OfferOpen, "enroll_offer_render_inputs_lost")
		return nil, "", errOfferUnavailable
	}
	if o.NetBird != (r.netbird != nil) {
		s.failOffer(idHash, executordb.OfferOpen, "enroll_offer_render_inputs_lost")
		return nil, "", errOfferUnavailable
	}
	var key []byte
	if o.NetBird {
		if o.SetupKey.Status != executordb.SetupKeyCreated || o.SetupKey.VaultRef == "" {
			return nil, "", errOfferUnavailable
		}
		if key, err = s.vault.Open(o.SetupKey.VaultRef); err != nil {
			s.log.Error("enroll offer: setup key", "offer", offerLog(idHash), "err", err)
			return nil, "", errOfferUnavailable
		}
		defer wipe(key)
		if !enrollscript.ValidSetupKey(string(key)) || string(key) == enrollscript.SetupKeyPlaceholder {
			s.log.Error("enroll offer: stored setup key is malformed", "offer", offerLog(idHash))
			return nil, "", errOfferUnavailable
		}
	}
	script, err := r.render(o.Salt, string(key))
	if err != nil {
		s.log.Error("enroll offer: render", "offer", offerLog(idHash), "err", err)
		return nil, "", errOfferUnavailable
	}
	sum := sha256.Sum256(script)
	if subtle.ConstantTimeCompare(sum[:], o.ScriptSHA256) != 1 {
		wipe(script)
		s.failOffer(idHash, executordb.OfferOpen, "enroll_script_hash_mismatch", "variant", via)
		return nil, "", errOfferUnavailable
	}
	if err := s.db.ClaimOfferDownload(idHash, client, peer); err != nil {
		wipe(script)
		return nil, "", errOfferUnavailable
	}
	s.log.Warn("audit", "kind", "enroll_script_downloaded", "offer", offerLog(idHash), "via", via,
		"client_addr", client, "peer_addr", peer)
	return script, hex.EncodeToString(sum[:]), nil
}

// ShowEnrollScript renders the placeholder variant for "Show script"
// (server role, creating session only). It never reads the setup key,
// never changes the offer and may be called any number of times.
func (s *Service) ShowEnrollScript(ctx context.Context, req *pb.ShowEnrollScriptRequest) (*pb.ShowEnrollScriptResponse, error) {
	idHash, ok := parseOfferID(req.GetOfferId())
	if !ok {
		return nil, errOfferUnavailable
	}
	o, err := s.db.Offer(idHash)
	if err != nil || !sessionMatches(o, req.GetSessionBinding()) || o.State.Final() || len(o.Salt) != pairing.SaltSize {
		return nil, errOfferUnavailable
	}
	r := s.offers.get(idHash)
	if r == nil || o.NetBird != (r.netbird != nil) {
		return nil, status.Error(codes.FailedPrecondition, "show enroll script: the offer cannot be rendered any more; create it again")
	}
	script, err := r.render(o.Salt, r.placeholderKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "show enroll script: render failed")
	}
	if sum := sha256.Sum256(script); subtle.ConstantTimeCompare(sum[:], r.placeholderSHA[:]) != 1 {
		wipe(script)
		if s.offers.showMismatch(r) {
			s.log.Warn("audit", "kind", "enroll_script_hash_mismatch", "offer", offerLog(idHash), "variant", "show")
		}
		return nil, status.Error(codes.FailedPrecondition, "show enroll script: the render does not match the stored hash")
	}
	resp := &pb.ShowEnrollScriptResponse{Script: script}
	if len(o.ScriptSHA256) == sha256.Size {
		resp.ScriptSha256 = hex.EncodeToString(o.ScriptSHA256)
	}
	return resp, nil
}

// RevokeEnrollOffer revokes an offer in any non-final state (server role
// from any session, admin role).
func (s *Service) RevokeEnrollOffer(ctx context.Context, req *pb.RevokeEnrollOfferRequest) (*pb.RevokeEnrollOfferResponse, error) {
	idHash, ok := parseOfferIDHash(req.GetOfferIdHash())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "revoke enroll offer: offer ID hash must be 64 lowercase hex characters")
	}
	by := "unknown"
	if c, ok := peercred.CallerFrom(ctx); ok {
		by = string(c.Role)
	}
	for range enrollRevokeAttempts {
		o, err := s.db.Offer(idHash)
		if errors.Is(err, executordb.ErrOfferNotFound) {
			return nil, status.Error(codes.NotFound, "revoke enroll offer: no such offer")
		}
		if err != nil {
			return nil, s.adminStoreError("revoke enroll offer", err)
		}
		if o.State.Final() {
			return nil, status.Errorf(codes.FailedPrecondition, "revoke enroll offer: offer is already %s", o.State)
		}
		err = s.db.EndOffer(idHash, o.State, executordb.OfferRevoked)
		if errors.Is(err, executordb.ErrOfferState) {
			continue
		}
		if err != nil && !errors.Is(err, executordb.ErrOfferWipeIncomplete) {
			return nil, s.adminStoreError("revoke enroll offer", err)
		}
		s.offers.final(idHash)
		s.log.Warn("audit", "kind", "enroll_offer_revoked", "offer", offerLog(idHash), "from", string(o.State), "by", by)
		return &pb.RevokeEnrollOfferResponse{State: string(executordb.OfferRevoked)}, nil
	}
	return nil, status.Error(codes.Aborted, "revoke enroll offer: the offer kept changing; try again")
}

// ListEnrollOffers lists the offers of the process-local index (admin
// role), without offer ID, salt, script or setup key.
func (s *Service) ListEnrollOffers(ctx context.Context, _ *pb.ListEnrollOffersRequest) (*pb.ListEnrollOffersResponse, error) {
	s.sweepOffers()
	out := &pb.ListEnrollOffersResponse{}
	for _, h := range s.offers.index() {
		o, err := s.db.Offer(h)
		if errors.Is(err, executordb.ErrOfferNotFound) {
			continue
		}
		if err != nil {
			return nil, s.adminStoreError("list enroll offers", err)
		}
		info := &pb.EnrollOfferInfo{OfferIdHash: hex.EncodeToString(h[:]), HostId: o.HostID, SshUser: o.SSHUser,
			CredentialRef: o.CredentialRef, Netbird: o.NetBird, State: string(o.State),
			CreatedUnix: o.CreatedAt.Unix(), ExpiresUnix: o.ExpiresAt.Unix(),
			ClientAddr: o.ClientAddr, PeerAddr: o.PeerAddr, Probes: int32(o.Probes), RejectedCodes: int32(o.RejectedCodes),
			SetupKeyRecord: string(o.SetupKey.Status), ShowMismatches: int32(s.offers.showMismatches(h))}
		if len(o.ScriptSHA256) == sha256.Size {
			info.ScriptSha256 = hex.EncodeToString(o.ScriptSHA256)
		}
		if !o.DownloadedAt.IsZero() {
			info.DownloadedUnix = o.DownloadedAt.Unix()
		}
		out.Offers = append(out.Offers, info)
	}
	return out, nil
}

// openNetBirdOffer records a validated setup key for a NetBird offer whose
// setup-key record is pending (ADR 0013 D6 step 3, spec 03 "Placeholder
// hash"): it renders both variants from the stored inputs, requires the
// placeholder variant to match the stored placeholder hash and the two
// renders to differ in exactly the setup-key line, seals the key in the
// vault and opens the offer with the full-render hash in one transaction.
// EN-12 calls it after NetBird's create answer; nothing else does.
func (s *Service) openNetBirdOffer(idHash [sha256.Size]byte, keyID, setupKey string) error {
	if !enrollscript.ValidSetupKey(setupKey) || setupKey == enrollscript.SetupKeyPlaceholder {
		return errors.New("open NetBird offer: malformed setup key")
	}
	r := s.offers.get(idHash)
	if r == nil || r.netbird == nil {
		return errors.New("open NetBird offer: no render inputs")
	}
	o, err := s.db.Offer(idHash)
	if err != nil {
		return fmt.Errorf("open NetBird offer %s: %w", offerLog(idHash), err)
	}
	placeholder, err := r.render(o.Salt, enrollscript.SetupKeyPlaceholder)
	if err != nil {
		return fmt.Errorf("open NetBird offer %s: render placeholder: %w", offerLog(idHash), err)
	}
	defer wipe(placeholder)
	full, err := r.render(o.Salt, setupKey)
	if err != nil {
		return fmt.Errorf("open NetBird offer %s: render: %w", offerLog(idHash), err)
	}
	defer wipe(full)
	if sha256.Sum256(placeholder) != r.placeholderSHA || !differInOneLine(placeholder, full) {
		s.log.Warn("audit", "kind", "enroll_script_hash_mismatch", "offer", offerLog(idHash), "variant", "open")
		return errors.New("open NetBird offer: renders do not match the stored placeholder")
	}
	sum := sha256.Sum256(full)
	_, err = s.vault.PutWithCommit(executordb.SetupKeyVaultRef(idHash), []byte(setupKey), "executor",
		func(sec executordb.VaultSecret) error { return s.db.OpenNetBirdOffer(idHash, keyID, sec, sum) })
	if err != nil {
		return fmt.Errorf("open NetBird offer %s: %w", offerLog(idHash), err)
	}
	return nil
}

// differInOneLine reports whether a and b have the same number of lines
// and differ in exactly one of them.
func differInOneLine(a, b []byte) bool {
	la, lb := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	if len(la) != len(lb) {
		return false
	}
	diff := 0
	for i := range la {
		if !bytes.Equal(la[i], lb[i]) {
			diff++
		}
	}
	return diff == 1
}
