// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Bulk enrollment from the web UI (spec 08: "Bulk enrollment shows a
// table of address and fingerprint for confirmation"). The executor reads
// every host key itself; the approval (at least HIGH, user verification)
// binds host, endpoint, fingerprint, SSH user and credential of each host;
// the commit reads the keys again and pins only what still matches.

const (
	enrollAction  = "nebula.host_key.enroll"
	enrollVersion = "1.0.0"
	// MaxEnrollHosts bounds one bulk enrollment.
	MaxEnrollHosts = 50
	// enrollProbes bounds parallel probes.
	enrollProbes       = 8
	enrollProbeTimeout = 15 * time.Second
	defaultEnrollUser  = "nebula"
	defaultEnrollCred  = "nebula-default"
)

var (
	enrollArtifact  = []byte("nebula.host_key.enroll 1.0.0\nPin the SSH host keys listed in the parameters for these hosts, with the given SSH user\nand credential. No criticality record is created (unrecorded hosts count as HIGH).\n")
	stagePlanEnroll = func() string {
		s, _ := canonical.HashParameters([]byte(`{"plan":"enroll-v1"}`))
		return s
	}()
	enrollUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	enrollCredRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// enrollEntry is one host of an enrollment, normalized.
type enrollEntry struct {
	HostID      string `json:"host"`
	Endpoint    string `json:"endpoint"`
	User        string `json:"ssh_user"`
	Credential  string `json:"credential"`
	Fingerprint string `json:"fingerprint"`
}

// normalizeEnroll validates the caller's part of an entry and fills the
// defaults. The endpoint is returned in its canonical form.
func normalizeEnroll(h *pb.EnrollHost) (enrollEntry, error) {
	e := enrollEntry{HostID: h.GetHostId(), User: h.GetSshUser(), Credential: h.GetCredentialRef()}
	if !canonical.ValidHostID(e.HostID) {
		return e, errors.New("malformed host ID")
	}
	ep, err := sshtransport.ParseEndpoint(h.GetEndpoint())
	if err != nil {
		return e, errors.New("malformed endpoint")
	}
	e.Endpoint = ep.String()
	if e.User == "" {
		e.User = defaultEnrollUser
	}
	if e.Credential == "" {
		e.Credential = defaultEnrollCred
	}
	if !enrollUserRe.MatchString(e.User) {
		return e, errors.New("malformed SSH user")
	}
	if !enrollCredRe.MatchString(e.Credential) {
		return e, errors.New("malformed credential reference")
	}
	return e, nil
}

// enrollParams is the canonical parameter document of an enrollment.
func enrollParams(entries []enrollEntry) ([]byte, error) {
	sorted := slices.Clone(entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].HostID < sorted[j].HostID })
	return json.Marshal(map[string]any{"hosts": sorted, "criticality": "none (counts as HIGH)"})
}

// probeKey reads the host key of one endpoint.
func (s *Service) probeKey(ctx context.Context, endpoint string) (ssh.PublicKey, error) {
	ep, err := sshtransport.ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, enrollProbeTimeout)
	defer cancel()
	k, err := s.transport.Probe(ctx, ep)
	if err != nil {
		return nil, err
	}
	if err := sshtransport.CheckHostKey(k); err != nil {
		return nil, err
	}
	return k, nil
}

// ProposeEnroll reads the host keys of new hosts and proposes pinning
// them (server role).
func (s *Service) ProposeEnroll(ctx context.Context, req *pb.ProposeEnrollRequest) (*pb.ProposeEnrollResponse, error) {
	in := req.GetHosts()
	if len(in) == 0 || len(in) > MaxEnrollHosts {
		return nil, status.Errorf(codes.InvalidArgument, "1 to %d hosts per enrollment", MaxEnrollHosts)
	}
	out := make([]*pb.EnrollHost, len(in))
	entries := make([]enrollEntry, len(in))
	seen := map[string]bool{}
	for i, h := range in {
		e, err := normalizeEnroll(h)
		out[i] = &pb.EnrollHost{HostId: h.GetHostId(), Endpoint: e.Endpoint, SshUser: e.User, CredentialRef: e.Credential}
		switch {
		case err != nil:
			out[i].Error = err.Error()
		case seen[e.HostID]:
			out[i].Error = "listed twice"
		default:
			seen[e.HostID] = true
			if _, ok, err := s.db.HostKey(e.HostID); err != nil {
				return nil, s.adminStoreError("enroll", err)
			} else if ok {
				out[i].Error = "already pinned"
			} else if _, err := s.keys.Signer(e.Credential); errors.Is(err, keyring.ErrUnknownRef) {
				out[i].Error = "credential not loaded in the keyring"
			}
		}
		entries[i] = e
	}
	// Probe the remaining hosts in parallel.
	var wg sync.WaitGroup
	sem := make(chan struct{}, enrollProbes)
	for i := range out {
		if out[i].Error != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			k, err := s.probeKey(ctx, entries[i].Endpoint)
			if err != nil {
				out[i].Error = "no host key: " + string(sshtransport.ClassOf(err))
				return
			}
			entries[i].Fingerprint = sshtransport.Fingerprint(k)
			out[i].Fingerprint, out[i].KeyType = entries[i].Fingerprint, k.Type()
		}(i)
	}
	wg.Wait()
	// A key may belong to one host only (cloned machines must be re-keyed).
	byFP := map[string]int{}
	for i := range out {
		if out[i].Error == "" {
			byFP[entries[i].Fingerprint]++
		}
	}
	var ok []enrollEntry
	for i := range out {
		if out[i].Error != "" {
			continue
		}
		if byFP[entries[i].Fingerprint] > 1 {
			out[i].Error = "the same host key as another host in this list"
			continue
		}
		if other, err := s.db.HostByFingerprint(entries[i].Fingerprint); err != nil {
			return nil, s.adminStoreError("enroll", err)
		} else if other != "" {
			out[i].Error = "this host key is pinned for " + other
			continue
		}
		ok = append(ok, entries[i])
	}
	resp := &pb.ProposeEnrollResponse{Hosts: out}
	if len(ok) == 0 {
		return resp, nil
	}
	r, params, err := enrollRequest(ok, s.clock())
	if err != nil {
		return nil, status.Error(codes.Internal, "enroll request")
	}
	res, err := s.auth.ProposeAtLeastMinimum(r, params)
	if err != nil {
		return nil, toStatus(err)
	}
	if resp.Permit, err = s.permitResponse(res.Permit); err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(ok))
	for _, e := range ok {
		hosts = append(hosts, e.HostID+"="+e.Fingerprint)
	}
	s.log.Warn("audit", "kind", "enroll_proposed", "digest", res.Permit.Digest.String(), "hosts", hosts,
		"risk", string(res.Permit.Request.RiskClass))
	return resp, nil
}

func enrollRequest(entries []enrollEntry, now time.Time) (canonical.Request, []byte, error) {
	params, err := enrollParams(entries)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	id, err := newExecutionID()
	if err != nil {
		return canonical.Request{}, nil, err
	}
	var creds []string
	var targets []canonical.Target
	for _, e := range entries {
		if !slices.Contains(creds, e.Credential) {
			creds = append(creds, e.Credential)
		}
		targets = append(targets, canonical.Target{HostID: e.HostID, HostKeyFingerprint: e.Fingerprint})
	}
	sort.Strings(creds)
	return canonical.Request{
		ExecutionID: id, ActionID: enrollAction, ModuleVersion: enrollVersion,
		ArtifactSHA256: sha256Hex(enrollArtifact), ParametersHash: ph, CredentialRefs: creds,
		RiskClass: canonical.RiskHigh, StagePlanHash: stagePlanEnroll,
		ExpiryUnix:      now.Add(repinLifetime).Unix(),
		ResolvedTargets: targets,
	}, params, nil
}

// CommitEnroll pins the hosts of an approved enrollment (server role).
func (s *Service) CommitEnroll(ctx context.Context, req *pb.CommitEnrollRequest) (*pb.CommitEnrollResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	in := req.GetHosts()
	if len(in) == 0 || len(in) > MaxEnrollHosts {
		return nil, status.Errorf(codes.InvalidArgument, "1 to %d hosts per enrollment", MaxEnrollHosts)
	}
	entries := make([]enrollEntry, 0, len(in))
	for _, h := range in {
		e, err := normalizeEnroll(h)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "host %q: %v", h.GetHostId(), err)
		}
		if !canonical.ValidHostKeyFingerprint(h.GetFingerprint()) {
			return nil, status.Errorf(codes.InvalidArgument, "host %q: malformed fingerprint", h.GetHostId())
		}
		e.Fingerprint = h.GetFingerprint()
		entries = append(entries, e)
	}
	params, err := enrollParams(entries)
	if err != nil {
		return nil, status.Error(codes.Internal, "enroll parameters")
	}
	results := make([]*pb.EnrollResult, 0, len(entries))
	by := "enroll:" + d.String()[:16]
	for i, e := range entries {
		res := &pb.EnrollResult{HostId: e.HostID}
		results = append(results, res)
		// Each host is authorized against the approval: the parameters
		// (every host's endpoint, key, user and credential) must hash to
		// the approved value, and each host can be used once.
		if _, err := s.auth.AuthorizeGrant(d, permit.Run{
			HostID: e.HostID, HostKeyFingerprint: e.Fingerprint, ActionID: enrollAction, ModuleVersion: enrollVersion,
			Artifact: enrollArtifact, ParametersJSON: params, CredentialRef: e.Credential,
		}); err != nil {
			if i == 0 {
				// The whole list does not match the approval.
				return nil, toStatus(err)
			}
			res.Error = "not authorized: " + status.Convert(toStatus(err)).Message()
			continue
		}
		k, err := s.probeKey(ctx, e.Endpoint)
		if err != nil {
			res.Error = "no host key: " + string(sshtransport.ClassOf(err)) + "; nothing pinned (enroll it again)"
			continue
		}
		if got := sshtransport.Fingerprint(k); got != e.Fingerprint {
			res.Error = "the endpoint now presents " + got + ", not the approved key; nothing pinned"
			s.log.Error("audit", "kind", "enroll_key_changed", "host", e.HostID, "digest", d.String(), "approved", e.Fingerprint, "presented", got)
			continue
		}
		pinned, err := s.db.PinHostKey(executordb.HostKey{HostID: e.HostID, PublicKey: k.Marshal(), User: e.User,
			CredentialRef: e.Credential, Source: executordb.SourceProbe, PinnedBy: by})
		switch {
		case errors.Is(err, executordb.ErrHostPinned):
			res.Error = "pinned meanwhile; left as it is"
			continue
		case errors.Is(err, executordb.ErrInvalid):
			res.Error = "refused: " + err.Error()
			continue
		case err != nil:
			return nil, s.adminStoreError("enroll", err)
		}
		res.Pinned, res.Fingerprint = true, pinned.Fingerprint
		s.log.Info("audit", "kind", "host_key_pinned", "by", by, "host", pinned.HostID, "fingerprint", pinned.Fingerprint,
			"user", pinned.User, "credential", pinned.CredentialRef, "source", "enroll")
		// A first login shows that the enrollment script ran on the host.
		if s.keys.Unlocked() {
			ep, _ := sshtransport.ParseEndpoint(e.Endpoint)
			lctx, cancel := context.WithTimeout(ctx, enrollProbeTimeout)
			c, err := s.Connect(lctx, e.HostID, pinned.Fingerprint, []sshtransport.Endpoint{ep})
			cancel()
			if err == nil {
				res.LoginOk = true
				c.Close()
			} else {
				res.LoginDetail = "login failed: " + string(sshtransport.ClassOf(err)) + " (did the enrollment script run on the host?)"
			}
		}
	}
	return &pb.CommitEnrollResponse{Results: results}, nil
}
