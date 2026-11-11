// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

// Private registry reads on the server (ADR 0006, cu06 part 1, G13). The
// server never holds a registry credential: it lists the executor's private
// registry metadata, builds and proposes registry read leases from that
// metadata alone (registrymeta.ProposeRegistryReadLease; the user approves
// the digest on the lease page) and asks the executor for typed digest
// reads of the private images a docker.check_updates result could not
// read (dockerhost.ResolvePrivateDigestsWith over one long-lived
// registrymeta.DigestReader, so a re-render within the lease interval is
// answered from memory instead of being rate limited).

// registryCallTimeout bounds one registry call chain from a page.
const registryCallTimeout = 10 * time.Second

// registryExecutor is the server-role executor API the registry reads use.
type registryExecutor interface {
	registrymeta.ExecutorRegistry
	registrymeta.LeaseProposer
	registrymeta.ReadGrantLister
}

// serverRegistryReads implements ui.RegistryReads.
type serverRegistryReads struct {
	exec   registryExecutor
	reader *registrymeta.DigestReader
	now    func() time.Time
	newID  func() (string, error)
	log    *slog.Logger
}

func newServerRegistryReads(exec registryExecutor, now func() time.Time, log *slog.Logger) *serverRegistryReads {
	if now == nil {
		now = time.Now
	}
	return &serverRegistryReads{exec: exec, reader: registrymeta.NewDigestReader(exec, now), now: now, newID: newLeaseID, log: log}
}

// newLeaseID returns a random lowercase UUIDv4, the read grant id form.
func newLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("lease id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := fmt.Sprintf("%x", b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// PrivateRegistries lists the executor's private registries.
func (s *serverRegistryReads) PrivateRegistries(ctx context.Context) ([]registrymeta.PrivateIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, registryCallTimeout)
	defer cancel()
	return registrymeta.ListPrivateIdentities(ctx, s.exec)
}

// ProposeRegistryLease builds the registry read lease for req under a new
// id from the executor's current registries and proposes it.
func (s *serverRegistryReads) ProposeRegistryLease(ctx context.Context, user string, req registrymeta.LeaseRequest) (registrymeta.LeaseProposal, error) {
	id, err := s.newID()
	if err != nil {
		return registrymeta.LeaseProposal{}, err
	}
	req.ID = id
	ctx, cancel := context.WithTimeout(ctx, registryCallTimeout)
	defer cancel()
	p, err := registrymeta.ProposeRegistryReadLease(ctx, s.exec, req, s.now())
	if err != nil {
		return registrymeta.LeaseProposal{}, err
	}
	s.log.Info("registry read lease proposed", "grant", id, "digest", p.Digest, "user", user)
	return p, nil
}

// RegistryLeases lists the executor's registry read leases.
func (s *serverRegistryReads) RegistryLeases(ctx context.Context) ([]registrymeta.LeaseView, error) {
	ctx, cancel := context.WithTimeout(ctx, registryCallTimeout)
	defer cancel()
	return registrymeta.ListRegistryLeases(ctx, s.exec, s.now())
}

// Close stops the digest reader's background reads on shutdown: the batch
// in flight is cancelled and Close waits for the worker until ctx ends.
func (s *serverRegistryReads) Close(ctx context.Context) error {
	return s.reader.Close(ctx)
}

// closeRegistryReads waits until life ends (the server shuts down), then
// closes s, waiting at most timeout for its background worker.
func closeRegistryReads(life context.Context, s *serverRegistryReads, timeout time.Duration, log *slog.Logger) {
	<-life.Done()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		log.Error("stop private registry reads", "error", err.Error())
	}
}

// ResolveImageUpdates fills the executor-read digests of private images
// into u; when the registries cannot be listed u is returned unchanged.
func (s *serverRegistryReads) ResolveImageUpdates(ctx context.Context, u dockerhost.ImageUpdates) dockerhost.ImageUpdates {
	ctx, cancel := context.WithTimeout(ctx, registryCallTimeout)
	defer cancel()
	out, err := dockerhost.ResolvePrivateDigestsWith(ctx, u, s.reader)
	if err != nil {
		s.log.Warn("private registry digests unavailable", "error", err.Error())
		return u
	}
	return out
}
