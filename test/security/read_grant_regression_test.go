// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
)

// pausedReadReservations stops the first claim after authorization has read
// the active grant but before the store starts its reservation transaction.
type pausedReadReservations struct {
	permit.ReadGrantStore
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (s *pausedReadReservations) ReserveReadRun(id, action, host string, now time.Time, budget int, interval time.Duration) (bool, error) {
	s.once.Do(func() { close(s.reached); <-s.resume })
	return s.ReadGrantStore.ReserveReadRun(id, action, host, now, budget, interval)
}

func (s *pausedReadReservations) wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("authorization did not reach reservation")
	}
}

func TestReadGrantRevocationBeforeReservationStopsClaim(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	for _, action := range readGrantActions {
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(readFactArtifact), ActionID: action, ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "acceptance"}); err != nil {
			t.Fatal(err)
		}
	}
	s := &pausedReadReservations{ReadGrantStore: h.db, reached: make(chan struct{}), resume: make(chan struct{})}
	release := sync.OnceFunc(func() { close(s.resume) })
	defer release()
	auth := newLeaseAuthority(t, h, s)
	p, err := auth.ProposeReadGrant(readFactGrantDoc(t, readGrantID, time.Now(), 1))
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := auth.AuthorizeReadRun(g.ID, "racing", permit.TriggerOnDemand, readFactRun("core.facts"))
		result <- err
	}()
	s.wait(t)
	if err := auth.RevokeReadGrant(g.ID, "acceptance"); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-result:
		if permit.CodeOf(err) != permit.CodeLeaseInactive {
			t.Fatalf("claim after completed revocation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reservation did not finish")
	}
}

func newReadGrantService(t *testing.T, h *harness, store permit.ReadGrantStore) (*permit.Authority, *executor.Service) {
	t.Helper()
	auth := newLeaseAuthority(t, h, store)
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: rpID, Origins: []string{origin}}, h.verifier, h.db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(filepath.Join(h.dataDir, "testkeys")), h.db, reg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	return auth, svc
}

func TestReadGrantUnspentGrantPausesAcrossLockAndRestart(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("read-lease")
	if _, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: host.id, HostKeyFingerprint: host.fp, Criticality: pb.RiskClass_RISK_CLASS_LOW}); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("#!/bin/sh\nprintf '{}'\n")
	for _, action := range readGrantActions {
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(artifact), ActionID: action, ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "acceptance"}); err != nil {
			t.Fatal(err)
		}
	}
	s := &pausedReadReservations{ReadGrantStore: h.db, reached: make(chan struct{}), resume: make(chan struct{})}
	release := sync.OnceFunc(func() { close(s.resume) })
	defer release()
	auth, svc := newReadGrantService(t, h, s)
	if _, err := svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	var doc permit.ReadGrantDoc
	if err := json.Unmarshal(readFactGrantDoc(t, readGrantID, time.Now(), 3), &doc); err != nil {
		t.Fatal(err)
	}
	doc.Targets = []canonical.Target{{HostID: host.id, HostKeyFingerprint: host.fp}}
	doc.Credentials = []permit.ReadGrantCredential{{HostID: host.id, CredentialRef: credRef, CredentialVersion: ssh.FingerprintSHA256(h.userKey)}}
	for i := range doc.Actions {
		doc.Actions[i].ArtifactSHA256 = hexSum(artifact)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	request := func(action string) *pb.RunScheduledRequest {
		return &pb.RunScheduledRequest{GrantId: g.ID, Endpoints: []string{host.endpoint}, Run: &pb.AuthorizeRunRequest{HostId: host.id, HostKeyFingerprint: host.fp, ActionId: action, ModuleVersion: "1.0.0", Artifact: artifact, ParametersJson: readFactParams, CredentialRef: credRef}}
	}
	// Queue an authorized run before dispatch, then complete lock before
	// allowing the reservation to proceed. No command may reach the host.
	type outcome struct {
		response *pb.RunScheduledResponse
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		r, err := svc.RunScheduled(context.Background(), request("core.facts"))
		result <- outcome{r, err}
	}()
	s.wait(t)
	if _, err := svc.Lock(context.Background(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case out := <-result:
		if out.err != nil || out.response.GetResult().GetClass() != "vault_locked" {
			t.Fatalf("queued dispatch after lock: %v, %v", out.response, out.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued dispatch did not finish")
	}
	if len(host.srv.Commands()) != 0 {
		t.Fatal("queued dispatch reached host while locked")
	}
	// docker.list is unspent and has never hit the action floor.
	_, err = svc.RunScheduled(context.Background(), request("docker.list"))
	wantCode(t, err, codes.FailedPrecondition, "vault_locked")
	h.stop()
	h2 := newHarness(t, harnessOptions{dataDir: h.dataDir, identity: h.id})
	auth2, svc2 := newReadGrantService(t, h2, h2.db)
	stored, err := auth2.ReadGrants()
	if err != nil || len(stored) != 1 || stored[0].ID != g.ID || !stored[0].RevokedAt.IsZero() {
		t.Fatalf("grant after locked restart: %+v, %v", stored, err)
	}
	_, err = svc2.RunScheduled(context.Background(), request("docker.list"))
	wantCode(t, err, codes.FailedPrecondition, "vault_locked")
	if len(host.srv.Commands()) != 0 {
		t.Fatal("locked restart dispatched a read")
	}
	if _, err := svc2.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	r, err := svc2.RunScheduled(context.Background(), request("docker.list"))
	if err != nil || r.GetResult().GetClass() != "success" {
		t.Fatalf("unspent grant after explicit unlock: %v, %v", r, err)
	}
	if len(host.srv.Commands()) != 1 {
		t.Fatalf("queued work escaped or unlocked read did not dispatch: %d commands", len(host.srv.Commands()))
	}
}

// claimedReadReservations queues work after its durable budget claim, before
// the executor can connect or dispatch. Lifecycle calls must invalidate it.
type claimedReadReservations struct {
	permit.ReadGrantStore
	reached, resume chan struct{}
	once            sync.Once
}

func (s *claimedReadReservations) ReserveReadRun(id, action, host string, now time.Time, budget int, interval time.Duration) (bool, error) {
	ok, err := s.ReadGrantStore.ReserveReadRun(id, action, host, now, budget, interval)
	if ok && err == nil {
		s.once.Do(func() { close(s.reached); <-s.resume })
	}
	return ok, err
}

func TestReadGrantFinalDispatchDeniesQueuedStateChanges(t *testing.T) {
	for _, trigger := range []string{permit.TriggerScheduled, permit.TriggerOnDemand} {
		for _, change := range []string{"none", "revoke", "lock-unlock", "recovery"} {
			t.Run(trigger+"/"+change, func(t *testing.T) {
				h := newHarness(t, harnessOptions{})
				h.unlock()
				host := h.pinnedRunHost("queued-read")
				if _, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: host.id, HostKeyFingerprint: host.fp, Criticality: pb.RiskClass_RISK_CLASS_LOW}); err != nil {
					t.Fatal(err)
				}
				artifact := []byte("#!/bin/sh\nprintf '{}'\n")
				for _, action := range readGrantActions {
					if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(artifact), ActionID: action, ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "acceptance"}); err != nil {
						t.Fatal(err)
					}
				}
				store := &claimedReadReservations{ReadGrantStore: h.db, reached: make(chan struct{}), resume: make(chan struct{})}
				release := sync.OnceFunc(func() { close(store.resume) })
				defer release()
				auth, svc := newReadGrantService(t, h, store)
				if _, err := svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
					t.Fatal(err)
				}
				var doc permit.ReadGrantDoc
				if err := json.Unmarshal(readFactGrantDoc(t, readGrantID, time.Now(), 3), &doc); err != nil {
					t.Fatal(err)
				}
				doc.Targets = []canonical.Target{{HostID: host.id, HostKeyFingerprint: host.fp}}
				doc.Credentials = []permit.ReadGrantCredential{{HostID: host.id, CredentialRef: credRef, CredentialVersion: ssh.FingerprintSHA256(h.userKey)}}
				for i := range doc.Actions {
					doc.Actions[i].ArtifactSHA256 = hexSum(artifact)
				}
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				p, err := auth.ProposeReadGrant(raw)
				if err != nil {
					t.Fatal(err)
				}
				g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
				if err != nil {
					t.Fatal(err)
				}
				request := &pb.RunScheduledRequest{GrantId: g.ID, Endpoints: []string{host.endpoint}, Run: &pb.AuthorizeRunRequest{HostId: host.id, HostKeyFingerprint: host.fp, ActionId: "core.facts", ModuleVersion: "1.0.0", Artifact: artifact, ParametersJson: readFactParams, CredentialRef: credRef}}
				result := make(chan error, 1)
				go func() {
					r, err := svc.RunRead(context.Background(), trigger, request)
					if err == nil && r.GetResult().GetClass() != "success" {
						err = fmt.Errorf("read outcome: %s", r.GetResult().GetClass())
					}
					result <- err
				}()
				select {
				case <-store.reached:
				case <-time.After(10 * time.Second):
					t.Fatal("read did not reach claimed queue")
				}
				switch change {
				case "revoke":
					if err := auth.RevokeReadGrant(g.ID, "acceptance"); err != nil {
						t.Fatal(err)
					}
				case "lock-unlock":
					if _, err := svc.Lock(context.Background(), &pb.LockRequest{}); err != nil {
						t.Fatal(err)
					}
					if _, err := svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
						t.Fatal(err)
					}
				case "recovery":
					if err := h.db.SetRecoveryPending(); err != nil {
						t.Fatal(err)
					}
				}
				release()
				select {
				case err := <-result:
					if change == "none" {
						if err != nil || len(host.srv.Commands()) != 1 {
							t.Fatalf("unchanged read: %v, %d commands", err, len(host.srv.Commands()))
						}
					} else if err == nil || len(host.srv.Commands()) != 0 {
						t.Fatalf("queued read escaped %s: %v, %d commands", change, err, len(host.srv.Commands()))
					}
				case <-time.After(10 * time.Second):
					t.Fatal("queued read did not finish")
				}
			})
		}
	}
}

func TestReadGrantUnresponsiveSessionCannotHoldLockPastReadTimeout(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted, session := make(chan net.Conn, 1), make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- raw
		defer raw.Close()
		config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), h.userKey.Marshal()) {
				return nil, fmt.Errorf("unexpected test client key")
			}
			return nil, nil
		}}
		config.AddHostKey(hostKey)
		conn, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		if channel, ok := <-channels; ok && channel.ChannelType() == "session" {
			// Never accept/reject the channel. hostrun.Attached is blocked in
			// NewSession, before its own command timeout starts.
			close(session)
			_ = conn.Wait()
		}
	}()
	pin, err := h.db.PinHostKey(executordb.HostKey{HostID: "stall-read", PublicKey: hostKey.PublicKey().Marshal(), User: "root", CredentialRef: credRef, Source: executordb.SourceProbe, PinnedBy: "acceptance"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: pin.HostID, HostKeyFingerprint: pin.Fingerprint, Criticality: pb.RiskClass_RISK_CLASS_LOW}); err != nil {
		t.Fatal(err)
	}
	for _, action := range readGrantActions {
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hexSum(readFactArtifact), ActionID: action, ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "acceptance"}); err != nil {
			t.Fatal(err)
		}
	}
	auth, svc := newReadGrantService(t, h, h.db)
	if _, err := svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	var doc permit.ReadGrantDoc
	if err := json.Unmarshal(readFactGrantDoc(t, readGrantID, time.Now(), 3), &doc); err != nil {
		t.Fatal(err)
	}
	doc.Targets = []canonical.Target{{HostID: pin.HostID, HostKeyFingerprint: pin.Fingerprint}}
	doc.Credentials = []permit.ReadGrantCredential{{HostID: pin.HostID, CredentialRef: credRef, CredentialVersion: ssh.FingerprintSHA256(h.userKey)}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = svc.RunRead(context.Background(), permit.TriggerOnDemand, &pb.RunScheduledRequest{GrantId: g.ID, TimeoutSeconds: 1, Endpoints: []string{listener.Addr().String()}, Run: &pb.AuthorizeRunRequest{HostId: pin.HostID, HostKeyFingerprint: pin.Fingerprint, ActionId: "core.facts", ModuleVersion: "1.0.0", Artifact: readFactArtifact, ParametersJson: readFactParams, CredentialRef: credRef}})
	}()
	select {
	case <-session:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not request a session")
	}
	locked := make(chan struct{})
	go func() { _, _ = svc.Lock(context.Background(), &pb.LockRequest{}); close(locked) }()
	select {
	case <-locked:
	case <-time.After(3 * time.Second):
		t.Fatal("unresponsive session held lock beyond read timeout")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed out read did not finish")
	}
}
