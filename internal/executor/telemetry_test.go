// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

func TestReadAdmissionBoundsConnectionsAcrossGrants(t *testing.T) {
	s := &Service{}
	var releases []func()
	for range 4 {
		release, err := s.admitRead()
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := s.admitRead(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("unbounded admission: %v", err)
	}
	releases[0]()
	release, err := s.admitRead()
	if err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
}

func TestRunReadSaturationRejectsBeforeAuthorityGuard(t *testing.T) {
	e := newReconcileEnv(t)
	verifier, err := webauthnverify.New(webauthnverify.Config{
		RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	entered, unblock, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	e.svc.auth, err = permit.New(permit.Options{
		Verifier: verifier, Store: e.db, RiskPolicy: risk,
		Audit: func(ev permit.Event) {
			if ev.Kind == "locked" {
				close(entered)
				<-unblock
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range maxConcurrentReads {
		release, err := e.svc.admitRead()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
	}
	// Hold the same authority mutex as a remote read's dispatch callback.
	go func() { e.svc.auth.Lock("admin"); close(finished) }()
	defer func() { close(unblock); <-finished }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("authority mutex was not acquired")
	}
	for _, trigger := range []string{permit.TriggerOnDemand, permit.TriggerScheduled} {
		t.Run(trigger, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			result := make(chan error, 1)
			go func() {
				_, err := e.svc.RunRead(ctx, trigger, &pb.RunScheduledRequest{Run: &pb.AuthorizeRunRequest{}})
				result <- err
			}()
			select {
			case err := <-result:
				if status.Code(err) != codes.ResourceExhausted {
					t.Fatalf("saturated RunRead: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("saturated RunRead blocked on the authority mutex")
			}
		})
	}
}
