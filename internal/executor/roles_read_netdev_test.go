// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

const roNetDevLeaseID = "00000000-0000-4000-8000-0000000a1000"

// leaseDoc returns a device read lease document over targets.
func (e *netDevGrantEnv) leaseDoc(targets ...permit.NetDeviceTarget) []byte {
	e.t.Helper()
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: roNetDevLeaseID, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(permit.DefaultReadGrantLifetime).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 900, RunBudget: schedgrant.NetDeviceDefaultRunBudget,
		RateProfile: schedgrant.NetDeviceReadProfile, NetDeviceTargets: targets,
	}
	raw, err := json.Marshal(d)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *netDevGrantEnv) proposeLease(raw []byte) (*pb.ProposeReadGrantResponse, error) {
	return e.svc.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{GrantJson: raw})
}

// TestProposeNetDeviceLeaseChecksRegistry (A1-0): ProposeReadGrant refuses a
// device read lease whose device is unknown, removed or blocked, or whose
// frozen pin, trust generation, credential version or read family differ
// from the registry, with InvalidArgument, a message without device data and
// no pending grant. A lease matching the registry is proposed.
func TestProposeNetDeviceLeaseChecksRegistry(t *testing.T) {
	cbsReads := []string{schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs}
	for _, tc := range []struct {
		name   string
		setup  func(*netDevGrantEnv)
		mutate func(*permit.NetDeviceTarget)
	}{
		{name: "unknown device", mutate: func(tg *permit.NetDeviceTarget) { tg.DeviceID = "ghost-sw" }},
		{name: "tombstoned device", setup: func(e *netDevGrantEnv) {
			if _, err := e.db.TombstoneNetDevice(netDevGrantDevice); err != nil {
				e.t.Fatal(err)
			}
		}},
		{name: "blocked device", setup: func(e *netDevGrantEnv) {
			if _, err := e.db.BlockNetDevice(netDevGrantDevice, "test"); err != nil {
				e.t.Fatal(err)
			}
		}},
		{name: "stale pin", mutate: func(tg *permit.NetDeviceTarget) { tg.TrustPin = testNetDevPin2 }},
		{name: "wrong trust generation", mutate: func(tg *permit.NetDeviceTarget) { tg.TrustGeneration++ }},
		{name: "wrong credential version", mutate: func(tg *permit.NetDeviceTarget) { tg.CredentialVersion++ }},
		{name: "re-pinned after the target was frozen", setup: func(e *netDevGrantEnv) {
			if _, err := e.db.BumpTrustGeneration(netDevGrantDevice, testNetDevPin2); err != nil {
				e.t.Fatal(err)
			}
		}},
		{name: "reads of another device family", mutate: func(tg *permit.NetDeviceTarget) {
			tg.Reads = []string{schedgrant.NetDeviceReadPANOSZones}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevGrantEnv(t)
			tg := e.target(netDevGrantDevice, cbsReads...)
			if tc.mutate != nil {
				tc.mutate(&tg)
			}
			if tc.setup != nil {
				tc.setup(e)
			}
			fw := e.target(netDevGrantFW, schedgrant.NetDeviceReadPANOSZones)
			// The refused device is listed second so that a valid first
			// target cannot make the check pass.
			_, err := e.proposeLease(e.leaseDoc(fw, tg))
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("propose: %v, want InvalidArgument", err)
			}
			msg := status.Convert(err).Message()
			for _, leak := range []string{tg.DeviceID, tg.TrustPin, netDevGrantFW, testNetDevPin2, "10.20.0."} {
				if strings.Contains(msg, leak) {
					t.Errorf("refusal %q carries device data %q", msg, leak)
				}
			}
			if p := e.svc.auth.PendingReadGrants(); len(p) != 0 {
				t.Fatalf("refused lease left %d pending grants", len(p))
			}
		})
	}

	t.Run("valid targets", func(t *testing.T) {
		e := newNetDevGrantEnv(t)
		raw := e.leaseDoc(e.target(netDevGrantDevice, cbsReads...), e.target(netDevGrantFW, schedgrant.NetDeviceReadPANOSZones))
		pg, err := e.proposeLease(raw)
		if err != nil {
			t.Fatalf("propose: %v", err)
		}
		p := e.svc.auth.PendingReadGrants()
		if len(p) != 1 || p[0].Digest != pg.GetGrantDigest() {
			t.Fatalf("pending grants %v, want the proposed lease", p)
		}
	})
}

// TestProposeNetDeviceLeaseStoreErrorIsUnavailable: a registry lookup that
// fails is a store error (adminStoreError), not a proposal.
func TestProposeNetDeviceLeaseStoreErrorIsUnavailable(t *testing.T) {
	e := newNetDevGrantEnv(t)
	raw := e.leaseDoc(e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion))
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := e.proposeLease(raw)
	if status.Code(err) != codes.Unavailable || !strings.HasPrefix(status.Convert(err).Message(), "storage_error: ") {
		t.Fatalf("propose on a closed store: %v, want adminStoreError Unavailable", err)
	}
	if p := e.svc.auth.PendingReadGrants(); len(p) != 0 {
		t.Fatalf("store error left %d pending grants", len(p))
	}
}
