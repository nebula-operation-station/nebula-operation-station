// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/totp"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	netDevGrantDevice = "core-sw"
	netDevGrantFW     = "edge-fw"
	netDevGrantSecret = "s3cr3t-switch-password"
)

// netDevGrantEnv is an executor with an unlocked keyring and vault, read
// dispatch resumed, a live CBS switch and a live PAN-OS firewall, each
// with a read credential at version 1.
type netDevGrantEnv struct {
	*reconcileEnv
	grantSeq int
}

func newNetDevGrantEnv(t *testing.T) *netDevGrantEnv {
	t.Helper()
	e := newReconcileEnv(t)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: risk, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	e.svc.SetVaultParams(testVaultParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, testVaultParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	reg := &NetDeviceRegistry{Store: e.db, Vault: e.svc.vault}
	ctx := context.Background()
	if _, err := reg.RegisterNetDevice(ctx, cbsReq(netDevGrantDevice, "10.20.0.2")); err != nil {
		t.Fatal(err)
	}
	fw := cbsReq(netDevGrantFW, "10.20.0.1")
	fw.Family, fw.PinKind, fw.Pin, fw.Port = netdevcontract.FamilyPANOS, netdevcontract.PinTLSLeaf, testNetDevPin2, 443
	if _, err := reg.RegisterNetDevice(ctx, fw); err != nil {
		t.Fatal(err)
	}
	ge := &netDevGrantEnv{reconcileEnv: e}
	for _, id := range []string{netDevGrantDevice, netDevGrantFW} {
		if _, v, err := e.svc.netDevAdmin().SetCredential(ctx, NetDevCredential{DeviceID: id, Username: "nos", Secret: []byte(netDevGrantSecret), By: "admin"}); err != nil || v != 1 {
			t.Fatalf("set credential %s: v%d %v", id, v, err)
		}
	}
	return ge
}

func (e *netDevGrantEnv) device(id string) executordb.NetDevice {
	e.t.Helper()
	d, ok, err := e.db.GetNetDevice(id)
	if err != nil || !ok {
		e.t.Fatalf("device %s: %v %v", id, ok, err)
	}
	return d
}

// target freezes the current registry row of id with the given reads.
func (e *netDevGrantEnv) target(id string, reads ...string) permit.NetDeviceTarget {
	e.t.Helper()
	d := e.device(id)
	v, err := e.svc.netDevAdmin().credentialVersion(netDevReadCredRef(d))
	if err != nil {
		e.t.Fatal(err)
	}
	return permit.NetDeviceTarget{DeviceID: d.ID, TrustPin: d.PinValue, TrustGeneration: d.TrustGeneration, CredentialVersion: v, Reads: reads}
}

// grant proposes and approves a device read lease and returns its id.
func (e *netDevGrantEnv) grant(budget, intervalS int64, lifetime time.Duration, targets ...permit.NetDeviceTarget) string {
	e.t.Helper()
	e.grantSeq++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012x", 0xd13b00+e.grantSeq)
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: id, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(lifetime).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: intervalS, RunBudget: budget,
		RateProfile: schedgrant.NetDeviceReadProfile, NetDeviceTargets: targets,
	}
	raw, err := json.Marshal(d)
	if err != nil {
		e.t.Fatal(err)
	}
	p, err := e.svc.auth.ProposeReadGrant(raw)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	if _, err := e.svc.auth.ApproveReadGrantCLI(p.Digest, "test"); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
	return id
}

// defaultGrant grants every CBS read on the switch with the default
// budget and the 15-minute floor.
func (e *netDevGrantEnv) defaultGrant() string {
	return e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, permit.DefaultReadGrantLifetime,
		e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs,
			schedgrant.NetDeviceReadCBSInterfaces, schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP))
}

func (e *netDevGrantEnv) read(id string, r pb.NetDeviceRead) error {
	got, err := e.svc.ReadNetDevice(context.Background(), &pb.ReadNetDeviceRequest{DeviceId: id, Read: r})
	if got != nil {
		e.t.Errorf("%s %v: reply %v, want none", id, r, got)
	}
	return err
}

func (e *netDevGrantEnv) check(id string, r pb.NetDeviceRead) (netDeviceGrant, error) {
	return e.svc.checkNetDeviceGrant(context.Background(), id, r, e.clock.Now())
}

// spent counts the reservations recorded for the device in the shared
// rolling-hour counter (a read grant budget of one denies after one).
func (e *netDevGrantEnv) spent(id string) int {
	e.t.Helper()
	n := 0
	for {
		ok, err := e.db.ReserveReadRun(e.anyActiveGrant(), fmt.Sprintf("probe-%d", n), netDevBudgetKey(id), e.clock.Now(), n+1, 0)
		if err != nil {
			e.t.Fatal(err)
		}
		if ok {
			return n
		}
		n++
		if n > schedgrant.NetDeviceMaxRunBudget {
			e.t.Fatal("spent counter does not converge")
		}
	}
}

func (e *netDevGrantEnv) activeGrant() (string, bool) {
	e.t.Helper()
	gs, err := e.db.ReadGrants()
	if err != nil {
		e.t.Fatal(err)
	}
	for _, g := range gs {
		if g.RevokedAt.IsZero() && e.clock.Now().Before(g.ExpiresAt) {
			return g.ID, true
		}
	}
	return "", false
}

func (e *netDevGrantEnv) anyActiveGrant() string {
	e.t.Helper()
	id, ok := e.activeGrant()
	if !ok {
		e.t.Fatal("no active grant to probe with")
	}
	return id
}

// TestNetDeviceReadNamesMatchGrantReads: every typed read of the RPC maps
// to the schedgrant read of the same name and family.
func TestNetDeviceReadNamesMatchGrantReads(t *testing.T) {
	for _, r := range append(append([]pb.NetDeviceRead{}, cbsReads...), panosReads...) {
		name, ok := netDeviceGrantRead(r)
		fam, _ := netDeviceReadFamily(r)
		if !ok || !schedgrant.IsNetDeviceRead(name) || schedgrant.NetDeviceReadFamily(name) != string(fam) {
			t.Errorf("%v: grant read %q ok=%v", r, name, ok)
		}
	}
	for _, r := range []pb.NetDeviceRead{pb.NetDeviceRead_NET_DEVICE_READ_UNSPECIFIED, pb.NetDeviceRead(11), pb.NetDeviceRead(-1)} {
		if name, ok := netDeviceGrantRead(r); ok {
			t.Errorf("%v maps to %q", r, name)
		}
	}
}

// TestReadNetDeviceGrantHappyPathRecordsSpend: an approved grant that
// matches the registry row lets the read reach Unimplemented (no device
// I/O yet) and spends one unit of the shared per-device counter.
func TestReadNetDeviceGrantHappyPathRecordsSpend(t *testing.T) {
	e := newNetDevGrantEnv(t)
	id := e.defaultGrant()
	err := e.read(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("read: %v, want Unimplemented", err)
	}
	if strings.Contains(err.Error(), netDevGrantSecret) {
		t.Fatal("error repeats the credential")
	}
	if n := e.spent(netDevGrantDevice); n != 1 {
		t.Fatalf("spent %d, want 1", n)
	}
	recs := e.logs.find("netdev_read_authorized", "")
	if len(recs) != 1 || recs[0].attrs["grant"] != id || recs[0].attrs["device"] != netDevGrantDevice {
		t.Fatalf("audit records %v, want one for grant %s", recs, id)
	}
	e.logs.mu.Lock()
	for _, r := range e.logs.records {
		if strings.Contains(r.msg+fmt.Sprint(r.attrs), netDevGrantSecret) {
			t.Error("log repeats the credential")
		}
	}
	e.logs.mu.Unlock()
}

// TestCheckNetDeviceGrantErrorClasses: each refusal has its typed error
// and its status code, and no refused call spends.
func TestCheckNetDeviceGrantErrorClasses(t *testing.T) {
	cbsVersion := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	for _, tc := range []struct {
		name  string
		setup func(e *netDevGrantEnv)
		want  error
		code  codes.Code
	}{
		{"no grant", func(*netDevGrantEnv) {}, ErrNoGrant, codes.PermissionDenied},
		{"grant for another device", func(e *netDevGrantEnv) {
			e.grant(24, 900, permit.DefaultReadGrantLifetime, e.target(netDevGrantFW, schedgrant.NetDeviceReadPANOSZones))
		}, ErrNoGrant, codes.PermissionDenied},
		{"revoked", func(e *netDevGrantEnv) {
			if err := e.svc.auth.RevokeReadGrant(e.defaultGrant(), "test"); err != nil {
				e.t.Fatal(err)
			}
		}, ErrNoGrant, codes.PermissionDenied},
		{"expired", func(e *netDevGrantEnv) {
			e.grant(24, 900, permit.ReadGrantMinLifetime, e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion))
			e.clock.Add(permit.ReadGrantMinLifetime + time.Second)
		}, ErrGrantExpired, codes.PermissionDenied},
		{"read not granted", func(e *netDevGrantEnv) {
			e.grant(24, 900, permit.DefaultReadGrantLifetime, e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSLLDP))
		}, ErrReadNotGranted, codes.PermissionDenied},
		{"stale pin", func(e *netDevGrantEnv) {
			tg := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			tg.TrustPin = testNetDevPin2
			e.grant(24, 900, permit.DefaultReadGrantLifetime, tg)
		}, ErrGrantStale, codes.PermissionDenied},
		{"stale generation", func(e *netDevGrantEnv) {
			tg := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			tg.TrustGeneration++
			e.grant(24, 900, permit.DefaultReadGrantLifetime, tg)
		}, ErrGrantStale, codes.PermissionDenied},
		{"stale credential version", func(e *netDevGrantEnv) {
			tg := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			tg.CredentialVersion = 2
			e.grant(24, 900, permit.DefaultReadGrantLifetime, tg)
		}, ErrGrantStale, codes.PermissionDenied},
		{"blocked", func(e *netDevGrantEnv) {
			e.defaultGrant()
			if _, err := e.db.BlockNetDevice(netDevGrantDevice, "test"); err != nil {
				e.t.Fatal(err)
			}
		}, ErrNetDevReadBlocked, codes.FailedPrecondition},
		{"tombstoned", func(e *netDevGrantEnv) {
			e.defaultGrant()
			if _, err := e.db.TombstoneNetDevice(netDevGrantDevice); err != nil {
				e.t.Fatal(err)
			}
		}, ErrNetDevReadGone, codes.NotFound},
		{"executor locked", func(e *netDevGrantEnv) {
			e.defaultGrant()
			e.svc.auth.Lock("test")
		}, ErrNetDevReadPaused, codes.FailedPrecondition},
		{"recovery pending", func(e *netDevGrantEnv) {
			e.defaultGrant()
			if err := e.db.SetRecoveryPending(); err != nil {
				e.t.Fatal(err)
			}
		}, ErrNetDevReadPaused, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevGrantEnv(t)
			tc.setup(e)
			if _, err := e.check(netDevGrantDevice, cbsVersion); !errors.Is(err, tc.want) {
				t.Fatalf("check: %v, want %v", err, tc.want)
			}
			if got := status.Code(netDeviceGrantStatus(tc.want)); got != tc.code {
				t.Fatalf("status %v, want %v", got, tc.code)
			}
			if got := status.Code(e.read(netDevGrantDevice, cbsVersion)); got != tc.code {
				t.Fatalf("ReadNetDevice status %v, want %v", got, tc.code)
			}
			// The spend probe below reserves, which recovery refuses.
			if err := e.db.ClearRecoveryPending(); err != nil {
				t.Fatal(err)
			}
			if _, ok := e.activeGrant(); ok && e.spent(netDevGrantDevice) != 0 {
				t.Fatal("a refused check spent")
			}
		})
	}
}

// TestCheckNetDeviceGrantNoCredential: a device without a read credential
// is refused before any grant lookup.
func TestCheckNetDeviceGrantNoCredential(t *testing.T) {
	e := newNetDevGrantEnv(t)
	reg := &NetDeviceRegistry{Store: e.db, Vault: e.svc.vault}
	req := cbsReq("bare-sw", "10.20.0.7")
	req.Pin = strings.Repeat("ab", 32)
	if _, err := reg.RegisterNetDevice(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := e.check("bare-sw", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); !errors.Is(err, ErrNetDevReadNoCredential) {
		t.Fatalf("check: %v", err)
	}
	if status.Code(netDeviceGrantStatus(ErrNetDevReadNoCredential)) != codes.FailedPrecondition {
		t.Fatal("no credential is not FailedPrecondition")
	}
}

// TestNetDeviceGrantStaleAfterRepin: a re-pin (trust generation bump)
// leaves every older grant stale; reads stay refused, nothing re-binds.
func TestNetDeviceGrantStaleAfterRepin(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.defaultGrant()
	if err := e.read(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); status.Code(err) != codes.Unimplemented {
		t.Fatalf("before repin: %v", err)
	}
	if _, err := e.db.BumpTrustGeneration(netDevGrantDevice, testNetDevPin2); err != nil {
		t.Fatal(err)
	}
	for _, r := range cbsReads {
		if _, err := e.check(netDevGrantDevice, r); !errors.Is(err, ErrGrantStale) {
			t.Fatalf("%v after repin: %v, want ErrGrantStale", r, err)
		}
		if err := e.read(netDevGrantDevice, r); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%v after repin: %v, want PermissionDenied", r, err)
		}
	}
	// A new grant for the new generation works again.
	e.defaultGrant()
	if err := e.read(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS); status.Code(err) != codes.Unimplemented {
		t.Fatalf("with new grant: %v", err)
	}
}

// TestNetDeviceGrantStaleAfterRotation: a credential rotation leaves every
// older grant stale.
func TestNetDeviceGrantStaleAfterRotation(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.defaultGrant()
	if _, v, err := e.svc.netDevAdmin().RotateCredential(context.Background(), NetDevCredential{
		DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte("rotated-secret"), ExpectedVersion: 1, By: "admin"}); err != nil || v != 2 {
		t.Fatalf("rotate: v%d %v", v, err)
	}
	for _, r := range cbsReads {
		if _, err := e.check(netDevGrantDevice, r); !errors.Is(err, ErrGrantStale) {
			t.Fatalf("%v after rotation: %v, want ErrGrantStale", r, err)
		}
	}
}

// TestNetDeviceGrantPausedByLock: after Lock no read is authorized, even
// once the vault alone is unlocked again; only a credential unlock (which
// resumes read dispatch) lets reads continue.
func TestNetDeviceGrantPausedByLock(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.usePrivateKeyring()
	e.defaultGrant()
	if _, err := e.svc.Lock(context.Background(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); !errors.Is(err, ErrNetDevReadPaused) {
		t.Fatalf("after lock: %v", err)
	}
	if err := e.read(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("after lock: %v, want FailedPrecondition", err)
	}
	if err := e.svc.vault.Unlock([]byte(strings.Repeat("correct-horse-battery-staple-", 4))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); !errors.Is(err, ErrNetDevReadPaused) {
		t.Fatalf("vault unlocked, keys locked: %v", err)
	}
	e.localUnlock()
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); err != nil {
		t.Fatalf("after local credential unlock: %v", err)
	}
}

// localUnlock is the local credential unlock (keys scope) that resumes
// read dispatch for SSH, provider and device reads alike.
func (e *netDevGrantEnv) localUnlock() {
	e.t.Helper()
	resp, err := e.svc.Unlock(context.Background(), &pb.UnlockRequest{Passphrase: []byte(testPassphrase), Scope: pb.UnlockScope_UNLOCK_SCOPE_KEYS})
	if err != nil || !resp.GetKeysUnlocked() {
		e.t.Fatalf("local unlock: %v %v", resp, err)
	}
}

// TestNetDeviceGrantPausedAfterRecoveryUntilUnlock: a recovery login
// pauses device reads like every other read; finishing the recovery does
// not resume them, only the local credential unlock does.
func TestNetDeviceGrantPausedAfterRecoveryUntilUnlock(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.usePrivateKeyring()
	e.defaultGrant()
	v := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	secret := []byte(strings.Repeat("r", 20))
	if err := e.db.SetTOTP(secret, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.UseTOTPStep(1); err != nil { // activates the secret
		t.Fatal(err)
	}
	if _, err := e.svc.RecoveryLogin(context.Background(), &pb.RecoveryLoginRequest{Code: totp.Code(secret, time.Now())}); err != nil {
		t.Fatalf("recovery login: %v", err)
	}
	if _, err := e.check(netDevGrantDevice, v); !errors.Is(err, ErrNetDevReadPaused) {
		t.Fatalf("recovery pending: %v, want ErrNetDevReadPaused", err)
	}
	// FinishRecovery's state change: the recovery is no longer pending.
	if err := e.db.ClearRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.check(netDevGrantDevice, v); !errors.Is(err, ErrNetDevReadPaused) {
		t.Fatalf("recovery finished, not unlocked: %v, want ErrNetDevReadPaused", err)
	}
	if err := e.read(netDevGrantDevice, v); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("recovery finished, not unlocked: %v, want FailedPrecondition", err)
	}
	e.localUnlock()
	if _, err := e.check(netDevGrantDevice, v); err != nil {
		t.Fatalf("after local credential unlock: %v", err)
	}
}

// TestNetDeviceGrantRecheckAfterReserveReleases: a lock, re-pin, credential
// rotation or block between the reservation and the return refuses the
// read and gives the reservation back (budget and interval).
func TestNetDeviceGrantRecheckAfterReserveReleases(t *testing.T) {
	v := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	for _, tc := range []struct {
		name  string
		act   func(e *netDevGrantEnv)
		want  error
		after func(e *netDevGrantEnv) // restores a state a new check may pass
	}{
		{"lock", func(e *netDevGrantEnv) { e.svc.auth.Lock("test") }, ErrNetDevReadPaused,
			func(e *netDevGrantEnv) { e.localUnlock() }},
		{"repin", func(e *netDevGrantEnv) {
			if _, err := e.db.BumpTrustGeneration(netDevGrantDevice, testNetDevPin2); err != nil {
				e.t.Fatal(err)
			}
		}, ErrGrantStale, func(e *netDevGrantEnv) { e.defaultGrant() }},
		{"rotation", func(e *netDevGrantEnv) {
			if _, _, err := e.svc.netDevAdmin().RotateCredential(context.Background(), NetDevCredential{
				DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte("rotated-secret"), ExpectedVersion: 1, By: "admin"}); err != nil {
				e.t.Fatal(err)
			}
		}, ErrGrantStale, func(e *netDevGrantEnv) { e.defaultGrant() }},
		{"block", func(e *netDevGrantEnv) {
			if _, err := e.db.BlockNetDevice(netDevGrantDevice, "test"); err != nil {
				e.t.Fatal(err)
			}
		}, ErrNetDevReadBlocked, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevGrantEnv(t)
			e.usePrivateKeyring()
			e.defaultGrant()
			calls := 0
			hook := func() { calls++; tc.act(e) }
			netDevAfterReserve.Store(&hook)
			t.Cleanup(func() { netDevAfterReserve.Store(nil) })
			if _, err := e.check(netDevGrantDevice, v); !errors.Is(err, tc.want) {
				t.Fatalf("check: %v, want %v", err, tc.want)
			}
			netDevAfterReserve.Store(nil)
			if calls != 1 {
				t.Fatalf("hook ran %d times, want 1", calls)
			}
			if _, ok, err := e.db.ReadActionLastRun(netDevActionKey(schedgrant.NetDeviceReadCBSVersion), netDevBudgetKey(netDevGrantDevice)); err != nil || ok {
				t.Fatalf("interval still reserved: %v %v", ok, err)
			}
			if recs := e.logs.find("netdev_read_authorized", ""); len(recs) != 0 {
				t.Fatalf("refused read audited as authorized: %v", recs)
			}
			if tc.after != nil {
				tc.after(e)
				// The interval was released, so the same read runs at once.
				if _, err := e.check(netDevGrantDevice, v); err != nil {
					t.Fatalf("after release: %v", err)
				}
				return
			}
			if n := e.spent(netDevGrantDevice); n != 0 {
				t.Fatalf("spent %d after release, want 0", n)
			}
		})
	}
}

// TestNetDeviceGrantTooSoonAfterRestart: the interval refusal is told from
// the budget refusal by the durable counters, so a restarted executor (new
// authority and handler on the same store) still reports ErrTooSoon.
func TestNetDeviceGrantTooSoonAfterRestart(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.defaultGrant()
	v := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	if _, err := e.check(netDevGrantDevice, v); err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: e.db, RiskPolicy: risk, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewService(auth, e.svc.keys, e.db, e.svc.reg, e.svc.log)
	restarted.Now = e.clock.Now
	if _, err := restarted.checkNetDeviceGrant(context.Background(), netDevGrantDevice, v, e.clock.Now()); !errors.Is(err, ErrNetDevReadPaused) {
		t.Fatalf("restart before unlock: %v, want ErrNetDevReadPaused", err)
	}
	if err := auth.ResumeReadDispatch(); err != nil { // local credential unlock
		t.Fatal(err)
	}
	e.clock.Add(schedgrant.NetDeviceMinInterval - time.Second)
	if _, err := restarted.checkNetDeviceGrant(context.Background(), netDevGrantDevice, v, e.clock.Now()); !errors.Is(err, ErrTooSoon) {
		t.Fatalf("within floor after restart: %v, want ErrTooSoon", err)
	}
	e.clock.Add(time.Second)
	if _, err := restarted.checkNetDeviceGrant(context.Background(), netDevGrantDevice, v, e.clock.Now()); err != nil {
		t.Fatalf("after floor: %v", err)
	}
}

// TestNetDeviceGrantBudgetNotTooSoon: an exhausted budget with no recent
// run of the read is ErrBudget, never ErrTooSoon.
func TestNetDeviceGrantBudgetNotTooSoon(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.grant(1, 900, permit.DefaultReadGrantLifetime, e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs))
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); err != nil {
		t.Fatal(err)
	}
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS); !errors.Is(err, ErrBudget) {
		t.Fatalf("other read, budget spent: %v, want ErrBudget", err)
	}
}

// TestNetDeviceGrantFifteenMinuteFloor: the same read on the same device
// is refused within 15 minutes, also under a second grant and also when
// the grant asked for less; another read is not affected.
func TestNetDeviceGrantFifteenMinuteFloor(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.defaultGrant()
	v := pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	if _, err := e.check(netDevGrantDevice, v); err != nil {
		t.Fatal(err)
	}
	e.defaultGrant() // a second grant must not reset the floor
	e.clock.Add(schedgrant.NetDeviceMinInterval - time.Second)
	if _, err := e.check(netDevGrantDevice, v); !errors.Is(err, ErrTooSoon) {
		t.Fatalf("within floor: %v, want ErrTooSoon", err)
	}
	if status.Code(netDeviceGrantStatus(ErrTooSoon)) != codes.ResourceExhausted {
		t.Fatal("too soon is not ResourceExhausted")
	}
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS); err != nil {
		t.Fatalf("other read: %v", err)
	}
	e.clock.Add(time.Second)
	if _, err := e.check(netDevGrantDevice, v); err != nil {
		t.Fatalf("after floor: %v", err)
	}
}

// TestNetDeviceGrantBudgetExhausted: the per-device rolling-hour budget is
// shared across reads and grants; the next call is ErrBudget.
func TestNetDeviceGrantBudgetExhausted(t *testing.T) {
	e := newNetDevGrantEnv(t)
	tg := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSLLDP)
	e.grant(2, 900, permit.DefaultReadGrantLifetime, tg)
	e.grant(2, 900, permit.DefaultReadGrantLifetime, tg)
	for _, r := range []pb.NetDeviceRead{pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS} {
		if _, err := e.check(netDevGrantDevice, r); err != nil {
			t.Fatalf("%v: %v", r, err)
		}
	}
	_, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP)
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("third read: %v, want ErrBudget", err)
	}
	if err := e.read(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("rpc: %v, want ResourceExhausted", err)
	}
	e.clock.Add(permit.RollingHour + time.Second)
	if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP); err != nil {
		t.Fatalf("after the hour: %v", err)
	}
}

// TestNetDeviceGrantConcurrentCallsKeepBudget: many concurrent calls
// against a budget of 3 succeed exactly three times.
func TestNetDeviceGrantConcurrentCallsKeepBudget(t *testing.T) {
	e := newNetDevGrantEnv(t)
	all := []string{schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSInterfaces,
		schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSLLDP}
	e.grant(3, 900, permit.DefaultReadGrantLifetime, e.target(netDevGrantDevice, all...))
	var (
		wg                     sync.WaitGroup
		mu                     sync.Mutex
		exhausted, unimpl, bad int
	)
	for i := 0; i < 20; i++ {
		r := cbsReads[i%len(cbsReads)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.ReadNetDevice(context.Background(), &pb.ReadNetDeviceRequest{DeviceId: netDevGrantDevice, Read: r})
			mu.Lock()
			defer mu.Unlock()
			switch status.Code(err) {
			case codes.Unimplemented:
				unimpl++
			case codes.ResourceExhausted:
				exhausted++
			default:
				bad++
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if unimpl != 3 || bad != 0 {
		t.Fatalf("authorized %d (want 3), exhausted %d, other %d", unimpl, exhausted, bad)
	}
	if n := e.spent(netDevGrantDevice); n != 3 {
		t.Fatalf("spent %d, want 3", n)
	}
}
