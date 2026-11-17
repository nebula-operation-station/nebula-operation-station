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
	return newNetDevGrantEnvWithCredentials(t, netDevGrantDevice, netDevGrantFW)
}

// newNetDevGrantEnvWithCredentials is newNetDevGrantEnv, but only the
// devices in withCredential get their first read credential; the others
// stay at credential version 0.
func newNetDevGrantEnvWithCredentials(t *testing.T, withCredential ...string) *netDevGrantEnv {
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
	for _, id := range withCredential {
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

// TestNetDeviceGrantStaleAfterRotation: a credential rotation revokes every
// older grant of the device (ADR 0010 D2), so none is merely stale: each is
// revoked in the store and no read is authorized. (The stale path itself is
// covered by TestNetDeviceGrantStaleAfterRepin, which bumps the trust
// generation without the lifecycle.)
func TestNetDeviceGrantStaleAfterRotation(t *testing.T) {
	e := newNetDevGrantEnv(t)
	e.defaultGrant()
	if _, v, err := e.svc.netDevAdmin().RotateCredential(context.Background(), NetDevCredential{
		DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte("rotated-secret"), ExpectedVersion: 1, By: "admin"}); err != nil || v != 2 {
		t.Fatalf("rotate: v%d %v", v, err)
	}
	for _, r := range cbsReads {
		if _, err := e.check(netDevGrantDevice, r); !errors.Is(err, ErrNoGrant) {
			t.Fatalf("%v after rotation: %v, want ErrNoGrant (old lease revoked)", r, err)
		}
	}
	gs, err := e.db.ReadGrants()
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) == 0 {
		t.Fatal("no stored lease")
	}
	for _, g := range gs {
		if g.RevokedAt.IsZero() {
			t.Errorf("lease %s still active after rotation", g.ID)
		}
	}
}

// TestNetDevLifecycleRevokesLeasesAheadOfRegistry (ADR 0010 D1/D2): a
// lease approved ahead of the registry (credential version or trust
// generation the device does not have yet) must not go live once a later
// credential set, rotation, block, unblock, re-pin or removal brings the
// registry to that identity. Each lifecycle step revokes every device read
// lease of the device, so the ahead lease is revoked in the store right
// after that step alone and, once the registry has caught up, it still
// authorizes no read. A lease of the other device is untouched.
func TestNetDevLifecycleRevokesLeasesAheadOfRegistry(t *testing.T) {
	ctx := context.Background()
	// The re-pin case runs the production Repin against a loopback SSH
	// endpoint that presents the new host key.
	repinSrv := startNetDevSSHServer(t)
	newPin := sshPinOf(repinSrv.key)
	rotate := func(e *netDevGrantEnv, from int64) {
		e.t.Helper()
		if _, v, err := e.svc.netDevAdmin().RotateCredential(ctx, NetDevCredential{
			DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte("rotated-secret"), ExpectedVersion: from, By: "admin"}); err != nil || v != from+1 {
			e.t.Fatalf("rotate from v%d: v%d %v", from, v, err)
		}
	}
	block := func(e *netDevGrantEnv) {
		e.t.Helper()
		if _, err := e.svc.netDevAdmin().Block(ctx, netDevGrantDevice, "maintenance"); err != nil {
			e.t.Fatalf("block: %v", err)
		}
	}
	unblock := func(e *netDevGrantEnv) {
		e.t.Helper()
		if _, err := e.svc.netDevAdmin().Unblock(ctx, netDevGrantDevice, netDevConfirmWord); err != nil {
			e.t.Fatalf("unblock: %v", err)
		}
	}
	cases := []struct {
		name string
		// noCredential leaves the switch without a read credential
		// (credential version 0) before the lease is approved.
		noCredential bool
		// prepare runs before the lease is approved (nil for none).
		prepare func(*netDevGrantEnv)
		// ahead edits the lease target to an identity the registry reaches
		// only through lifecycle or catchUp.
		ahead func(*permit.NetDeviceTarget)
		// before is the refusal of the read before the lifecycle step.
		before error
		// lifecycle is the single admin step that must revoke the lease;
		// the store is checked right after it.
		lifecycle func(*netDevGrantEnv)
		// catchUp brings the registry to the lease's identity (nil when the
		// lifecycle step itself does).
		catchUp func(*netDevGrantEnv)
		// want is the refusal of the read after catch-up.
		want error
	}{
		// First credential set: a lease approved for credential version 1
		// while the device had no credential must not go live once the
		// admin stores the first credential (version 1).
		{"first credential set", true, nil, func(t *permit.NetDeviceTarget) { t.CredentialVersion = 1 }, ErrNetDevReadNoCredential,
			func(e *netDevGrantEnv) {
				if _, v, err := e.svc.netDevAdmin().SetCredential(ctx, NetDevCredential{
					DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte(netDevGrantSecret), By: "admin"}); err != nil || v != 1 {
					e.t.Fatalf("set credential: v%d %v", v, err)
				}
			}, nil, ErrNoGrant},
		{"rotation", false, nil, func(t *permit.NetDeviceTarget) { t.CredentialVersion = 2 }, ErrGrantStale,
			func(e *netDevGrantEnv) { rotate(e, 1) }, nil, ErrNoGrant},
		// Block alone must revoke: the store is checked before the unblock
		// (which revokes too) and the rotation that catches up.
		{"block", false, nil, func(t *permit.NetDeviceTarget) { t.CredentialVersion = 2 }, ErrGrantStale,
			block, func(e *netDevGrantEnv) { unblock(e); rotate(e, 1) }, ErrNoGrant},
		// A lease approved while the device is blocked: only the unblock
		// can revoke it, so it is the step under test.
		{"unblock", false, block, func(t *permit.NetDeviceTarget) { t.CredentialVersion = 2 }, ErrNetDevReadBlocked,
			unblock, func(e *netDevGrantEnv) { rotate(e, 1) }, ErrNoGrant},
		// Re-pin through the production Repin (probe of the new key, the
		// permit check stubbed to approve), which reaches the ahead lease's
		// trust generation and pin itself.
		{"re-pin", false, nil, func(t *permit.NetDeviceTarget) { t.TrustGeneration = 2; t.TrustPin = newPin }, ErrGrantStale,
			func(e *netDevGrantEnv) {
				a := e.svc.netDevAdmin()
				d := &netDevDialer{target: repinSrv.addr}
				a.Dial = d.dial
				a.AuthorizeRepin = func(context.Context, NetDevRepinBinding, string) error { return nil }
				if _, err := a.Repin(ctx, netDevGrantDevice, testNetDevPin, newPin, "digest"); err != nil {
					e.t.Fatalf("repin: %v", err)
				}
			}, nil, ErrNoGrant},
		// Removal tombstones the id: no read at all, and the lease is
		// revoked so it cannot match a later registration.
		{"removal", false, nil, func(t *permit.NetDeviceTarget) { t.CredentialVersion = 2 }, ErrGrantStale,
			func(e *netDevGrantEnv) {
				if _, err := e.svc.netDevAdmin().Remove(ctx, netDevGrantDevice, netDevConfirmWord); err != nil {
					e.t.Fatalf("remove: %v", err)
				}
			}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e *netDevGrantEnv
			if tc.noCredential {
				e = newNetDevGrantEnvWithCredentials(t, netDevGrantFW)
			} else {
				e = newNetDevGrantEnv(t)
			}
			if tc.prepare != nil {
				tc.prepare(e)
			}
			tgt := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			tc.ahead(&tgt)
			id := e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, time.Hour, tgt)
			fwID := e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, time.Hour, e.target(netDevGrantFW, schedgrant.NetDeviceReadPANOSZones))
			// Ahead of the registry: refused before the lifecycle.
			if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); !errors.Is(err, tc.before) {
				t.Fatalf("before %s: %v, want %v", tc.name, err, tc.before)
			}
			tc.lifecycle(e)
			revoked := map[string]bool{}
			gs, err := e.db.ReadGrants()
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range gs {
				revoked[g.ID] = !g.RevokedAt.IsZero()
			}
			if !revoked[id] {
				t.Errorf("%s left the lease ahead of the registry active", tc.name)
			}
			if revoked[fwID] {
				t.Errorf("%s revoked the other device's lease", tc.name)
			}
			if tc.catchUp != nil {
				tc.catchUp(e)
			}
			if tc.want == nil {
				// Removed: the device is gone, so no lease can cover it.
				if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); err == nil {
					t.Fatal("read of a removed device authorized")
				}
				return
			}
			// The registry now has exactly the identity the lease named.
			cur := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			if cur.TrustGeneration != tgt.TrustGeneration || cur.CredentialVersion != tgt.CredentialVersion || cur.TrustPin != tgt.TrustPin {
				t.Fatalf("registry at %+v, lease at %+v: catch-up did not reach the lease identity", cur, tgt)
			}
			if _, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); !errors.Is(err, tc.want) {
				t.Fatalf("after %s and catch-up: %v, want %v (the ahead lease went live)", tc.name, err, tc.want)
			}
		})
	}
}

// setNetDevCredWriteHook installs f as the credential write stage hook for
// this test only.
func setNetDevCredWriteHook(t *testing.T, f func(stage netDevCredWriteStage, deviceID string)) {
	t.Helper()
	netDevCredWriteHook.Store(&f)
	t.Cleanup(func() { netDevCredWriteHook.Store(nil) })
}

// concurrentRead runs one CBS version read of the switch on another
// goroutine and returns its result.
func (e *netDevGrantEnv) concurrentRead() error {
	done := make(chan error, 1)
	go func() {
		got, err := e.svc.ReadNetDevice(context.Background(), &pb.ReadNetDeviceRequest{DeviceId: netDevGrantDevice, Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION})
		if got != nil {
			err = errors.Join(err, fmt.Errorf("read reply %v, want none", got))
		}
		done <- err
	}()
	return <-done
}

// TestReadNetDeviceRefusedBetweenCredentialCommitAndRevocation (ADR 0010
// D1/D2): at every stage of a credential write (blocked before the commit,
// committed before the revocation, revoked before the unblock) a read on
// another goroutine is refused by the credential write lock (Unavailable;
// a lock taken only after the commit or released before the revocation
// fails this), the device is durably blocked, and the lease check alone
// (without the lock) refuses too. After the commit the new version is
// visible and leases approved ahead of the registry for it (one before the
// write, one inside the window) are active until the revocation. After the
// write both are revoked, the device is unblocked, and only a lease
// approved afterwards authorizes a read. First set, first rotation and a
// later rotation, each through the RPC handler (holding netDevAdminMu) and
// through NetDevAdmin directly.
func TestReadNetDeviceRefusedBetweenCredentialCommitAndRevocation(t *testing.T) {
	ctx := context.Background()
	type tcase struct {
		name string
		from int64 // credential version before the write
		rpc  bool  // through the RPC handler, else NetDevAdmin directly
	}
	var cases []tcase
	for _, c := range []tcase{{"first set", 0, false}, {"first rotation", 1, false}, {"later rotation", 2, false}} {
		cases = append(cases, c)
		c.rpc, c.name = true, c.name+" via RPC"
		cases = append(cases, c)
	}
	read := func(e *netDevGrantEnv) error {
		got, err := e.svc.ReadNetDevice(ctx, &pb.ReadNetDeviceRequest{DeviceId: netDevGrantDevice, Read: pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION})
		if got != nil {
			e.t.Errorf("read reply %v, want none", got)
		}
		return err
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e *netDevGrantEnv
			if tc.from == 0 {
				e = newNetDevGrantEnvWithCredentials(t, netDevGrantFW)
			} else {
				e = newNetDevGrantEnv(t)
			}
			for v := int64(1); v < tc.from; v++ {
				if _, err := e.svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: netDevGrantDevice, Username: "nos",
					Secret: []byte("step-secret"), ExpectedCredentialVersion: v}); err != nil {
					t.Fatalf("prepare rotation from v%d: %v", v, err)
				}
			}
			tgt := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
			if tgt.CredentialVersion != tc.from {
				t.Fatalf("registry at credential version %d, want %d", tgt.CredentialVersion, tc.from)
			}
			tgt.CredentialVersion = tc.from + 1
			// Approved before the write, ahead of the registry.
			e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, time.Hour, tgt)

			stages := map[netDevCredWriteStage]bool{}
			setNetDevCredWriteHook(t, func(stage netDevCredWriteStage, deviceID string) {
				if deviceID != netDevGrantDevice {
					return
				}
				stages[stage] = true
				wantVersion := tc.from
				if stage != netDevCredBeforeCommit {
					wantVersion = tc.from + 1
				}
				if cur := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion); cur.CredentialVersion != wantVersion {
					t.Errorf("stage %d: credential version %d, want %d", stage, cur.CredentialVersion, wantVersion)
				}
				if d := e.device(netDevGrantDevice); !d.Blocked || d.BlockReason != netDevCredChangeReason {
					t.Errorf("stage %d: blocked %v reason %q, want the durable credential change block", stage, d.Blocked, d.BlockReason)
				}
				_, active := e.activeGrant()
				switch stage {
				case netDevCredAfterCommit:
					// The window: committed, the ahead lease not yet revoked.
					if !active {
						t.Error("after commit: the ahead lease is already revoked; the window is not forced")
					}
					// A second lease approved inside the window.
					e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, time.Hour, tgt)
				case netDevCredAfterRevoke:
					if active {
						t.Error("after revoke: a lease is still active")
					}
				}
				if err := e.concurrentRead(); status.Code(err) != codes.Unavailable {
					t.Errorf("concurrent read at stage %d: %v, want Unavailable (credential write lock held)", stage, err)
				}
				// Without the lock the block still refuses the lease check.
				if g, err := e.check(netDevGrantDevice, pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION); err == nil {
					t.Errorf("lease check at stage %d authorized lease %s", stage, g.GrantID)
				}
				// spent records a probe reservation itself, so it is taken
				// once, in the window, covering the reads of both stages.
				if stage == netDevCredAfterCommit {
					if n := e.spent(netDevGrantDevice); n != 0 {
						t.Errorf("reads before the revocation spent %d", n)
					}
				}
			})
			var err error
			switch {
			case tc.rpc && tc.from == 0:
				_, err = e.svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: netDevGrantDevice, Username: "nos", Secret: []byte("first-secret")})
			case tc.rpc:
				_, err = e.svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: netDevGrantDevice, Username: "nos",
					Secret: []byte("rotated-secret"), ExpectedCredentialVersion: tc.from})
			case tc.from == 0:
				_, _, err = e.svc.netDevAdmin().SetCredential(ctx, NetDevCredential{DeviceID: netDevGrantDevice, Username: "nos", Secret: []byte("first-secret"), By: "admin"})
			default:
				_, _, err = e.svc.netDevAdmin().RotateCredential(ctx, NetDevCredential{DeviceID: netDevGrantDevice, Username: "nos",
					Secret: []byte("rotated-secret"), ExpectedVersion: tc.from, By: "admin"})
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			for _, st := range []netDevCredWriteStage{netDevCredBeforeCommit, netDevCredAfterCommit, netDevCredAfterRevoke} {
				if !stages[st] {
					t.Fatalf("stage hook %d did not run", st)
				}
			}
			if d := e.device(netDevGrantDevice); d.Blocked {
				t.Fatalf("after %s: device still blocked (%q)", tc.name, d.BlockReason)
			}
			// Both ahead leases are revoked; the read is now refused for
			// lack of a lease, not for the write in progress.
			if id, ok := e.activeGrant(); ok {
				t.Fatalf("lease %s still active after %s", id, tc.name)
			}
			if err := read(e); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("read after %s: %v, want PermissionDenied", tc.name, err)
			}
			// A lease approved after the write authorizes the read.
			e.grant(schedgrant.NetDeviceDefaultRunBudget, 900, time.Hour, tgt)
			if err := read(e); status.Code(err) != codes.Unimplemented {
				t.Fatalf("read under a lease approved after %s: %v, want Unimplemented (authorized)", tc.name, err)
			}
		})
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
