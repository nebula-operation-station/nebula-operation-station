// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

const (
	pvePinA = "1111111111111111111111111111111111111111111111111111111111111111"
	pvePinB = "2222222222222222222222222222222222222222222222222222222222222222"
)

func providerDocAt(now time.Time, id string, budget int64, methods ...string) ReadGrantDoc {
	if len(methods) == 0 {
		methods = []string{ProviderMethodNodes, ProviderMethodGuests}
	}
	return ReadGrantDoc{
		Grant: ReadGrantFormat, ID: id, Issuer: "root",
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(DefaultReadGrantLifetime).Unix(),
		Trigger: TriggerScheduled, MinIntervalS: 60, RunBudget: budget, RateProfile: ProviderReadProfile,
		Actions: []ReadGrantAction{}, Targets: nil,
		ProviderTargets: []ProviderTarget{{RemoteID: "pve-1", TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 1, Methods: methods}},
	}
}

func providerRead(method string) ProviderRead {
	return ProviderRead{RemoteID: "pve-1", Method: method, TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 1}
}

func TestProviderGrantDocValidation(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	ok := providerDocAt(now, rgID, 240)
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, ok), now); err != nil {
		t.Fatalf("valid provider grant rejected: %v", err)
	}
	ordinary := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	cases := map[string]func(d *ReadGrantDoc){
		"ssh action":           func(d *ReadGrantDoc) { d.Actions = ordinary.Actions },
		"ssh target":           func(d *ReadGrantDoc) { d.Targets = ordinary.Targets },
		"ssh credential":       func(d *ReadGrantDoc) { d.Credentials = ordinary.Credentials },
		"on-demand only":       func(d *ReadGrantDoc) { d.Trigger = TriggerOnDemand },
		"interval below 60s":   func(d *ReadGrantDoc) { d.MinIntervalS = 59 },
		"budget zero":          func(d *ReadGrantDoc) { d.RunBudget = 0 },
		"budget above max":     func(d *ReadGrantDoc) { d.RunBudget = MaxProviderRequestBudget + 1 },
		"no remotes":           func(d *ReadGrantDoc) { d.ProviderTargets = nil },
		"bad remote id":        func(d *ReadGrantDoc) { d.ProviderTargets[0].RemoteID = "PVE 1" },
		"bad pin":              func(d *ReadGrantDoc) { d.ProviderTargets[0].TrustPin = "abc" },
		"generation zero":      func(d *ReadGrantDoc) { d.ProviderTargets[0].TrustGeneration = 0 },
		"generation too large": func(d *ReadGrantDoc) { d.ProviderTargets[0].TrustGeneration = 1 << 48 },
		"credential version 0": func(d *ReadGrantDoc) { d.ProviderTargets[0].CredentialVersion = 0 },
		"no methods":           func(d *ReadGrantDoc) { d.ProviderTargets[0].Methods = nil },
		"unknown method":       func(d *ReadGrantDoc) { d.ProviderTargets[0].Methods = []string{"proxy"} },
		"metrics method":       func(d *ReadGrantDoc) { d.ProviderTargets[0].Methods = []string{"metrics"} },
		"duplicate method":     func(d *ReadGrantDoc) { d.ProviderTargets[0].Methods = []string{"nodes", "nodes"} },
		"duplicate remote":     func(d *ReadGrantDoc) { d.ProviderTargets = append(d.ProviderTargets, d.ProviderTargets[0]) },
		"too many remotes": func(d *ReadGrantDoc) {
			for i := 0; i < MaxProviderTargets; i++ {
				t := d.ProviderTargets[0]
				t.RemoteID = "pve-x" + strings.Repeat("a", i+1)
				d.ProviderTargets = append(d.ProviderTargets, t)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := providerDocAt(now, rgID, 240)
			d.ProviderTargets = append([]ProviderTarget(nil), d.ProviderTargets...)
			mutate(&d)
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("malformed provider grant accepted")
			}
		})
	}
	// SSH profiles cannot smuggle provider scope.
	for _, profile := range []string{"ordinary", "telemetry"} {
		d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
		d.RateProfile = profile
		d.ProviderTargets = ok.ProviderTargets
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Fatalf("%s grant with provider targets accepted", profile)
		}
	}
}

func TestProviderReadRequiresCoveringGrant(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err == nil {
		t.Fatal("read authorized without any grant")
	} else {
		wantCode(t, err, CodeLeaseNotCovered)
	}
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240)))
	claim, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes))
	if err != nil {
		t.Fatalf("covered read denied: %v", err)
	}
	if claim.GrantID != rgID || claim.Check() != nil {
		t.Fatalf("claim %+v does not check", claim)
	}
	for name, r := range map[string]ProviderRead{
		"method not granted":     providerRead(ProviderMethodStorage),
		"other remote":           {RemoteID: "pve-2", Method: ProviderMethodNodes, TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 1},
		"pin changed":            {RemoteID: "pve-1", Method: ProviderMethodGuests, TrustPin: pvePinB, TrustGeneration: 1, CredentialVersion: 1},
		"generation changed":     {RemoteID: "pve-1", Method: ProviderMethodGuests, TrustPin: pvePinA, TrustGeneration: 2, CredentialVersion: 1},
		"credential was rotated": {RemoteID: "pve-1", Method: ProviderMethodGuests, TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 2},
	} {
		if _, err := e.auth.AuthorizeProviderRead(r); err == nil {
			t.Fatalf("%s: read authorized", name)
		} else {
			wantCode(t, err, CodeLeaseNotCovered)
		}
	}
	if _, err := e.auth.AuthorizeProviderRead(ProviderRead{RemoteID: "pve-1", Method: "metrics"}); err == nil {
		t.Fatal("metrics read authorized")
	} else {
		wantCode(t, err, CodeLeaseInvalid)
	}
}

// An SSH read grant confers no provider authority and a provider grant
// confers no SSH authority.
func TestProviderAndSSHGrantsAreDisjoint(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, readGrantDocAt(t, e.clk.Now(), DefaultReadGrantLifetime)))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err == nil {
		t.Fatal("ssh grant authorized a provider read")
	}
	g := approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID2, 240)))
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e1", TriggerScheduled, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("provider grant authorized an SSH run")
	}
}

func TestProviderReadIntervalAndBudget(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 3)))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err != nil {
		t.Fatal(err)
	}
	// Same method inside the approved interval.
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err == nil {
		t.Fatal("second read inside the interval authorized")
	} else {
		wantCode(t, err, CodeLeaseBudget)
	}
	// Another method has its own interval but shares the remote budget.
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(time.Minute)
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("read beyond the rolling-hour request budget authorized")
	} else {
		wantCode(t, err, CodeLeaseBudget)
	}
	// A second covering grant cannot multiply the per-remote counter past
	// its own budget.
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID2, 3)))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("overlapping grant refilled the shared budget")
	}
}

func TestProviderReadExpiryAndRevocation(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240)))
	claim, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes))
	if err != nil {
		t.Fatal(err)
	}
	// Revocation while the request is in flight discards its result.
	if n, err := e.auth.RevokeProviderGrants("pve-1", "test"); err != nil || n != 1 {
		t.Fatalf("revoke = %d, %v", n, err)
	}
	if err := claim.Check(); err == nil {
		t.Fatal("claim survived revocation")
	}
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("revoked grant authorized a read")
	}
	if n, err := e.auth.RevokeProviderGrants("pve-2", "test"); err != nil || n != 0 {
		t.Fatalf("revoke unrelated remote = %d, %v", n, err)
	}

	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID2, 240)))
	claim, err = e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests))
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Add(DefaultReadGrantLifetime)
	if err := claim.Check(); err == nil {
		t.Fatal("claim survived grant expiry")
	}
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err == nil {
		t.Fatal("expired grant authorized a read")
	}
}

// Lock invalidates reserved reads and pauses new ones; a restart starts
// paused, keeps spent budget, and only local credential unlock resumes.
func TestProviderReadLockAndRestart(t *testing.T) {
	store, counters := newMemStore(), newMemCounters()
	e := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	le := newMemLeases()
	e.auth.leases = le
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 1)))
	claim, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes))
	if err != nil {
		t.Fatal(err)
	}
	e.auth.Lock("test")
	if err := claim.Check(); err == nil {
		t.Fatal("claim survived lock")
	} else {
		wantCode(t, err, CodeLeaseInactive)
	}
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("read authorized while locked")
	} else {
		wantCode(t, err, CodeLeaseInactive)
	}
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	if err := claim.Check(); err == nil {
		t.Fatal("claim from before the lock survived unlock")
	}

	e2 := newEnvWithStores(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{}, store, counters)
	e2.auth.leases = le
	if _, err := e2.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("read authorized after restart before unlock")
	} else {
		wantCode(t, err, CodeLeaseInactive)
	}
	if err := e2.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	e2.clk.Add(2 * time.Minute)
	if _, err := e2.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("spent budget refilled by restart")
	} else {
		wantCode(t, err, CodeLeaseBudget)
	}
}

func TestProviderReadRecoveryAndStorageFailClosed(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240)))
	claim, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes))
	if err != nil {
		t.Fatal(err)
	}
	le.recovering = true
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("read authorized during recovery")
	}
	if err := claim.Check(); err == nil {
		t.Fatal("claim checked during recovery")
	}
	le.recovering = false
	le.failReserve = true
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("read authorized when the budget store fails")
	}
	le.failReserve = false
	// A tampered stored grant fails closed.
	le.setDigest(rgID, strings.Repeat("0", 64))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err == nil {
		t.Fatal("tampered grant authorized a read")
	}
}

// Per-guest methods keep one interval per guest, so a collection cycle can
// read every guest once, while all of them spend the one remote budget.
func TestProviderGuestReadIntervalIsPerGuest(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	doc := providerDocAt(e.clk.Now(), rgID, 4)
	doc.ProviderTargets[0].Methods = []string{ProviderMethodSnapshots}
	approveReadGrant(t, e, readGrantRaw(t, doc))
	guest := func(vmid uint64) ProviderRead {
		r := providerRead(ProviderMethodSnapshots)
		r.VMID = vmid
		return r
	}
	for _, vmid := range []uint64{100, 101} {
		if _, err := e.auth.AuthorizeProviderRead(guest(vmid)); err != nil {
			t.Fatalf("guest %d: %v", vmid, err)
		}
	}
	// Budget is left (2 of 4), so this denial is the guest's own interval.
	_, err := e.auth.AuthorizeProviderRead(guest(100))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(time.Minute)
	if _, err := e.auth.AuthorizeProviderRead(guest(100)); err != nil {
		t.Fatalf("guest 100 after its interval: %v", err)
	}
	if _, err := e.auth.AuthorizeProviderRead(guest(102)); err != nil {
		t.Fatal(err)
	}
	// All guests spend the one remote budget of 4.
	_, err = e.auth.AuthorizeProviderRead(guest(103))
	wantCode(t, err, CodeLeaseBudget)
}

func TestProviderReadRejectsMisplacedVMID(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	doc := providerDocAt(e.clk.Now(), rgID, 240)
	doc.ProviderTargets[0].Methods = []string{ProviderMethodNodes, ProviderMethodGuestConfig}
	approveReadGrant(t, e, readGrantRaw(t, doc))
	for name, r := range map[string]ProviderRead{
		"guest method without vmid": providerRead(ProviderMethodGuestConfig),
		"remote method with vmid":   func() ProviderRead { r := providerRead(ProviderMethodNodes); r.VMID = 100; return r }(),
		"vmid below range":          func() ProviderRead { r := providerRead(ProviderMethodGuestConfig); r.VMID = 99; return r }(),
		"vmid above contract range": func() ProviderRead { r := providerRead(ProviderMethodGuestConfig); r.VMID = 1e10; return r }(),
	} {
		_, err := e.auth.AuthorizeProviderRead(r)
		if err == nil {
			t.Fatalf("%s: authorized", name)
		}
		wantCode(t, err, CodeLeaseInvalid)
	}
}
