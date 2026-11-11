// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

const (
	regCfgDigest = "5555555555555555555555555555555555555555555555555555555555555555"
	regCredID    = "0123456789abcdef0123456789abcdef"
)

func registryDocAt(now time.Time, lifetime time.Duration) ReadGrantDoc {
	return ReadGrantDoc{
		Grant: ReadGrantFormat, ID: rgID, Issuer: "root",
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(lifetime).Unix(),
		Trigger: TriggerOnDemand, MinIntervalS: 900, RunBudget: schedgrant.RegistryDefaultRunBudget,
		RateProfile: schedgrant.RegistryReadProfile,
		RegistryTargets: []RegistryTarget{{
			RegistryID: "harbor", ConfigDigest: regCfgDigest, ConfigVersion: 1,
			CredentialID: regCredID, CredentialVersion: 2,
			Repositories: []string{"team/app", "team/worker"},
			Methods:      []string{schedgrant.RegistryReadTagDigest},
		}},
	}
}

func cloneRegistryDoc(d ReadGrantDoc) ReadGrantDoc {
	ts := make([]RegistryTarget, len(d.RegistryTargets))
	for i, t := range d.RegistryTargets {
		t.Repositories = append([]string(nil), t.Repositories...)
		t.Methods = append([]string(nil), t.Methods...)
		ts[i] = t
	}
	d.RegistryTargets = ts
	return d
}

func TestRegistryGrantParses(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for _, lifetime := range []time.Duration{ReadGrantMinLifetime, schedgrant.RegistryReadMaxLifetime} {
		d := registryDocAt(now, lifetime)
		doc, canon, digest, err := ParseReadGrant(readGrantRaw(t, d), now)
		if err != nil {
			t.Fatalf("valid registry grant (%v) rejected: %v", lifetime, err)
		}
		if len(digest) != 64 || len(doc.RegistryTargets) != 1 {
			t.Fatalf("unexpected parse result %+v", doc)
		}
		if !bytes.Contains(canon, []byte(`"registry_targets":[{"config_digest":"`+regCfgDigest+`","config_version":1,"credential_id":"`+regCredID+`","credential_version":2`)) {
			t.Fatalf("canonical form lacks the bound registry identity: %s", canon)
		}
	}
	d := registryDocAt(now, time.Hour)
	d.RunBudget = schedgrant.RegistryMaxRunBudget
	d.RegistryTargets[0].Methods = schedgrant.RegistryReadMethods()
	d.RegistryTargets[0].CredentialVersion = 1<<53 - 1
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("boundary registry grant rejected: %v", err)
	}
}

func TestRegistryGrantRejectsInvalidFields(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	ordinary := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	many := make([]RegistryTarget, MaxRegistryTargets+1)
	for i := range many {
		many[i] = registryDocAt(now, time.Hour).RegistryTargets[0]
		many[i].RegistryID = "r" + strings.Repeat("a", i%10) + string(rune('a'+i%26))
	}
	manyRepos := make([]string, MaxRegistryRepositories+1)
	for i := range manyRepos {
		manyRepos[i] = "team/app" + strings.Repeat("x", i)
	}
	cases := map[string]func(*ReadGrantDoc){
		"over 7 days": func(d *ReadGrantDoc) {
			d.ExpiryUnix = d.CreatedUnix + int64(schedgrant.RegistryReadMaxLifetime/time.Second) + 1
		},
		"scheduled trigger":     func(d *ReadGrantDoc) { d.Trigger = TriggerScheduled },
		"both trigger":          func(d *ReadGrantDoc) { d.Trigger = TriggerBoth },
		"interval below floor":  func(d *ReadGrantDoc) { d.MinIntervalS = 899 },
		"interval above max":    func(d *ReadGrantDoc) { d.MinIntervalS = int64(schedgrant.MaxInterval/time.Second) + 1 },
		"budget zero":           func(d *ReadGrantDoc) { d.RunBudget = 0 },
		"budget above max":      func(d *ReadGrantDoc) { d.RunBudget = schedgrant.RegistryMaxRunBudget + 1 },
		"ssh actions":           func(d *ReadGrantDoc) { d.Actions = ordinary.Actions },
		"ssh hosts":             func(d *ReadGrantDoc) { d.Targets = ordinary.Targets },
		"ssh credentials":       func(d *ReadGrantDoc) { d.Credentials = ordinary.Credentials },
		"provider remotes":      func(d *ReadGrantDoc) { d.ProviderTargets = []ProviderTarget{{}} },
		"network devices":       func(d *ReadGrantDoc) { d.NetDeviceTargets = netDeviceDocAt(now, time.Hour).NetDeviceTargets },
		"no registry":           func(d *ReadGrantDoc) { d.RegistryTargets = nil },
		"too many registries":   func(d *ReadGrantDoc) { d.RegistryTargets = many },
		"bad registry id":       func(d *ReadGrantDoc) { d.RegistryTargets[0].RegistryID = "Harbor" },
		"registry twice":        func(d *ReadGrantDoc) { d.RegistryTargets = append(d.RegistryTargets, d.RegistryTargets[0]) },
		"bad config digest":     func(d *ReadGrantDoc) { d.RegistryTargets[0].ConfigDigest = "AB" + regCfgDigest[2:] },
		"short config digest":   func(d *ReadGrantDoc) { d.RegistryTargets[0].ConfigDigest = regCfgDigest[:63] },
		"bad credential id":     func(d *ReadGrantDoc) { d.RegistryTargets[0].CredentialID = "secret" },
		"config version zero":   func(d *ReadGrantDoc) { d.RegistryTargets[0].ConfigVersion = 0 },
		"cred version zero":     func(d *ReadGrantDoc) { d.RegistryTargets[0].CredentialVersion = 0 },
		"cred version too big":  func(d *ReadGrantDoc) { d.RegistryTargets[0].CredentialVersion = 1 << 53 },
		"no repository":         func(d *ReadGrantDoc) { d.RegistryTargets[0].Repositories = nil },
		"too many repositories": func(d *ReadGrantDoc) { d.RegistryTargets[0].Repositories = manyRepos },
		"repository with host":  func(d *ReadGrantDoc) { d.RegistryTargets[0].Repositories = []string{"Registry.example:5000/app"} },
		"repository with tag":   func(d *ReadGrantDoc) { d.RegistryTargets[0].Repositories = []string{"team/app:latest"} },
		"repository twice":      func(d *ReadGrantDoc) { d.RegistryTargets[0].Repositories = []string{"team/app", "team/app"} },
		"no method":             func(d *ReadGrantDoc) { d.RegistryTargets[0].Methods = nil },
		"blob method":           func(d *ReadGrantDoc) { d.RegistryTargets[0].Methods = []string{"blob"} },
		"pull method":           func(d *ReadGrantDoc) { d.RegistryTargets[0].Methods = []string{"pull"} },
		"method twice": func(d *ReadGrantDoc) {
			d.RegistryTargets[0].Methods = []string{schedgrant.RegistryReadTagDigest, schedgrant.RegistryReadTagDigest}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := cloneRegistryDoc(registryDocAt(now, time.Hour))
			mutate(&d)
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("invalid registry grant accepted")
			}
		})
	}
}

func TestOnlyRegistryLeasesBindRegistries(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	targets := registryDocAt(now, time.Hour).RegistryTargets
	ordinary := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	ordinary.RegistryTargets = targets
	netdev := netDeviceDocAt(now, DefaultReadGrantLifetime)
	netdev.RegistryTargets = targets
	for name, d := range map[string]ReadGrantDoc{"ordinary": ordinary, "netdevice": netdev} {
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Errorf("%s grant with registry targets accepted", name)
		}
	}
}

func TestRegistryTargetLookup(t *testing.T) {
	d := registryDocAt(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), time.Hour)
	tg, ok := d.RegistryTarget("harbor")
	if !ok || !tg.AllowsRead(schedgrant.RegistryReadTagDigest, "team/app") {
		t.Fatal("bound read not allowed")
	}
	if tg.AllowsRead(schedgrant.RegistryReadListTags, "team/app") {
		t.Fatal("unbound method allowed")
	}
	if tg.AllowsRead(schedgrant.RegistryReadTagDigest, "team/other") || tg.AllowsRead(schedgrant.RegistryReadTagDigest, "team") {
		t.Fatal("out-of-scope repository allowed")
	}
	if _, ok := d.RegistryTarget("other"); ok {
		t.Fatal("unknown registry found")
	}
	c := cloneReadGrantDoc(d)
	c.RegistryTargets[0].Repositories[0] = "evil/app"
	if d.RegistryTargets[0].Repositories[0] != "team/app" {
		t.Fatal("cloneReadGrantDoc shares registry repositories")
	}
}
