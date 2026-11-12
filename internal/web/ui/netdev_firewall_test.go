// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the PAN-OS firewall view (ADR 0010 D4, ND-20): rules in
// rulebase order, NAT rules, object usage counts, hit counts with the
// counter reset time, the unused-rule hint only after at least 30 observed
// days and never as a delete proposal, the "changed in elements not
// displayed" note, hostile device text escaped, admin-only access, 404 for
// non-PAN-OS devices and the strict CSP on every answer.

package ui_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakeFirewallStore adds stored hit counts, config drift and injected
// store errors to fakeNetDevStore.
type fakeFirewallStore struct {
	*fakeNetDevStore
	hits map[string][]netdevcontract.HitCount
	// drift is the ConfigChangedNotDisplayed answer per device.
	drift map[string]netdevinventory.ConfigDrift
	// The *Err fields, when set, are returned by the matching method.
	hitsErr, driftErr, policyErr, datasetErr error
}

func (f *fakeFirewallStore) HitCounts(_ context.Context, id string) ([]netdevcontract.HitCount, error) {
	if f.hitsErr != nil {
		return nil, f.hitsErr
	}
	if v, ok := f.hits[id]; ok {
		return v, nil
	}
	return nil, netdevinventory.ErrDatasetNotFound
}

func (f *fakeFirewallStore) ConfigChangedNotDisplayed(_ context.Context, id string) (netdevinventory.ConfigDrift, error) {
	if f.driftErr != nil {
		return netdevinventory.ConfigDrift{}, f.driftErr
	}
	return f.drift[id], nil
}

func (f *fakeFirewallStore) FirewallPolicy(ctx context.Context, id string) (netdevcontract.FirewallPolicy, error) {
	if f.policyErr != nil {
		return netdevcontract.FirewallPolicy{}, f.policyErr
	}
	return f.fakeNetDevStore.FirewallPolicy(ctx, id)
}

func (f *fakeFirewallStore) GetDataset(ctx context.Context, id string, read netdevinventory.Read) (netdevinventory.Dataset, error) {
	if f.datasetErr != nil {
		return netdevinventory.Dataset{}, f.datasetErr
	}
	return f.fakeNetDevStore.GetDataset(ctx, id, read)
}

// firewallEnv is a netdevEnv with the detail pages and the firewall view
// mounted behind the real auth and security middleware.
type firewallEnv struct {
	*netdevEnv
	fw *fakeFirewallStore
	// adminErr, when set, is returned by the admin check.
	adminErr error
}

func newFirewallEnv(t *testing.T) *firewallEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	e := &netdevEnv{t: t, store: newFakeNetDevStore(), admins: map[string]bool{"alice": true}}
	fw := &fakeFirewallStore{fakeNetDevStore: e.store, hits: map[string][]netdevcontract.HitCount{}, drift: map[string]netdevinventory.ConfigDrift{}}
	fe := &firewallEnv{netdevEnv: e, fw: fw}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{PublicOrigin: pveOrigin, Log: log, Now: func() time.Time { return netdevNow }})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	isAdmin := func(_ context.Context, user string) (bool, error) {
		if fe.adminErr != nil {
			// A failing check still says "admin" to prove the error wins.
			return true, fe.adminErr
		}
		return e.admins[user], nil
	}
	registry := func(context.Context) ([]ui.NetDevRegistryEntry, error) { return e.registry, e.regErr }
	pages, err := u.NetDevPages(ui.NetDevOptions{Store: e.store, Registry: registry, IsAdmin: isAdmin})
	if err != nil {
		t.Fatalf("NetDevPages: %v", err)
	}
	fwPage, err := u.NetDevFirewallPage(ui.NetDevFirewallOptions{Store: fw, Registry: registry, IsAdmin: isAdmin})
	if err != nil {
		t.Fatalf("NetDevFirewallPage: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", u.Handler())
	pages.Register(mux)
	fwPage.Register(mux)
	e.sessions = auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: e.sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(mux)))
	t.Cleanup(e.srv.Close)
	e.cookie = e.session("cred-alice", "alice")
	return fe
}

// hitsObservedAt is when addPANOS stores the hit-count dataset.
var hitsObservedAt = netdevNow.Add(-10 * time.Minute)

func ptrTime(t time.Time) *time.Time { return &t }

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func TestNetDevFirewallNewNeedsStoreAndAdminCheck(t *testing.T) {
	u, err := ui.New(ui.Options{PublicOrigin: pveOrigin, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	fw := &fakeFirewallStore{fakeNetDevStore: newFakeNetDevStore()}
	if _, err := u.NetDevFirewallPage(ui.NetDevFirewallOptions{Store: fw}); err == nil {
		t.Error("NetDevFirewallPage without IsAdmin succeeded")
	}
	if _, err := u.NetDevFirewallPage(ui.NetDevFirewallOptions{IsAdmin: func(context.Context, string) (bool, error) { return true, nil }}); err == nil {
		t.Error("NetDevFirewallPage without Store succeeded")
	}
}

func TestNetDevFirewallRulesInRulebaseOrder(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	// Names deliberately not sorted: the page must keep the stored order.
	names := []string{"zz-allow-dns", "aa-deny-all", "mm-allow-web", "bb-last"}
	var pol netdevcontract.FirewallPolicy
	for _, n := range names {
		pol.SecurityRules = append(pol.SecurityRules, netdevcontract.SecurityRule{Name: n, From: []string{"trust"},
			To: []string{"untrust"}, Source: []string{"any"}, Destination: []string{"any"}, Application: []string{"dns"},
			Service: []string{"application-default"}, Action: netdevcontract.ActionAllow})
	}
	pol.SecurityRules[1].Action = netdevcontract.ActionDeny
	pol.SecurityRules[3].Disabled = true
	natNames := []string{"nat-z", "nat-a", "nat-m"}
	for _, n := range natNames {
		pol.NATRules = append(pol.NATRules, netdevcontract.NATRule{Name: n, From: []string{"trust"}, To: []string{"untrust"},
			Source: []string{"any"}, Destination: []string{"any"}, SourceTranslation: "dynamic-ip-and-port ethernet1/1"})
	}
	e.store.policy["fw1"] = pol
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	assertInOrder(t, body, names)
	assertInOrder(t, body, natNames)
	for _, want := range []string{"deny", "allow", "disabled", "dynamic-ip-and-port ethernet1/1", "trust", "untrust", "application-default"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Rule positions are numbered from 1 in rulebase order.
	if !regexp.MustCompile(`<td>1</td>\s*<td[^>]*>zz-allow-dns</td>`).MatchString(body) {
		t.Error("first rule is not shown as position 1")
	}
}

func assertInOrder(t *testing.T, body string, names []string) {
	t.Helper()
	last := -1
	for _, n := range names {
		i := strings.Index(body, ">"+n+"<")
		if i < 0 {
			t.Errorf("page lacks %q", n)
			continue
		}
		if i < last {
			t.Errorf("%q is out of rulebase order", n)
		}
		last = i
	}
}

func TestNetDevFirewallHostileTextIsEscaped(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", hostileStrings[0])
	var pol netdevcontract.FirewallPolicy
	for _, s := range hostileStrings {
		pol.SecurityRules = append(pol.SecurityRules, netdevcontract.SecurityRule{Name: s, From: []string{s}, To: []string{s},
			Source: []string{s}, Destination: []string{s}, Application: []string{s}, Service: []string{s},
			Action: netdevcontract.RuleAction(s), Description: s, Tags: []string{s}})
		pol.NATRules = append(pol.NATRules, netdevcontract.NATRule{Name: s, From: []string{s}, To: []string{s}, Source: []string{s},
			Destination: []string{s}, Service: s, SourceTranslation: s, DestinationTranslation: s, Description: s})
		pol.Addresses = append(pol.Addresses, netdevcontract.AddressObject{Name: s, Type: netdevcontract.AddressType(s), Value: s, Description: s})
		pol.Services = append(pol.Services, netdevcontract.ServiceObject{Name: s, Protocol: s, Port: s, Description: s})
		pol.AddressGroups = append(pol.AddressGroups, netdevcontract.Group{Name: s + "-g", Static: []string{s}, DynamicFilter: s})
		pol.ServiceGroups = append(pol.ServiceGroups, netdevcontract.Group{Name: s + "-sg", Static: []string{s}})
		e.fw.hits["fw1"] = append(e.fw.hits["fw1"], netdevcontract.HitCount{RuleName: s, Hits: 3,
			LastHit: ptrTime(netdevNow.Add(-time.Hour)), ResetAt: ptrTime(netdevNow.Add(-days(40)))})
	}
	e.store.policy["fw1"] = pol
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	assertNoHostileMarkup(t, body)
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("hostile rule name is not shown as escaped text")
	}
	if !strings.Contains(body, "evil"+replacement+"gnp.exe") {
		t.Error("bidi override is not replaced")
	}
}

func TestNetDevFirewallNeedsAdmin(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{SecurityRules: []netdevcontract.SecurityRule{{Name: "secret-rule", Action: netdevcontract.ActionAllow}}}
	bob := e.session("cred-bob", "bob")
	for _, path := range []string{"/netdev/fw1/firewall", "/netdev/unknown/firewall"} {
		res, body := e.getAs(bob, path)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s as non-admin = %d, want 403", path, res.StatusCode)
		}
		if strings.Contains(body, "secret-rule") || strings.Contains(body, "Edge") {
			t.Errorf("GET %s as non-admin leaks device data", path)
		}
		if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
			t.Errorf("GET %s as non-admin: CSP = %q", path, got)
		}
	}
	res, _ := e.getAs(nil, "/netdev/fw1/firewall")
	if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
		t.Errorf("GET firewall logged out = %d, want redirect", res.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/netdev/fw1/firewall", strings.NewReader(""))
	req.Header.Set("Origin", pveOrigin)
	req.AddCookie(e.cookie)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST firewall = %d, want 405", res2.StatusCode)
	}
}

func TestNetDevFirewallAdminCheckErrorFailsClosed(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{SecurityRules: []netdevcontract.SecurityRule{{Name: "secret-rule", Action: netdevcontract.ActionAllow}}}
	e.adminErr = errors.New("role lookup failed: db=/var/lib/nebula/secret.db")
	res, body := e.getAs(e.cookie, "/netdev/fw1/firewall")
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("GET firewall with failing admin check = %d, want 403", res.StatusCode)
	}
	for _, leak := range []string{"secret-rule", "Edge", "role lookup failed", "secret.db"} {
		if strings.Contains(body, leak) {
			t.Errorf("failing admin check leaks %q", leak)
		}
	}
	if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
		t.Errorf("failing admin check: CSP = %q", got)
	}
	// Without an error, a user without the role is refused too.
	e.adminErr = nil
	e.admins = nil
	if res, _ := e.getAs(e.cookie, "/netdev/fw1/firewall"); res.StatusCode != http.StatusForbidden {
		t.Errorf("GET firewall without admin role = %d, want 403", res.StatusCode)
	}
}

func TestNetDevFirewallOnlyForPANOS(t *testing.T) {
	e := newFirewallEnv(t)
	e.addCBS("sw1", "Core")
	e.addPANOS("fw1", "Edge")
	for _, path := range []string{"/netdev/sw1/firewall", "/netdev/unknown/firewall", "/netdev/bad%20id/firewall"} {
		code, body := e.get(path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
		if strings.Contains(body, "Core") {
			t.Errorf("GET %s leaks device data", path)
		}
	}
	res, _ := e.getAs(e.cookie, "/netdev/fw1/firewall")
	if res.StatusCode != http.StatusOK {
		t.Errorf("GET PAN-OS firewall view = %d, want 200", res.StatusCode)
	}
	// The 200 page carries the same strict CSP as every other answer.
	if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
		t.Errorf("GET PAN-OS firewall view: CSP = %q, want %q", got, netdevCSP)
	}
}

// hintPolicy is one rule per hit-count case.
func hintPolicy() netdevcontract.FirewallPolicy {
	var pol netdevcontract.FirewallPolicy
	for _, n := range []string{"r-45d", "r-29d", "r-30d", "r-hit", "r-noreset", "r-nocount", "r-future"} {
		pol.SecurityRules = append(pol.SecurityRules, netdevcontract.SecurityRule{Name: n, Action: netdevcontract.ActionAllow})
	}
	return pol
}

// ruleRow returns the table row of a security rule.
func ruleRow(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<tr id="rule-\d+">.*?</tr>`).FindAllString(body, -1)
	for _, row := range m {
		if strings.Contains(row, ">"+name+"<") {
			return row
		}
	}
	t.Fatalf("no row for rule %q", name)
	return ""
}

func TestNetDevFirewallUnusedRuleHint(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = hintPolicy()
	reset45 := hitsObservedAt.Add(-days(45))
	e.fw.hits["fw1"] = []netdevcontract.HitCount{
		{RuleName: "r-45d", Hits: 0, ResetAt: ptrTime(reset45)},
		{RuleName: "r-29d", Hits: 0, ResetAt: ptrTime(hitsObservedAt.Add(-days(29)))},
		{RuleName: "r-30d", Hits: 0, ResetAt: ptrTime(hitsObservedAt.Add(-days(30)))},
		{RuleName: "r-hit", Hits: 7, FirstHit: ptrTime(reset45.Add(time.Hour)), LastHit: ptrTime(netdevNow.Add(-2 * time.Hour)), ResetAt: ptrTime(reset45)},
		{RuleName: "r-noreset", Hits: 0},
		{RuleName: "r-future", Hits: 0, ResetAt: ptrTime(netdevNow.Add(days(40)))},
	}
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	row := ruleRow(t, body, "r-45d")
	if !strings.Contains(row, "no hits in 45 days") {
		t.Errorf("rule with 45 observed days lacks the hint: %s", row)
	}
	if !strings.Contains(row, `<time datetime="`+reset45.UTC().Format(time.RFC3339)+`">`) {
		t.Errorf("hint row lacks the counter reset time: %s", row)
	}
	if row := ruleRow(t, body, "r-30d"); !strings.Contains(row, "no hits in 30 days") {
		t.Errorf("rule with exactly 30 observed days lacks the hint: %s", row)
	}
	for _, n := range []string{"r-29d", "r-hit", "r-noreset", "r-nocount", "r-future"} {
		if row := ruleRow(t, body, n); strings.Contains(row, "no hits in") {
			t.Errorf("rule %s shows the unused hint: %s", n, row)
		}
	}
	if row := ruleRow(t, body, "r-hit"); !strings.Contains(row, ">7<") ||
		!strings.Contains(row, `<time datetime="`+netdevNow.Add(-2*time.Hour).UTC().Format(time.RFC3339)+`">`) {
		t.Errorf("hit count or last hit missing: %s", row)
	}
	if !strings.Contains(body, "since counter reset at") {
		t.Error("page lacks the counter reset label")
	}
	assertNoChangeProposal(t, body)
}

// assertNoChangeProposal checks the view is read-only: no form, button or
// delete/disable proposal.
func assertNoChangeProposal(t *testing.T, body string) {
	t.Helper()
	_, content, _ := strings.Cut(body, `aria-label="Firewall view"`)
	if content == "" {
		t.Fatal("firewall section missing")
	}
	lower := strings.ToLower(content)
	for _, bad := range []string{"<form", "<button", "delete", "remove", "disable this", "clean up", "cleanup"} {
		if strings.Contains(lower, bad) {
			t.Errorf("firewall view contains %q", bad)
		}
	}
}

func TestNetDevFirewallNoHintWithoutHitCounts(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = hintPolicy()
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	if strings.Contains(body, "no hits in") {
		t.Error("hint shown without stored hit counts")
	}
	if !strings.Contains(body, "No hit counts read yet.") {
		t.Error("missing hit counts are not stated")
	}
}

func TestNetDevFirewallObjectUsage(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{
		SecurityRules: []netdevcontract.SecurityRule{
			{Name: "r1", Source: []string{"obj-web"}, Service: []string{"svc-https"}, Action: netdevcontract.ActionAllow},
			{Name: "r2", Destination: []string{"grp-inner", "obj-web"}, Action: netdevcontract.ActionAllow},
			{Name: "r3", Source: []string{"grp-outer"}, Service: []string{"svc-grp"}, Action: netdevcontract.ActionAllow},
		},
		NATRules: []netdevcontract.NATRule{{Name: "n1", Destination: []string{"obj-db"}}},
		Addresses: []netdevcontract.AddressObject{
			{Name: "obj-web", Type: netdevcontract.AddressNetmask, Value: "10.0.0.1/32"},
			{Name: "obj-db", Type: netdevcontract.AddressNetmask, Value: "10.0.0.2/32"},
			{Name: "obj-unused", Type: netdevcontract.AddressNetmask, Value: "10.0.0.3/32"},
		},
		AddressGroups: []netdevcontract.Group{
			{Name: "grp-inner", Static: []string{"obj-web"}},
			// A cycle must not loop.
			{Name: "grp-outer", Static: []string{"grp-inner", "grp-outer"}},
		},
		Services:      []netdevcontract.ServiceObject{{Name: "svc-https", Protocol: "tcp", Port: "443"}},
		ServiceGroups: []netdevcontract.Group{{Name: "svc-grp", Static: []string{"svc-https"}}},
	}
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	for name, want := range map[string]string{
		"obj-web":    "used by 3 rules", // r1 direct, r2 direct and nested (counted once), r3 via grp-outer
		"obj-db":     "used by 1 rule",  // NAT rule n1
		"obj-unused": "used by 0 rules",
		"grp-inner":  "used by 2 rules",
		"grp-outer":  "used by 1 rule",
		"svc-https":  "used by 2 rules",
		"svc-grp":    "used by 1 rule",
	} {
		row := objectRow(t, body, name)
		if !strings.Contains(row, want+"<") {
			t.Errorf("object %s: want %q in %s", name, want, row)
		}
	}
	assertNoChangeProposal(t, body)
}

func objectRow(t *testing.T, body, name string) string {
	t.Helper()
	for _, row := range regexp.MustCompile(`(?s)<tr class="object">.*?</tr>`).FindAllString(body, -1) {
		if strings.Contains(row, ">"+name+"<") {
			return row
		}
	}
	t.Fatalf("no row for object %q", name)
	return ""
}

const (
	notDisplayedNote   = "Configuration changed in elements not displayed"
	readIncompleteNote = "Read incomplete"
)

func TestNetDevFirewallIncompleteReadShowsReadIncomplete(t *testing.T) {
	cases := []struct {
		name       string
		incomplete bool
		state      netdevinventory.DatasetState
	}{
		{"incomplete flag", true, netdevinventory.StateFresh},
		{"partial state", false, netdevinventory.StatePartial},
		{"both", true, netdevinventory.StatePartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFirewallEnv(t)
			e.addPANOS("fw1", "Edge")
			e.store.policy["fw1"] = hintPolicy()
			_, body := e.get("/netdev/fw1/firewall")
			if strings.Contains(body, readIncompleteNote) || strings.Contains(body, notDisplayedNote) {
				t.Fatal("complete policy without drift shows a note")
			}
			ds := e.store.datasets["fw1"][netdevinventory.ReadFirewallPolicy]
			ds.Incomplete, ds.State = c.incomplete, c.state
			e.store.datasets["fw1"][netdevinventory.ReadFirewallPolicy] = ds
			_, body = e.get("/netdev/fw1/firewall")
			if !strings.Contains(body, readIncompleteNote) {
				t.Error("partial policy read is not shown as read incomplete")
			}
			// A truncated read is not a policy change.
			if strings.Contains(body, notDisplayedNote) {
				t.Error("partial policy read is shown as a change in elements not displayed")
			}
		})
	}
}

func TestNetDevFirewallRawOnlyDriftShowsElementsNotDisplayed(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.addPANOS("fw2", "Branch")
	e.store.policy["fw1"] = hintPolicy()
	e.store.policy["fw2"] = hintPolicy()
	// fw1: raw_digest changed while the redacted text did not.
	changedAfter := netdevNow.Add(-3 * time.Hour)
	seenAt := netdevNow.Add(-2 * time.Hour)
	e.fw.drift["fw1"] = netdevinventory.ConfigDrift{NotDisplayed: true, ChangedAfter: changedAfter,
		SeenAt: seenAt, LastSeen: netdevNow.Add(-10 * time.Minute)}
	_, body := e.get("/netdev/fw1/firewall")
	note := notDisplayedBanner(t, body)
	// The banner dates the change: after which read, first seen when.
	for _, want := range []string{
		`after the read at <time datetime="` + changedAfter.UTC().Format(time.RFC3339) + `">`,
		`first seen at <time datetime="` + seenAt.UTC().Format(time.RFC3339) + `">`,
	} {
		if !strings.Contains(note, want) {
			t.Errorf("banner lacks %q: %s", want, note)
		}
	}
	// A return to an earlier version: the first read is not known and the
	// banner says so instead of showing the old first_seen.
	e.fw.drift["fw1"] = netdevinventory.ConfigDrift{NotDisplayed: true, ChangedAfter: changedAfter,
		LastSeen: netdevNow.Add(-10 * time.Minute)}
	_, body = e.get("/netdev/fw1/firewall")
	if note := notDisplayedBanner(t, body); !strings.Contains(note, "first read showing it is not stored") ||
		strings.Contains(note, "first seen at") ||
		!strings.Contains(note, `<time datetime="`+changedAfter.UTC().Format(time.RFC3339)+`">`) {
		t.Errorf("banner for a return to an earlier version: %s", note)
	}
	if strings.Contains(body, readIncompleteNote) {
		t.Error("drift on a complete read is shown as read incomplete")
	}
	// The stored policy is still shown next to the note.
	if !strings.Contains(body, ">r-45d<") {
		t.Error("drift note hides the stored rules")
	}
	_, body = e.get("/netdev/fw2/firewall")
	if strings.Contains(body, notDisplayedNote) {
		t.Error("device without drift shows the not-displayed note")
	}
	// Drift and a partial read are two separate notes.
	ds := e.store.datasets["fw1"][netdevinventory.ReadFirewallPolicy]
	ds.Incomplete, ds.State = true, netdevinventory.StatePartial
	e.store.datasets["fw1"][netdevinventory.ReadFirewallPolicy] = ds
	_, body = e.get("/netdev/fw1/firewall")
	if !strings.Contains(body, notDisplayedNote) || !strings.Contains(body, readIncompleteNote) {
		t.Error("drift with a partial read does not show both notes")
	}
}

// notDisplayedBanner returns the "changed in elements not displayed"
// banner of a page.
func notDisplayedBanner(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<p [^>]*id="not-displayed">.*?</p>`).FindString(body)
	if m == "" || !strings.Contains(m, notDisplayedNote) {
		t.Fatalf("drift outside the allowlist is not shown")
	}
	return m
}

func TestNetDevFirewallPartialHitCountsAreStated(t *testing.T) {
	const partialNote = "The stored hit counts are partial"
	cases := []struct {
		name       string
		incomplete bool
		state      netdevinventory.DatasetState
		want       bool
	}{
		{"complete", false, netdevinventory.StateFresh, false},
		{"incomplete flag", true, netdevinventory.StateFresh, true},
		{"partial state", false, netdevinventory.StatePartial, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFirewallEnv(t)
			e.addPANOS("fw1", "Edge")
			e.store.policy["fw1"] = hintPolicy()
			e.fw.hits["fw1"] = []netdevcontract.HitCount{{RuleName: "r-hit", Hits: 7}}
			ds := e.store.datasets["fw1"][netdevinventory.ReadHitCounts]
			ds.Incomplete, ds.State = c.incomplete, c.state
			e.store.datasets["fw1"][netdevinventory.ReadHitCounts] = ds
			code, body := e.get("/netdev/fw1/firewall")
			if code != http.StatusOK {
				t.Fatalf("GET firewall = %d", code)
			}
			if got := strings.Contains(body, partialNote); got != c.want {
				t.Errorf("partial hit count note shown = %v, want %v", got, c.want)
			}
			// Partial hit counts are not a partial policy read.
			if strings.Contains(body, readIncompleteNote) {
				t.Error("partial hit counts are shown as read incomplete")
			}
		})
	}
}

func TestNetDevFirewallHitCountsOverCapAreStatedPartial(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = hintPolicy()
	hs := make([]netdevcontract.HitCount, netdevcontract.MaxHitCountEntries+1)
	for i := range hs {
		hs[i] = netdevcontract.HitCount{RuleName: "h" + strconv.Itoa(i), Hits: 1}
	}
	e.fw.hits["fw1"] = hs
	_, body := e.get("/netdev/fw1/firewall")
	if !strings.Contains(body, "The stored hit counts are partial") {
		t.Error("hit counts cut at the display cap are not stated partial")
	}
	e.fw.hits["fw1"] = hs[:netdevcontract.MaxHitCountEntries]
	_, body = e.get("/netdev/fw1/firewall")
	if strings.Contains(body, "The stored hit counts are partial") {
		t.Error("hit counts at the cap are stated partial")
	}
}

func TestNetDevFirewallListsOverCapShowReadIncomplete(t *testing.T) {
	addr := netdevcontract.AddressObject{Name: "a", Type: netdevcontract.AddressNetmask, Value: "10.0.0.1/32"}
	svc := netdevcontract.ServiceObject{Name: "s", Protocol: "tcp", Port: "443"}
	cases := []struct {
		name string
		fill func(p *netdevcontract.FirewallPolicy, n func(limit int) int)
		max  int
	}{
		{"security rules", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.SecurityRules = make([]netdevcontract.SecurityRule, n(netdevcontract.MaxSecurityRules))
		}, netdevcontract.MaxSecurityRules},
		{"NAT rules", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.NATRules = make([]netdevcontract.NATRule, n(netdevcontract.MaxNATRules))
		}, netdevcontract.MaxNATRules},
		{"address objects", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.Addresses = make([]netdevcontract.AddressObject, n(netdevcontract.MaxAddressObjects))
			for i := range p.Addresses {
				p.Addresses[i] = addr
			}
		}, netdevcontract.MaxAddressObjects},
		{"address groups", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.AddressGroups = make([]netdevcontract.Group, n(netdevcontract.MaxAddressGroups))
		}, netdevcontract.MaxAddressGroups},
		{"service objects", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.Services = make([]netdevcontract.ServiceObject, n(netdevcontract.MaxServiceObjects))
			for i := range p.Services {
				p.Services[i] = svc
			}
		}, netdevcontract.MaxServiceObjects},
		{"service groups", func(p *netdevcontract.FirewallPolicy, n func(int) int) {
			p.ServiceGroups = make([]netdevcontract.Group, n(netdevcontract.MaxServiceGroups))
		}, netdevcontract.MaxServiceGroups},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFirewallEnv(t)
			e.addPANOS("fw1", "Edge")
			for _, over := range []bool{false, true} {
				var pol netdevcontract.FirewallPolicy
				c.fill(&pol, func(limit int) int {
					if over {
						return limit + 1
					}
					return limit
				})
				e.store.policy["fw1"] = pol
				code, body := e.get("/netdev/fw1/firewall")
				if code != http.StatusOK {
					t.Fatalf("GET firewall = %d", code)
				}
				if got := strings.Contains(body, readIncompleteNote); got != over {
					t.Errorf("%s, cap %d, over cap %v: read incomplete shown = %v", c.name, c.max, over, got)
				}
			}
		})
	}
}

func TestNetDevFirewallGroupReachedShallowerIsExpanded(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	// A chain c1 -> c2 -> ... -> c8 -> late reaches "late" at the nesting
	// limit, where it is not expanded. The rule also names "late"
	// directly; that shallower path must expand it to its member "leaf".
	var groups []netdevcontract.Group
	for i := 1; i <= netdevcontract.MaxGroupNestingDepth; i++ {
		next := "c" + strconv.Itoa(i+1)
		if i == netdevcontract.MaxGroupNestingDepth {
			next = "late"
		}
		groups = append(groups, netdevcontract.Group{Name: "c" + strconv.Itoa(i), Static: []string{next}})
	}
	groups = append(groups, netdevcontract.Group{Name: "late", Static: []string{"leaf"}})
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{
		// The stack is LIFO: the chain (named last) is walked first.
		SecurityRules: []netdevcontract.SecurityRule{{Name: "r1", Source: []string{"late", "c1"}, Action: netdevcontract.ActionAllow}},
		Addresses:     []netdevcontract.AddressObject{{Name: "leaf", Type: netdevcontract.AddressNetmask, Value: "10.0.0.9/32"}},
		AddressGroups: groups,
	}
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	if row := objectRow(t, body, "leaf"); !strings.Contains(row, "used by 1 rule<") {
		t.Errorf("member of a group reached again at a shallower depth is not counted: %s", row)
	}
	if row := objectRow(t, body, "late"); !strings.Contains(row, "used by 1 rule<") {
		t.Errorf("group late counted wrongly: %s", row)
	}
}

// usagePolicy has rules rules that each name one address group of
// MaxGroupMembers members, so counting usage takes rules *
// (MaxGroupMembers+1) steps.
func usagePolicy(rules int) netdevcontract.FirewallPolicy {
	members := make([]string, netdevcontract.MaxGroupMembers)
	for i := range members {
		members[i] = "m" + strconv.Itoa(i)
	}
	pol := netdevcontract.FirewallPolicy{
		Addresses:     []netdevcontract.AddressObject{{Name: "m0", Type: netdevcontract.AddressNetmask, Value: "10.0.0.1/32"}},
		AddressGroups: []netdevcontract.Group{{Name: "big", Static: members}},
	}
	for i := range rules {
		pol.SecurityRules = append(pol.SecurityRules, netdevcontract.SecurityRule{Name: "r" + strconv.Itoa(i),
			Source: []string{"big"}, Action: netdevcontract.ActionAllow})
	}
	return pol
}

func TestNetDevFirewallUsageWorkLimit(t *testing.T) {
	// netdevUsageMaxSteps is 2,000,000; one rule costs 2,501 steps.
	const perRule = netdevcontract.MaxGroupMembers + 1
	under := 2_000_000 / perRule // 799 rules: 1,998,399 steps
	cases := []struct {
		name    string
		rules   int
		skipped bool
	}{
		{"just under the limit", under, false},
		{"just over the limit", under + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFirewallEnv(t)
			e.addPANOS("fw1", "Edge")
			e.store.policy["fw1"] = usagePolicy(c.rules)
			code, body := e.get("/netdev/fw1/firewall")
			if code != http.StatusOK {
				t.Fatalf("GET firewall = %d", code)
			}
			skipped := strings.Contains(body, "Rule usage not computed")
			if skipped != c.skipped {
				t.Fatalf("usage skipped = %v, want %v", skipped, c.skipped)
			}
			row := objectRow(t, body, "m0")
			if c.skipped {
				if strings.Contains(row, "used by") {
					t.Errorf("usage shown although not computed: %s", row)
				}
				// The rules themselves are still listed.
				if !strings.Contains(body, ">r"+strconv.Itoa(c.rules-1)+"<") {
					t.Error("last rule missing when usage is skipped")
				}
			} else if want := "used by " + strconv.Itoa(c.rules) + " rules<"; !strings.Contains(row, want) {
				t.Errorf("want %q in %s", want, row)
			}
		})
	}
}

func TestNetDevFirewallStaleBadges(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = hintPolicy()
	e.store.setDataset("fw1", netdevinventory.ReadHitCounts, netdevinventory.StateStale, netdevNow.Add(-5*time.Hour))
	_, body := e.get("/netdev/fw1/firewall")
	for _, want := range []string{"firewall_policy", "hit_counts", "stale", "fresh"} {
		if !strings.Contains(body, want) {
			t.Errorf("dataset table lacks %q", want)
		}
	}
}

func TestNetDevFirewallMissingPolicyIsStated(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	code, body := e.get("/netdev/fw1/firewall")
	if code != http.StatusOK {
		t.Fatalf("GET firewall = %d", code)
	}
	if !strings.Contains(body, "No firewall policy read yet.") {
		t.Error("missing policy is not stated")
	}
	if strings.Contains(body, "Stored data unavailable") {
		t.Error("a missing dataset is reported as a store error")
	}
}

func TestNetDevFirewallStoreErrorsDoNotLeak(t *testing.T) {
	// secretErr carries text that must never reach the page.
	secretErr := errors.New("sqlite: disk I/O error at /var/lib/nebula/server.db token=hunter2")
	cases := []struct {
		name   string
		inject func(f *fakeFirewallStore)
		want   []string
	}{
		{"policy", func(f *fakeFirewallStore) { f.policyErr = secretErr }, []string{"Stored data unavailable: firewall policy<"}},
		{"hit counts", func(f *fakeFirewallStore) { f.hitsErr = secretErr }, []string{"Stored data unavailable: hit counts<"}},
		{"config versions", func(f *fakeFirewallStore) { f.driftErr = secretErr }, []string{"Stored data unavailable: config versions<"}},
		{"dataset states", func(f *fakeFirewallStore) { f.datasetErr = secretErr },
			[]string{"Stored data unavailable: firewall policy state, hit count state<"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFirewallEnv(t)
			e.addPANOS("fw1", "Edge")
			e.store.policy["fw1"] = hintPolicy()
			e.fw.hits["fw1"] = []netdevcontract.HitCount{{RuleName: "r-45d", ResetAt: ptrTime(hitsObservedAt.Add(-days(45)))}}
			c.inject(e.fw)
			code, body := e.get("/netdev/fw1/firewall")
			if code != http.StatusOK {
				t.Fatalf("GET firewall = %d", code)
			}
			if !strings.Contains(body, "Stored data unavailable") {
				t.Fatal("store error is not reported as unavailable")
			}
			for _, w := range c.want {
				if !strings.Contains(body, w) {
					t.Errorf("unavailable note lacks %q", w)
				}
			}
			for _, leak := range []string{"sqlite", "disk I/O", "server.db", "hunter2"} {
				if strings.Contains(body, leak) {
					t.Errorf("page leaks store error text %q", leak)
				}
			}
			// A failed drift check must not claim drift.
			if strings.Contains(body, notDisplayedNote) {
				t.Error("store error shown as a change in elements not displayed")
			}
		})
	}
}

func TestNetDevDetailLinksToFirewallView(t *testing.T) {
	e := newFirewallEnv(t)
	e.addPANOS("fw1", "Edge")
	e.store.policy["fw1"] = hintPolicy()
	_, body := e.get("/netdev/fw1")
	if !strings.Contains(body, `href="/netdev/fw1/firewall"`) {
		t.Error("detail page lacks the firewall view link")
	}
	if strings.Contains(body, "not available yet") {
		t.Error("detail page still shows the placeholder")
	}
}
