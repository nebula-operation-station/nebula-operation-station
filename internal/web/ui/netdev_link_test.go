// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the network device ↔ asset link on the device detail page
// (ADR 0010 D4, ND-18 part 2): a MAC match is shown as a suggestion and
// never creates a link, only an admin's POST confirms or removes one,
// both are audited, and a link whose asset was removed disappears.

package ui_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// ndLinkEnv is a netdev environment with a real ipam store as link store
// and a captured log (lockedBuffer of pve_links_test.go).
type ndLinkEnv struct {
	*netdevEnv
	ipam *ipam.Store
	log  *lockedBuffer
}

func newNDLinkEnv(t *testing.T) *ndLinkEnv {
	t.Helper()
	le := &ndLinkEnv{log: &lockedBuffer{}}
	le.netdevEnv = newNetDevEnvWith(t, func(db *sql.DB) ui.NetDevLinkStore {
		le.ipam = ipam.New(db, nil)
		return le.ipam
	}, le.log)
	return le
}

// addSwitch adds a CBS switch to the fake page store and to the device
// table the link store checks.
func (le *ndLinkEnv) addSwitch(id string) {
	le.t.Helper()
	le.addCBS(id, "Switch "+id)
	if _, err := le.db.Exec(`INSERT INTO netdev_devices_seen (device_id, family, label, trust_generation, created_at, updated_at)
		VALUES (?, 'cbs', '', 3, 0, 0)`, id); err != nil {
		le.t.Fatal(err)
	}
}

func (le *ndLinkEnv) asset(id string, kind ipam.Kind, mac string) {
	le.t.Helper()
	if err := le.ipam.SaveAsset(context.Background(), ipam.Asset{ID: id, Name: "Asset " + id, Kind: kind, MAC: mac}); err != nil {
		le.t.Fatal(err)
	}
}

func (le *ndLinkEnv) links() int {
	le.t.Helper()
	var n int
	if err := le.db.QueryRow(`SELECT count(*) FROM netdev_asset_links`).Scan(&n); err != nil {
		le.t.Fatal(err)
	}
	return n
}

// post sends a form POST with cookie (nil: logged out) and origin ("" for
// none) without following redirects.
func (e *netdevEnv) post(cookie *http.Cookie, origin, path string, form url.Values) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatalf("POST %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
		e.t.Errorf("POST %s: CSP = %q, want %q", path, got, netdevCSP)
	}
	return res
}

func TestNetDevAssetSuggestionNeverCreatesLink(t *testing.T) {
	le := newNDLinkEnv(t)
	le.addSwitch("sw1")
	le.asset("core", ipam.KindSwitch, "aa:bb:cc:00:00:01")
	le.asset("other", ipam.KindSwitch, "")
	le.store.macs["sw1"] = []netdevcontract.MACEntry{
		{VLAN: 1, MAC: "aa:bb:cc:00:00:01", Port: `"><img src=x onerror=alert(2)>`, Type: netdevcontract.MACOther},
	}
	for range 3 {
		code, body := le.get("/netdev/sw1")
		if code != http.StatusOK {
			t.Fatalf("GET = %d", code)
		}
		assertNoHostileMarkup(t, body)
		for _, want := range []string{"Asset core", ipam.SourceMACTable, "aa:bb:cc:00:00:01", "suggestion", `action="/netdev/sw1/asset-link"`, "Not linked"} {
			if !strings.Contains(body, want) {
				t.Errorf("detail page lacks %q", want)
			}
		}
	}
	if n := le.links(); n != 0 {
		t.Errorf("links after showing suggestions = %d, want 0", n)
	}
	if strings.Contains(le.log.String(), "netdev_asset_link") {
		t.Error("rendering wrote a link audit line")
	}
}

func TestNetDevAssetLinkConfirmNeedsAdmin(t *testing.T) {
	le := newNDLinkEnv(t)
	le.addSwitch("sw1")
	le.asset("core", ipam.KindSwitch, "aa:bb:cc:00:00:01")
	bob := le.session("cred-bob", "bob")
	form := url.Values{"asset": {"core"}}
	if res := le.post(bob, pveOrigin, "/netdev/sw1/asset-link", form); res.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin confirm = %d, want 403", res.StatusCode)
	}
	if res := le.post(le.cookie, "", "/netdev/sw1/asset-link", form); res.StatusCode != http.StatusForbidden {
		t.Errorf("confirm without Origin = %d, want 403", res.StatusCode)
	}
	if res := le.post(le.cookie, "https://evil.example", "/netdev/sw1/asset-link", form); res.StatusCode != http.StatusForbidden {
		t.Errorf("confirm with foreign Origin = %d, want 403", res.StatusCode)
	}
	if res := le.post(nil, pveOrigin, "/netdev/sw1/asset-link", form); res.StatusCode < 300 || strings.HasPrefix(res.Header.Get("Location"), "/netdev/") {
		t.Errorf("logged-out confirm = %d %q, want refusal", res.StatusCode, res.Header.Get("Location"))
	}
	if n := le.links(); n != 0 {
		t.Fatalf("links = %d, want 0", n)
	}
	// Removal is admin-only as well.
	if res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link", form); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin confirm = %d, want 303", res.StatusCode)
	}
	if res := le.post(bob, pveOrigin, "/netdev/sw1/asset-link/remove", url.Values{}); res.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin remove = %d, want 403", res.StatusCode)
	}
	if n := le.links(); n != 1 {
		t.Errorf("links = %d, want 1", n)
	}
	if strings.Contains(le.log.String(), "user=bob") {
		t.Error("refused request was audited as a change")
	}
}

func TestNetDevAssetLinkConfirmAndRemoveAreAudited(t *testing.T) {
	le := newNDLinkEnv(t)
	le.addSwitch("sw1")
	le.asset("core", ipam.KindSwitch, "aa:bb:cc:00:00:01")
	res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link", url.Values{"asset": {"core"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/netdev/sw1#asset-link" {
		t.Fatalf("confirm = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	l, err := le.ipam.DeviceLink(context.Background(), "sw1")
	if err != nil || l.AssetID != "core" || l.ConfirmedBy != "alice" {
		t.Fatalf("link = %+v, %v", l, err)
	}
	log := le.log.String()
	if !strings.Contains(log, "msg=audit kind=netdev_asset_link_confirmed device=sw1 asset=core user=alice") {
		t.Errorf("no confirm audit line in log:\n%s", log)
	}
	_, body := le.get("/netdev/sw1")
	for _, want := range []string{"Asset core", `href="/network/a/core"`, "alice", `action="/netdev/sw1/asset-link/remove"`} {
		if !strings.Contains(body, want) {
			t.Errorf("linked page lacks %q", want)
		}
	}
	res = le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link/remove", url.Values{})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("remove = %d", res.StatusCode)
	}
	if _, err := le.ipam.DeviceLink(context.Background(), "sw1"); !errors.Is(err, ipam.ErrNotFound) {
		t.Errorf("after remove: %v", err)
	}
	if !strings.Contains(le.log.String(), "msg=audit kind=netdev_asset_link_removed device=sw1 asset=core user=alice") {
		t.Errorf("no remove audit line in log:\n%s", le.log.String())
	}
	// Removing again: nothing to remove, nothing audited.
	before := strings.Count(le.log.String(), "netdev_asset_link_removed")
	if res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link/remove", url.Values{}); res.StatusCode != http.StatusNotFound {
		t.Errorf("second remove = %d, want 404", res.StatusCode)
	}
	if after := strings.Count(le.log.String(), "netdev_asset_link_removed"); after != before {
		t.Error("a failed remove was audited")
	}
}

func TestNetDevAssetLinkRejections(t *testing.T) {
	le := newNDLinkEnv(t)
	le.addSwitch("sw1")
	le.addSwitch("sw2")
	le.asset("core", ipam.KindSwitch, "")
	le.asset("edge", ipam.KindSwitch, "")
	le.asset("nas", ipam.KindNAS, "")
	if res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link", url.Values{"asset": {"core"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm = %d", res.StatusCode)
	}
	cases := []struct {
		name string
		path string
		form url.Values
		want int
	}{
		{"unknown asset", "/netdev/sw2/asset-link", url.Values{"asset": {"nope"}}, http.StatusNotFound},
		{"wrong kind", "/netdev/sw2/asset-link", url.Values{"asset": {"nas"}}, http.StatusBadRequest},
		{"asset linked elsewhere", "/netdev/sw2/asset-link", url.Values{"asset": {"core"}}, http.StatusConflict},
		{"device already linked", "/netdev/sw1/asset-link", url.Values{"asset": {"edge"}}, http.StatusConflict},
		{"bad asset id", "/netdev/sw2/asset-link", url.Values{"asset": {"<b>x</b>"}}, http.StatusBadRequest},
		{"missing asset", "/netdev/sw2/asset-link", url.Values{}, http.StatusBadRequest},
		{"two assets", "/netdev/sw2/asset-link", url.Values{"asset": {"edge", "core"}}, http.StatusBadRequest},
		{"oversized body", "/netdev/sw2/asset-link", url.Values{"asset": {"edge"}, "pad": {strings.Repeat("x", 8<<10)}}, http.StatusRequestEntityTooLarge},
		{"unknown device", "/netdev/sw9/asset-link", url.Values{"asset": {"edge"}}, http.StatusNotFound},
		{"invalid device id", "/netdev/SW%20X/asset-link", url.Values{"asset": {"edge"}}, http.StatusNotFound},
		{"remove unlinked", "/netdev/sw2/asset-link/remove", url.Values{}, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if res := le.post(le.cookie, pveOrigin, c.path, c.form); res.StatusCode != c.want {
				t.Errorf("POST %s = %d, want %d", c.path, res.StatusCode, c.want)
			}
		})
	}
	if n := le.links(); n != 1 {
		t.Errorf("links = %d, want 1", n)
	}
	// The link routes take POST only.
	res, _ := le.getAs(le.cookie, "/netdev/sw1/asset-link")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET confirm route = %d, want 405", res.StatusCode)
	}
}

func TestNetDevAssetLinkGoneAfterAssetRemoval(t *testing.T) {
	le := newNDLinkEnv(t)
	le.addSwitch("sw1")
	le.asset("core", ipam.KindSwitch, "aa:bb:cc:00:00:01")
	if res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link", url.Values{"asset": {"core"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm = %d", res.StatusCode)
	}
	if err := le.ipam.DeleteAsset(context.Background(), "core"); err != nil {
		t.Fatal(err)
	}
	code, body := le.get("/netdev/sw1")
	if code != http.StatusOK {
		t.Fatalf("GET = %d", code)
	}
	if !strings.Contains(body, "Not linked") || strings.Contains(body, `href="/network/a/core"`) {
		t.Error("page still shows the link of a removed asset")
	}
	// Re-creating the asset does not bring the confirmation back.
	le.asset("core", ipam.KindSwitch, "aa:bb:cc:00:00:01")
	if _, err := le.ipam.DeviceLink(context.Background(), "sw1"); !errors.Is(err, ipam.ErrNotFound) {
		t.Errorf("link after re-creation: %v", err)
	}
	if res := le.post(le.cookie, pveOrigin, "/netdev/sw1/asset-link/remove", url.Values{}); res.StatusCode != http.StatusNotFound {
		t.Errorf("remove stale = %d, want 404", res.StatusCode)
	}
}

func TestNetDevAssetLinkDisabledWithoutStore(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	if res := e.post(e.cookie, pveOrigin, "/netdev/sw1/asset-link", url.Values{"asset": {"core"}}); res.StatusCode != http.StatusNotFound {
		t.Errorf("confirm without link store = %d, want 404", res.StatusCode)
	}
	_, body := e.get("/netdev/sw1")
	if strings.Contains(body, "asset-link") {
		t.Error("page shows the link section without a link store")
	}
}

// brokenLinkStore fails every call with an error carrying a marker that
// must not reach the browser.
type brokenLinkStore struct{}

var errBrokenLink = errors.New("SECRET-db-path /var/lib/nos/server.db")

func (brokenLinkStore) Assets(context.Context) ([]ipam.Asset, error) { return nil, errBrokenLink }
func (brokenLinkStore) DeviceLink(context.Context, string) (ipam.DeviceLink, error) {
	return ipam.DeviceLink{}, errBrokenLink
}
func (brokenLinkStore) ConfirmDeviceLink(context.Context, string, string, string) (ipam.DeviceLink, error) {
	return ipam.DeviceLink{}, errBrokenLink
}
func (brokenLinkStore) RemoveDeviceLink(context.Context, string) (ipam.DeviceLink, error) {
	return ipam.DeviceLink{}, errBrokenLink
}

func TestNetDevAssetLinkStoreErrorFailsClosed(t *testing.T) {
	logs := &lockedBuffer{}
	e := newNetDevEnvWith(t, func(*sql.DB) ui.NetDevLinkStore { return brokenLinkStore{} }, logs)
	e.addCBS("sw1", "Core")
	for _, path := range []string{"/netdev/sw1/asset-link", "/netdev/sw1/asset-link/remove"} {
		if res := e.post(e.cookie, pveOrigin, path, url.Values{"asset": {"core"}}); res.StatusCode != http.StatusInternalServerError {
			t.Errorf("POST %s on a broken store = %d, want 500", path, res.StatusCode)
		}
	}
	code, body := e.get("/netdev/sw1")
	if code != http.StatusOK || !strings.Contains(body, "Asset link unavailable") || strings.Contains(body, "SECRET") {
		t.Errorf("GET on a broken link store = %d, unavailable note missing or error leaked", code)
	}
	if strings.Contains(logs.String(), "msg=audit") {
		t.Error("a failed change was audited")
	}
}
