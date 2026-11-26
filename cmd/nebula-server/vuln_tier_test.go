// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// tierLister is a host criticality source for the tierer: it returns hosts
// or err and counts the reads.
type tierLister struct {
	mu    sync.Mutex
	hosts []inventory.Host
	err   error
	calls int
}

func (l *tierLister) List(context.Context) ([]inventory.Host, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.err != nil {
		return nil, l.err
	}
	return append([]inventory.Host(nil), l.hosts...), nil
}

func (l *tierLister) set(hosts []inventory.Host, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hosts, l.err = hosts, err
}

func (l *tierLister) readCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// tierClock is an injected clock for the tierer.
type tierClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *tierClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *tierClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// tierRecord is a finding with CVSS 10.0 (NVD) and EPSS 0.8, so the score
// per criticality is: unset (0.85) 52, LOW 31, MEDIUM 43, HIGH 52, CRITICAL
// 62 (exposure unknown, 0.7). The tiers are therefore medium, high, high,
// critical for LOW, MEDIUM, HIGH/unset and CRITICAL.
func tierRecord(kev bool) vulnfinding.Record {
	return vulnfinding.Record{Scores: tierScores(kev)}
}

func tierScores(kev bool) vulnfinding.Scores {
	sc := vulnfinding.Scores{
		CVSS: &vulnfinding.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			BaseScore: 10, Source: vulnfinding.CVSSSourceNVD},
		EPSS: &vulnfinding.EPSS{Probability: 0.8, Percentile: 0.99, Date: "2026-11-25"},
	}
	if kev {
		sc.KEV = &vulnfinding.KEV{DateAdded: "2026-11-01"}
	}
	return sc
}

func tierSubjects() map[string]vulnstore.Subject {
	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	return map[string]vulnstore.Subject{
		"host web-low":    {Kind: vulnfinding.SubjectHost, ID: "web-low"},
		"host web-med":    {Kind: vulnfinding.SubjectHost, ID: "web-med"},
		"host web-high":   {Kind: vulnfinding.SubjectHost, ID: "web-high"},
		"host web-crit":   {Kind: vulnfinding.SubjectHost, ID: "web-crit"},
		"host web-gone":   {Kind: vulnfinding.SubjectHost, ID: "web-gone"},
		"image web-low":   {Kind: vulnfinding.SubjectImage, ID: "web-low", ImageDigest: digest},
		"image web-crit":  {Kind: vulnfinding.SubjectImage, ID: "web-crit", ImageDigest: digest},
		"image web-gone":  {Kind: vulnfinding.SubjectImage, ID: "web-gone", ImageDigest: digest},
		"device web-crit": {Kind: vulnfinding.SubjectDevice, ID: "web-crit"},
	}
}

func tierHosts() []inventory.Host {
	return []inventory.Host{
		{ID: "web-low", Criticality: inventory.CriticalityLow},
		{ID: "web-med", Criticality: inventory.CriticalityMedium},
		{ID: "web-high", Criticality: inventory.CriticalityHigh},
		{ID: "web-crit", Criticality: inventory.CriticalityCritical},
	}
}

// TestVulnTierFollowsHostCriticality: the host's criticality enters vu-prio-v1
// (ADR 0011 D7). A host or an image names its host and takes its criticality;
// a device, an unknown host and a host without criticality count as unset.
func TestVulnTierFollowsHostCriticality(t *testing.T) {
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	clk := &tierClock{t: now}
	lister := &tierLister{hosts: tierHosts()}
	tr := newVulnTierer(lister, clk.Now, nil)
	r := tierRecord(false)
	want := map[string]vulnstore.Tier{
		"host web-low":    vulnstore.TierMedium,   // LOW 0.5: score 31
		"host web-med":    vulnstore.TierHigh,     // MEDIUM 0.7: score 43
		"host web-high":   vulnstore.TierHigh,     // HIGH 0.85: score 52
		"host web-crit":   vulnstore.TierCritical, // CRITICAL 1.0: score 62
		"host web-gone":   vulnstore.TierHigh,     // not in the inventory: unset 0.85
		"image web-low":   vulnstore.TierMedium,   // an image takes its host's criticality
		"image web-crit":  vulnstore.TierCritical,
		"image web-gone":  vulnstore.TierHigh,
		"device web-crit": vulnstore.TierHigh, // a device names no host: unset
	}
	for name, s := range tierSubjects() {
		if got := tr.Tier(s, r); got != want[name] {
			t.Errorf("%s: tier = %v, want %v", name, got, want[name])
		}
	}
}

// TestVulnTierUnsetIsTheDefaultOnTheStore: a nil source (no inventory) gives
// every subject the ADR default, which is the tier of today.
func TestVulnTierUnsetIsTheDefaultOnTheStore(t *testing.T) {
	tr := newVulnTierer(nil, nil, nil)
	r := tierRecord(false)
	for name, s := range tierSubjects() {
		if got := tr.Tier(s, r); got != vulnstore.TierHigh {
			t.Errorf("%s without an inventory: tier = %v, want the unset tier high", name, got)
		}
	}
	if got := vulnTier(vulnstore.Subject{}, r); got != vulnstore.TierHigh {
		t.Errorf("vulnTier = %v, want high", got)
	}
}

// TestVulnTierKEVIsNeverBelowHigh: a KEV finding is never below high on any
// subject (the floor of D7; with exposure unknown it is critical).
func TestVulnTierKEVIsNeverBelowHigh(t *testing.T) {
	tr := newVulnTierer(&tierLister{hosts: tierHosts()}, time.Now, nil)
	r := tierRecord(true)
	for name, s := range tierSubjects() {
		if got := tr.Tier(s, r); got != vulnstore.TierHigh && got != vulnstore.TierCritical {
			t.Errorf("KEV on %s: tier = %v, want high or critical", name, got)
		}
	}
}

// TestVulnTierInvalidScoresStayUnknown: a record whose scores vulnprio rejects
// is unknown, as before (no criticality can make it a tier).
func TestVulnTierInvalidScoresStayUnknown(t *testing.T) {
	tr := newVulnTierer(&tierLister{hosts: tierHosts()}, time.Now, nil)
	bad := vulnfinding.Record{Scores: vulnfinding.Scores{EPSS: &vulnfinding.EPSS{Probability: 2}}}
	if got := tr.Tier(vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web-crit"}, bad); got != vulnstore.TierUnknown {
		t.Errorf("invalid scores: tier = %v, want unknown", got)
	}
}

// TestVulnTierReadFailureNeverLowersATier: an inventory read error gives the
// unset tier of today when nothing was read before, and never a lower tier
// than the unset one or the criticality read earlier.
func TestVulnTierReadFailureNeverLowersATier(t *testing.T) {
	clk := &tierClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	lister := &tierLister{err: errors.New("inventory unavailable")}
	tr := newVulnTierer(lister, clk.Now, nil)
	r := tierRecord(false)
	crit := vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web-crit"}
	low := vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web-low"}
	if got := tr.Tier(crit, r); got != vulnstore.TierHigh {
		t.Errorf("first read fails: CRITICAL host tier = %v, want the unset tier high", got)
	}

	// A good read, then a failing one after the cache expired.
	lister.set(tierHosts(), nil)
	clk.Add(vulnCriticalityTTL)
	if got := tr.Tier(crit, r); got != vulnstore.TierCritical {
		t.Fatalf("good read: CRITICAL host tier = %v, want critical", got)
	}
	lister.set(nil, errors.New("inventory unavailable"))
	clk.Add(vulnCriticalityTTL)
	if got := tr.Tier(crit, r); got != vulnstore.TierCritical {
		t.Errorf("failed read: CRITICAL host tier = %v, want the criticality read earlier (critical)", got)
	}
	if got := tr.Tier(low, r); got != vulnstore.TierHigh {
		t.Errorf("failed read: LOW host tier = %v, want the unset tier high, never medium", got)
	}
}

// TestVulnTierCachesCriticalityForTheTTL: a criticality read is reused for
// vulnCriticalityTTL, so a change in the inventory is seen after the TTL.
func TestVulnTierCachesCriticalityForTheTTL(t *testing.T) {
	clk := &tierClock{t: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)}
	lister := &tierLister{hosts: tierHosts()}
	tr := newVulnTierer(lister, clk.Now, nil)
	r := tierRecord(false)
	low := vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web-low"}
	if got := tr.Tier(low, r); got != vulnstore.TierMedium {
		t.Fatalf("LOW host tier = %v, want medium", got)
	}
	lister.set([]inventory.Host{{ID: "web-low", Criticality: inventory.CriticalityCritical}}, nil)
	for i := 0; i < 50; i++ {
		if got := tr.Tier(low, r); got != vulnstore.TierMedium {
			t.Fatalf("within the TTL: tier = %v, want the cached medium", got)
		}
	}
	if n := lister.readCount(); n != 1 {
		t.Fatalf("reads within the TTL = %d, want 1", n)
	}
	clk.Add(vulnCriticalityTTL)
	if got := tr.Tier(low, r); got != vulnstore.TierCritical {
		t.Fatalf("after the TTL: tier = %v, want critical", got)
	}
	if n := lister.readCount(); n != 2 {
		t.Fatalf("reads after the TTL = %d, want 2", n)
	}
}

// tierPost sends one agent API call with the vuln token and fails on any
// status other than want.
func tierPost(t *testing.T, s *vrServer, method, path string, body any, want int) []byte {
	t.Helper()
	code, out := s.do(t, method, path, "", vrToken, body)
	if code != want {
		t.Fatalf("%s %s = %d %s, want %d", method, path, code, out, want)
	}
	return out
}

// tierAgentRun stores the records the way an agent does: an inventory
// snapshot, a run that names fresh feeds, one batch and the completion.
func tierAgentRun(t *testing.T, s *vrServer, records []map[string]any) {
	t.Helper()
	var inv struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal(tierPost(t, s, http.MethodGet, "/api/v1/vuln/inventory", nil, http.StatusOK), &inv); err != nil || inv.SnapshotID == "" {
		t.Fatalf("inventory snapshot: %v", err)
	}
	at := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	var sources []any
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		sources = append(sources, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none",
			"date_kind": "data", "content_date": at})
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	out := tierPost(t, s, http.MethodPost, "/api/v1/vuln/runs", map[string]any{
		"inventory_snapshot_id": inv.SnapshotID, "matcher_version": "1.4.0", "sources": sources}, http.StatusCreated)
	if err := json.Unmarshal(out, &started); err != nil || started.RunID == "" {
		t.Fatalf("run start: %v %s", err, out)
	}
	recs := make([]any, len(records))
	for i, r := range records {
		recs[i] = r
	}
	base := "/api/v1/vuln/runs/" + started.RunID
	out = tierPost(t, s, http.MethodPost, base+"/findings", map[string]any{"batch_seq": 0, "subjects": []any{}, "findings": recs}, http.StatusOK)
	if !strings.Contains(string(out), `"rejected":0`) {
		t.Fatalf("batch rejected findings: %s", out)
	}
	tierPost(t, s, http.MethodPost, base+"/complete", nil, http.StatusOK)
}

// tierAPIRecord is the agent's record of one finding on subject host.
func tierAPIRecord(host, cve string, kev bool) map[string]any {
	r := vtRecord(cve, kev)
	r["subject_ref"] = map[string]any{"id": host}
	// The installed openssl of the inventory read (e2eVulnerable), with the
	// fix the tracker names (e2eFixed).
	r["component"] = map[string]any{"source_package": "openssl", "source_version": e2eVulnerable}
	r["fix"] = map[string]any{"state": "fixed", "version": e2eFixed}
	sc := map[string]any{
		"cvss": map[string]any{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"base_score": 10.0, "source": "nvd"},
		"epss": map[string]any{"probability": 0.8, "percentile": 0.99, "date": "2026-11-25"},
	}
	if kev {
		sc["kev"] = map[string]any{"date_added": "2026-11-01"}
	}
	r["scores"] = sc
	return r
}

// tierCell is the tier badge of a finding row (the state badge has the same
// markup and comes after it).
var tierCell = regexp.MustCompile(`<td><span class="badge [^"]*">([a-z]+)</span></td>`)

// tierShown returns the tier the CVE page shows for the finding of cve on
// host, "" when the page has no row for it. A row is split out at its
// markup, and it must name the host's subject link.
func tierShown(t *testing.T, s *vrServer, alice, cve, host string) string {
	t.Helper()
	code, body := s.do(t, http.MethodGet, "/vulnerabilities/cve/"+cve, alice, "", nil)
	if code != http.StatusOK {
		t.Fatalf("CVE page %s = %d", cve, code)
	}
	subject := `/vulnerabilities/subject/host/` + host + `"`
	for _, row := range strings.Split(string(body), `<tr class="vuln-finding">`)[1:] {
		if end := strings.Index(row, "</tr>"); end >= 0 {
			row = row[:end]
		}
		if !strings.Contains(row, subject) {
			continue
		}
		m := tierCell.FindStringSubmatch(row)
		if m == nil {
			t.Fatalf("CVE page %s: the row of %s has no tier cell", cve, host)
		}
		return m[1]
	}
	return ""
}

// TestVulnTierCriticalityOnFindingPagesOverHTTP runs the server through
// runServer with the real vulnerability store and inventory and reads the
// finding pages over HTTP: the same finding is medium on a LOW host and
// critical on a CRITICAL host, a host outside the inventory keeps today's
// tier (high), a KEV finding is never below high, and a changed criticality
// shows on the page only after the TTL.
func TestVulnTierCriticalityOnFindingPagesOverHTTP(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	alice, _ := vrSessions(t, dir)
	cfg := vrConfig(t, dir, sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})

	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	hosts := []inventory.Host{
		{ID: "web-low", Criticality: inventory.CriticalityLow},
		{ID: "web-crit", Criticality: inventory.CriticalityCritical},
	}
	for i, h := range hosts {
		if _, err := inventory.New(db).Create(ctx, inventory.Host{ID: h.ID, DisplayName: h.ID + ".lab",
			Environment: inventory.EnvProd, Criticality: h.Criticality,
			Endpoints: []inventory.Endpoint{{Address: fmt.Sprintf("192.0.2.%d", 21+i), Port: 22}}, CredentialRef: "lab"},
			inventory.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// A host takes part in a run only with a stored package read, so each
	// host gets the Debian 12 release and one installed-package read, as
	// the inventory chain stores them.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC().Truncate(time.Second)
	seed := &invEnv{db: db}
	inv := e2eInventory(t, db, log)
	for i, h := range hosts {
		seed.insertFactsAt(t, 100+i, h.ID, factsResult(t, debian12Release), now)
		inv.ObserveInstalled(ctx, h.ID, fmt.Sprintf("exec-tier-%d", i), now.Add(-2*time.Minute), now.Add(-time.Minute), e2eFixture(t))
		if r, err := inv.store.Latest(ctx, h.ID); err != nil || !r.Complete {
			t.Fatalf("read of %s: complete=%v reason=%q err=%v", h.ID, r.Complete, r.Reason, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock := &e2eClock{}
	s := startE2E(t, dir, cfg, clock.now, &e2eWiring{})
	const cve, kevCVE = "CVE-2026-7001", "CVE-2026-7002"
	tierAgentRun(t, s, []map[string]any{
		tierAPIRecord("web-low", cve, false),
		tierAPIRecord("web-crit", cve, false),
		tierAPIRecord("web-low", kevCVE, true),
	})

	// The first page read loads the criticality; the expected tiers are the
	// D7 tiers of the record (see tierRecord).
	if got := tierShown(t, s, alice, cve, "web-low"); got != "medium" {
		t.Fatalf("LOW host: the page shows %q for the finding, want medium (D7 with LOW)", got)
	}
	if got := tierShown(t, s, alice, cve, "web-crit"); got != "critical" {
		t.Fatalf("CRITICAL host: the page shows %q for the finding, want critical (D7 with CRITICAL)", got)
	}
	if got := tierShown(t, s, alice, kevCVE, "web-low"); got != "critical" {
		t.Fatalf("KEV finding on a LOW host: the page shows %q, want critical (never below high)", got)
	}

	// Raise web-low to CRITICAL in the inventory. The page keeps the cached
	// criticality until the TTL has passed, then shows the new tier.
	db, err = serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := inventory.New(db).Get(ctx, "web-low")
	if err != nil {
		t.Fatal(err)
	}
	h.Criticality = inventory.CriticalityCritical
	if _, err := inventory.New(db).Update(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := tierShown(t, s, alice, cve, "web-low"); got != "medium" {
		t.Fatalf("within the TTL: the page shows %q, want the cached medium", got)
	}
	clock.set(vulnCriticalityTTL + time.Second)
	if got := tierShown(t, s, alice, cve, "web-low"); got != "critical" {
		t.Fatalf("after the TTL: the page shows %q, want the new critical tier", got)
	}
}
