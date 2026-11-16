// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
)

// adminGuideSlug is the slug the admin guide gets in the test corpus.
// helpdocs.FromDocsembed does not embed the admin guide yet, so the
// golden tests read it from docs/admin/guide.md.
const adminGuideSlug = "admin-guide"

// corpus builds the ADR 0014 D2 corpus: the embedded handbook (FAQ
// included) and the admin guide.
func corpus(t testing.TB) *helpdocs.Index {
	t.Helper()
	pages, err := docsembed.Pages()
	if err != nil {
		t.Fatalf("docsembed.Pages: %v", err)
	}
	srcs := make([]helpdocs.Source, 0, len(pages)+1)
	for _, p := range pages {
		srcs = append(srcs, helpdocs.Source{Slug: p.Slug, File: p.File, Data: p.Source})
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "admin", "guide.md"))
	if err != nil {
		t.Fatalf("read admin guide: %v", err)
	}
	srcs = append(srcs, helpdocs.Source{Slug: adminGuideSlug, File: "guide.md", Data: guide})
	ix, err := helpdocs.Build(srcs)
	if err != nil {
		t.Fatalf("helpdocs.Build: %v", err)
	}
	return ix
}

// goldenQuery is a question with the sections that must rank in the
// top 3.
type goldenQuery struct {
	q    string
	want []string
}

// AS-04 acceptance: the handbook enrollment section and admin guide
// 7.1/7.2 rank in the top 3 for both maintainer questions. "7.1/7.2"
// is read as the enrollment script section 7.1; 7.2 (pinning) is the
// next step, which neither question asks about.
var as04Golden = []goldenQuery{
	{q: "enroll 192.168.22.1", want: []string{"hosts#run-the-enrollment-script-on-a-new-host", adminGuideSlug + "#71-the-enrollment-script"}},
	{q: "ich will auf IP 192.168.22.1 die Connection einrichten", want: []string{"hosts#run-the-enrollment-script-on-a-new-host", adminGuideSlug + "#71-the-enrollment-script"}},
}

// handbookGolden are further questions against handbook sections, in
// German and English, so the parameters are not fitted to the two
// AS-04 questions alone. Each expected section must rank in the top 3.
var handbookGolden = []goldenQuery{
	{q: "how do I restore a backup", want: []string{"backup-restore#restore-a-backup"}},
	{q: "Wie kann ich ein Backup wiederherstellen?", want: []string{"backup-restore#restore-a-backup"}},
	{q: "the host key of a server changed", want: []string{"hosts#re-pin-a-host-whose-key-changed"}},
	{q: "Der Hostschlüssel hat sich geändert, was tun?", want: []string{"hosts#re-pin-a-host-whose-key-changed"}},
	{q: "unlock the executor after a reboot", want: []string{"faq#why-does-the-executor-ask-for-unlock-after-every-reboot"}},
	{q: "Executor nach Neustart entsperren", want: []string{"faq#why-does-the-executor-ask-for-unlock-after-every-reboot"}},
	{q: "I lost my YubiKey", want: []string{"faq#what-happens-if-i-lose-my-yubikey"}},
	{q: "Sicherheitsschlüssel verloren", want: []string{"faq#what-happens-if-i-lose-my-yubikey"}},
	{q: "import hosts from a CSV file", want: []string{"hosts#import-many-hosts-from-a-csv-file"}},
	{q: "Hosts aus einer CSV-Datei importieren", want: []string{"hosts#import-many-hosts-from-a-csv-file"}},
	{q: "test the ssh login to a host", want: []string{"hosts#test-the-login-to-a-host"}},
	{q: "find a free IP address", want: []string{"network#find-a-free-ip-address"}},
}

// setupGolden are general set-up questions that contain a verb the
// synonym table maps ("einrichten", "set up") but are about another
// topic than enrolling a host. They guard against query drift: the
// expansion must not pull them onto the enrollment sections. Unlike
// the other golden sets, want lists the acceptable sections (handbook
// and admin guide cover the same task): at least one must rank in the
// top 3, and no enrollment section may rank first
// (TestSetupQuestionsDoNotDriftToEnrollment).
var setupGolden = []goldenQuery{
	{q: "Backup einrichten", want: backupSetup},
	{q: "how do I set up a backup", want: backupSetup},
	{q: "Zeitplan für Checks einrichten", want: scheduleSetup},
	{q: "set up a schedule for read-only checks", want: scheduleSetup},
	{q: "Benachrichtigungen einrichten", want: notificationSetup},
	{q: "set up notifications", want: notificationSetup},
}

var (
	// admin guide 12.1 "Set up once" is merged into the chapter chunk.
	backupSetup = []string{
		"backup-restore#create-the-backup-key-once",
		"backup-restore#back-up-nebula",
		adminGuideSlug + "#12-backup-and-restore",
	}
	scheduleSetup = []string{
		"patching-and-services#run-read-only-checks-on-a-schedule-read-lease",
		adminGuideSlug + "#94-read-leases-and-scheduled-checks",
		adminGuideSlug + "#94-read-leases-and-scheduled-checks#p1",
		adminGuideSlug + "#94-read-leases-and-scheduled-checks#p2",
	}
	notificationSetup = []string{
		adminGuideSlug + "#101-notifications",
		"vulnerabilities#get-notified-about-kev-and-critical-findings",
	}
)

// enrollmentSections are the sections about enrolling a host.
var enrollmentSections = []string{
	"hosts#run-the-enrollment-script-on-a-new-host",
	adminGuideSlug + "#71-the-enrollment-script",
	adminGuideSlug + "#74-one-step-enrollment-from-the-web-ui",
	"hosts#enroll-a-host-reachable-over-a-vpn-netbird-wireguard-tailscale",
	"faq#is-there-a-one-step-enrollment",
}

func allGolden() []goldenQuery {
	return slices.Concat(as04Golden, handbookGolden)
}

// checkSetup returns a reason why g fails the set-up check, or "".
func checkSetup(t *testing.T, s *Index, g goldenQuery) string {
	t.Helper()
	hits, err := s.Search(g.q)
	if err != nil {
		t.Fatalf("Search(%q): %v", g.q, err)
	}
	got := ids(hits)
	if len(got) > 0 && slices.Contains(enrollmentSections, got[0]) {
		return "enrollment section " + got[0] + " ranks first; ranking " + strings.Join(got, " ")
	}
	for _, id := range got[:min(3, len(got))] {
		if slices.Contains(g.want, id) {
			return ""
		}
	}
	return "none of " + strings.Join(g.want, " ") + " in top 3; ranking " + strings.Join(got, " ")
}

func ids(hits []Hit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.Chunk.ID
	}
	return out
}

// checkTop3 returns the expected IDs missing from the top 3.
func checkTop3(t *testing.T, s *Index, g goldenQuery) []string {
	t.Helper()
	hits, err := s.Search(g.q)
	if err != nil {
		t.Fatalf("Search(%q): %v", g.q, err)
	}
	got := ids(hits)
	top := got[:min(3, len(got))]
	var missing []string
	for _, w := range g.want {
		if !slices.Contains(top, w) {
			missing = append(missing, w)
		}
	}
	return missing
}

func TestCorpusHasGoldenSections(t *testing.T) {
	ix := corpus(t)
	for _, g := range allGolden() {
		for _, w := range g.want {
			if _, ok := ix.Lookup(w); !ok {
				t.Errorf("golden section %q is not in the corpus", w)
			}
		}
	}
	if _, ok := ix.Lookup(adminGuideSlug + "#72-pinning-host-keys"); !ok {
		t.Errorf("admin guide 7.2 is not in the corpus")
	}
}

func TestGoldenAS04QueriesRankEnrollmentSectionsInTop3(t *testing.T) {
	s := New(corpus(t))
	for _, g := range as04Golden {
		if missing := checkTop3(t, s, g); len(missing) > 0 {
			hits, _ := s.Search(g.q)
			t.Errorf("Search(%q): %v not in top 3; ranking %v", g.q, missing, ids(hits))
		}
	}
}

func TestGoldenHandbookQueriesRankExpectedSectionInTop3(t *testing.T) {
	s := New(corpus(t))
	for _, g := range handbookGolden {
		if missing := checkTop3(t, s, g); len(missing) > 0 {
			hits, _ := s.Search(g.q)
			t.Errorf("Search(%q): %v not in top 3; ranking %v", g.q, missing, ids(hits))
		}
	}
}

// TestSetupQuestionsDoNotDriftToEnrollment is the regression test for
// the "einrichten" row that mapped only to enrollment vocabulary: a
// general set-up question about backup, schedules or notifications
// must find its topic, not the enrollment sections.
func TestSetupQuestionsDoNotDriftToEnrollment(t *testing.T) {
	s := New(corpus(t))
	for _, g := range setupGolden {
		if why := checkSetup(t, s, g); why != "" {
			t.Errorf("Search(%q): %s", g.q, why)
		}
	}
}

// TestGoldenStableAroundParameters guards against parameters that pass
// the golden set only at one point: every golden query must also pass
// with each parameter moved to its neighbours.
func TestGoldenStableAroundParameters(t *testing.T) {
	ix := corpus(t)
	variants := map[string]params{}
	for _, k := range []float64{3, 5} {
		p := defaultParams
		p.k1 = k
		variants["k1="+ftoa(k)] = p
	}
	set := func(name string, f int, weights, bs []float64) {
		for _, w := range weights {
			p := defaultParams
			p.weight[f] = w
			variants[name+"Weight="+ftoa(w)] = p
		}
		for _, b := range bs {
			p := defaultParams
			p.b[f] = b
			variants[name+"B="+ftoa(b)] = p
		}
	}
	set("title", fieldTitle, []float64{5, 8}, []float64{0.3, 0.75})
	set("path", fieldPath, []float64{0.5, 2}, []float64{0, 0.6})
	set("body", fieldBody, nil, []float64{0.6, 0.8})
	for _, w := range []float64{0.35, 0.7} {
		p := defaultParams
		p.synWeight = w
		variants["synWeight="+ftoa(w)] = p
	}
	names := make([]string, 0, len(variants))
	for n := range variants {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		s := newWithParams(ix, variants[n])
		for _, g := range allGolden() {
			if missing := checkTop3(t, s, g); len(missing) > 0 {
				t.Errorf("%s: Search(%q): %v not in top 3", n, g.q, missing)
			}
		}
		for _, g := range setupGolden {
			if why := checkSetup(t, s, g); why != "" {
				t.Errorf("%s: Search(%q): %s", n, g.q, why)
			}
		}
	}
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// baselineIndex is plain single-field BM25 (k1 1.2, b 0.75) over the
// chunk text with its heading line, as in as04, but with this
// package's tokenizer and synonyms, for the before/after table in the
// report.
func baselineIndex(ix *helpdocs.Index) *Index {
	flat := &helpdocs.Index{}
	for _, c := range ix.Chunks {
		c.Path = nil
		c.Text = "\n" + c.Text
		flat.Chunks = append(flat.Chunks, c)
	}
	return newWithParams(flat, params{k1: 1.2, weight: [numFields]float64{0, 0, 1}, b: [numFields]float64{0, 0, 0.75}, synWeight: 1})
}

// TestGoldenRankingTable logs the top k before (plain BM25) and after
// (BM25F) for every golden query; run with -v for the report.
func TestGoldenRankingTable(t *testing.T) {
	ix := corpus(t)
	for name, s := range map[string]*Index{"bm25": baselineIndex(ix), "bm25f": New(ix)} {
		for _, g := range allGolden() {
			hits, err := s.Search(g.q)
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			for i, h := range hits {
				mark := ""
				if slices.Contains(g.want, h.Chunk.ID) {
					mark = "*"
				}
				b.WriteString("\n    " + strconv.Itoa(i+1) + ". " + mark + h.Chunk.ID + " " + strconv.FormatFloat(h.Score, 'f', 2, 64))
			}
			t.Logf("%s %q:%s", name, g.q, b.String())
		}
	}
}
