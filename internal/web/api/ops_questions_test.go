// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// questionMarker is text that must never reach a log, an audit line or a
// response other than the agent's work item.
const questionMarker = "MARKER-QUESTION-TEXT-7f3a"

// askOpsQuestion stores a question of an admin in the env's notes store.
func askOpsQuestion(t *testing.T, e *opsEnv, text string) opsnotes.Question {
	t.Helper()
	q, err := e.notes.AskQuestion(t.Context(), "admin", text)
	if err != nil {
		t.Fatalf("AskQuestion: %v", err)
	}
	return q
}

// questionItems returns the question items of a work list.
func questionItems(t *testing.T, r opsResp) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, it := range workItems(t, r) {
		if it["kind"] == "question" {
			out = append(out, it)
		}
	}
	return out
}

func TestOpsWorkOpenQuestionsComeFirst(t *testing.T) {
	e := newOpsEnv(t)
	e.facts.groups = []opsfacts.Group{labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)}
	askOpsQuestion(t, e, "Ist die Box erreichbar?")
	items := workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) < 2 || items[0]["kind"] != "question" {
		t.Fatalf("items = %v, want the question first", items)
	}
}

// Open questions take at most MaxOpsQuestionItems slots, so MaxOpenQuestions
// open questions still leave room for the summary and the fix items.
func TestOpsWorkManyOpenQuestionsKeepSlotsForSummaryAndFixes(t *testing.T) {
	e := newOpsEnv(t)
	for i := range opsnotes.MaxOpenQuestions {
		askOpsQuestion(t, e, fmt.Sprintf("Frage Nummer %d", i))
	}
	for i := range 3 {
		e.facts.groups = append(e.facts.groups,
			labGroup(fmt.Sprintf("h-fix-%d", i), fmt.Sprintf("CVE-2026-%04d", i), opsfacts.TierHigh, false, 70))
	}
	items := workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if got := len(questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))); got != api.MaxOpsQuestionItems {
		t.Errorf("question items = %d, want the cap %d", got, api.MaxOpsQuestionItems)
	}
	kinds := map[string]int{}
	for _, it := range items {
		kinds[fmt.Sprint(it["kind"])]++
	}
	if kinds["summary"] != 1 || kinds["fix"] != 3 {
		t.Errorf("kinds = %v, want one summary and three fix items", kinds)
	}
	if len(items) > api.MaxOpsWorkItems {
		t.Errorf("%d items, want at most %d", len(items), api.MaxOpsWorkItems)
	}
}

// The largest question item the projector can produce fits MaxOpsItemBytes:
// MaxOpsQuestionHosts hosts, each with a label of MaxLabelBytes and
// MaxPortsPerHost ports, and a question of MaxQuestionBytes. The item carries
// no findings, so nothing else can grow it.
func TestOpsWorkQuestionWorstCaseFitsItemLimit(t *testing.T) {
	e := newOpsEnv(t)
	var names []string
	for i := range api.MaxOpsQuestionHosts {
		id := fmt.Sprintf("h-w%d", i)
		label := fmt.Sprintf("lab-%d-%s", i, strings.Repeat("x", opsfacts.MaxLabelBytes-6))
		g := labGroup(id, "CVE-2026-0001", opsfacts.TierCritical, true, 99)
		g.Projection.Host.Label = label
		for p := range opsfacts.MaxPortsPerHost {
			g.Projection.Ports = append(g.Projection.Ports, opsfacts.Port{Number: 60000 + p, Protocol: "udp"})
		}
		g.Projection.PortsOmitted = 1000
		e.facts.groups = append(e.facts.groups, g)
		names = append(names, label)
	}
	text := "Ist " + strings.Join(names, " und ") + " betroffen? " + strings.Repeat("a ", 400)
	if len(text) > opsnotes.MaxQuestionBytes {
		t.Fatalf("test question is %d bytes, over %d", len(text), opsnotes.MaxQuestionBytes)
	}
	askOpsQuestion(t, e, text)
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != api.MaxOpsQuestionHosts {
		t.Fatalf("hosts = %d, want %d: the worst case must keep every host fact", len(hosts), api.MaxOpsQuestionHosts)
	}
	size, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	if len(size) > api.MaxOpsItemBytes {
		t.Errorf("worst-case question item is %d bytes, over %d", len(size), api.MaxOpsItemBytes)
	}
}

// jsonCounts reads a counts object of a decoded work item.
func jsonCounts(t *testing.T, v any) map[string]float64 {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("counts = %v, want an object", v)
	}
	out := map[string]float64{}
	for k, x := range m {
		f, _ := x.(float64)
		out[k] = f
	}
	return out
}

// imageGroup is a container image group of host, with the given counts.
func imageGroup(host, subject string, c opsfacts.Counts) opsfacts.Group {
	g := labGroup(host, "CVE-2026-0002", opsfacts.TierHigh, false, 70)
	g.Key = host + "/image:" + subject
	g.Digest = "d-" + g.Key
	g.Projection.Group = g.Key
	g.Projection.Counts = c
	return g
}

// A named host with an OS group and two image groups is one host fact whose
// counts are the sum of its groups.
func TestOpsWorkQuestionHostWithSeveralGroupsIsOneEntry(t *testing.T) {
	e := newOpsEnv(t)
	osg := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	osg.Projection.Host.Label = "Web 01"
	osg.Projection.Counts = opsfacts.Counts{Critical: 1, High: 1}
	e.facts.groups = []opsfacts.Group{
		osg,
		imageGroup(opsHost, "img-a", opsfacts.Counts{High: 2, KEV: 1}),
		imageGroup(opsHost, "img-b", opsfacts.Counts{Medium: 3}),
	}
	askOpsQuestion(t, e, "Warum ist Web 01 kritisch?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want one entry for the one named host", len(hosts))
	}
	host, _ := hosts[0].(map[string]any)
	want := map[string]float64{"critical": 1, "high": 3, "medium": 3, "low": 0, "kev": 1}
	got := jsonCounts(t, host["counts"])
	for k, v := range want {
		if got[k] != v {
			t.Errorf("counts[%s] = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
}

// Five named hosts with extra image groups still give five host facts, so the
// agent answers the question instead of refusing it (MaxFactHosts = 5).
func TestOpsWorkQuestionFiveHostsWithImageGroupsAreAnswered(t *testing.T) {
	e := newOpsEnv(t)
	var names []string
	for i := range api.MaxOpsQuestionHosts {
		id := fmt.Sprintf("h-f%d", i)
		label := fmt.Sprintf("lab-f%d", i)
		osg := labGroup(id, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
		osg.Projection.Host.Label = label
		e.facts.groups = append(e.facts.groups, osg,
			imageGroup(id, "img-a", opsfacts.Counts{High: 1}),
			imageGroup(id, "img-b", opsfacts.Counts{High: 1}))
		names = append(names, label)
	}
	askOpsQuestion(t, e, "Was ist mit "+strings.Join(names, ", ")+"?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != api.MaxOpsQuestionHosts {
		t.Fatalf("hosts = %d, want %d", len(hosts), api.MaxOpsQuestionHosts)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		host, _ := h.(map[string]any)
		id, _ := host["host"].(map[string]any)["id"].(string)
		if seen[id] {
			t.Errorf("host %s has more than one entry", id)
		}
		seen[id] = true
		if c := jsonCounts(t, host["counts"]); c["high"] != 3 {
			t.Errorf("host %s high = %v, want 3 (one OS and two image groups)", id, c["high"])
		}
	}
}

// PortsOmitted of the group's host reaches the host fact, so a truncated
// port list is visible to the agent.
func TestOpsWorkQuestionHostCarriesPortsOmitted(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	g.Projection.Ports = []opsfacts.Port{{Number: 443, Protocol: "tcp"}}
	g.Projection.PortsOmitted = 7
	e.facts.groups = []opsfacts.Group{g}
	askOpsQuestion(t, e, "Ist "+opsHost+" betroffen?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(hosts))
	}
	if got := hosts[0].(map[string]any)["ports_omitted"]; got != float64(7) {
		t.Errorf("ports_omitted = %v, want 7", got)
	}
}

// A host named at the end of a sentence is named: a trailing '.' ends a word.
func TestOpsWorkQuestionHostNamedAtSentenceEnd(t *testing.T) {
	tests := []struct {
		name, text string
		want       int
	}{
		{"sentence end", "Check web01.", 1},
		{"sentence end then more text", "Check web01. Danach.", 1},
		{"domain continues", "Check web01.example.org", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpsEnv(t)
			g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
			g.Projection.Host.Label = "web01"
			e.facts.groups = []opsfacts.Group{g}
			askOpsQuestion(t, e, tc.text)
			items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
			if len(items) != 1 {
				t.Fatalf("question items = %d, want 1", len(items))
			}
			hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
			if len(hosts) != tc.want {
				t.Errorf("hosts = %d, want %d", len(hosts), tc.want)
			}
		})
	}
}

func TestOpsWorkQuestionCarriesDigestAndText(t *testing.T) {
	e := newOpsEnv(t)
	q := askOpsQuestion(t, e, "Was ist offen?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	it := items[0]
	if it["ref"] != fmt.Sprint(q.ID) || it["digest"] != opsnotes.QuestionDigest(q.Text) {
		t.Errorf("ref/digest = %v/%v", it["ref"], it["digest"])
	}
	question, _ := it["question"].(map[string]any)
	if question["text"] != "Was ist offen?" {
		t.Errorf("question = %v", question)
	}
}

func TestOpsWorkLabQuestionGivesGroupFactsOfNamedHosts(t *testing.T) {
	e := newOpsEnv(t)
	named := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	named.Projection.Host.Label = "Web 01"
	other := labGroup("h-other", "CVE-2026-0009", opsfacts.TierCritical, false, 80)
	other.Projection.Host.Label = "Mail 02"
	e.facts.groups = []opsfacts.Group{named, other}
	askOpsQuestion(t, e, "Warum ist Web 01 kritisch?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("hosts = %v, want only the named host", hosts)
	}
	if !strings.Contains(fmt.Sprint(hosts[0]), opsHost) {
		t.Errorf("group of the named host missing: %v", hosts[0])
	}
	if strings.Contains(fmt.Sprint(items[0]), "h-other") {
		t.Errorf("a host the question does not name is in the item")
	}
}

func TestOpsWorkQuestionNamesAtMostFiveHostsDeterministically(t *testing.T) {
	e := newOpsEnv(t)
	var names []string
	for i := range 7 {
		g := labGroup(fmt.Sprintf("h-%d", i), "CVE-2026-0001", opsfacts.TierCritical, false, 50)
		g.Projection.Host.Label = fmt.Sprintf("lab-%d", i)
		e.facts.groups = append(e.facts.groups, g)
		names = append(names, fmt.Sprintf("lab-%d", i))
	}
	askOpsQuestion(t, e, "Was ist mit "+strings.Join(names, ", ")+"?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	hosts, _ := items[0]["question"].(map[string]any)["hosts"].([]any)
	if len(hosts) != api.MaxOpsQuestionHosts {
		t.Fatalf("%d hosts, want %d", len(hosts), api.MaxOpsQuestionHosts)
	}
	for i, h := range hosts {
		id, _ := h.(map[string]any)["host"].(map[string]any)["id"].(string)
		if want := fmt.Sprintf("h-%d", i); id != want {
			t.Errorf("host %d id = %q, want the first five in key order (%s)", i, id, want)
		}
	}
}

func TestOpsWorkExternalQuestionHasNoHostOrCVEData(t *testing.T) {
	e := newOpsEnv(t)
	e.settings.row.DataClass = opsconfig.DataClassExternal
	g := labGroup(opsHost, "CVE-2026-4242", opsfacts.TierCritical, true, 99)
	e.facts.groups = []opsfacts.Group{g}
	e.facts.fleet = opsfacts.ExternalProjection{Fleet: opsfacts.Counts{Critical: 1, KEV: 1}}
	askOpsQuestion(t, e, "Ist "+opsHost+" betroffen?")
	items := questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("question items = %d, want 1", len(items))
	}
	question, _ := items[0]["question"].(map[string]any)
	if _, ok := question["hosts"]; ok {
		t.Errorf("external item carries host facts: %v", question)
	}
	if _, ok := items[0]["group"]; ok {
		t.Errorf("external item carries a group")
	}
	if _, ok := items[0]["fleet"]; !ok {
		t.Errorf("external item carries no fleet counters")
	}
	body := opsGet(e.h, "/api/v1/ops/work", oaTok).body
	for _, leak := range []string{"CVE-2026-4242", "openssl", "h-other", "candidates", "findings"} {
		if strings.Contains(body, leak) {
			t.Errorf("external work list contains %q", leak)
		}
	}
}

func TestOpsAnswerClosesQuestionAndCarriesNoSteps(t *testing.T) {
	e := newOpsEnv(t)
	q := askOpsQuestion(t, e, "Ist die Box erreichbar?")
	ref := fmt.Sprint(q.ID)
	withSteps := fmt.Sprintf(`{"kind":"answer","ref":%q,"digest":%q,"text":"Ja.",`+
		`"steps":[{"action_id":"service.restart","host_id":%q}]}`, ref, q.Digest, opsHost)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, withSteps); r.code != http.StatusBadRequest {
		t.Fatalf("answer with steps: %d %s, want 400", r.code, r.body)
	}
	withButtons := fmt.Sprintf(`{"kind":"answer","ref":%q,"digest":%q,"text":"Ja.","mitigations":["Dienst stoppen"]}`, ref, q.Digest)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, withButtons); r.code != http.StatusBadRequest {
		t.Fatalf("answer with mitigations: %d %s, want 400", r.code, r.body)
	}
	if got := len(questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))); got != 1 {
		t.Fatalf("refused answers closed the question: %d items", got)
	}
	ok := fmt.Sprintf(`{"kind":"answer","ref":%q,"digest":%q,"text":"Ja, sie ist erreichbar."}`, ref, q.Digest)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, ok); r.code != http.StatusCreated {
		t.Fatalf("answer: %d %s", r.code, r.body)
	}
	if got := len(questionItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))); got != 0 {
		t.Errorf("answered question still due: %d items", got)
	}
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, ok); r.code == http.StatusCreated {
		t.Errorf("second answer to the same question was stored")
	}
}

func TestOpsQuestionTextNeverReachesLogs(t *testing.T) {
	e := newOpsEnv(t)
	q := askOpsQuestion(t, e, questionMarker+" was ist offen?")
	_ = opsGet(e.h, "/api/v1/ops/work", oaTok)
	ok := fmt.Sprintf(`{"kind":"answer","ref":%q,"digest":%q,"text":"Antwort."}`, fmt.Sprint(q.ID), q.Digest)
	_ = opsPost(e.h, "/api/v1/ops/notes", oaTok, ok)
	_ = opsPost(e.h, "/api/v1/ops/notes", oaTok, ok)
	if strings.Contains(e.log.String(), questionMarker) {
		t.Errorf("question text reached the log:\n%s", e.log.String())
	}
}
