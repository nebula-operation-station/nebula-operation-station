// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
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
		if want := fmt.Sprintf(`"h-%d/os"`, i); !strings.Contains(fmt.Sprint(h), fmt.Sprintf("h-%d/os", i)) {
			t.Errorf("host %d = %v, want the first five in key order (%s)", i, h, want)
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
