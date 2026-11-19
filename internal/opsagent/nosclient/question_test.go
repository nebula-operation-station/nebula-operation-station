// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// testDigest is a well-formed item digest (64 lower-case hex characters).
const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The question item as the server sends it (internal/web/api, ops.go): fleet
// counts, the question text and, in class lab, the facts of the named hosts.
const questionItemJSON = `{"kind":"question","ref":"7","digest":"` + testDigest + `",` +
	`"fleet":{"critical":2,"high":3,"medium":0,"low":0,"kev":1},` +
	`"question":{"text":"Ist web-01 betroffen?","hosts":[{"host":{"id":"h1","label":"web-01","environment":"lab","criticality":"high"},` +
	`"exposure":"lan","ports":[{"number":443,"protocol":"tcp"}],"counts":{"critical":1,"high":0,"medium":0,"low":0,"kev":0}}]}}`

// TestQuestionItemDecodesAsServerSendsIt: a question item in a work list with
// a summary item decodes strictly into the question type.
func TestQuestionItemDecodesAsServerSendsIt(t *testing.T) {
	body := `{"items":[` + questionItemJSON + `,{"kind":"summary","ref":"2026-11-19","digest":"` +
		testDigest + `","fleet":{"critical":2}}]}`
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	items, err := c.Work(context.Background())
	if err != nil {
		t.Fatalf("Work: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items %d, want 2", len(items))
	}
	q := items[0]
	if q.Question == nil || q.Question.Text != "Ist web-01 betroffen?" || q.Fleet == nil || q.Fleet.KEV != 1 {
		t.Fatalf("question item %+v", q)
	}
	if len(q.Question.Hosts) != 1 || q.Question.Hosts[0].Host.ID != "h1" || q.Question.Hosts[0].Counts.Critical != 1 {
		t.Errorf("question hosts %+v", q.Question.Hosts)
	}
}

// TestQuestionItemRefusesUnknownFields: the question type is strict. A host
// carrying findings or candidates, or a question that is still a plain
// string, fails the whole list with ErrProtocol.
func TestQuestionItemRefusesUnknownFields(t *testing.T) {
	bodies := map[string]string{
		"string question": `{"items":[{"kind":"question","ref":"7","digest":"` + testDigest + `","fleet":{},"question":"Ist web-01 betroffen?"}]}`,
		"host findings": `{"items":[{"kind":"question","ref":"7","digest":"` + testDigest + `","fleet":{},` +
			`"question":{"text":"x","hosts":[{"host":{"id":"h1"},"findings":[]}]}}]}`,
		"host candidates": `{"items":[{"kind":"question","ref":"7","digest":"` + testDigest + `","fleet":{},` +
			`"question":{"text":"x","hosts":[{"host":{"id":"h1"},"candidates":[]}]}}]}`,
		"old facts key": `{"items":[{"kind":"question","ref":"7","digest":"` + testDigest + `","fleet":{},` +
			`"question":{"text":"x"},"facts":[]}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
			if _, err := c.Work(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Work: %v, want ErrProtocol", err)
			}
		})
	}
}
