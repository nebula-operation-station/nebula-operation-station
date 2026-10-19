// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// A host's page with the module tabs (M7-6, spec 10 declarative UI): every
// tab, card and label comes from a module's signed or unsigned metadata
// and is rendered as text by the core's template; values come from the
// latest successful result of the card's action on the host (untrusted
// host output, shown as text). Modules provide no HTML, links or scripts.

type moduleFieldView struct{ Label, Value string }

type moduleCardView struct {
	Title, ActionID, When string
	Fields                []moduleFieldView
}

type moduleTabView struct {
	Module, Version, Title, State string
	Cards                         []moduleCardView
}

type hostPageData struct {
	ID   string
	Tabs []moduleTabView
}

const maxFieldValue = 200

func (h *Handler) handleHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonical.ValidHostID(id) {
		http.NotFound(w, r)
		return
	}
	data := pageData{Title: "Host " + id, Active: "inventory", Content: "host", Host: &hostPageData{ID: id}}
	if h.modules != nil && h.lastResult != nil {
		ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
		defer cancel()
		mods, err := h.modules.Latest(ctx)
		if err != nil {
			h.log.Error("list modules", "error", err)
		}
		for _, v := range mods {
			if v.Lock.UI == nil || v.Lock.UI.HostTab == nil {
				continue
			}
			t := v.Lock.UI.HostTab
			tab := moduleTabView{Module: v.Lock.Name, Version: v.Lock.Version, Title: t.Title, State: v.State}
			for _, c := range t.Cards {
				cv := moduleCardView{Title: c.Title, ActionID: v.Lock.ActionID(c.Action), When: "never run on this host"}
				res, at, ok, err := h.lastResult(ctx, cv.ActionID, id)
				if err != nil {
					h.log.Error("last result", "error", err)
				}
				for _, f := range c.Fields {
					val := "—"
					if ok {
						val = fieldValue(res, f.Path)
					}
					cv.Fields = append(cv.Fields, moduleFieldView{Label: f.Label, Value: val})
				}
				if ok {
					cv.When = "as of " + at.UTC().Format("2006-01-02 15:04 MST")
				}
				tab.Cards = append(tab.Cards, cv)
			}
			data.Host.Tabs = append(data.Host.Tabs, tab)
		}
	}
	h.render(w, data)
}

// fieldValue reads path from the "result" object of a runbook-v1 result
// document and returns it as one line of plain text.
func fieldValue(result []byte, path string) string {
	var doc struct {
		Result map[string]any `json:"result"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Result == nil {
		return "—"
	}
	var cur any = doc.Result
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "—"
		}
		if cur, ok = m[seg]; !ok {
			return "—"
		}
	}
	var s string
	switch v := cur.(type) {
	case nil:
		return "—"
	case string:
		s = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "—"
		}
		s = string(b)
	}
	return plainLine(s)
}

// plainLine replaces control and invisible formatting characters and cuts
// the text at maxFieldValue bytes on a character boundary.
func plainLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' || r == utf8.RuneError {
			r = '�'
		}
		if b.Len()+utf8.RuneLen(r) > maxFieldValue {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LastResultFunc returns the latest successful result of an action on a
// host (executions.Service.LastResult).
type LastResultFunc func(ctx context.Context, actionID, host string) ([]byte, time.Time, bool, error)
