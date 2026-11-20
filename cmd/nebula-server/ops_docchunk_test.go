// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpsearch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// docChunkTok is the ops token of these tests; only its hash is configured.
const docChunkTok = "ops-agent-token-0123456789abcdef"

// docChunkSearchWords are the fixed search terms of the contract test. Each
// one must be answered by helpsearch over the embedded index; at least one
// must yield a hit, so the contract is not vacuous.
var docChunkSearchWords = []string{"Passwort", "Backup", "Update"}

// docChunkAudit runs settings writes in a transaction without an audit log.
type docChunkAudit struct{ db *sql.DB }

func (a docChunkAudit) WithTx(ctx context.Context,
	fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx, func(string, map[string]string) error { return nil }); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// docChunkEnv is the server's ops API as newOpsAPI wires it: real notes store
// and settings row in a temporary server.db.
func docChunkEnv(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := newOpsNotes(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	settings, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	want := opsconfig.Settings{Enabled: true, BaseURL: "https://192.168.10.20:8080/v1", Model: "qwen",
		DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE}
	if _, err := settings.Save(context.Background(), "admin", want, 0, docChunkAudit{db: db}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{{
		Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(docChunkTok),
		Scopes: []string{serverconfig.ScopeOpsRead, serverconfig.ScopeOpsNotesWrite}}}}
	hosts := func(context.Context) ([]inventory.Host, error) { return nil, nil }
	h, err := newOpsAPI(cfg, db, st, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("newOpsAPI returned no handler for an ops token")
	}
	return h
}

// docChunkDo sends one request with the ops token from a loopback address.
func docChunkDo(h http.Handler, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("Authorization", "Bearer "+docChunkTok)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// docChunkSummaryRef returns the ref and digest of the summary item in the
// work list.
func docChunkSummaryRef(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	code, body := docChunkDo(h, http.MethodGet, "/api/v1/ops/work", "")
	if code != http.StatusOK {
		t.Fatalf("work: %d %s", code, body)
	}
	var v struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("work: %v in %s", err, body)
	}
	for _, it := range v.Items {
		if it["kind"] == "summary" {
			ref, _ := it["ref"].(string)
			digest, _ := it["digest"].(string)
			return ref, digest
		}
	}
	t.Fatalf("no summary item in work list: %s", body)
	return "", ""
}

// docChunkNote is a summary note of the day with the given citations.
func docChunkNote(ref, digest string, citations ...string) string {
	cites, _ := json.Marshal(citations)
	return fmt.Sprintf(`{"kind":"summary","ref":%q,"digest":%q,"text":"Heute keine Auffälligkeiten.","citations":%s}`,
		ref, digest, cites)
}

// TestOpsNoteRefusesCitationOutsideEmbeddedIndex checks the server end to end
// with the real notes store and settings: a well-formed chunk ID that the
// embedded index does not hold is refused with 422 and stores nothing. The
// same summary without a citation is accepted (201), so the refusal is about
// the citation alone.
func TestOpsNoteRefusesCitationOutsideEmbeddedIndex(t *testing.T) {
	h := docChunkEnv(t)
	ref, digest := docChunkSummaryRef(t, h)

	invented := docChunkNote(ref, digest, "handbuch:gibt-es-nicht")
	if code, body := docChunkDo(h, http.MethodPost, "/api/v1/ops/notes", invented); code != http.StatusUnprocessableEntity {
		t.Fatalf("invented citation: %d %s, want 422", code, body)
	}
	plain := fmt.Sprintf(`{"kind":"summary","ref":%q,"digest":%q,"text":"Heute keine Auffälligkeiten."}`, ref, digest)
	if code, body := docChunkDo(h, http.MethodPost, "/api/v1/ops/notes", plain); code != http.StatusCreated {
		t.Fatalf("summary without citation: %d %s, want 201", code, body)
	}
}

// TestDocChunkContractKnowsEveryChunkTheAgentSearchReturns checks that every
// chunk ID the agent's search path (helpdocs.FromDocsembed, helpsearch.New,
// Search) returns for the fixed words is known to the server's citation check.
func TestDocChunkContractKnowsEveryChunkTheAgentSearchReturns(t *testing.T) {
	ix, err := helpdocs.FromDocsembed()
	if err != nil {
		t.Fatal(err)
	}
	known := opsDocChunk(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if known == nil {
		t.Fatal("embedded index did not load on the server")
	}
	seen := 0
	for _, w := range docChunkSearchWords {
		hits, err := helpsearch.New(ix).Search(w)
		if err != nil {
			t.Fatalf("search %q: %v", w, err)
		}
		for _, hit := range hits {
			seen++
			if !known(hit.Chunk.ID) {
				t.Errorf("search %q returned chunk %q, which the server does not accept", w, hit.Chunk.ID)
			}
		}
	}
	if seen == 0 {
		t.Fatal("the fixed search words returned no chunk; the contract is not checked")
	}
	if known("handbuch#gibt-es-nicht") {
		t.Error("an invented chunk ID is accepted")
	}
}
