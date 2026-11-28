// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Maintainer decisions end to end (ADR 0011 D5, D6, Q4, variant A; decision of
// 2026-11-21, docs/implementation/vuln-decisions-assertion.md, follow-up 3).
//
// The chain under test is the real one. A real executor Service serves on a
// Unix socket in a temporary directory, with the executor's own credential
// store and WebAuthn verifier. The server is started by runServer with a
// temporary server.db, so the findings are stored by the real vulnstore. The
// decisions are sent over loopback HTTP (the forms' JSON endpoints), and the
// logins, the privileged session and the decision assertions are answered
// by virtual security keys (virtualwebauthn). Nothing else is virtual: no
// network except loopback and the Unix socket, no mock of vulnstore, no fake
// executor.
//
// Each case runs with its own executor, its own server and its own server.db,
// because a read or a run stored for one finding can close another finding of
// the same host.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// dexRPID is the host of vrOrigin, the public origin of the test server: the
// relying party every virtual key answers for.
const dexRPID = "nebula.example.org"

// dexRP is the relying party of the virtual keys.
var dexRP = virtualwebauthn.RelyingParty{Name: "Nebula", ID: dexRPID, Origin: vrOrigin}

// dexDecisionAudits are the audit kinds of the five decisions (vulnstore).
var dexDecisionAudits = []string{vulnstore.AuditVulnAcceptedRisk, vulnstore.AuditVulnFalsePositive,
	vulnstore.AuditVulnHoldConfirmed, vulnstore.AuditVulnHoldDiscarded, vulnstore.AuditVulnMarkReset}

// dexKey is one security key: a virtual authenticator holding one credential.
type dexKey struct {
	dev  virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

// newDexKey returns a fresh security key.
func newDexKey() dexKey {
	dev := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	dev.AddCredential(cred)
	return dexKey{dev: dev, cred: cred}
}

// sign answers the request options opts (a CredentialRequestOptions JSON
// document) with the key, as navigator.credentials.get() does.
func (k dexKey) sign(t *testing.T, opts []byte) json.RawMessage {
	t.Helper()
	o, err := virtualwebauthn.ParseAssertionOptions(string(opts))
	if err != nil {
		t.Fatalf("assertion options: %v", err)
	}
	return json.RawMessage(virtualwebauthn.CreateAssertionResponse(dexRP, k.dev, k.cred, *o))
}

// dexRig is the executor of the test: a real Service with its own store,
// verifier and registrar, served on a Unix socket for the server role.
type dexRig struct {
	reg  *webauthnreg.Registrar
	sock string
}

// newDexRig starts the executor. Its store is in a temporary directory, and
// its socket admits the test's user with the server role only.
func newDexRig(t *testing.T) *dexRig {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: dexRPID, Origins: []string{vrOrigin}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := permit.New(permit.Options{Mode: permit.ModeStandard, Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: dexRPID, Origins: []string{vrOrigin}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(authority, keyring.New(filepath.Join(dir, "keys")), db, reg, log)

	// Short directory: Unix socket paths are limited to about 100 bytes.
	sockDir, err := os.MkdirTemp("", "nos-dec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: sock, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}, executor.MethodRoles())
	srv := executor.NewGRPCServer(svc, policy, log)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return &dexRig{reg: reg, sock: sock}
}

// enroll registers key k for user with a one-time code and the attestation of
// the virtual key, as the registration ceremony does. When a key is already
// enrolled, the registration needs a user-verified assertion of that key
// (by); the first key needs none.
func (r *dexRig) enroll(t *testing.T, user string, k dexKey, by *dexKey) {
	t.Helper()
	code, _, err := r.reg.CreateCode(user, user+" key", "admin:uid1000")
	if err != nil {
		t.Fatalf("code for %s: %v", user, err)
	}
	b, err := r.reg.Begin(code)
	if err != nil {
		t.Fatalf("begin registration of %s: %v", user, err)
	}
	opts, err := virtualwebauthn.ParseAttestationOptions(string(b.CreationOptions))
	if err != nil {
		t.Fatal(err)
	}
	att := []byte(virtualwebauthn.CreateAttestationResponse(dexRP, k.dev, k.cred, *opts))
	var assertion []byte
	if b.AuthorizationOptions != nil {
		if by == nil {
			t.Fatalf("registration of %s asks for an assertion but no key is enrolled", user)
		}
		assertion = []byte(by.sign(t, b.AuthorizationOptions))
	}
	if _, err := r.reg.Finish(b.ID, att, assertion); err != nil {
		t.Fatalf("finish registration of %s: %v", user, err)
	}
}

// dexSeedEnv is the findings service over db, with the test clock moved
// clsClockBack into the past as clsEnv does, so the seeded reads and runs
// pass the store's clock check. The caller closes db.
func dexSeedEnv(t *testing.T, db *sql.DB) *vtEnv {
	t.Helper()
	clk := &vtClock{t: time.Now().UTC().Truncate(time.Second)}
	clk.Add(-clsClockBack)
	sink := newVTSink()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := newVulnService(db, sink, log, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vtToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"192.0.2.10"}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{tok}}, svc,
		vtInventory{at: clk.Now().Add(-time.Minute)}, vtAgentCfg{}, log)
	if err != nil || vh == nil {
		t.Fatalf("newVulnAPI = %v, %v", vh, err)
	}
	readOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "read-only api", http.StatusTeapot) })
	return &vtEnv{db: db, svc: svc, sink: sink, clk: clk, api: api.Mount(readOnly, vh), audit: auditlog.New(db, false)}
}

// dexSeed is what a case stores before the server starts: the finding keys
// the case checks and, for a held closure or a mark reset, the run ID the
// decision names.
type dexSeed struct {
	keys []vulnfinding.Key
	run  string
}

// dexEnv is a started server with its executor, the two enrolled keys and
// the browser sessions of their users.
type dexEnv struct {
	t          *testing.T
	dir        string
	s          *vrServer
	alice, bob dexKey
	aliceSess  string
	bobSess    string
	// before is the store state (dexState) before the server starts.
	before string
}

// dexSetup seeds the store of a new server.db with seed (through the real
// vulnstore), starts the executor and runServer, enrolls alice (the
// maintainer) and bob (another user), logs both in over /login with their
// keys, and opens alice's privileged session. It returns once everything is
// in place, with the seed and the store state before the first request.
func dexSetup(t *testing.T, seed func(t *testing.T, e *vtEnv) dexSeed) (*dexEnv, dexSeed) {
	t.Helper()
	dir := t.TempDir()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	sd := seed(t, dexSeedEnv(t, db))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := dexState(t, dir, sd.keys)

	rig := newDexRig(t)
	de := &dexEnv{t: t, dir: dir, alice: newDexKey(), bob: newDexKey(), before: before}
	rig.enroll(t, "alice", de.alice, nil)
	rig.enroll(t, "bob", de.bob, &de.alice)

	cfg := vrConfig(t, dir, rig.sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})
	de.s = startVR(t, dir, cfg)
	de.aliceSess = dexLogin(t, de.s, de.alice)
	de.bobSess = dexLogin(t, de.s, de.bob)

	// The privileged session of alice: begun and finished with her key over
	// her own web session. The holder of this session is the only maintainer.
	code, body, _ := dexCall(t, de.s.base, http.MethodPost, "/privileged/begin", de.aliceSess, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("privileged begin = %d %s (log: %s)", code, body, de.s.stderr)
	}
	var pb struct {
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(body, &pb); err != nil {
		t.Fatalf("privileged begin body %s: %v", body, err)
	}
	code, body, _ = dexCall(t, de.s.base, http.MethodPost, "/privileged/finish", de.aliceSess,
		map[string]any{"assertion": de.alice.sign(t, pb.Options)})
	if code != http.StatusOK {
		t.Fatalf("privileged finish = %d %s (log: %s)", code, body, de.s.stderr)
	}
	return de, sd
}

// dexCall sends one request to base. cookie is a session cookie value (empty
// for none). It returns the status, the body and the cookies of the response.
func dexCall(t *testing.T, base, method, path, cookie string, body any) (int, []byte, []*http.Cookie) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", vrOrigin)
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Cookies()
}

// dexLogin logs key in over the login page as the browser does: begin, sign
// the options, finish. It returns the session cookie.
func dexLogin(t *testing.T, s *vrServer, k dexKey) string {
	t.Helper()
	code, body, _ := dexCall(t, s.base, http.MethodPost, "/login/begin", "", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("login begin = %d %s", code, body)
	}
	var b struct {
		LoginID string          `json:"login_id"`
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("login begin body %s: %v", body, err)
	}
	code, body, cookies := dexCall(t, s.base, http.MethodPost, "/login/finish", "",
		map[string]any{"login_id": b.LoginID, "assertion": k.sign(t, b.Options)})
	if code != http.StatusOK {
		t.Fatalf("login finish = %d %s (log: %s)", code, body, s.stderr)
	}
	for _, c := range cookies {
		if c.Name == auth.CookieName {
			return c.Value
		}
	}
	t.Fatal("login set no session cookie")
	return ""
}

// dexBegin sends the decision in as the form does (POST decide/begin) with the
// session cookie. It returns the status, and for 200 the challenge ID and the
// options.
func (de *dexEnv) dexBegin(cookie string, in map[string]any) (int, string, []byte) {
	de.t.Helper()
	code, body, _ := dexCall(de.t, de.s.base, http.MethodPost, "/vulnerabilities/decide/begin", cookie, in)
	if code != http.StatusOK {
		return code, "", nil
	}
	var ch struct {
		ID      string          `json:"id"`
		Options json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(body, &ch); err != nil || ch.ID == "" {
		de.t.Fatalf("begin body %s: %v", body, err)
	}
	return code, ch.ID, []byte(ch.Options)
}

// dexCommit sends the challenge id with an assertion (nil for none) as the
// form does (POST decide/commit). It returns the status.
func (de *dexEnv) dexCommit(cookie, id string, assertion json.RawMessage) int {
	de.t.Helper()
	code, _, _ := dexCall(de.t, de.s.base, http.MethodPost, "/vulnerabilities/decide/commit", cookie,
		map[string]any{"id": id, "assertion": assertion})
	return code
}

// dexPage returns the page at path for the session cookie, which must answer
// 200.
func (de *dexEnv) dexPage(cookie, path string) string {
	de.t.Helper()
	code, body, _ := dexCall(de.t, de.s.base, http.MethodGet, path, cookie, nil)
	if code != http.StatusOK {
		de.t.Fatalf("GET %s = %d", path, code)
	}
	return string(body)
}

// dexState is what a decision may change, read from server.db: the state,
// the closure and the number of held closures of every key, and the number
// of audit lines of each decision kind. The server must not be running on
// dir.
func dexState(t *testing.T, dir string, keys []vulnfinding.Key) string {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := dexSeedEnv(t, db)
	ctx := context.Background()
	var b strings.Builder
	for _, k := range keys {
		f, err := e.svc.store.Get(ctx, k)
		if err != nil {
			t.Fatalf("finding %s: %v", k, err)
		}
		holds, err := e.svc.store.Holds(ctx, k)
		if err != nil {
			t.Fatalf("holds of %s: %v", k, err)
		}
		fmt.Fprintf(&b, "finding %s state=%s closed_by=%s holds=%d\n", k, f.State, f.ClosedBy, len(holds))
	}
	for _, kind := range dexDecisionAudits {
		got, err := e.audit.List(ctx, 0, 100, kind)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "audit %s=%d\n", kind, len(got))
	}
	return b.String()
}

// dexStop stops the server and returns the store state of keys after it.
func (de *dexEnv) dexStop(keys []vulnfinding.Key) string {
	de.s.stop()
	return dexState(de.t, de.dir, keys)
}

// dexSignedDecision is the full flow of one decision as the browser does it:
// begin, sign with key k, commit. It returns the commit status.
func (de *dexEnv) dexSignedDecision(cookie string, k dexKey, in map[string]any) int {
	de.t.Helper()
	code, id, opts := de.dexBegin(cookie, in)
	if code != http.StatusOK {
		de.t.Fatalf("begin %v = %d", in["kind"], code)
	}
	return de.dexCommit(cookie, id, k.sign(de.t, opts))
}

// dexExpiry is a date 30 days ahead, in the form's layout.
func dexExpiry() string { return time.Now().Add(30 * 24 * time.Hour).UTC().Format("2006-01-02") }

// dexDecisionCase is one good decision: the seed of the store, the input
// the form sends, the audit kind it writes, what the page shows afterwards,
// and the check of the applied store state.
type dexDecisionCase struct {
	name  string
	kind  string
	seed  func(t *testing.T, e *vtEnv) dexSeed
	input func(sd dexSeed) map[string]any
	// shows is text the finding page (or, for a mark reset, the overview)
	// shows after the decision.
	shows string
	// overview is set when the decision is shown on the overview, not on a
	// finding page.
	overview bool
	check    func(t *testing.T, e *vtEnv, sd dexSeed)
}

// TestVulnDecisionEndToEndOverHTTP: each of the four decisions a maintainer
// may submit with a security key (accept risk, confirm a held closure,
// discard a held closure, reset a feed mark) is sent over HTTP, signed by
// the maintainer's virtual key, applied by the real store, shown on the page,
// and audited exactly once.
func TestVulnDecisionEndToEndOverHTTP(t *testing.T) {
	cases := []dexDecisionCase{
		{
			name: "accept_risk", kind: vulnstore.AuditVulnAcceptedRisk,
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				return dexSeed{keys: []vulnfinding.Key{vdFinding(t, e, "CVE-2026-8701").Key}}
			},
			input: func(sd dexSeed) map[string]any {
				return map[string]any{"kind": "accept_risk", "key": sd.keys[0].String(), "approver": "dana",
					"reason": "vendor patch scheduled", "expires": dexExpiry()}
			},
			shows: "accepted risk",
			check: func(t *testing.T, e *vtEnv, sd dexSeed) {
				if f, err := e.svc.store.Get(context.Background(), sd.keys[0]); err != nil || f.State != vulnstore.StateAcceptedRisk {
					t.Fatalf("finding state = %v, %v; want accepted_risk", f.State, err)
				}
			},
		},
		{
			name: "confirm_hold", kind: vulnstore.AuditVulnHoldConfirmed,
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				f, run := vdHeld(t, e, "CVE-2026-8702")
				return dexSeed{keys: []vulnfinding.Key{f.Key}, run: run}
			},
			input: func(sd dexSeed) map[string]any {
				return map[string]any{"kind": "confirm_hold", "key": sd.keys[0].String(), "run_id": sd.run, "reason": "checked by hand"}
			},
			shows: "fixed (confirmed by the maintainer)",
			check: func(t *testing.T, e *vtEnv, sd dexSeed) {
				ctx := context.Background()
				if h, err := e.svc.store.Holds(ctx, sd.keys[0]); err != nil || len(h) != 0 {
					t.Fatalf("holds = %+v, %v; want none", h, err)
				}
				if f, err := e.svc.store.Get(ctx, sd.keys[0]); err != nil || f.State != vulnstore.StateFixed || f.ClosedBy != vulnstore.ClosedByAdminConfirmed {
					t.Fatalf("finding = %s %s, %v; want fixed by the maintainer", f.State, f.ClosedBy, err)
				}
			},
		},
		{
			name: "discard_hold", kind: vulnstore.AuditVulnHoldDiscarded,
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				f, run := vdHeld(t, e, "CVE-2026-8703")
				return dexSeed{keys: []vulnfinding.Key{f.Key}, run: run}
			},
			input: func(sd dexSeed) map[string]any {
				return map[string]any{"kind": "discard_hold", "key": sd.keys[0].String(), "run_id": sd.run}
			},
			shows: "open",
			check: func(t *testing.T, e *vtEnv, sd dexSeed) {
				ctx := context.Background()
				if h, err := e.svc.store.Holds(ctx, sd.keys[0]); err != nil || len(h) != 0 {
					t.Fatalf("holds = %+v, %v; want none", h, err)
				}
				if f, err := e.svc.store.Get(ctx, sd.keys[0]); err != nil || f.State != vulnstore.StateOpen {
					t.Fatalf("finding state = %v, %v; want open", f.State, err)
				}
			},
		},
		{
			name: "mark_reset", kind: vulnstore.AuditVulnMarkReset, overview: true,
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				return dexSeed{run: vdMarkRegressed(t, e)}
			},
			input: func(sd dexSeed) map[string]any {
				return map[string]any{"kind": "mark_reset", "source_id": "debian-tracker", "run_id": sd.run, "reason": "feed was rolled back"}
			},
			shows: "on probation after a mark reset",
			check: func(t *testing.T, e *vtEnv, _ dexSeed) {
				view, err := e.svc.store.MarkResetCandidate(context.Background(), "debian-tracker")
				if err != nil || !view.Probation || !view.MarkDate.Equal(view.ReportedDate) || !view.PreResetDate.After(view.MarkDate) {
					t.Fatalf("reset view = %+v, %v; want the mark at the reported value, on probation", view, err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			de, sd := dexSetup(t, tc.seed)
			if code := de.dexSignedDecision(de.aliceSess, de.alice, tc.input(sd)); code != http.StatusOK {
				t.Fatalf("decision = %d (log: %s)", code, de.s.stderr)
			}
			path := "/vulnerabilities"
			if !tc.overview {
				path = "/vulnerabilities/f/" + sd.keys[0].String()
			}
			if page := de.dexPage(de.aliceSess, path); !strings.Contains(page, tc.shows) {
				t.Fatalf("%s does not show %q", path, tc.shows)
			}
			de.s.stop()
			db, err := serverdb.Open(filepath.Join(de.dir, "server.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			e := dexSeedEnv(t, db)
			got, err := e.audit.List(context.Background(), 0, 10, tc.kind)
			if err != nil || len(got) != 1 || got[0].User != "alice" {
				t.Fatalf("audit %s = %+v, %v; want exactly one line by alice", tc.kind, got, err)
			}
			tc.check(t, e, sd)
		})
	}
}

// TestVulnDecisionRefusalsLeaveStoreUnchanged: each refused decision over
// HTTP (another user's assertion, the assertion of another decision's
// challenge, a non-maintainer, a discard without an assertion) is answered
// with a refusal and leaves the store as it was before the request.
func TestVulnDecisionRefusalsLeaveStoreUnchanged(t *testing.T) {
	accept := func(reason string, sd dexSeed) map[string]any {
		return map[string]any{"kind": "accept_risk", "key": sd.keys[0].String(), "approver": "dana",
			"reason": reason, "expires": dexExpiry()}
	}
	cases := []struct {
		name string
		seed func(t *testing.T, e *vtEnv) dexSeed
		// run performs the refused requests and checks their statuses.
		run func(t *testing.T, de *dexEnv, sd dexSeed)
	}{
		{
			name: "assertion of another user",
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				return dexSeed{keys: []vulnfinding.Key{vdFinding(t, e, "CVE-2026-8801").Key}}
			},
			run: func(t *testing.T, de *dexEnv, sd dexSeed) {
				code, id, opts := de.dexBegin(de.aliceSess, accept("vendor patch scheduled", sd))
				if code != http.StatusOK {
					t.Fatalf("begin = %d", code)
				}
				if got := de.dexCommit(de.aliceSess, id, de.bob.sign(t, opts)); got != http.StatusForbidden {
					t.Fatalf("commit with bob's assertion = %d, want 403", got)
				}
			},
		},
		{
			name: "assertion of another decision's challenge",
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				return dexSeed{keys: []vulnfinding.Key{vdFinding(t, e, "CVE-2026-8802").Key}}
			},
			run: func(t *testing.T, de *dexEnv, sd dexSeed) {
				codeA, idA, _ := de.dexBegin(de.aliceSess, accept("vendor patch scheduled", sd))
				codeB, _, optsB := de.dexBegin(de.aliceSess, accept("another reason", sd))
				if codeA != http.StatusOK || codeB != http.StatusOK {
					t.Fatalf("begin = %d, %d", codeA, codeB)
				}
				if got := de.dexCommit(de.aliceSess, idA, de.alice.sign(t, optsB)); got != http.StatusForbidden {
					t.Fatalf("commit of decision A with the assertion of B = %d, want 403", got)
				}
			},
		},
		{
			name: "non-maintainer begins and commits",
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				return dexSeed{keys: []vulnfinding.Key{vdFinding(t, e, "CVE-2026-8803").Key}}
			},
			run: func(t *testing.T, de *dexEnv, sd dexSeed) {
				if code, _, _ := de.dexBegin(de.bobSess, accept("vendor patch scheduled", sd)); code != http.StatusForbidden {
					t.Fatalf("begin by bob = %d, want 403", code)
				}
				code, id, opts := de.dexBegin(de.aliceSess, accept("vendor patch scheduled", sd))
				if code != http.StatusOK {
					t.Fatalf("begin by alice = %d", code)
				}
				if got := de.dexCommit(de.bobSess, id, de.alice.sign(t, opts)); got != http.StatusForbidden {
					t.Fatalf("commit by bob = %d, want 403", got)
				}
			},
		},
		{
			name: "discard_hold without an assertion",
			seed: func(t *testing.T, e *vtEnv) dexSeed {
				f, run := vdHeld(t, e, "CVE-2026-8804")
				return dexSeed{keys: []vulnfinding.Key{f.Key}, run: run}
			},
			run: func(t *testing.T, de *dexEnv, sd dexSeed) {
				code, id, _ := de.dexBegin(de.aliceSess, map[string]any{"kind": "discard_hold",
					"key": sd.keys[0].String(), "run_id": sd.run})
				if code != http.StatusOK {
					t.Fatalf("begin = %d", code)
				}
				if got := de.dexCommit(de.aliceSess, id, nil); got != http.StatusForbidden {
					t.Fatalf("commit without an assertion = %d, want 403", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			de, sd := dexSetup(t, tc.seed)
			tc.run(t, de, sd)
			if after := de.dexStop(sd.keys); after != de.before {
				t.Fatalf("store changed by a refused decision:\nbefore:\n%s\nafter:\n%s", de.before, after)
			}
		})
	}
}

// TestVulnDecisionChallengeIsSingleUse: a decision applied with a challenge
// cannot be applied again with the same challenge. The second commit is
// answered 404, and the store holds the one applied decision and its one
// audit line.
func TestVulnDecisionChallengeIsSingleUse(t *testing.T) {
	de, sd := dexSetup(t, func(t *testing.T, e *vtEnv) dexSeed {
		return dexSeed{keys: []vulnfinding.Key{vdFinding(t, e, "CVE-2026-8805").Key}}
	})
	in := map[string]any{"kind": "accept_risk", "key": sd.keys[0].String(), "approver": "dana",
		"reason": "vendor patch scheduled", "expires": dexExpiry()}
	code, id, opts := de.dexBegin(de.aliceSess, in)
	if code != http.StatusOK {
		t.Fatalf("begin = %d", code)
	}
	assertion := de.alice.sign(t, opts)
	if got := de.dexCommit(de.aliceSess, id, assertion); got != http.StatusOK {
		t.Fatalf("first commit = %d, want 200", got)
	}
	if got := de.dexCommit(de.aliceSess, id, assertion); got != http.StatusNotFound {
		t.Fatalf("second commit with the same challenge = %d, want 404", got)
	}
	state := de.dexStop(sd.keys)
	want := fmt.Sprintf("finding %s state=%s", sd.keys[0], vulnstore.StateAcceptedRisk)
	if !strings.Contains(state, want) || !strings.Contains(state, "audit "+vulnstore.AuditVulnAcceptedRisk+"=1") {
		t.Fatalf("store after the reuse:\n%s\nwant %q and one accepted-risk audit line", state, want)
	}
}
