// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
)

// Guest power proposals, fix round 1 of pu01: the page headline is the
// executor's binding, an unshowable binding refuses the proposal, a
// proposal belongs to its proposer, and the background commit's errors
// set the right state.

// gpNoApproval checks that a proposal page offers no way to approve.
func gpNoApproval(t *testing.T, body string) {
	t.Helper()
	for _, bad := range []string{"schedule-approve", "nebula approve", `action="/pve/guests/power/run"`, "webauthn.js"} {
		if strings.Contains(body, bad) {
			t.Errorf("page offers approval (%q)", bad)
		}
	}
}

func TestGuestPowerProposalHeadlineIsExecutorBinding(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.risk = pb.RiskClass_RISK_CLASS_HIGH
	h := e.h.Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop")); rec.Code != http.StatusSeeOther {
		t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
	}
	body := getBody(t, h, "/pve/guests/power/"+e.exec.lastDigest())
	rq := gpCanonical(&pb.PVEGuestPowerTarget{RemoteId: gpRemote, Kind: "qemu", Node: "pve1", Vmid: 100, Verb: "stop"}, "HIGH", "")
	bound := strings.Index(body, "Request bound by the executor")
	uiRead := strings.Index(body, "UI inventory read")
	name := strings.Index(body, "web-vm")
	if bound < 0 || uiRead < 0 || name < 0 || !(bound < uiRead && uiRead < name) {
		t.Errorf("the executor's binding is not the headline (bound %d, UI read %d, name %d)", bound, uiRead, name)
	}
	head := body[bound:uiRead]
	for _, want := range []string{
		"pve.guest.power", ">stop<", rq.ResolvedTargets[0].HostID, "(bound target matches)",
		`class="badge badge--critical">HIGH<`, rq.ParametersHash, e.exec.lastDigest(), `id="guest-power-canonical"`,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("binding headline lacks %q", want)
		}
	}
	if strings.Contains(head, "web-vm") {
		t.Error("the UI's guest name is in the binding headline")
	}
	// The exact canonical request is visible, not in a collapsed block.
	if strings.Contains(body, "<details") {
		t.Error("the bound request is in a collapsed details block")
	}
	if !strings.Contains(head, `&#34;action_id&#34;:&#34;pve.guest.power&#34;`) {
		t.Error("the canonical request is not shown in full")
	}
	if !strings.Contains(body, "schedule-approve") {
		t.Error("a matching binding offers no approval")
	}
}

func TestGuestPowerBindingMismatchWithholdsApproval(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*canonical.Request)
		want   string
	}{
		{"other verb", func(r *canonical.Request) { r.ArtifactSHA256 = gpArtifactSHA256("reset") }, "bound the verb reset, not stop"},
		{"unknown verb", func(r *canonical.Request) { r.ArtifactSHA256 = strings.Repeat("ee", 32) }, "unknown power verb"},
		{"other guest", func(r *canonical.Request) {
			*r = gpCanonical(&pb.PVEGuestPowerTarget{RemoteId: gpRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "stop"}, string(r.RiskClass), r.ExecutionID)
		}, "bound a different guest"},
		{"other node", func(r *canonical.Request) {
			*r = gpCanonical(&pb.PVEGuestPowerTarget{RemoteId: gpRemote, Kind: "qemu", Node: "pve2", Vmid: 100, Verb: "stop"}, string(r.RiskClass), r.ExecutionID)
		}, "bound a different guest"},
		{"other risk", func(r *canonical.Request) { r.RiskClass = canonical.RiskMedium }, "differs from the executor"},
		{"other action", func(r *canonical.Request) { r.ActionID = "pve.guest.snapshot" }, "different action"},
		{"other trust pin", func(r *canonical.Request) {
			r.ResolvedTargets[0].HostKeyFingerprint = "SHA256:" + strings.Repeat("A", 43)
		}, "trust pin"},
		{"two targets", func(r *canonical.Request) {
			r.ResolvedTargets = append(r.ResolvedTargets, r.ResolvedTargets[0])
		}, "exactly one target"},
	}
	for _, requirement := range []pb.ApprovalRequirement{
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY,
	} {
		for _, tc := range cases {
			t.Run(requirement.String()+"/"+tc.name, func(t *testing.T) {
				e := newGPEnv(t, gpGuests())
				e.exec.risk = pb.RiskClass_RISK_CLASS_HIGH
				e.exec.requirement = requirement
				e.exec.mutate = tc.mutate
				h := e.h.Handler()
				if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop")); rec.Code != http.StatusSeeOther {
					t.Fatalf("propose = %d %q", rec.Code, rec.Body.String())
				}
				d := e.exec.lastDigest()
				body := getBody(t, h, "/pve/guests/power/"+d)
				if !strings.Contains(body, "approval withheld") || !strings.Contains(body, tc.want) {
					t.Errorf("no prominent mismatch %q", tc.want)
				}
				if strings.Contains(body, "(bound target matches)") {
					t.Error("a mismatching binding is shown as matching")
				}
				gpNoApproval(t, body)
				if rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": d, "assertion": map[string]string{"id": "x"}}); rec.Code != http.StatusNotFound {
					t.Errorf("commit of a mismatching proposal = %d", rec.Code)
				}
				if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {d}}); rec.Code != http.StatusNotFound {
					t.Errorf("run of a mismatching proposal = %d", rec.Code)
				}
				time.Sleep(10 * time.Millisecond)
				if e.exec.commitCount() != 0 || len(e.exec.assertions) != 0 {
					t.Error("a mismatching proposal reached approval or commit")
				}
			})
		}
	}
}

func TestGuestPowerRefusesUnshowableCanonicalRequest(t *testing.T) {
	big, _ := json.Marshal(map[string]string{"action_id": "pve.guest.power", "pad": strings.Repeat("x", 16<<10)})
	cases := []struct {
		name      string
		raw       []byte
		badDigest bool
		want      string
	}{
		{"over 16 KiB", big, false, "too large"},
		{"invalid UTF-8", []byte("{\"action_id\":\"pve.guest.power\xff\"}"), false, "not valid UTF-8"},
		{"empty", []byte{}, false, "cannot be shown"},
		{"not JSON", []byte("action pve.guest.power"), false, "cannot be shown"},
		{"digest mismatch", nil, true, "does not match its digest"},
	}
	for _, requirement := range []pb.ApprovalRequirement{
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY,
	} {
		for _, tc := range cases {
			t.Run(requirement.String()+"/"+tc.name, func(t *testing.T) {
				e := newGPEnv(t, gpGuests())
				e.exec.requirement = requirement
				e.exec.raw, e.exec.badDigest = tc.raw, tc.badDigest
				h := e.h.Handler()
				rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "stop"))
				if rec.Code != http.StatusBadGateway {
					t.Fatalf("propose = %d, want 502", rec.Code)
				}
				msg := rec.Body.String()
				if !strings.Contains(msg, tc.want) || !strings.Contains(msg, "proposal is refused") {
					t.Errorf("error %q lacks %q", msg, tc.want)
				}
				gpNoApproval(t, msg)
				// No proposal page exists to approve from.
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/pve/guests/power/"+e.exec.lastDigest(), nil))
				if r.Code != http.StatusNotFound {
					t.Errorf("refused proposal page = %d", r.Code)
				}
				if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {e.exec.lastDigest()}}); rec.Code != http.StatusNotFound {
					t.Errorf("run of a refused proposal = %d", rec.Code)
				}
			})
		}
	}
}

// gpUsers serves the power routes behind the real login chain with one
// web session per user.
type gpUsers struct {
	*gpEnv
	srv      *httptest.Server
	sessions *auth.Store
}

func newGPUsers(t *testing.T, now func() time.Time) *gpUsers {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	e := newGPEnvClock(t, gpGuests(), now)
	sessions := auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	ts := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: gpOrigin}, a.Wrap(e.h.Handler())))
	t.Cleanup(ts.Close)
	return &gpUsers{gpEnv: e, srv: ts, sessions: sessions}
}

func (u *gpUsers) login(t *testing.T, user string) *http.Cookie {
	t.Helper()
	token, _, err := u.sessions.Create(context.Background(), "cred-"+user, user)
	if err != nil {
		t.Fatalf("create session for %s: %v", user, err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// do sends one request as the session's user and returns status and body.
func (u *gpUsers) do(t *testing.T, c *http.Cookie, method, path, contentType, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, u.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(c)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", gpOrigin)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(b)
}

const gpFormCT = "application/x-www-form-urlencoded"

// TestGuestPowerProposalIsolatedBetweenUsers checks with two real users
// that bob can neither see, approve nor run alice's proposal.
func TestGuestPowerProposalIsolatedBetweenUsers(t *testing.T) {
	t.Run("security key", func(t *testing.T) {
		u := newGPUsers(t, nil)
		alice, bob := u.login(t, "alice"), u.login(t, "bob")
		if code, body := u.do(t, alice, http.MethodPost, "/pve/guests/power", gpFormCT, gpForm("100", "qemu", "stop").Encode()); code != http.StatusSeeOther {
			t.Fatalf("alice propose = %d %q", code, body)
		}
		d := u.exec.lastDigest()
		if code, body := u.do(t, alice, http.MethodGet, "/pve/guests/power/"+d, "", ""); code != http.StatusOK || !strings.Contains(body, "schedule-approve") {
			t.Fatalf("alice's own page = %d", code)
		}
		if code, body := u.do(t, bob, http.MethodGet, "/pve/guests/power/"+d, "", ""); code != http.StatusNotFound || strings.Contains(body, d) {
			t.Errorf("bob sees alice's proposal: %d", code)
		}
		commit := `{"id":"` + d + `","assertion":{"id":"x"}}`
		if code, _ := u.do(t, bob, http.MethodPost, "/pve/guests/power/commit", "application/json", commit); code != http.StatusNotFound {
			t.Errorf("bob commits alice's proposal: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
		if len(u.exec.assertions) != 0 || u.exec.commitCount() != 0 {
			t.Error("bob's approval reached the executor")
		}
		// Alice's proposal is untouched by bob's attempt.
		if code, body := u.do(t, alice, http.MethodGet, "/pve/guests/power/"+d, "", ""); code != http.StatusOK || !strings.Contains(body, "schedule-approve") {
			t.Errorf("alice's proposal changed after bob's attempt: %d", code)
		}
	})
	t.Run("CLI", func(t *testing.T) {
		u := newGPUsers(t, nil)
		u.exec.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
		alice, bob := u.login(t, "alice"), u.login(t, "bob")
		if code, _ := u.do(t, alice, http.MethodPost, "/pve/guests/power", gpFormCT, gpForm("100", "qemu", "reboot").Encode()); code != http.StatusSeeOther {
			t.Fatalf("alice propose = %d", code)
		}
		d := u.exec.lastDigest()
		if code, _ := u.do(t, bob, http.MethodGet, "/pve/guests/power/"+d, "", ""); code != http.StatusNotFound {
			t.Errorf("bob sees alice's proposal: %d", code)
		}
		if code, _ := u.do(t, bob, http.MethodPost, "/pve/guests/power/run", gpFormCT, url.Values{"digest": {d}}.Encode()); code != http.StatusNotFound {
			t.Errorf("bob runs alice's proposal: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
		if u.exec.commitCount() != 0 {
			t.Fatal("bob's run reached the executor")
		}
		if code, _ := u.do(t, alice, http.MethodPost, "/pve/guests/power/run", gpFormCT, url.Values{"digest": {d}}.Encode()); code != http.StatusSeeOther {
			t.Errorf("alice's own run = %d", code)
		}
		gpWaitCommit(t, u.exec)
	})
}

// gpWaitPage polls the proposal page until it contains want.
func gpWaitPage(t *testing.T, h http.Handler, digest, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		body := getBody(t, h, "/pve/guests/power/"+digest)
		if strings.Contains(body, want) {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("page never showed %q: %s", want, body)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestGuestPowerBackgroundCommitErrors(t *testing.T) {
	cli := pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	key := pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED
	cases := []struct {
		name        string
		requirement pb.ApprovalRequirement
		err         error
		pending     bool   // back to pending: the run form is offered again
		want        string // shown message
		hidden      string // must not be shown
	}{
		{"CLI not approved", cli, status.Error(codes.PermissionDenied, "permit not approved"), true, "the executor refused: permit not approved", ""},
		{"CLI guest changed", cli, status.Error(codes.FailedPrecondition, "guest state changed"), true, "the executor refused: guest state changed", ""},
		{"CLI not found", cli, status.Error(codes.NotFound, "permit unknown"), false, "the executor refused: permit unknown", ""},
		{"key refused", key, status.Error(codes.PermissionDenied, "permit consumed"), false, "the executor refused: permit consumed", ""},
		{"key precondition", key, status.Error(codes.FailedPrecondition, "guest stopped"), false, "the executor refused: guest stopped", ""},
		{"transport", cli, errors.New("dial tcp 10.1.2.3:7443: connect: connection refused"), false, "executor unavailable", "10.1.2.3"},
		{"grpc transport", key, status.Error(codes.Unavailable, "connection error: desc = \"transport: Error while dialing: dial tcp 10.1.2.3:7443: connect: connection refused\""), false, "executor unavailable", "10.1.2.3"},
		{"internal", key, status.Error(codes.Internal, "sqlite: /var/lib/nebula/executor.db locked"), false, "executor unavailable", "sqlite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGPEnv(t, gpGuests())
			e.exec.requirement = tc.requirement
			e.exec.commitErr = tc.err
			h := e.h.Handler()
			if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "shutdown")); rec.Code != http.StatusSeeOther {
				t.Fatalf("propose = %d", rec.Code)
			}
			d := e.exec.lastDigest()
			if tc.requirement == cli {
				if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {d}}); rec.Code != http.StatusSeeOther {
					t.Fatalf("run = %d", rec.Code)
				}
			} else {
				if rec := gpPostJSON(t, h, "/pve/guests/power/commit", map[string]any{"id": d, "assertion": map[string]string{"id": "x"}}); rec.Code != http.StatusOK {
					t.Fatalf("commit = %d", rec.Code)
				}
			}
			gpWaitCommit(t, e.exec)
			body := gpWaitPage(t, h, d, tc.want)
			if tc.hidden != "" && strings.Contains(body, tc.hidden) {
				t.Errorf("page shows internal detail %q", tc.hidden)
			}
			offered := strings.Contains(body, `action="/pve/guests/power/run"`)
			if offered != tc.pending {
				t.Errorf("run form offered = %v, want %v (back to pending)", offered, tc.pending)
			}
			if strings.Contains(body, "schedule-approve") {
				t.Error("a failed security key commit offers approval again")
			}
			if !tc.pending {
				if !strings.Contains(body, "Back to the chart") {
					t.Error("failed run shows no way back")
				}
				// A failed proposal cannot be run again.
				if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {d}}); rec.Code != http.StatusNotFound {
					t.Errorf("run after failure = %d", rec.Code)
				}
			} else {
				// Back to pending: after CLI approval it can run again.
				e.exec.mu.Lock()
				e.exec.commitErr = nil
				e.exec.mu.Unlock()
				if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {d}}); rec.Code != http.StatusSeeOther {
					t.Errorf("run again = %d", rec.Code)
				}
				gpWaitPage(t, h, d, "exec-1")
			}
		})
	}
}

func TestGuestPowerExecutorTextIsCapped(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	e.exec.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	e.exec.commitErr = status.Error(codes.NotFound, strings.Repeat("é", 400))
	h := e.h.Handler()
	gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "shutdown"))
	d := e.exec.lastDigest()
	if rec := gpPost(t, h, "/pve/guests/power/run", url.Values{"digest": {d}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("run = %d", rec.Code)
	}
	body := gpWaitPage(t, h, d, "the executor refused: é")
	// 300 bytes of two-byte runes, cut on a rune boundary.
	if n := strings.Count(body, "é"); n != 150 {
		t.Errorf("executor text shows %d runes, want 150", n)
	}
}

func TestGuestPowerProposeThrottledBeforeStoreReads(t *testing.T) {
	e := newGPEnv(t, gpGuests())
	h := e.h.Handler()
	if rec := gpPost(t, h, "/pve/guests/power", gpForm("100", "qemu", "shutdown")); rec.Code != http.StatusSeeOther {
		t.Fatalf("first propose = %d", rec.Code)
	}
	lists := e.store.lists()
	rec := gpPost(t, h, "/pve/guests/power", gpForm("101", "lxc", "shutdown"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second propose = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q", got)
	}
	if e.store.lists() != lists {
		t.Error("a throttled proposal read the store")
	}
	if len(e.exec.proposals()) != 1 {
		t.Error("a throttled proposal reached the executor")
	}
}

// gpClock is a test clock advanced by hand.
type gpClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *gpClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *gpClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestGuestPowerProposalLimitKeepsOtherUsersPending fills the 256-entry
// table with alice's pending proposals: bob's proposal is refused rather
// than evicting one of hers, and her own next proposal evicts her oldest.
func TestGuestPowerProposalLimitKeepsOtherUsersPending(t *testing.T) {
	clock := &gpClock{t: time.Now()}
	u := newGPUsers(t, clock.now)
	alice, bob := u.login(t, "alice"), u.login(t, "bob")
	var first string
	for i := 0; i < 256; i++ {
		if code, body := u.do(t, alice, http.MethodPost, "/pve/guests/power", gpFormCT, gpForm("100", "qemu", "shutdown").Encode()); code != http.StatusSeeOther {
			t.Fatalf("alice proposal %d = %d %q", i, code, body)
		}
		if i == 0 {
			first = u.exec.lastDigest()
		}
		clock.add(2 * time.Second)
	}
	code, body := u.do(t, bob, http.MethodPost, "/pve/guests/power", gpFormCT, gpForm("101", "lxc", "shutdown").Encode())
	if code != http.StatusServiceUnavailable {
		t.Errorf("bob's proposal with a full table = %d %q, want 503", code, body)
	}
	if code, _ := u.do(t, alice, http.MethodGet, "/pve/guests/power/"+first, "", ""); code != http.StatusOK {
		t.Errorf("alice's oldest proposal was evicted by bob: %d", code)
	}
	if code, _ := u.do(t, alice, http.MethodPost, "/pve/guests/power", gpFormCT, gpForm("100", "qemu", "shutdown").Encode()); code != http.StatusSeeOther {
		t.Fatalf("alice's proposal 257 = %d", code)
	}
	if code, _ := u.do(t, alice, http.MethodGet, "/pve/guests/power/"+first, "", ""); code != http.StatusNotFound {
		t.Errorf("alice's own oldest proposal kept: %d", code)
	}
	if code, _ := u.do(t, alice, http.MethodGet, "/pve/guests/power/"+u.exec.lastDigest(), "", ""); code != http.StatusOK {
		t.Errorf("alice's newest proposal = %d", code)
	}
}
