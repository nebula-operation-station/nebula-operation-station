// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// The production provider (executorclient.Client, wrapped by
// lazyExecutor in cmd/nebula-server) must satisfy the banner interface,
// so the production wiring compiles.
var _ ui.BuiltinTrustProvider = (*executorclient.Client)(nil)

// fakeBuiltinTrust is the Options.BuiltinTrust provider for tests.
type fakeBuiltinTrust struct {
	resp *pb.GetBuiltinTrustStatusResponse
	err  error
}

func (f fakeBuiltinTrust) GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error) {
	return f.resp, f.err
}

func trustHandler(t *testing.T, bt *pb.GetBuiltinTrustStatusResponse, err error) http.Handler {
	t.Helper()
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		BuiltinTrust: fakeBuiltinTrust{resp: bt, err: err},
	})
	return h.Handler()
}

func TestTrustBannerUntrustedRendersAffectedVersionsEscaped(t *testing.T) {
	body := getBody(t, trustHandler(t, &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "<img src=x onerror=alert(1)>", ReleaseVersion: "<b>2.1.0</b>", ReleaseSha256: "bb"},
			{Name: "core", TrustedVersion: "1.0.0", TrustedSha256: "aa", ReleaseVersion: "1.1.0", ReleaseSha256: "cc"},
		},
	}, nil), "/dashboard")

	for _, want := range []string{
		`class="trust-banner trust-banner--untrusted"`,
		"Built-ins are untrusted: every operation using them needs UV until you trust them.",
		"Affected built-ins:",
		"&lt;img src=x onerror=alert(1)&gt;",
		"&lt;b&gt;2.1.0&lt;/b&gt;",
		"<code>1.1.0</code>",
		"(trusted: <code>1.0.0</code>)",
		"nebula artifact trust-builtins",
		"does not amend existing read leases",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, raw := range []string{"<img src=x onerror=alert(1)>", "<b>2.1.0</b>"} {
		if strings.Contains(body, raw) {
			t.Errorf("dashboard renders untrusted executor text as HTML: %q", raw)
		}
	}
}

func TestTrustBannerUnavailableIsDistinct(t *testing.T) {
	body := getBody(t, trustHandler(t, &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE,
	}, nil), "/dashboard")
	for _, want := range []string{
		`trust-banner--unavailable`,
		"unreachable",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, not := range []string{
		"Built-ins are untrusted",
		"Affected built-ins",
		"trust-builtins",
	} {
		if strings.Contains(body, not) {
			t.Errorf("unavailable banner conflates unreachable with untrusted: %q", not)
		}
	}
}

func TestTrustBannerHiddenWhenTrusted(t *testing.T) {
	body := getBody(t, trustHandler(t, &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED,
	}, nil), "/dashboard")
	if strings.Contains(body, "trust-banner") {
		t.Error("trusted state: banner rendered")
	}
}

func TestTrustBannerRPCErrorIsUnreachable(t *testing.T) {
	var logged bytes.Buffer
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		BuiltinTrust: fakeBuiltinTrust{err: errors.New(rawExecutorError)},
		Log:          slog.New(slog.NewTextHandler(&logged, nil)),
	})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "trust-banner--unavailable") {
		t.Error("RPC failure: banner is not the unreachable state")
	}
	for _, frag := range []string{"dial unix", "connection refused", "/run/nebula/executor.sock"} {
		if strings.Contains(body, frag) {
			t.Errorf("banner leaked raw error fragment %q", frag)
		}
	}
	if !strings.Contains(logged.String(), rawExecutorError) {
		t.Error("error detail not logged")
	}
}

func TestTrustBannerNotOnBarePages(t *testing.T) {
	// The login page is bare: no banner even when the built-ins are
	// untrusted.
	body := getBody(t, trustHandler(t, &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
	}, nil), "/login")
	if strings.Contains(body, "trust-banner") {
		t.Error("bare page rendered the trust banner")
	}
}

// countingBuiltinTrust counts RPCs made by page renders.
type countingBuiltinTrust struct {
	calls atomic.Int32
	resp  *pb.GetBuiltinTrustStatusResponse
}

func (f *countingBuiltinTrust) GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error) {
	f.calls.Add(1)
	return f.resp, nil
}

func TestTrustBannerCachedAcrossPageRenders(t *testing.T) {
	p := &countingBuiltinTrust{resp: &pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED}}
	now := time.Unix(1_000_000, 0)
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		BuiltinTrust: p,
		Now:          func() time.Time { return now },
	}).Handler()
	for _, path := range []string{"/dashboard", "/inventory", "/dashboard"} {
		if body := getBody(t, h, path); !strings.Contains(body, "trust-banner--untrusted") {
			t.Fatalf("GET %s: untrusted banner missing", path)
		}
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("%d trust RPCs for three page renders within the TTL, want 1", n)
	}
}

func TestTrustBannerRendersRemovedModule(t *testing.T) {
	body := getBody(t, trustHandler(t, &pb.GetBuiltinTrustStatusResponse{
		State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED,
		Modules: []*pb.BuiltinTrustEntry{
			{Name: "oldmod", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED, TrustedVersion: "0.9.0", TrustedSha256: "ee"},
		},
	}, nil), "/dashboard")
	for _, want := range []string{
		"Affected built-ins:",
		"<code>oldmod</code> removed from the local release (trusted: <code>0.9.0</code>)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}
