// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	privDigest = "sha256:" + "ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	privUser   = "robot"
	privSecret = "s3cr3t-pat-value"
	privToken  = "authenticated-bearer-token"
)

// privServer is a TLS registry with token auth on /auth. It records every
// request with the Authorization scheme it carried.
type privServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	reqs      []string
	realm     string // realm sent in the challenge; default srv.URL+"/auth"
	service   string
	basicOnly bool // basic auth on the registry itself
	secret    string
	redirect  string // when set, manifest requests redirect here
}

func newPrivServer(t *testing.T) *privServer {
	t.Helper()
	p := &privServer{secret: privSecret, service: "registry.example"}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *privServer) goodBasic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(privUser+":"+p.secret))
}

func (p *privServer) handle(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	scheme, _, _ := strings.Cut(authz, " ")
	p.mu.Lock()
	p.reqs = append(p.reqs, r.Method+" "+r.URL.Path+" "+scheme)
	realm, redirect := p.realm, p.redirect
	p.mu.Unlock()
	if realm == "" {
		realm = p.srv.URL + "/auth"
	}
	if r.URL.Path == "/auth" {
		if authz != p.goodBasic() || r.URL.Query().Get("scope") != "repository:team/app:pull" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": privToken})
		return
	}
	ok := authz == "Bearer "+privToken
	if p.basicOnly {
		ok = authz == p.goodBasic()
	}
	if !ok {
		if p.basicOnly {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		} else {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",scope="repository:team/app:pull"`, realm, p.service))
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case redirect != "" && strings.Contains(r.URL.Path, "/manifests/"):
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/v2/team/app/manifests/"):
		w.Header().Set("Docker-Content-Digest", privDigest)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/team/app/tags/list":
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "team/app", "tags": []string{"1.0.0", "1.1.0"}})
	default:
		http.NotFound(w, r)
	}
}

func (p *privServer) log() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.reqs...)
}

func (p *privServer) registry(mode AuthMode) PrivateRegistry {
	r := PrivateRegistry{Registry: p.srv.URL, Mode: mode, Repositories: []string{"team/app"}}
	if mode == AuthToken {
		r.Realm, r.Service = p.srv.URL+"/auth", "registry.example"
	}
	return r
}

func newPrivClient(t *testing.T, p *privServer, reg PrivateRegistry, fc *fakeClock) *PrivateClient {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(p.srv.Certificate())
	c, err := NewPrivateClient(PrivateOptions{
		Registry: reg, RootCAs: pool, Now: fc.Now, Sleep: fc.Sleep,
		Jitter: func() time.Duration { return 0 }, AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewPrivateClient: %v", err)
	}
	return c
}

func goodCred() Credential { return Credential{Username: privUser, Secret: []byte(privSecret)} }

func TestPrivateTokenAuthSendsCredentialOnlyToApprovedRealm(t *testing.T) {
	p := newPrivServer(t)
	c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
	ref := Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}
	res, err := c.TagDigest(context.Background(), ref, goodCred(), "reg1/cred:1")
	if err != nil || res.Digest != privDigest {
		t.Fatalf("TagDigest = %+v, %v", res, err)
	}
	for _, l := range p.log() {
		if strings.HasSuffix(l, " Basic") && !strings.HasPrefix(l, "GET /auth ") {
			t.Fatalf("basic credential sent outside the realm: %q", l)
		}
	}
	tags, err := c.ListTags(context.Background(), Ref{Registry: p.srv.URL, Repository: "team/app"}, goodCred(), "reg1/cred:1")
	if err != nil || len(tags.Tags) != 2 || tags.Incomplete {
		t.Fatalf("ListTags = %+v, %v", tags, err)
	}
}

func TestPrivateBasicAuthOnRegistryOrigin(t *testing.T) {
	p := newPrivServer(t)
	p.basicOnly = true
	c := newPrivClient(t, p, p.registry(AuthBasic), newFakeClock())
	res, err := c.TagDigest(context.Background(), Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}, goodCred(), "reg1/cred:1")
	if err != nil || res.Digest != privDigest {
		t.Fatalf("TagDigest = %+v, %v", res, err)
	}
	if got := p.log(); len(got) != 1 || got[0] != "HEAD /v2/team/app/manifests/1.0.0 Basic" {
		t.Fatalf("requests = %q", got)
	}
}

func TestPrivateChallengeCannotSelectRealmOrService(t *testing.T) {
	other := newPrivServer(t)
	for name, mutate := range map[string]func(p *privServer){
		"other origin":  func(p *privServer) { p.realm = other.srv.URL + "/auth" },
		"other path":    func(p *privServer) { p.realm = p.srv.URL + "/evil" },
		"other service": func(p *privServer) { p.service = "attacker" },
		"query smuggle": func(p *privServer) { p.realm = p.srv.URL + "/auth?x=1" },
	} {
		t.Run(name, func(t *testing.T) {
			p := newPrivServer(t)
			mutate(p)
			c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
			_, err := c.TagDigest(context.Background(), Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}, goodCred(), "reg1/cred:1")
			if !errors.Is(err, ErrRealmNotApproved) {
				t.Fatalf("err = %v, want ErrRealmNotApproved", err)
			}
			for _, l := range append(p.log(), other.log()...) {
				if !strings.HasSuffix(l, " ") {
					t.Fatalf("a credentialed request was sent: %q", l)
				}
			}
		})
	}
}

func TestPrivateRedirectsAreNotFollowed(t *testing.T) {
	p := newPrivServer(t)
	other := newPrivServer(t)
	p.redirect = other.srv.URL + "/v2/team/app/manifests/1.0.0"
	c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
	_, err := c.TagDigest(context.Background(), Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}, goodCred(), "reg1/cred:1")
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("err = %v, want ErrRedirectNotAllowed", err)
	}
	if n := len(other.log()); n != 0 {
		t.Fatalf("redirect target received %d requests", n)
	}
}

func TestPrivateRepositoryScopeIsExact(t *testing.T) {
	p := newPrivServer(t)
	c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
	for _, repo := range []string{"team/other", "team", "team/app/sub", "library/team/app"} {
		_, err := c.TagDigest(context.Background(), Ref{Registry: p.srv.URL, Repository: repo, Tag: "1"}, goodCred(), "reg1/cred:1")
		if !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("%s: err = %v, want ErrOutOfScope", repo, err)
		}
	}
	_, err := c.ListTags(context.Background(), Ref{Registry: "https://registry-1.docker.io", Repository: "team/app"}, goodCred(), "reg1/cred:1")
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("other registry: err = %v", err)
	}
	if n := len(p.log()); n != 0 {
		t.Fatalf("out-of-scope reads sent %d requests", n)
	}
}

func TestPrivateCredentialRotationUsesSeparateCacheScope(t *testing.T) {
	p := newPrivServer(t)
	fc := newFakeClock()
	c := newPrivClient(t, p, p.registry(AuthToken), fc)
	ref := Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}
	bad := Credential{Username: privUser, Secret: []byte("old-revoked-secret")}
	_, err := c.TagDigest(context.Background(), ref, bad, "reg1/cred:1")
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("err = %v, want ErrCredentialRejected", err)
	}
	if strings.Contains(err.Error(), "old-revoked-secret") || strings.Contains(err.Error(), privUser+":") {
		t.Fatalf("error leaks the credential: %v", err)
	}
	n := len(p.log())
	if _, err := c.TagDigest(context.Background(), ref, bad, "reg1/cred:1"); !errors.Is(err, ErrCredentialRejected) || len(p.log()) != n {
		t.Fatalf("failure not cached per scope: %v, %d -> %d requests", err, n, len(p.log()))
	}
	fc.Advance(2 * time.Second)
	res, err := c.TagDigest(context.Background(), ref, goodCred(), "reg1/cred:2")
	if err != nil || res.Digest != privDigest || res.FromCache {
		t.Fatalf("rotated credential: %+v, %v", res, err)
	}
}

func TestPrivateClientNeverPullsBodiesOrLayers(t *testing.T) {
	reg := PrivateRegistry{Registry: "https://reg.example", Mode: AuthToken, Realm: "https://auth.example/token", Repositories: []string{"team/app"}}
	realm, err := reg.Validate()
	if err != nil {
		t.Fatal(err)
	}
	pc := &privateConfig{reg: reg, registry: reg.Registry, realm: realm}
	for _, tc := range []struct {
		method, url string
		ok          bool
	}{
		{http.MethodHead, "https://reg.example/v2/team/app/manifests/1.0", true},
		{http.MethodGet, "https://reg.example/v2/team/app/tags/list?n=100&last=a", true},
		{http.MethodGet, "https://auth.example/token?scope=repository%3Ateam%2Fapp%3Apull", true},
		{http.MethodGet, "https://reg.example/v2/team/app/manifests/1.0", false},
		{http.MethodGet, "https://reg.example/v2/team/app/blobs/sha256:00", false},
		{http.MethodHead, "https://reg.example/v2/team/app/blobs/sha256:00", false},
		{http.MethodHead, "https://reg.example/v2/team/other/manifests/1.0", false},
		{http.MethodGet, "https://reg.example/v2/_catalog", false},
		{http.MethodGet, "https://auth.example/other", false},
		{http.MethodPost, "https://auth.example/token", false},
		{http.MethodHead, "https://evil.example/v2/team/app/manifests/1.0", false},
	} {
		req, _ := http.NewRequest(tc.method, tc.url, nil)
		if err := pc.allowRequest(req); (err == nil) != tc.ok {
			t.Errorf("%s %s: err = %v, want ok=%v", tc.method, tc.url, err, tc.ok)
		}
	}
	req, _ := http.NewRequest(http.MethodHead, "https://reg.example/v2/team/app/manifests/1.0", nil)
	req.Header.Set("Authorization", "Basic eDp5")
	if err := pc.allowRequest(req); err == nil {
		t.Error("basic credential to the registry origin in token mode was allowed")
	}
}

func TestPrivateRegistryValidation(t *testing.T) {
	base := PrivateRegistry{Registry: "https://reg.example", Mode: AuthToken, Realm: "https://auth.example/token", Repositories: []string{"team/app"}}
	for name, mutate := range map[string]func(r *PrivateRegistry){
		"http registry":   func(r *PrivateRegistry) { r.Registry = "http://reg.example" },
		"registry path":   func(r *PrivateRegistry) { r.Registry = "https://reg.example/v2" },
		"http realm":      func(r *PrivateRegistry) { r.Realm = "http://auth.example/token" },
		"realm query":     func(r *PrivateRegistry) { r.Realm = "https://auth.example/token?a=b" },
		"realm userinfo":  func(r *PrivateRegistry) { r.Realm = "https://u:p@auth.example/token" },
		"no realm":        func(r *PrivateRegistry) { r.Realm = "" },
		"basic realm":     func(r *PrivateRegistry) { r.Mode = AuthBasic },
		"unknown mode":    func(r *PrivateRegistry) { r.Mode = "helper" },
		"no repositories": func(r *PrivateRegistry) { r.Repositories = nil },
		"wildcard":        func(r *PrivateRegistry) { r.Repositories = []string{"team/*"} },
		"duplicate":       func(r *PrivateRegistry) { r.Repositories = []string{"team/app", "team/app"} },
		"service quote":   func(r *PrivateRegistry) { r.Service = `a"b` },
	} {
		r := base
		r.Repositories = append([]string(nil), base.Repositories...)
		mutate(&r)
		if _, err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := base.Validate(); err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}
}

func TestPrivateCredentialValidation(t *testing.T) {
	for _, c := range []Credential{
		{Username: "", Secret: []byte("x")},
		{Username: "a:b", Secret: []byte("x")},
		{Username: "a", Secret: nil},
		{Username: "a", Secret: make([]byte, MaxSecretLen+1)},
		{Username: "a\nb", Secret: []byte("x")},
	} {
		if _, err := c.basic(); !errors.Is(err, ErrCredentialRejected) {
			t.Errorf("%q accepted: %v", c.Username, err)
		}
	}
}

func TestPrivateClientRefusesAnonymousUse(t *testing.T) {
	p := newPrivServer(t)
	c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
	ref := Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}
	if _, err := c.c.TagDigest(context.Background(), ref); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("anonymous TagDigest: %v", err)
	}
	if _, err := c.c.ListTags(context.Background(), ref); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("anonymous ListTags: %v", err)
	}
	pubSrv := httptest.NewServer(http.NotFoundHandler())
	defer pubSrv.Close()
	pub := newTestClient(t, pubSrv, newFakeClock())
	cred := goodCred()
	if _, err := pub.request(context.Background(), ref, "team/app", http.MethodHead, ref.Registry, nil, &cred); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("public client accepted a credential: %v", err)
	}
}

func TestPrivateNetworkStillRefusesLoopback(t *testing.T) {
	reg := PrivateRegistry{Registry: "https://reg.example", Mode: AuthBasic, Repositories: []string{"team/app"}, AllowPrivateNetwork: true}
	c, err := NewPrivateClient(PrivateOptions{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"127.0.0.1:443", "169.254.1.1:443", "[::1]:443"} {
		if _, err := c.c.dialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrPrivateAddress) {
			t.Fatalf("%s: err = %v", addr, err)
		}
	}
	reg.AllowPrivateNetwork = false
	c, err = NewPrivateClient(PrivateOptions{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.c.dialContext(context.Background(), "tcp", "10.1.2.3:443"); !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("private address without approval: %v", err)
	}
}

func TestParseChallengeParams(t *testing.T) {
	got, err := parseChallengeParams(`realm="https://a/b",service="s", scope="repository:x:pull"`)
	if err != nil || got["realm"] != "https://a/b" || got["service"] != "s" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{`realm="a",realm="b"`, `realm="a`, `=x`, `realm="a" service="b"`, `realm="a\"b"`} {
		if _, err := parseChallengeParams(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
