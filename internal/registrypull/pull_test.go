// SPDX-License-Identifier: AGPL-3.0-or-later

package registrypull

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

const (
	testRepo    = "team/app"
	testUser    = "puller"
	testSecret  = "s3cret-PAT-value"
	testToken   = "bearer-TOKEN-value"
	testService = "reg.test"
	testSig     = "SIGNED-QUERY-value"
)

var testPlatform = Platform{OS: "linux", Architecture: "amd64"}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type reqLog struct {
	server string
	path   string
	authz  string
}

// fakeRegistry is an httptest TLS registry with token or basic auth.
type fakeRegistry struct {
	srv       *httptest.Server
	mode      registrymeta.AuthMode
	realm     string // challenge realm; default srv.URL+"/token"
	service   string // challenge service
	tokenCode int    // non-zero: token endpoint status
	alwaysNo  bool   // registry refuses even a valid token

	mu        sync.Mutex
	manifests map[string][]byte
	mtypes    map[string]string
	blobs     map[string][]byte
	hook      func(w http.ResponseWriter, r *http.Request) bool
	log       *[]reqLog
}

func newFakeRegistry(t *testing.T, mode registrymeta.AuthMode, log *[]reqLog) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{mode: mode, service: testService, manifests: map[string][]byte{}, mtypes: map[string]string{}, blobs: map[string][]byte{}, log: log}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.realm = f.srv.URL + "/token"
	return f
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	*f.log = append(*f.log, reqLog{server: f.srv.URL, path: r.URL.Path, authz: r.Header.Get("Authorization")})
	hook := f.hook
	f.mu.Unlock()
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(testUser+":"+testSecret))
	if r.URL.Path == "/token" {
		if f.tokenCode != 0 {
			w.WriteHeader(f.tokenCode)
			return
		}
		if r.Header.Get("Authorization") != basic || r.URL.Query().Get("scope") != "repository:"+testRepo+":pull" ||
			r.URL.Query().Get("service") != testService {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": testToken})
		return
	}
	authz := r.Header.Get("Authorization")
	ok := (f.mode == registrymeta.AuthToken && authz == "Bearer "+testToken) || (f.mode == registrymeta.AuthBasic && authz == basic)
	if !ok || f.alwaysNo {
		if f.mode == registrymeta.AuthToken {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s",scope="repository:%s:pull"`, f.realm, f.service, testRepo))
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	prefix := "/v2/" + testRepo + "/"
	switch {
	case strings.HasPrefix(r.URL.Path, prefix+"manifests/"):
		d := strings.TrimPrefix(r.URL.Path, prefix+"manifests/")
		b, found := f.manifests[d]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", f.mtypes[d])
		_, _ = w.Write(b)
	case strings.HasPrefix(r.URL.Path, prefix+"blobs/"):
		b, found := f.blobs[strings.TrimPrefix(r.URL.Path, prefix+"blobs/")]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeRegistry) setHook(h func(w http.ResponseWriter, r *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

// testImage is one image registered in a fake registry.
type testImage struct {
	layers   [][]byte
	config   []byte
	manifest []byte
	index    []byte
}

func (img testImage) manifestDigest() string { return sha(img.manifest) }
func (img testImage) indexDigest() string    { return sha(img.index) }

// addImage registers an image with the given layers and an index holding it
// and an arm64 sibling.
func (f *fakeRegistry) addImage(t *testing.T, layers ...[]byte) testImage {
	t.Helper()
	var diffIDs []string
	var descs []map[string]any
	for _, l := range layers {
		diffIDs = append(diffIDs, sha(append([]byte("diff-"), l...)))
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(l), "size": len(l)})
		f.blobs[sha(l)] = l
	}
	cfg := mustJSON(t, map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	f.blobs[sha(cfg)] = cfg
	man := mustJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": map[string]any{"mediaType": mtOCIConfig, "digest": sha(cfg), "size": len(cfg)},
		"layers": descs,
	})
	f.manifests[sha(man)] = man
	f.mtypes[sha(man)] = mtOCIManifest
	idx := mustJSON(t, map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIIndex,
		"manifests": []map[string]any{
			{"mediaType": mtOCIManifest, "digest": sha(man), "size": len(man), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			{"mediaType": mtOCIManifest, "digest": sha([]byte("other")), "size": 10, "platform": map[string]string{"os": "linux", "architecture": "arm64", "variant": "v8"}},
		},
	})
	f.manifests[sha(idx)] = idx
	f.mtypes[sha(idx)] = mtOCIIndex
	return testImage{layers: layers, config: cfg, manifest: man, index: idx}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rootsFor(srvs ...*httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, s := range srvs {
		pool.AddCert(s.Certificate())
	}
	return pool
}

func newTestPuller(t *testing.T, f *fakeRegistry, mut func(*Options)) *Puller {
	t.Helper()
	reg := registrymeta.PrivateRegistry{Registry: f.srv.URL, Mode: f.mode, Repositories: []string{testRepo, "team/other"}}
	if f.mode == registrymeta.AuthToken {
		reg.Realm = f.srv.URL + "/token"
		reg.Service = testService
	}
	o := Options{Registry: reg, RootCAs: rootsFor(f.srv), TempDir: t.TempDir(), AllowLoopback: true}
	if mut != nil {
		mut(&o)
	}
	p, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func testCred() registrymeta.Credential {
	return registrymeta.Credential{Username: testUser, Secret: []byte(testSecret)}
}

func request(digest string) Request {
	return Request{Repository: testRepo, Digest: digest, Tag: "1.2.3", Platform: testPlatform}
}

// readArchive returns the archive's regular files and whether the tar
// stream ended with a proper trailer.
func readArchive(t *testing.T, b []byte) (map[string][]byte, bool) {
	t.Helper()
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			// archive/tar also reports a clean EOF without a trailer; a
			// finished archive ends with two zero blocks.
			return files, len(b) >= 1024 && bytes.Equal(b[len(b)-1024:], make([]byte, 1024))
		}
		if err != nil {
			return files, false
		}
		if h.Typeflag == tar.TypeReg {
			c, err := io.ReadAll(tr)
			if err != nil {
				return files, false
			}
			files[h.Name] = c
		}
	}
}

// assertClean fails when err mentions the credential, token or a signed
// blob URL query.
func assertClean(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{testSecret, testToken, testSig, base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testSecret))} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks a secret: %v", err)
		}
	}
}

// assertNoArchive fails when out holds manifest.json or a complete archive.
func assertNoArchive(t *testing.T, out []byte) {
	t.Helper()
	files, complete := readArchive(t, out)
	if _, ok := files["manifest.json"]; ok || complete {
		t.Fatalf("failed pull produced a loadable archive (complete=%v, files=%d)", complete, len(files))
	}
}

func digestPath(d string) string {
	pd, err := parseDigest(d)
	if err != nil {
		panic(err)
	}
	return pd.path()
}

func TestPullIndexWithTokenAuthWritesDockerArchive(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	l1, l2 := bytes.Repeat([]byte("a"), 70000), []byte("layer-two")
	img := f.addImage(t, l1, l2, l1)
	tmp := t.TempDir()
	p := newTestPuller(t, f, func(o *Options) { o.TempDir = tmp })

	var out bytes.Buffer
	res, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	host := strings.TrimPrefix(f.srv.URL, "https://")
	want := Result{IndexDigest: img.indexDigest(), ManifestDigest: img.manifestDigest(), ImageID: sha(img.config),
		RepoTag: host + "/team/app:1.2.3", Layers: 3, BlobBytes: int64(len(l1) + len(l2) + len(img.config))}
	if res != want {
		t.Fatalf("result = %+v, want %+v", res, want)
	}
	files, complete := readArchive(t, out.Bytes())
	if !complete {
		t.Fatal("archive is not complete")
	}
	var man []archiveManifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	wantMan := []archiveManifest{{Config: digestPath(sha(img.config)), RepoTags: []string{host + "/team/app:1.2.3"},
		Layers: []string{digestPath(sha(l1)), digestPath(sha(l2)), digestPath(sha(l1))}}}
	if fmt.Sprint(man) != fmt.Sprint(wantMan) {
		t.Fatalf("manifest.json = %+v, want %+v", man, wantMan)
	}
	var repos map[string]map[string]string
	if err := json.Unmarshal(files["repositories"], &repos); err != nil {
		t.Fatal(err)
	}
	if repos[host+"/team/app"]["1.2.3"] != strings.TrimPrefix(sha(img.config), "sha256:") {
		t.Fatalf("repositories = %v", repos)
	}
	for _, b := range [][]byte{l1, l2, img.config} {
		if !bytes.Equal(files[digestPath(sha(b))], b) {
			t.Fatalf("blob %s missing or altered", sha(b))
		}
	}
	// The credential went only to the realm, the token only to the registry.
	blobGets := 0
	for _, l := range log {
		switch {
		case l.path == "/token":
			if !strings.HasPrefix(l.authz, "Basic ") {
				t.Fatalf("token request without Basic credential")
			}
		case strings.HasPrefix(l.authz, "Basic "):
			t.Fatalf("Basic credential sent to %s", l.path)
		case strings.Contains(l.path, "/blobs/"):
			blobGets++
		}
	}
	if blobGets != 3 { // config + two unique layers
		t.Fatalf("blob GETs = %d, want 3 (duplicate layer fetched once)", blobGets)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("spool files left behind: %d", len(ents))
	}
	if strings.Contains(fmt.Sprintf("%+v", res), testToken) {
		t.Fatal("result leaks the token")
	}
}

func TestPullBasicAuthSingleManifest(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthBasic, &log)
	img := f.addImage(t, []byte("only-layer"))
	p := newTestPuller(t, f, nil)
	var out bytes.Buffer
	res, err := p.Pull(context.Background(), testCred(), request(img.manifestDigest()), &out)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if res.IndexDigest != "" || res.ManifestDigest != img.manifestDigest() {
		t.Fatalf("result = %+v", res)
	}
	if files, complete := readArchive(t, out.Bytes()); !complete || files["manifest.json"] == nil {
		t.Fatal("archive incomplete")
	}
	for _, l := range log {
		if l.path == "/token" {
			t.Fatal("basic auth must not call a token endpoint")
		}
	}
}

func TestWrongBlobDigestStopsPullWithoutWritingBlob(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	good := []byte("good-layer-content")
	img := f.addImage(t, []byte("first"), good)
	evil := []byte("EVIL-layer-content") // same length as good
	f.blobs[sha(good)] = evil
	p := newTestPuller(t, f, nil)
	var out bytes.Buffer
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	assertClean(t, err)
	assertNoArchive(t, out.Bytes())
	if bytes.Contains(out.Bytes(), evil) {
		t.Fatal("unverified blob bytes reached the output")
	}
}

func TestManifestDigestMismatchIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	other := f.addImage(t, []byte("m"))
	f.manifests[img.manifestDigest()] = other.manifest // served under the wrong digest
	p := newTestPuller(t, f, nil)
	for _, d := range []string{img.manifestDigest(), img.indexDigest()} {
		var out bytes.Buffer
		_, err := p.Pull(context.Background(), testCred(), request(d), &out)
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("%s: err = %v, want ErrDigestMismatch", d, err)
		}
		if out.Len() != 0 {
			t.Fatal("output written before the manifest was verified")
		}
	}
}

func TestOversizeManifestIsRefused(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			var log []reqLog
			f := newFakeRegistry(t, registrymeta.AuthToken, &log)
			img := f.addImage(t, []byte("l"))
			if chunked {
				f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
					if !strings.Contains(r.URL.Path, "/manifests/") {
						return false
					}
					w.Header().Set("Content-Type", mtOCIIndex)
					_, _ = w.Write(img.index[:10])
					w.(http.Flusher).Flush() // no Content-Length
					_, _ = w.Write(img.index[10:])
					return true
				})
			}
			p := newTestPuller(t, f, func(o *Options) { o.Limits.ManifestBytes = 64 })
			_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestOversizeBlobIsRefusedBeforeFetch(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, bytes.Repeat([]byte("x"), 4096))
	p := newTestPuller(t, f, func(o *Options) { o.Limits.BlobBytes = 1024 })
	var out bytes.Buffer
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	for _, l := range log {
		if strings.Contains(l.path, "/blobs/") {
			t.Fatalf("blob fetched despite the size limit: %s", l.path)
		}
	}
	if out.Len() != 0 {
		t.Fatal("output written")
	}
	// Total limit and config limit are checked the same way.
	p = newTestPuller(t, f, func(o *Options) { o.Limits.TotalBytes = 2048 })
	if _, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("total: err = %v, want ErrTooLarge", err)
	}
	p = newTestPuller(t, f, func(o *Options) { o.Limits.ConfigBytes = 8 })
	if _, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("config: err = %v, want ErrTooLarge", err)
	}
}

func TestBlobLongerThanDescriptorIsRefused(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			var log []reqLog
			f := newFakeRegistry(t, registrymeta.AuthToken, &log)
			layer := []byte("declared-layer")
			img := f.addImage(t, layer)
			f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, sha(layer)) {
					return false
				}
				if chunked {
					_, _ = w.Write(layer)
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write(append(append([]byte{}, layer...), bytes.Repeat([]byte("+"), 1000)...))
				return true
			})
			p := newTestPuller(t, f, nil)
			var out bytes.Buffer
			_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
			if !errors.Is(err, ErrSizeMismatch) {
				t.Fatalf("err = %v, want ErrSizeMismatch", err)
			}
			assertNoArchive(t, out.Bytes())
		})
	}
}

func TestInterruptedBlobStreamFailsPull(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	layer := bytes.Repeat([]byte("z"), 50000)
	img := f.addImage(t, layer)
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, sha(layer)) {
			return false
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(layer)))
		_, _ = w.Write(layer[:len(layer)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // cut the connection mid-body
	})
	p := newTestPuller(t, f, nil)
	var out bytes.Buffer
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("err = %v, want ErrSizeMismatch", err)
	}
	assertClean(t, err)
	assertNoArchive(t, out.Bytes())
	if bytes.Contains(out.Bytes(), layer[:1000]) {
		t.Fatal("partial blob reached the output")
	}
}

func TestOutOfScopeRepositoryIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	p := newTestPuller(t, f, nil)
	req := request(img.indexDigest())
	req.Repository = "team/secret"
	_, err := p.Pull(context.Background(), testCred(), req, io.Discard)
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
	if len(log) != 0 {
		t.Fatalf("requests sent for an out-of-scope repository: %v", log)
	}
}

func TestRedirectToOtherRepositoryIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthBasic, &log)
	layer := []byte("layer")
	img := f.addImage(t, layer)
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/blobs/"+sha(layer)) && strings.HasPrefix(r.URL.Path, "/v2/team/app/") {
			http.Redirect(w, r, "/v2/team/unlisted/blobs/"+sha(layer), http.StatusTemporaryRedirect)
			return true
		}
		return false
	})
	p := newTestPuller(t, f, nil)
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard)
	if !errors.Is(err, ErrRequestNotAllowed) {
		t.Fatalf("err = %v, want ErrRequestNotAllowed", err)
	}
	for _, l := range log {
		if strings.Contains(l.path, "unlisted") {
			t.Fatal("redirect to an unapproved repository was followed")
		}
	}
}

func TestCrossHostRedirectIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	other := newFakeRegistry(t, registrymeta.AuthToken, &log)
	layer := []byte("layer")
	img := f.addImage(t, layer)
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, sha(layer)) {
			http.Redirect(w, r, other.srv.URL+"/blob?sig="+testSig, http.StatusTemporaryRedirect)
			return true
		}
		return false
	})
	p := newTestPuller(t, f, func(o *Options) { o.RootCAs = rootsFor(f.srv, other.srv) })
	var out bytes.Buffer
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("err = %v, want ErrRedirectNotAllowed", err)
	}
	assertClean(t, err)
	assertNoArchive(t, out.Bytes())
	for _, l := range log {
		if l.server == other.srv.URL {
			t.Fatal("request reached the unapproved host")
		}
	}
}

func TestManifestRedirectIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/manifests/") && !strings.Contains(r.URL.Path, img.manifestDigest()) {
			http.Redirect(w, r, "/v2/team/app/manifests/"+img.manifestDigest(), http.StatusTemporaryRedirect)
			return true
		}
		return false
	})
	p := newTestPuller(t, f, nil)
	if _, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("err = %v, want ErrRedirectNotAllowed", err)
	}
}

func TestApprovedBlobHostRedirectGetsNoAuthorization(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	layer := []byte("cdn-layer")
	img := f.addImage(t, layer)
	var cdnAuth []string
	cdnBody := layer
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnAuth = append(cdnAuth, r.Header.Get("Authorization"))
		if r.URL.Query().Get("sig") != testSig {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write(cdnBody)
	}))
	t.Cleanup(cdn.Close)
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, sha(layer)) {
			http.Redirect(w, r, cdn.URL+"/bucket/x?sig="+testSig, http.StatusTemporaryRedirect)
			return true
		}
		return false
	})
	p := newTestPuller(t, f, func(o *Options) {
		o.RootCAs = rootsFor(f.srv, cdn)
		o.BlobHosts = []string{cdn.URL}
	})
	var out bytes.Buffer
	if _, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(cdnAuth) != 1 || cdnAuth[0] != "" {
		t.Fatalf("blob host saw Authorization headers %q", cdnAuth)
	}
	// A corrupted blob from the blob host is refused and the signed URL
	// does not appear in the error.
	cdnBody = []byte("cdn-LAYER")
	out.Reset()
	_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), &out)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	assertClean(t, err)
	assertNoArchive(t, out.Bytes())
}

func TestAuthChallengeWithUnapprovedRealmSendsNoCredential(t *testing.T) {
	cases := map[string]func(f, evil *fakeRegistry){
		"foreign realm":   func(f, evil *fakeRegistry) { f.realm = evil.srv.URL + "/token" },
		"other path":      func(f, evil *fakeRegistry) { f.realm = f.srv.URL + "/token2" },
		"service changed": func(f, evil *fakeRegistry) { f.service = "evil" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var log []reqLog
			f := newFakeRegistry(t, registrymeta.AuthToken, &log)
			evil := newFakeRegistry(t, registrymeta.AuthToken, &log)
			img := f.addImage(t, []byte("l"))
			mut(f, evil)
			p := newTestPuller(t, f, func(o *Options) { o.RootCAs = rootsFor(f.srv, evil.srv) })
			_, err := p.Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard)
			if !errors.Is(err, ErrRealmNotApproved) {
				t.Fatalf("err = %v, want ErrRealmNotApproved", err)
			}
			for _, l := range log {
				if l.authz != "" || l.server == evil.srv.URL {
					t.Fatalf("credential or request sent after an unapproved challenge: %+v", l)
				}
			}
		})
	}
}

func TestRejectedCredentialIsReportedWithoutSecrets(t *testing.T) {
	t.Run("realm refuses", func(t *testing.T) {
		var log []reqLog
		f := newFakeRegistry(t, registrymeta.AuthToken, &log)
		f.tokenCode = http.StatusUnauthorized
		img := f.addImage(t, []byte("l"))
		_, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard)
		if !errors.Is(err, ErrCredentialRejected) {
			t.Fatalf("err = %v, want ErrCredentialRejected", err)
		}
		assertClean(t, err)
	})
	t.Run("registry refuses token", func(t *testing.T) {
		var log []reqLog
		f := newFakeRegistry(t, registrymeta.AuthToken, &log)
		f.alwaysNo = true
		img := f.addImage(t, []byte("l"))
		_, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard)
		if !errors.Is(err, ErrCredentialRejected) {
			t.Fatalf("err = %v, want ErrCredentialRejected", err)
		}
		assertClean(t, err)
		tokens := 0
		for _, l := range log {
			if l.path == "/token" {
				tokens++
			}
		}
		if tokens != 1 {
			t.Fatalf("token requests = %d, want 1", tokens)
		}
	})
	t.Run("basic refused", func(t *testing.T) {
		var log []reqLog
		f := newFakeRegistry(t, registrymeta.AuthBasic, &log)
		img := f.addImage(t, []byte("l"))
		cred := registrymeta.Credential{Username: testUser, Secret: []byte(testSecret + "x")}
		_, err := newTestPuller(t, f, nil).Pull(context.Background(), cred, request(img.indexDigest()), io.Discard)
		if !errors.Is(err, ErrCredentialRejected) {
			t.Fatalf("err = %v, want ErrCredentialRejected", err)
		}
		assertClean(t, err)
	})
	t.Run("malformed credential", func(t *testing.T) {
		var log []reqLog
		f := newFakeRegistry(t, registrymeta.AuthBasic, &log)
		cred := registrymeta.Credential{Username: "a:b", Secret: []byte(testSecret)}
		_, err := newTestPuller(t, f, nil).Pull(context.Background(), cred, request(sha([]byte("x"))), io.Discard)
		if !errors.Is(err, ErrCredentialRejected) || len(log) != 0 {
			t.Fatalf("err = %v, requests = %d", err, len(log))
		}
		assertClean(t, err)
	})
}

func TestExpiredTokenIsRefreshedOncePerRequest(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l1"), []byte("l2"))
	expired := false
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if !expired && strings.Contains(r.URL.Path, "/blobs/") {
			expired = true
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="%s"`, f.realm, testService))
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})
	if _, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	tokens := 0
	for _, l := range log {
		if l.path == "/token" {
			tokens++
		}
	}
	if tokens != 2 {
		t.Fatalf("token requests = %d, want 2", tokens)
	}
}

func TestPlatformMustMatchExactly(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	p := newTestPuller(t, f, nil)

	req := request(img.indexDigest())
	req.Platform = Platform{OS: "linux", Architecture: "s390x"}
	if _, err := p.Pull(context.Background(), testCred(), req, io.Discard); !errors.Is(err, ErrPlatform) {
		t.Fatalf("missing platform: err = %v", err)
	}
	// A single manifest whose config names another platform.
	req = request(img.manifestDigest())
	req.Platform = Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	if _, err := p.Pull(context.Background(), testCred(), req, io.Discard); !errors.Is(err, ErrPlatform) {
		t.Fatalf("config platform: err = %v", err)
	}
}

func TestIndexEntrySizeMismatchIsRefused(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	idx := mustJSON(t, map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []map[string]any{
		{"mediaType": mtOCIManifest, "digest": img.manifestDigest(), "size": len(img.manifest) - 1, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
	}})
	f.manifests[sha(idx)] = idx
	_, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(sha(idx)), io.Discard)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("err = %v, want ErrSizeMismatch", err)
	}
}

func TestUnsupportedManifestContentIsRefused(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"foreign layer": func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
		},
		"layer urls": func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["urls"] = []string{"https://elsewhere.example/x"}
		},
		"config type": func(m map[string]any) { m["config"].(map[string]any)["mediaType"] = "application/octet-stream" },
		"schema 1":    func(m map[string]any) { m["schemaVersion"] = 1 },
		"both kinds":  func(m map[string]any) { m["manifests"] = []any{m["config"]} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var log []reqLog
			f := newFakeRegistry(t, registrymeta.AuthToken, &log)
			img := f.addImage(t, []byte("l"))
			var m map[string]any
			if err := json.Unmarshal(img.manifest, &m); err != nil {
				t.Fatal(err)
			}
			mut(m)
			b := mustJSON(t, m)
			f.manifests[sha(b)] = b
			_, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(sha(b)), io.Discard)
			if !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrBadResponse) {
				t.Fatalf("err = %v, want ErrUnsupported or ErrBadResponse", err)
			}
			for _, l := range log {
				if strings.Contains(l.path, "/blobs/") {
					t.Fatal("blob fetched for a refused manifest")
				}
			}
		})
	}
}

func TestRateLimitIsReported(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	})
	if _, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(img.indexDigest()), io.Discard); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

func TestInvalidRequestIsRefusedBeforeNetwork(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	p := newTestPuller(t, f, nil)
	good := request(sha([]byte("x")))
	cases := map[string]func(r *Request){
		"tag digest":     func(r *Request) { r.Digest = "latest" },
		"uppercase hex":  func(r *Request) { r.Digest = strings.ToUpper(r.Digest) },
		"md5":            func(r *Request) { r.Digest = "md5:" + strings.Repeat("a", 32) },
		"bad tag":        func(r *Request) { r.Tag = "a b" },
		"empty tag":      func(r *Request) { r.Tag = "" },
		"no arch":        func(r *Request) { r.Platform.Architecture = "" },
		"bad variant":    func(r *Request) { r.Platform.Variant = "V8/../" },
		"repo traversal": func(r *Request) { r.Repository = "team/app/../other" },
	}
	for name, mut := range cases {
		r := good
		mut(&r)
		_, err := p.Pull(context.Background(), testCred(), r, io.Discard)
		if !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if len(log) != 0 {
		t.Fatalf("requests sent for invalid input: %d", len(log))
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	reg := registrymeta.PrivateRegistry{Registry: "https://reg.example", Mode: registrymeta.AuthBasic, Repositories: []string{testRepo}}
	cases := map[string]Options{
		"http blob host":    {Registry: reg, BlobHosts: []string{"http://cdn.example"}},
		"blob host path":    {Registry: reg, BlobHosts: []string{"https://cdn.example/bucket"}},
		"blob host user":    {Registry: reg, BlobHosts: []string{"https://u@cdn.example"}},
		"upper blob host":   {Registry: reg, BlobHosts: []string{"https://CDN.example"}},
		"registry as blob":  {Registry: reg, BlobHosts: []string{"https://reg.example"}},
		"duplicate host":    {Registry: reg, BlobHosts: []string{"https://cdn.example", "https://cdn.example"}},
		"limit above max":   {Registry: reg, Limits: Limits{ManifestBytes: MaxManifestBytes + 1}},
		"negative limit":    {Registry: reg, Limits: Limits{Layers: -1}},
		"negative timeout":  {Registry: reg, BlobTimeout: -1},
		"no repositories":   {Registry: registrymeta.PrivateRegistry{Registry: "https://reg.example", Mode: registrymeta.AuthBasic}},
		"http registry":     {Registry: registrymeta.PrivateRegistry{Registry: "http://reg.example", Mode: registrymeta.AuthBasic, Repositories: []string{testRepo}}},
		"upper registry":    {Registry: registrymeta.PrivateRegistry{Registry: "https://Reg.example", Mode: registrymeta.AuthBasic, Repositories: []string{testRepo}}},
		"realm as blobhost": {Registry: registrymeta.PrivateRegistry{Registry: "https://reg.example", Mode: registrymeta.AuthToken, Realm: "https://auth.example/token", Repositories: []string{testRepo}}, BlobHosts: []string{"https://auth.example"}},
	}
	for name, o := range cases {
		if _, err := New(o); err == nil {
			t.Fatalf("%s: New accepted invalid options", name)
		}
	}
	many := make([]string, MaxBlobHosts+1)
	for i := range many {
		many[i] = fmt.Sprintf("https://cdn%d.example", i)
	}
	if _, err := New(Options{Registry: reg, BlobHosts: many}); err == nil {
		t.Fatal("New accepted too many blob hosts")
	}
}

func TestTransportAllowlist(t *testing.T) {
	p, err := New(Options{
		Registry: registrymeta.PrivateRegistry{Registry: "https://reg.example", Mode: registrymeta.AuthToken,
			Realm: "https://auth.example/token", Service: "reg", Repositories: []string{testRepo}},
		BlobHosts: []string{"https://cdn.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := sha([]byte("x"))
	cases := []struct {
		method, url, authz string
		ok                 bool
	}{
		{"GET", "https://reg.example/v2/team/app/blobs/" + d, "Bearer t", true},
		{"GET", "https://reg.example/v2/team/app/manifests/" + d, "", true},
		{"GET", "https://reg.example/v2/team/app/manifests/latest", "Bearer t", false},
		{"GET", "https://reg.example/v2/team/app/blobs/" + d, "Basic x", false},
		{"GET", "https://reg.example/v2/team/app/blobs/" + d + "?x=1", "Bearer t", false},
		{"GET", "https://reg.example/v2/team/other/blobs/" + d, "Bearer t", false},
		{"GET", "https://reg.example/v2/team/app/tags/list", "Bearer t", false},
		{"HEAD", "https://reg.example/v2/team/app/blobs/" + d, "Bearer t", false},
		{"PUT", "https://reg.example/v2/team/app/blobs/" + d, "Bearer t", false},
		{"GET", "http://reg.example/v2/team/app/blobs/" + d, "", false},
		{"GET", "https://auth.example/token?scope=x", "Basic x", true},
		{"GET", "https://auth.example/token", "Bearer t", false},
		{"GET", "https://auth.example/other", "Basic x", false},
		{"GET", "https://cdn.example/any/path?sig=1", "", true},
		{"GET", "https://cdn.example/any/path", "Bearer t", false},
		{"GET", "https://cdn.example/any/path", "Basic x", false},
		{"GET", "https://evil.example/v2/team/app/blobs/" + d, "", false},
	}
	for _, c := range cases {
		req, err := http.NewRequest(c.method, c.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.authz != "" {
			req.Header.Set("Authorization", c.authz)
		}
		err = p.allowRequest(req)
		if (err == nil) != c.ok {
			t.Fatalf("%s %s (%q): err = %v, want ok=%v", c.method, c.url, c.authz, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrRequestNotAllowed) {
			t.Fatalf("%s %s: err = %v, want ErrRequestNotAllowed", c.method, c.url, err)
		}
	}
}

// failWriter fails after n bytes.
type failWriter struct{ n int }

func (w *failWriter) Write(b []byte) (int, error) {
	if len(b) > w.n {
		return 0, errors.New("sink closed")
	}
	w.n -= len(b)
	return len(b), nil
}

func TestOutputWriteFailureStopsPull(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, bytes.Repeat([]byte("q"), 10000), []byte("second"))
	_, err := newTestPuller(t, f, nil).Pull(context.Background(), testCred(), request(img.indexDigest()), &failWriter{n: 2048})
	if err == nil || !strings.Contains(err.Error(), "sink closed") {
		t.Fatalf("err = %v, want write failure", err)
	}
	for _, l := range log {
		if strings.HasSuffix(l.path, sha([]byte("second"))) {
			t.Fatal("pull continued after the output failed")
		}
	}
}

func TestCanceledContextStopsPull(t *testing.T) {
	var log []reqLog
	f := newFakeRegistry(t, registrymeta.AuthToken, &log)
	img := f.addImage(t, []byte("l"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if _, err := newTestPuller(t, f, nil).Pull(ctx, testCred(), request(img.indexDigest()), &out); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Fatal("output written")
	}
}
