// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrypull"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The private transfer tests (cu06 part 3) run the executor against a fake
// TLS registry that serves one real, verifiable image and a fake SSH target
// that emulates `docker info`, `docker load` and `docker image inspect`
// for the classic and the containerd image store.

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// testImage is one image the fake registry serves.
type testImage struct {
	layer, config, manifest []byte
	manifestDigest          string
}

func newTestImage(t *testing.T) testImage {
	t.Helper()
	return newTestImageWith(t, "layer-bytes-of-the-approved-image")
}

// newTestImageWith builds an image whose one layer repeats seed to 256 KiB,
// larger than the stream's hold-back, so a transfer streams before it ends.
func newTestImageWith(t *testing.T, seed string) testImage {
	t.Helper()
	layer := []byte(strings.Repeat(seed, (256<<10)/len(seed)+1))
	config, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{sha([]byte("diff"))}}})
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": sha(config), "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": sha(layer), "size": len(layer)}}})
	return testImage{layer: layer, config: config, manifest: man, manifestDigest: sha(man)}
}

// pullRegistry is a basic-auth TLS registry serving one image of team/app.
type pullRegistry struct {
	srv *httptest.Server
	img testImage

	mu         sync.Mutex
	reqs       []string
	headers    []http.Header
	tagDigest  string // what a tag HEAD answers; default the manifest digest
	corruptBlb bool   // serve a layer that does not match its digest
	onBlob     func()
}

func newPullRegistry(t *testing.T) *pullRegistry {
	t.Helper()
	r := &pullRegistry{img: newTestImage(t)}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *pullRegistry) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req.Method+" "+req.URL.Path)
	r.headers = append(r.headers, req.Header.Clone())
	tagDigest, corrupt, onBlob := r.tagDigest, r.corruptBlb, r.onBlob
	r.mu.Unlock()
	if req.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(regUser+":"+regSecret)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if tagDigest == "" {
		tagDigest = r.img.manifestDigest
	}
	const mt = "application/vnd.docker.distribution.manifest.v2+json"
	p := req.URL.Path
	switch {
	case req.Method == http.MethodHead && strings.HasPrefix(p, "/v2/team/app/manifests/"):
		w.Header().Set("Docker-Content-Digest", tagDigest)
		w.Header().Set("Content-Type", mt)
	case req.Method == http.MethodGet && p == "/v2/team/app/manifests/"+r.img.manifestDigest:
		w.Header().Set("Content-Type", mt)
		_, _ = w.Write(r.img.manifest)
	case req.Method == http.MethodGet && p == "/v2/team/app/blobs/"+sha(r.img.config):
		_, _ = w.Write(r.img.config)
	case req.Method == http.MethodGet && p == "/v2/team/app/blobs/"+sha(r.img.layer):
		if onBlob != nil {
			onBlob()
		}
		b := r.img.layer
		if corrupt {
			b = []byte(strings.Repeat("x", len(b)))
		}
		_, _ = w.Write(b)
	default:
		http.NotFound(w, req)
	}
}

func (r *pullRegistry) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reqs...)
}

func (r *pullRegistry) blobRequests() int {
	n := 0
	for _, q := range r.requests() {
		if strings.Contains(q, "/blobs/") {
			n++
		}
	}
	return n
}

// Import behaviours of the emulated containerd store.
const (
	// importFaithful imports like containerd: an OCI layout by its
	// index.json, else a docker-archive under a generated manifest.
	importFaithful = ""
	// importDockerArchiveOnly ignores oci-layout and index.json, as an
	// engine that reads only manifest.json would.
	importDockerArchiveOnly = "docker-archive-only"
	// importRewriteManifest re-encodes the manifest on import.
	importRewriteManifest = "rewrite-manifest"
)

// fakeTarget is an SSH target emulating the Docker CLI of one image store.
// Everything `docker image inspect` reports is derived from the archive
// `docker load` received, never from the digest the test expects.
type fakeTarget struct {
	store string // imageStoreClassic or imageStoreContainerd
	// importMode changes the containerd import (importFaithful default).
	importMode string
	// loadFails makes `docker load` exit 1 after reading all of stdin.
	loadFails bool
	// loadExitsEarly makes `docker load` exit 1 after the first bytes,
	// without reading the rest of stdin.
	loadExitsEarly bool

	mu       sync.Mutex
	commands []string
	envReqs  []string
	stdin    [][]byte
	// images: reference -> inspect JSON after a load.
	images map[string]inspectedImage
}

func (f *fakeTarget) record(cmd string) {
	f.mu.Lock()
	f.commands = append(f.commands, cmd)
	f.mu.Unlock()
}

func (f *fakeTarget) cmds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// run executes one exec request and returns its exit status.
func (f *fakeTarget) run(cmd string, stdin io.Reader, stdout io.Writer) uint32 {
	f.record(cmd)
	switch {
	case cmd == "docker info --format '{{json .DriverStatus}}'":
		if f.store == imageStoreContainerd {
			_, _ = io.WriteString(stdout, `[["driver-type","io.containerd.snapshotter.v1"]]`+"\n")
		} else {
			_, _ = io.WriteString(stdout, `[["Backing Filesystem","extfs"],["Supports d_type","true"]]`+"\n")
		}
		return 0
	case cmd == "docker load -q" && f.loadExitsEarly:
		buf := make([]byte, 512)
		_, _ = io.ReadFull(stdin, buf)
		return 1
	case cmd == "docker load -q":
		raw, _ := io.ReadAll(stdin)
		f.mu.Lock()
		f.stdin = append(f.stdin, raw)
		f.mu.Unlock()
		if f.loadFails {
			return 1
		}
		return f.load(raw)
	case strings.HasPrefix(cmd, wantInspectPrefix):
		ref := strings.TrimSuffix(strings.TrimPrefix(cmd, wantInspectPrefix), "'")
		f.mu.Lock()
		img, ok := f.images[ref]
		f.mu.Unlock()
		if !ok {
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(img)
		return 0
	}
	return 127
}

// wantInspectPrefix is the evidence inspect command up to the reference:
// a narrow template, never '{{json .}}'.
const wantInspectPrefix = `docker image inspect --format '{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},` +
	`"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Variant":{{json .Variant}}}' -- '`

// imageConfig is the part of an image configuration the store reports.
type imageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

// readTarFiles reads every regular file of a tar stream the way
// containerd's importer does: entries until the end of the stream (a
// missing trailer is not an error, a broken entry is).
func readTarFiles(raw []byte) (map[string][]byte, bool) {
	tr := tar.NewReader(strings.NewReader(string(raw)))
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, true
		}
		if err != nil {
			return nil, false
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, false
		}
		files[h.Name] = b
	}
}

// blobOf returns the archive blob of digest d after checking its bytes
// against d, as a content store does on ingest.
func blobOf(files map[string][]byte, d string, size int64) ([]byte, bool) {
	hexPart, ok := strings.CutPrefix(d, "sha256:")
	if !ok {
		return nil, false
	}
	b, ok := files["blobs/sha256/"+hexPart]
	if !ok || sha(b) != d || (size >= 0 && int64(len(b)) != size) {
		return nil, false
	}
	return b, true
}

// imageFromManifest checks that every blob of manifest body is in the
// archive and returns the platform of its configuration.
func imageFromManifest(files map[string][]byte, body []byte) (imageConfig, bool) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"layers"`
	}
	if json.Unmarshal(body, &m) != nil {
		return imageConfig{}, false
	}
	for _, l := range m.Layers {
		if _, ok := blobOf(files, l.Digest, l.Size); !ok {
			return imageConfig{}, false
		}
	}
	cfgBytes, ok := blobOf(files, m.Config.Digest, m.Config.Size)
	var cfg imageConfig
	if !ok || json.Unmarshal(cfgBytes, &cfg) != nil {
		return imageConfig{}, false
	}
	return cfg, true
}

// load emulates `docker load` of the received bytes in the target's store.
func (f *fakeTarget) load(raw []byte) uint32 {
	files, ok := readTarFiles(raw)
	if !ok {
		return 1
	}
	var loaded []inspectedImage
	switch f.store {
	case imageStoreClassic:
		loaded, ok = loadDockerArchiveClassic(files)
	case imageStoreContainerd:
		loaded, ok = f.loadContainerd(files)
	}
	if !ok {
		return 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.images == nil {
		f.images = map[string]inspectedImage{}
	}
	for _, img := range loaded {
		for _, ref := range append(append([]string(nil), img.RepoTags...), img.RepoDigests...) {
			f.images[ref] = img
		}
	}
	return 0
}

// dockerArchiveManifest is one manifest.json entry.
type dockerArchiveManifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// loadDockerArchiveClassic is the classic store: manifest.json names the
// config and layers; the Id is the configuration digest and no repository
// digest is recorded.
func loadDockerArchiveClassic(files map[string][]byte) ([]inspectedImage, bool) {
	var man []dockerArchiveManifest
	if json.Unmarshal(files["manifest.json"], &man) != nil || len(man) == 0 {
		return nil, false
	}
	var out []inspectedImage
	for _, m := range man {
		cfgBytes, ok := files[m.Config]
		var cfg imageConfig
		if !ok || json.Unmarshal(cfgBytes, &cfg) != nil {
			return nil, false
		}
		for _, l := range m.Layers {
			if _, ok := files[l]; !ok {
				return nil, false
			}
		}
		out = append(out, inspectedImage{ID: sha(cfgBytes), RepoTags: m.RepoTags, OS: cfg.OS, Architecture: cfg.Architecture,
			Variant: cfg.Variant})
	}
	return out, true
}

// loadContainerd is the containerd store. With oci-layout the image
// targets are index.json's descriptors (the manifest bytes in the archive,
// digest-checked); without it a manifest is generated from manifest.json,
// as containerd's importer does for a docker-archive. The Id is the target
// digest and every image name gets a repository digest of that target.
func (f *fakeTarget) loadContainerd(files map[string][]byte) ([]inspectedImage, bool) {
	type target struct {
		name   string
		digest string
		body   []byte
	}
	var targets []target
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	useOCI := f.importMode != importDockerArchiveOnly && files["oci-layout"] != nil
	if useOCI {
		if json.Unmarshal(files["oci-layout"], &layout) != nil || layout.Version != "1.0.0" {
			return nil, false
		}
		var idx struct {
			Manifests []struct {
				Digest      string            `json:"digest"`
				Size        int64             `json:"size"`
				Annotations map[string]string `json:"annotations"`
			} `json:"manifests"`
		}
		if json.Unmarshal(files["index.json"], &idx) != nil || len(idx.Manifests) == 0 {
			return nil, false
		}
		for _, d := range idx.Manifests {
			body, ok := blobOf(files, d.Digest, d.Size)
			if !ok {
				return nil, false
			}
			targets = append(targets, target{name: d.Annotations["io.containerd.image.name"], digest: d.Digest, body: body})
		}
	} else {
		var man []dockerArchiveManifest
		if json.Unmarshal(files["manifest.json"], &man) != nil || len(man) == 0 {
			return nil, false
		}
		for _, m := range man {
			cfgBytes := files[m.Config]
			gen := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": sha(cfgBytes), "size": len(cfgBytes)}}
			var layers []any
			for _, l := range m.Layers {
				b := files[l]
				layers = append(layers, map[string]any{"mediaType": "application/vnd.docker.image.rootfs.diff.tar", "digest": sha(b), "size": len(b)})
			}
			gen["layers"] = layers
			body, _ := json.Marshal(gen)
			for _, name := range m.RepoTags {
				targets = append(targets, target{name: name, digest: sha(body), body: body})
			}
		}
	}
	var out []inspectedImage
	for _, t := range targets {
		if f.importMode == importRewriteManifest {
			var v any
			_ = json.Unmarshal(t.body, &v)
			t.body, _ = json.MarshalIndent(v, "", " ")
			t.digest = sha(t.body)
		}
		// The manifest's own blobs must be there, digest-checked; for a
		// generated manifest they were addressed by path.
		var cfg imageConfig
		if useOCI {
			c, ok := imageFromManifest(files, t.body)
			if !ok {
				return nil, false
			}
			cfg = c
		} else {
			var m struct {
				Config struct{ Digest string } `json:"config"`
			}
			_ = json.Unmarshal(t.body, &m)
			hexPart := strings.TrimPrefix(m.Config.Digest, "sha256:")
			if json.Unmarshal(files["blobs/sha256/"+hexPart], &cfg) != nil {
				return nil, false
			}
		}
		img := inspectedImage{ID: t.digest, OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
		if i := strings.LastIndex(t.name, ":"); t.name != "" && i > strings.LastIndex(t.name, "/") {
			img.RepoTags = []string{t.name}
			img.RepoDigests = []string{t.name[:i] + "@" + t.digest}
		}
		out = append(out, img)
	}
	return out, true
}

// serve starts the fake target and returns a client connected to it.
func (f *fakeTarget) serve(t *testing.T) *ssh.Client {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSigner, _ := ssh.NewSignerFromKey(userPriv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(userSigner.PublicKey().Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handleConn(nc, cfg)
		}
	}()
	c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "nos", Auth: []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func (f *fakeTarget) handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, in, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range in {
				switch req.Type {
				case "env":
					f.mu.Lock()
					f.envReqs = append(f.envReqs, string(req.Payload))
					f.mu.Unlock()
					_ = req.Reply(false, nil)
				case "exec":
					var p struct{ Cmd string }
					_ = ssh.Unmarshal(req.Payload, &p)
					_ = req.Reply(true, nil)
					code := f.run(p.Cmd, ch, ch)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

type transferEnv struct {
	*registryEnv
	pull   *pullRegistry
	target *fakeTarget
	client *ssh.Client
	info   *pb.PrivateRegistryInfo
}

func newTransferEnv(t *testing.T, store string) *transferEnv {
	t.Helper()
	e := newRegistryEnv(t)
	pr := newPullRegistry(t)
	req := e.addRequest()
	req.RegistryOrigin, req.CaPem = pr.srv.URL, string(pemOf(pr.srv.Certificate()))
	resp, err := e.svc.AddPrivateRegistry(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetPrivateTransferTempDir(t.TempDir())
	tg := &fakeTarget{store: store}
	return &transferEnv{registryEnv: e, pull: pr, target: tg, client: tg.serve(t), info: resp.GetRegistry()}
}

func (e *transferEnv) repository() string {
	return strings.TrimPrefix(e.pull.srv.URL, "https://") + "/team/app"
}

func (e *transferEnv) binding() canonical.BatchContainerUpdate {
	return canonical.BatchContainerUpdate{Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormCompose,
		Images: []canonical.ContainerUpdateImage{{Service: "app", Repository: e.repository(), Platform: "linux/amd64",
			OldTag: "1.0.0", NewTag: "1.1.0", OldDigests: []string{regDigest}, NewPlatformDigest: e.pull.img.manifestDigest,
			OldImageID: regDigest}},
		Registry: &canonical.ContainerUpdateRegistry{RegistryID: "corp", RecordDigest: e.info.GetConfigDigest(),
			CredentialID: e.info.GetCredentialId(), CredentialVersion: uint64(e.info.GetCredentialVersion())}}
}

func (e *transferEnv) transfer(u canonical.BatchContainerUpdate) ([]TransferredImage, error) {
	return e.svc.transferPrivateImages(context.Background(), e.client, u)
}

// assertNoCredentialOnTarget checks commands, env requests, stdin, the
// result and the logs for every form of the credential.
func (e *transferEnv) assertNoCredentialOnTarget(t *testing.T, result any) {
	t.Helper()
	forms := []string{regSecret, base64.StdEncoding.EncodeToString([]byte(regUser + ":" + regSecret)), "Authorization", "X-Registry-Auth"}
	e.target.mu.Lock()
	defer e.target.mu.Unlock()
	if len(e.target.envReqs) != 0 {
		t.Fatalf("the target got environment variables: %q", e.target.envReqs)
	}
	for _, c := range e.target.commands {
		for _, bad := range append(forms, regUser, "login", "DOCKER_CONFIG", "pull") {
			if strings.Contains(c, bad) {
				t.Fatalf("command %q holds %q", c, bad)
			}
		}
	}
	for _, in := range e.target.stdin {
		for _, bad := range append(forms, regUser) {
			if strings.Contains(string(in), bad) {
				t.Fatalf("docker load stdin holds %q", bad)
			}
		}
	}
	txt := fmt.Sprintf("%+v", result) + allLogText(e.logs)
	for _, bad := range forms[:2] {
		if strings.Contains(txt, bad) {
			t.Fatalf("result or log holds the credential")
		}
	}
}

func TestPrivateTransferContainerdLoadsImageBytesOnly(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	out, err := e.transfer(e.binding())
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if len(out) != 1 || out[0].ImageID != e.pull.img.manifestDigest || out[0].Store != imageStoreContainerd ||
		out[0].PlatformDigest != e.pull.img.manifestDigest {
		t.Fatalf("evidence: %+v", out)
	}
	want := []string{"docker info --format '{{json .DriverStatus}}'", "docker load -q",
		wantInspectPrefix + e.repository() + "@" + e.pull.img.manifestDigest + "'"}
	if got := e.target.cmds(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("target commands:\n got %q\nwant %q", got, want)
	}
	e.assertNoCredentialOnTarget(t, out)
	// The archive records the transfer tag, never the operator's tag.
	if !strings.Contains(string(e.target.stdin[0]), e.repository()+":"+transferTagPrefix) ||
		strings.Contains(string(e.target.stdin[0]), e.repository()+":1.1.0") {
		t.Fatal("the archive does not record the transfer tag")
	}
	// Phase 2 used one read-grant claim for the new tag.
	if len(e.grants.reads) != 1 || e.grants.reads[0].Reference != "1.1.0" || e.grants.reads[0].Method != RegistryMethodTagDigest {
		t.Fatalf("resolve reads: %+v", e.grants.reads)
	}
	// Every registry request came from the executor with its credential;
	// none carried a registry auth header meant for an engine.
	for _, h := range e.pull.headers {
		if h.Get("X-Registry-Auth") != "" {
			t.Fatal("X-Registry-Auth was sent")
		}
	}
}

func TestPrivateTransferClassicStoreRefusedBeforeAnyBlob(t *testing.T) {
	e := newTransferEnv(t, imageStoreClassic)
	_, err := e.transfer(e.binding())
	if !errors.Is(err, errTransferStore) || !strings.Contains(err.Error(), "--pull never") {
		t.Fatalf("classic store: %v", err)
	}
	if n := e.pull.blobRequests(); n != 0 {
		t.Fatalf("%d blob requests for an unavailable store", n)
	}
	for _, c := range e.target.cmds() {
		if strings.Contains(c, "load") {
			t.Fatal("docker load ran on an unavailable store")
		}
	}
	e.assertNoCredentialOnTarget(t, err)
}

// The classic evidence is defined and checked even though it cannot serve
// the host job: the loaded Id must be the verified configuration digest.
func TestClassicStoreEvidenceIsTheConfigDigest(t *testing.T) {
	e := newTransferEnv(t, imageStoreClassic)
	img := transferImage{repository: e.repository(), platformDigest: e.pull.img.manifestDigest,
		platform: registrypull.Platform{OS: "linux", Architecture: "amd64"}}
	ev := imageStoreEvidence[imageStoreClassic]
	if ev.available {
		t.Fatal("the classic store must stay unavailable")
	}
	// Load the real archive through the classic emulation.
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.wipe()
	pl, err := registrypull.New(registrypull.Options{Registry: l.rec.meta(), RootCAs: l.roots, AllowLoopback: true, TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	res, err := pl.Pull(context.Background(), registrymeta.Credential{Username: l.cred.Username, Secret: l.cred.Secret}, registrypull.Request{Repository: "team/app", Digest: img.platformDigest,
		Tag: img.transferTag(), Platform: img.platform}, &sb)
	if err != nil {
		t.Fatal(err)
	}
	if code := e.target.load([]byte(sb.String())); code != 0 {
		t.Fatal("classic load failed")
	}
	got := e.target.images[ev.ref(img)]
	if err := ev.verify(img, res, got); err != nil || got.ID != sha(e.pull.img.config) {
		t.Fatalf("classic evidence: %+v, %v", got, err)
	}
	if len(got.RepoDigests) != 0 {
		t.Fatal("a classic load must not show a repository digest")
	}
	got.ID = regDigest
	if !errors.Is(ev.verify(img, res, got), errTransferEvidence) {
		t.Fatal("a wrong classic Id passed")
	}
}

// A store that does not keep the registry manifest (it imports only
// manifest.json, or re-encodes the manifest) shows another Id and no
// repository@platform-digest: the evidence fails.
func TestPrivateTransferWrongDigestAfterLoadStops(t *testing.T) {
	for _, mode := range []string{importDockerArchiveOnly, importRewriteManifest} {
		t.Run(mode, func(t *testing.T) {
			e := newTransferEnv(t, imageStoreContainerd)
			e.target.importMode = mode
			_, err := e.transfer(e.binding())
			if !errors.Is(err, errTransferEvidence) {
				t.Fatalf("wrong digest after load: %v", err)
			}
			e.target.mu.Lock()
			_, found := e.target.images[e.repository()+"@"+e.pull.img.manifestDigest]
			e.target.mu.Unlock()
			if found {
				t.Fatal("the emulated store kept the registry digest despite the rewrite")
			}
			e.assertNoCredentialOnTarget(t, err)
		})
	}
}

// ociArchive builds a valid OCI layout archive of img named name.
func ociArchive(t *testing.T, img testImage, name string) []byte {
	t.Helper()
	var sb strings.Builder
	tw := tar.NewWriter(&sb)
	put := func(n string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Size: int64(len(b)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range [][]byte{img.layer, img.config, img.manifest} {
		put("blobs/sha256/"+strings.TrimPrefix(sha(b), "sha256:"), b)
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{
		"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": img.manifestDigest, "size": len(img.manifest),
		"annotations": map[string]string{"io.containerd.image.name": name}}}})
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	put("index.json", idx)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return []byte(sb.String())
}

// The containerd evidence is what the store derives from the archive
// registrypull streams: the real archive passes; a valid archive of
// another image under the same name, a docker-archive and a re-encoded
// manifest do not.
func TestContainerdEvidenceComesFromTheStreamedArchive(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	img := transferImage{repository: e.repository(), platformDigest: e.pull.img.manifestDigest,
		platform: registrypull.Platform{OS: "linux", Architecture: "amd64"}}
	ev := imageStoreEvidence[imageStoreContainerd]
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.wipe()
	pl, err := registrypull.New(registrypull.Options{Registry: l.rec.meta(), RootCAs: l.roots, AllowLoopback: true, TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	res, err := pl.Pull(context.Background(), registrymeta.Credential{Username: l.cred.Username, Secret: l.cred.Secret},
		registrypull.Request{Repository: "team/app", Digest: img.platformDigest, Tag: img.transferTag(), Platform: img.platform}, &sb)
	if err != nil {
		t.Fatal(err)
	}
	streamed := []byte(sb.String())
	name := img.repository + ":" + img.transferTag()
	other := newTestImageWith(t, "a-different-image")
	for _, c := range []struct {
		name    string
		mode    string
		archive []byte
		ok      bool
	}{
		{"streamed archive", importFaithful, streamed, true},
		{"streamed archive, docker-archive import", importDockerArchiveOnly, streamed, false},
		{"streamed archive, manifest re-encoded", importRewriteManifest, streamed, false},
		{"another image under the transfer tag", importFaithful, ociArchive(t, other, name), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := &fakeTarget{store: imageStoreContainerd, importMode: c.mode}
			if code := tg.load(c.archive); code != 0 {
				t.Fatal("containerd load failed")
			}
			got := tg.images[ev.ref(img)]
			err := ev.verify(img, res, got)
			if c.ok && (err != nil || got.ID != e.pull.img.manifestDigest) {
				t.Fatalf("evidence of the streamed archive: %+v, %v", got, err)
			}
			if !c.ok && !errors.Is(err, errTransferEvidence) {
				t.Fatalf("evidence passed for %s: %+v", c.name, got)
			}
			// Phase 5 resolves repository:tag@digest by the digest; it is
			// found exactly when the evidence passes.
			if _, found := tg.images[img.repository+"@"+img.platformDigest]; found != c.ok {
				t.Fatalf("repository@digest found = %v", found)
			}
		})
	}
}

// A lock after the last archive byte left registrypull but before the
// stream is closed still stops the member, and `docker load` never gets
// the entries that complete the archive.
func TestPrivateTransferLockBeforeCloseStops(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	e.svc.transfer.hooks.beforeClose = func() {
		e.svc.vault.Lock()
		_ = e.svc.vault.Unlock(pass)
	}
	_, err := e.transfer(e.binding())
	if !errors.Is(err, errTransferLocked) {
		t.Fatalf("lock before close: %v", err)
	}
	e.target.mu.Lock()
	defer e.target.mu.Unlock()
	if len(e.target.stdin) != 1 {
		t.Fatalf("docker load ran %d times", len(e.target.stdin))
	}
	for _, entry := range []string{"manifest.json", "index.json", "oci-layout"} {
		if strings.Contains(string(e.target.stdin[0]), entry) {
			t.Fatalf("docker load got %s across a lock", entry)
		}
	}
	if len(e.target.images) != 0 {
		t.Fatal("an image was loaded across a lock")
	}
	for _, c := range e.target.commands {
		if strings.Contains(c, "inspect") {
			t.Fatal("a transfer across a lock was verified")
		}
	}
}

// `docker load` exiting before the archive ended is a load failure, not a
// registry failure.
func TestPrivateTransferEarlyLoadExitIsALoadFailure(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	e.target.loadExitsEarly = true
	_, err := e.transfer(e.binding())
	if !errors.Is(err, errTransferLoad) || errors.Is(err, errTransferPull) {
		t.Fatalf("early load exit: %v", err)
	}
	for _, c := range e.target.cmds() {
		if strings.Contains(c, "inspect") {
			t.Fatal("a failed load was verified")
		}
	}
}

func TestPrivateTransferLockMidStreamStops(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	var once sync.Once
	e.svc.transfer.hooks.duringStream = func() {
		once.Do(func() {
			e.svc.vault.Lock()
			_ = e.svc.vault.Unlock(pass)
		})
	}
	_, err := e.transfer(e.binding())
	if !errors.Is(err, errTransferLocked) {
		t.Fatalf("lock during transfer: %v", err)
	}
	// The stream was cut: docker load never saw manifest.json and nothing
	// was inspected.
	if len(e.target.stdin) != 1 || strings.Contains(string(e.target.stdin[0]), "manifest.json") ||
		strings.Contains(string(e.target.stdin[0]), "index.json") || len(e.target.images) != 0 {
		t.Fatal("the archive was completed across a lock")
	}
	for _, c := range e.target.cmds() {
		if strings.Contains(c, "inspect") {
			t.Fatal("a transfer across a lock was verified")
		}
	}
	e.assertNoCredentialOnTarget(t, err)
}

func TestPrivateTransferRecheckStopsOnChange(t *testing.T) {
	rotate := func(e *transferEnv) {
		_, _ = e.svc.RotatePrivateRegistryCredential(context.Background(), &pb.RotatePrivateRegistryCredentialRequest{
			RegistryId: "corp", Username: regUser, Secret: []byte(regSecret), CredentialExpiresUnix: e.clock.Now().Add(24 * time.Hour).Unix()})
	}
	for _, c := range []struct {
		name  string
		setup func(e *transferEnv)
		want  error
	}{
		{"rotation after resolve", func(e *transferEnv) { e.svc.transfer.hooks.afterResolve = func() { rotate(e) } }, errTransferBinding},
		{"rotation mid stream", func(e *transferEnv) { e.pull.onBlob = func() { rotate(e) } }, errTransferBinding},
		{"expiry after resolve", func(e *transferEnv) { e.svc.transfer.hooks.afterResolve = func() { e.clock.Add(31 * 24 * time.Hour) } }, errTransferExpired},
		{"grant revoked mid stream", func(e *transferEnv) {
			e.pull.onBlob = func() { e.grants.mu.Lock(); e.grants.revoked = true; e.grants.mu.Unlock() }
		}, errTransferGrant},
		{"removed after resolve", func(e *transferEnv) {
			e.svc.transfer.hooks.afterResolve = func() {
				_, _ = e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"})
			}
		}, errTransferBinding},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTransferEnv(t, imageStoreContainerd)
			c.setup(e)
			_, err := e.transfer(e.binding())
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			for _, cmd := range e.target.cmds() {
				if strings.Contains(cmd, "inspect") {
					t.Fatal("a changed transfer was verified")
				}
			}
			e.assertNoCredentialOnTarget(t, err)
		})
	}
}

func TestPrivateTransferRefusesBeforeTheRegistry(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(e *transferEnv, u *canonical.BatchContainerUpdate)
		want   error
	}{
		{"credential version", func(_ *transferEnv, u *canonical.BatchContainerUpdate) { u.Registry.CredentialVersion = 2 }, errTransferBinding},
		{"credential id", func(_ *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Registry.CredentialID = strings.Repeat("0", 32)
		}, errTransferBinding},
		{"record digest", func(_ *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Registry.RecordDigest = strings.Repeat("0", 64)
		}, errTransferBinding},
		{"unknown registry", func(_ *transferEnv, u *canonical.BatchContainerUpdate) { u.Registry.RegistryID = "other" }, errTransferBinding},
		{"no registry", func(_ *transferEnv, u *canonical.BatchContainerUpdate) { u.Registry = nil }, errTransferScope},
		{"rollback", func(_ *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Kind = canonical.ContainerUpdateKindRollback
		}, errTransferScope},
		{"out of scope repository", func(e *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Images[0].Repository = strings.TrimPrefix(e.pull.srv.URL, "https://") + "/team/other"
		}, errTransferScope},
		{"other registry host", func(_ *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Images[0].Repository = "registry.example.com/team/app"
		}, errTransferScope},
		{"quote in repository", func(e *transferEnv, u *canonical.BatchContainerUpdate) {
			u.Images[0].Repository = strings.TrimPrefix(e.pull.srv.URL, "https://") + "/team/app'"
		}, errTransferScope},
		{"locked", func(e *transferEnv, _ *canonical.BatchContainerUpdate) { e.svc.vault.Lock() }, errTransferLocked},
		{"expired", func(e *transferEnv, _ *canonical.BatchContainerUpdate) { e.clock.Add(31 * 24 * time.Hour) }, errTransferExpired},
		{"no grant", func(e *transferEnv, _ *canonical.BatchContainerUpdate) { e.grants.revoked = true }, errTransferGrant},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTransferEnv(t, imageStoreContainerd)
			u := e.binding()
			c.mutate(e, &u)
			_, err := e.transfer(u)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if n := len(e.pull.requests()); n != 0 {
				t.Fatalf("%d registry requests", n)
			}
			if n := len(e.target.cmds()); n != 0 {
				t.Fatalf("%d target commands", n)
			}
		})
	}
}

func TestPrivateTransferTagMovedStops(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	e.pull.tagDigest = regDigest
	if _, err := e.transfer(e.binding()); !errors.Is(err, errTransferTagMoved) {
		t.Fatalf("tag moved: %v", err)
	}
	if n := e.pull.blobRequests(); n != 0 || len(e.target.cmds()) != 0 {
		t.Fatal("a moved tag was transferred")
	}
}

func TestPrivateTransferWrongBlobNeverCompletesTheArchive(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	e.pull.corruptBlb = true
	_, err := e.transfer(e.binding())
	if !errors.Is(err, errTransferPull) || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("wrong blob: %v", err)
	}
	if len(e.target.stdin) != 1 || strings.Contains(string(e.target.stdin[0]), "manifest.json") ||
		strings.Contains(string(e.target.stdin[0]), strings.Repeat("x", 8)) {
		t.Fatal("the target got an unverified or complete archive")
	}
	e.assertNoCredentialOnTarget(t, err)
}

func TestPrivateTransferLoadFailureStops(t *testing.T) {
	e := newTransferEnv(t, imageStoreContainerd)
	e.target.loadFails = true
	if _, err := e.transfer(e.binding()); !errors.Is(err, errTransferLoad) {
		t.Fatalf("load failure: %v", err)
	}
	for _, c := range e.target.cmds() {
		if strings.Contains(c, "inspect") {
			t.Fatal("a failed load was verified")
		}
	}
}
