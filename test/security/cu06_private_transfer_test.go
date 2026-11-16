// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrypull"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Private image transfer (container updates cu06, ADR 0006 R7, threat model
// "Private image transfer"): the registry credential and every bearer token
// derived from it stay in the executor. The target host gets image bytes on
// the stdin of `docker load` and nothing else; the server, the collectors,
// executor.db, the executor log and the audit chain never hold them.
//
// The executor's own transfer over SSH (command line, environment requests,
// stdin, result and log against a fake target) is covered in
// internal/executor (TestPrivateTransferContainerdLoadsImageBytesOnly). Batch
// admission still refuses private members (internal/permit/batch), so these
// tests check the parts a release relies on through exported surfaces: the
// exact byte stream that goes to the host, the real executor over its Unix
// socket, and the method-role table.

const (
	cu06User    = "cu06-robot-account"
	cu06Secret  = "cu06-registry-secret-never-on-a-host"
	cu06Secret2 = "cu06-rotated-secret-never-on-a-host"
	cu06Token   = "cu06-bearer-token-never-on-a-host"
	cu06Repo    = "team/app"
)

// cu06Forbidden lists every form a registry credential or token could take
// on the way to a host, a server or a log.
func cu06Forbidden() []string {
	return []string{
		cu06User, cu06Secret, cu06Secret2, cu06Token,
		base64.StdEncoding.EncodeToString([]byte(cu06User + ":" + cu06Secret)),
		base64.StdEncoding.EncodeToString([]byte(cu06User + ":" + cu06Secret2)),
		base64.StdEncoding.EncodeToString([]byte(`{"username":"` + cu06User)),
	}
}

// cu06HostForbidden adds what must never be on a host even without a
// secret value: an auth header, an engine auth header or a Docker client
// configuration.
func cu06HostForbidden() []string {
	return append(cu06Forbidden(), "Authorization", "X-Registry-Auth", "Bearer ", "Basic ", `"auths"`, "credsStore", "credHelpers")
}

func cu06Sha(b []byte) string { return "sha256:" + hexSum(b) }

// cu06Image is one small, verifiable single-platform image.
type cu06Image struct {
	layer, config, manifest []byte
}

func newCU06Image() cu06Image {
	layer := bytes.Repeat([]byte("approved-layer-bytes-"), 4096)
	config, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{cu06Sha([]byte("diff"))}}})
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": cu06Sha(config), "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": cu06Sha(layer), "size": len(layer)}}})
	return cu06Image{layer: layer, config: config, manifest: man}
}

// cu06Registry is a loopback TLS registry in basic or token mode. In token
// mode /token exchanges the Basic credential for cu06Token and the API
// answers only to that bearer token.
type cu06Registry struct {
	srv     *httptest.Server
	mode    registrymeta.AuthMode
	img     cu06Image
	corrupt bool

	mu      sync.Mutex
	headers []http.Header
	authed  int // API requests that carried the expected credential or token
}

func newCU06Registry(t *testing.T, mode registrymeta.AuthMode) *cu06Registry {
	t.Helper()
	r := &cu06Registry{mode: mode, img: newCU06Image()}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *cu06Registry) realm() string { return r.srv.URL + "/token" }

func (r *cu06Registry) handle(w http.ResponseWriter, req *http.Request) {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(cu06User+":"+cu06Secret))
	r.mu.Lock()
	r.headers = append(r.headers, req.Header.Clone())
	r.mu.Unlock()
	if req.URL.Path == "/token" {
		if r.mode != registrymeta.AuthToken || req.Header.Get("Authorization") != basic {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"token":"`+cu06Token+`"}`)
		return
	}
	want := basic
	if r.mode == registrymeta.AuthToken {
		want = "Bearer " + cu06Token
	}
	if req.Header.Get("Authorization") != want {
		if r.mode == registrymeta.AuthToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.realm()+`",service="registry.test"`)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	r.authed++
	r.mu.Unlock()
	p := req.URL.Path
	switch {
	case p == "/v2/"+cu06Repo+"/manifests/"+cu06Sha(r.img.manifest):
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		_, _ = w.Write(r.img.manifest)
	case p == "/v2/"+cu06Repo+"/blobs/"+cu06Sha(r.img.config):
		_, _ = w.Write(r.img.config)
	case p == "/v2/"+cu06Repo+"/blobs/"+cu06Sha(r.img.layer):
		b := r.img.layer
		if r.corrupt {
			b = bytes.Repeat([]byte("x"), len(b))
		}
		_, _ = w.Write(b)
	default:
		http.NotFound(w, req)
	}
}

func (r *cu06Registry) puller(t *testing.T) *registrypull.Puller {
	t.Helper()
	rec := registrymeta.PrivateRegistry{Registry: r.srv.URL, Mode: r.mode, Repositories: []string{cu06Repo}}
	if r.mode == registrymeta.AuthToken {
		rec.Realm, rec.Service = r.realm(), "registry.test"
	}
	p, err := registrypull.New(registrypull.Options{Registry: rec, RootCAs: certPool(r.srv), TempDir: t.TempDir(), AllowLoopback: true})
	if err != nil {
		t.Fatalf("puller: %v", err)
	}
	return p
}

// certPool trusts exactly the test registry's certificate.
func certPool(srv *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(srv.Certificate())
	return p
}

// assertNoneIn fails when text holds any of forbidden.
func assertNoneIn(t *testing.T, where, text string, forbidden []string) {
	t.Helper()
	for _, bad := range forbidden {
		if strings.Contains(text, bad) {
			t.Fatalf("%s holds %q", where, bad)
		}
	}
}

// TestCU06_HostReceivesImageBytesOnly: the archive the executor streams into
// `docker load` on the target is the only thing the host receives in a
// private transfer. For both auth modes it holds the verified image and no
// credential, token, auth header or Docker client configuration; the
// registry was really authenticated (so the test is not vacuous) and never
// got X-Registry-Auth. A failed pull leaks neither in its error nor in the
// partial stream.
func TestCU06_HostReceivesImageBytesOnly(t *testing.T) {
	for _, mode := range []registrymeta.AuthMode{registrymeta.AuthBasic, registrymeta.AuthToken} {
		t.Run(string(mode), func(t *testing.T) {
			reg := newCU06Registry(t, mode)
			var archive bytes.Buffer
			res, err := reg.puller(t).Pull(context.Background(), registrymeta.Credential{Username: cu06User, Secret: []byte(cu06Secret)},
				registrypull.Request{Repository: cu06Repo, Digest: cu06Sha(reg.img.manifest), Tag: "nos-transfer",
					Platform: registrypull.Platform{OS: "linux", Architecture: "amd64"}}, &archive)
			if err != nil {
				t.Fatalf("pull: %v", err)
			}
			if res.ManifestDigest != cu06Sha(reg.img.manifest) || res.ImageID != cu06Sha(reg.img.config) {
				t.Fatalf("result: %+v", res)
			}
			// The stream is a complete archive holding the verified blobs.
			names := map[string]bool{}
			tr := tar.NewReader(bytes.NewReader(archive.Bytes()))
			for {
				h, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("archive: %v", err)
				}
				names[h.Name] = true
			}
			for _, want := range []string{"manifest.json", "index.json", "oci-layout",
				"blobs/sha256/" + strings.TrimPrefix(cu06Sha(reg.img.layer), "sha256:")} {
				if !names[want] {
					t.Fatalf("archive lacks %s: %v", want, names)
				}
			}
			assertNoneIn(t, "the archive streamed to the host", archive.String(), cu06HostForbidden())
			assertNoneIn(t, "the pull result", fmt.Sprintf("%+v", res), cu06Forbidden())

			reg.mu.Lock()
			authed, headers := reg.authed, reg.headers
			reg.mu.Unlock()
			if authed < 3 {
				t.Fatalf("registry saw %d authenticated requests, want manifest, config and layer", authed)
			}
			for _, h := range headers {
				if h.Get("X-Registry-Auth") != "" {
					t.Fatal("X-Registry-Auth was sent")
				}
			}

			// A blob that fails verification: no credential or token in the
			// error or in the bytes written before the failure.
			reg.corrupt = true
			var partial bytes.Buffer
			_, err = reg.puller(t).Pull(context.Background(), registrymeta.Credential{Username: cu06User, Secret: []byte(cu06Secret)},
				registrypull.Request{Repository: cu06Repo, Digest: cu06Sha(reg.img.manifest), Tag: "nos-transfer",
					Platform: registrypull.Platform{OS: "linux", Architecture: "amd64"}}, &partial)
			if !errors.Is(err, registrypull.ErrDigestMismatch) {
				t.Fatalf("corrupt blob: %v", err)
			}
			assertNoneIn(t, "the pull error", err.Error(), cu06Forbidden())
			assertNoneIn(t, "the partial stream", partial.String(), cu06HostForbidden())
		})
	}
}

// TestCU06_HostJobHasNoRegistryLogin: the host side of a private update is
// the docker.compose_update job, which gets a non-secret binding only. No
// built-in docker action logs in, sends an engine auth header or writes a
// Docker credential configuration on the host.
func TestCU06_HostJobHasNoRegistryLogin(t *testing.T) {
	a, ok := actions.Lookup("docker.compose_update")
	if !ok || len(a.Script) == 0 {
		t.Fatal("docker.compose_update is not a built-in action")
	}
	for _, act := range actions.Builtin {
		if !strings.HasPrefix(act.ID, "docker.") {
			continue
		}
		assertNoneIn(t, act.ID+" script", string(act.Script),
			[]string{"docker login", "X-Registry-Auth", "--password", "credsStore", "credHelpers", `"auths"`})
	}
	// The private branch exists and takes no pull with credentials: the
	// script empties DOCKER_CONFIG for every Docker call it makes.
	if !strings.Contains(string(a.Script), `"registry" in u`) || !strings.Contains(string(a.Script), `env["DOCKER_CONFIG"] = empty`) {
		t.Fatal("docker.compose_update lost its private-registry branch or its empty DOCKER_CONFIG")
	}
}

// TestCU06_RegistryCredentialStaysInExecutor runs the real executor over its
// Unix socket: the credential enters with AddPrivateRegistry (admin) and is
// never returned by any answer the server can obtain (registry list, read,
// lease proposal, lease list), never written in clear to the executor data
// directory, and never logged or audited. The server-built registry lease
// carries the credential identity, not the credential.
func TestCU06_RegistryCredentialStaysInExecutor(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	if _, err := h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	var wire []string
	rec := func(ms ...proto.Message) {
		for _, m := range ms {
			if m != nil {
				b, _ := protojson.Marshal(m)
				wire = append(wire, string(b))
			}
		}
	}
	expiry := time.Now().Add(30 * 24 * time.Hour).Unix()
	add, err := h.client.AddPrivateRegistry(h.ctx(), &pb.AddPrivateRegistryRequest{RegistryId: "corp",
		RegistryOrigin: "https://registry.example.org", AuthMode: pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC,
		Repositories: []string{cu06Repo}, Username: cu06User, Secret: []byte(cu06Secret), CredentialExpiresUnix: expiry})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	rec(add)
	rot, err := h.client.RotatePrivateRegistryCredential(h.ctx(), &pb.RotatePrivateRegistryCredentialRequest{RegistryId: "corp",
		Username: cu06User, Secret: []byte(cu06Secret2), CredentialExpiresUnix: expiry})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rec(rot)
	list, err := h.client.ListPrivateRegistries(h.ctx(), &pb.ListPrivateRegistriesRequest{})
	if err != nil || len(list.GetRegistries()) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	rec(list)
	if list.GetRegistries()[0].GetCredentialId() == "" {
		t.Fatal("the server cannot see the credential identity it must lease")
	}

	// The server builds and proposes a registry read lease from the list
	// alone, over the real socket.
	prop, err := registrymeta.ProposeRegistryReadLease(h.ctx(), h.client, registrymeta.LeaseRequest{
		ID: "00000000-0000-4000-8000-0000000c06d0", Days: 7,
		Registries: []registrymeta.LeaseSelection{{RegistryID: "corp", Repositories: []string{cu06Repo}}}}, time.Now())
	if err != nil {
		t.Fatalf("server lease proposal: %v", err)
	}
	wire = append(wire, fmt.Sprintf("%+v", prop))
	grants, err := h.client.ListReadGrants(h.ctx(), &pb.ListReadGrantsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	rec(grants)
	if !strings.Contains(strings.Join(wire, "\n"), list.GetRegistries()[0].GetCredentialId()) {
		t.Fatal("the lease proposal does not bind the credential identity")
	}

	// A read without an approved lease fails closed; its error carries
	// nothing either.
	_, err = h.client.ReadPrivateRegistry(h.ctx(), &pb.ReadPrivateRegistryRequest{RegistryId: "corp", Repository: cu06Repo,
		Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST, Tag: "1.0.0"})
	if err == nil {
		t.Fatal("read without an approved lease succeeded")
	}
	wire = append(wire, err.Error())

	assertNoneIn(t, "what the server received", strings.Join(wire, "\n"), cu06Forbidden())
	logs := h.logs.String()
	if !strings.Contains(logs, "corp") {
		t.Fatalf("no audit line for the registry; log:\n%s", logs)
	}
	assertNoneIn(t, "the executor log and audit chain", logs, cu06Forbidden())

	// executor.db (with the signed event chain), the vault and every other
	// file of the data directory hold no credential in clear.
	h.stop()
	err = filepath.WalkDir(h.dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		assertNoneIn(t, p, string(b), cu06Forbidden())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCU06_CollectorsAndServerCannotObtainCredential: the collectors have
// no private registry method at all; the server cannot add, rotate or
// remove a credential; and no answer message the server or a collector can
// receive for these methods has a field that could carry a user name,
// secret, password or token.
func TestCU06_CollectorsAndServerCannotObtainCredential(t *testing.T) {
	const serverUID, pveUID, netdevUID = 20001, 20002, 20003
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer}, pveUID: {peercred.RolePVECollector}, netdevUID: {peercred.RoleNetDevCollector},
	}, executor.MethodRoles())
	write := []string{
		pb.ExecutorService_AddPrivateRegistry_FullMethodName,
		pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName,
		pb.ExecutorService_RemovePrivateRegistry_FullMethodName,
	}
	read := []string{
		pb.ExecutorService_ListPrivateRegistries_FullMethodName,
		pb.ExecutorService_ReadPrivateRegistry_FullMethodName,
	}
	for _, m := range append(append([]string(nil), write...), read...) {
		for _, uid := range []uint32{pveUID, netdevUID} {
			if _, ok := policy.Allowed(uid, m); ok {
				t.Errorf("collector uid %d may call %s", uid, m)
			}
		}
	}
	for _, m := range write {
		if _, ok := policy.Allowed(serverUID, m); ok {
			t.Errorf("server may call %s", m)
		}
	}
	for _, msg := range []proto.Message{&pb.AddPrivateRegistryResponse{}, &pb.RotatePrivateRegistryCredentialResponse{},
		&pb.RemovePrivateRegistryResponse{}, &pb.ListPrivateRegistriesResponse{}, &pb.ReadPrivateRegistryResponse{}} {
		checkNoCredentialField(t, msg.ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{})
	}
}

func checkNoCredentialField(t *testing.T, d protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[d.FullName()] {
		return
	}
	seen[d.FullName()] = true
	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		name := strings.ToLower(string(f.Name()))
		for _, bad := range []string{"username", "user_name", "secret", "password", "token", "authorization", "auth_header"} {
			if strings.Contains(name, bad) {
				t.Errorf("%s.%s could carry a registry credential", d.FullName(), f.Name())
			}
		}
		if f.Kind() == protoreflect.BytesKind {
			t.Errorf("%s.%s is a bytes field", d.FullName(), f.Name())
		}
		if f.Message() != nil {
			checkNoCredentialField(t, f.Message(), seen)
		}
	}
}
