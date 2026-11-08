// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Standalone containers and their definitions in the tree (cu05).

const ctrDefID = "0b8f2c1e-6a0d-4e57-9f43-1f7f0f5d9a11"

// fakeDefinitions is the executor's ListContainerDefinitions. It only
// lists: the UI's dependency has no way to store or remove a definition.
type fakeDefinitions struct {
	defs  []*pb.ContainerDefinitionInfo
	err   error
	hosts []string
}

func (f *fakeDefinitions) ListContainerDefinitions(_ context.Context, in *pb.ListContainerDefinitionsRequest, _ ...grpc.CallOption) (*pb.ListContainerDefinitionsResponse, error) {
	f.hosts = append(f.hosts, in.GetHostId())
	if f.err != nil {
		return nil, f.err
	}
	return &pb.ListContainerDefinitionsResponse{Definitions: f.defs}, nil
}

// ctrStandalonePreview is a host with two standalone containers, "app"
// and "worker", as the preview parser returns them (one target each).
func ctrStandalonePreview(id string) executions.ContainerPreview {
	unit := func(c, name string) dockerhost.PreviewUnit {
		return dockerhost.PreviewUnit{Form: "standalone", ContainerID: ctrHex(c),
			Targets: []dockerhost.PreviewTarget{{ContainerID: ctrHex(c), ContainerName: name, State: "running", ImageID: ctrDigest("d"),
				RunningReference: "nginx:1.27", ConfigurationDigest: ctrHex("c")}},
			Images: []dockerhost.PreviewImage{{ImageID: ctrDigest("d"), RunningReference: "nginx:1.27", Repository: "docker.io/library/nginx",
				Tag: "1.27", Platform: "linux/amd64", OldDigests: []string{ctrDigest("a")},
				Resolved: []dockerhost.PreviewResolution{{Tag: "1.27", IndexDigest: ctrDigest("8"), PlatformDigest: ctrDigest("9")}}}}}
	}
	return executions.ContainerPreview{ID: id, StartedAt: ctrNow.Add(-10 * time.Minute), Status: "ok",
		Units: []dockerhost.PreviewUnit{unit("7", "app"), unit("8", "worker")}}
}

func ctrDefinitionHandler(t *testing.T, defs ui.ContainerDefinitionLister) *ui.Handler {
	t.Helper()
	f := &fakeContainers{previews: map[string]executions.ContainerPreview{"web-01": ctrStandalonePreview(ctrPreviewID)}}
	o := ui.Options{
		Hosts:            func(context.Context) ([]inventory.Host, error) { return ctrHosts(), nil },
		HostKeys:         stagedPins(),
		Operations:       &fakeOps{},
		ContainerBatches: f,
		Now:              func() time.Time { return ctrNow },
		Log:              slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin:     "https://nebula.example",
	}
	if defs != nil {
		o.ContainerDefinitions = defs
	}
	return newTestHandler(t, o)
}

// ctrStandaloneSection is the tree entry of standalone container name.
func ctrStandaloneSection(t *testing.T, body, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, `Standalone container <span class="mono">`+name+`</span>`)
	if !ok {
		t.Fatalf("no tree entry for %s: %s", name, body)
	}
	if i := strings.Index(rest, `<li class="ctr-tree__unit">`); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func TestStandaloneWithoutDefinitionUnavailable(t *testing.T) {
	defs := &fakeDefinitions{defs: []*pb.ContainerDefinitionInfo{
		{HostId: "web-01", ContainerName: "app", DefinitionId: ctrDefID, Version: 2, CreatedBy: "alice", CreatedAtUnix: 1700000000},
		{HostId: "web-01", ContainerName: "app", DefinitionId: ctrDefID, Version: 3, CreatedBy: "bob", CreatedAtUnix: 1700003600, Latest: true},
		// Another host's "worker" is not this host's definition.
		{HostId: "db-01", ContainerName: "worker", DefinitionId: ctrDefID, Version: 1, CreatedBy: "carol", Latest: true},
	}}
	h := ctrDefinitionHandler(t, defs)
	body := getBody(t, h.Handler(), "/inventory/containers?host=web-01")

	if len(defs.hosts) != 1 || defs.hosts[0] != "web-01" {
		t.Fatalf("definitions read for %v, want once for web-01", defs.hosts)
	}
	worker := ctrStandaloneSection(t, body, "worker")
	if !strings.Contains(worker, "unavailable") || !strings.Contains(worker, "no container definition is stored for this container") ||
		!strings.Contains(worker, "none stored") {
		t.Errorf("worker without definition: %s", worker)
	}
	if strings.Contains(worker, "carol") {
		t.Error("another host's definition is shown")
	}
	app := ctrStandaloneSection(t, body, "app")
	for _, want := range []string{"stored", "version 3", "bob", "2023-11-14T23:13:20Z", "unavailable",
		"no batch planner for docker.update"} {
		if !strings.Contains(app, want) {
			t.Errorf("app entry lacks %q: %s", want, app)
		}
	}
	if strings.Contains(app, "version 2") || strings.Contains(app, "alice") || strings.Contains(app, "no container definition is stored") {
		t.Errorf("app entry shows an older version or a wrong reason: %s", app)
	}
	// The definition ID is metadata, but the tree does not need it.
	if strings.Contains(body, ctrDefID) {
		t.Error("definition ID shown")
	}
	// Nothing standalone can be selected.
	for _, c := range ctrCheckboxes(body) {
		if strings.Contains(c, "app") || strings.Contains(c, "worker") || strings.Contains(c, ctrHex("7")) {
			t.Errorf("standalone container selectable: %s", c)
		}
	}
	for _, cmd := range []string{"nebula container definition put web-01 app DEFINITION.json", "nebula container definition remove web-01 worker"} {
		if !strings.Contains(body, cmd) {
			t.Errorf("admin command %q not shown", cmd)
		}
	}
}

// When the server may not read definitions, the status is unknown and
// says why; the update stays unavailable with its reason.
func TestStandaloneDefinitionStatusUnknown(t *testing.T) {
	cases := map[string]struct {
		lister ui.ContainerDefinitionLister
		want   string
	}{
		"no lister":        {nil, "this server cannot read the executor&#39;s container definitions"},
		"admin only":       {&fakeDefinitions{err: status.Error(codes.PermissionDenied, "role server may not call")}, "the executor lets only an administrator read container definitions"},
		"executor failure": {&fakeDefinitions{err: errors.New("dial: " + ctrPlanted)}, "the executor&#39;s container definitions could not be read"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := getBody(t, ctrDefinitionHandler(t, tc.lister).Handler(), "/inventory/containers?host=web-01")
			for _, c := range []string{"app", "worker"} {
				s := ctrStandaloneSection(t, body, c)
				if !strings.Contains(s, tc.want) || !strings.Contains(s, "unavailable") || !strings.Contains(s, "no batch planner for docker.update") {
					t.Errorf("%s: %s", c, s)
				}
				if strings.Contains(s, "none stored") || regexp.MustCompile(`version \d`).MatchString(s) {
					t.Errorf("%s: unknown status shown as known: %s", c, s)
				}
			}
			if strings.Contains(body, ctrPlanted) {
				t.Error("executor error text shown")
			}
		})
	}
}

// Metadata from the executor is text: an author name with markup is
// escaped, and a long one is cut.
func TestStandaloneDefinitionMetadataEscaped(t *testing.T) {
	defs := &fakeDefinitions{defs: []*pb.ContainerDefinitionInfo{
		{HostId: "web-01", ContainerName: "app", DefinitionId: ctrDefID, Version: 1, CreatedBy: `<script>alert(1)</script>` + strings.Repeat("x", 500), Latest: true},
	}}
	body := getBody(t, ctrDefinitionHandler(t, defs).Handler(), "/inventory/containers?host=web-01")
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("author not escaped")
	}
	if strings.Contains(body, strings.Repeat("x", 300)) {
		t.Error("author not bounded")
	}
}

// The web server never takes or shows a definition: there is no route
// that stores or removes one, the page has no field for one, and a
// definition posted to the plan route is neither proposed nor echoed.
func TestContainerDefinitionContentNeverInResponse(t *testing.T) {
	defs := &fakeDefinitions{defs: []*pb.ContainerDefinitionInfo{
		{HostId: "web-01", ContainerName: "app", DefinitionId: ctrDefID, Version: 1, CreatedBy: "alice", Latest: true},
	}}
	h := ctrDefinitionHandler(t, defs).Handler()
	definition := `{"format":"nebula-container-definition-v1","container_name":"app","options":["--name=app"],"command":[],` +
		`"env":[{"name":"DB_PASSWORD","value":"` + ctrPlanted + `"}]}`
	form := url.Values{"host": {"web-01"}, "container": {"app"}, "definition": {definition}, "env": {"DB_PASSWORD=" + ctrPlanted}}.Encode()
	for _, path := range []string{"/inventory/containers/definition", "/inventory/containers/definitions",
		"/inventory/containers/definition/put", "/inventory/containers/definition/remove", "/inventory/containers/plan"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec := httptest.NewRecorder()
			req := formPost(path, form)
			req.Method = method
			h.ServeHTTP(rec, req)
			if rec.Code < 400 {
				t.Errorf("%s %s accepted a definition: %d", method, path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), ctrPlanted) {
				t.Errorf("%s %s echoed the definition", method, path)
			}
		}
	}
	body := getBody(t, h, "/inventory/containers?host=web-01")
	if regexp.MustCompile(`(?i)<form[^>]*action="[^"]*definition`).MatchString(body) ||
		regexp.MustCompile(`(?i)<(textarea|input)[^>]*name="(definition|env)[^"]*"`).MatchString(body) {
		t.Error("the tree has a definition field")
	}
	if strings.Contains(body, ctrPlanted) {
		t.Error("planted value on the tree")
	}
}

// Browser-facing checks like cu04's: the strict CSP through the security
// chain, no inline script, no JavaScript needed (the admin commands sit
// in a details element), and state named in text, not by color alone.
func TestStandaloneTreeWorksWithoutJavaScript(t *testing.T) {
	const origin = "https://nebula.example"
	defs := &fakeDefinitions{defs: []*pb.ContainerDefinitionInfo{
		{HostId: "web-01", ContainerName: "app", DefinitionId: ctrDefID, Version: 1, CreatedBy: "alice", Latest: true},
	}}
	srv, err := middleware.NewServer(middleware.Options{PublicOrigin: origin}, ctrDefinitionHandler(t, defs).Handler())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inventory/containers?host=web-01", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != strictCSP {
		t.Errorf("CSP %q", csp)
	}
	body := rec.Body.String()
	if regexp.MustCompile(`<script(?:\s[^>]*)?>[^<]`).MatchString(body) || regexp.MustCompile(`\son[a-z]+="`).MatchString(body) ||
		strings.Contains(body, ` style="`) {
		t.Error("inline script, handler or style on the page")
	}
	for _, c := range []string{"app", "worker"} {
		s := ctrStandaloneSection(t, body, c)
		if !strings.Contains(s, "<details") || !strings.Contains(s, "<summary>") {
			t.Errorf("%s: admin commands not in a details element", c)
		}
		// Each badge also says its state in words.
		if !strings.Contains(s, `badge--grey">unavailable</span>`) {
			t.Errorf("%s: unavailable state not in text", c)
		}
	}
	if !strings.Contains(ctrStandaloneSection(t, body, "app"), `badge--ok">stored</span>`) {
		t.Error("stored state not in text")
	}
}
