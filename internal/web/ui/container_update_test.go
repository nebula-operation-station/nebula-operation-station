// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Container and Compose update and rollback from the tree (cu04).

const (
	ctrPreviewID = "00000000-0000-4000-8000-0000000000a1"
	ctrOtherID   = "00000000-0000-4000-8000-0000000000a2"
	ctrUpdateID  = "00000000-0000-4000-8000-0000000000b1"
	ctrBatchID   = "11111111-2222-4333-8444-555555555555"
	// ctrPlanted stands for an environment value of a container; it must
	// not appear on any page.
	ctrPlanted = "PLANTED_DB_PASSWORD_9f3e"
)

var ctrNow = time.Unix(1791960000, 0)

func ctrHex(c string) string    { return strings.Repeat(c, 64) }
func ctrDigest(c string) string { return "sha256:" + ctrHex(c) }

// ctrPreview is the update preview of a host: project "site" with web
// (new digest for 1.27, tags 1.28 and 2.0 resolved), db (digest_pinned),
// cache (up to date), proxy and sidecar (sharing a namespace); project
// "big" truncated; one standalone container.
func ctrPreview(id string) executions.ContainerPreview {
	img := func(imageID, ref, repo, tag string, old string, res ...dockerhost.PreviewResolution) dockerhost.PreviewImage {
		return dockerhost.PreviewImage{ImageID: imageID, RunningReference: ref, Repository: repo, Tag: tag, Platform: "linux/amd64",
			OldDigests: []string{old}, Resolved: res}
	}
	tgt := func(svc, cid, name, imageID, ref string) dockerhost.PreviewTarget {
		return dockerhost.PreviewTarget{Service: svc, ContainerID: cid, ContainerName: name, State: "running", ImageID: imageID,
			RunningReference: ref, ConfigurationDigest: ctrHex("c")}
	}
	return executions.ContainerPreview{ID: id, StartedAt: ctrNow.Add(-10 * time.Minute), Status: "ok", Units: []dockerhost.PreviewUnit{
		{Form: "compose", Project: "big", Reason: "truncated"},
		{Form: "compose", Project: "site", WorkingDirHash: ctrHex("1"), ConfigFilesHash: ctrHex("2"), SourceDigest: ctrHex("3"),
			Services: []dockerhost.PreviewService{
				{Service: "cache", Replicas: 1, Scale: 1},
				{Service: "db", Replicas: 1, Scale: 1, Reasons: []string{"digest_pinned"}},
				{Service: "proxy", Replicas: 1, Scale: 1, Shares: []string{"sidecar"}},
				{Service: "sidecar", Replicas: 1, Scale: 1, Shares: []string{"proxy"}},
				{Service: "web", Replicas: 1, Scale: 1, Depends: []dockerhost.PreviewDependency{{Service: "db"}}},
			},
			Targets: []dockerhost.PreviewTarget{
				tgt("cache", ctrHex("5"), "site-cache-1", ctrDigest("f"), "redis:7"),
				tgt("db", ctrHex("3"), "site-db-1", ctrDigest("e"), "postgres@"+ctrDigest("7")),
				tgt("proxy", ctrHex("6"), "site-proxy-1", ctrDigest("d"), "nginx:1.27"),
				tgt("sidecar", ctrHex("7"), "site-sidecar-1", ctrDigest("d"), "nginx:1.27"),
				tgt("web", ctrHex("1"), "site-web-1", ctrDigest("d"), "nginx:1.27"),
			},
			Images: []dockerhost.PreviewImage{
				img(ctrDigest("d"), "nginx:1.27", "docker.io/library/nginx", "1.27", ctrDigest("a"),
					dockerhost.PreviewResolution{Tag: "1.27", IndexDigest: ctrDigest("8"), PlatformDigest: ctrDigest("9")},
					dockerhost.PreviewResolution{Tag: "1.28", IndexDigest: ctrDigest("6"), PlatformDigest: ctrDigest("5")},
					dockerhost.PreviewResolution{Tag: "2.0", IndexDigest: ctrDigest("4"), PlatformDigest: ctrDigest("3")},
					dockerhost.PreviewResolution{Tag: "1.27-alpine", IndexDigest: ctrDigest("2"), PlatformDigest: ctrDigest("1")}),
				img(ctrDigest("e"), "postgres@"+ctrDigest("7"), "docker.io/library/postgres", "", ctrDigest("7")),
				img(ctrDigest("f"), "redis:7", "docker.io/library/redis", "7", ctrDigest("b"),
					dockerhost.PreviewResolution{Tag: "7", PlatformDigest: ctrDigest("b")}),
			}},
		{Form: "standalone", ContainerID: ctrHex("9"), Reason: ""},
	}}
}

// ctrRow is a recorded update of web on web-01 from 1.26 to 1.27.
func ctrRow(id, state string, mod func(*pb.ContainerRecreationInfo)) *pb.ContainerRecreationInfo {
	r := &pb.ContainerRecreationInfo{ExecutionId: id, Kind: "update", HostId: "web-01", Form: "compose", Unit: "site", State: state,
		WindowExpiresAtUnix: ctrNow.Add(time.Hour).Unix(), HasBaseline: true,
		Images: []*pb.ContainerRecreationImage{{Service: "web", Repository: "docker.io/library/nginx", OldTag: "1.26", NewTag: "1.27",
			RetainedReference: "docker.io/library/nginx:1.26", PriorImageId: ctrDigest("2")}},
		Verdict:      &pb.ContainerRecreationVerdict{Judged: true, Findings: []string{"env DB_PASSWORD=" + ctrPlanted}},
		RecoveryPlan: &pb.ContainerRecoveryPlanInfo{Digest: ctrHex("5")}}
	if mod != nil {
		mod(r)
	}
	return r
}

// fakeContainers is the planner side of the controls. Its bindings follow
// the preview like the real planner's (which internal/executions tests).
type fakeContainers struct {
	previews   map[string]executions.ContainerPreview
	rows       map[string][]*pb.ContainerRecreationInfo
	proposed   []executions.BatchRequest
	proposeErr error
}

func (f *fakeContainers) ProposeBatch(_ context.Context, _ string, req executions.BatchRequest) (executions.BatchCreated, error) {
	f.proposed = append(f.proposed, req)
	if f.proposeErr != nil {
		return executions.BatchCreated{}, f.proposeErr
	}
	return executions.BatchCreated{ID: ctrBatchID}, nil
}

func (f *fakeContainers) Batch(context.Context, string) (executions.BatchView, error) {
	return executions.BatchView{}, executions.ErrBatchNotFound
}

func (f *fakeContainers) LatestContainerPreview(_ context.Context, host string) (executions.ContainerPreview, error) {
	return f.previews[host], nil
}

func (f *fakeContainers) ContainerRecreations(_ context.Context, host string) ([]*pb.ContainerRecreationInfo, error) {
	return f.rows[host], nil
}

func stale() error {
	return &executions.BatchInputError{Reason: "member 1: the update preview is not fresh", Err: executions.ErrBatchPreviewStale}
}

func (f *fakeContainers) PlanContainerUpdate(_ context.Context, host string, spec executions.ContainerUpdateSpec) (canonical.BatchContainerUpdate, error) {
	p := f.previews[host]
	if spec.PreviewExecutionID != p.ID {
		return canonical.BatchContainerUpdate{}, stale()
	}
	i := slices.IndexFunc(p.Units, func(u dockerhost.PreviewUnit) bool { return u.Project == spec.Project })
	u := p.Units[i]
	b := canonical.BatchContainerUpdate{Kind: "update", Form: "compose", Project: u.Project, SourceDigest: u.SourceDigest,
		WorkingDirHash: u.WorkingDirHash, ConfigFilesHash: u.ConfigFilesHash}
	for _, s := range spec.Services {
		for _, t := range u.Targets {
			if t.Service != s.Service {
				continue
			}
			b.Targets = append(b.Targets, canonical.ContainerUpdateTarget{Service: t.Service, ContainerID: t.ContainerID, ContainerName: t.ContainerName,
				ImageID: t.ImageID, RunningReference: t.RunningReference, ConfigurationDigest: t.ConfigurationDigest})
			im := u.Images[slices.IndexFunc(u.Images, func(im dockerhost.PreviewImage) bool { return im.ImageID == t.ImageID })]
			tag := s.NewTag
			if tag == "" {
				tag = im.Tag
			}
			res := im.Resolved[slices.IndexFunc(im.Resolved, func(r dockerhost.PreviewResolution) bool { return r.Tag == tag })]
			b.Images = append(b.Images, canonical.ContainerUpdateImage{Service: s.Service, Repository: im.Repository, Platform: im.Platform,
				OldTag: im.Tag, NewTag: tag, OldDigests: im.OldDigests, NewIndexDigest: res.IndexDigest, NewPlatformDigest: res.PlatformDigest,
				OldImageID: im.ImageID, PolicyVersion: s.PolicyVersion, PolicyDigest: s.PolicyDigest, MajorChange: s.MajorChange})
		}
		if s.Service == "web" {
			b.Dependencies = append(b.Dependencies, canonical.ContainerUpdateDependency{Service: "db", Relation: "requires",
				Containers: []canonical.ContainerDependencyMember{{ContainerID: ctrHex("3"), ContainerName: "site-db-1", ConfigurationDigest: ctrHex("c")}}})
		}
	}
	return b, nil
}

func (f *fakeContainers) PlanContainerRollback(_ context.Context, host string, spec executions.ContainerRollbackSpec) (canonical.BatchContainerUpdate, error) {
	if spec.PreviewExecutionID != f.previews[host].ID {
		return canonical.BatchContainerUpdate{}, stale()
	}
	for _, r := range f.rows[host] {
		if r.GetExecutionId() == spec.RollbackOf {
			return canonical.BatchContainerUpdate{Kind: "rollback", Form: "compose", Project: r.GetUnit(), SourceDigest: ctrHex("3"),
				RollbackOf: r.GetExecutionId(), RecoveryPlanDigest: r.GetRecoveryPlan().GetDigest(),
				Images: []canonical.ContainerUpdateImage{{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64", OldTag: "1.27", NewTag: "1.26",
					OldDigests: []string{ctrDigest("9")}, Rollback: &canonical.ContainerRollbackImage{PriorImageID: ctrDigest("2"), RetainedTag: "u-b1-web",
						RetainedReference: "docker.io/library/nginx:1.26"}}},
				Targets: []canonical.ContainerUpdateTarget{{Service: "web", ContainerID: ctrHex("1"), ContainerName: "site-web-1", ImageID: ctrDigest("d"),
					RunningReference: "nginx:1.27", ConfigurationDigest: ctrHex("c")}}}, nil
		}
	}
	return canonical.BatchContainerUpdate{}, &executions.BatchInputError{Reason: "member 1: no recorded update", Err: executions.ErrBatchRollbackSource}
}

// fakeTagPolicy: 1.27 to 1.28 is minor, to 2.0 major; a variant change
// cannot be compared.
type fakeTagPolicy struct{}

func (fakeTagPolicy) CompareTags(_ context.Context, _, oldTag, newTag string) (ui.ContainerTagComparison, error) {
	if strings.Contains(newTag, "-") || strings.Contains(oldTag, "-") {
		return ui.ContainerTagComparison{}, errors.New("variant change")
	}
	return ui.ContainerTagComparison{PolicyVersion: "stable-v1", PolicyDigest: ctrHex("9"), MajorChange: !strings.HasPrefix(newTag, "1.")}, nil
}

func ctrHosts() []inventory.Host {
	hosts := stagedHosts()
	hosts[2].DisplayName = `<b>web</b> "one"`
	hosts[2].Tags = map[string]string{"db_password": ctrPlanted}
	return hosts
}

func ctrHandler(t *testing.T, policy bool) (*ui.Handler, *fakeContainers) {
	t.Helper()
	f := &fakeContainers{
		previews: map[string]executions.ContainerPreview{"web-01": ctrPreview(ctrPreviewID), "ci-01": ctrPreview(ctrPreviewID)},
		rows: map[string][]*pb.ContainerRecreationInfo{"web-01": {
			ctrRow(ctrUpdateID, "recreated", nil),
			ctrRow("00000000-0000-4000-8000-0000000000c1", "uncertain", nil),
			ctrRow("00000000-0000-4000-8000-0000000000c2", "recreated", func(r *pb.ContainerRecreationInfo) { r.WindowExpiresAtUnix = ctrNow.Add(-time.Hour).Unix() }),
			ctrRow("00000000-0000-4000-8000-0000000000c3", "recreated", func(r *pb.ContainerRecreationInfo) { r.RecoveryPlan = nil }),
			ctrRow("00000000-0000-4000-8000-0000000000c4", "partial", func(r *pb.ContainerRecreationInfo) { r.HasBaseline = false }),
			ctrRow("00000000-0000-4000-8000-0000000000c5", "rolled_back", nil),
		}},
	}
	o := ui.Options{
		Hosts:            func(context.Context) ([]inventory.Host, error) { return ctrHosts(), nil },
		HostKeys:         stagedPins(),
		Operations:       &fakeOps{},
		ContainerBatches: f,
		Now:              func() time.Time { return ctrNow },
		Log:              slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin:     "https://nebula.example",
	}
	if policy {
		o.ContainerTagPolicy = fakeTagPolicy{}
	}
	return newTestHandler(t, o), f
}

func ctrPost(t *testing.T, h *ui.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/containers/plan", body))
	return rec
}

var ctrCheckboxRe = regexp.MustCompile(`<input type="checkbox" name="(svc|rollback)" value="([^"]*)"`)

func ctrCheckboxes(body string) []string {
	var out []string
	for _, m := range ctrCheckboxRe.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1]+"="+html.UnescapeString(m[2]))
	}
	return out
}

// ctrConfirmBody is the body the confirmation form submits.
func ctrConfirmBody(t *testing.T, body string) url.Values {
	t.Helper()
	_, form, ok := strings.Cut(body, `<section class="panel ctr-confirm"`)
	if !ok {
		t.Fatalf("no confirmation section: %s", body)
	}
	v := url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(form, -1) {
		v.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return v
}

func selection(pairs ...string) string {
	v := url.Values{"preview:web-01": {ctrPreviewID}}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Add(pairs[i], pairs[i+1])
	}
	return v.Encode()
}

func TestContainerTreeOffersOnlyWhatCanBeUpdated(t *testing.T) {
	h, _ := ctrHandler(t, false)
	body := getBody(t, h.Handler(), "/inventory/containers")
	got := ctrCheckboxes(body)
	want := []string{"svc=ci-01/site/proxy", "svc=ci-01/site/sidecar", "svc=ci-01/site/web",
		"svc=web-01/site/proxy", "svc=web-01/site/sidecar", "svc=web-01/site/web", "rollback=web-01/" + ctrUpdateID}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("checkboxes = %v, want %v", got, want)
	}
	for _, reason := range []string{
		"the image is pinned by digest",                  // db
		"up to date: no new digest for this tag",         // cache
		"cut off by a preview limit",                     // big
		"standalone containers are not offered here",     // standalone
		"shares a namespace with",                        // proxy, sidecar
		"tag changes need the executor&#39;s tag policy", // no policy
		"the outcome of this update is uncertain",
		"the rollback window is over",
		"no recovery plan is recorded",
		"no baseline was recorded",
		"already rolled back",
		"not enrolled", // plain-01
	} {
		if !strings.Contains(body, reason) {
			t.Errorf("tree lacks the reason %q", reason)
		}
	}
	// No tag policy: no target tag is offered.
	if strings.Contains(body, `name="tag:`) || strings.Contains(body, `name="major:`) {
		t.Error("tag change controls shown without a tag policy")
	}
	// A project has no checkbox of its own.
	if strings.Contains(body, `name="unit"`) || strings.Contains(body, `name="project"`) {
		t.Error("a project has a checkbox")
	}
}

func TestContainerTreeHostGates(t *testing.T) {
	h, f := ctrHandler(t, false)
	f.previews["web-01"] = executions.ContainerPreview{ID: ctrPreviewID, StartedAt: ctrNow, Status: "prepare_required"}
	f.previews["ci-01"] = executions.ContainerPreview{ID: ctrOtherID, StartedAt: ctrNow.Add(-2 * time.Hour), Stale: "the preview is older than 1h0m0s; run a fresh preview"}
	body := getBody(t, h.Handler(), "/inventory/containers")
	for _, want := range []string{
		"/operations/new?action=docker.update_prepare&amp;host=web-01",
		"/operations/new?action=docker.update_preview&amp;host=ci-01",
		"the preview is older than 1h0m0s",
		"the host is not prepared for container updates",
		"needs a fresh update preview",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tree lacks %q", want)
		}
	}
	if got := ctrCheckboxes(body); len(got) != 0 {
		t.Errorf("checkboxes %v without a usable preview", got)
	}
	if strings.Contains(body, "Review the plan") {
		t.Error("submit button without anything selectable")
	}
}

func TestContainerConfirmShowsCurrentToApprovedAndProposesIt(t *testing.T) {
	h, f := ctrHandler(t, false)
	rec := ctrPost(t, h, selection("svc", "web-01/site/web"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"docker.io/library/nginx", "linux/amd64",
		ctrDigest("a"),                        // current repository digest
		ctrDigest("d"),                        // current image ID
		ctrDigest("8"),                        // approved index digest
		ctrDigest("9"),                        // approved platform digest
		ctrHex("3"), ctrHex("1"), ctrHex("2"), // source, working dir, config files
		"site-web-1", ctrHex("c"), // container and configuration digest
		"Dependencies: affected, not recreated", "site-db-1",
		"Stage 1: prod", "MEDIUM",
		"Volume and database migrations are not undone",
		"&lt;b&gt;web&lt;/b&gt; &#34;one&#34;", // escaped host name
	} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation lacks %q", want)
		}
	}
	if len(f.proposed) != 0 {
		t.Fatal("the first POST proposed")
	}
	rec = ctrPost(t, h, ctrConfirmBody(t, body).Encode())
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/batches/"+ctrBatchID {
		t.Fatalf("confirm: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(f.proposed) != 1 || len(f.proposed[0].Stages) != 1 {
		t.Fatalf("proposed %+v", f.proposed)
	}
	st := f.proposed[0].Stages[0]
	if st.Gate != "manual" || st.FailureThreshold != 0 || st.UnreachableThreshold != 0 || len(st.Members) != 1 {
		t.Fatalf("stage %+v", st)
	}
	up := st.Members[0]
	if up.ActionID != "docker.compose_update" || up.Version != "2.0.0" || up.HostID != "web-01" || up.Update == nil ||
		up.Update.PreviewExecutionID != ctrPreviewID || up.Update.Project != "site" || len(up.Update.Services) != 1 || up.Update.Services[0] != (executions.ContainerServiceSpec{Service: "web"}) {
		t.Errorf("update member %+v %+v", up, up.Update)
	}
}

func TestContainerRollbackConfirmIsBoundToTheRecreatedContainers(t *testing.T) {
	h, f := ctrHandler(t, false)
	rec := ctrPost(t, h, selection("rollback", "web-01/"+ctrUpdateID))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Rolls back update", ctrUpdateID, "docker.io/library/nginx:1.26", ctrDigest("2"),
		"bound to the containers that update created", ctrHex("1"), "HIGH", "Volume and database migrations are not undone"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation lacks %q", want)
		}
	}
	rec = ctrPost(t, h, ctrConfirmBody(t, body).Encode())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	rb := f.proposed[0].Stages[0].Members[0]
	if rb.ActionID != "docker.compose_rollback" || rb.Version != "1.0.0" || rb.Rollback == nil || rb.Rollback.RollbackOf != ctrUpdateID || rb.Rollback.PreviewExecutionID != ctrPreviewID {
		t.Errorf("rollback member %+v", rb)
	}
}

func TestContainerPlanUsesHostStages(t *testing.T) {
	h, f := ctrHandler(t, false)
	body := url.Values{"preview:web-01": {ctrPreviewID}, "preview:ci-01": {ctrPreviewID}, "svc": {"web-01/site/web", "ci-01/site/web"}}
	rec := ctrPost(t, h, body.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: %d %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	if i, j := strings.Index(page, "Stage 1: dev"), strings.Index(page, "Stage 2: prod"); i < 0 || j < i {
		t.Fatalf("stages not shown in DEV, PROD order")
	}
	if !strings.Contains(page, "ctr-confirm__gate") {
		t.Error("no gate between the stages")
	}
	rec = ctrPost(t, h, ctrConfirmBody(t, page).Encode())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	st := f.proposed[0].Stages
	if len(st) != 2 || st[0].Members[0].HostID != "ci-01" || st[1].Members[0].HostID != "web-01" {
		t.Fatalf("stages %+v", st)
	}
}

func TestContainerTagChangeIsHighAndNeedsTheSecondChoice(t *testing.T) {
	h, f := ctrHandler(t, true)
	tree := getBody(t, h.Handler(), "/inventory/containers?host=web-01")
	for _, want := range []string{`name="tag:web-01/site/web"`, `<option value="1.28">`, `name="major:web-01/site/web"`} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree lacks %q", want)
		}
	}
	// A major change without the second choice is refused.
	rec := ctrPost(t, h, selection("svc", "web-01/site/web", "tag:web-01/site/web", "2.0"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "major version change") {
		t.Fatalf("major without second choice: %d %s", rec.Code, rec.Body.String())
	}
	// A variant change is not offered.
	rec = ctrPost(t, h, selection("svc", "web-01/site/web", "tag:web-01/site/web", "1.27-alpine"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not offered") {
		t.Fatalf("variant change: %d %s", rec.Code, rec.Body.String())
	}
	// A tag the preview did not resolve is refused.
	rec = ctrPost(t, h, selection("svc", "web-01/site/web", "tag:web-01/site/web", "1.29"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "did not resolve") {
		t.Fatalf("unresolved tag: %d %s", rec.Code, rec.Body.String())
	}
	rec = ctrPost(t, h, selection("svc", "web-01/site/web", "tag:web-01/site/web", "2.0", "major:web-01/site/web", "1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("major with second choice: %d %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{"HIGH", "tag change", "stable-v1", ctrHex("9"), "major version change", ctrDigest("4"), ctrDigest("3")} {
		if !strings.Contains(page, want) {
			t.Errorf("confirmation lacks %q", want)
		}
	}
	if strings.Contains(page, ">MEDIUM<") {
		t.Error("a tag change is shown as MEDIUM")
	}
	if rec = ctrPost(t, h, ctrConfirmBody(t, page).Encode()); rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	got := f.proposed[0].Stages[0].Members[0].Update.Services[0]
	want := executions.ContainerServiceSpec{Service: "web", NewTag: "2.0", MajorChange: true, PolicyVersion: "stable-v1", PolicyDigest: ctrHex("9")}
	if got != want {
		t.Fatalf("proposed service %+v, want %+v", got, want)
	}
}

func TestContainerTagChangeRefusedWithoutPolicy(t *testing.T) {
	h, _ := ctrHandler(t, false)
	rec := ctrPost(t, h, selection("svc", "web-01/site/web", "tag:web-01/site/web", "1.28"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tag policy") {
		t.Fatalf("tag change without policy: %d %s", rec.Code, rec.Body.String())
	}
}

func TestContainerPlanRefusals(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"nothing selected", selection(), "select at least one"},
		{"parent without children", selection("unit", "web-01/site"), "selects none of its services"},
		{"project field", selection("project", "site"), "selects none of its services"},
		{"unavailable service", selection("svc", "web-01/site/db"), "cannot be updated"},
		{"service outside the preview", selection("svc", "web-01/other/web"), "not in the update preview"},
		{"unknown host", selection("svc", "nope-01/site/web"), "unknown host"},
		{"not enrolled host", selection("svc", "plain-01/site/web"), "not enrolled"},
		{"no preview named", url.Values{"svc": {"web-01/site/web"}}.Encode(), "names no update preview"},
		{"stale preview", url.Values{"svc": {"web-01/site/web"}, "preview:web-01": {ctrOtherID}}.Encode(), "no longer the newest"},
		{"repeated selection", selection("svc", "web-01/site/web", "svc", "web-01/site/web"), "repeated"},
		{"malformed key", selection("svc", "web-01"), "invalid selection"},
		{"update and rollback of one project", selection("svc", "web-01/site/web", "rollback", "web-01/"+ctrUpdateID), "changes a project once"},
		{"unknown rollback", selection("rollback", "web-01/00000000-0000-4000-8000-0000000000ff"), "no recorded update"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, f := ctrHandler(t, true)
			rec := ctrPost(t, h, c.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
				t.Fatalf("%d %q, want 400 with %q", rec.Code, rec.Body.String(), c.want)
			}
			if len(f.proposed) != 0 {
				t.Fatal("a refused plan was proposed")
			}
		})
	}
}

func TestContainerConfirmIsBoundToTheShownPlan(t *testing.T) {
	h, f := ctrHandler(t, false)
	rec := ctrPost(t, h, selection("svc", "web-01/site/web"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: %d", rec.Code)
	}
	confirm := ctrConfirmBody(t, rec.Body.String())

	// A selection outside the shown plan: the digest no longer matches.
	tampered := url.Values{}
	for k, v := range confirm {
		tampered[k] = slices.Clone(v)
	}
	tampered.Add("svc", "web-01/site/proxy")
	tampered.Add("svc", "web-01/site/sidecar")
	if rec := ctrPost(t, h, tampered.Encode()); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "changed since you reviewed") {
		t.Fatalf("tampered plan: %d %s", rec.Code, rec.Body.String())
	}
	// A query string cannot add a selection or confirm (PostForm only).
	req := formPost("/inventory/containers/plan?svc=web-01/site/proxy&confirm=1&plan_digest="+confirm.Get("plan_digest"), selection())
	rec2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("query selection: %d", rec2.Code)
	}
	// The preview changed after review: refused, nothing proposed.
	f.previews["web-01"] = ctrPreview(ctrOtherID)
	if rec := ctrPost(t, h, confirm.Encode()); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no longer the newest") {
		t.Fatalf("stale at confirm: %d %s", rec.Code, rec.Body.String())
	}
	if len(f.proposed) != 0 {
		t.Fatal("a tampered or stale plan was proposed")
	}
}

func TestContainerCriticalHasNoSeparateApproval(t *testing.T) {
	h, f := ctrHandler(t, false)
	f.proposeErr = &executions.BatchCriticalError{Container: true, Members: []executions.BatchMemberView{{MemberID: "m-001", ActionID: "docker.compose_update", HostID: "web-01"}}}
	rec := ctrPost(t, h, selection("svc", "web-01/site/web"))
	rec = ctrPost(t, h, ctrConfirmBody(t, rec.Body.String()).Encode())
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("critical: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, executions.BatchCriticalContainerAdvice) || strings.Contains(body, "approve each separately") {
		t.Fatalf("critical text %q", body)
	}
}

func TestContainerPagesNeverShowSecrets(t *testing.T) {
	h, _ := ctrHandler(t, true)
	pages := []string{getBody(t, h.Handler(), "/inventory/containers")}
	rec := ctrPost(t, h, selection("svc", "web-01/site/web", "rollback", "web-01/"+ctrUpdateID))
	pages = append(pages, rec.Body.String())
	for i, p := range pages {
		if strings.Contains(p, ctrPlanted) {
			t.Errorf("page %d shows the planted value", i)
		}
	}
}

func TestChartLinksEachHostToItsContainerUpdates(t *testing.T) {
	h, _ := ctrHandler(t, false)
	body := getBody(t, h.Handler(), "/inventory/chart")
	if !strings.Contains(body, `href="/inventory/containers?host=web-01"`) {
		t.Error("the chart does not link web-01 to its container updates")
	}
	plain, _ := stagedChartHandler(t, false)
	if strings.Contains(getBody(t, plain.Handler(), "/inventory/chart"), "/inventory/containers") {
		t.Error("the chart links container updates without a planner")
	}
}

func TestContainerControlsAbsentWithoutPlanner(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example", Hosts: func(context.Context) ([]inventory.Host, error) { return ctrHosts(), nil }})
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/inventory/containers", nil),
		formPost("/inventory/containers/plan", selection("svc", "web-01/site/web")),
	} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", req.Method, req.URL.Path, rec.Code)
		}
	}
}
