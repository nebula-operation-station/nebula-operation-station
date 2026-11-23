// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// imageRef is a digest-pinned image of the image.packages form.
var imageRef = "registry.example/app/web@sha256:" + strings.Repeat("a", 64)

// imageFake is the fake lease store with the image lease methods. It
// embeds the shared fakeLeases, so the other lease pages see the same data.
type imageFake struct {
	*fakeLeases
	options    []executions.ImageLeaseOption
	optErr     error
	optHosts   []string
	preview    executions.ReadGrantPreview
	proposeErr error
	proposed   []executions.ImageReadGrantRequest
}

// ImageLeaseOptions records the host and returns the configured pairs.
func (f *imageFake) ImageLeaseOptions(_ context.Context, host string) ([]executions.ImageLeaseOption, error) {
	f.optHosts = append(f.optHosts, host)
	return f.options, f.optErr
}

// ProposeImageReadGrant records the request and returns the configured preview.
func (f *imageFake) ProposeImageReadGrant(_ context.Context, _ string, in executions.ImageReadGrantRequest) (executions.ReadGrantPreview, error) {
	f.proposed = append(f.proposed, in)
	return f.preview, f.proposeErr
}

// ImageLeaseOptions makes the shared fake a Leases with no image pairs; the
// image tests use imageFake, which shadows this method.
func (f *fakeLeases) ImageLeaseOptions(context.Context, string) ([]executions.ImageLeaseOption, error) {
	return nil, nil
}

// ProposeImageReadGrant makes the shared fake a Leases that refuses image
// proposals; the image tests use imageFake, which shadows this method.
func (f *fakeLeases) ProposeImageReadGrant(context.Context, string, executions.ImageReadGrantRequest) (executions.ReadGrantPreview, error) {
	return executions.ReadGrantPreview{}, errors.New("image proposals are not faked here")
}

// imageHosts is the inventory of the image section: web-1 and an
// untrusted-looking host name that must only ever appear escaped.
func imageHosts() func(context.Context) ([]inventory.Host, error) {
	return func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{{ID: "web-1"}, {ID: "<b>evil</b>"}}, nil
	}
}

func imageHandler(t *testing.T, f *imageFake, clock *leaseClock) http.Handler {
	t.Helper()
	o := ui.Options{PublicOrigin: leaseOrigin, Leases: f, Hosts: imageHosts()}
	if clock != nil {
		o.Now = clock.Now
	}
	return newTestHandler(t, o).Handler()
}

func imagePairs() []executions.ImageLeaseOption {
	return []executions.ImageLeaseOption{{Container: "c1", Image: imageRef}}
}

// imagePreview is a browser-approved image lease preview on web-1.
func imagePreview() executions.ReadGrantPreview {
	return executions.ReadGrantPreview{
		ID: leaseID, Digest: leaseDigest, ScopeKind: "hosts",
		Targets: []executions.ReadGrantPreviewTarget{
			{HostID: "web-1", HostKeyFingerprint: "SHA256:hostkey", CredentialRef: "default", CredentialVersion: "SHA256:credversion"},
		},
		Actions: []executions.ReadGrantPreviewAction{
			{ActionID: "docker.inspect", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("d", 64), ParametersHash: strings.Repeat("e", 64)},
			{ActionID: "image.packages", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("f", 64), ParametersHash: strings.Repeat("1", 64)},
		},
		Params: map[string]map[string]string{
			"docker.inspect": {"container": "c1"},
			"image.packages": {"image": imageRef},
		},
		Issuer:  "nebula-server",
		Created: time.Unix(1_800_000_000, 0).UTC(), Expiry: time.Unix(1_800_000_000+7*86400, 0).UTC(),
		Trigger: "both", RateProfile: "ordinary", MinInterval: executions.ImageLeaseInterval, RunBudget: executions.ImageLeaseRunBudget,
		Options:         []byte(`{"publicKey":{"challenge":"abc"}}`),
		ChallengeExpiry: time.Unix(1_800_000_300, 0).UTC(),
	}
}

// imageFormBody is the form the image section posts for c1 on web-1.
func imageFormBody(days string) string {
	return "scope=image&host=web-1&pair=c1%7C" + imageRef + "&days=" + days
}

func TestImageLeaseFormRendersSectionAndPairs(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, options: imagePairs()}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new?image_host=web-1")
	for _, want := range []string{
		"Image packages (one container image)",
		`name="image_host"`,
		`value="web-1" selected`,
		`name="scope" value="image"`,
		`name="pair" value="c1|` + imageRef + `"`,
		`<span class="mono">c1</span>`,
		"7 days", "30 days",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("form page lacks %q", want)
		}
	}
	if len(f.optHosts) != 1 || f.optHosts[0] != "web-1" {
		t.Fatalf("pairs read for hosts %v, want [web-1]", f.optHosts)
	}
}

func TestImageLeaseFormWithoutHostReadsNoPairs(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, options: imagePairs()}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new")
	if len(f.optHosts) != 0 {
		t.Errorf("pairs read without a host: %v", f.optHosts)
	}
	if !strings.Contains(page, `name="image_host"`) || strings.Contains(page, `name="pair"`) {
		t.Error("host choice missing, or pairs offered without a host")
	}
}

func TestImageLeaseFormWithoutPairsExplainsHowToGetThem(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new?image_host=web-1")
	for _, want := range []string{"docker.inspect", "Trivy"} {
		if !strings.Contains(page, want) {
			t.Errorf("empty pair hint lacks %q", want)
		}
	}
}

func TestImageLeaseFormHostTextIsEscaped(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, options: imagePairs()}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new?image_host=web-1")
	if strings.Contains(page, "<b>evil</b>") {
		t.Fatal("inventory host name rendered as HTML")
	}
	if !strings.Contains(page, "&lt;b&gt;evil&lt;/b&gt;") {
		t.Error("escaped inventory host name missing")
	}
}

func TestImageLeaseFormUnknownHostReadsNoPairs(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, options: imagePairs()}
	getBody(t, imageHandler(t, f, nil), "/leases/new?image_host=not-in-inventory")
	if len(f.optHosts) != 0 {
		t.Errorf("pairs read for a host outside the inventory: %v", f.optHosts)
	}
}

func TestImageLeaseFormLimitsPairsTo200(t *testing.T) {
	var opts []executions.ImageLeaseOption
	for i := 0; i < 250; i++ {
		opts = append(opts, executions.ImageLeaseOption{Container: "c" + strings.Repeat("x", i%5) + string(rune('a'+i%26)), Image: imageRef})
	}
	f := &imageFake{fakeLeases: &fakeLeases{}, options: opts}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new?image_host=web-1")
	if got := strings.Count(page, `name="pair" value="`); got != 200 {
		t.Fatalf("pairs offered = %d, want 200", got)
	}
}

func TestGeneralLeaseFormDoesNotOfferImagePackages(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, options: imagePairs()}
	page := getBody(t, imageHandler(t, f, nil), "/leases/new")
	if strings.Contains(page, `name="action" value="image.packages"`) {
		t.Fatal("the general form offers image.packages")
	}
}

func TestImageLeasePreviewRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct{ name, form string }{
		{"bad host", "scope=image&host=" + "web%201&pair=c1%7C" + imageRef + "&days=7"},
		{"no pair", "scope=image&host=web-1&days=7"},
		{"pair without separator", "scope=image&host=web-1&pair=c1&days=7"},
		{"bad container", "scope=image&host=web-1&pair=" + "c%201%7C" + imageRef + "&days=7"},
		{"image without digest", "scope=image&host=web-1&pair=c1%7Cregistry.example%2Fweb%3Alatest&days=7"},
		{"bad days", imageFormBody("3")},
		{"oversized pair", "scope=image&host=web-1&pair=" + strings.Repeat("a", 700) + "&days=7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &imageFake{fakeLeases: &fakeLeases{}, preview: imagePreview()}
			code, _ := postLeaseForm(t, imageHandler(t, f, nil), "/leases/preview", tc.form)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", code)
			}
			if len(f.proposed) != 0 {
				t.Fatal("malformed input reached the service")
			}
		})
	}
}

func TestImageLeasePreviewUnknownPairIsFixedError(t *testing.T) {
	const reason = "no recent inspection of this host names this container and image"
	f := &imageFake{fakeLeases: &fakeLeases{}, proposeErr: &executions.ReadGrantInputError{Reason: reason}}
	code, body := postLeaseForm(t, imageHandler(t, f, nil), "/leases/preview", imageFormBody("7"))
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if strings.TrimSpace(body) != reason {
		t.Errorf("body = %q, want the fixed reason", body)
	}
}

func TestImageLeasePreviewThrottle(t *testing.T) {
	clock := &leaseClock{t: time.Unix(1_800_000_000, 0)}
	f := &imageFake{fakeLeases: &fakeLeases{}, preview: imagePreview()}
	h := imageHandler(t, f, clock)
	if code, _ := postLeaseForm(t, h, "/leases/preview", imageFormBody("7")); code != http.StatusSeeOther {
		t.Fatalf("first preview = %d, want 303", code)
	}
	clock.Add(9 * time.Second)
	code, _ := postLeaseForm(t, h, "/leases/preview", imageFormBody("7"))
	if code != http.StatusTooManyRequests {
		t.Fatalf("second preview within 10 s = %d, want 429", code)
	}
	if len(f.proposed) != 1 {
		t.Fatalf("a throttled preview reached the executor (%d proposals)", len(f.proposed))
	}
}

func TestImageLeasePreviewNeedsSameOriginPost(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		want         int
	}{
		{"plain form post", "null", http.StatusForbidden},
		{"no origin", "", http.StatusForbidden},
		{"cross origin", "https://evil.example.org", http.StatusForbidden},
		{"fetch post", leaseOrigin, http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &imageFake{fakeLeases: &fakeLeases{}, preview: imagePreview()}
			u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Leases: f, Hosts: imageHosts()})
			srv, err := u.Server()
			if err != nil {
				t.Fatalf("ui server: %v", err)
			}
			ts := httptest.NewServer(srv.Handler)
			t.Cleanup(ts.Close)
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/leases/preview", strings.NewReader(imageFormBody("7")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("POST with Origin %q = %d, want %d", tc.origin, res.StatusCode, tc.want)
			}
			wantProposed := 0
			if tc.want == http.StatusSeeOther {
				wantProposed = 1
			}
			if len(f.proposed) != wantProposed {
				t.Fatalf("proposals = %d, want %d", len(f.proposed), wantProposed)
			}
		})
	}
}

func TestImageLeasePreviewRedirectsToProposal(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, preview: imagePreview()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/leases/preview", strings.NewReader(imageFormBody("30")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	imageHandler(t, f, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/leases/proposals/"+leaseDigest {
		t.Fatalf("= %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(f.proposed) != 1 || f.proposed[0].HostID != "web-1" || f.proposed[0].Container != "c1" ||
		f.proposed[0].Image != imageRef || f.proposed[0].Days != executions.ReadGrantLongDays {
		t.Fatalf("proposed = %+v", f.proposed)
	}
}

func TestImageLeaseProposalShowsPlainParametersAnd24h(t *testing.T) {
	f := &imageFake{fakeLeases: &fakeLeases{}, preview: imagePreview()}
	h := imageHandler(t, f, nil)
	postLeaseForm(t, h, "/leases/preview", imageFormBody("7"))
	page := getBody(t, h, "/leases/proposals/"+leaseDigest)
	for _, want := range []string{
		"Parameters (plain text)",
		"<td class=\"mono\">docker.inspect</td><td class=\"mono\">container</td><td class=\"mono\">c1</td>",
		"<td class=\"mono\">image.packages</td><td class=\"mono\">image</td><td class=\"mono\">" + imageRef + "</td>",
		"each action at most every 24 h",
		"at most 2 runs per host per hour",
		"<td class=\"mono\">web-1</td>",
		"SHA256:hostkey",
		"SHA256:credversion",
		"Approve with security key",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("proposal page lacks %q", want)
		}
	}
}

func TestImageLeaseProposalCLIHardenedShowsCommand(t *testing.T) {
	v := imagePreview()
	v.CLI, v.Options = true, nil
	f := &imageFake{fakeLeases: &fakeLeases{}, preview: v}
	h := imageHandler(t, f, nil)
	postLeaseForm(t, h, "/leases/preview", imageFormBody("7"))
	page := getBody(t, h, "/leases/proposals/"+leaseDigest)
	if !strings.Contains(page, `id="lease-cli"`) || strings.Contains(page, "Approve with security key") {
		t.Error("hardened proposal does not show the CLI command instead of the button")
	}
}

func TestImageLeaseListShowsContainerAndRefreshesToHostForm(t *testing.T) {
	g := executions.ReadGrantView{
		ID: leaseID, State: "active", ScopeKind: "hosts", Hosts: []string{"web-1"},
		Actions: []string{"docker.inspect", "image.packages"},
		Params: map[string]map[string]string{
			"docker.inspect": {"container": "c1"},
			"image.packages": {"image": imageRef},
		},
		Expiry: time.Now().Add(time.Hour),
	}
	f := &imageFake{fakeLeases: &fakeLeases{grants: []executions.ReadGrantView{g}}}
	h := imageHandler(t, f, nil)
	list := getBody(t, h, "/leases")
	for _, want := range []string{"c1", imageRef, `href="/leases/new?image_host=web-1"`} {
		if !strings.Contains(list, want) {
			t.Errorf("lease list lacks %q", want)
		}
	}
}

func TestImageLeaseListWithoutParamsHasNoImageRefresh(t *testing.T) {
	g := executions.ReadGrantView{ID: leaseID, State: "active", ScopeKind: "hosts", Hosts: []string{"web-1"},
		Actions: []string{"core.facts"}, Expiry: time.Now().Add(time.Hour)}
	f := &imageFake{fakeLeases: &fakeLeases{grants: []executions.ReadGrantView{g}}}
	if list := getBody(t, imageHandler(t, f, nil), "/leases"); strings.Contains(list, "image_host") {
		t.Error("a lease without image parameters links to the image form")
	}
}
