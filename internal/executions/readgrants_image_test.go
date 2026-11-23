// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// imageTestNow is the fixed clock of the image lease tests.
var imageTestNow = time.Unix(1_800_000_000, 0)

// imageTestRef is the digest-pinned image the test inspections name.
var imageTestRef = "registry.example/app/web@sha256:" + strings.Repeat("d", 64)

// inspectFixture is a successful docker-inspect-v1 result of container whose
// image has the given repository digests (the shape docker.inspect stores).
func inspectFixture(container string, repoDigests ...string) []byte {
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	inner := `{"id":"` + strings.Repeat("a", 64) + `","name":"/` + container + `","image":"img","image_id":"sha256:` +
		strings.Repeat("c", 64) + `","created":"2026-01-02T03:04:05Z","state":{"Status":"running","StartedAt":"2026-01-01T00:00:00Z"}}`
	quoted := make([]string, 0, len(repoDigests))
	for _, d := range repoDigests {
		quoted = append(quoted, `"`+d+`"`)
	}
	image := `{"id":"sha256:` + strings.Repeat("c", 64) + `","created":"2026-01-01T00:00:00Z",` +
		`"os":"linux","architecture":"amd64","repo_digests":[` + strings.Join(quoted, ",") + `]}`
	return []byte(`{"format":"docker-inspect-v1","phase":"done","container":"` + container + `","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(image)) + `"}`)
}

// insertInspectRun stores one finished, successful docker.inspect execution
// of host with result at finished.
func insertInspectRun(t *testing.T, db *sql.DB, n int, host string, finished time.Time, result []byte) {
	t.Helper()
	id := fmt.Sprintf("%036d", n)
	if _, err := db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement,
		state, durable, timeout_s, created_by, created_at, finished_at) VALUES (?, '', 'docker.inspect', '1.0.0', ?, 'low', '',
		'finished', 0, 60, 'alice', ?, ?)`, id, strings.Repeat("a", 64), finished.Unix(), finished.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class,
		result, started_at, finished_at) VALUES (?, ?, ?, 'default', '[]', 'finished', 'success', ?, ?, ?)`,
		id, host, testHostFP, result, finished.Unix(), finished.Unix()); err != nil {
		t.Fatal(err)
	}
}

// imageService returns a service on a fresh server.db with the fake executor
// f, the clock at imageTestNow and the test inventory.
func imageService(t *testing.T, f Executor) (*Service, *sql.DB, *bytes.Buffer) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var audit bytes.Buffer
	s := New(context.Background(), f, db, readGrantHostsFrom(testInventory()), slog.New(slog.NewTextHandler(&audit, nil)))
	s.now = func() time.Time { return imageTestNow }
	return s, db, &audit
}

// withInspect stores one recent successful inspect of web naming container c1.
func withInspect(t *testing.T, db *sql.DB) {
	t.Helper()
	insertInspectRun(t, db, 1, "web", imageTestNow.Add(-time.Hour), inspectFixture("c1", imageTestRef))
}

func imageRequest(container, image string) ImageReadGrantRequest {
	return ImageReadGrantRequest{HostID: "web", Container: container, Image: image, Days: ReadGrantShortDays}
}

func TestImageLeaseOptionsListsRecentInspects(t *testing.T) {
	s, db, _ := imageService(t, newProposeFake())
	withInspect(t, db)
	insertInspectRun(t, db, 2, "db", imageTestNow.Add(-time.Hour), inspectFixture("c9", imageTestRef))
	got, err := s.ImageLeaseOptions(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	want := []ImageLeaseOption{{Container: "c1", Image: imageTestRef}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("options %+v, want %+v (other host's inspect must not count)", got, want)
	}
}

func TestImageLeaseOptionsSkipsStaleAndUnreadableResults(t *testing.T) {
	s, db, _ := imageService(t, newProposeFake())
	insertInspectRun(t, db, 1, "web", imageTestNow.Add(-ImageLeaseInspectMaxAge-time.Hour), inspectFixture("old", imageTestRef))
	insertInspectRun(t, db, 2, "web", imageTestNow.Add(-time.Hour), []byte(`{"format":"other"}`))
	insertInspectRun(t, db, 3, "web", imageTestNow.Add(-time.Hour), inspectFixture("c2"))
	got, err := s.ImageLeaseOptions(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("options %+v, want none: stale, unreadable and digest-less results never count", got)
	}
}

func TestProposeImageReadGrantRejectsPairNotInOptions(t *testing.T) {
	for _, tc := range []struct{ name, container, image string }{
		{"other container", "c2", imageTestRef},
		{"other image", "c1", "registry.example/app/db@sha256:" + strings.Repeat("e", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			s, db, _ := imageService(t, f)
			withInspect(t, db)
			_, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest(tc.container, tc.image))
			var ie *ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err %v, want a ReadGrantInputError", err)
			}
			if f.sent.ID != "" {
				t.Error("the executor was asked for a pair that is not in the options")
			}
		})
	}
}

func TestProposeImageReadGrantRejectsMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container string
		image     string
		days      int
	}{
		{"leading dash container", "-c1", imageTestRef, ReadGrantShortDays},
		{"space in container", "c 1", imageTestRef, ReadGrantShortDays},
		{"tag instead of digest", "c1", "registry.example/app/web:latest", ReadGrantShortDays},
		{"uppercase repository", "c1", "Registry/app@sha256:" + strings.Repeat("d", 64), ReadGrantShortDays},
		{"wrong lifetime", "c1", imageTestRef, 14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			s, db, _ := imageService(t, f)
			withInspect(t, db)
			req := imageRequest(tc.container, tc.image)
			req.Days = tc.days
			_, err := s.ProposeImageReadGrant(context.Background(), "alice", req)
			var ie *ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err %v, want a ReadGrantInputError", err)
			}
			if f.sent.ID != "" {
				t.Error("the executor was asked for malformed input")
			}
		})
	}
}

func TestProposeImageReadGrantDocument(t *testing.T) {
	f := newProposeFake()
	s, db, _ := imageService(t, f)
	withInspect(t, db)
	v, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef))
	if err != nil {
		t.Fatal(err)
	}
	d := f.sent
	if len(d.Actions) != 2 || len(d.Targets) != 1 || d.Targets[0].HostID != "web" || len(d.Credentials) != 1 {
		t.Fatalf("document scope %+v, want one host and exactly two actions", d)
	}
	if d.Grant != permit.ReadGrantFormat || d.Trigger != permit.TriggerBoth || d.RateProfile != "ordinary" ||
		d.MinIntervalS != 86400 || d.RunBudget != 2 {
		t.Errorf("document %+v, want ordinary, both triggers, 24 h, budget 2", d)
	}
	if !time.Unix(d.ExpiryUnix, 0).Equal(imageTestNow.Add(7 * 24 * time.Hour)) {
		t.Errorf("expiry %v", time.Unix(d.ExpiryUnix, 0))
	}
	hashOf := func(raw string) string {
		h, err := canonical.HashParameters([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	wantHash := map[string]string{"docker.inspect": hashOf(`{"container":"c1"}`), "image.packages": hashOf(`{"image":"` + imageTestRef + `"}`)}
	for _, a := range d.Actions {
		if a.ParametersHash != wantHash[a.ActionID] {
			t.Errorf("action %s hash %s, want %s", a.ActionID, a.ParametersHash, wantHash[a.ActionID])
		}
	}
	if _, _, _, err := permit.ParseReadGrant(marshalDoc(t, d), imageTestNow); err != nil {
		t.Errorf("the sent document does not parse as a read grant: %v", err)
	}
	if got := v.Params["docker.inspect"]["container"]; got != "c1" {
		t.Errorf("preview params %+v, want the container", v.Params)
	}
	if got := v.Params["image.packages"]["image"]; got != imageTestRef {
		t.Errorf("preview params %+v, want the image", v.Params)
	}
}

func TestProposeImageReadGrantExcludesUnusableHost(t *testing.T) {
	f := newProposeFake("web")
	s, db, _ := imageService(t, f)
	withInspect(t, db)
	_, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef))
	var ie *ReadGrantInputError
	if !errors.As(err, &ie) {
		t.Fatalf("err %v, want a ReadGrantInputError for a blocked host", err)
	}
	if f.sent.ID != "" {
		t.Error("a blocked host was proposed")
	}
}

func TestProposeImageReadGrantRejectsChangedAnswer(t *testing.T) {
	f := newProposeFake()
	f.alter = func(d *permit.ReadGrantDoc) { d.RunBudget = 3 }
	s, db, _ := imageService(t, f)
	withInspect(t, db)
	if _, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef)); !errors.Is(err, ErrReadGrantProposalMismatch) {
		t.Fatalf("err %v, want ErrReadGrantProposalMismatch", err)
	}
}

func TestProposeImageReadGrantPersistsParamsAndPrunes(t *testing.T) {
	f := newProposeFake()
	s, db, _ := imageService(t, f)
	withInspect(t, db)
	stale := strings.Repeat("9", 36)
	if _, err := db.Exec(`INSERT INTO read_grant_params (grant_id, action_id, params, created_at) VALUES (?, 'docker.inspect', '{"container":"x"}', ?)`,
		stale, imageTestNow.Add(-(permit.ReadGrantMaxLifetime + 25*time.Hour)).Unix()); err != nil {
		t.Fatal(err)
	}
	v, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM read_grant_params WHERE grant_id = ?`, v.ID).Scan(&n); err != nil || n != 2 {
		t.Errorf("rows of the grant %d (%v), want 2", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM read_grant_params WHERE grant_id = ?`, stale).Scan(&n); err != nil || n != 0 {
		t.Errorf("stale rows %d (%v), want them removed", n, err)
	}
}

func TestReadGrantsShowsImageParamsOnlyWhenHashMatches(t *testing.T) {
	f := newProposeFake()
	s, db, _ := imageService(t, f)
	withInspect(t, db)
	v, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.sent)
	f.grants = []*pb.ReadGrant{{GrantId: v.ID, GrantDigest: testDigest, CanonicalGrant: raw, ApprovedBy: "alice",
		CreatedUnix: f.sent.CreatedUnix, ExpiryUnix: f.sent.ExpiryUnix}}
	got, err := s.ReadGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Params["docker.inspect"]["container"] != "c1" || got[0].Params["image.packages"]["image"] != imageTestRef {
		t.Fatalf("views %+v, want the stored parameters", got)
	}
	if _, err := db.Exec(`UPDATE read_grant_params SET params = '{"container":"other"}' WHERE grant_id = ? AND action_id = 'docker.inspect'`, v.ID); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0].Params) != 1 || got[0].Params["image.packages"]["image"] != imageTestRef {
		t.Errorf("params %+v: a row whose hash does not match the document must not be shown", got[0].Params)
	}
	if _, ok := got[0].Params["docker.inspect"]; ok {
		t.Error("a mismatching parameter row was shown")
	}
}

func TestImageProposalAuditOmitsImageName(t *testing.T) {
	f := newProposeFake()
	s, db, audit := imageService(t, f)
	withInspect(t, db)
	if _, err := s.ProposeImageReadGrant(context.Background(), "alice", imageRequest("c1", imageTestRef)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit.String(), "read_grant_proposed") {
		t.Errorf("proposal not audited: %s", audit.String())
	}
	if strings.Contains(audit.String(), "registry.example") || strings.Contains(audit.String(), imageTestRef) ||
		strings.Contains(audit.String(), "container=") {
		t.Errorf("audit names the image or container: %s", audit.String())
	}
}

func TestImageActionsStayOutOfGenericLeases(t *testing.T) {
	for _, id := range []string{"docker.inspect", "image.packages"} {
		for _, got := range ReadGrantActionIDs() {
			if got == id {
				t.Errorf("%s is offered by the generic lease form", id)
			}
		}
		if err := checkReadGrantRequest(ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{id}, Days: ReadGrantShortDays}); err == nil {
			t.Errorf("the generic lease form accepts %s", id)
		}
	}
}
