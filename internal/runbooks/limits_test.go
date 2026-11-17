// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// Documented limits, pinned as literals on purpose. The tests must not read
// them back from the code under test: a loosened bound has to fail here.
// Units follow the code: title, description, label and user are counted in
// bytes (len), and the body in bytes.
const (
	limSlug         = 40        // slug: 1 leading character + up to 39 more
	limUser         = 64        // user name, printable ASCII
	limTitle        = 100       // title, bytes
	limDescription  = 2000      // description, bytes
	limBody         = 256 << 10 // script, bytes (256 KiB)
	limTimeoutMinS  = 10        // timeout minimum, seconds
	limTimeoutS     = 600       // attached timeout maximum, seconds (10 min)
	limDurableTimeS = 21600     // durable timeout maximum, seconds (6 h)
	limParams       = 10        // parameters per runbook
	limSecrets      = 8         // secret slots per runbook
	limLabel        = 100       // parameter label, bytes
	limChoices      = 20        // values per choice parameter
)

// requireInvalid asserts that Validate rejects d with an InvalidError whose
// reason contains want. A rejection for any other reason fails the test,
// because then the limit under test was never the thing that refused d.
func requireInvalid(t *testing.T, name string, d Draft, want string) {
	t.Helper()
	err := Validate(d)
	var ie *InvalidError
	if !errors.As(err, &ie) {
		t.Errorf("%s: want InvalidError, got %v", name, err)
		return
	}
	if !strings.Contains(ie.Reason, want) {
		t.Errorf("%s: rejected for another reason %q, want it to contain %q", name, ie.Reason, want)
	}
}

// requireValid asserts that Validate accepts d.
func requireValid(t *testing.T, name string, d Draft) {
	t.Helper()
	if err := Validate(d); err != nil {
		t.Errorf("%s: want accepted, got %v", name, err)
	}
}

// storeWithDB opens a fresh server database and returns the store and the
// database handle, so tests can count what was stored.
func storeWithDB(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), db
}

// storedCounts returns the number of runbooks and runbook versions stored.
func storedCounts(t *testing.T, db *sql.DB) (runbooks, versions int) {
	t.Helper()
	if err := db.QueryRow(`SELECT count(*) FROM runbooks`).Scan(&runbooks); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM runbook_versions`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	return runbooks, versions
}

// slugOf returns a valid slug of exactly n characters.
func slugOf(n int) string { return "a" + strings.Repeat("a", n-1) }

func TestSlugLengthLimit(t *testing.T) {
	d := draft()
	d.Slug = slugOf(limSlug)
	requireValid(t, "slug at limit", d)
	d.Slug = slugOf(limSlug + 1)
	requireInvalid(t, "slug limit+1", d, "the name must be 1 to 40 lowercase")
	d.Slug = "new"
	requireInvalid(t, "reserved slug", d, "the name must be 1 to 40 lowercase")
}

func TestTitleLimit(t *testing.T) {
	d := draft()
	d.Title = strings.Repeat("t", limTitle)
	requireValid(t, "title at limit", d)
	d.Title = strings.Repeat("t", limTitle+1)
	requireInvalid(t, "title limit+1", d, "the title must be 1 to 100 characters")
}

// TestTitleLimitCountsBytes pins the unit the code enforces for multibyte
// text: "ä" is two bytes, so 50 of them are exactly at the 100-byte limit and
// 51 are over it. The user-facing message says "characters"; the byte unit is
// a known mismatch recorded in the implementation report.
func TestTitleLimitCountsBytes(t *testing.T) {
	d := draft()
	d.Title = strings.Repeat("ä", limTitle/2)
	requireValid(t, "multibyte title at byte limit", d)
	d.Title = strings.Repeat("ä", limTitle/2+1)
	requireInvalid(t, "multibyte title byte limit+1", d, "the title must be 1 to 100 characters")
}

func TestDescriptionLimit(t *testing.T) {
	d := draft()
	d.Description = strings.Repeat("d", limDescription)
	requireValid(t, "description at limit", d)
	d.Description = strings.Repeat("d", limDescription+1)
	requireInvalid(t, "description limit+1", d, "the description must be at most 2000 characters")
}

// TestDescriptionLimitCountsBytes pins the byte unit for multibyte text, as
// TestTitleLimitCountsBytes does for titles.
func TestDescriptionLimitCountsBytes(t *testing.T) {
	d := draft()
	d.Description = strings.Repeat("ä", limDescription/2)
	requireValid(t, "multibyte description at byte limit", d)
	d.Description = strings.Repeat("ä", limDescription/2+1)
	requireInvalid(t, "multibyte description byte limit+1", d, "the description must be at most 2000 characters")
}

func TestBodyLimit(t *testing.T) {
	// A comment keeps the script valid shell at exactly limBody bytes.
	d := draft()
	d.Body = "# " + strings.Repeat("x", limBody-3) + "\n"
	if len(d.Body) != limBody {
		t.Fatalf("test body is %d bytes, want %d", len(d.Body), limBody)
	}
	requireValid(t, "body at limit", d)
	d.Body = "# " + strings.Repeat("x", limBody-2) + "\n"
	requireInvalid(t, "body limit+1", d, "the script must be 1 byte to 256 KiB")
}

func TestTimeoutLimits(t *testing.T) {
	d := draft()
	d.TimeoutS = limTimeoutMinS
	requireValid(t, "timeout at minimum", d)
	d.TimeoutS = limTimeoutMinS - 1
	requireInvalid(t, "timeout minimum-1", d, "the timeout must be 10 to 600 seconds")

	d = draft()
	d.TimeoutS = limTimeoutS
	requireValid(t, "attached timeout at limit", d)
	d.TimeoutS = limTimeoutS + 1
	requireInvalid(t, "attached timeout limit+1", d, "the timeout must be 10 to 600 seconds")

	d = draft()
	d.Durable, d.TimeoutS = true, limDurableTimeS
	requireValid(t, "durable timeout at limit", d)
	d.TimeoutS = limDurableTimeS + 1
	requireInvalid(t, "durable timeout limit+1", d, "the timeout must be 10 to 21600 seconds")
}

func TestParamCountLimit(t *testing.T) {
	params := func(n int) []Param {
		out := make([]Param, n)
		for i := range out {
			out[i] = Param{Name: fmt.Sprintf("p%d", i+1), Label: "L", Type: TypeInt}
		}
		return out
	}
	d := draft()
	d.Params = params(limParams)
	requireValid(t, "parameters at limit", d)
	d.Params = params(limParams + 1)
	requireInvalid(t, "parameters limit+1", d, "at most 10 parameters")
}

func TestSecretCountLimit(t *testing.T) {
	slots := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("s%d", i+1)
		}
		return out
	}
	d := draft()
	d.Params, d.Secrets = nil, slots(limSecrets)
	requireValid(t, "secret slots at limit", d)
	d.Secrets = slots(limSecrets + 1)
	requireInvalid(t, "secret slots limit+1", d, "at most 8 secret slots")
}

func TestParamLabelLimit(t *testing.T) {
	d := draft()
	d.Params = []Param{{Name: "unit", Label: strings.Repeat("l", limLabel), Type: TypeName}}
	requireValid(t, "label at limit", d)
	d.Params[0].Label = strings.Repeat("l", limLabel+1)
	requireInvalid(t, "label limit+1", d, "needs a label of 1 to 100 characters")
	// Byte unit, as for titles: 50 "ä" are 100 bytes.
	d.Params[0].Label = strings.Repeat("ä", limLabel/2)
	requireValid(t, "multibyte label at byte limit", d)
	d.Params[0].Label = strings.Repeat("ä", limLabel/2+1)
	requireInvalid(t, "multibyte label byte limit+1", d, "needs a label of 1 to 100 characters")
}

func TestChoiceCountLimit(t *testing.T) {
	choices := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("v%d", i+1)
		}
		return out
	}
	d := draft()
	d.Params = []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: choices(limChoices)}}
	requireValid(t, "choices at limit", d)
	d.Params[0].Choices = choices(limChoices + 1)
	requireInvalid(t, "choices limit+1", d, "a choice has 1 to 20 values")
}

// TestSaveRejectsLimitPlusOneAndStoresNothing runs every limit+1 case through
// Save: each must fail with the same reason Validate gives, and must leave
// no runbook or version behind.
func TestSaveRejectsLimitPlusOneAndStoresNothing(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*Draft)
		reason string
	}{
		{"slug", func(d *Draft) { d.Slug = slugOf(limSlug + 1) }, "the name must be 1 to 40 lowercase"},
		{"title", func(d *Draft) { d.Title = strings.Repeat("t", limTitle+1) }, "the title must be 1 to 100 characters"},
		{"description", func(d *Draft) { d.Description = strings.Repeat("d", limDescription+1) }, "the description must be at most 2000 characters"},
		{"body", func(d *Draft) { d.Body = "# " + strings.Repeat("x", limBody-2) + "\n" }, "the script must be 1 byte to 256 KiB"},
		{"timeout", func(d *Draft) { d.TimeoutS = limTimeoutS + 1 }, "the timeout must be 10 to 600 seconds"},
		{"parameters", func(d *Draft) {
			d.Params = nil
			for i := 0; i <= limParams; i++ {
				d.Params = append(d.Params, Param{Name: fmt.Sprintf("p%d", i+1), Label: "L", Type: TypeInt})
			}
		}, "at most 10 parameters"},
		{"secret slots", func(d *Draft) {
			d.Params = nil
			d.Secrets = nil
			for i := 0; i <= limSecrets; i++ {
				d.Secrets = append(d.Secrets, fmt.Sprintf("s%d", i+1))
			}
		}, "at most 8 secret slots"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := storeWithDB(t)
			d := draft()
			c.mut(&d)
			_, err := s.Save(context.Background(), "alice", d)
			var ie *InvalidError
			if !errors.As(err, &ie) || !strings.Contains(ie.Reason, c.reason) {
				t.Fatalf("Save: want InvalidError containing %q, got %v", c.reason, err)
			}
			if rb, v := storedCounts(t, db); rb != 0 || v != 0 {
				t.Fatalf("rejected save stored %d runbooks and %d versions", rb, v)
			}
		})
	}
}

// TestSaveUserLimit pins the user name limit (64 printable bytes) on Save.
// The rejection must come from the user check, and nothing may be stored.
func TestSaveUserLimit(t *testing.T) {
	ctx := context.Background()
	s, db := storeWithDB(t)
	atLimit := strings.Repeat("u", limUser)
	v, err := s.Save(ctx, atLimit, draft())
	if err != nil {
		t.Fatalf("user at limit: %v", err)
	}
	if v.CreatedBy != atLimit || v.Version != 1 {
		t.Fatalf("user at limit: stored CreatedBy %q version %d", v.CreatedBy, v.Version)
	}
	rbBefore, verBefore := storedCounts(t, db)

	_, err = s.Save(ctx, strings.Repeat("u", limUser+1), draft())
	if err == nil || err.Error() != "runbooks: invalid user" {
		t.Fatalf("user limit+1: want \"runbooks: invalid user\", got %v", err)
	}
	var ie *InvalidError
	if errors.As(err, &ie) {
		t.Fatalf("user limit+1: rejected by draft validation (%v), not by the user check", err)
	}
	if rb, ver := storedCounts(t, db); rb != rbBefore || ver != verBefore {
		t.Fatalf("user limit+1 stored data: runbooks %d->%d, versions %d->%d", rbBefore, rb, verBefore, ver)
	}
}

// FuzzParseActionVersion checks that ParseActionVersion never panics and
// that an accepted pair maps back to the same action ID and module version.
func FuzzParseActionVersion(f *testing.F) {
	f.Add("runbook.web", "3.0.0")
	f.Add("runbook.web", "")
	f.Add("runbook.web", "0.0.0")
	f.Add("runbook.web", "03.0.0")
	f.Add("runbook.", "1.0.0")
	f.Add("core.facts", "1.0.0")
	f.Add("runbook.web", "99999999999999999999.0.0")
	f.Fuzz(func(t *testing.T, actionID, moduleVersion string) {
		slug, version, ok := ParseActionVersion(actionID, moduleVersion)
		if !ok {
			return
		}
		v := Version{Draft: Draft{Slug: slug}, Version: version}
		if v.ActionID() != actionID {
			t.Fatalf("%q %q: slug %q gives action %q", actionID, moduleVersion, slug, v.ActionID())
		}
		if moduleVersion == "" {
			if version != 0 {
				t.Fatalf("%q without module version: version %d", actionID, version)
			}
			return
		}
		if v.ModuleVersion() != moduleVersion {
			t.Fatalf("%q %q: version %d gives module version %q", actionID, moduleVersion, version, v.ModuleVersion())
		}
		if version < 1 {
			t.Fatalf("%q %q: accepted version %d", actionID, moduleVersion, version)
		}
	})
}
