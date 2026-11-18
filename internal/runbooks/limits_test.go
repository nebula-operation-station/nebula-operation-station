// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// Documented limits, pinned as literals on purpose. The tests must not read
// them back from the code under test: a loosened bound has to fail here.
// Units follow the code: title and description are counted in bytes (len),
// the body in bytes. Every limit below has an at-limit and a limit+1 test.
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
	limName         = 32        // parameter and secret slot names (prelude nameRe)
	limLabel        = 100       // parameter label, bytes
	limChoices      = 20        // values per choice parameter
	limChoiceValue  = 63        // one choice value, characters (prelude choiceRe)
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

// slugOf returns a valid name of exactly n characters.
func slugOf(n int) string { return "a" + strings.Repeat("a", n-1) }

// paramsOf returns n int parameters named p1..pn.
func paramsOf(n int) []Param {
	out := make([]Param, n)
	for i := range out {
		out[i] = Param{Name: fmt.Sprintf("p%d", i+1), Label: "L", Type: TypeInt}
	}
	return out
}

// slotsOf returns n secret slot names s1..sn.
func slotsOf(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("s%d", i+1)
	}
	return out
}

// choicesOf returns n choice values v1..vn.
func choicesOf(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("v%d", i+1)
	}
	return out
}

func TestSlugLengthLimit(t *testing.T) {
	d := draft()
	d.Slug = slugOf(limSlug)
	requireValid(t, "slug at limit", d)
	d.Slug = slugOf(limSlug + 1)
	requireInvalid(t, "slug limit+1", d, "the name must be 1 to 40 lowercase")
}

// TestReservedSlugNewIsRefused pins the reserved name on its own: "new" is
// refused for being reserved, while a name that only starts with it is fine.
func TestReservedSlugNewIsRefused(t *testing.T) {
	d := draft()
	d.Slug = "new"
	requireInvalid(t, "reserved slug new", d, "the name must be 1 to 40 lowercase")
	d.Slug = "news"
	requireValid(t, "slug starting with new", d)
}

func TestTitleLimit(t *testing.T) {
	d := draft()
	d.Title = strings.Repeat("t", limTitle)
	requireValid(t, "title at limit", d)
	d.Title = strings.Repeat("t", limTitle+1)
	requireInvalid(t, "title limit+1", d, "the title must be 1 to 100 bytes")
}

// TestTitleLimitCountsBytes pins the unit the code enforces for multibyte
// text: "ä" is two bytes, so 50 of them are exactly at the 100-byte limit and
// 51 are over it. The message says "bytes", matching the check.
func TestTitleLimitCountsBytes(t *testing.T) {
	d := draft()
	d.Title = strings.Repeat("ä", limTitle/2)
	requireValid(t, "multibyte title at byte limit", d)
	d.Title = strings.Repeat("ä", limTitle/2+1)
	requireInvalid(t, "multibyte title byte limit+1", d, "the title must be 1 to 100 bytes")
}

func TestDescriptionLimit(t *testing.T) {
	d := draft()
	d.Description = strings.Repeat("d", limDescription)
	requireValid(t, "description at limit", d)
	d.Description = strings.Repeat("d", limDescription+1)
	requireInvalid(t, "description limit+1", d, "the description must be at most 2000 bytes")
}

// TestDescriptionLimitCountsBytes pins the byte unit for multibyte text, as
// TestTitleLimitCountsBytes does for titles.
func TestDescriptionLimitCountsBytes(t *testing.T) {
	d := draft()
	d.Description = strings.Repeat("ä", limDescription/2)
	requireValid(t, "multibyte description at byte limit", d)
	d.Description = strings.Repeat("ä", limDescription/2+1)
	requireInvalid(t, "multibyte description byte limit+1", d, "the description must be at most 2000 bytes")
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

// TestTimeoutOverflowIsRefused covers values far outside the timeout range.
// Validate must compare the integer against the bounds before it converts to
// time.Duration: 1<<55+60 seconds times 10^9 ns is 2^64 * 5^9 + 60 s, so the
// int64 product wraps to exactly 60 s and would pass a check made after the
// conversion. The other values are the int extremes and negatives.
func TestTimeoutOverflowIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		timeout int
		durable bool
		want    string
	}{
		{"wraps to 60 s, attached", 1<<55 + 60, false, "the timeout must be 10 to 600 seconds"},
		{"wraps to 60 s, durable", 1<<55 + 60, true, "the timeout must be 10 to 21600 seconds"},
		{"max int, attached", math.MaxInt, false, "the timeout must be 10 to 600 seconds"},
		{"max int, durable", math.MaxInt, true, "the timeout must be 10 to 21600 seconds"},
		{"min int, attached", math.MinInt, false, "the timeout must be 10 to 600 seconds"},
		{"min int, durable", math.MinInt, true, "the timeout must be 10 to 21600 seconds"},
		{"negative, attached", -1, false, "the timeout must be 10 to 600 seconds"},
		{"zero, durable", 0, true, "the timeout must be 10 to 21600 seconds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := draft()
			d.Durable, d.TimeoutS = c.durable, c.timeout
			requireInvalid(t, c.name, d, c.want)
		})
	}
}

func TestParamCountLimit(t *testing.T) {
	d := draft()
	d.Params = paramsOf(limParams)
	requireValid(t, "parameters at limit", d)
	d.Params = paramsOf(limParams + 1)
	requireInvalid(t, "parameters limit+1", d, "at most 10 parameters")
}

func TestSecretCountLimit(t *testing.T) {
	d := draft()
	d.Params, d.Secrets = nil, slotsOf(limSecrets)
	requireValid(t, "secret slots at limit", d)
	d.Secrets = slotsOf(limSecrets + 1)
	requireInvalid(t, "secret slots limit+1", d, "at most 8 secret slots")
}

// TestParamNameLimit pins the 32-character parameter name limit (prelude
// nameRe: one leading letter and up to 31 more).
func TestParamNameLimit(t *testing.T) {
	d := draft()
	d.Params = []Param{{Name: slugOf(limName), Label: "L", Type: TypeInt}}
	requireValid(t, "parameter name at limit", d)
	d.Params[0].Name = slugOf(limName + 1)
	requireInvalid(t, "parameter name limit+1", d, "parameter names are 1 to 32")
}

// TestSecretSlotNameLimit pins the same 32-character limit for secret slots.
func TestSecretSlotNameLimit(t *testing.T) {
	d := draft()
	d.Params, d.Secrets = nil, []string{slugOf(limName)}
	requireValid(t, "secret slot name at limit", d)
	d.Secrets = []string{slugOf(limName + 1)}
	requireInvalid(t, "secret slot name limit+1", d, "secret slots are distinct names of 1 to 32")
}

// TestChoiceValueLimit pins the 63-character choice value limit (prelude
// choiceRe: one leading letter or digit and up to 62 more).
func TestChoiceValueLimit(t *testing.T) {
	d := draft()
	d.Params = []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: []string{slugOf(limChoiceValue)}}}
	requireValid(t, "choice value at limit", d)
	d.Params[0].Choices = []string{slugOf(limChoiceValue + 1)}
	requireInvalid(t, "choice value limit+1", d, "choices are distinct lowercase words")
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
	d := draft()
	d.Params = []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: choicesOf(limChoices)}}
	requireValid(t, "choices at limit", d)
	d.Params[0].Choices = choicesOf(limChoices + 1)
	requireInvalid(t, "choices limit+1", d, "a choice has 1 to 20 values")
}

// TestSaveRejectsLimitPlusOneAndStoresNothing runs every limit+1 case through
// Save: each must fail with the reason Validate gives, and must leave no
// runbook or version behind.
func TestSaveRejectsLimitPlusOneAndStoresNothing(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*Draft)
		reason string
	}{
		{"slug", func(d *Draft) { d.Slug = slugOf(limSlug + 1) }, "the name must be 1 to 40 lowercase"},
		{"title", func(d *Draft) { d.Title = strings.Repeat("t", limTitle+1) }, "the title must be 1 to 100 bytes"},
		{"description", func(d *Draft) { d.Description = strings.Repeat("d", limDescription+1) }, "the description must be at most 2000 bytes"},
		{"body", func(d *Draft) { d.Body = "# " + strings.Repeat("x", limBody-2) + "\n" }, "the script must be 1 byte to 256 KiB"},
		{"timeout", func(d *Draft) { d.TimeoutS = limTimeoutS + 1 }, "the timeout must be 10 to 600 seconds"},
		{"timeout minimum-1", func(d *Draft) { d.TimeoutS = limTimeoutMinS - 1 }, "the timeout must be 10 to 600 seconds"},
		{"durable timeout", func(d *Draft) { d.Durable, d.TimeoutS = true, limDurableTimeS+1 }, "the timeout must be 10 to 21600 seconds"},
		{"timeout overflow", func(d *Draft) { d.TimeoutS = 1<<55 + 60 }, "the timeout must be 10 to 600 seconds"},
		{"parameters", func(d *Draft) { d.Params = paramsOf(limParams + 1) }, "at most 10 parameters"},
		{"parameter name", func(d *Draft) { d.Params = []Param{{Name: slugOf(limName + 1), Label: "L", Type: TypeInt}} }, "parameter names are 1 to 32"},
		{"label", func(d *Draft) {
			d.Params = []Param{{Name: "unit", Label: strings.Repeat("l", limLabel+1), Type: TypeName}}
		}, "needs a label of 1 to 100 characters"},
		{"choices", func(d *Draft) {
			d.Params = []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: choicesOf(limChoices + 1)}}
		}, "a choice has 1 to 20 values"},
		{"choice value", func(d *Draft) {
			d.Params = []Param{{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: []string{slugOf(limChoiceValue + 1)}}}
		}, "choices are distinct lowercase words"},
		{"secret slots", func(d *Draft) { d.Params, d.Secrets = nil, slotsOf(limSecrets+1) }, "at most 8 secret slots"},
		{"secret slot name", func(d *Draft) { d.Params, d.Secrets = nil, []string{slugOf(limName + 1)} }, "secret slots are distinct names of 1 to 32"},
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
	f.Add("runbook.web", "1.0.0")
	f.Add("runbook.web", "9223372036854775807.0.0")
	f.Add("runbook.web", "9223372036854775808.0.0")
	f.Add("runbook.web", "-1.0.0")
	f.Add("runbook.web", "1.0.0.0.0")
	f.Add("runbook.web", ".0.0")
	f.Add("runbook.a", "1.0.0")
	f.Add("runbook.", "")
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
