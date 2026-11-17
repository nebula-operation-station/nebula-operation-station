// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// regexMax reads the upper repetition bound from a regular expression, so
// the tests follow the pattern the code enforces instead of a copied number.
func regexMax(t *testing.T, re *regexp.Regexp) int {
	t.Helper()
	m := regexp.MustCompile(`\{\d+,(\d+)\}`).FindStringSubmatch(re.String())
	if m == nil {
		t.Fatalf("no bounded repetition in %s", re)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// slugMax is the longest accepted slug: one leading character plus the
// bounded remainder of slugRe.
func slugMax(t *testing.T) int { return 1 + regexMax(t, slugRe) }

// userMax is the longest accepted user name (userRe).
func userMax(t *testing.T) int { return regexMax(t, userRe) }

// requireInvalid asserts that Validate rejects d with an InvalidError.
func requireInvalid(t *testing.T, name string, d Draft) {
	t.Helper()
	var ie *InvalidError
	if err := Validate(d); !errors.As(err, &ie) {
		t.Errorf("%s: want InvalidError, got %v", name, err)
	}
}

// requireValid asserts that Validate accepts d.
func requireValid(t *testing.T, name string, d Draft) {
	t.Helper()
	if err := Validate(d); err != nil {
		t.Errorf("%s: want accepted, got %v", name, err)
	}
}

func TestSlugLengthLimit(t *testing.T) {
	max := slugMax(t)
	atLimit := "a" + strings.Repeat("a", max-1)
	d := draft()
	d.Slug = atLimit
	requireValid(t, "slug at limit", d)
	d.Slug = atLimit + "a"
	requireInvalid(t, "slug limit+1", d)
	d.Slug = "new"
	requireInvalid(t, "reserved slug", d)
}

func TestTitleLimit(t *testing.T) {
	d := draft()
	d.Title = strings.Repeat("t", MaxTitle)
	requireValid(t, "title at limit", d)
	d.Title = strings.Repeat("t", MaxTitle+1)
	requireInvalid(t, "title limit+1", d)
}

func TestDescriptionLimit(t *testing.T) {
	d := draft()
	d.Description = strings.Repeat("d", MaxDescription)
	requireValid(t, "description at limit", d)
	d.Description = strings.Repeat("d", MaxDescription+1)
	requireInvalid(t, "description limit+1", d)
}

func TestBodyLimit(t *testing.T) {
	// A comment keeps the script valid shell at exactly MaxBody bytes.
	d := draft()
	d.Body = "# " + strings.Repeat("x", MaxBody-3) + "\n"
	if len(d.Body) != MaxBody {
		t.Fatalf("test body is %d bytes, want %d", len(d.Body), MaxBody)
	}
	requireValid(t, "body at limit", d)
	d.Body = "# " + strings.Repeat("x", MaxBody-2) + "\n"
	requireInvalid(t, "body limit+1", d)
}

func TestTimeoutLimits(t *testing.T) {
	minS := int(MinTimeout / time.Second)
	d := draft()
	d.TimeoutS = minS
	requireValid(t, "timeout at minimum", d)
	d.TimeoutS = minS - 1
	requireInvalid(t, "timeout minimum-1", d)

	maxS := int(hostrun.MaxTimeout / time.Second)
	d = draft()
	d.TimeoutS = maxS
	requireValid(t, "attached timeout at limit", d)
	d.TimeoutS = maxS + 1
	requireInvalid(t, "attached timeout limit+1", d)

	maxDurS := int(hostrun.MaxDurableTimeout / time.Second)
	d = draft()
	d.Durable, d.TimeoutS = true, maxDurS
	requireValid(t, "durable timeout at limit", d)
	d.TimeoutS = maxDurS + 1
	requireInvalid(t, "durable timeout limit+1", d)
}

func TestSaveUserLimit(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	max := userMax(t)
	if _, err := s.Save(ctx, strings.Repeat("u", max), draft()); err != nil {
		t.Fatalf("user at limit: %v", err)
	}
	if _, err := s.Save(ctx, strings.Repeat("u", max+1), draft()); err == nil {
		t.Fatal("user limit+1 accepted")
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
