// SPDX-License-Identifier: AGPL-3.0-or-later

package static_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// A form control named "action" or "method" shadows the property of the
// same name on HTMLFormElement, so form.action can be that control or a
// RadioNodeList instead of the URL. The lease form has both, and its
// preview went to /leases/[object RadioNodeList]. Neither Go tests nor
// jsdom model the shadowing, so these tests pin the source instead.

// memberAccess finds .action and .method and captures the receiver.
var memberAccess = regexp.MustCompile(`([\w$\])]+)\.(action|method)\b`)

// plainObjects are the receivers that cannot be a form element.
var plainObjects = map[string]bool{"dataset": true, "spec": true}

func TestScriptsDoNotReadShadowableFormProperties(t *testing.T) {
	err := fs.WalkDir(static.FS, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// htmx.min.js is vendored and pinned by hash.
		if d.IsDir() || !strings.HasSuffix(name, ".js") || name == "htmx.min.js" {
			return nil
		}
		for _, m := range memberAccess.FindAllStringSubmatch(mustRead(t, static.FS, name), -1) {
			if !plainObjects[m[1]] {
				t.Errorf("%s reads %s: use getAttribute, or add the receiver to plainObjects if it is no form", name, m[0])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk static assets: %v", err)
	}
}

func TestFetchFormsResolveTheActionAttribute(t *testing.T) {
	for _, name := range []string{"formpost.js", "software.js"} {
		if !strings.Contains(mustRead(t, static.FS, name), "form.getAttribute('action')") {
			t.Errorf("%s does not resolve the target from the action attribute", name)
		}
	}
}

// formTag matches an opening form tag, also one that spans lines.
var formTag = regexp.MustCompile(`<form\b[^>]*>`)

func TestDataFetchFormsDeclareActionAndPostMethod(t *testing.T) {
	names, err := fs.Glob(templates.FS, "*.html")
	if err != nil {
		t.Fatalf("glob templates: %v", err)
	}
	found := 0
	for _, name := range names {
		for _, tag := range formTag.FindAllString(mustRead(t, templates.FS, name), -1) {
			if !strings.Contains(tag, "data-fetch") {
				continue
			}
			found++
			if !strings.Contains(tag, `method="post"`) {
				t.Errorf("%s: %s lacks method=\"post\", formpost.js would skip it", name, tag)
			}
			if !strings.Contains(tag, ` action="`) {
				t.Errorf("%s: %s lacks an action attribute", name, tag)
			}
		}
	}
	if found == 0 {
		t.Fatal("found no data-fetch forms, the template scan is broken")
	}
}
