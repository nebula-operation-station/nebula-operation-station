// SPDX-License-Identifier: AGPL-3.0-or-later

package prelude

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runArtifact(t *testing.T, body string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "a.sh")
	pf := filepath.Join(dir, "p.json")
	_ = os.WriteFile(script, Build("test", nil, nil, body), 0o600)
	_ = os.WriteFile(pf, []byte(`{}`), 0o600)
	cmd := exec.Command(sh, script)
	cmd.Env = []string{"NEBULA_PARAMS=" + pf, "PATH=" + os.Getenv("PATH"), "TMPDIR=" + dir}
	var out strings.Builder
	cmd.Stdout = &out
	err = cmd.Run()
	left, _ := filepath.Glob(filepath.Join(dir, "nebula-result.*"))
	if len(left) != 0 {
		t.Fatalf("result file left: %v", left)
	}
	return out.String(), err
}

// A script's result object is embedded; the result file goes away.
func TestResultFile(t *testing.T) {
	out, err := runArtifact(t, `printf '{"version":"1.2","ok":true}' > "$NEBULA_RESULT"; echo noise`)
	var doc struct {
		Exit   int            `json:"exit"`
		Result map[string]any `json:"result"`
	}
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil || doc.Result["version"] != "1.2" {
		t.Fatalf("%q %v", out, err)
	}
	// No result, or something that is not an object: the plain line.
	for _, body := range []string{"true", `echo '[1]' > "$NEBULA_RESULT"`, `head -c 70000 /dev/zero | tr '\0' a > "$NEBULA_RESULT"`} {
		out, _ := runArtifact(t, body)
		if strings.Contains(out, `"result"`) || !strings.HasPrefix(out, `{"format":"runbook-v1","phase":"done"`) {
			t.Errorf("%s: %q", body, out)
		}
	}
}
