// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const backupList = "system backup All System {11111111-2222-3333-4444-555555555555} Success 2025-09-15 00:30:02 2025-09-15 00:33:52"

// TestBackupStatusScript verifies that backup.status is a LOW read-only
// action without parameters and that the script runs the allowlisted
// veeamconfig session list and session info commands only, reports a host
// without the Veeam Agent as such, and never reports a denied or failed
// query as a safe backup.
func TestBackupStatusScript(t *testing.T) {
	a, ok := Lookup("backup.status")
	if !ok || !a.ReadOnly || len(a.Params) != 0 || a.Retry != RetrySafe || a.Risk != pb.RiskClass_RISK_CLASS_LOW {
		t.Fatalf("backup.status %+v", a)
	}
	f := newFakeHost(t, "1")
	f.write(t, "veeamconfig", `echo "$@" >> "`+f.calls+`"
case "$1 $2" in
"session list")
	printf '%s\n' '`+backupList+`'
	exit 0 ;;
"session info")
	printf '%s\n' 'ID: {11111111-2222-3333-4444-555555555555}' 'Job name: system backup All System' 'Job ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}' 'State: Success' 'Start time: 2025-09-15 00:30:02 UTC' 'End time: 2025-09-15 00:33:52 UTC'
	exit 0 ;;
*)
	echo "Error: unknown command" >&2
	exit 1 ;;
esac`)
	code, doc := f.run(t, a.Script)
	if code != 0 || doc["phase"] != "done" || doc["present"] != true {
		t.Fatalf("%d %v", code, doc)
	}
	sessions := b64(t, doc, "sessions")
	if !strings.Contains(sessions, "ID: {11111111-2222-3333-4444-555555555555}") ||
		!strings.Contains(sessions, "Job name: system backup All System") ||
		!strings.Contains(sessions, "Start time: 2025-09-15 00:30:02 UTC") {
		t.Fatalf("sessions %q", sessions)
	}
	if calls := f.readCalls(t); strings.Count(calls, "session list") != 1 || strings.Count(calls, "session info --id {11111111-2222-3333-4444-555555555555}") != 1 {
		t.Fatalf("calls %q", calls)
	}

	t.Run("no veeamconfig", func(t *testing.T) {
		f := newFakeHost(t, "1")
		// Only the tools the script needs, so a veeamconfig on this
		// machine stays out of reach.
		for _, tool := range []string{"base64", "head", "tr"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Skip(tool + " missing")
			}
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		code, doc := f.runPath(t, a.Script, f.bin)
		if code != 0 || doc["phase"] != "done" || doc["present"] != false {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("session list fails", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "veeamconfig", `echo "Error: unknown command 'session'" >&2
exit 1`)
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || doc["reason"] != "veeamconfig session list failed" {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("session list denied", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "veeamconfig", `echo "Permission denied: access to the agent database is not permitted" >&2
exit 3`)
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || doc["reason"] != "the host denies access to the Veeam Agent metadata" {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("session info fails", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "veeamconfig", `case "$1 $2" in
"session list")
	printf '%s\n' '`+backupList+`'
	exit 0 ;;
*)
	echo "Error: session not found" >&2
	exit 1 ;;
esac`)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["phase"] != "done" || doc["present"] != true || doc["truncated"] != true {
			t.Fatalf("%d %v", code, doc)
		}
		if _, ok := doc["sessions"]; ok {
			t.Fatalf("sessions must be dropped on truncation: %v", doc)
		}
	})

	t.Run("session list overflows the limit", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "veeamconfig", `[ "$2" = "list" ] && head -c 262145 /dev/zero | tr '\0' 'x'
exit 0`)
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || doc["reason"] != "command output exceeds byte limit" {
			t.Fatalf("%d %v", code, doc)
		}
	})

	t.Run("hostile info is passed through for the parser", func(t *testing.T) {
		// The script is a bounded collector; identity and time limits
		// are enforced by the parser, which must reject this block.
		f := newFakeHost(t, "1")
		f.write(t, "veeamconfig", `case "$1 $2" in
"session list")
	printf '%s\n' '`+backupList+`'
	exit 0 ;;
*)
	printf '%s\n' 'ID: {99999999-8888-7777-6666-555555555555}' 'Job name: evil' 'State: Success' 'Start time: 2025-09-15 00:30:02 UTC' 'End time: 2025-09-15 00:33:52 UTC'
	exit 0 ;;
esac`)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["phase"] != "done" {
			t.Fatalf("%d %v", code, doc)
		}
		sessions := b64(t, doc, "sessions")
		if !strings.Contains(sessions, "ID: {99999999-8888-7777-6666-555555555555}") {
			t.Fatalf("sessions %q", sessions)
		}
	})
}
