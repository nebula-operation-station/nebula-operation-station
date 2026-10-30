// SPDX-License-Identifier: AGPL-3.0-or-later
package backupstatus

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t *testing.T, name string) Report {
	t.Helper()
	rep, err := Parse(load(t, name))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return rep
}

func TestParsePresent(t *testing.T) {
	rep := mustParse(t, "backup-present.json")
	if rep.Phase != "done" || !rep.Present || rep.Truncated {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Jobs) != 2 {
		t.Fatalf("jobs = %+v, want 2", rep.Jobs)
	}
	sys := rep.Jobs[0]
	if sys.Name != "system backup" {
		t.Errorf("job name = %q", sys.Name)
	}
	if sys.State != "Success" {
		t.Errorf("state = %q", sys.State)
	}
	if !sys.StartedAt.Equal(time.Date(2025, 9, 15, 0, 30, 2, 0, time.UTC)) {
		t.Errorf("started = %v", sys.StartedAt)
	}
	if sys.EndedAt == nil || !sys.EndedAt.Equal(time.Date(2025, 9, 15, 0, 33, 52, 0, time.UTC)) {
		t.Errorf("ended = %v", sys.EndedAt)
	}
	if !sys.UTC {
		t.Error("UTC = false, source said UTC")
	}
	if sys.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", sys.Sessions)
	}
	file := rep.Jobs[1]
	if file.Name != "file backup" || file.State != "Failed" {
		t.Errorf("file job = %+v", file)
	}
	if file.UTC {
		t.Error("UTC = true, source had no timezone")
	}
	if file.EndedAt == nil || !file.EndedAt.Equal(time.Date(2025, 9, 15, 1, 2, 11, 0, time.UTC)) {
		t.Errorf("ended = %v", file.EndedAt)
	}
}

func TestParseAbsent(t *testing.T) {
	rep := mustParse(t, "backup-absent.json")
	if rep.Phase != "done" || rep.Present || len(rep.Jobs) != 0 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestParseDenied(t *testing.T) {
	rep := mustParse(t, "backup-denied.json")
	if rep.Phase != "precheck" {
		t.Fatalf("phase = %q", rep.Phase)
	}
	if rep.Reason != "the host denies access to the Veeam Agent metadata" {
		t.Errorf("reason = %q", rep.Reason)
	}
}

func TestParseTruncated(t *testing.T) {
	rep := mustParse(t, "backup-truncated.json")
	if !rep.Truncated {
		t.Fatal("truncated = false")
	}
}

func TestParseRunning(t *testing.T) {
	rep := mustParse(t, "backup-running.json")
	if len(rep.Jobs) != 1 {
		t.Fatalf("jobs = %+v", rep.Jobs)
	}
	j := rep.Jobs[0]
	if j.State != "Running" {
		t.Errorf("state = %q", j.State)
	}
	if j.EndedAt != nil {
		t.Errorf("ended = %v, want nil", j.EndedAt)
	}
}

// TestParseHostile checks that blocks that violate the strict schema are
// dropped: a spoofed session ID, an impossible calendar date and a
// state outside the allowlist. Only the valid block survives.
func TestParseHostile(t *testing.T) {
	rep := mustParse(t, "backup-hostile.json")
	if len(rep.Jobs) != 1 {
		t.Fatalf("jobs = %+v, want exactly the valid one", rep.Jobs)
	}
	if rep.Jobs[0].Name != "ok job" {
		t.Errorf("job = %+v", rep.Jobs[0])
	}
}

func TestParseCorruptHeaderStopsParsing(t *testing.T) {
	// Header numbering must be strictly sequential; a gap means the
	// document is hostile, so no evidence is taken from it.
	doc := `[1] {11111111-2222-3333-4444-555555555555}
ID: {11111111-2222-3333-4444-555555555555}
Job name: ok job
State: Success
Start time: 2025-09-15 00:30:02 UTC
End time: 2025-09-15 00:33:52 UTC

[3] {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
Job name: skipped
State: Success
Start time: 2025-09-15 00:30:02 UTC
End time: 2025-09-15 00:33:52 UTC
`
	rep := parseFromDoc(t, doc)
	if len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v, want none", rep.Jobs)
	}
}

func TestParseBadBase64(t *testing.T) {
	if _, err := Parse([]byte(`{"format":"backup-status-v1","phase":"done","present":true,"sessions":"!!!"}`)); err != ErrFormat {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestParseWrongFormat(t *testing.T) {
	if _, err := Parse([]byte(`{"format":"gpu-status-v1","phase":"done"}`)); err != ErrFormat {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestParseOversizedDocument(t *testing.T) {
	doc := `{"format":"backup-status-v1","phase":"done","present":true,"sessions":"` +
		strings.Repeat("A", maxEncodedSize+1) + `"}`
	if _, err := Parse([]byte(doc)); err != ErrFormat {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

func TestParseOversizedReasonIsDropped(t *testing.T) {
	rep, err := Parse([]byte(`{"format":"backup-status-v1","phase":"precheck","reason":"` + strings.Repeat("x", maxReasonLen+1) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reason != "" {
		t.Errorf("reason = %q, want dropped", rep.Reason)
	}
}

func TestParseControlCharInNameDropsSession(t *testing.T) {
	doc := "[1] {11111111-2222-3333-4444-555555555555}\n" +
		"ID: {11111111-2222-3333-4444-555555555555}\n" +
		"Job name: evil\x01name\n" +
		"State: Success\n" +
		"Start time: 2025-09-15 00:30:02 UTC\n" +
		"End time: 2025-09-15 00:33:52 UTC\n"
	if rep := parseFromDoc(t, doc); len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v, want none", rep.Jobs)
	}
}

func TestParseOversizedNameDropsSession(t *testing.T) {
	doc := "[1] {11111111-2222-3333-4444-555555555555}\n" +
		"ID: {11111111-2222-3333-4444-555555555555}\n" +
		"Job name: " + strings.Repeat("n", maxNameLen+1) + "\n" +
		"State: Success\n" +
		"Start time: 2025-09-15 00:30:02 UTC\n" +
		"End time: 2025-09-15 00:33:52 UTC\n"
	if rep := parseFromDoc(t, doc); len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v, want none", rep.Jobs)
	}
}

func TestParseDuplicateKeyDropsSession(t *testing.T) {
	doc := "[1] {11111111-2222-3333-4444-555555555555}\n" +
		"ID: {11111111-2222-3333-4444-555555555555}\n" +
		"Job name: dup\n" +
		"Job name: dup again\n" +
		"State: Success\n" +
		"Start time: 2025-09-15 00:30:02 UTC\n" +
		"End time: 2025-09-15 00:33:52 UTC\n"
	if rep := parseFromDoc(t, doc); len(rep.Jobs) != 0 {
		t.Fatalf("jobs = %+v, want none", rep.Jobs)
	}
}

func TestParseTimes(t *testing.T) {
	for _, in := range []string{
		"2025-02-30 00:30:02",   // impossible date
		"2025-13-01 00:30:02",   // month 13
		"2025-09-15 25:00:02",   // hour 25
		"2025-09-15 00:60:02",   // minute 60
		"1999-09-15 00:30:02",   // before the year bound
		"2100-09-15 00:30:02",   // after the year bound
		"2025-09-15 00:30:02 X", // unknown timezone
		"2025-09-15T00:30:02",   // not the veeamconfig format
	} {
		if _, _, ok := parseTime(in); ok {
			t.Errorf("parseTime(%q) accepted", in)
		}
	}
	for in, wantUTC := range map[string]bool{
		"2025-09-15 00:30:02":     false,
		"2025-09-15 00:30:02 UTC": true,
		"2025-09-15 00:30:02 GMT": true,
		"2025-09-15 00:30:02 Z":   true,
	} {
		tt, utc, ok := parseTime(in)
		if !ok {
			t.Errorf("parseTime(%q) rejected", in)
			continue
		}
		if utc != wantUTC {
			t.Errorf("parseTime(%q) utc = %v, want %v", in, utc, wantUTC)
		}
		if tt.Location() != time.UTC {
			t.Errorf("parseTime(%q) location = %v", in, tt.Location())
		}
	}
}

func TestClassify(t *testing.T) {
	now := time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	fresh := time.Date(2025, 9, 15, 2, 0, 0, 0, time.UTC)
	stale := time.Date(2025, 9, 13, 2, 0, 0, 0, time.UTC)
	future := time.Date(2025, 9, 16, 2, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		rep  Report
		want Classification
	}{
		{"absent", Report{Phase: "done"}, ClassUnknown},
		{"precheck", Report{Phase: "precheck", Present: true}, ClassUnknown},
		{"truncated", Report{Phase: "done", Present: true, Truncated: true, Jobs: []Job{{Name: "j", State: "Success", StartedAt: fresh, EndedAt: &fresh, UTC: true, EndUTC: true}}}, ClassUnknown},
		{"no jobs", Report{Phase: "done", Present: true}, ClassUnknown},
		{"fresh success", Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Success", StartedAt: fresh, EndedAt: &fresh, UTC: true, EndUTC: true}}}, ClassOK},
		{"stale success", Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Success", StartedAt: stale, EndedAt: &stale, UTC: true, EndUTC: true}}}, ClassWarning},
		{"future end", Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Success", StartedAt: fresh, EndedAt: &future, UTC: true, EndUTC: true}}}, ClassWarning},
		{"failed", Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Failed", StartedAt: fresh, EndedAt: &fresh, UTC: true, EndUTC: true}}}, ClassWarning},
		{"running", Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Running", StartedAt: fresh}}}, ClassWarning},
		{
			"one of two stale",
			Report{Phase: "done", Present: true, Jobs: []Job{
				{Name: "ok", State: "Success", StartedAt: fresh, EndedAt: &fresh, UTC: true, EndUTC: true},
				{Name: "stale", State: "Success", StartedAt: stale, EndedAt: &stale, UTC: true, EndUTC: true},
			}},
			ClassWarning,
		},
	}
	for _, c := range cases {
		if got := c.rep.Classify(now, day); got != c.want {
			t.Errorf("%s: Classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyRespectsMaxAge(t *testing.T) {
	now := time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC)
	end := time.Date(2025, 9, 15, 11, 0, 0, 0, time.UTC)
	rep := Report{Phase: "done", Present: true, Jobs: []Job{{Name: "j", State: "Success", StartedAt: end, EndedAt: &end, UTC: true, EndUTC: true}}}
	if got := rep.Classify(now, time.Hour); got != ClassOK {
		t.Errorf("1h maxAge: %q, want ok", got)
	}
	if got := rep.Classify(now, time.Minute); got != ClassWarning {
		t.Errorf("1m maxAge: %q, want warning", got)
	}
}

// parseFromDoc builds a full result document around a session document
// and parses it.
func parseFromDoc(t *testing.T, doc string) Report {
	t.Helper()
	raw := base64.StdEncoding.EncodeToString([]byte(doc))
	var body map[string]any
	if err := json.Unmarshal([]byte(`{"format":"backup-status-v1","phase":"done","present":true}`), &body); err != nil {
		t.Fatal(err)
	}
	body["sessions"] = raw
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func sessionDocument(number int, name string) string {
	id := fmt.Sprintf("{00000000-0000-0000-0000-%012x}", number)
	return fmt.Sprintf("[%d] %s\nID: %s\nJob name: %s\nState: Success\nStart time: 2025-09-15 00:30:02 UTC\nEnd time: 2025-09-15 00:33:52 UTC\n", number, id, id, name)
}

func TestInvalidSessionsForceUnknownWithValidSuccess(t *testing.T) {
	valid := sessionDocument(1, "valid job")
	for _, tc := range []struct {
		name string
		old  string
		new  string
	}{
		{"identity mismatch", "ID: {00000000-0000-0000-0000-000000000002}", "ID: {00000000-0000-0000-0000-000000000003}"},
		{"invalid state", "State: Success", "State: Unexpected"},
		{"missing start", "Start time: 2025-09-15 00:30:02 UTC\n", ""},
		{"invalid calendar", "2025-09-15 00:30:02", "2025-02-30 00:30:02"},
		{"duplicate state", "State: Success", "State: Success\nState: Failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := parseFromDoc(t, valid+strings.Replace(sessionDocument(2, "invalid job"), tc.old, tc.new, 1))
			if len(rep.Jobs) != 1 || rep.Jobs[0].Name != "valid job" {
				t.Fatalf("jobs = %+v, want only valid job", rep.Jobs)
			}
			assertIncompleteUnknown(t, rep)
		})
	}
}

func TestSessionTimezoneCertaintyAndOrdering(t *testing.T) {
	for _, tc := range []struct {
		name     string
		start    string
		end      string
		startUTC bool
		endUTC   bool
		invalid  bool
		want     Classification
	}{
		{"explicit UTC", "2025-09-15 00:30:02 UTC", "2025-09-15 00:33:52 UTC", true, true, false, ClassOK},
		{"explicit GMT and Z", "2025-09-15 00:30:02 GMT", "2025-09-15 00:33:52 Z", true, true, false, ClassOK},
		{"unknown start timezone", "2025-09-15 00:30:02", "2025-09-15 00:33:52 UTC", false, true, false, ClassUnknown},
		{"unknown end timezone", "2025-09-15 00:30:02 UTC", "2025-09-15 00:33:52", true, false, false, ClassUnknown},
		{"unknown both timezones", "2025-09-15 00:30:02", "2025-09-15 00:33:52", false, false, false, ClassUnknown},
		{"end before start", "2025-09-15 00:34:00 UTC", "2025-09-15 00:33:52 UTC", true, true, true, ClassUnknown},
		{"equal timestamps", "2025-09-15 00:33:52 UTC", "2025-09-15 00:33:52 UTC", true, true, false, ClassOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(sessionDocument(1, "job"), "2025-09-15 00:30:02 UTC", tc.start, 1)
			doc = strings.Replace(doc, "2025-09-15 00:33:52 UTC", tc.end, 1)
			rep := parseFromDoc(t, doc)
			if tc.invalid {
				if len(rep.Jobs) != 0 {
					t.Fatalf("impossible session retained: %+v", rep.Jobs)
				}
				assertIncompleteUnknown(t, rep)
			} else if len(rep.Jobs) != 1 || rep.Jobs[0].UTC != tc.startUTC || rep.Jobs[0].EndUTC != tc.endUTC {
				t.Fatalf("timezone markers not preserved: %+v", rep.Jobs)
			}
			if got := rep.Classify(time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour); got != tc.want {
				t.Fatalf("Classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSessionCountLimit(t *testing.T) {
	for _, count := range []int{maxSessions - 1, maxSessions, maxSessions + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var doc strings.Builder
			for i := 1; i <= count; i++ {
				// One job keeps the session limit independent of the job limit.
				doc.WriteString(sessionDocument(i, "job"))
			}
			rep := parseFromDoc(t, doc.String())
			if count > maxSessions {
				assertIncompleteUnknown(t, rep)
				return
			}
			if rep.Truncated || len(rep.Jobs) != 1 || rep.Jobs[0].Sessions != count {
				t.Fatalf("report = %+v", rep)
			}
			if got := rep.Classify(time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour); got != ClassOK {
				t.Fatalf("Classify = %q, want ok", got)
			}
		})
	}
}

func TestSessionBlockLineLimit(t *testing.T) {
	for _, lines := range []int{maxBlockLines - 1, maxBlockLines, maxBlockLines + 1} {
		t.Run(fmt.Sprint(lines), func(t *testing.T) {
			doc := sessionDocument(1, "job") + strings.Repeat("Ignored: value\n", min(lines, maxBlockLines)-5)
			if lines > maxBlockLines {
				// The contradictory field sits just beyond the line limit.
				doc += "State: Failed\n"
			}
			rep := parseFromDoc(t, doc)
			if lines > maxBlockLines {
				assertIncompleteUnknown(t, rep)
				return
			}
			if rep.Truncated || len(rep.Jobs) != 1 {
				t.Fatalf("report = %+v", rep)
			}
			if got := rep.Classify(time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour); got != ClassOK {
				t.Fatalf("Classify = %q, want ok", got)
			}
		})
	}
}

func TestMalformedUTF8JobNamesAreRejected(t *testing.T) {
	for _, name := range []string{"bad\xffname", "bad\xc0\xafname", "bad\xe2\x82", "bad\xed\xa0\x80name"} {
		t.Run(fmt.Sprintf("%x", name), func(t *testing.T) {
			rep := parseFromDoc(t, sessionDocument(1, "valid job")+sessionDocument(2, name))
			if len(rep.Jobs) != 1 || rep.Jobs[0].Name != "valid job" {
				t.Fatalf("malformed name retained: %+v", rep.Jobs)
			}
			assertIncompleteUnknown(t, rep)
		})
	}
	if rep := parseFromDoc(t, sessionDocument(1, "valid \ufffd name")); len(rep.Jobs) != 1 || rep.Truncated {
		t.Fatalf("valid replacement rune rejected: %+v", rep)
	}
}

func assertIncompleteUnknown(t *testing.T, rep Report) {
	t.Helper()
	if !rep.Truncated {
		t.Error("incomplete evidence was not marked")
	}
	if got := rep.Classify(time.Date(2025, 9, 15, 12, 0, 0, 0, time.UTC), 24*time.Hour); got != ClassUnknown {
		t.Errorf("Classify = %q, want unknown", got)
	}
}
