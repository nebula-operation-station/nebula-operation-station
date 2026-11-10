// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// jobBody wraps job elements in a success response of show jobs id.
func jobBody(elems string) []byte {
	return wrapResult(`<job>` + elems + `</job>`)
}

// jobElems builds the elements of one job.
func jobElems(id, typ, status, result, progress, details string) string {
	return `<id>` + id + `</id><type>` + typ + `</type><status>` + status + `</status><result>` +
		result + `</result><progress>` + progress + `</progress>` + details
}

func TestParseJobFixture(t *testing.T) {
	got, err := ParseJob(readFixture(t, "job.xml"), 42)
	if err != nil {
		t.Fatalf("ParseJob: %v", err)
	}
	want := Job{
		ID:       42,
		Type:     "Commit",
		Status:   JobFinished,
		Result:   JobResultOK,
		Progress: 100,
		Details: []string{
			"Configuration committed successfully",
			"Partial changes to commit: changes to configuration by administrators: nos-change",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseJob =\n%+v\nwant\n%+v", got, want)
	}
	if s := fmt.Sprintf("%+v", got); strings.Contains(s, "must-not-leak") || strings.Contains(s, "nos permit") {
		t.Fatalf("non-allowlisted content leaked: %s", s)
	}
}

func TestParseJobStatusMapping(t *testing.T) {
	tests := []struct {
		status, result string
		wantStatus     JobStatus
		wantResult     JobResult
	}{
		{"ACT", "PEND", JobActive, JobResultPending},
		{"PEND", "PEND", JobPending, JobResultPending},
		{"FIN", "OK", JobFinished, JobResultOK},
		{"FIN", "FAIL", JobFinished, JobResultFail},
	}
	for _, tt := range tests {
		t.Run(tt.status+"/"+tt.result, func(t *testing.T) {
			got, err := ParseJob(jobBody(jobElems("7", "Validate", tt.status, tt.result, "50", "")), 7)
			if err != nil {
				t.Fatalf("ParseJob: %v", err)
			}
			if got.Status != tt.wantStatus || got.Result != tt.wantResult {
				t.Fatalf("got %s/%s, want %s/%s", got.Status, got.Result, tt.wantStatus, tt.wantResult)
			}
			if got.Done() != (tt.wantStatus == JobFinished) {
				t.Fatalf("Done() = %v for %s", got.Done(), tt.wantStatus)
			}
		})
	}
}

func TestParseJobUnknownStateIsError(t *testing.T) {
	tests := []struct {
		name, status, result string
	}{
		{"unknown status", "DONE", "OK"},
		{"lower-case status", "fin", "OK"},
		{"padded status", " FIN", "OK"},
		{"empty status", "", "OK"},
		{"unknown result", "FIN", "SUCCESS"},
		{"lower-case result", "FIN", "ok"},
		{"empty result", "FIN", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJob(jobBody(jobElems("7", "Commit", tt.status, tt.result, "100", "")), 7)
			if !errors.Is(err, ErrUnknownJobState) {
				t.Fatalf("err = %v, want ErrUnknownJobState", err)
			}
			if !reflect.DeepEqual(got, Job{}) {
				t.Fatalf("non-zero result with error: %+v", got)
			}
			if strings.Contains(err.Error(), "SUCCESS") || strings.Contains(err.Error(), "DONE") {
				t.Fatalf("error repeats device text: %v", err)
			}
		})
	}
	for _, missing := range []string{"status", "result"} {
		elems := strings.Replace(jobElems("7", "Commit", "FIN", "OK", "100", ""),
			"<"+missing+">", "<x-"+missing+">", 1)
		elems = strings.Replace(elems, "</"+missing+">", "</x-"+missing+">", 1)
		if _, err := ParseJob(jobBody(elems), 7); !errors.Is(err, ErrUnknownJobState) {
			t.Errorf("missing %s: err = %v, want ErrUnknownJobState", missing, err)
		}
	}
}

func TestParseJobInconsistentStateIsError(t *testing.T) {
	for _, sr := range [][2]string{
		{"FIN", "PEND"},
		{"ACT", "OK"},
		{"ACT", "FAIL"},
		{"PEND", "OK"},
		{"PEND", "FAIL"},
	} {
		_, err := ParseJob(jobBody(jobElems("7", "Commit", sr[0], sr[1], "100", "")), 7)
		if !errors.Is(err, ErrInvalidJob) {
			t.Errorf("%s/%s: err = %v, want ErrInvalidJob", sr[0], sr[1], err)
		}
	}
}

func TestParseJobRefusesBadFields(t *testing.T) {
	ok := func(id, typ, progress, details string) []byte {
		return jobBody(jobElems(id, typ, "ACT", "PEND", progress, details))
	}
	tests := []struct {
		name string
		data []byte
		id   uint64
	}{
		{"other job id", ok("43", "Commit", "10", ""), 42},
		{"id zero", ok("0", "Commit", "10", ""), 0},
		{"negative id", ok("-42", "Commit", "10", ""), 42},
		{"id overflow", ok("18446744073709551616", "Commit", "10", ""), 42},
		{"id leading zero", ok("042", "Commit", "10", ""), 42},
		{"progress over 100", ok("42", "Commit", "101", ""), 42},
		{"negative progress", ok("42", "Commit", "-1", ""), 42},
		{"progress fraction", ok("42", "Commit", "50.5", ""), 42},
		{"progress percent", ok("42", "Commit", "50%", ""), 42},
		{"progress timestamp", ok("42", "Commit", "2026/01/01 00:00:30", ""), 42},
		{"progress empty", ok("42", "Commit", "", ""), 42},
		{"type empty", ok("42", "", "10", ""), 42},
		{"type with tab", ok("42", "Com\tmit", "10", ""), 42},
		{"type too long", ok("42", strings.Repeat("A", maxJobTypeBytes+1), "10", ""), 42},
		{"type markup chars", ok("42", "Commit&lt;x&gt;", "10", ""), 42},
		{"details line with bidi override", ok("42", "Commit", "10", "<details><line>bad"+string(rune(0x202e))+"line</line></details>"), 42},
		{"details line with inner tab", ok("42", "Commit", "10", "<details><line>bad\tline</line></details>"), 42},
		{"details repeated", ok("42", "Commit", "10", "<details/><details/>"), 42},
		{"id repeated", jobBody(`<id>42</id>` + jobElems("42", "Commit", "ACT", "PEND", "10", "")), 42},
		{"status repeated", jobBody(`<status>ACT</status>` + jobElems("42", "Commit", "ACT", "PEND", "10", "")), 42},
		{"result repeated", jobBody(`<result>PEND</result>` + jobElems("42", "Commit", "ACT", "PEND", "10", "")), 42},
		{"progress repeated", jobBody(`<progress>1</progress>` + jobElems("42", "Commit", "ACT", "PEND", "10", "")), 42},
		{"type repeated", jobBody(`<type>Commit</type>` + jobElems("42", "Commit", "ACT", "PEND", "10", "")), 42},
		{"id missing", jobBody(`<type>Commit</type><status>ACT</status><result>PEND</result><progress>1</progress>`), 42},
		{"progress missing", jobBody(`<id>42</id><type>Commit</type><status>ACT</status><result>PEND</result>`), 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJob(tt.data, tt.id)
			if !errors.Is(err, ErrInvalidJob) {
				t.Fatalf("err = %v, want ErrInvalidJob", err)
			}
			if !reflect.DeepEqual(got, Job{}) {
				t.Fatalf("non-zero result with error: %+v", got)
			}
			if strings.Contains(err.Error(), "bad") {
				t.Fatalf("error repeats device text: %v", err)
			}
		})
	}
}

func TestParseJobStructure(t *testing.T) {
	one := jobElems("42", "Commit", "FIN", "OK", "100", "")
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"no job", wrapResult(``), ErrMalformedResponse},
		{"two jobs", wrapResult(`<job>` + one + `</job><job>` + one + `</job>`), ErrInvalidJob},
		{"two results", []byte(`<response status="success"><result><job>` + one + `</job></result><result/></response>`), ErrInvalidJob},
		{"status error", readFixture(t, "status-error.xml"), ErrAPIStatus},
		{"not XML", []byte(`<response status="success"><result>`), ErrMalformedResponse},
		{"doctype", []byte(`<!DOCTYPE x [<!ENTITY a "b">]><response status="success"><result/></response>`), ErrMalformedResponse},
		{"over response cap", jobBody(one + strings.Repeat("<pad/>", int(MaxOtherResponseBytes)/6)), ErrXMLLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJob(tt.data, 42)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(got, Job{}) {
				t.Fatalf("non-zero result with error: %+v", got)
			}
		})
	}
}

func TestParseJobDetailsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("<details>")
	for i := 0; i < MaxJobDetailLines+5; i++ {
		fmt.Fprintf(&b, "<line>line %d</line>", i)
	}
	b.WriteString("<line></line><line>   </line></details>")
	got, err := ParseJob(jobBody(jobElems("42", "Commit", "FIN", "FAIL", "100", b.String())), 42)
	if err != nil {
		t.Fatalf("ParseJob: %v", err)
	}
	if len(got.Details) != MaxJobDetailLines || !got.DetailsTruncated {
		t.Fatalf("%d details, truncated %v; want %d and truncated", len(got.Details), got.DetailsTruncated, MaxJobDetailLines)
	}
	if got.Details[0] != "line 0" || got.Details[MaxJobDetailLines-1] != fmt.Sprintf("line %d", MaxJobDetailLines-1) {
		t.Fatalf("details not the first lines in order: %q ... %q", got.Details[0], got.Details[MaxJobDetailLines-1])
	}

	// exactly at the limit, plus blank lines that are dropped: not truncated
	b.Reset()
	b.WriteString("<details>")
	for i := 0; i < MaxJobDetailLines; i++ {
		fmt.Fprintf(&b, "<line>l%d</line><line> </line>", i)
	}
	b.WriteString("</details>")
	got, err = ParseJob(jobBody(jobElems("42", "Commit", "FIN", "OK", "100", b.String())), 42)
	if err != nil {
		t.Fatalf("ParseJob: %v", err)
	}
	if len(got.Details) != MaxJobDetailLines || got.DetailsTruncated {
		t.Fatalf("%d details, truncated %v; want %d, not truncated", len(got.Details), got.DetailsTruncated, MaxJobDetailLines)
	}
}

func TestParseJobDetailLineOverTextLimit(t *testing.T) {
	long := strings.Repeat("x", MaxXMLTextBytes+1)
	_, err := ParseJob(jobBody(jobElems("42", "Commit", "FIN", "FAIL", "100", "<details><line>"+long+"</line></details>")), 42)
	if !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit", err)
	}
}

func TestParseJobWithoutDetails(t *testing.T) {
	got, err := ParseJob(jobBody(jobElems("1", "Commit", "PEND", "PEND", "0", "")), 1)
	if err != nil {
		t.Fatalf("ParseJob: %v", err)
	}
	if got.Details != nil || got.DetailsTruncated || got.Progress != 0 {
		t.Fatalf("ParseJob = %+v", got)
	}
}

func FuzzParseJob(f *testing.F) {
	f.Add(readFixture(f, "job.xml"))
	f.Add(jobBody(jobElems("42", "Commit", "ACT", "PEND", "50", "<details><line>x</line></details>")))
	f.Add(jobBody(jobElems("42", "Commit", "FIN", "WHAT", "100", "")))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseJob(data, 42)
		if err != nil {
			if !reflect.DeepEqual(got, Job{}) {
				t.Fatalf("error with non-zero result: %v", err)
			}
			return
		}
		if got.ID != 42 || got.Progress > 100 || len(got.Details) > MaxJobDetailLines {
			t.Fatalf("out-of-range job accepted: %+v", got)
		}
		switch got.Status {
		case JobFinished:
			if got.Result != JobResultOK && got.Result != JobResultFail {
				t.Fatalf("finished job with result %q", got.Result)
			}
		case JobActive, JobPending:
			if got.Result != JobResultPending {
				t.Fatalf("unfinished job with result %q", got.Result)
			}
		default:
			t.Fatalf("unknown status %q accepted", got.Status)
		}
	})
}
