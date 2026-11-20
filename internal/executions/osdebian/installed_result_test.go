// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

func wrapInstalled(t *testing.T, text string, truncated bool) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		Format    string `json:"format"`
		Text      string `json:"text"`
		Truncated bool   `json:"truncated"`
	}{InstalledFormat, text, truncated})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// The 1.1.0 envelope carries the nos-installed-v1 text unchanged: the
// result parses exactly like the bare text.
func TestInstalledResultEnvelopeParsesLikeText(t *testing.T) {
	text := readInstalledFixture(t, "debian12.txt")
	want := ParseInstalled(text, ReadStatus{}, vulnver.DistroDebian)
	got := ParseInstalledResult(wrapInstalled(t, string(text), false), ReadStatus{}, vulnver.DistroDebian)
	if !got.Complete || got.Reason != "" || len(got.Packages) != len(want.Packages) || got.RunningKernel != want.RunningKernel {
		t.Fatalf("got complete=%v reason=%q %d packages kernel %+v, want %d packages kernel %+v",
			got.Complete, got.Reason, len(got.Packages), got.RunningKernel, len(want.Packages), want.RunningKernel)
	}
}

// "truncated":true from the script makes the read partial even when the
// text itself looks complete; it can never make a read complete.
func TestInstalledResultTruncatedFlagMakesReadPartial(t *testing.T) {
	text := string(readInstalledFixture(t, "debian12.txt"))
	inv := ParseInstalledResult(wrapInstalled(t, text, true), ReadStatus{}, vulnver.DistroDebian)
	if inv.Complete || inv.Reason != ReasonTruncated {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
	}
	if len(inv.Packages) == 0 {
		t.Fatal("a truncated read still adds inventory")
	}
	inv = ParseInstalledResult(wrapInstalled(t, text, false), ReadStatus{ExitCode: 1}, vulnver.DistroDebian)
	if inv.Complete || inv.Reason != ReasonReadFailed {
		t.Fatalf("exit 1: complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

// Everything but the exact 1.1.0 object is rejected as a whole, including
// a plain nos-installed-v1 text result of 1.0.0.
func TestInstalledResultRejectsMalformedEnvelopes(t *testing.T) {
	text := string(readInstalledFixture(t, "debian12.txt"))
	q, _ := json.Marshal(text)
	body := `"format":"nos-installed-v1","text":` + string(q)
	cases := map[string]string{
		"plain 1.0.0 text":     text,
		"empty":                "",
		"null":                 "null",
		"array":                "[" + string(q) + "]",
		"string":               string(q),
		"missing truncated":    "{" + body + "}",
		"missing text":         `{"format":"nos-installed-v1","truncated":false}`,
		"missing format":       `{"text":` + string(q) + `,"truncated":false}`,
		"other format":         `{"format":"nos-installed-v2","text":` + string(q) + `,"truncated":false}`,
		"apt format":           `{"format":"apt-simulate-v1","text":` + string(q) + `,"truncated":false}`,
		"duplicate text":       "{" + body + `,"truncated":false,"text":""}`,
		"duplicate format":     `{"format":"x",` + body + `,"truncated":false}`,
		"case variant key":     "{" + body + `,"truncated":false,"TEXT":""}`,
		"escaped duplicate":    "{" + body + `,"truncated":false,"text":""}`,
		"unknown key":          "{" + body + `,"truncated":false,"exit":0}`,
		"null text":            `{"format":"nos-installed-v1","text":null,"truncated":false}`,
		"null truncated":       "{" + body + `,"truncated":null}`,
		"string truncated":     "{" + body + `,"truncated":"false"}`,
		"number text":          `{"format":"nos-installed-v1","text":1,"truncated":false}`,
		"object text":          `{"format":"nos-installed-v1","text":{},"truncated":false}`,
		"two documents":        "{" + body + `,"truncated":false}{}`,
		"trailing garbage":     "{" + body + `,"truncated":false} x`,
		"cut document":         "{" + body,
		"invalid utf-8":        `{"format":"nos-installed-v1","text":"` + "\xff" + `","truncated":false}`,
		"too large":            `{"format":"nos-installed-v1","text":"` + strings.Repeat("x", MaxInstalledResult) + `","truncated":false}`,
		"format with trailing": `{"format":"nos-installed-v1 ","text":` + string(q) + `,"truncated":false}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			inv := ParseInstalledResult([]byte(doc), ReadStatus{}, vulnver.DistroDebian)
			if inv.Complete || inv.Reason != ReasonResultFormat || len(inv.Packages) != 0 {
				t.Fatalf("complete=%v reason=%q packages=%d", inv.Complete, inv.Reason, len(inv.Packages))
			}
			if inv.RunningKernel.State != KernelVersionUnknown {
				t.Fatalf("kernel %+v", inv.RunningKernel)
			}
		})
	}
}

// Escaped tabs, backslashes, quotes and non-ASCII bytes reach the text
// parser exactly as the host wrote them, and the parser still treats them
// as untrusted: a value with a quote, backslash, extra tab or non-ASCII
// character makes its line malformed, never a forged record.
func TestInstalledResultEscapedValuesStayUntrusted(t *testing.T) {
	const pkgLine = "P\tinstalled\topenssl\tamd64\t3.0.15-1~deb12u1\topenssl\t3.0.15-1~deb12u1\t\t.\n"
	const kLine = "K\t6.1.0-26-amd64\t#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)\n"
	cases := map[string]string{
		"quote in version":       "P\tinstalled\tevil\tamd64\t1.0\"x\tevil\t1.0\t\t.\n",
		"backslash in version":   "P\tinstalled\tevil\tamd64\t1.0\\t\tevil\t1.0\t\t.\n",
		"tab in version":         "P\tinstalled\tevil\tamd64\t1.0\tx\tevil\t1.0\t\t.\n",
		"non-ascii in version":   "P\tinstalled\tevil\tamd64\t1.0ü\tevil\t1.0\t\t.\n",
		"replacement in version": "P\tinstalled\tevil\tamd64\t1.0�\tevil\t1.0\t\t.\n",
		"control in source":      "P\tinstalled\tevil\tamd64\t1.0\tev\x01il\t1.0\t\t.\n",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			text := InstalledFormat + "\n" + pkgLine + bad + kLine + "END\t2\n"
			doc := wrapInstalled(t, text, false)
			if !strings.Contains(string(doc), `\t`) {
				t.Fatalf("tabs not escaped: %s", doc)
			}
			inv := ParseInstalledResult(doc, ReadStatus{}, vulnver.DistroDebian)
			if inv.Complete || !strings.HasPrefix(inv.Reason, ReasonMalformed) || inv.Dropped != 1 {
				t.Fatalf("complete=%v reason=%q dropped=%d", inv.Complete, inv.Reason, inv.Dropped)
			}
			if len(inv.Packages) != 1 || inv.Packages[0].Name != "openssl" {
				t.Fatalf("packages %+v", inv.Packages)
			}
		})
	}
}

// The END record and the K record are still checked inside the envelope.
func TestInstalledResultEndAndKernelRecordsChecked(t *testing.T) {
	text := string(readInstalledFixture(t, "debian12.txt"))
	lines := strings.SplitAfter(text, "\n")
	var noEnd, noK, wrongCount strings.Builder
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "END\t"):
			noK.WriteString(l)
			wrongCount.WriteString("END\t999\n")
		case strings.HasPrefix(l, "K\t"):
			noEnd.WriteString(l)
			wrongCount.WriteString(l)
		default:
			noEnd.WriteString(l)
			noK.WriteString(l)
			wrongCount.WriteString(l)
		}
	}
	for _, c := range []struct{ name, text, reason string }{
		{"no END", noEnd.String(), ReasonNoEnd},
		{"no K", noK.String(), ReasonNoKernel},
		{"END count wrong", wrongCount.String(), ReasonCountMismatch},
		{"text cut", text[:len(text)-3], ReasonTruncated},
	} {
		t.Run(c.name, func(t *testing.T) {
			inv := ParseInstalledResult(wrapInstalled(t, c.text, false), ReadStatus{}, vulnver.DistroDebian)
			if inv.Complete || inv.Reason != c.reason {
				t.Fatalf("complete=%v reason=%q, want %q", inv.Complete, inv.Reason, c.reason)
			}
		})
	}
}
