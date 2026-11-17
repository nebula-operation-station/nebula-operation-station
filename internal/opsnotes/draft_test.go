// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"errors"
	"strings"
	"testing"
)

// fakeResolver is a Resolver with a fixed catalog, hosts and documentation index.
type fakeResolver struct {
	digests    map[string]string
	external   map[string]bool
	cands      map[string][]Candidate
	groupHosts map[string]string
	hosts      map[string]bool
	actions    map[string]string
	chunks     map[string]bool
}

// newFakeResolver's catalog holds allowlisted actions (package.install_security,
// service.restart, docker.restart), one catalog action outside the suggestion
// allowlist (package.remove) and the candidates of two groups. Candidates may
// name a host other than the group's host, as a computed set could.
func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		digests:    map[string]string{"vu:host1:openssl": "d1", "ext:1": "e1"},
		external:   map[string]bool{"ext:1": true},
		groupHosts: map[string]string{"vu:host1:openssl": "host1", "ext:1": "host1"},
		cands: map[string][]Candidate{
			"vu:host1:openssl|d1": {
				{ActionID: "package.install_security", HostID: "host1"},
				{ActionID: "service.restart", HostID: "host1"},
				{ActionID: "package.remove", HostID: "host1"},
				{ActionID: "package.install_security", HostID: "host2"},
			},
			"ext:1|e1": {{ActionID: "package.install_security", HostID: "host1"}},
		},
		hosts: map[string]bool{"host1": true, "host2": true},
		actions: map[string]string{
			"package.install_security": "os-update",
			"service.restart":          "service-restart",
			"package.remove":           "os-remove",
			"docker.restart":           "container-restart",
		},
		chunks: map[string]bool{"doc-1": true, "doc-2": true},
	}
}

func (f *fakeResolver) GroupHost(ref string) (string, bool) {
	h, ok := f.groupHosts[ref]
	return h, ok
}

func (f *fakeResolver) CurrentDigest(kind Kind, ref string) (string, bool) {
	if d, ok := f.digests[ref]; ok {
		return d, true
	}
	if kind == KindSummary || kind == KindAnswer {
		return "dig-" + ref, true
	}
	return "", false
}

func (f *fakeResolver) External(ref string) bool { return f.external[ref] }

func (f *fakeResolver) Candidates(ref, digest string) []Candidate {
	return f.cands[ref+"|"+digest]
}

func (f *fakeResolver) HostExists(hostID string) bool { return f.hosts[hostID] }

func (f *fakeResolver) ActionFamily(actionID string) (string, bool) {
	fam, ok := f.actions[actionID]
	return fam, ok
}

func (f *fakeResolver) DocChunkExists(chunkID string) bool { return f.chunks[chunkID] }

// validFix is a fix draft that passes every check against newFakeResolver.
func validFix() Draft {
	return Draft{
		Kind:   KindFix,
		Ref:    "vu:host1:openssl",
		Digest: "d1",
		Body: Body{
			Summary:   "Paket aktualisieren",
			Urgency:   "hoch",
			Steps:     []StepInput{{ActionID: "package.install_security", HostID: "host1", Why: "behebt CVE"}},
			Citations: []string{"doc-1"},
		},
	}
}

// validText is a summary draft that passes every check.
func validText(kind Kind) Draft {
	return Draft{Kind: kind, Ref: "2026-11-17", Digest: "dig-2026-11-17", Body: Body{Text: "Ein Text."}}
}

func TestValidateAcceptsWellFormedNotes(t *testing.T) {
	r := newFakeResolver()
	tests := []struct {
		name  string
		draft func() Draft
	}{
		{"fix with one step", validFix},
		{"fix with mitigation only", func() Draft {
			d := validFix()
			d.Steps = nil
			d.Mitigations = []string{"Dienst nicht erreichbar machen"}
			return d
		}},
		{"fix summary of exactly 600 bytes", func() Draft {
			d := validFix()
			d.Summary = strings.Repeat("a", MaxSummaryBytes)
			return d
		}},
		{"fix with multi-line summary", func() Draft {
			d := validFix()
			d.Summary = "Zeile eins\nZeile zwei"
			return d
		}},
		{"fix with two steps on one host", func() Draft {
			d := validFix()
			d.Steps = []StepInput{
				{ActionID: "package.install_security", HostID: "host1"},
				{ActionID: "service.restart", HostID: "host1"},
			}
			return d
		}},
		{"summary", func() Draft { return validText(KindSummary) }},
		{"answer", func() Draft { return validText(KindAnswer) }},
		{"summary text of exactly 2 KiB", func() Draft {
			d := validText(KindSummary)
			d.Text = strings.Repeat("ä", MaxTextBytes/2)
			return d
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Validate(tc.draft(), r); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestValidateRejectsMalformedNotes(t *testing.T) {
	tests := []struct {
		name   string
		draft  func() Draft
		wantIs error
	}{
		{"unknown kind", func() Draft { d := validFix(); d.Kind = "fixx"; return d }, ErrInvalidKind},
		{"empty kind", func() Draft { d := validFix(); d.Kind = ""; return d }, ErrInvalidKind},
		{"unknown ref", func() Draft { d := validFix(); d.Ref = "vu:host9:x"; return d }, ErrUnknownRef},
		{"stale digest", func() Draft { d := validFix(); d.Digest = "d0"; return d }, ErrStaleDigest},
		{"empty digest", func() Draft { d := validFix(); d.Digest = ""; return d }, ErrMissing},
		{"digest with space", func() Draft { d := validFix(); d.Digest = "d 1"; return d }, ErrInvalidField},
		{"ref over 128 bytes", func() Draft { d := validFix(); d.Ref = strings.Repeat("r", 129); return d }, ErrLimit},
		{"ref with URL", func() Draft { d := validFix(); d.Ref = "x://y"; return d }, ErrURL},
		{"fix in external data class", func() Draft { d := validFix(); d.Ref = "ext:1"; d.Digest = "e1"; return d }, ErrExternalData},
		{"fix summary with URL", func() Draft { d := validFix(); d.Summary = "siehe http://x"; return d }, ErrURL},
		{"fix summary with www", func() Draft { d := validFix(); d.Summary = "siehe WWW.example"; return d }, ErrURL},
		{"fix urgency with URL", func() Draft { d := validFix(); d.Urgency = "a://b"; return d }, ErrURL},
		{"fix summary with control character", func() Draft { d := validFix(); d.Summary = "a\x07b"; return d }, ErrInvalidText},
		{"fix summary with tab", func() Draft { d := validFix(); d.Summary = "a\tb"; return d }, ErrInvalidText},
		{"fix summary with bidi override", func() Draft { d := validFix(); d.Summary = "abc\u202Eevil"; return d }, ErrInvalidText},
		{"fix summary with zero-width space", func() Draft { d := validFix(); d.Summary = "pa\u200Bket"; return d }, ErrInvalidText},
		{"fix summary with BOM", func() Draft { d := validFix(); d.Summary = "\uFEFFPaket"; return d }, ErrInvalidText},
		{"fix summary with replacement character", func() Draft { d := validFix(); d.Summary = "a\uFFFDb"; return d }, ErrInvalidText},
		{"fix summary with invalid UTF-8", func() Draft { d := validFix(); d.Summary = "a\xffb"; return d }, ErrInvalidText},
		{"fix summary over 600 bytes", func() Draft {
			d := validFix()
			d.Summary = strings.Repeat("a", MaxSummaryBytes+1)
			return d
		}, ErrLimit},
		{"fix without summary", func() Draft { d := validFix(); d.Summary = ""; return d }, ErrMissing},
		{"fix without steps or mitigations", func() Draft { d := validFix(); d.Steps = nil; return d }, ErrMissing},
		{"fix with seven steps", func() Draft {
			d := validFix()
			d.Steps = make([]StepInput, MaxStepsPerNote+1)
			for i := range d.Steps {
				d.Steps[i] = StepInput{ActionID: "package.install_security", HostID: "host1"}
			}
			return d
		}, ErrLimit},
		{"step with unknown action", func() Draft {
			d := validFix()
			d.Steps[0].ActionID = "act.unknown"
			return d
		}, ErrUnknownAction},
		{"catalog action that is not on the suggestion allowlist, though a candidate", func() Draft {
			d := validFix()
			d.Steps[0] = StepInput{ActionID: "package.remove", HostID: "host1"}
			return d
		}, ErrNotAllowlisted},
		{"allowlisted action on a host that is a candidate but not the group's host", func() Draft {
			d := validFix()
			d.Steps[0] = StepInput{ActionID: "package.install_security", HostID: "host2"}
			return d
		}, ErrNotGroupHost},
		{"step with unknown host", func() Draft {
			d := validFix()
			d.Steps[0].HostID = "host9"
			return d
		}, ErrUnknownHost},
		{"step that is a known action on a known host but not a candidate", func() Draft {
			d := validFix()
			d.Steps[0] = StepInput{ActionID: "docker.restart", HostID: "host1"}
			return d
		}, ErrNotCandidate},
		{"duplicate step", func() Draft {
			d := validFix()
			d.Steps = append(d.Steps, d.Steps[0])
			return d
		}, ErrDuplicateStep},
		{"step with ID containing space", func() Draft {
			d := validFix()
			d.Steps[0].ActionID = "act pkg"
			return d
		}, ErrInvalidField},
		{"step why over 300 bytes", func() Draft {
			d := validFix()
			d.Steps[0].Why = strings.Repeat("w", MaxStepWhyBytes+1)
			return d
		}, ErrLimit},
		{"step why with URL", func() Draft {
			d := validFix()
			d.Steps[0].Why = "www.example.org"
			return d
		}, ErrURL},
		{"four mitigations", func() Draft {
			d := validFix()
			d.Mitigations = []string{"a", "b", "c", "d"}
			return d
		}, ErrLimit},
		{"mitigation over 400 bytes", func() Draft {
			d := validFix()
			d.Mitigations = []string{strings.Repeat("m", MaxMitigationBytes+1)}
			return d
		}, ErrLimit},
		{"mitigation with control character", func() Draft {
			d := validFix()
			d.Mitigations = []string{"a\x1bb"}
			return d
		}, ErrInvalidText},
		{"fix urgency over 300 bytes", func() Draft {
			d := validFix()
			d.Urgency = strings.Repeat("u", MaxUrgencyBytes+1)
			return d
		}, ErrLimit},
		{"fix with text", func() Draft { d := validFix(); d.Text = "zusätzlich"; return d }, ErrFieldNotAllowed},
		{"unknown citation", func() Draft { d := validFix(); d.Citations = []string{"doc-9"}; return d }, ErrUnknownCitation},
		{"four citations", func() Draft {
			d := validFix()
			d.Citations = []string{"doc-1", "doc-2", "doc-1", "doc-2"}
			return d
		}, ErrLimit},
		{"citation with URL", func() Draft {
			d := validFix()
			d.Citations = []string{"http://doc-1"}
			return d
		}, ErrURL},
		{"summary without text", func() Draft { d := validText(KindSummary); d.Text = ""; return d }, ErrMissing},
		{"summary text over 2 KiB", func() Draft {
			d := validText(KindSummary)
			d.Text = strings.Repeat("a", MaxTextBytes+1)
			return d
		}, ErrLimit},
		{"summary text with control character", func() Draft {
			d := validText(KindSummary)
			d.Text = "ok\x00"
			return d
		}, ErrInvalidText},
		{"summary text with URL", func() Draft {
			d := validText(KindSummary)
			d.Text = "siehe https://example.org"
			return d
		}, ErrURL},
		{"summary text with replacement character", func() Draft {
			d := validText(KindSummary)
			d.Text = "\uFFFD"
			return d
		}, ErrInvalidText},
		{"summary carrying steps", func() Draft {
			d := validText(KindSummary)
			d.Steps = []StepInput{{ActionID: "package.install_security", HostID: "host1"}}
			return d
		}, ErrFieldNotAllowed},
		{"answer carrying mitigations", func() Draft {
			d := validText(KindAnswer)
			d.Mitigations = []string{"neu starten"}
			return d
		}, ErrFieldNotAllowed},
		{"answer carrying urgency", func() Draft {
			d := validText(KindAnswer)
			d.Urgency = "hoch"
			return d
		}, ErrFieldNotAllowed},
		{"summary carrying summary field", func() Draft {
			d := validText(KindSummary)
			d.Summary = "doppelt"
			return d
		}, ErrFieldNotAllowed},
	}
	r := newFakeResolver()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.draft(), r)
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("Validate error = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

// TestDecodeErrorsDoNotEchoModelText checks that a refused note's error
// carries none of the model's field names or values: they reach logs and
// HTTP errors and are untrusted (ADR 0016 D6).
func TestDecodeErrorsDoNotEchoModelText(t *testing.T) {
	const secret = "zzEVIL‮"
	inputs := []string{
		`{"kind":"fix","` + secret + `":1}`,
		`{"kind":"fix","ref":"` + secret + `","digest":5}`,
		`{"kind":"fix","ref":"x","summary":"` + secret + `" "x"}`,
		`{"kind":"fix","ref":"x",` + secret + `}`,
	}
	for _, in := range inputs {
		_, err := Decode([]byte(in))
		if err == nil {
			t.Fatalf("Decode(%q) succeeded", in)
		}
		if strings.Contains(err.Error(), "zzEVIL") || strings.ContainsRune(err.Error(), '‮') {
			t.Errorf("Decode error echoes model text: %q", err.Error())
		}
	}
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	ok := `{"kind":"fix","ref":"vu:host1:openssl","digest":"d1","summary":"s","steps":[{"action_id":"package.install_security","host_id":"host1"}]}`
	tests := []struct {
		name   string
		data   string
		wantIs error
	}{
		{"valid", ok, nil},
		{"unknown top-level field", strings.Replace(ok, `"summary"`, `"facts":1,"summary"`, 1), ErrDecode},
		{"snapshot smuggled in body", strings.Replace(ok, `"summary"`, `"snapshot":"{}","summary"`, 1), ErrDecode},
		{"unknown step field", strings.Replace(ok, `"host_id"`, `"parameters":{},"host_id"`, 1), ErrDecode},
		{"trailing data", ok + `{}`, ErrDecode},
		{"array instead of object", `[]`, ErrDecode},
		{"number for digest", strings.Replace(ok, `"d1"`, `1`, 1), ErrDecode},
		{"invalid UTF-8 in raw input", strings.Replace(ok, `"s"`, "\"\xff\"", 1), ErrDecode},
		{"over the request limit", `{"summary":"` + strings.Repeat("a", MaxNoteBytes) + `"}`, ErrLimit},
		{"capitalised top-level key", strings.Replace(ok, `"kind"`, `"Kind"`, 1), ErrDecode},
		{"upper-case step key", strings.Replace(ok, `"action_id"`, `"ACTION_ID"`, 1), ErrDecode},
		{"duplicate steps key", strings.Replace(ok, `"summary"`, `"steps":[],"summary"`, 1), ErrDecode},
		{"duplicate digest key", strings.Replace(ok, `"summary"`, `"digest":"d2","summary"`, 1), ErrDecode},
		{"duplicate step key", strings.Replace(ok, `"host_id"`, `"action_id":"service.restart","host_id"`, 1), ErrDecode},
		{"object instead of mitigation text", `{"kind":"fix","ref":"vu:host1:openssl","digest":"d1","summary":"s","mitigations":[{"text":"x"}]}`, ErrDecode},
		{"object as summary", `{"kind":"fix","ref":"vu:host1:openssl","digest":"d1","summary":{"a":"b"},"steps":[]}`, ErrDecode},
		{"null instead of object", `null`, ErrDecode},
		{"truncated JSON", `{"kind":`, ErrDecode},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.data))
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("Decode error = %v, want %v", err, tc.wantIs)
			}
		})
	}
}
