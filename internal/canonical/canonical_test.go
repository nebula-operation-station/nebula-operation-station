// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const (
	fpA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func validRequest() Request {
	return Request{
		ExecutionID:    "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00",
		ActionID:       "patching.install_security",
		ModuleVersion:  "1.2.0",
		ArtifactSHA256: strings.Repeat("a", 64),
		ParametersHash: strings.Repeat("b", 64),
		CredentialRefs: []string{"nebula-default"},
		RiskClass:      RiskMedium,
		StagePlanHash:  strings.Repeat("c", 64),
		ExpiryUnix:     testNow.Add(time.Hour).Unix(),
		ResolvedTargets: []Target{
			{HostID: "strompi", HostKeyFingerprint: fpB},
			{HostID: "dockerflux", HostKeyFingerprint: fpA},
		},
	}
}

func TestCanonicalFormIsStable(t *testing.T) {
	_, b, d, err := Canonicalize(validRequest(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	// Golden value: if this changes, every stored permit and every client
	// implementation changes meaning. Bump RequestVersion instead.
	const want = `{"action_id":"patching.install_security","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_refs":["nebula-default"],"execution_id":"0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00","expiry_unix":1791637200,"module_version":"1.2.0","parameters_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_version":1,"resolved_targets":[{"host_id":"dockerflux","host_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},{"host_id":"strompi","host_key_fingerprint":"SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}],"risk_class":"MEDIUM","stage_plan_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	if string(b) != want {
		t.Fatalf("canonical bytes changed:\n got %s\nwant %s", b, want)
	}
	// Computed independently: python3 hashlib.sha256 over the bytes above.
	const wantDigest = "2d322457f32cd7d426a1985554f8d8cfe542ce6f86fd6f030e208a6531d8f9e7"
	if d.String() != wantDigest {
		t.Fatalf("digest changed: got %s want %s", d, wantDigest)
	}
}

func TestTargetOrderDoesNotChangeDigest(t *testing.T) {
	a := validRequest()
	b := validRequest()
	b.ResolvedTargets[0], b.ResolvedTargets[1] = b.ResolvedTargets[1], b.ResolvedTargets[0]
	_, _, da, err := Canonicalize(a, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, _, db, err := Canonicalize(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("target order must not change the digest")
	}
}

func TestEveryBoundFieldChangesDigest(t *testing.T) {
	_, _, base, err := Canonicalize(validRequest(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Request){
		"execution_id":     func(r *Request) { r.ExecutionID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a01" },
		"action_id":        func(r *Request) { r.ActionID = "patching.install_all" },
		"module_version":   func(r *Request) { r.ModuleVersion = "1.2.1" },
		"artifact":         func(r *Request) { r.ArtifactSHA256 = strings.Repeat("d", 64) },
		"parameters":       func(r *Request) { r.ParametersHash = strings.Repeat("e", 64) },
		"credential":       func(r *Request) { r.CredentialRefs = []string{"other-key"} },
		"risk":             func(r *Request) { r.RiskClass = RiskHigh },
		"stage_plan":       func(r *Request) { r.StagePlanHash = strings.Repeat("f", 64) },
		"expiry":           func(r *Request) { r.ExpiryUnix++ },
		"extra target":     func(r *Request) { r.ResolvedTargets = append(r.ResolvedTargets, Target{"netbird-vps", fpA}) },
		"host key":         func(r *Request) { r.ResolvedTargets[0].HostKeyFingerprint = fpA },
		"host id":          func(r *Request) { r.ResolvedTargets[0].HostID = "strompi2" },
		"dropped target":   func(r *Request) { r.ResolvedTargets = r.ResolvedTargets[:1] },
		"extra credential": func(r *Request) { r.CredentialRefs = append(r.CredentialRefs, "second") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := validRequest()
			mutate(&r)
			_, _, d, err := Canonicalize(r, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if d == base {
				t.Fatalf("mutating %s did not change the digest", name)
			}
		})
	}
}

func TestValidationRejectsMalformedRequests(t *testing.T) {
	cases := map[string]func(*Request){
		"uppercase uuid":     func(r *Request) { r.ExecutionID = strings.ToUpper(r.ExecutionID) },
		"bad action":         func(r *Request) { r.ActionID = "patching" },
		"bad version":        func(r *Request) { r.ModuleVersion = "1.2" },
		"short artifact":     func(r *Request) { r.ArtifactSHA256 = "abc" },
		"uppercase hex":      func(r *Request) { r.ParametersHash = strings.Repeat("B", 64) },
		"unknown risk":       func(r *Request) { r.RiskClass = "SEVERE" },
		"expired":            func(r *Request) { r.ExpiryUnix = testNow.Add(-time.Second).Unix() },
		"too long":           func(r *Request) { r.ExpiryUnix = testNow.Add(25 * time.Hour).Unix() },
		"no credentials":     func(r *Request) { r.CredentialRefs = nil },
		"dup credentials":    func(r *Request) { r.CredentialRefs = []string{"a", "a"} },
		"no targets":         func(r *Request) { r.ResolvedTargets = nil },
		"dup targets":        func(r *Request) { r.ResolvedTargets[1].HostID = r.ResolvedTargets[0].HostID },
		"bad fingerprint":    func(r *Request) { r.ResolvedTargets[0].HostKeyFingerprint = "MD5:aa:bb" },
		"html in host":       func(r *Request) { r.ResolvedTargets[0].HostID = "<script>" },
		"wrong version":      func(r *Request) { r.RequestVersion = 2 },
		"bad credential ref": func(r *Request) { r.CredentialRefs = []string{"../etc/passwd"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRequest()
			mutate(&r)
			_, _, _, err := Canonicalize(r, testNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}

func TestNormalizeDoesNotMutateInput(t *testing.T) {
	r := validRequest()
	first := r.ResolvedTargets[0].HostID
	if _, err := Normalize(r, testNow); err != nil {
		t.Fatal(err)
	}
	if r.ResolvedTargets[0].HostID != first {
		t.Fatal("Normalize mutated its input")
	}
}

func TestHashParameters(t *testing.T) {
	a, err := HashParameters([]byte(`{"b":1,"a":[1,2,{"y":true,"x":null}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashParameters([]byte(" {\n \"a\": [1,2,{\"x\":null,\"y\":true}], \"b\": 1 }"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("equivalent JSON must hash identically")
	}
	empty1, _ := HashParameters(nil)
	empty2, _ := HashParameters([]byte("{}"))
	if empty1 != empty2 {
		t.Fatal("empty parameters must equal {}")
	}
	for name, in := range map[string]string{
		"array":         `[1,2]`,
		"string":        `"x"`,
		"duplicate":     `{"a":1,"a":2}`,
		"nested dup":    `{"a":{"k":1,"k":2}}`,
		"trailing":      `{"a":1} {"b":2}`,
		"invalid":       `{"a":}`,
		"deep":          strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40),
		"deep in array": `{"a":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`,
		"float alias":   `{"n":1.0}`,
		"exponent":      `{"n":1e0}`,
		"negative zero": `{"n":-0}`,
		"beyond 2^53":   `{"n":9007199254740993}`,
		"huge":          `{"n":1e400}`,
		"nested number": `{"a":[{"n":2.50}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := HashParameters([]byte(in)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
	if _, err := HashParameters([]byte(`{"a":"` + strings.Repeat("x", MaxParametersSize) + `"}`)); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestCanonicalNumbersAccepted(t *testing.T) {
	for _, in := range []string{`{"n":1}`, `{"n":-2.5}`, `{"n":9007199254740992}`, `{"n":1e+21}`, `{"n":0.000001}`, `{"n":1e-7}`} {
		if _, err := HashParameters([]byte(in)); err != nil {
			t.Errorf("%s rejected: %v", in, err)
		}
	}
}

func TestOneHashOneMeaning(t *testing.T) {
	// Each pair denotes the same double but different text; only the
	// canonical spelling may be accepted, so no two inputs share a hash.
	for _, pair := range [][2]string{{`{"n":1}`, `{"n":1.0}`}, {`{"n":0}`, `{"n":-0}`}, {`{"n":9007199254740992}`, `{"n":9007199254740993}`}} {
		_, errA := HashParameters([]byte(pair[0]))
		_, errB := HashParameters([]byte(pair[1]))
		if errA != nil || errB == nil {
			t.Errorf("%s / %s: want canonical accepted and alias rejected, got %v / %v", pair[0], pair[1], errA, errB)
		}
	}
}

func FuzzHashParameters(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":[{"b":"é"}]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		h1, err1 := HashParameters(in)
		h2, err2 := HashParameters(in)
		if (err1 == nil) != (err2 == nil) || h1 != h2 {
			t.Fatal("HashParameters is not deterministic")
		}
	})
}

func TestParseDigest(t *testing.T) {
	_, _, d, err := Canonicalize(validRequest(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseDigest(d.String())
	if err != nil || back != d {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := ParseDigest(strings.ToUpper(d.String())); err == nil {
		t.Fatal("uppercase digest must be rejected")
	}
}
