// SPDX-License-Identifier: AGPL-3.0-or-later

package riskpolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// fakeSource keys host records by host_id and fingerprint, like executordb.
type fakeSource struct {
	artifacts map[string]canonical.Risk // sha|action|version
	hosts     map[string]canonical.Risk // host|fingerprint
	err       error
}

func key(a, b, c string) string { return a + "|" + b + "|" + c }

func (f *fakeSource) ArtifactRisk(sha, action, version string) (canonical.Risk, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	r, ok := f.artifacts[key(sha, action, version)]
	return r, ok, nil
}

func (f *fakeSource) HostCriticality(h, fp string) (canonical.Risk, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	if r, ok := f.hosts[h+"|"+fp]; ok {
		return r, true, nil
	}
	var related canonical.Risk
	for k, r := range f.hosts {
		kh, kfp, _ := strings.Cut(k, "|")
		if kh == h || kfp == fp {
			related = canonical.MaxRisk(related, r)
		}
	}
	return related, false, nil
}

const (
	fpA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

// tg builds targets "a" (key fpA) and "b" (key fpB) by name.
func tg(names ...string) []canonical.Target {
	var out []canonical.Target
	for _, n := range names {
		fp := fpA
		if n == "b" {
			fp = fpB
		}
		out = append(out, canonical.Target{HostID: n, HostKeyFingerprint: fp})
	}
	return out
}

// rec builds host records for tg's targets.
func rec(m map[string]canonical.Risk) map[string]canonical.Risk {
	out := map[string]canonical.Risk{}
	for n, r := range m {
		out[tg(n)[0].HostID+"|"+tg(n)[0].HostKeyFingerprint] = r
	}
	return out
}

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

func req() canonical.Request {
	return canonical.Request{ArtifactSHA256: shaA, ActionID: "patching.install_security", ModuleVersion: "1.0.0"}
}

func TestNewRequiresSource(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("policy without a source accepted")
	}
}

func TestMinimumRisk(t *testing.T) {
	const (
		L = canonical.RiskLow
		M = canonical.RiskMedium
		H = canonical.RiskHigh
		C = canonical.RiskCritical
	)
	type hm = map[string]canonical.Risk
	cases := []struct {
		name      string
		declared  canonical.Risk // "" = not trusted
		hosts     hm
		targets   []string
		want      canonical.Risk
		reasonHas string
	}{
		{"untrusted artifact is HIGH", "", hm{"a": L}, []string{"a"}, H, "not trusted"},
		{"untrusted artifact on a critical host", "", hm{"a": C}, []string{"a"}, C, "host a (" + fpA + ") is CRITICAL"},
		{"trusted LOW on recorded LOW..HIGH hosts", L, hm{"a": H, "b": L}, []string{"a", "b"}, L, "trusted as LOW"},
		{"trusted LOW on a CRITICAL host needs MEDIUM", L, hm{"a": L, "b": C}, []string{"a", "b"}, M, "host b"},
		{"trusted LOW on an unrecorded host needs MEDIUM", L, hm{"a": L}, []string{"a", "b"}, M, "no matching criticality record"},
		{"trusted MEDIUM on LOW hosts", M, hm{"a": L, "b": L}, []string{"a", "b"}, M, "trusted as MEDIUM"},
		{"trusted MEDIUM on an unrecorded host", M, hm{"a": L}, []string{"a", "b"}, H, "host b"},
		{"trusted MEDIUM, highest host wins", M, hm{"a": H, "b": C}, []string{"a", "b"}, C, "host b"},
		{"trusted CRITICAL is not lowered by hosts", C, hm{"a": L}, []string{"a"}, C, "trusted as CRITICAL"},
		{"no hosts: action floor only", M, nil, nil, M, "trusted as MEDIUM"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := &fakeSource{artifacts: map[string]canonical.Risk{}, hosts: rec(c.hosts)}
			if c.declared != "" {
				src.artifacts[key(shaA, "patching.install_security", "1.0.0")] = c.declared
			}
			p, err := New(src)
			if err != nil {
				t.Fatal(err)
			}
			got, why, err := p.MinimumRisk(req(), tg(c.targets...))
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("floor %s, want %s (%s)", got, c.want, why)
			}
			if !strings.Contains(why, c.reasonHas) {
				t.Fatalf("reason %q does not contain %q", why, c.reasonHas)
			}
		})
	}
}

// A host record counts only for its own pinned key: the server cannot put
// a CRITICAL host's key under the name of a LOW host.
func TestHostRecordIsBoundToItsKey(t *testing.T) {
	src := &fakeSource{
		artifacts: map[string]canonical.Risk{key(shaA, "patching.install_security", "1.0.0"): canonical.RiskMedium},
		hosts:     rec(map[string]canonical.Risk{"a": canonical.RiskLow, "b": canonical.RiskCritical}),
	}
	p, _ := New(src)
	// The LOW host's name with an unrelated key: unrecorded, HIGH.
	other := []canonical.Target{{HostID: "a", HostKeyFingerprint: "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"}}
	got, why, err := p.MinimumRisk(req(), other)
	if err != nil {
		t.Fatal(err)
	}
	if got != UnknownHostFloor {
		t.Fatalf("LOW host under another key: floor %s, want %s (%s)", got, UnknownHostFloor, why)
	}
	relabelled := []canonical.Target{{HostID: "a", HostKeyFingerprint: fpB}}
	// The CRITICAL host under another key (or the key under another name)
	// stays CRITICAL: a partial match can raise the floor, never lower it.
	for _, tgt := range []canonical.Target{
		{HostID: "b", HostKeyFingerprint: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
		{HostID: "c", HostKeyFingerprint: fpB},
	} {
		got, why, err := p.MinimumRisk(req(), []canonical.Target{tgt})
		if err != nil {
			t.Fatal(err)
		}
		if got != canonical.RiskCritical {
			t.Fatalf("%v: floor %s, want CRITICAL (%s)", tgt, got, why)
		}
	}
	src.artifacts[key(shaA, "patching.install_security", "1.0.0")] = canonical.RiskLow
	if got, _, _ := p.MinimumRisk(req(), relabelled); got != canonical.RiskMedium {
		t.Fatalf("relabelled host, read-only action: floor %s, want MEDIUM", got)
	}
}

// Trust is bound to the exact artifact, action and version.
func TestTrustIsBoundToArtifactActionAndVersion(t *testing.T) {
	src := &fakeSource{
		artifacts: map[string]canonical.Risk{key(shaA, "patching.install_security", "1.0.0"): canonical.RiskLow},
		hosts:     map[string]canonical.Risk{},
	}
	p, _ := New(src)
	for name, mut := range map[string]func(*canonical.Request){
		"other artifact": func(r *canonical.Request) { r.ArtifactSHA256 = shaB },
		"other action":   func(r *canonical.Request) { r.ActionID = "system.reboot" },
		"other version":  func(r *canonical.Request) { r.ModuleVersion = "1.0.1" },
	} {
		r := req()
		mut(&r)
		got, _, err := p.MinimumRisk(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != UntrustedFloor {
			t.Errorf("%s: floor %s, want %s", name, got, UntrustedFloor)
		}
	}
}

func TestSourceErrorsArePropagated(t *testing.T) {
	p, _ := New(&fakeSource{err: errors.New("io")})
	if _, _, err := p.MinimumRisk(req(), tg("a")); err == nil {
		t.Fatal("source error swallowed")
	}
	// Error from the host lookup only.
	src := &hostErrSource{}
	p, _ = New(src)
	if _, _, err := p.MinimumRisk(req(), tg("a")); err == nil {
		t.Fatal("host lookup error swallowed")
	}
}

type hostErrSource struct{}

func (hostErrSource) ArtifactRisk(string, string, string) (canonical.Risk, bool, error) {
	return canonical.RiskMedium, true, nil
}
func (hostErrSource) HostCriticality(string, string) (canonical.Risk, bool, error) {
	return "", false, errors.New("io")
}
