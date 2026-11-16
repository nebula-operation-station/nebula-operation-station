// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// Fuzz targets for the parsers of untrusted input that decide where a
// credential or a metadata request may go: the WWW-Authenticate challenge,
// the realm, the Link pagination header, and image references from hosts.
// Every seed below is taken from the existing tests of this package.

// FuzzParseChallengeParams drives parseChallengeParams with arbitrary header
// parameter text. It must never panic, and an accepted challenge stays within
// maxChallengeParams parameters and MaxChallengeLen bytes per value.
func FuzzParseChallengeParams(f *testing.F) {
	f.Add(`realm="https://a/b",service="s", scope="repository:x:pull"`)
	f.Add(`realm="a",realm="b"`)
	f.Add(`realm="a`)
	f.Add(`=x`)
	f.Add(`realm="a" service="b"`)
	f.Add(`realm="a\"b"`)
	f.Add(`realm="https://auth.example/token",service="registry.example"`)
	f.Add(`realm=""`)
	f.Add(`realm="a,b",service=c`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, s string) {
		got, err := parseChallengeParams(s)
		if err != nil {
			return
		}
		if len(got) > maxChallengeParams {
			t.Fatalf("accepted %d parameters, limit %d: %q", len(got), maxChallengeParams, s)
		}
		for k, v := range got {
			if k == "" {
				t.Fatalf("empty parameter name accepted: %q", s)
			}
			if len(v) > MaxChallengeLen {
				t.Fatalf("value of %d bytes accepted, limit %d", len(v), MaxChallengeLen)
			}
		}
	})
}

// TestParseChallengeParamsLimits pins the parameter-count and value-length
// limits at the boundary: the limit is accepted, one more is refused.
func TestParseChallengeParamsLimits(t *testing.T) {
	var params []string
	for i := 0; i < maxChallengeParams; i++ {
		params = append(params, fmt.Sprintf(`k%d="v"`, i))
	}
	if _, err := parseChallengeParams(strings.Join(params, ",")); err != nil {
		t.Fatalf("%d parameters refused: %v", maxChallengeParams, err)
	}
	params = append(params, `extra="v"`)
	if _, err := parseChallengeParams(strings.Join(params, ",")); !errors.Is(err, ErrRealmNotApproved) {
		t.Fatalf("%d parameters accepted or wrong error: %v", maxChallengeParams+1, err)
	}

	atLimit := `realm="` + strings.Repeat("a", MaxChallengeLen) + `"`
	if _, err := parseChallengeParams(atLimit); err != nil {
		t.Fatalf("value of %d bytes refused: %v", MaxChallengeLen, err)
	}
	overLimit := `realm="` + strings.Repeat("a", MaxChallengeLen+1) + `"`
	if _, err := parseChallengeParams(overLimit); !errors.Is(err, ErrRealmNotApproved) {
		t.Fatalf("value of %d bytes accepted or wrong error: %v", MaxChallengeLen+1, err)
	}
}

// FuzzParseRealm drives parseRealm with arbitrary realm text. Precondition
// (private.go Validate and checkChallenge): an accepted realm is the one the
// administrator approved, so the test asserts only the shape it must have:
// https, no userinfo, a host, and an exact round trip.
func FuzzParseRealm(f *testing.F) {
	f.Add("https://auth.example/token")
	f.Add("https://auth.example/token?a=b")
	f.Add("https://u:p@auth.example/token")
	f.Add("http://auth.example/token")
	f.Add("https://a/b#frag")
	f.Add("https:///token")
	f.Add("https://@auth.example/token")
	f.Add("https://auth.example")
	f.Add("https://auth.example/a b")
	f.Add("https://auth.example/a\"b")

	f.Fuzz(func(t *testing.T, s string) {
		u, err := parseRealm(s)
		if err != nil {
			return
		}
		if u.Scheme != "https" {
			t.Fatalf("accepted realm with scheme %q: %q", u.Scheme, s)
		}
		if u.User != nil {
			t.Fatalf("accepted realm with userinfo: %q", s)
		}
		if u.Host == "" {
			t.Fatalf("accepted realm without host: %q", s)
		}
		if u.String() != s {
			t.Fatalf("realm does not round trip: %q -> %q", s, u.String())
		}
	})
}

// FuzzParseLinkNext drives parseLinkNext and the resolveLink step that the
// caller (fetchTags in client.go) always applies to its result before any
// request. Precondition: parseLinkNext only extracts the target; the
// tag-list walk never uses it without resolveLink. The test asserts that
// whatever resolveLink accepts is a path on the same registry origin, with no
// userinfo, fragment or other path.
func FuzzParseLinkNext(f *testing.F) {
	f.Add(`</v2/repo/tags/list?n=2>; rel="next"`)
	f.Add(`<http://evil.example.com/v2/repo/tags/list>; rel="next"`)
	f.Add(`</v2/repo/blobs/sha256:abc>; rel="next"`)
	f.Add(`<https://registry.example/v2/repo/tags/list>; rel="next"`)
	f.Add(`<//evil.example/v2/repo/tags/list>; rel=next`)
	f.Add(`<https://u:p@registry.example/v2/repo/tags/list>; rel="next"`)
	f.Add(`</a>; rel="prev", </v2/repo/tags/list?last=x>; rel="next"`)
	f.Add(`</v2/repo/tags/list#x>; rel="next"`)
	f.Add(`<>; rel="next"`)

	const registry = "https://registry.example"
	const listPath = "/v2/repo/tags/list"
	f.Fuzz(func(t *testing.T, h string) {
		next, ok := parseLinkNext(h)
		if !ok {
			return
		}
		var c Client
		resolved, err := c.resolveLink(registry, listPath, next)
		if err != nil {
			return
		}
		u, err := url.Parse(resolved)
		if err != nil {
			t.Fatalf("resolved link does not parse: %q", resolved)
		}
		if originOf(u) != registry {
			t.Fatalf("resolved link leaves the registry: %q from %q", resolved, h)
		}
		if u.User != nil || u.Fragment != "" || u.Path != listPath {
			t.Fatalf("resolved link has a foreign part: %q from %q", resolved, h)
		}
	})
}

// TestResolveLinkRefusesUserinfoAndFragment is the regression for a Link
// target with userinfo on the registry's own origin: net/http would turn the
// userinfo into a Basic Authorization header, so the link is refused.
func TestResolveLinkRefusesUserinfoAndFragment(t *testing.T) {
	const registry = "https://registry.example"
	const listPath = "/v2/repo/tags/list"
	var c Client
	for _, raw := range []string{
		"https://u:p@registry.example/v2/repo/tags/list",
		"//u@registry.example/v2/repo/tags/list",
		"/v2/repo/tags/list#x",
	} {
		if _, err := c.resolveLink(registry, listPath, raw); !errors.Is(err, ErrRedirectNotAllowed) {
			t.Errorf("resolveLink(%q): want ErrRedirectNotAllowed, got %v", raw, err)
		}
	}
	if got, err := c.resolveLink(registry, listPath, "/v2/repo/tags/list?n=2"); err != nil || got != registry+"/v2/repo/tags/list?n=2" {
		t.Fatalf("plain next link refused: %q, %v", got, err)
	}
}

// FuzzParseRef drives ParseRef with arbitrary image references. An accepted
// reference has a valid repository, at most one of tag and digest, and
// parsing its reassembled name yields the same reference.
func FuzzParseRef(f *testing.F) {
	digest := "sha256:" + strings.Repeat("a", 64)
	f.Add("https://registry-1.docker.io/library/nginx:1.25")
	f.Add("registry-1.docker.io/library/nginx:1.25")
	f.Add("http://ghcr.io/owner/repo:2.0")
	f.Add("ghcr.io/owner/repo")
	f.Add("quay.io/org/app@" + digest)
	f.Add("example.com")
	f.Add("example.com/")
	f.Add("ftp://example.com/repo:1")
	f.Add("example.com/UPPER:1")
	f.Add("example.com/repo:bad tag")
	f.Add("example.com/repo@sha256:zzz")
	f.Add("example.com/repo:1@" + digest)
	f.Add("a@b/repo:1")
	f.Add("")

	f.Fuzz(func(t *testing.T, image string) {
		ref, err := ParseRef(image)
		if err != nil {
			return
		}
		if err := validateRepo(ref.Repository); err != nil {
			t.Fatalf("accepted repository %q: %v", ref.Repository, err)
		}
		if ref.Tag != "" && ref.Digest != "" {
			t.Fatalf("tag and digest both set for %q: %+v", image, ref)
		}
		if ref.Tag != "" && !ValidTag(ref.Tag) {
			t.Fatalf("accepted tag %q", ref.Tag)
		}
		if ref.Digest != "" && !ValidDigest(ref.Digest) {
			t.Fatalf("accepted digest %q", ref.Digest)
		}
		name := ref.Registry + "/" + ref.Repository
		switch {
		case ref.Tag != "":
			name += ":" + ref.Tag
		case ref.Digest != "":
			name += "@" + ref.Digest
		}
		again, err := ParseRef(name)
		if err != nil {
			t.Fatalf("reassembled name %q refused: %v", name, err)
		}
		if again != ref {
			t.Fatalf("reassembled name %q gives %+v, want %+v", name, again, ref)
		}
	})
}

// FuzzRegistryHostOf drives registryHostOf with arbitrary image text. An
// accepted host never contains a path separator, an at sign or white space,
// and host plus rest reassembles the image.
func FuzzRegistryHostOf(f *testing.F) {
	f.Add("registry-1.docker.io/library/nginx:1.25")
	f.Add("localhost:5000/app")
	f.Add("ghcr.io/owner/repo")
	f.Add("a@b/repo:1")
	f.Add("https://ghcr.io/x")
	f.Add("quay.io/org/app@sha256:" + strings.Repeat("a", 64))
	f.Add("nginx:1.25")
	f.Add("ghcr.io /repo")
	f.Add("")

	f.Fuzz(func(t *testing.T, image string) {
		host, rest, ok := registryHostOf(image)
		if !ok {
			return
		}
		if strings.ContainsAny(host, "/@") {
			t.Fatalf("host %q contains / or @: %q", host, image)
		}
		if strings.IndexFunc(host, unicode.IsSpace) >= 0 {
			t.Fatalf("host %q contains white space: %q", host, image)
		}
		if host+"/"+rest != image {
			t.Fatalf("host %q and rest %q do not reassemble %q", host, rest, image)
		}
	})
}
