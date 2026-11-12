// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// regEntry and linkEntry build installed-files entries as maps.
func regEntry(path string, content []byte, mode string) map[string]any {
	return map[string]any{"path": path, "type": "file", "size": len(content), "sha256": hexSum(content), "mode": mode, "owner": "root:root"}
}

func linkEntry(path, target string) map[string]any {
	return map[string]any{"path": path, "type": "symlink", "target": target, "owner": "root:root"}
}

// testList returns a valid installed-files document as a map, for
// mutation.
func testList() map[string]any {
	files := []any{
		regEntry("/lib/systemd/system/nebula-executor.service", []byte("[Unit]\n"), "0644"),
		regEntry("/lib/systemd/system/nebula-server.service.d/20-x.conf", []byte("[Service]\n"), "0644"),
		regEntry("/usr/bin/nebula", []byte("nebula"), "0755"),
		regEntry("/usr/bin/nebula-executor", []byte("executor"), "0755"),
		linkEntry("/usr/share/doc/nebula-operation-station/guide.md", "../../nebula/guide.md"),
		regEntry("/usr/share/nebula/release/builtins.tar", []byte("tar"), "0644"),
		regEntry("/usr/share/nebula/web/empty.css", nil, "0644"),
	}
	return map[string]any{
		"format":          InstalledFilesFormat,
		"release_version": "1.4.0",
		"flavours": map[string]any{
			"deb:amd64":     files,
			"tarball:arm64": []any{regEntry("/etc/systemd/system/nebula-server.service", []byte("u"), "0644"), regEntry("/usr/bin/nebula", []byte("n"), "0755")},
		},
	}
}

func TestParseInstalledFilesAcceptsValidList(t *testing.T) {
	raw := canon(t, testList())
	l, err := ParseInstalledFiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if l.ReleaseVersion != "1.4.0" || len(l.Flavours) != 2 || l.Flavours[0].Name != "deb:amd64" || l.Flavours[1].Name != "tarball:arm64" {
		t.Fatalf("list = %+v", l)
	}
	if l.Digest != hexSum(raw) {
		t.Fatalf("digest %s", l.Digest)
	}
	f, ok := l.Flavour("deb:amd64")
	if !ok || len(f.Files) != 7 {
		t.Fatalf("flavour = %+v", f)
	}
	nb := f.Files[2]
	if nb.Path != "/usr/bin/nebula" || nb.Type != FileRegular || nb.Size != 6 || nb.SHA256 != hexSum([]byte("nebula")) || nb.Mode != 0o755 || nb.Owner != "root:root" || nb.Target != "" {
		t.Fatalf("regular entry = %+v", nb)
	}
	ln := f.Files[4]
	if ln.Type != FileSymlink || ln.Target != "../../nebula/guide.md" || ln.Size != 0 || ln.SHA256 != "" {
		t.Fatalf("symlink entry = %+v", ln)
	}
	if _, ok := l.Flavour("container:amd64"); ok {
		t.Fatal("unknown flavour found")
	}
	// Marshal is the exact inverse of the parser.
	out, err := l.Marshal()
	if err != nil || !bytes.Equal(out, raw) {
		t.Fatalf("marshal round trip: %v\n%s\n%s", err, out, raw)
	}
}

// mutate returns testList with one change applied to it.
func mutate(fn func(m map[string]any, files []any) map[string]any) map[string]any {
	m := testList()
	files := m["flavours"].(map[string]any)["deb:amd64"].([]any)
	if r := fn(m, files); r != nil {
		return r
	}
	return m
}

func setEntry(i int, k string, v any) func(map[string]any, []any) map[string]any {
	return func(_ map[string]any, files []any) map[string]any {
		if v == nil {
			delete(files[i].(map[string]any), k)
		} else {
			files[i].(map[string]any)[k] = v
		}
		return nil
	}
}

func TestParseInstalledFilesRejectsMalformedLists(t *testing.T) {
	many := make([]any, 0, MaxInstalledEntries+1)
	for i := 0; i <= MaxInstalledEntries; i++ {
		many = append(many, regEntry(fmt.Sprintf("/usr/share/nebula/f%05d", i), nil, "0644"))
	}
	flavours := map[string]any{}
	for i := 0; i <= MaxFlavours; i++ {
		flavours[fmt.Sprintf("deb:a%d", i)] = []any{regEntry("/usr/bin/nebula", nil, "0755")}
	}
	cases := map[string]map[string]any{
		"wrong format":      mutate(func(m map[string]any, _ []any) map[string]any { m["format"] = "nebula-release-v1"; return nil }),
		"bad version":       mutate(func(m map[string]any, _ []any) map[string]any { m["release_version"] = "v1.4.0"; return nil }),
		"extra top field":   mutate(func(m map[string]any, _ []any) map[string]any { m["comment"] = "x"; return nil }),
		"missing flavours":  mutate(func(m map[string]any, _ []any) map[string]any { delete(m, "flavours"); return nil }),
		"flavours an array": mutate(func(m map[string]any, _ []any) map[string]any { m["flavours"] = []any{}; return nil }),
		"no flavours":       mutate(func(m map[string]any, _ []any) map[string]any { m["flavours"] = map[string]any{}; return nil }),
		"too many flavours": mutate(func(m map[string]any, _ []any) map[string]any { m["flavours"] = flavours; return nil }),
		"bad flavour kind": mutate(func(m map[string]any, files []any) map[string]any {
			m["flavours"] = map[string]any{"rpm:amd64": files}
			return nil
		}),
		"bad flavour arch": mutate(func(m map[string]any, files []any) map[string]any {
			m["flavours"] = map[string]any{"deb:AMD64": files}
			return nil
		}),
		"flavour without arch": mutate(func(m map[string]any, files []any) map[string]any {
			m["flavours"] = map[string]any{"deb": files}
			return nil
		}),
		"empty flavour": mutate(func(m map[string]any, _ []any) map[string]any {
			m["flavours"] = map[string]any{"deb:amd64": []any{}}
			return nil
		}),
		"too many entries": mutate(func(m map[string]any, _ []any) map[string]any {
			m["flavours"] = map[string]any{"deb:amd64": many}
			return nil
		}),
		"unsorted paths": mutate(func(m map[string]any, files []any) map[string]any {
			files[2], files[3] = files[3], files[2]
			return nil
		}),
		"duplicate path": mutate(func(m map[string]any, files []any) map[string]any {
			files[3] = regEntry("/usr/bin/nebula", []byte("x"), "0755")
			return nil
		}),
		"file is a parent directory of another": mutate(func(m map[string]any, files []any) map[string]any {
			m["flavours"] = map[string]any{"deb:amd64": []any{
				regEntry("/usr/share/nebula/web", nil, "0644"),
				regEntry("/usr/share/nebula/web.css", nil, "0644"),
				regEntry("/usr/share/nebula/web/app.js", nil, "0644"),
			}}
			return nil
		}),
		"entry not an object":     mutate(func(_ map[string]any, files []any) map[string]any { files[0] = "x"; return nil }),
		"unknown entry field":     mutate(setEntry(2, "uid", 0)),
		"missing mode":            mutate(setEntry(2, "mode", nil)),
		"missing owner":           mutate(setEntry(2, "owner", nil)),
		"regular with target":     mutate(setEntry(2, "target", "/usr/bin/x")),
		"symlink with sha256":     mutate(setEntry(4, "sha256", hexSum(nil))),
		"symlink with mode":       mutate(setEntry(4, "mode", "0777")),
		"symlink no target":       mutate(setEntry(4, "target", nil)),
		"empty target":            mutate(setEntry(4, "target", "")),
		"target bad char":         mutate(setEntry(4, "target", "a b")),
		"target too long":         mutate(setEntry(4, "target", strings.Repeat("a", MaxInstalledPath+1))),
		"unknown type":            mutate(setEntry(2, "type", "dir")),
		"type not a string":       mutate(setEntry(2, "type", 1)),
		"relative path":           mutate(setEntry(2, "path", "usr/bin/nebula")),
		"dot dot path":            mutate(setEntry(2, "path", "/usr/bin/../bin/nebula")),
		"dot component":           mutate(setEntry(2, "path", "/usr/share/nebula/./x")),
		"double slash":            mutate(setEntry(2, "path", "/usr/bin//nebula")),
		"trailing slash":          mutate(setEntry(2, "path", "/usr/share/nebula/x/")),
		"space in path":           mutate(setEntry(2, "path", "/usr/bin/nebula x")),
		"non-ASCII path":          mutate(setEntry(2, "path", "/usr/bin/nebulä")),
		"newline in path":         mutate(setEntry(2, "path", "/usr/bin/nebula\n")),
		"path too long":           mutate(setEntry(5, "path", pathOverLimit)),
		"deb unit in tarball dir": mutate(setEntry(0, "path", "/etc/systemd/system/nebula-executor.service")),
		"deb local drop-in":       mutate(setEntry(1, "path", "/etc/systemd/system/nebula-server.service.d/20-x.conf")),
		"deb drop-in not .conf":   mutate(setEntry(1, "path", "/lib/systemd/system/nebula-server.service.d/20-x")),
		"iconfetch nftables":      mutate(setEntry(6, "path", "/etc/nebula/nebula-iconfetch.nft")),
		"tarball local drop-in": mutate(func(m map[string]any, _ []any) map[string]any {
			m["flavours"].(map[string]any)["tarball:arm64"] = []any{
				regEntry("/etc/systemd/system/nebula-executor.service.d/10-local.conf", []byte("[Service]\n"), "0644"),
				regEntry("/usr/bin/nebula", []byte("n"), "0755"),
			}
			return nil
		}),
		"tarball unit in deb dir": mutate(func(m map[string]any, _ []any) map[string]any {
			m["flavours"].(map[string]any)["tarball:arm64"] = []any{
				regEntry("/lib/systemd/system/nebula-server.service", []byte("u"), "0644"),
				regEntry("/usr/bin/nebula", []byte("n"), "0755"),
			}
			return nil
		}),
		"container unit": mutate(func(m map[string]any, _ []any) map[string]any {
			m["flavours"].(map[string]any)["container:amd64"] = []any{
				regEntry("/etc/systemd/system/nebula-server.service", []byte("u"), "0644"),
			}
			return nil
		}),
		"config path":           mutate(setEntry(6, "path", "/var/lib/nebula/x")),
		"etc nebula config":     mutate(setEntry(5, "path", "/usr/share/nebula/../../../etc/nebula/server.json")),
		"server.json":           mutate(setEntry(6, "path", "/var/nebula/server.json")),
		"foreign binary":        mutate(setEntry(2, "path", "/usr/bin/a-nebula")),
		"bin subdirectory":      mutate(setEntry(2, "path", "/usr/bin/nebula.d/x")),
		"foreign unit":          mutate(setEntry(0, "path", "/lib/systemd/system/ssh.service")),
		"unit too deep":         mutate(setEntry(1, "path", "/lib/systemd/system/nebula-server.service.d/a/b")),
		"drop-in dir not .d":    mutate(setEntry(1, "path", "/lib/systemd/system/nebula-server.service/x")),
		"bare prefix directory": mutate(setEntry(6, "path", "/usr/share/nebulax")),
		"mode not octal":        mutate(setEntry(2, "mode", "0758")),
		"mode three digits":     mutate(setEntry(2, "mode", "755")),
		"mode integer":          mutate(setEntry(2, "mode", 493)),
		"owner without group":   mutate(setEntry(2, "owner", "root")),
		"owner uppercase":       mutate(setEntry(2, "owner", "Root:root")),
		"owner numeric":         mutate(setEntry(2, "owner", "0:0")),
		"owner extra colon":     mutate(setEntry(2, "owner", "root:root:x")),
		"uppercase sha256":      mutate(setEntry(2, "sha256", strings.ToUpper(hexSum(nil)))),
		"short sha256":          mutate(setEntry(2, "sha256", "abcd")),
		"negative size":         mutate(setEntry(2, "size", -1)),
		"size too large":        mutate(setEntry(2, "size", int64(MaxInstalledFileSize)+1)),
		"fractional size":       mutate(setEntry(2, "size", 1.5)),
		"size a string":         mutate(setEntry(2, "size", "6")),
	}
	for name, m := range cases {
		if _, err := ParseInstalledFiles(canon(t, m)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	good := canon(t, testList())
	raw := map[string][]byte{
		"empty":            nil,
		"not an object":    []byte(`[]`),
		"null":             []byte(strings.Replace(string(good), `"owner":"root:root"`, `"owner":null`, 1)),
		"noncanonical":     append(append([]byte(nil), good...), '\n'),
		"whitespace":       []byte(strings.Replace(string(good), `":`, `": `, 1)),
		"unsorted keys":    []byte(strings.Replace(string(good), `{"flavours":`, `{"zz":1,"flavours":`, 1)),
		"BOM":              append([]byte{0xEF, 0xBB, 0xBF}, good...),
		"invalid UTF-8":    []byte(strings.Replace(string(good), "nebula-executor", "nebula-\xffxecutor", 1)),
		"escaped path":     []byte(strings.Replace(string(good), `"/usr/bin/nebula"`, `"/usr/bin/nebul`+"\\"+`u0061"`, 1)),
		"duplicate key":    []byte(strings.Replace(string(good), `"format":`, `"flavours":{},"format":`, 1)),
		"too deep":         []byte(`{"a":{"b":{"c":{"d":{}}}}}`),
		"over 4 MiB":       append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"z":"`+strings.Repeat("a", MaxInstalledFilesDocument)+`"}`)...),
		"trailing garbage": append(append([]byte(nil), good...), []byte("{}")...),
	}
	for name, b := range raw {
		if _, err := ParseInstalledFiles(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestInstalledFilesMarshalRejectsInvalidList(t *testing.T) {
	l, err := ParseInstalledFiles(canon(t, testList()))
	if err != nil {
		t.Fatal(err)
	}
	l.Flavours[0].Files[0].Path = "/etc/nebula/server.json"
	if _, err := l.Marshal(); !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v", err)
	}
	l.Flavours[0].Files[0].Path = "/lib/systemd/system/nebula-executor.service"
	l.Flavours[0].Files[0].Type = "socket"
	if _, err := l.Marshal(); !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v", err)
	}
}

// signedRelease returns a manifest that lists list as installed-files.json,
// signed by k.
func signedRelease(t testing.TB, k *testSK, list []byte, edit func(man map[string]any)) (manifest, sig []byte) {
	t.Helper()
	man, _ := defaultRelease(t)
	arts := man["artifacts"].([]any)
	arts = append(arts, map[string]any{"name": InstalledFilesArtifact, "size": len(list), "sha256": hexSum(list)})
	// Keep artifacts sorted: builtins.tar < installed-files.json < nebula-server_...
	arts[1], arts[2] = arts[2], arts[1]
	man["artifacts"] = arts
	if edit != nil {
		edit(man)
	}
	manifest = canon(t, man)
	return manifest, k.sign(t, manifest)
}

func TestVerifyInstalledFilesAcceptsListCoveredBySignedManifest(t *testing.T) {
	k := newTestSK(t)
	state := testState(t, k)
	list := canon(t, testList())
	man, sig := signedRelease(t, k, list, nil)
	m, l, err := VerifyInstalledFiles(state, man, sig, list)
	if err != nil {
		t.Fatal(err)
	}
	if m.SignedBy.ID != "root-1" || m.Digest != hexSum(man) || l.Digest != hexSum(list) || l.ReleaseVersion != m.ReleaseVersion || len(l.Flavours) != 2 {
		t.Fatalf("manifest %+v list %+v", m, l)
	}
}

// testState returns a bootstrap root state trusting only k as root-1.
func testState(t testing.TB, k *testSK) RootState {
	t.Helper()
	s, err := Bootstrap([]Anchor{{ID: "root-1", Key: k.pub}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyInstalledFilesRejections(t *testing.T) {
	k := newTestSK(t)
	other := newTestSK(t)
	state := testState(t, k)
	list := canon(t, testList())
	man, sig := signedRelease(t, k, list, nil)

	otherList := mutate(func(m map[string]any, _ []any) map[string]any { m["release_version"] = "1.4.1"; return nil })
	wrongVersion := canon(t, otherList)
	wvMan, wvSig := signedRelease(t, k, wrongVersion, nil)

	badList := []byte(`{"format":"x"}`)
	badMan, badSig := signedRelease(t, k, badList, nil)

	noListMan, _ := defaultRelease(t)
	noList := canon(t, noListMan)

	tampered := bytes.Replace(list, []byte(`"0755"`), []byte(`"4755"`), 1)
	sizeMan, sizeSig := signedRelease(t, k, list, func(man map[string]any) {
		man["artifacts"].([]any)[1].(map[string]any)["size"] = len(list) + 1
	})

	_, plainPriv, err := genPlain(t)
	if err != nil {
		t.Fatal(err)
	}

	revoked := revokedState(t, k, other)

	cases := []struct {
		name           string
		state          RootState
		man, sig, list []byte
		want           error
	}{
		{"list digest differs", state, man, sig, tampered, ErrInstalledFiles},
		{"list size differs", state, sizeMan, sizeSig, list, ErrInstalledFiles},
		{"list missing from manifest", state, noList, k.sign(t, noList), list, ErrInstalledFiles},
		{"list of another manifest", state, wvMan, wvSig, list, ErrInstalledFiles},
		{"malformed list covered by manifest", state, badMan, badSig, badList, ErrFormat},
		{"empty list", state, man, sig, nil, ErrInstalledFiles},
		{"signature by unknown key", state, man, other.sign(t, man), list, ErrUntrusted},
		{"signature over other document", state, man, k.sign(t, noList), list, ErrSignature},
		{"signature without user presence", state, man, k.signNS(t, Namespace, 0, man), list, ErrSignature},
		{"wrong namespace", state, man, k.signNS(t, "file", 1, man), list, ErrSignature},
		{"plain ed25519 signature", state, man, plainSign(t, plainPriv, man), list, ErrUntrusted},
		{"no signature", state, man, nil, list, ErrFormat},
		{"garbage signature", state, man, []byte("not a signature"), list, ErrFormat},
		{"revoked root", revoked, man, sig, list, ErrUntrusted},
		{"invalid root state", RootState{}, man, sig, list, ErrFormat},
	}
	for _, tc := range cases {
		if _, _, err := VerifyInstalledFiles(tc.state, tc.man, tc.sig, tc.list); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// The list's digest matches the signed manifest, so only the
	// release_version comparison rejects it.
	if _, _, err := VerifyInstalledFiles(state, wvMan, wvSig, wrongVersion); !errors.Is(err, ErrInstalledFiles) || !strings.Contains(err.Error(), "release_version") {
		t.Fatalf("version mismatch: %v", err)
	}
}

// revokedState returns a state where k (root-1) was revoked by a rotation
// that enrolled other as root-2.
func revokedState(t *testing.T, k, other *testSK) RootState {
	t.Helper()
	s0 := testState(t, k)
	doc := canon(t, map[string]any{"format": RotationFormat, "sequence": 1, "previous_sha256": ZeroDigest,
		"add": []any{map[string]any{"id": "root-2", "public_key": FormatRootKey(other.pub)}}, "revoke": []any{"root-1"}})
	s1, _, err := s0.ApplyRotation(doc, k.sign(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return s1
}

func TestVerifyPublishedInstalledFilesTrustsOnlyCompiledAnchors(t *testing.T) {
	k := newTestSK(t)
	list := canon(t, testList())
	man, sig := signedRelease(t, k, list, nil)
	// A test key is not a compiled anchor, whatever the files claim.
	if _, _, err := VerifyPublishedInstalledFiles(nil, man, sig, list); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("test key against compiled anchors: %v", err)
	}
	// A rotation signed by a key that is not trusted cannot add one.
	doc := canon(t, map[string]any{"format": RotationFormat, "sequence": 1, "previous_sha256": ZeroDigest,
		"add": []any{map[string]any{"id": "root-2", "public_key": FormatRootKey(k.pub)}}, "revoke": []any{}})
	if _, _, err := VerifyPublishedInstalledFiles([]SignedRotation{{Document: doc, Signature: k.sign(t, doc)}}, man, sig, list); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("self-signed rotation: %v", err)
	}
}

func TestVerifyPublishedFollowsSignedRotations(t *testing.T) {
	r1, r2 := newTestSK(t), newTestSK(t)
	anchors := []Anchor{{ID: "root-1", Key: r1.pub}, {ID: "root-2"}}
	list := canon(t, testList())
	man1, sig1 := signedRelease(t, r1, list, nil)
	if _, l, err := verifyPublished(anchors, nil, man1, sig1, list); err != nil || l.Digest != hexSum(list) {
		t.Fatalf("anchor root: %v", err)
	}
	man2, sig2 := signedRelease(t, r2, list, nil)
	if _, _, err := verifyPublished(anchors, nil, man2, sig2, list); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("root-2 before rotation: %v", err)
	}
	doc := canon(t, map[string]any{"format": RotationFormat, "sequence": 1, "previous_sha256": ZeroDigest,
		"add": []any{map[string]any{"id": "root-3", "public_key": FormatRootKey(r2.pub)}}, "revoke": []any{"root-1"}})
	rots := []SignedRotation{{Document: doc, Signature: r1.sign(t, doc)}}
	m, _, err := verifyPublished(anchors, rots, man2, sig2, list)
	if err != nil || m.SignedBy.ID != "root-3" {
		t.Fatalf("rotated root: %v", err)
	}
	// root-1 is revoked by the rotation.
	if _, _, err := verifyPublished(anchors, rots, man1, sig1, list); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("revoked root: %v", err)
	}
	// A rotation signed by the key it adds is rejected.
	self := []SignedRotation{{Document: doc, Signature: r2.sign(t, doc)}}
	if _, _, err := verifyPublished(anchors, self, man2, sig2, list); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("self-enrolled rotation: %v", err)
	}
	// Replayed rotations are rejected, even by a root that stays trusted.
	keep := canon(t, map[string]any{"format": RotationFormat, "sequence": 1, "previous_sha256": ZeroDigest,
		"add": []any{map[string]any{"id": "root-3", "public_key": FormatRootKey(r2.pub)}}, "revoke": []any{}})
	once := SignedRotation{Document: keep, Signature: r1.sign(t, keep)}
	if _, _, err := verifyPublished(anchors, []SignedRotation{once}, man2, sig2, list); err != nil {
		t.Fatalf("rotation without revocation: %v", err)
	}
	if _, _, err := verifyPublished(anchors, []SignedRotation{once, once}, man2, sig2, list); !errors.Is(err, ErrRotation) {
		t.Fatalf("replayed rotation: %v", err)
	}
	if _, _, err := verifyPublished(anchors, make([]SignedRotation, MaxRotations+1), man2, sig2, list); !errors.Is(err, ErrRotation) {
		t.Fatalf("too many rotations: %v", err)
	}
}

// writeFile creates a file in a build tree.
func writeFile(t *testing.T, root, rel string, data []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func testBuildDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	deb := filepath.Join(dir, "deb:amd64")
	writeFile(t, deb, "usr/bin/nebula", []byte("nebula-binary"), 0o755)
	writeFile(t, deb, "usr/bin/nebula-executor", []byte("executor-binary"), 0o755)
	writeFile(t, deb, "lib/systemd/system/nebula-server.service", []byte("[Unit]\n"), 0o644)
	writeFile(t, deb, "lib/systemd/system/nebula-server.service.d/50-pkg.conf", []byte("[Service]\n"), 0o644)
	writeFile(t, deb, "usr/share/nebula/web/empty.css", nil, 0o644)
	if err := os.Symlink("../../nebula/web/empty.css", filepath.Join(deb, "usr/share/nebula/web/link.css")); err != nil {
		t.Fatal(err)
	}
	tb := filepath.Join(dir, "tarball:arm64")
	writeFile(t, tb, "usr/bin/nebula", []byte("arm"), 0o750)
	writeFile(t, tb, "etc/systemd/system/nebula-server.service", []byte("[Unit]\n"), 0o644)
	return dir
}

func TestGenerateInstalledFilesFromBuildDirectory(t *testing.T) {
	dir := testBuildDir(t)
	raw, err := GenerateInstalledFiles("1.4.0", dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseInstalledFiles(raw)
	if err != nil {
		t.Fatalf("generated list does not parse: %v\n%s", err, raw)
	}
	if l.ReleaseVersion != "1.4.0" || len(l.Flavours) != 2 {
		t.Fatalf("list %+v", l)
	}
	deb, _ := l.Flavour("deb:amd64")
	want := []InstalledFile{
		{Path: "/lib/systemd/system/nebula-server.service", Type: FileRegular, Size: 7, SHA256: hexSum([]byte("[Unit]\n")), Mode: 0o644, Owner: "root:root"},
		{Path: "/lib/systemd/system/nebula-server.service.d/50-pkg.conf", Type: FileRegular, Size: 10, SHA256: hexSum([]byte("[Service]\n")), Mode: 0o644, Owner: "root:root"},
		{Path: "/usr/bin/nebula", Type: FileRegular, Size: 13, SHA256: hexSum([]byte("nebula-binary")), Mode: 0o755, Owner: "root:root"},
		{Path: "/usr/bin/nebula-executor", Type: FileRegular, Size: 15, SHA256: hexSum([]byte("executor-binary")), Mode: 0o755, Owner: "root:root"},
		{Path: "/usr/share/nebula/web/empty.css", Type: FileRegular, Size: 0, SHA256: hexSum(nil), Mode: 0o644, Owner: "root:root"},
		{Path: "/usr/share/nebula/web/link.css", Type: FileSymlink, Target: "../../nebula/web/empty.css", Owner: "root:root"},
	}
	if fmt.Sprint(deb.Files) != fmt.Sprint(want) {
		t.Fatalf("deb files\n got %+v\nwant %+v", deb.Files, want)
	}
	tb, _ := l.Flavour("tarball:arm64")
	if len(tb.Files) != 2 || tb.Files[0].Path != "/etc/systemd/system/nebula-server.service" ||
		tb.Files[1].Mode != 0o750 || tb.Files[1].SHA256 != hexSum([]byte("arm")) {
		t.Fatalf("tarball files %+v", tb.Files)
	}
	// Deterministic output.
	again, err := GenerateInstalledFiles("1.4.0", dir)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("second run differs: %v", err)
	}
}

func TestGenerateInstalledFilesRejectsBadBuildDirectories(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"configuration staged": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "etc/nebula/server.json", []byte("{}"), 0o640)
		},
		"iconfetch nftables staged": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "etc/nebula/nebula-iconfetch.nft", []byte("table inet x {}\n"), 0o644)
		},
		"tarball local drop-in staged": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "tarball:arm64"), "etc/systemd/system/nebula-executor.service.d/10-local.conf", []byte("[Service]\n"), 0o644)
		},
		"deb local drop-in staged": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "etc/systemd/system/nebula-server.service.d/20-discovery.conf", []byte("[Service]\n"), 0o644)
		},
		"deb unit in tarball dir": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "etc/systemd/system/nebula-server.service", []byte("[Unit]\n"), 0o644)
		},
		"tarball unit in deb dir": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "tarball:arm64"), "lib/systemd/system/nebula-server.service", []byte("[Unit]\n"), 0o644)
		},
		"container unit": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "container:amd64"), "usr/lib/systemd/system/nebula-server.service", []byte("[Unit]\n"), 0o644)
		},
		"data staged": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "var/lib/nebula/server/db.sqlite", []byte("x"), 0o600)
		},
		"bad path character": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb:amd64"), "usr/share/nebula/a b", []byte("x"), 0o644)
		},
		"fifo": func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "deb:amd64", "usr/share/nebula/web/fifo"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"bad flavour directory": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "deb-amd64"), "usr/bin/nebula", []byte("x"), 0o755)
		},
		"file at top level": func(t *testing.T, dir string) {
			writeFile(t, dir, "README", []byte("x"), 0o644)
		},
		"symlinked flavour": func(t *testing.T, dir string) {
			if err := os.Symlink("deb:amd64", filepath.Join(dir, "container:amd64")); err != nil {
				t.Fatal(err)
			}
		},
		"empty flavour": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "container:amd64", "usr/bin"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink target bad character": func(t *testing.T, dir string) {
			if err := os.Symlink("a b", filepath.Join(dir, "deb:amd64", "usr/bin/nebula-x")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := testBuildDir(t)
			setup(t, dir)
			if _, err := GenerateInstalledFiles("1.4.0", dir); !errors.Is(err, ErrFormat) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if _, err := GenerateInstalledFiles("1.4.0", t.TempDir()); !errors.Is(err, ErrFormat) {
		t.Fatalf("empty build directory: %v", err)
	}
	if _, err := GenerateInstalledFiles("v1", testBuildDir(t)); !errors.Is(err, ErrFormat) {
		t.Fatalf("bad version: %v", err)
	}
	if _, err := GenerateInstalledFiles("1.4.0", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing build directory accepted")
	}
}

// Exactly MaxInstalledPath and one byte more ("/usr/share/nebula/" is 18
// bytes).
var (
	pathAtLimit   = "/usr/share/nebula/" + strings.Repeat("a", MaxInstalledPath-18)
	pathOverLimit = pathAtLimit + "a"
)

func TestValidInstalledPathAcceptsCoveredPathsPerFlavour(t *testing.T) {
	everywhere := []string{
		"/usr/bin/nebula", "/usr/bin/nebula-server", "/usr/share/nebula/release/builtins.tar",
		"/usr/share/nebula/modules/docker/1.2.0/actions/restart.sh", "/usr/lib/nebula/web/static/app.js",
		"/usr/share/doc/nebula-operation-station/guide.md", pathAtLimit,
	}
	cases := map[string][]string{
		"deb:amd64": append([]string{
			"/lib/systemd/system/nebula-executor.service", "/usr/lib/systemd/system/nebula-server.service",
			// A drop-in the package ships in the vendor unit directory.
			"/lib/systemd/system/nebula-server.service.d/20-discovery.conf",
			"/usr/lib/systemd/system/nebula-executor.service.d/50-hardening.conf",
		}, everywhere...),
		"tarball:arm64":   append([]string{"/etc/systemd/system/nebula-server.service", "/etc/systemd/system/nebula-discovery.timer"}, everywhere...),
		"container:amd64": everywhere,
	}
	if len(pathAtLimit) != MaxInstalledPath {
		t.Fatalf("pathAtLimit has %d bytes", len(pathAtLimit))
	}
	for flavour, paths := range cases {
		for _, p := range paths {
			if !ValidInstalledPath(flavour, p) {
				t.Errorf("%s: %s rejected", flavour, p)
			}
		}
	}
}

func TestValidInstalledPathRejectsConfigurationDataAndForeignUnitDirs(t *testing.T) {
	everywhere := []string{
		"", "/", "/usr/bin/", "/usr/bin/sshd", "/usr/sbin/nebula", "/etc/nebula/server.json",
		// The iconfetch nftables file is configuration (ADR 0015 D3).
		"/etc/nebula/nebula-iconfetch.nft",
		"/var/lib/nebula/executor/keys/nebula-default.key", "/run/nebula/x", "/usr/share/nebula", "/usr/share/nebula/",
		"/usr/share/nebula/../../../etc/shadow", "/usr/share/nebula/a/./b", "/usr/share/nebula/a//b", "/usr/bin/nebula.d/x",
		pathOverLimit, "/usr/share/nebula/a\x00",
		// Local drop-ins generated by deploy/install.sh and the deb
		// postinst, and any other drop-in under /etc/systemd/system.
		"/etc/systemd/system/nebula-executor.service.d/10-local.conf",
		"/etc/systemd/system/nebula-executor.service.d/20-local.conf",
		"/etc/systemd/system/nebula-server.service.d/20-discovery.conf",
		"/etc/systemd/system/ssh.service", "/etc/systemd/system/nebula-x.service.d",
		"/lib/systemd/system/ssh.service", "/lib/systemd/system/nebula-x.service.d", "/lib/systemd/system/nebula-x.service.d/",
		"/lib/systemd/system/nebula-x.service.d/a/b.conf",
		// systemd reads only *.conf drop-ins.
		"/lib/systemd/system/nebula-x.service.d/README", "/lib/systemd/system/nebula-x.service.d/.conf",
		"/lib/systemd/system/nebula-.d/x.conf", "/lib/systemd/system/nebula-x.service/x.conf",
	}
	cases := map[string][]string{
		"deb:amd64": append([]string{
			// The tarball's unit directory is not the package's.
			"/etc/systemd/system/nebula-server.service",
		}, everywhere...),
		"tarball:arm64": append([]string{
			// The package's unit directories are not the tarball's.
			"/lib/systemd/system/nebula-server.service", "/usr/lib/systemd/system/nebula-server.service",
			"/lib/systemd/system/nebula-server.service.d/20-discovery.conf",
		}, everywhere...),
		"container:amd64": append([]string{
			"/lib/systemd/system/nebula-server.service", "/usr/lib/systemd/system/nebula-server.service",
			"/etc/systemd/system/nebula-server.service",
		}, everywhere...),
		// An invalid flavour name admits nothing.
		"rpm:amd64": {"/usr/bin/nebula", "/lib/systemd/system/nebula-server.service"},
		"deb":       {"/usr/bin/nebula"},
		"":          {"/usr/bin/nebula"},
	}
	for flavour, paths := range cases {
		for _, p := range paths {
			if ValidInstalledPath(flavour, p) {
				t.Errorf("%s: %q accepted", flavour, p)
			}
		}
	}
}

func FuzzParseInstalledFiles(f *testing.F) {
	good := canon(f, testList())
	f.Add(good)
	f.Add([]byte(`{"flavours":{"deb:amd64":[{"mode":"0755","owner":"root:root","path":"/usr/bin/nebula","sha256":"` + hexSum(nil) + `","size":0,"type":"file"}]},"format":"nebula-installed-files-v1","release_version":"1.0.0"}`))
	f.Add([]byte(`{"flavours":{"deb:amd64":[{"owner":"root:root","path":"/usr/bin/nebula","target":"x","type":"symlink"}]},"format":"nebula-installed-files-v1","release_version":"1.0.0"}`))
	f.Add([]byte(`{"a":{"b":{"c":{"d":{}}}}}`))
	f.Add([]byte(`{"flavours":null}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		l, err := ParseInstalledFiles(raw)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("error not ErrFormat: %v", err)
			}
			return
		}
		// Every accepted document is canonical: marshalling the parsed
		// list reproduces the exact bytes.
		out, err := l.Marshal()
		if err != nil || !bytes.Equal(out, raw) {
			t.Fatalf("accepted document does not round-trip: %v", err)
		}
		if len(raw) > MaxInstalledFilesDocument || len(l.Flavours) == 0 || len(l.Flavours) > MaxFlavours {
			t.Fatalf("limits not enforced")
		}
		for _, fl := range l.Flavours {
			if len(fl.Files) == 0 || len(fl.Files) > MaxInstalledEntries {
				t.Fatalf("entry limit not enforced")
			}
			for i, e := range fl.Files {
				if !ValidInstalledPath(fl.Name, e.Path) || (i > 0 && fl.Files[i-1].Path >= e.Path) {
					t.Fatalf("invalid or unsorted path %q", e.Path)
				}
			}
		}
	})
}

// checkAdmitted asserts what an admitted list guarantees, independently of
// the code under test: the manifest covers its exact bytes and version,
// and no listed path is configuration or data (ADR 0015 D3).
func checkAdmitted(t *testing.T, m Manifest, l InstalledFiles, list []byte) {
	t.Helper()
	covered := false
	for _, a := range m.Artifacts {
		if a.Name == InstalledFilesArtifact && a.Size == int64(len(list)) && a.SHA256 == hexSum(list) {
			covered = true
		}
	}
	if !covered || l.Digest != hexSum(list) || l.ReleaseVersion != m.ReleaseVersion {
		t.Fatalf("admitted list not covered by the manifest: %+v", m)
	}
	for _, fl := range l.Flavours {
		for _, e := range fl.Files {
			if !ValidInstalledPath(fl.Name, e.Path) || strings.HasPrefix(e.Path, "/etc/nebula/") || strings.HasPrefix(e.Path, "/var/") ||
				strings.HasPrefix(e.Path, "/run/") || (strings.HasPrefix(e.Path, "/etc/systemd/system/") && strings.Count(e.Path, "/") > 4) {
				t.Fatalf("admitted configuration or data path %q in %s", e.Path, fl.Name)
			}
		}
	}
}

func FuzzVerifyInstalledFiles(f *testing.F) {
	k := newTestSK(f)
	state := testState(f, k)
	list := canon(f, testList())
	man, sig := signedRelease(f, k, list, nil)
	f.Add(man, sig, list)
	f.Add(man, sig, bytes.Replace(list, []byte(`"0755"`), []byte(`"4755"`), 1))
	f.Add(man, []byte{}, list)
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(man, sig, []byte(`{"format":"x"}`))
	// Validly signed and covered, but listing a local drop-in: only the
	// list parser can reject it.
	dropIn := canon(f, mutate(func(m map[string]any, _ []any) map[string]any {
		m["flavours"].(map[string]any)["tarball:arm64"] = []any{
			regEntry("/etc/systemd/system/nebula-executor.service.d/10-local.conf", []byte("[Service]\n"), "0644"),
		}
		return nil
	}))
	dMan, dSig := signedRelease(f, k, dropIn, nil)
	f.Add(dMan, dSig, dropIn)
	f.Fuzz(func(t *testing.T, manifest, sig, list []byte) {
		known := func(err error, sentinels ...error) {
			t.Helper()
			for _, s := range sentinels {
				if errors.Is(err, s) {
					return
				}
			}
			t.Fatalf("unexpected error: %v", err)
		}
		if m, l, err := VerifyInstalledFiles(state, manifest, sig, list); err != nil {
			known(err, ErrFormat, ErrSignature, ErrUntrusted, ErrInstalledFiles)
		} else {
			checkAdmitted(t, m, l, list)
		}
		// Any well-formed manifest, signed or not, against the list.
		if pm, err := ParseManifest(manifest); err == nil {
			if l, err := matchInstalledFiles(pm, list); err != nil {
				known(err, ErrFormat, ErrInstalledFiles)
			} else {
				checkAdmitted(t, pm, l, list)
			}
		}
		// A manifest that covers the list exactly: only the list parser
		// and the version comparison decide.
		cover := Manifest{ReleaseVersion: "1.4.0", Artifacts: []Artifact{{Name: InstalledFilesArtifact, Size: int64(len(list)), SHA256: hexSum(list)}}}
		if l, err := matchInstalledFiles(cover, list); err != nil {
			known(err, ErrFormat, ErrInstalledFiles)
		} else {
			checkAdmitted(t, cover, l, list)
		}
	})
}

func TestParseInstalledFilesAcceptsValuesAtLimits(t *testing.T) {
	// MaxInstalledEntries entries, one of them a MaxInstalledPath-byte
	// path, and a symlink target of MaxInstalledPath bytes.
	// Sorted: pathAtLimit (/usr/share/nebula/aaa...) < f00000 < link.
	entries := []any{regEntry(pathAtLimit, nil, "0644")}
	for i := 0; i < MaxInstalledEntries-2; i++ {
		entries = append(entries, regEntry(fmt.Sprintf("/usr/share/nebula/f%05d", i), nil, "0644"))
	}
	entries = append(entries, linkEntry("/usr/share/nebula/link", strings.Repeat("b", MaxInstalledPath)))
	// MaxFlavours flavours.
	flavours := map[string]any{"deb:amd64": entries}
	for i := 1; i < MaxFlavours; i++ {
		flavours[fmt.Sprintf("deb:a%d", i)] = []any{regEntry("/usr/bin/nebula", nil, "0755")}
	}
	m := testList()
	m["flavours"] = flavours
	// A regular file of exactly MaxInstalledFileSize bytes.
	flavours["deb:a1"].([]any)[0].(map[string]any)["size"] = int64(MaxInstalledFileSize)
	l, err := ParseInstalledFiles(canon(t, m))
	if err != nil {
		t.Fatalf("list at the limits rejected: %v", err)
	}
	deb, _ := l.Flavour("deb:amd64")
	a1, _ := l.Flavour("deb:a1")
	if len(l.Flavours) != MaxFlavours || len(deb.Files) != MaxInstalledEntries || a1.Files[0].Size != MaxInstalledFileSize ||
		deb.Files[len(deb.Files)-1].Target != strings.Repeat("b", MaxInstalledPath) || deb.Files[0].Path != pathAtLimit {
		t.Fatalf("limits not kept: %d flavours, %d entries", len(l.Flavours), len(deb.Files))
	}
	// One byte more in the symlink target is rejected (the other
	// over-limit cases are in TestParseInstalledFilesRejectsMalformedLists).
	entries[len(entries)-1] = linkEntry("/usr/share/nebula/link", strings.Repeat("b", MaxInstalledPath+1))
	if _, err := ParseInstalledFiles(canon(t, m)); !errors.Is(err, ErrFormat) {
		t.Fatalf("symlink target over the limit: %v", err)
	}
}

func TestParseInstalledFilesDocumentSizeLimit(t *testing.T) {
	// Entries with paths of a fixed prefix, padded with x up to
	// MaxInstalledPath bytes; shortening a path by n bytes shortens the
	// document by n bytes.
	const prefix = "/usr/share/nebula/f%05d-"
	var flavours []string
	var paths [][]string
	for fi := 0; fi < 3; fi++ {
		flavours = append(flavours, fmt.Sprintf("deb:a%d", fi))
		ps := make([]string, MaxInstalledEntries)
		for i := range ps {
			p := fmt.Sprintf(prefix, i)
			ps[i] = p + strings.Repeat("x", MaxInstalledPath-len(p))
		}
		paths = append(paths, ps)
	}
	build := func() []byte {
		fl := map[string]any{}
		for fi, name := range flavours {
			es := make([]any, len(paths[fi]))
			for i, p := range paths[fi] {
				es[i] = regEntry(p, nil, "0644")
			}
			fl[name] = es
		}
		return canon(t, map[string]any{"format": InstalledFilesFormat, "release_version": "1.4.0", "flavours": fl})
	}
	excess := len(build()) - MaxInstalledFilesDocument
	if excess <= 0 {
		t.Fatalf("test document too small by %d bytes", -excess)
	}
	var last *string
	for fi := len(paths) - 1; fi >= 0 && excess > 0; fi-- {
		for i := len(paths[fi]) - 1; i >= 0 && excess > 0; i-- {
			p := &paths[fi][i]
			cut := min(excess, len(*p)-len(fmt.Sprintf(prefix, i)))
			*p = (*p)[:len(*p)-cut]
			excess -= cut
			last = p
		}
	}
	exact := build()
	if len(exact) != MaxInstalledFilesDocument {
		t.Fatalf("document has %d bytes", len(exact))
	}
	if _, err := ParseInstalledFiles(exact); err != nil {
		t.Fatalf("document of exactly %d bytes rejected: %v", MaxInstalledFilesDocument, err)
	}
	*last += "x"
	over := build()
	_, err := ParseInstalledFiles(over)
	if len(over) != MaxInstalledFilesDocument+1 || !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), fmt.Sprintf("1 to %d bytes", MaxInstalledFilesDocument)) {
		t.Fatalf("document of %d bytes: %v", len(over), err)
	}
}

func TestGenerateInstalledFilesLimits(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		dir := t.TempDir()
		deb := filepath.Join(dir, "deb:amd64")
		for i := 0; i < MaxInstalledEntries; i++ {
			writeFile(t, deb, fmt.Sprintf("usr/share/nebula/f%05d", i), nil, 0o644)
		}
		raw, err := GenerateInstalledFiles("1.4.0", dir)
		if err != nil {
			t.Fatalf("%d files rejected: %v", MaxInstalledEntries, err)
		}
		if l, err := ParseInstalledFiles(raw); err != nil || len(l.Flavours[0].Files) != MaxInstalledEntries {
			t.Fatalf("generated list: %v", err)
		}
		writeFile(t, deb, "usr/share/nebula/g", nil, 0o644)
		if _, err := GenerateInstalledFiles("1.4.0", dir); !errors.Is(err, ErrFormat) {
			t.Fatalf("%d files: %v", MaxInstalledEntries+1, err)
		}
	})
	t.Run("flavours", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < MaxFlavours; i++ {
			writeFile(t, filepath.Join(dir, fmt.Sprintf("deb:a%d", i)), "usr/bin/nebula", nil, 0o755)
		}
		if _, err := GenerateInstalledFiles("1.4.0", dir); err != nil {
			t.Fatalf("%d flavours rejected: %v", MaxFlavours, err)
		}
		writeFile(t, filepath.Join(dir, "deb:z"), "usr/bin/nebula", nil, 0o755)
		if _, err := GenerateInstalledFiles("1.4.0", dir); !errors.Is(err, ErrFormat) {
			t.Fatalf("%d flavours: %v", MaxFlavours+1, err)
		}
	})
	t.Run("path", func(t *testing.T) {
		dir := t.TempDir()
		deb := filepath.Join(dir, "deb:amd64")
		writeFile(t, deb, pathAtLimit[1:], nil, 0o644)
		if _, err := GenerateInstalledFiles("1.4.0", dir); err != nil {
			t.Fatalf("%d-byte path rejected: %v", MaxInstalledPath, err)
		}
		writeFile(t, deb, pathOverLimit[1:], nil, 0o644)
		if _, err := GenerateInstalledFiles("1.4.0", dir); !errors.Is(err, ErrFormat) {
			t.Fatalf("%d-byte path: %v", MaxInstalledPath+1, err)
		}
	})
	t.Run("file size", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "deb:amd64", "usr/bin/nebula")
		writeFile(t, filepath.Join(dir, "deb:amd64"), "usr/bin/nebula", nil, 0o755)
		// Sparse: no disk space is used.
		if err := os.Truncate(p, MaxInstalledFileSize); err != nil {
			t.Fatal(err)
		}
		raw, err := GenerateInstalledFiles("1.4.0", dir)
		if err != nil {
			t.Fatalf("file of %d bytes rejected: %v", MaxInstalledFileSize, err)
		}
		if l, err := ParseInstalledFiles(raw); err != nil || l.Flavours[0].Files[0].Size != MaxInstalledFileSize {
			t.Fatalf("generated list: %v", err)
		}
		if err := os.Truncate(p, MaxInstalledFileSize+1); err != nil {
			t.Fatal(err)
		}
		if _, err := GenerateInstalledFiles("1.4.0", dir); !errors.Is(err, ErrFormat) {
			t.Fatalf("file of %d bytes: %v", MaxInstalledFileSize+1, err)
		}
	})
}
