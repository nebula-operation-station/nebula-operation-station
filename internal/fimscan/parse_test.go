// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func testOpts() Options {
	return Options{
		Profile: Profile{ID: "fim-test-v1", Roots: []Root{
			{Pattern: "/etc"},
			{Pattern: "/usr/bin"},
			{Pattern: "/boot"},
			{Pattern: "/boot/efi", Optional: true},
			{Pattern: "/home/*/.ssh/authorized_keys*", Optional: true},
			{Pattern: "/opt", Optional: true},
		}},
		Mode:    ModeFull,
		HostKey: bytes.Repeat([]byte{0x5a}, HostKeySize),
	}
}

func validDoc(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return string(b)
}

// mutate replaces the single occurrence of old in doc.
func mutate(t testing.TB, doc, old, repl string) string {
	t.Helper()
	if strings.Count(doc, old) != 1 {
		t.Fatalf("mutation anchor %q occurs %d times", old, strings.Count(doc, old))
	}
	return strings.Replace(doc, old, repl, 1)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// jsonU returns the JSON escape for code point hex, built so the source
// file stays ASCII-only.
func jsonU(hex string) string { return `\` + "u" + hex }

func parseString(t testing.TB, doc string) (*Result, error) {
	t.Helper()
	return Parse(context.Background(), strings.NewReader(doc), testOpts())
}

func parseLim(t testing.TB, doc string, lim limits) (*Result, error) {
	t.Helper()
	return parse(context.Background(), strings.NewReader(doc), testOpts(), lim)
}

func findRecord(t testing.TB, res *Result, p string) Record {
	t.Helper()
	for _, r := range res.Records {
		if string(r.Path) == p {
			return r
		}
	}
	t.Fatalf("record %s missing", p)
	return Record{}
}

func mustHex(t testing.TB, s string) [32]byte {
	t.Helper()
	var out [32]byte
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		t.Fatal(err)
	}
	return out
}

func keyed(plain [32]byte) [32]byte {
	m := hmac.New(sha256.New, testOpts().HostKey)
	m.Write(plain[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func TestValidDocumentIsComplete(t *testing.T) {
	res, err := parseString(t, validDoc(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !res.Complete() {
		t.Fatalf("partial: %v dropped: %v", res.Partial, res.Dropped)
	}
	if len(res.Records) != 11 || len(res.Mounts) != 1 || len(res.SSHConfig) != 1 {
		t.Fatalf("got %d records, %d mounts, %d ssh files", len(res.Records), len(res.Mounts), len(res.SSHConfig))
	}
	if res.ProfileID != "fim-test-v1" || res.Mode != ModeFull || res.Started != 1762934400 || res.Ended != 1762934460 {
		t.Fatalf("header: %+v", res)
	}
	if res.SSHConfigState != SSHConfigValid || string(res.SSHConfig[0].Content) != "Port 22\n" {
		t.Fatalf("ssh config state %v", res.SSHConfigState)
	}
	wantRoots := []RootState{RootScanned, RootScanned, RootScanned, RootAbsent, RootScanned, RootAbsent}
	for i, r := range res.Roots {
		if r.State != wantRoots[i] {
			t.Errorf("root %s state %v, want %v", r.Pattern, r.State, wantRoots[i])
		}
	}
	if m := res.Mounts[0]; string(m.Path) != "/etc/pve" || m.FSType != "fuse" {
		t.Errorf("mount %+v", m)
	}
	sh := findRecord(t, res, "/usr/bin/sh")
	if sh.Type != TypeSymlink || string(sh.Link) != "dash" || sh.Hash.Kind != HashNone {
		t.Errorf("symlink record %+v", sh)
	}
	ls := findRecord(t, res, "/usr/bin/ls")
	if ls.Type != TypeFile || ls.Size != 151344 || ls.Mode != 0o755 || ls.Inode != 7 {
		t.Errorf("ls record %+v", ls)
	}
}

func TestContentHashesFollowD6(t *testing.T) {
	res, err := parseString(t, validDoc(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path   string
		plain  string
		kind   HashKind
		secret bool
	}{
		{"/usr/bin/ls", strings.Repeat("2", 64), HashPlain, false},
		{"/boot/vmlinuz-6.1.0-18-amd64", strings.Repeat("3", 64), HashPlain, false},
		{"/boot/grub/grub.cfg", strings.Repeat("4", 64), HashKeyed, false},
		{"/etc/shadow", strings.Repeat("1", 64), HashKeyed, true},
		{"/home/alice/.ssh/authorized_keys", strings.Repeat("5", 64), HashKeyed, false},
		{"/etc/ssh/sshd_config", "e807422bad84e7926a98fb262153b3d9c84244080e69b0e5d20446c183ffafc4", HashKeyed, false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := findRecord(t, res, tt.path)
			plain := mustHex(t, tt.plain)
			if r.Hash.Kind != tt.kind || r.Hash.Secret != tt.secret {
				t.Fatalf("hash kind %v secret %v, want %v %v", r.Hash.Kind, r.Hash.Secret, tt.kind, tt.secret)
			}
			want := plain
			if tt.kind == HashKeyed {
				want = keyed(plain)
				if r.Hash.Sum == plain {
					t.Fatal("keyed path carries its plain hash")
				}
			}
			if r.Hash.Sum != want {
				t.Fatalf("sum %x, want %x", r.Hash.Sum, want)
			}
		})
	}
}

func TestKeyedHashDiffersPerHostKey(t *testing.T) {
	opts := testOpts()
	a, err := Parse(context.Background(), strings.NewReader(validDoc(t)), opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.HostKey = bytes.Repeat([]byte{0xa5}, HostKeySize)
	b, err := Parse(context.Background(), strings.NewReader(validDoc(t)), opts)
	if err != nil {
		t.Fatal(err)
	}
	if findRecord(t, a, "/etc/shadow").Hash.Sum == findRecord(t, b, "/etc/shadow").Hash.Sum {
		t.Fatal("keyed hash equal under two host keys")
	}
	if findRecord(t, a, "/usr/bin/ls").Hash.Sum != findRecord(t, b, "/usr/bin/ls").Hash.Sum {
		t.Fatal("plain hash differs under two host keys")
	}
}

func TestInvalidDocumentRejectedAsWhole(t *testing.T) {
	doc := validDoc(t)
	tests := []struct {
		name string
		doc  string
	}{
		{"empty", ""},
		{"not an object", `[]`},
		{"syntax error", mutate(t, doc, `"mode": "full",`, `"mode": "full",,`)},
		{"truncated JSON", doc[:len(doc)/2]},
		{"data after document", doc + "x"},
		{"second document", doc + "{}"},
		{"unknown top-level member", mutate(t, doc, `"mode": "full",`, `"mode": "full", "extra": 1,`)},
		{"duplicate member", mutate(t, doc, `"mode": "full",`, `"mode": "full", "mode": "full",`)},
		{"case variant member", mutate(t, doc, `"mode": "full",`, `"mode": "full", "MODE": "full",`)},
		{"case variant instead of name", mutate(t, doc, `"format":`, `"Format":`)},
		{"kelvin sign member", mutate(t, doc, `"truncated": false,`, `"truncated": false, "`+jsonU("212a")+`": 1,`)},
		{"raw kelvin sign member", mutate(t, doc, `"truncated": false,`, "\"truncated\": false, \"\xe2\x84\xaa\": 1,")},
		{"long s in schema name", mutate(t, doc, `"truncated": false,`, `"truncated": false, "record`+jsonU("017f")+`": 1,`)},
		{"raw non-ASCII member", mutate(t, doc, `"truncated": false,`, "\"truncated\": false, \"\xff\": 1,")},
		{"wrong format", mutate(t, doc, `"fim-scan-v1"`, `"fim-scan-v2"`)},
		{"wrong profile", mutate(t, doc, `"fim-test-v1"`, `"fim-default-v1"`)},
		{"wrong mode", mutate(t, doc, `"mode": "full"`, `"mode": "incremental"`)},
		{"missing member", mutate(t, doc, `"truncated": false,`, ``)},
		{"missing records", mutate(t, doc, `"mode": "full",`, `"mode": "full", "x": [`)},
		{"started float", mutate(t, doc, `"started": 1762934400`, `"started": 1762934400.0`)},
		{"started exponent", mutate(t, doc, `"started": 1762934400`, `"started": 1e9`)},
		{"started out of range", mutate(t, doc, `"started": 1762934400`, `"started": 253402300800`)},
		{"started string", mutate(t, doc, `"started": 1762934400`, `"started": "1762934400"`)},
		{"truncated not bool", mutate(t, doc, `"truncated": false`, `"truncated": 0`)},
		{"records not array", mutate(t, doc, `"mounts": [`, `"mounts": {"a": [`)},
		{"counters unknown member", mutate(t, doc, `"unreadable": 0}`, `"unreadable": 0, "x": 0}`)},
		{"counters missing member", mutate(t, doc, `, "unreadable": 0}`, `}`)},
		{"counters negative", mutate(t, doc, `"unreadable": 0}`, `"unreadable": -1}`)},
		{"counters not object", mutate(t, doc, `"counters": {"records": 11, "mounts": 1, "ssh_config": 1, "unreadable": 0}`, `"counters": 11`)},
		{"deep nesting in record", mutate(t, doc, `"inode": 2,`, `"inode": 2, "x": `+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`,`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseString(t, tt.doc)
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v, res = %+v; want ErrInvalidResult", err, res)
			}
			if res != nil {
				t.Fatal("result returned with error")
			}
		})
	}
}

func TestRejectionErrorsQuoteNoHostBytes(t *testing.T) {
	marker := "HOSTMARKER"
	doc := validDoc(t)
	docs := []string{
		mutate(t, doc, `"fim-scan-v1"`, `"`+marker+`"`),
		mutate(t, doc, `"mode": "full",`, `"mode": "full", "`+marker+`": 1,`),
		mutate(t, doc, `"mode": "full",`, `"mode": "full", `+marker),
		doc + marker,
	}
	for i, d := range docs {
		_, err := parseString(t, d)
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

const firstRecord = `{"path": "L2V0Yw==", "type": "dir", "size": 4096, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1762934000, "ctime": 1762934000}`

func TestInvalidRecordDroppedAndCounted(t *testing.T) {
	rec := func(kv string) string {
		return `{"path": "L2V0Yw==", "type": "dir", "size": 4096, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1762934000, "ctime": 1762934000` + kv + `}`
	}
	withPath := func(path string) string {
		return `{"path": "` + path + `", "type": "dir", "size": 1, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1, "ctime": 1}`
	}
	tests := []struct {
		name string
		rec  string
		want DropReason
	}{
		{"not an object", `42`, DropNotObject},
		{"array", `[1, {"a": 2}]`, DropNotObject},
		{"null", `null`, DropNotObject},
		{"unknown member", rec(`, "owner": "root"`), DropBadMember},
		{"case variant member", rec(`, "PATH": "L2V0Yw=="`), DropBadMember},
		{"duplicate member", rec(`, "size": 4096`), DropBadMember},
		{"escaped long s member", rec(`, "` + jsonU("017f") + `ize": 1`), DropBadMember},
		{"raw long s member", rec(", \"\xc5\xbfize\": 1"), DropBadMember},
		{"escaped kelvin link member", rec(`, "lin` + jsonU("212a") + `": "ZGFzaA=="`), DropBadMember},
		{"missing ctime", `{"path": "L2V0Yw==", "type": "dir", "size": 1, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1}`, DropMissingMember},
		{"path not base64", withPath(`/etc`), DropBadPath},
		{"path unpadded", withPath(`L2V0Yy9zc2g`), DropBadPath},
		{"path with newline", withPath(`L2V0\nYy9zc2g=`), DropBadPath},
		{"path with escaped newline char", withPath(`L2V0\u000aYy9zc2g=`), DropBadPath},
		{"path url-safe alphabet", withPath(b64("/etc/\xfb\xff")[:8] + "_-__"), DropBadPath},
		{"path non-canonical padding bits", withPath(`L2V0Yx==`), DropBadPath},
		{"path padding inside", withPath(`L2V0=Yw=`), DropBadPath},
		{"path not a string", `{"path": 5, "type": "dir", "size": 1, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1, "ctime": 1}`, DropBadPath},
		{"path empty", withPath(``), DropBadPath},
		{"path relative", withPath(b64("etc/passwd")), DropBadPath},
		{"path dot", withPath(b64("/etc/./passwd")), DropBadPath},
		{"path dotdot", withPath(b64("/etc/../root/x")), DropBadPath},
		{"path double slash", withPath(b64("/etc//passwd")), DropBadPath},
		{"path trailing slash", withPath(b64("/etc/")), DropBadPath},
		{"path NUL", withPath(b64("/etc/pass\x00wd")), DropBadPath},
		{"path too long", withPath(b64("/etc/" + strings.Repeat("a", MaxPathBytes-4))), DropBadPath},
		{"path too deep", withPath(b64("/etc" + strings.Repeat("/a", MaxPathDepth))), DropBadPath},
		{"path outside roots", withPath(b64("/var/lib/x")), DropOutsideRoots},
		{"path prefix but not component", withPath(b64("/etcetera/x")), DropOutsideRoots},
		{"path glob root mismatch", withPath(b64("/home/alice/.ssh/known_hosts")), DropOutsideRoots},
		{"type unknown", strings.Replace(rec(``), `"dir"`, `"fifo"`, 1), DropBadType},
		{"type case", strings.Replace(rec(``), `"dir"`, `"Dir"`, 1), DropBadType},
		{"size negative", strings.Replace(rec(``), `"size": 4096`, `"size": -1`, 1), DropBadInteger},
		{"size float", strings.Replace(rec(``), `"size": 4096`, `"size": 4096.5`, 1), DropBadInteger},
		{"size exponent", strings.Replace(rec(``), `"size": 4096`, `"size": 4e3`, 1), DropBadInteger},
		{"size overflow", strings.Replace(rec(``), `"size": 4096`, `"size": 9223372036854775808`, 1), DropBadInteger},
		{"size string", strings.Replace(rec(``), `"size": 4096`, `"size": "4096"`, 1), DropBadInteger},
		{"size object", strings.Replace(rec(``), `"size": 4096`, `"size": {"v": 1}`, 1), DropBadInteger},
		{"mode with type bits", strings.Replace(rec(``), `"mode": 493`, `"mode": 16877`, 1), DropBadInteger},
		{"uid no-id value", strings.Replace(rec(``), `"uid": 0`, `"uid": 4294967295`, 1), DropBadInteger},
		{"gid negative", strings.Replace(rec(``), `"gid": 0`, `"gid": -0`, 1), DropBadInteger},
		{"inode negative", strings.Replace(rec(``), `"inode": 2`, `"inode": -2`, 1), DropBadInteger},
		{"inode too big", strings.Replace(rec(``), `"inode": 2`, `"inode": 18446744073709551616`, 1), DropBadInteger},
		{"mtime out of range", strings.Replace(rec(``), `"mtime": 1762934000`, `"mtime": -62135596801`, 1), DropBadInteger},
		{"sha256 uppercase", strings.Replace(rec(`, "sha256": "`+strings.Repeat("A", 64)+`"`), `"dir"`, `"file"`, 1), DropBadHash},
		{"sha256 short", strings.Replace(rec(`, "sha256": "`+strings.Repeat("a", 63)+`"`), `"dir"`, `"file"`, 1), DropBadHash},
		{"sha256 on dir", rec(`, "sha256": "` + strings.Repeat("a", 64) + `"`), DropBadHash},
		{"sha256 null", strings.Replace(rec(`, "sha256": null`), `"dir"`, `"file"`, 1), DropBadHash},
		{"symlink without link", strings.Replace(rec(``), `"dir"`, `"symlink"`, 1), DropBadLink},
		{"link on dir", rec(`, "link": "ZGFzaA=="`), DropBadLink},
		{"link empty", strings.Replace(rec(`, "link": ""`), `"dir"`, `"symlink"`, 1), DropBadLink},
		{"link NUL", strings.Replace(rec(`, "link": "`+b64("a\x00b")+`"`), `"dir"`, `"symlink"`, 1), DropBadLink},
		{"link too long", strings.Replace(rec(`, "link": "`+b64(strings.Repeat("a", MaxLinkBytes+1))+`"`), `"dir"`, `"symlink"`, 1), DropBadLink},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := mutate(t, validDoc(t), firstRecord, tt.rec)
			res, err := parseString(t, doc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if res.Complete() || !slices.Contains(res.Partial, ReasonInvalidRecord) {
				t.Fatalf("partial = %v, want %s", res.Partial, ReasonInvalidRecord)
			}
			if len(res.Records) != 10 {
				t.Fatalf("got %d records, want 10", len(res.Records))
			}
			if res.Dropped[tt.want] != 1 {
				t.Fatalf("dropped = %v, want one %s", res.Dropped, tt.want)
			}
			for _, r := range res.Records {
				if validatePath(r.Path) != nil {
					t.Fatalf("invalid path passed: %q", r.Path)
				}
			}
		})
	}
}

func TestValidPathEdgeCasesAccepted(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"non-UTF-8 name", "/etc/\xff\xfe"},
		{"newline in name", "/etc/a\nb"},
		{"max length", "/etc/" + strings.Repeat("a", MaxPathBytes-5)},
		{"max depth", "/etc" + strings.Repeat("/a", MaxPathDepth-1)},
		{"dots in name", "/etc/...x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := `{"path": "` + b64(tt.path) + `", "type": "other", "size": 0, "mode": 0, "uid": 4294967294, "gid": 0, "inode": 18446744073709551615, "mtime": -1, "ctime": 253402300799}`
			doc := mutate(t, validDoc(t), firstRecord, firstRecord+", "+rec)
			doc = mutate(t, doc, `"records": 11`, `"records": 12`)
			res, err := parseString(t, doc)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Complete() {
				t.Fatalf("partial %v dropped %v", res.Partial, res.Dropped)
			}
			findRecord(t, res, tt.path)
		})
	}
}

func TestDuplicatePathDropped(t *testing.T) {
	doc := mutate(t, validDoc(t), firstRecord, firstRecord+", "+firstRecord)
	doc = mutate(t, doc, `"records": 11`, `"records": 12`)
	res, err := parseString(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dropped[DropDuplicatePath] != 1 || len(res.Records) != 11 || res.Complete() {
		t.Fatalf("dropped %v records %d partial %v", res.Dropped, len(res.Records), res.Partial)
	}
}

func TestRecordLimitCutsRunToPartial(t *testing.T) {
	lim := defaultLimits
	lim.records = 3
	res, err := parseLim(t, validDoc(t), lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || res.Dropped[DropOverLimit] != 8 || !slices.Contains(res.Partial, ReasonRecordLimit) {
		t.Fatalf("records %d dropped %v partial %v", len(res.Records), res.Dropped, res.Partial)
	}
	// Counters still match the entries seen, so the only reasons are the
	// limit and the SSH configuration whose file record was cut off.
	if slices.Contains(res.Partial, ReasonCounterMismatch) {
		t.Fatalf("partial %v", res.Partial)
	}
}

func TestDocumentLimitCutsRunToPartial(t *testing.T) {
	doc := validDoc(t)
	cutAt := strings.Index(doc, `{"path": "L3Vzci9iaW4="`)
	lim := defaultLimits
	lim.docBytes = int64(cutAt)
	res, err := parseLim(t, doc, lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Complete() || !slices.Contains(res.Partial, ReasonDocumentLimit) {
		t.Fatalf("partial %v", res.Partial)
	}
	if len(res.Records) == 0 || len(res.Records) > 4 {
		t.Fatalf("got %d records", len(res.Records))
	}
	if res.SSHConfig != nil || res.SSHConfigState != SSHConfigMissing {
		t.Fatal("cut run supplies an SSH configuration")
	}
}

func TestDocumentExactlyAtLimitIsAccepted(t *testing.T) {
	doc := validDoc(t)
	lim := defaultLimits
	lim.docBytes = int64(len(doc))
	res, err := parseLim(t, doc, lim)
	if err != nil || !res.Complete() {
		t.Fatalf("err %v res %+v", err, res)
	}
	lim.docBytes--
	res, err = parseLim(t, doc, lim)
	if err != nil || !slices.Contains(res.Partial, ReasonDocumentLimit) {
		t.Fatalf("one byte over: err %v partial %v", err, res.Partial)
	}
}

func TestCutBeforeHeaderRejects(t *testing.T) {
	doc := validDoc(t)
	// Move the header to the end so the cut happens before it is seen.
	header := "\"format\": \"fim-scan-v1\",\n  \"profile\": \"fim-test-v1\",\n  \"mode\": \"full\",\n"
	doc = mutate(t, doc, header, "")
	doc = mutate(t, doc, `"truncated": false,`, `"truncated": false, "format": "fim-scan-v1", "profile": "fim-test-v1", "mode": "full",`)
	if _, err := parseString(t, doc); err != nil {
		t.Fatalf("reordered document: %v", err)
	}
	lim := defaultLimits
	lim.docBytes = int64(len(doc) / 2)
	if _, err := parseLim(t, doc, lim); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("err = %v, want ErrInvalidResult", err)
	}
}

func TestOversizedRecordCutsRun(t *testing.T) {
	big := `{"path": "L2V0Yw==", "type": "dir", "size": 1, "mode": 493, "uid": 0, "gid": 0, "inode": 2, "mtime": 1, "ctime": 1, "pad": "` + strings.Repeat("a", MaxRecordBytes) + `"}`
	doc := mutate(t, validDoc(t), firstRecord, big)
	res, err := parseString(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Partial, ReasonEntryLimit) || len(res.Records) != 0 {
		t.Fatalf("partial %v records %d", res.Partial, len(res.Records))
	}
}

func TestRecordJustBelowEntryLimitIsDroppedNotCut(t *testing.T) {
	pad := MaxRecordBytes - len(firstRecord) - 200
	big := strings.TrimSuffix(firstRecord, "}") + `, "pad": "` + strings.Repeat("a", pad) + `"}`
	doc := mutate(t, validDoc(t), firstRecord, big)
	res, err := parseString(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.Partial, ReasonEntryLimit) || res.Dropped[DropBadMember] != 1 || len(res.Records) != 10 {
		t.Fatalf("partial %v dropped %v records %d", res.Partial, res.Dropped, len(res.Records))
	}
}

// endlessReader yields a fixed prefix and then whitespace forever, counting
// how much the parser pulled.
type endlessReader struct {
	prefix []byte
	n      int64
}

func (e *endlessReader) Read(p []byte) (int, error) {
	if len(e.prefix) > 0 {
		n := copy(p, e.prefix)
		e.prefix = e.prefix[n:]
		e.n += int64(n)
		return n, nil
	}
	for i := range p {
		p[i] = ' '
	}
	e.n += int64(len(p))
	return len(p), nil
}

func TestEndlessInputIsBoundedByEntryWindow(t *testing.T) {
	r := &endlessReader{prefix: []byte(`{"format": "fim-scan-v1", "profile": "fim-test-v1", "mode": "full", "records": [`)}
	res, err := Parse(context.Background(), r, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Partial, ReasonEntryLimit) {
		t.Fatalf("partial %v", res.Partial)
	}
	if r.n > 2*MaxRecordBytes {
		t.Fatalf("parser pulled %d bytes from an endless reader", r.n)
	}
}

func TestStreamingNeverBuffersMoreThanAWindow(t *testing.T) {
	// A long but valid document: the reader must not be drained ahead.
	var sb strings.Builder
	sb.WriteString(`{"format": "fim-scan-v1", "profile": "fim-test-v1", "mode": "full", "records": [`)
	const n = 2000
	for i := range n {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"path": "` + b64("/etc/f"+strings.Repeat("x", i%50)+string(rune('a'+i%26))+itoa(i)) + `", "type": "file", "size": 1, "mode": 420, "uid": 0, "gid": 0, "inode": 1, "mtime": 1, "ctime": 1}`)
	}
	sb.WriteString(`]}`)
	cr := &peakReader{r: strings.NewReader(sb.String())}
	_, err := Parse(context.Background(), cr, testOpts())
	if !errors.Is(err, ErrInvalidResult) { // members missing; only the reads matter
		t.Fatalf("err = %v", err)
	}
	if cr.maxRead > MaxRecordBytes {
		t.Fatalf("single read of %d bytes", cr.maxRead)
	}
}

type peakReader struct {
	r       io.Reader
	maxRead int
}

func (p *peakReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.maxRead = max(p.maxRead, n)
	return n, err
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestRootsClassification(t *testing.T) {
	doc := validDoc(t)
	tests := []struct {
		name    string
		doc     string
		want    map[string]RootState
		partial []Reason
	}{
		{
			name:    "missing non-optional root is skipped",
			doc:     mutate(t, doc, `{"root": "/usr/bin", "status": "scanned"}`, `{"root": "/usr/bin", "status": "missing"}`),
			want:    map[string]RootState{"/usr/bin": RootSkipped},
			partial: []Reason{ReasonRootSkipped, ReasonInvalidRecord},
		},
		{
			name:    "unreadable root is skipped even if optional",
			doc:     mutate(t, doc, `{"root": "/opt", "status": "missing"}`, `{"root": "/opt", "status": "error"}`),
			want:    map[string]RootState{"/opt": RootSkipped},
			partial: []Reason{ReasonRootSkipped},
		},
		{
			name:    "unreported root is skipped",
			doc:     mutate(t, doc, `{"root": "/opt", "status": "missing"}`, `{"root": "/boot/efi", "status": "missing"}`),
			want:    map[string]RootState{"/opt": RootSkipped},
			partial: []Reason{ReasonRootSkipped, ReasonInvalidRoot},
		},
		{
			name:    "unknown root entry dropped",
			doc:     mutate(t, doc, `{"root": "/opt", "status": "missing"}`, `{"root": "/opt", "status": "missing"}, {"root": "/var", "status": "scanned"}`),
			want:    map[string]RootState{"/opt": RootAbsent},
			partial: []Reason{ReasonInvalidRoot},
		},
		{
			name:    "unknown status dropped",
			doc:     mutate(t, doc, `{"root": "/opt", "status": "missing"}`, `{"root": "/opt", "status": "absent"}`),
			want:    map[string]RootState{"/opt": RootSkipped},
			partial: []Reason{ReasonInvalidRoot, ReasonRootSkipped},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseString(t, tt.doc)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range res.Roots {
				if want, ok := tt.want[r.Pattern]; ok && r.State != want {
					t.Errorf("root %s = %v, want %v", r.Pattern, r.State, want)
				}
			}
			for _, p := range tt.partial {
				if !slices.Contains(res.Partial, p) {
					t.Errorf("partial %v lacks %s", res.Partial, p)
				}
			}
		})
	}
}

func TestRecordUnderUnscannedRootDropped(t *testing.T) {
	doc := mutate(t, validDoc(t), `{"root": "/usr/bin", "status": "scanned"}`, `{"root": "/usr/bin", "status": "missing"}`)
	res, err := parseString(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dropped[DropRootNotScanned] != 3 || len(res.Records) != 8 {
		t.Fatalf("dropped %v records %d", res.Dropped, len(res.Records))
	}
}

func TestRunLevelPartialReasons(t *testing.T) {
	doc := validDoc(t)
	tests := []struct {
		name string
		doc  string
		want Reason
	}{
		{"host truncated", mutate(t, doc, `"truncated": false`, `"truncated": true`), ReasonHostTruncated},
		{"unreadable files", mutate(t, doc, `"unreadable": 0`, `"unreadable": 2`), ReasonUnreadable},
		{"record counter mismatch", mutate(t, doc, `"records": 11`, `"records": 12`), ReasonCounterMismatch},
		{"mount counter mismatch", mutate(t, doc, `"mounts": 1,`, `"mounts": 0,`), ReasonCounterMismatch},
		{"ssh counter mismatch", mutate(t, doc, `"ssh_config": 1,`, `"ssh_config": 2,`), ReasonCounterMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseString(t, tt.doc)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(res.Partial, tt.want) {
				t.Fatalf("partial %v lacks %s", res.Partial, tt.want)
			}
		})
	}
}

func TestMountValidation(t *testing.T) {
	doc := validDoc(t)
	mount := `{"path": "L2V0Yy9wdmU=", "fstype": "fuse"}`
	tests := []struct {
		name string
		repl string
		drop DropReason
	}{
		{"fstype uppercase", `{"path": "L2V0Yy9wdmU=", "fstype": "FUSE"}`, DropBadFSType},
		{"fstype too long", `{"path": "L2V0Yy9wdmU=", "fstype": "` + strings.Repeat("a", MaxFSTypeBytes+1) + `"}`, DropBadFSType},
		{"fstype empty", `{"path": "L2V0Yy9wdmU=", "fstype": ""}`, DropBadFSType},
		{"fstype space", `{"path": "L2V0Yy9wdmU=", "fstype": "fuse x"}`, DropBadFSType},
		{"path outside roots", `{"path": "` + b64("/var") + `", "fstype": "ext4"}`, DropOutsideRoots},
		{"missing fstype", `{"path": "L2V0Yy9wdmU="}`, DropMissingMember},
		{"unknown member", `{"path": "L2V0Yy9wdmU=", "fstype": "fuse", "opts": "rw"}`, DropBadMember},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseString(t, mutate(t, doc, mount, tt.repl))
			if err != nil {
				t.Fatal(err)
			}
			if res.Dropped[tt.drop] != 1 || len(res.Mounts) != 0 || !slices.Contains(res.Partial, ReasonInvalidMount) {
				t.Fatalf("dropped %v mounts %d partial %v", res.Dropped, len(res.Mounts), res.Partial)
			}
		})
	}
}

func TestMountLimit(t *testing.T) {
	lim := defaultLimits
	lim.mounts = 1
	doc := mutate(t, validDoc(t), `{"path": "L2V0Yy9wdmU=", "fstype": "fuse"}`, `{"path": "L2V0Yy9wdmU=", "fstype": "fuse"}, {"path": "L2Jvb3Q=", "fstype": "ext4"}`)
	doc = mutate(t, doc, `"mounts": 1,`, `"mounts": 2,`)
	res, err := parseLim(t, doc, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Mounts) != 1 || !slices.Contains(res.Partial, ReasonMountLimit) || slices.Contains(res.Partial, ReasonCounterMismatch) {
		t.Fatalf("mounts %d partial %v", len(res.Mounts), res.Partial)
	}
}

func TestSSHConfigStates(t *testing.T) {
	doc := validDoc(t)
	entry := `{"path": "L2V0Yy9zc2gvc3NoZF9jb25maWc=", "content": "UG9ydCAyMgo="}`
	tests := []struct {
		name string
		doc  string
		lim  func(*limits)
		want SSHConfigState
	}{
		{"missing array", mutate(t, mutate(t, doc, `"ssh_config": [`+"\n    "+entry+"\n  ],", ``), `"ssh_config": 1,`, `"ssh_config": 0,`), nil, SSHConfigMissing},
		{"content differs from record hash", mutate(t, doc, `"UG9ydCAyMgo="`, `"`+b64("Port 23\n")+`"`), nil, SSHConfigInconsistent},
		{"no file record", mutate(t, doc, entry, `{"path": "`+b64("/etc/ssh/sshd_config.d/x.conf")+`", "content": "UG9ydCAyMgo="}`), nil, SSHConfigInconsistent},
		{"record not hashed", mutate(t, doc, `"inode": 4, "mtime": 1762934000, "ctime": 1762934000, "sha256": "e807422bad84e7926a98fb262153b3d9c84244080e69b0e5d20446c183ffafc4"`, `"inode": 4, "mtime": 1762934000, "ctime": 1762934000`), nil, SSHConfigInconsistent},
		{"bad base64", mutate(t, doc, `"UG9ydCAyMgo="`, `"UG9ydCAyMgo"`), nil, SSHConfigInvalid},
		{"path outside roots", mutate(t, doc, entry, `{"path": "`+b64("/var/x")+`", "content": "UG9ydCAyMgo="}`), nil, SSHConfigInvalid},
		{"unknown member", mutate(t, doc, entry, `{"path": "L2V0Yy9zc2gvc3NoZF9jb25maWc=", "content": "UG9ydCAyMgo=", "x": 1}`), nil, SSHConfigInvalid},
		{"duplicate path", mutate(t, mutate(t, doc, entry, entry+", "+entry), `"ssh_config": 1,`, `"ssh_config": 2,`), nil, SSHConfigInvalid},
		{"too many files", doc, func(l *limits) { l.sshFiles = 0 }, SSHConfigInvalid},
		{"too many bytes", doc, func(l *limits) { l.sshBytes = 7 }, SSHConfigInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lim := defaultLimits
			if tt.lim != nil {
				tt.lim(&lim)
			}
			res, err := parseLim(t, tt.doc, lim)
			if err != nil {
				t.Fatal(err)
			}
			if res.SSHConfigState != tt.want || res.SSHConfig != nil || !slices.Contains(res.Partial, ReasonSSHConfig) {
				t.Fatalf("state %v config %v partial %v", res.SSHConfigState, res.SSHConfig != nil, res.Partial)
			}
		})
	}
}

func TestSSHConfigEntryAtFullBudgetFits(t *testing.T) {
	content := strings.Repeat("#", MaxSSHConfigBytes)
	sum := sha256.Sum256([]byte(content))
	doc := validDoc(t)
	doc = mutate(t, doc, `"UG9ydCAyMgo="`, `"`+b64(content)+`"`)
	doc = mutate(t, doc, "e807422bad84e7926a98fb262153b3d9c84244080e69b0e5d20446c183ffafc4", hex.EncodeToString(sum[:]))
	res, err := parseString(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || res.SSHConfigState != SSHConfigValid {
		t.Fatalf("partial %v state %v", res.Partial, res.SSHConfigState)
	}
}

func TestBadOptionsRejected(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Options)
		want error
	}{
		{"short key", func(o *Options) { o.HostKey = o.HostKey[:16] }, ErrBadOptions},
		{"no key", func(o *Options) { o.HostKey = nil }, ErrBadOptions},
		{"unknown mode", func(o *Options) { o.Mode = "quick" }, ErrBadOptions},
		{"empty profile", func(o *Options) { o.Profile.ID = "" }, ErrBadProfile},
		{"no roots", func(o *Options) { o.Profile.Roots = nil }, ErrBadProfile},
		{"relative root", func(o *Options) { o.Profile.Roots[0].Pattern = "etc" }, ErrBadProfile},
		{"bad glob root", func(o *Options) { o.Profile.Roots[0].Pattern = "/etc/[" }, ErrBadProfile},
		{"duplicate root", func(o *Options) { o.Profile.Roots[1].Pattern = "/etc" }, ErrBadProfile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts()
			tt.mod(&opts)
			_, err := Parse(context.Background(), strings.NewReader(validDoc(t)), opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCanceledContextStopsParse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Parse(ctx, strings.NewReader(validDoc(t)), testOpts())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestLimitsMatchSpec(t *testing.T) {
	if MaxRecords != 300000 || MaxDocumentBytes != 128*1024*1024 || MaxPathDepth != 64 || MaxRecordBytes != 16*1024 ||
		MaxPathBytes != 4096 || MaxLinkBytes != 4096 || MaxMounts != 256 || MaxFSTypeBytes != 64 ||
		MaxSSHConfigFiles != 64 || MaxSSHConfigBytes != 256*1024 {
		t.Fatal("limits differ from ADR 0015 D6 / spec 09 v26-09-01")
	}
}
