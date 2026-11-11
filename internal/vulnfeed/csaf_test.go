// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// csafNow is the fixed clock of the CSAF tests.
var csafNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// csafTestKey is a throw-away OpenPGP key generated at test time. No key
// material is committed to testdata: only the synthetic advisories are.
type csafTestKey struct {
	ent     *openpgp.Entity
	armored []byte
}

// newCSAFTestKey generates a throw-away EdDSA key created at created with
// the given lifetime in seconds (0: no expiry).
func newCSAFTestKey(t *testing.T, created time.Time, lifetime uint32) csafTestKey {
	t.Helper()
	cfg := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return created },
		KeyLifetimeSecs: lifetime,
	}
	ent, err := openpgp.NewEntity("CSAF test key throw-away", "", "csaf-test@example.invalid", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return csafTestKey{ent: ent, armored: buf.Bytes()}
}

// sign returns an armored detached signature over doc made at "at".
func (k csafTestKey) sign(t *testing.T, doc []byte, at time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, k.ent, bytes.NewReader(doc), &packet.Config{Time: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var (
	csafKeyOnce sync.Once
	csafKey     csafTestKey
	csafOther   csafTestKey
)

// csafKeys returns the pinned test key and an unpinned one (shared, since
// generation is the slow part of these tests).
func csafKeys(t *testing.T) (pinned, other csafTestKey) {
	t.Helper()
	csafKeyOnce.Do(func() {
		csafKey = newCSAFTestKey(t, csafNow.Add(-365*24*time.Hour), 0)
		csafOther = newCSAFTestKey(t, csafNow.Add(-365*24*time.Hour), 0)
	})
	if csafKey.ent == nil || csafOther.ent == nil {
		t.Fatal("test key generation failed")
	}
	return csafKey, csafOther
}

// csafTestDoc renders a testdata advisory with the given tracking version
// and current release date.
func csafTestDoc(t *testing.T, file, version string, date time.Time) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "csaf", file))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "@VERSION@", version)
	s = strings.ReplaceAll(s, "@DATE@", date.UTC().Format(time.RFC3339))
	return []byte(s)
}

// csafServer is a loopback CSAF provider: provider metadata, one ROLIE
// feed and documents with their .asc and hash companions.
type csafServer struct {
	t    *testing.T
	srv  *httptest.Server
	mu   sync.Mutex
	docs []string // published document names, in feed order
	// files maps a request path to its body; a missing path is a 404.
	files map[string][]byte
	hits  map[string]int
	// updated is the ROLIE "updated" value per document name.
	updated map[string]string
	fetcher *Fetcher
}

func newCSAFServer(t *testing.T) *csafServer {
	t.Helper()
	cs := &csafServer{t: t, files: map[string][]byte{}, hits: map[string]int{}, updated: map[string]string{}}
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.hits[r.URL.Path]++
		b, ok := cs.files[r.URL.Path]
		if r.URL.Path == "/rolie/white.json" {
			b, ok = cs.feedLocked(), true
		}
		cs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	cs.srv = srv
	cs.fetcher = newTestFetcher(t, pool, 10*time.Second, srv)
	meta := map[string]any{
		"canonical_url": srv.URL + "/.well-known/csaf/provider-metadata.json",
		"role":          "csaf_trusted_provider",
		"distributions": []any{map[string]any{"rolie": map[string]any{"feeds": []any{
			map[string]any{"tlp_label": "WHITE", "url": srv.URL + "/rolie/white.json"},
			map[string]any{"tlp_label": "AMBER", "url": srv.URL + "/rolie/amber.json"},
		}}}},
		// Keys announced by the download itself; they must never be used.
		"public_openpgp_keys": []any{map[string]any{"fingerprint": "0000000000000000000000000000000000000000", "url": srv.URL + "/keys/provider.asc"}},
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	cs.files["/.well-known/csaf/provider-metadata.json"] = mb
	return cs
}

// feedLocked renders the ROLIE feed of the published documents.
func (cs *csafServer) feedLocked() []byte {
	entries := []any{}
	for _, name := range cs.docs {
		u := cs.srv.URL + "/docs/" + name
		entries = append(entries, map[string]any{
			"id":      strings.TrimSuffix(name, ".json"),
			"title":   name,
			"updated": cs.updated[name],
			"link":    []any{map[string]any{"rel": "self", "href": u}, map[string]any{"rel": "signature", "href": u + ".asc"}, map[string]any{"rel": "hash", "href": u + ".sha512"}},
			"content": map[string]any{"type": "application/json", "src": u},
			"format":  map[string]any{"schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", "version": "2.0"},
		})
	}
	b, _ := json.Marshal(map[string]any{"feed": map[string]any{"id": "test-white", "title": "test", "updated": "2026-11-11T00:00:00Z", "entry": entries}})
	return b
}

// csafPub controls how one document is published.
type csafPub struct {
	key     csafTestKey
	signAt  time.Time
	noSig   bool
	noHash  bool
	sha256  bool   // publish .sha256 instead of .sha512
	tamper  []byte // served instead of doc (signature and hash cover doc)
	badHash bool
	updated string
}

// publish serves doc under /docs/name with its companions.
func (cs *csafServer) publish(name string, doc []byte, p csafPub) {
	cs.t.Helper()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	base := "/docs/" + name
	if !containsString(cs.docs, name) {
		cs.docs = append(cs.docs, name)
	}
	if p.updated == "" {
		p.updated = time.Now().UTC().Format(time.RFC3339Nano)
	}
	cs.updated[name] = p.updated
	served := doc
	if p.tamper != nil {
		served = p.tamper
	}
	cs.files[base] = served
	delete(cs.files, base+".asc")
	delete(cs.files, base+".sha512")
	delete(cs.files, base+".sha256")
	if !p.noSig {
		at := p.signAt
		if at.IsZero() {
			at = csafNow.Add(-time.Hour)
		}
		cs.files[base+".asc"] = p.key.sign(cs.t, doc, at)
	}
	if !p.noHash {
		hashed := served
		if p.badHash {
			hashed = append([]byte("x"), served...)
		}
		if p.sha256 {
			s := sha256.Sum256(hashed)
			cs.files[base+".sha256"] = []byte(hex.EncodeToString(s[:]) + "  " + name + "\n")
		} else {
			s := sha512.Sum512(hashed)
			cs.files[base+".sha512"] = []byte(hex.EncodeToString(s[:]) + "  " + name + "\n")
		}
	}
}

func (cs *csafServer) hitCount(path string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hits[path]
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// source returns the signed CSAF source of the test provider.
func (cs *csafServer) source(t *testing.T, vendor CSAFVendor, keys ...csafTestKey) CSAFSource {
	t.Helper()
	armored := make([][]byte, len(keys))
	for i, k := range keys {
		armored[i] = k.armored
	}
	kr, err := ParseCSAFKeyring(armored...)
	if err != nil {
		t.Fatal(err)
	}
	return CSAFSource{
		Feed: Feed{
			Name: "test-csaf", SourceID: "test-csaf",
			URL:       cs.srv.URL + "/.well-known/csaf/provider-metadata.json",
			Integrity: vulnfinding.IntegritySigned, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
		},
		Vendor: vendor,
		Keys:   kr,
	}
}

func (cs *csafServer) client(t *testing.T) *CSAFClient {
	t.Helper()
	c, err := NewCSAFClient(cs.fetcher, func() time.Time { return csafNow })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const (
	ciscoDocName = "cisco-sa-test-ios-2026.json"
	panDocName   = "pan-sa-2026-0001.json"
	ciscoID      = "cisco-sa-test-ios-2026"
	panID        = "PAN-SA-2026-0001"
)

// syncOK runs a sync that must succeed as a whole.
func syncOK(t *testing.T, c *CSAFClient, src CSAFSource, prev CSAFState) (CSAFState, CSAFReport) {
	t.Helper()
	st, rep, err := c.Sync(context.Background(), src, prev)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return st, rep
}

// onlyRejection asserts exactly one rejection wrapping want.
func onlyRejection(t *testing.T, rep CSAFReport, want error) {
	t.Helper()
	if len(rep.Rejected) != 1 {
		t.Fatalf("rejections = %+v, want exactly one", rep.Rejected)
	}
	if !errors.Is(rep.Rejected[0].Err, want) {
		t.Fatalf("rejection = %v, want %v", rep.Rejected[0].Err, want)
	}
}

func TestCSAFSyncAcceptsSignedCiscoAndPanOS(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	d1 := csafNow.Add(-48 * time.Hour)
	d2 := csafNow.Add(-24 * time.Hour)
	cs.publish(ciscoDocName, csafTestDoc(t, ciscoDocName, "1.0.0", d1), csafPub{key: key})
	cs.publish(panDocName, csafTestDoc(t, panDocName, "2", d2), csafPub{key: key, sha256: true})

	st, rep := syncOK(t, cs.client(t), cs.source(t, CSAFVendorCisco, key), CSAFState{})
	if len(rep.Rejected) != 0 || rep.Accepted != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if got := st.ContentDate(); !got.Equal(d2) {
		t.Fatalf("content date = %v, want %v", got, d2)
	}
	if cs.hitCount("/rolie/amber.json") != 0 {
		t.Fatal("non-WHITE/CLEAR ROLIE feed fetched")
	}
	if cs.hitCount("/keys/provider.asc") != 0 {
		t.Fatal("key announced by the provider metadata was fetched")
	}
	c, ok := st.Documents[ciscoID]
	if !ok || c.Version != "1.0.0" || !c.ReleaseDate.Equal(d1) {
		t.Fatalf("cisco entry = %+v", c)
	}
	if p, ok := st.Documents[panID]; !ok || p.Version != "2" {
		t.Fatalf("pan entry = %+v", p)
	}
}

func TestParseCSAFAdvisoryCiscoProductTree(t *testing.T) {
	adv, err := ParseCSAFAdvisory(csafTestDoc(t, ciscoDocName, "1", csafNow), CSAFVendorCisco)
	if err != nil {
		t.Fatal(err)
	}
	if adv.TrackingID != ciscoID || len(adv.Vulnerabilities) != 1 || adv.Vulnerabilities[0].CVE != "CVE-2026-20001" {
		t.Fatalf("advisory = %+v", adv)
	}
	want := map[string]CSAFProduct{
		"CSAFPID-0001": {Vendor: "Cisco", Product: "Cisco IOS", Version: "15.2(4)M3", Train: "15.2M", Ecosystem: "vendor:cisco:ios"},
		"CSAFPID-0002": {Vendor: "Cisco", Product: "Cisco IOS", Version: "15.2(4)M11", Train: "15.2M", Ecosystem: "vendor:cisco:ios"},
		"CSAFPID-0003": {Vendor: "Cisco", Product: "Cisco IOS XE Software", Version: "17.3.1", Train: "17.3", Ecosystem: "vendor:cisco:ios-xe"},
		"CSAFPID-0004": {Vendor: "Cisco", Product: "Cisco IOS XE Software", Version: "17.3.8", Train: "17.3", Ecosystem: "vendor:cisco:ios-xe"},
		"CSAFPID-0005": {Vendor: "Cisco", Product: "Cisco Business 350 Series Managed Switches", Version: "3.2.0.84", Train: "3.2", Ecosystem: "vendor:cisco:cbs"},
		"CSAFPID-0006": {Vendor: "Cisco", Product: "Cisco Business 350 Series Managed Switches", Version: "3.3.0.16", Train: "3.3", Ecosystem: "vendor:cisco:cbs"},
	}
	checkProducts(t, adv, want)
	v := adv.Vulnerabilities[0]
	if strings.Join(v.Affected, ",") != "CSAFPID-0001,CSAFPID-0003,CSAFPID-0005" || strings.Join(v.Fixed, ",") != "CSAFPID-0002,CSAFPID-0004,CSAFPID-0006" {
		t.Fatalf("vulnerability = %+v", v)
	}
	fixed := adv.FixedProducts(v)
	if len(fixed) != 3 || fixed[1].Version != "17.3.8" {
		t.Fatalf("fixed products = %+v", fixed)
	}
}

func TestParseCSAFAdvisoryPanOSRanges(t *testing.T) {
	adv, err := ParseCSAFAdvisory(csafTestDoc(t, panDocName, "1", csafNow), CSAFVendorPaloAlto)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]CSAFProduct{
		"CSAFPID-1001": {Vendor: "Palo Alto Networks", Product: "PAN-OS", VersionRange: "vers:generic/>=10.2.0|<10.2.9", Train: "10.2", Ecosystem: "vendor:paloalto:panos"},
		"CSAFPID-1002": {Vendor: "Palo Alto Networks", Product: "PAN-OS", Version: "10.2.9", Train: "10.2", Ecosystem: "vendor:paloalto:panos"},
		"CSAFPID-1003": {Vendor: "Palo Alto Networks", Product: "PAN-OS", VersionRange: "vers:generic/>=11.1.0|<11.1.3", Train: "11.1", Ecosystem: "vendor:paloalto:panos"},
		"CSAFPID-1004": {Vendor: "Palo Alto Networks", Product: "PAN-OS", Version: "11.1.3-h4", Train: "11.1", Ecosystem: "vendor:paloalto:panos"},
	}
	checkProducts(t, adv, want)
}

func TestParseCSAFAdvisoryWrongVendorNotClassified(t *testing.T) {
	// A Cisco-shaped tree read for the Palo Alto source gets no ecosystem.
	adv, err := ParseCSAFAdvisory(csafTestDoc(t, ciscoDocName, "1", csafNow), CSAFVendorPaloAlto)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range adv.Products {
		if p.Ecosystem != "" {
			t.Fatalf("product %s classified as %s for the wrong vendor", p.ProductID, p.Ecosystem)
		}
	}
}

func checkProducts(t *testing.T, adv CSAFAdvisory, want map[string]CSAFProduct) {
	t.Helper()
	if len(adv.Products) != len(want) {
		t.Fatalf("products = %+v", adv.Products)
	}
	for _, p := range adv.Products {
		w, ok := want[p.ProductID]
		if !ok {
			t.Fatalf("unexpected product %+v", p)
		}
		w.ProductID, w.Name = p.ProductID, p.Name
		if p != w {
			t.Fatalf("product %s = %+v, want %+v", p.ProductID, p, w)
		}
	}
}

// acceptedCisco syncs a valid v1 Cisco document and returns the state.
func acceptedCisco(t *testing.T, cs *csafServer, src CSAFSource, key csafTestKey, version string, date time.Time) CSAFState {
	t.Helper()
	cs.publish(ciscoDocName, csafTestDoc(t, ciscoDocName, version, date), csafPub{key: key})
	st, rep := syncOK(t, cs.client(t), src, CSAFState{})
	if rep.Accepted != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("baseline sync report = %+v", rep)
	}
	return st
}

// assertKept checks that the previously accepted revision stays.
func assertKept(t *testing.T, st CSAFState, version string, date time.Time) {
	t.Helper()
	d, ok := st.Documents[ciscoID]
	if !ok || d.Version != version || !d.ReleaseDate.Equal(date) {
		t.Fatalf("previous revision not kept: %+v", d)
	}
}

func TestCSAFRejectionsKeepPreviousRevision(t *testing.T) {
	key, other := csafKeys(t)
	expired := newCSAFTestKey(t, csafNow.Add(-10*24*time.Hour), 24*60*60) // expired 9 days ago
	d1 := csafNow.Add(-72 * time.Hour)
	d2 := csafNow.Add(-1 * time.Hour)
	tests := []struct {
		name string
		pub  func(t *testing.T, doc []byte) csafPub
		doc  func(t *testing.T) []byte
		keys []csafTestKey
		want error
	}{
		{
			name: "tampered document",
			pub: func(t *testing.T, doc []byte) csafPub {
				return csafPub{key: key, tamper: bytes.Replace(doc, []byte("17.3.8"), []byte("17.3.0"), 1)}
			},
			want: ErrCSAFSignatureInvalid,
		},
		{
			name: "hash mismatch",
			pub:  func(t *testing.T, doc []byte) csafPub { return csafPub{key: key, badHash: true} },
			want: ErrChecksumMismatch,
		},
		{
			name: "missing signature",
			pub:  func(t *testing.T, doc []byte) csafPub { return csafPub{key: key, noSig: true} },
			want: ErrCSAFSignatureMissing,
		},
		{
			name: "missing hash",
			pub:  func(t *testing.T, doc []byte) csafPub { return csafPub{key: key, noHash: true} },
			want: ErrCSAFHashMissing,
		},
		{
			name: "signed by unpinned key",
			pub:  func(t *testing.T, doc []byte) csafPub { return csafPub{key: other} },
			want: ErrCSAFSignatureInvalid,
		},
		{
			name: "expired pinned key",
			pub: func(t *testing.T, doc []byte) csafPub {
				return csafPub{key: expired, signAt: csafNow.Add(-10*24*time.Hour + time.Hour)}
			},
			keys: []csafTestKey{key, expired},
			want: ErrCSAFKeyExpired,
		},
		{
			name: "signature made in the future",
			pub:  func(t *testing.T, doc []byte) csafPub { return csafPub{key: key, signAt: csafNow.Add(time.Hour)} },
			want: ErrCSAFSignatureInvalid,
		},
		{
			name: "older version",
			doc:  func(t *testing.T) []byte { return csafTestDoc(t, ciscoDocName, "1.0.0", d2) },
			want: ErrCSAFOlderRevision,
		},
		{
			name: "older release date",
			doc:  func(t *testing.T) []byte { return csafTestDoc(t, ciscoDocName, "3.0.0", d1.Add(-time.Hour)) },
			want: ErrCSAFOlderRevision,
		},
		{
			name: "release date in the future",
			doc:  func(t *testing.T) []byte { return csafTestDoc(t, ciscoDocName, "3.0.0", csafNow.Add(time.Hour)) },
			want: ErrFutureContentDate,
		},
		{
			name: "same revision with other content",
			doc: func(t *testing.T) []byte {
				return bytes.Replace(csafTestDoc(t, ciscoDocName, "2.0.0", d1), []byte("Synthetic test revision."), []byte("Changed."), 1)
			},
			want: ErrCSAFOlderRevision,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newCSAFServer(t)
			keys := tt.keys
			if keys == nil {
				keys = []csafTestKey{key}
			}
			src := cs.source(t, CSAFVendorCisco, keys...)
			prev := acceptedCisco(t, cs, src, key, "2.0.0", d1)

			doc := csafTestDoc(t, ciscoDocName, "2.1.0", d2)
			if tt.doc != nil {
				doc = tt.doc(t)
			}
			pub := csafPub{key: key}
			if tt.pub != nil {
				pub = tt.pub(t, doc)
			}
			cs.publish(ciscoDocName, doc, pub)
			st, rep := syncOK(t, cs.client(t), src, prev)
			onlyRejection(t, rep, tt.want)
			if rep.Accepted != 0 {
				t.Fatalf("accepted = %d", rep.Accepted)
			}
			assertKept(t, st, "2.0.0", d1)
			if !st.ContentDate().Equal(d1) {
				t.Fatalf("content date moved to %v", st.ContentDate())
			}
		})
	}
}

func TestCSAFNewerRevisionReplaces(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	src := cs.source(t, CSAFVendorCisco, key)
	d1 := csafNow.Add(-72 * time.Hour)
	d2 := csafNow.Add(-time.Hour)
	prev := acceptedCisco(t, cs, src, key, "1.9.0", d1)
	cs.publish(ciscoDocName, csafTestDoc(t, ciscoDocName, "1.10.0", d2), csafPub{key: key})
	st, rep := syncOK(t, cs.client(t), src, prev)
	if rep.Accepted != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	assertKept(t, st, "1.10.0", d2)
	// The caller's previous state is not modified.
	assertKept(t, prev, "1.9.0", d1)
}

func TestCSAFIdenticalRevisionUnchanged(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	src := cs.source(t, CSAFVendorCisco, key)
	d1 := csafNow.Add(-72 * time.Hour)
	prev := acceptedCisco(t, cs, src, key, "1", d1)
	// Re-publish identical bytes under a new ROLIE "updated" value.
	cs.publish(ciscoDocName, csafTestDoc(t, ciscoDocName, "1", d1), csafPub{key: key, updated: "2099-01-01T00:00:00Z"})
	st, rep := syncOK(t, cs.client(t), src, prev)
	if rep.Accepted != 0 || rep.Unchanged != 1 || len(rep.Rejected) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	assertKept(t, st, "1", d1)
}

func TestCSAFUnchangedIndexEntrySkipsFetch(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	src := cs.source(t, CSAFVendorCisco, key)
	cs.publish(ciscoDocName, csafTestDoc(t, ciscoDocName, "1", csafNow.Add(-time.Hour)), csafPub{key: key, updated: "2026-11-10T00:00:00Z"})
	st, _ := syncOK(t, cs.client(t), src, CSAFState{})
	before := cs.hitCount("/docs/" + ciscoDocName)
	_, rep := syncOK(t, cs.client(t), src, st)
	if cs.hitCount("/docs/"+ciscoDocName) != before || rep.Unchanged != 1 {
		t.Fatalf("unchanged entry refetched (report %+v)", rep)
	}
}

func TestCSAFIndexFailureKeepsPreviousState(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	src := cs.source(t, CSAFVendorCisco, key)
	d1 := csafNow.Add(-72 * time.Hour)
	prev := acceptedCisco(t, cs, src, key, "1", d1)
	cs.mu.Lock()
	delete(cs.files, "/.well-known/csaf/provider-metadata.json")
	cs.mu.Unlock()
	st, _, err := cs.client(t).Sync(context.Background(), src, prev)
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("err = %v, want ErrHTTPStatus", err)
	}
	assertKept(t, st, "1", d1)
}

func TestCSAFMetadataWithoutRolieFeedRejected(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	cs.mu.Lock()
	cs.files["/.well-known/csaf/provider-metadata.json"] = []byte(`{"distributions":[{"rolie":{"feeds":[{"tlp_label":"RED","url":"` + cs.srv.URL + `/rolie/white.json"}]}}]}`)
	cs.mu.Unlock()
	_, _, err := cs.client(t).Sync(context.Background(), cs.source(t, CSAFVendorCisco, key), CSAFState{})
	if !errors.Is(err, ErrCSAFMalformed) {
		t.Fatalf("err = %v, want ErrCSAFMalformed", err)
	}
}

func TestCSAFDocumentNameMismatchRejected(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	// A validly signed PAN document served under the Cisco file name.
	cs.publish(ciscoDocName, csafTestDoc(t, panDocName, "1", csafNow.Add(-time.Hour)), csafPub{key: key})
	_, rep := syncOK(t, cs.client(t), cs.source(t, CSAFVendorCisco, key), CSAFState{})
	onlyRejection(t, rep, ErrCSAFMalformed)
}

func TestCSAFDocumentOffAllowlistRejected(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	// An index entry pointing at an origin outside the allowlist.
	feed := `{"feed":{"entry":[{"id":"x","updated":"2026-11-10T00:00:00Z","content":{"src":"https://evil.example.invalid/docs/` + ciscoDocName + `"}}]}}`
	cs.mu.Lock()
	cs.files["/rolie/alt.json"] = []byte(feed)
	cs.files["/.well-known/csaf/provider-metadata.json"] = []byte(`{"distributions":[{"rolie":{"feeds":[{"tlp_label":"CLEAR","url":"` + cs.srv.URL + `/rolie/alt.json"}]}}]}`)
	cs.mu.Unlock()
	_, rep := syncOK(t, cs.client(t), cs.source(t, CSAFVendorCisco, key), CSAFState{})
	onlyRejection(t, rep, ErrOriginNotAllowed)
}

func TestVerifyCSAFSignatureRejectsMalformed(t *testing.T) {
	key, _ := csafKeys(t)
	kr, err := ParseCSAFKeyring(key.armored)
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"x":1}`)
	good := key.sign(t, doc, csafNow.Add(-time.Hour))
	if err := kr.Verify(doc, good, csafNow); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	for name, asc := range map[string][]byte{
		"empty":       nil,
		"garbage":     []byte("not a signature"),
		"public key":  key.armored,
		"truncated":   good[:len(good)/2],
		"oversize":    bytes.Repeat([]byte("A"), MaxCSAFSignatureBytes+1),
		"other bytes": key.sign(t, []byte(`{"x":2}`), csafNow.Add(-time.Hour)),
	} {
		if err := kr.Verify(doc, asc, csafNow); !errors.Is(err, ErrCSAFSignatureInvalid) {
			t.Errorf("%s: err = %v, want ErrCSAFSignatureInvalid", name, err)
		}
	}
}

func TestParseCSAFKeyringRejects(t *testing.T) {
	key, _ := csafKeys(t)
	var priv bytes.Buffer
	w, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.ent.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rsaSmall := func() []byte {
		ent, err := openpgp.NewEntity("small", "", "small@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 1024})
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		w, _ := armor.Encode(&b, openpgp.PublicKeyType, nil)
		_ = ent.Serialize(w)
		_ = w.Close()
		return b.Bytes()
	}()
	for name, in := range map[string][][]byte{
		"none":        nil,
		"empty":       {{}},
		"garbage":     {[]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")},
		"private key": {priv.Bytes()},
		"weak RSA":    {rsaSmall},
		"oversize":    {bytes.Repeat([]byte("A"), MaxCSAFPinnedKeyBytes+1)},
	} {
		if _, err := ParseCSAFKeyring(in...); !errors.Is(err, ErrCSAFKeyring) {
			t.Errorf("%s: err = %v, want ErrCSAFKeyring", name, err)
		}
	}
	kr, err := ParseCSAFKeyring(key.armored)
	if err != nil {
		t.Fatal(err)
	}
	if fps := kr.Fingerprints(); len(fps) != 1 || len(fps[0]) != 40 {
		t.Fatalf("fingerprints = %v", fps)
	}
}

func TestCompareCSAFVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		err  bool
	}{
		{"1", "1", 0, false},
		{"2", "10", -1, false},
		{"10", "9", 1, false},
		{"1.0.0", "1.0.0", 0, false},
		{"1.9.0", "1.10.0", -1, false},
		{"1.0.0-alpha", "1.0.0", -1, false},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, false},
		{"1.0.0-2", "1.0.0-10", -1, false},
		{"1.0.0+build1", "1.0.0+build2", 0, false},
		{"99999999999999999999999", "99999999999999999999998", 1, false},
		{"1", "1.0.0", 0, true},
		{"01", "1", 0, true},
		{"", "1", 0, true},
		{"1.0", "1.0.0", 0, true},
		{"v1", "1", 0, true},
	}
	for _, tt := range tests {
		got, err := compareCSAFVersion(tt.a, tt.b)
		if (err != nil) != tt.err || (!tt.err && got != tt.want) {
			t.Errorf("compare(%q, %q) = %d, %v; want %d, err %v", tt.a, tt.b, got, err, tt.want, tt.err)
		}
	}
}

func TestParseCSAFAdvisoryRejectsMalformed(t *testing.T) {
	base := string(csafTestDoc(t, ciscoDocName, "1", csafNow))
	deep := `{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","title":"t","tracking":{"id":"x-1","version":"1","status":"final","current_release_date":"2026-11-11T00:00:00Z"}},"product_tree":{"branches":[` +
		strings.Repeat(`{"category":"product_family","name":"f","branches":[`, MaxCSAFBranchDepth+1) +
		`{"category":"product_version","name":"1","product":{"product_id":"P","name":"p"}}` +
		strings.Repeat(`]}`, MaxCSAFBranchDepth+1) + `]}}`
	tests := map[string]string{
		"csaf version":     strings.Replace(base, `"csaf_version": "2.0"`, `"csaf_version": "1.2"`, 1),
		"draft status":     strings.Replace(base, `"status": "final"`, `"status": "draft"`, 1),
		"control in title": strings.Replace(base, `Test Advisory`, `Test\u001bAdvisory`, 1),
		"bad date":         strings.Replace(base, csafNow.Format(time.RFC3339), "yesterday", 1),
		"bad version":      strings.Replace(base, `"version": "1"`, `"version": "one"`, 1),
		"bad cve":          strings.Replace(base, `CVE-2026-20001`, `CVE-26-1`, 1),
		"bad tracking id":  strings.Replace(base, `"id": "cisco-sa-test-ios-2026"`, `"id": "../../etc"`, 1),
		"invalid utf8":     strings.Replace(base, `Test Advisory`, "Test \xff Advisory", 1),
		"not json":         `{"document":`,
		"too deep":         deep,
	}
	for name, doc := range tests {
		if _, err := ParseCSAFAdvisory([]byte(doc), CSAFVendorCisco); !errors.Is(err, ErrCSAFMalformed) {
			t.Errorf("%s: err = %v, want ErrCSAFMalformed", name, err)
		}
	}
}

func TestCSAFSourceRequiresSignedFeedAndKeys(t *testing.T) {
	key, _ := csafKeys(t)
	cs := newCSAFServer(t)
	good := cs.source(t, CSAFVendorCisco, key)
	noKeys := good
	noKeys.Keys = nil
	unsigned := good
	unsigned.Feed.Integrity = vulnfinding.IntegrityNone
	badVendor := good
	badVendor.Vendor = "juniper"
	for name, src := range map[string]CSAFSource{"no keys": noKeys, "unsigned feed": unsigned, "vendor": badVendor} {
		if _, _, err := cs.client(t).Sync(context.Background(), src, CSAFState{}); !errors.Is(err, ErrInvalidFeed) {
			t.Errorf("%s: err = %v, want ErrInvalidFeed", name, err)
		}
	}
	if cs.hitCount("/.well-known/csaf/provider-metadata.json") != 0 {
		t.Fatal("invalid source was fetched")
	}
}

func TestCSAFFileName(t *testing.T) {
	for id, want := range map[string]string{
		"cisco-sa-test-ios-2026": "cisco-sa-test-ios-2026.json",
		"PAN-SA-2026-0001":       "pan-sa-2026-0001.json",
		"Example:2026/01  x":     "example_2026_01_x.json",
	} {
		if got := csafFileName(id); got != want {
			t.Errorf("csafFileName(%q) = %q, want %q", id, got, want)
		}
	}
}
