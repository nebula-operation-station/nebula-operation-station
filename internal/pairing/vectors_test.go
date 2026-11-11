// SPDX-License-Identifier: AGPL-3.0-or-later

package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateVectors rewrites testdata/vectors.json from the deterministic
// generator: go test ./internal/pairing -run TestGeneratorReproducesVectors -update
var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsFile = "testdata/vectors.json"

// vectorFile is the on-disk format shared with the EN-04 script test.
type vectorFile struct {
	Comment string   `json:"comment"`
	Domain  string   `json:"domain"`
	Vectors []vector `json:"vectors"`
}

// vector is one test vector. HiHex and LoHex are the two 60-bit halves of
// the first 120 digest bits as 15 hex digits each; CheckValue is v mod 37.
type vector struct {
	SaltHex       string `json:"salt_hex"`
	KeyBlobBase64 string `json:"key_blob_base64"`
	HiHex         string `json:"hi_hex"`
	LoHex         string `json:"lo_hex"`
	CheckValue    int    `json:"check_value"`
	Code          string `json:"code"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vf); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return vf
}

func TestVectorsMatchCompute(t *testing.T) {
	vf := loadVectors(t)
	if vf.Domain != domain {
		t.Fatalf("domain %q, want %q", vf.Domain, domain)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vf.Vectors {
		salt, err := hex.DecodeString(v.SaltHex)
		if err != nil {
			t.Fatalf("vector %d salt: %v", i, err)
		}
		blob, err := base64.StdEncoding.DecodeString(v.KeyBlobBase64)
		if err != nil {
			t.Fatalf("vector %d blob: %v", i, err)
		}
		c, err := Compute(salt, blob)
		if err != nil {
			t.Fatalf("vector %d: Compute: %v", i, err)
		}
		if c.String() != v.Code {
			t.Fatalf("vector %d: code %s, want %s", i, c, v.Code)
		}
		if ref := referenceCode(salt, blob); ref != v.Code {
			t.Fatalf("vector %d: reference %s, want %s", i, ref, v.Code)
		}
		p, err := Parse(v.Code)
		if err != nil || !Equal(p, c) {
			t.Fatalf("vector %d: Parse(%s) = %v, %v", i, v.Code, p, err)
		}

		// The halves as the script reads them, and the split check formula.
		d := digest(salt, blob)
		full := hex.EncodeToString(d[:])
		if v.HiHex != full[:15] || v.LoHex != full[15:30] {
			t.Fatalf("vector %d: halves %s/%s, want %s/%s", i, v.HiHex, v.LoHex, full[:15], full[15:30])
		}
		var hi, lo uint64
		if _, err := fmt.Sscanf(v.HiHex+" "+v.LoHex, "%x %x", &hi, &lo); err != nil {
			t.Fatalf("vector %d: halves: %v", i, err)
		}
		if got := int(((hi%37)*10 + lo%37) % 37); got != v.CheckValue {
			t.Fatalf("vector %d: split check %d, want %d", i, got, v.CheckValue)
		}
		vb, _ := new(big.Int).SetString(full[:30], 16)
		if got := int(new(big.Int).Mod(vb, big.NewInt(37)).Int64()); got != v.CheckValue {
			t.Fatalf("vector %d: big check %d, want %d", i, got, v.CheckValue)
		}
		if v.Code[len(v.Code)-1] != checkAlphabet[v.CheckValue] {
			t.Fatalf("vector %d: check char %c, want %c", i, v.Code[len(v.Code)-1], checkAlphabet[v.CheckValue])
		}
	}
}

// coverage is what EN-03 requires the vector set to contain.
type coverage struct {
	symbolAt [dataChars][32]bool
	check    [37]bool
	hiOnly   bool // top bit of hi set, of lo clear
	loOnly   bool // top bit of lo set, of hi clear
	both     bool // top bits of hi and lo set
}

func (c *coverage) add(code string) {
	s := strings.ReplaceAll(code, "-", "")
	for i := 0; i < dataChars; i++ {
		c.symbolAt[i][strings.IndexByte(dataAlphabet, s[i])] = true
	}
	c.check[strings.IndexByte(checkAlphabet, s[dataChars])] = true
	hiTop := strings.IndexByte(dataAlphabet, s[0]) >= 16
	loTop := strings.IndexByte(dataAlphabet, s[12]) >= 16
	c.hiOnly = c.hiOnly || (hiTop && !loTop)
	c.loOnly = c.loOnly || (loTop && !hiTop)
	c.both = c.both || (hiTop && loTop)
}

func (c *coverage) missing() []string {
	var m []string
	for i := range c.symbolAt {
		for j, ok := range c.symbolAt[i] {
			if !ok {
				m = append(m, fmt.Sprintf("symbol %c at position %d", dataAlphabet[j], i+1))
			}
		}
	}
	for j, ok := range c.check {
		if !ok {
			m = append(m, fmt.Sprintf("check value %d (%c)", j, checkAlphabet[j]))
		}
	}
	if !c.hiOnly {
		m = append(m, "top bit of hi set (lo clear)")
	}
	if !c.loOnly {
		m = append(m, "top bit of lo set (hi clear)")
	}
	if !c.both {
		m = append(m, "top bits of hi and lo both set")
	}
	return m
}

func TestVectorsCoverAllSymbolsPositionsAndChecks(t *testing.T) {
	vf := loadVectors(t)
	var c coverage
	for _, v := range vf.Vectors {
		c.add(v.Code)
	}
	if m := c.missing(); len(m) > 0 {
		t.Fatalf("vector set misses %d items, first: %s", len(m), strings.Join(m[:min(len(m), 10)], "; "))
	}
}

func TestCoverageDetectsGaps(t *testing.T) {
	// The coverage check itself must report gaps; one vector cannot cover.
	var c coverage
	c.add(validCode(t, "0123456789ABCDEFGHJKMNPQ"))
	if len(c.missing()) == 0 {
		t.Fatal("coverage of one vector reported complete")
	}
}

// Generator. Candidates are deterministic: key k is the ed25519 key from
// seed SHA-256("nos-pairing-vector-key" || k), salt i is
// SHA-256("nos-pairing-vector-salt" || i). A greedy set cover picks
// candidates until the coverage is complete.

const (
	genKeys       = 8
	genCandidates = 40000
)

// coverage bit layout: 24*32 symbol bits, 37 check bits, 3 top-bit bits.
const coverBits = dataChars*32 + 37 + 3

type coverMask [(coverBits + 63) / 64]uint64

func (m *coverMask) set(i int) { m[i/64] |= 1 << (i % 64) }

func maskOf(code string) coverMask {
	var m coverMask
	s := strings.ReplaceAll(code, "-", "")
	for i := 0; i < dataChars; i++ {
		m.set(i*32 + strings.IndexByte(dataAlphabet, s[i]))
	}
	m.set(dataChars*32 + strings.IndexByte(checkAlphabet, s[dataChars]))
	hiTop := strings.IndexByte(dataAlphabet, s[0]) >= 16
	loTop := strings.IndexByte(dataAlphabet, s[12]) >= 16
	base := dataChars*32 + 37
	switch {
	case hiTop && loTop:
		m.set(base + 2)
	case hiTop:
		m.set(base)
	case loTop:
		m.set(base + 1)
	}
	return m
}

func generateVectors(t *testing.T) vectorFile {
	t.Helper()
	blobs := make([][]byte, genKeys)
	for k := range blobs {
		blobs[k] = testKeyBlob(t, fmt.Sprintf("nos-pairing-vector-key%d", k))
	}
	type cand struct {
		salt, blob []byte
		code       string
		mask       coverMask
	}
	cands := make([]cand, genCandidates)
	for i := range cands {
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		salt := sha256.Sum256(append([]byte("nos-pairing-vector-salt"), idx[:]...))
		blob := blobs[i%genKeys]
		c, err := Compute(salt[:], blob)
		if err != nil {
			t.Fatal(err)
		}
		cands[i] = cand{salt: salt[:], blob: blob, code: c.String(), mask: maskOf(c.String())}
	}
	var full coverMask
	for i := 0; i < coverBits; i++ {
		full.set(i)
	}
	var covered coverMask
	used := make([]bool, len(cands))
	vf := vectorFile{
		Comment: "EN-03/EN-04 pairing code vectors (ADR 0013 D3). Generated by TestGeneratorReproducesVectors -update; do not edit by hand.",
		Domain:  domain,
	}
	for covered != full {
		best, bestGain := -1, 0
		for i := range cands {
			if used[i] {
				continue
			}
			gain := 0
			for w := range covered {
				gain += bits.OnesCount64(cands[i].mask[w] &^ covered[w])
			}
			if gain > bestGain {
				best, bestGain = i, gain
			}
		}
		if best < 0 {
			t.Fatalf("generator: candidates cannot complete coverage")
		}
		used[best] = true
		for w := range covered {
			covered[w] |= cands[best].mask[w]
		}
		c := cands[best]
		d := digest(c.salt, c.blob)
		full30 := hex.EncodeToString(d[:15])
		vb, _ := new(big.Int).SetString(full30, 16)
		vf.Vectors = append(vf.Vectors, vector{
			SaltHex:       hex.EncodeToString(c.salt),
			KeyBlobBase64: base64.StdEncoding.EncodeToString(c.blob),
			HiHex:         full30[:15],
			LoHex:         full30[15:],
			CheckValue:    int(new(big.Int).Mod(vb, big.NewInt(37)).Int64()),
			Code:          c.code,
		})
	}
	return vf
}

func TestGeneratorReproducesVectors(t *testing.T) {
	vf := generateVectors(t)
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *updateVectors {
		if err := os.MkdirAll(filepath.Dir(vectorsFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsFile, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	have, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	if !bytes.Equal(have, out) {
		t.Fatalf("%s differs from generator output; regenerate with -update and review", vectorsFile)
	}
	t.Logf("%d vectors", len(vf.Vectors))
}
