// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu   sync.Mutex
	recs []Record
}

func (m *memStore) LastEvent() (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.recs) == 0 {
		return 0, nil, nil
	}
	r := m.recs[len(m.recs)-1]
	return r.Seq, r.Hash, nil
}

func (m *memStore) InsertEvent(r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if int64(len(m.recs))+1 != r.Seq {
		return errors.New("not next")
	}
	m.recs = append(m.recs, r)
	return nil
}

func newChain(t *testing.T) (*Chain, *memStore) {
	t.Helper()
	key, _, err := LoadOrCreateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := &memStore{}
	c := NewChain(st, key)
	c.now = func() time.Time { return time.Unix(1_800_000_000, 5).UTC() }
	return c, st
}

func TestChainVerifies(t *testing.T) {
	c, st := newChain(t)
	for i := 0; i < 5; i++ {
		if _, err := c.Append("unlocked", map[string]string{"by": "axel", "n": strings.Repeat("x", i)}); err != nil {
			t.Fatal(err)
		}
	}
	pub := c.PublicKey()
	if err := Verify(pub, st.recs, nil); err != nil {
		t.Fatal(err)
	}
	// A page in the middle verifies against the hash before it.
	if err := Verify(pub, st.recs[2:], st.recs[1].Hash); err != nil {
		t.Fatal(err)
	}
	var b Body
	if err := json.Unmarshal(st.recs[0].Body, &b); err != nil || b.Seq != 1 || b.Kind != "unlocked" || b.Time != "2027-01-15T08:00:00.000000005Z" {
		t.Fatalf("%+v %v", b, err)
	}
	clone := func() []Record { return append([]Record(nil), st.recs...) }
	changed := clone()
	changed[2].Body = bytes.Replace(changed[2].Body, []byte("axel"), []byte("evil"), 1)
	if err := Verify(pub, changed, nil); !errors.Is(err, ErrBadHash) {
		t.Fatal(err)
	}
	rehashed := clone()
	rehashed[2].Body = changed[2].Body
	rehashed[2].Hash = hashOf(rehashed[2].PrevHash, rehashed[2].Body)
	if err := Verify(pub, rehashed, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	dropped := append(clone()[:2], st.recs[3:]...)
	if err := Verify(pub, dropped, nil); !errors.Is(err, ErrBrokenChain) {
		t.Fatal(err)
	}
	swapped := clone()
	swapped[1], swapped[2] = swapped[2], swapped[1]
	if err := Verify(pub, swapped, nil); !errors.Is(err, ErrBrokenChain) {
		t.Fatal(err)
	}
	other, _, _ := LoadOrCreateKey(t.TempDir())
	if err := Verify(other.Public().(ed25519.PublicKey), st.recs, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	if err := Verify(pub, st.recs[2:], st.recs[0].Hash); !errors.Is(err, ErrBrokenChain) {
		t.Fatal(err)
	}
}

func TestAppendBoundsAttrs(t *testing.T) {
	c, st := newChain(t)
	attrs := map[string]string{"big": strings.Repeat("é", MaxAttrValue), "bad": "a\xffb"}
	for i := 0; i < MaxAttrs+5; i++ {
		attrs["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if _, err := c.Append(strings.Repeat("k", 200), attrs); err != nil {
		t.Fatal(err)
	}
	var b Body
	_ = json.Unmarshal(st.recs[0].Body, &b)
	if len(b.Attrs) != MaxAttrs+1 || b.Attrs["_truncated"] != "true" || len(b.Kind) != MaxKind {
		t.Fatalf("%d attrs, kind %d", len(b.Attrs), len(b.Kind))
	}
	for k, v := range b.Attrs {
		if len(v) > MaxAttrValue || strings.Contains(v, "\xff") {
			t.Fatalf("%s: %d bytes", k, len(v))
		}
	}
}

func TestHandlerRecordsAuditLines(t *testing.T) {
	c, st := newChain(t)
	var out bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&out, nil), c)).With("component", "executor")
	log.Info("started")
	log.Info("audit", "kind", "login_succeeded", "user", "axel", "time", time.Unix(0, 0))
	log.WithGroup("rpc").Warn("audit", "kind", "rpc_denied", "uid", 1001)
	if len(st.recs) != 2 {
		t.Fatalf("%d events", len(st.recs))
	}
	var b Body
	_ = json.Unmarshal(st.recs[1].Body, &b)
	if b.Kind != "rpc_denied" || b.Attrs["rpc.uid"] != "1001" || b.Attrs["component"] != "executor" || b.Attrs["level"] != "WARN" {
		t.Fatalf("%+v", b)
	}
	_ = json.Unmarshal(st.recs[0].Body, &b)
	if b.Attrs["time"] != "1970-01-01T00:00:00Z" || b.Attrs["user"] != "axel" {
		t.Fatalf("%+v", b)
	}
	if strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("log lines: %s", out.String())
	}
	// A store failure is logged and does not stop the line.
	bad := NewChain(failing{}, ed25519.NewKeyFromSeed(make([]byte, 32)))
	out.Reset()
	slog.New(NewHandler(slog.NewJSONHandler(&out, nil), bad)).Info("audit", "kind", "x")
	if !strings.Contains(out.String(), "event chain: append failed") || !strings.Contains(out.String(), `"msg":"audit"`) {
		t.Fatal(out.String())
	}
}

type failing struct{}

func (failing) LastEvent() (int64, []byte, error) { return 0, nil, errors.New("disk full") }
func (failing) InsertEvent(Record) error          { return errors.New("disk full") }

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	k1, created, err := LoadOrCreateKey(dir)
	if err != nil || !created {
		t.Fatal(err)
	}
	k2, created, err := LoadOrCreateKey(dir)
	if err != nil || created || !k1.Equal(k2) {
		t.Fatal("key not reused")
	}
	st, _ := os.Stat(filepath.Join(dir, KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	_ = os.Chmod(filepath.Join(dir, KeyFile), 0o644)
	if _, _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("loose mode accepted")
	}
	link := t.TempDir()
	_ = os.Symlink(filepath.Join(dir, KeyFile), filepath.Join(link, KeyFile))
	if _, _, err := LoadOrCreateKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	short := t.TempDir()
	_ = os.WriteFile(filepath.Join(short, KeyFile), []byte("short"), 0o600)
	if _, _, err := LoadOrCreateKey(short); err == nil {
		t.Fatal("short key accepted")
	}
	if !strings.HasPrefix(Fingerprint(k1.Public().(ed25519.PublicKey)), "SHA256:") {
		t.Fatal("fingerprint")
	}
}

func TestConcurrentAppends(t *testing.T) {
	c, st := newChain(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Append("x", nil)
		}()
	}
	wg.Wait()
	if err := Verify(c.PublicKey(), st.recs, nil); err != nil || len(st.recs) != 20 {
		t.Fatal(len(st.recs), err)
	}
	_ = context.Background()
}
