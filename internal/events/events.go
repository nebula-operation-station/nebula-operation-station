// SPDX-License-Identifier: AGPL-3.0-or-later

// Package events keeps the executor's signed event chain (spec 03, M10-1).
// Every audit line the executor logs is also appended as an event: its
// canonical JSON (RFC 8785), the hash of the previous event, and
// SHA-256(previous hash || event) signed with the executor's Ed25519 event
// key. The chain shows that the events came from the executor and were not
// changed, reordered or removed in the middle; it cannot stop root on the
// Nebula machine from rewriting it with the key.
package events

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// KeyFile is the event key in the executor's data directory.
const KeyFile = "events.key"

// Limits on what one event carries.
const (
	MaxAttrs     = 32
	MaxAttrValue = 1024
	MaxKind      = 64
)

// Record is one stored event.
type Record struct {
	Seq      int64
	Body     []byte // canonical JSON of Body
	PrevHash []byte // 32 bytes; zeros for the first event
	Hash     []byte // SHA-256(PrevHash || Body)
	Sig      []byte // Ed25519 over Hash
}

// Body is the signed content of an event.
type Body struct {
	Seq   int64             `json:"seq"`
	Time  string            `json:"time"` // RFC 3339, UTC, nanoseconds
	Kind  string            `json:"kind"`
	Attrs map[string]string `json:"attrs"`
}

// Store keeps the records (executordb).
type Store interface {
	LastEvent() (seq int64, hash []byte, err error)
	InsertEvent(r Record) error
}

// Chain appends events. It is safe for concurrent use.
type Chain struct {
	mu    sync.Mutex
	store Store
	key   ed25519.PrivateKey
	now   func() time.Time
}

// NewChain returns a chain over store signed with key.
func NewChain(store Store, key ed25519.PrivateKey) *Chain {
	return &Chain{store: store, key: key, now: time.Now}
}

// PublicKey is the chain's verification key.
func (c *Chain) PublicKey() ed25519.PublicKey { return c.key.Public().(ed25519.PublicKey) }

// Fingerprint is the SHA-256 fingerprint of a public key, in the form
// "SHA256:<base64>" without padding.
func Fingerprint(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
}

func clip(s string, n int) string {
	s = string(bytes.ToValidUTF8([]byte(s), []byte("?")))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Append adds one event and returns its record.
func (c *Chain) Append(kind string, attrs map[string]string) (Record, error) {
	if kind == "" {
		kind = "unknown"
	}
	b := Body{Kind: clip(kind, MaxKind), Attrs: map[string]string{}}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == MaxAttrs {
			b.Attrs["_truncated"] = "true"
			break
		}
		b.Attrs[clip(k, MaxKind)] = clip(attrs[k], MaxAttrValue)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seq, prev, err := c.store.LastEvent()
	if err != nil {
		return Record{}, err
	}
	if prev == nil {
		prev = make([]byte, sha256.Size)
	}
	b.Seq, b.Time = seq+1, c.now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(b)
	if err != nil {
		return Record{}, err
	}
	body, err := jcs.Transform(raw)
	if err != nil {
		return Record{}, err
	}
	r := Record{Seq: b.Seq, Body: body, PrevHash: prev}
	r.Hash = hashOf(prev, body)
	r.Sig = ed25519.Sign(c.key, r.Hash)
	if err := c.store.InsertEvent(r); err != nil {
		return Record{}, err
	}
	return r, nil
}

func hashOf(prev, body []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	return h.Sum(nil)
}

// Errors of verification.
var (
	ErrBadHash      = errors.New("events: an event does not match its hash")
	ErrBadSignature = errors.New("events: an event signature is not valid")
	ErrBrokenChain  = errors.New("events: the chain is broken (an event is missing, reordered or changed)")
)

// Verify checks consecutive records: each hash, each signature, each link
// to the record before, and that the body carries the record's sequence
// number. prev is the hash before the first record (nil: check the first
// record's own link only, or zeros when it is event 1).
func Verify(pub ed25519.PublicKey, records []Record, prev []byte) error {
	for i, r := range records {
		if !bytes.Equal(hashOf(r.PrevHash, r.Body), r.Hash) {
			return fmt.Errorf("%w (event %d)", ErrBadHash, r.Seq)
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, r.Hash, r.Sig) {
			return fmt.Errorf("%w (event %d)", ErrBadSignature, r.Seq)
		}
		var b Body
		if err := json.Unmarshal(r.Body, &b); err != nil || b.Seq != r.Seq {
			return fmt.Errorf("%w (event %d)", ErrBadHash, r.Seq)
		}
		switch {
		case i > 0 && (r.Seq != records[i-1].Seq+1 || !bytes.Equal(r.PrevHash, records[i-1].Hash)):
			return fmt.Errorf("%w (at event %d)", ErrBrokenChain, r.Seq)
		case i == 0 && prev != nil && !bytes.Equal(r.PrevHash, prev):
			return fmt.Errorf("%w (at event %d)", ErrBrokenChain, r.Seq)
		case i == 0 && r.Seq == 1 && !bytes.Equal(r.PrevHash, make([]byte, sha256.Size)):
			return fmt.Errorf("%w (at event 1)", ErrBrokenChain)
		}
	}
	return nil
}

// LoadOrCreateKey reads the event key from dir, creating it (0600) on
// first use. The file holds the 32-byte Ed25519 seed; a symlink, another
// mode or a wrong size is refused.
func LoadOrCreateKey(dir string) (ed25519.PrivateKey, bool, error) {
	path := filepath.Join(dir, KeyFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, false, err
		}
		nf, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, false, fmt.Errorf("events: create key: %w", err)
		}
		if _, err := nf.Write(seed); err != nil {
			_ = nf.Close()
			return nil, false, err
		}
		if err := nf.Sync(); err != nil {
			_ = nf.Close()
			return nil, false, err
		}
		if err := nf.Close(); err != nil {
			return nil, false, err
		}
		return ed25519.NewKeyFromSeed(seed), true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("events: open key: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("events: %s must be a regular file with mode 0600", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return nil, false, fmt.Errorf("events: %s is owned by another user", path)
	}
	seed, err := io.ReadAll(io.LimitReader(f, ed25519.SeedSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("events: %s has the wrong size", path)
	}
	return ed25519.NewKeyFromSeed(seed), false, nil
}

// --- slog handler ---

// Handler passes every record to next and also appends the records whose
// message is "audit" to the chain (the "kind" attribute names the event).
// A failure to append is logged through next and does not stop the log.
type Handler struct {
	next  slog.Handler
	chain *Chain
	pre   []slog.Attr
	group string
}

// NewHandler wraps next.
func NewHandler(next slog.Handler, chain *Chain) *Handler { return &Handler{next: next, chain: chain} }

// Enabled implements slog.Handler. Audit lines are logged at Info or
// above and are kept even when the log level hides them from next.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo || h.next.Enabled(ctx, l)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(as)
	for _, a := range as {
		c.pre = append(append([]slog.Attr{}, c.pre...), qualify(h.group, a))
	}
	return &c
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	c.next = h.next.WithGroup(name)
	if c.group != "" {
		c.group += "." + name
	} else {
		c.group = name
	}
	return &c
}

func qualify(group string, a slog.Attr) slog.Attr {
	if group != "" {
		a.Key = group + "." + a.Key
	}
	return a
}

func flatten(prefix string, a slog.Attr, out map[string]string) {
	v := a.Value.Resolve()
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if v.Kind() == slog.KindGroup {
		for _, g := range v.Group() {
			flatten(key, g, out)
		}
		return
	}
	switch v.Kind() {
	case slog.KindTime:
		out[key] = v.Time().UTC().Format(time.RFC3339Nano)
	default:
		out[key] = v.String()
	}
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "audit" && h.chain != nil {
		attrs := map[string]string{"level": r.Level.String()}
		for _, a := range h.pre {
			flatten("", a, attrs)
		}
		kind := ""
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "kind" && kind == "" {
				kind = a.Value.Resolve().String()
				return true
			}
			flatten(h.group, a, attrs)
			return true
		})
		if _, err := h.chain.Append(kind, attrs); err != nil {
			e := slog.NewRecord(time.Now(), slog.LevelError, "event chain: append failed", 0)
			e.AddAttrs(slog.String("kind", kind), slog.String("error", err.Error()))
			_ = h.next.Handle(ctx, e)
		}
	}
	if !h.next.Enabled(ctx, r.Level) {
		return nil
	}
	return h.next.Handle(ctx, r)
}
