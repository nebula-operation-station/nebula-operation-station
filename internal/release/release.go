// SPDX-License-Identifier: AGPL-3.0-or-later

// Package release verifies first-party release provenance (spec 10,
// Release signing; ADR 0007 E15): the signed release manifest, the signed
// root-rotation chain and the local built-in bundle (builtins.tar).
//
// Release roots are FIDO sk-ssh-ed25519@openssh.com keys bound to the
// application "ssh:". Signatures are detached SSHSIG envelopes in the
// namespace "nebula-release", verified by internal/sshsig through
// golang.org/x/crypto/ssh with user presence required. The only key
// sources are the anchors compiled into the binary and rotation documents
// signed by a root that was trusted before the rotation. A key supplied
// beside a bundle, a checksum alone or a server-exported directory
// establishes no trust. Provenance grants no execution authority.
package release

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/sshsig"
	"golang.org/x/crypto/ssh"
)

//go:embed rootkeys.txt
var anchorsFile []byte

// Namespace is the SSHSIG namespace of release manifests and rotations.
const Namespace = "nebula-release"

// Application is the FIDO application every release root is bound to.
const Application = "ssh:"

// Limits (spec 10, hard limits).
const (
	// MaxSignature bounds one armored detached signature, armor and
	// whitespace included.
	MaxSignature = 4096
	// MaxPublicKey bounds a root public key in a rotation document.
	MaxPublicKey = 256
	// MaxActiveRoots bounds the active roots after any rotation.
	MaxActiveRoots = 4
	// maxAnchorsFile bounds the compiled anchor file.
	maxAnchorsFile = 16 << 10
)

// Errors callers branch on.
var (
	// ErrFormat is malformed input: a document, signature or key that
	// does not meet the grammar or limits.
	ErrFormat = errors.New("release: malformed input")
	// ErrUntrusted is a signature by a key that is not a currently
	// trusted, non-revoked release root.
	ErrUntrusted = errors.New("release: signing key is not a trusted release root")
	// ErrSignature is a signature that does not verify, including a
	// security-key signature without user presence.
	ErrSignature = errors.New("release: signature does not verify")
	// ErrRotation is a rotation document that cannot be applied to the
	// current root state (replay, skipped sequence, wrong predecessor,
	// reuse, unknown revocation, too many or no active roots).
	ErrRotation = errors.New("release: rotation rejected")
	// ErrBundle is a built-in bundle that does not match its manifest or
	// violates the bundle grammar or limits.
	ErrBundle = errors.New("release: built-in bundle rejected")
)

var rootIDRe = regexp.MustCompile(`^root-[1-9][0-9]{0,26}$`)

// ValidRootID reports whether id is a root ID: root-<n>, 1 to 32 bytes.
func ValidRootID(id string) bool { return rootIDRe.MatchString(id) }

// Root is a release root: a label and an sk-ssh-ed25519 public key. The
// label is not the key's identity; keys are compared by their complete
// public-key blob.
type Root struct {
	// ID is the root's label, root-<n>.
	ID string
	// Key is the sk-ssh-ed25519@openssh.com public key bound to "ssh:".
	Key ssh.PublicKey
}

// Fingerprint is the root key's OpenSSH SHA256 fingerprint.
func (r Root) Fingerprint() string { return ssh.FingerprintSHA256(r.Key) }

// Anchor is one compiled bootstrap slot; Key is nil for an explicit empty
// placeholder, which never verifies anything.
type Anchor struct {
	// ID is the slot's root ID.
	ID string
	// Key is the root key, nil for an empty placeholder.
	Key ssh.PublicKey
}

// Anchors returns the bootstrap anchors compiled into this binary.
func Anchors() ([]Anchor, error) { return ParseAnchors(anchorsFile) }

// ParseAnchors parses an anchor file (see rootkeys.txt). It needs at
// least one non-empty anchor and rejects duplicate IDs or keys.
func ParseAnchors(raw []byte) ([]Anchor, error) {
	if len(raw) == 0 || len(raw) > maxAnchorsFile || bytes.ContainsRune(raw, '\r') {
		return nil, fmt.Errorf("%w: anchor file is empty, too large or not Unix text", ErrFormat)
	}
	var out []Anchor
	ids := map[string]bool{}
	keys := map[string]bool{}
	active := 0
	for i, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 || !ValidRootID(f[0]) || ids[f[0]] {
			return nil, fmt.Errorf("%w: anchor line %d: bad or duplicate root ID", ErrFormat, i+1)
		}
		ids[f[0]] = true
		if len(f) == 2 && f[1] == "-" {
			out = append(out, Anchor{ID: f[0]})
			continue
		}
		if len(f) < 3 {
			return nil, fmt.Errorf("%w: anchor line %d: expected a key or -", ErrFormat, i+1)
		}
		k, err := ParseRootKey(f[1] + " " + f[2])
		if err != nil {
			return nil, fmt.Errorf("anchor line %d: %w", i+1, err)
		}
		if keys[string(k.Marshal())] {
			return nil, fmt.Errorf("%w: anchor line %d: duplicate key", ErrFormat, i+1)
		}
		keys[string(k.Marshal())] = true
		out = append(out, Anchor{ID: f[0], Key: k})
		active++
	}
	if active == 0 || active > MaxActiveRoots {
		return nil, fmt.Errorf("%w: anchor file needs 1 to %d keys", ErrFormat, MaxActiveRoots)
	}
	return out, nil
}

// ParseRootKey parses a root public key written exactly as
// "sk-ssh-ed25519@openssh.com <canonical padded base64 key blob>", with no
// comment, options or newline, at most MaxPublicKey bytes. The blob must
// be a plain sk-ssh-ed25519 key (no certificate) bound to "ssh:".
func ParseRootKey(s string) (ssh.PublicKey, error) {
	bad := func(why string) (ssh.PublicKey, error) {
		return nil, fmt.Errorf("%w: root public key %s", ErrFormat, why)
	}
	if len(s) == 0 || len(s) > MaxPublicKey {
		return bad("is empty or too long")
	}
	typ, b64, ok := strings.Cut(s, " ")
	if !ok || typ != ssh.KeyAlgoSKED25519 || strings.ContainsAny(b64, " \t\r\n") {
		return bad("must be sk-ssh-ed25519@openssh.com and one base64 blob")
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || base64.StdEncoding.EncodeToString(blob) != b64 {
		return bad("is not canonical padded base64")
	}
	k, err := ssh.ParsePublicKey(blob)
	if err != nil || k.Type() != ssh.KeyAlgoSKED25519 || !bytes.Equal(k.Marshal(), blob) {
		return bad("is not an sk-ssh-ed25519 key blob")
	}
	var wire struct {
		Type        string
		PubKey      []byte
		Application string
	}
	if err := ssh.Unmarshal(blob, &wire); err != nil || wire.Application != Application {
		return bad("is not bound to application \"ssh:\"")
	}
	return k, nil
}

// FormatRootKey is the inverse of ParseRootKey.
func FormatRootKey(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

// verifyDocument checks that sig is a valid release-namespace signature
// over doc by one of roots and returns that root. Only the given roots
// are consulted; the key named in the envelope must equal one of them
// blob for blob.
func verifyDocument(roots []Root, doc, sig []byte) (Root, error) {
	if len(sig) == 0 || len(sig) > MaxSignature {
		return Root{}, fmt.Errorf("%w: signature must be 1 to %d bytes", ErrFormat, MaxSignature)
	}
	k, _, err := sshsig.Parse(sig)
	if err != nil {
		return Root{}, fmt.Errorf("%w: signature envelope does not parse", ErrFormat)
	}
	for _, r := range roots {
		if r.Key == nil || !bytes.Equal(r.Key.Marshal(), k.Marshal()) {
			continue
		}
		if _, err := sshsig.VerifySecurityKey(r.Key, Namespace, Application, doc, sig); err != nil {
			return Root{}, fmt.Errorf("%w: %w", ErrSignature, err)
		}
		return r, nil
	}
	return Root{}, ErrUntrusted
}
