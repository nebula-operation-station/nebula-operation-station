// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"path"
	"strings"
)

// HashKind says in which form a record's content hash is held.
type HashKind uint8

const (
	// HashNone: no content hash (not a file, or the host did not hash it).
	HashNone HashKind = iota
	// HashPlain: the host-reported SHA-256, kept only for the plain-hash
	// allowlist of ADR 0015 D6.
	HashPlain
	// HashKeyed: HMAC-SHA-256(k_host, sha256) computed by the parser; the
	// plain value never leaves it.
	HashKeyed
)

// String returns the kind name.
func (k HashKind) String() string {
	switch k {
	case HashPlain:
		return "plain"
	case HashKeyed:
		return "keyed"
	default:
		return "none"
	}
}

// Hash is a record's content hash in its D6 form.
type Hash struct {
	// Kind is the form of Sum.
	Kind HashKind
	// Secret marks a named secret-bearing path (ADR 0015 D6): always
	// keyed, and shown only as "content changed", never as a value.
	Secret bool
	// Sum is the plain SHA-256 (HashPlain) or the HMAC value (HashKeyed).
	Sum [sha256.Size]byte
}

// HostKeySize is the size of k_host, the per-host content key.
const HostKeySize = 32

// plainRoots are the roots whose file hashes stay plain (ADR 0015 D6).
var plainRoots = []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec"}

// plainBootPatterns are the kernel-image names directly in /boot whose
// hashes stay plain (ADR 0015 D6).
var plainBootPatterns = []string{"vmlinuz-*", "initrd.img-*", "System.map-*", "config-*"}

// PlainHashAllowed reports whether a file at path p keeps its plain SHA-256
// (ADR 0015 D6 allowlist). Named secret-bearing paths never do.
func PlainHashAllowed(p []byte) bool {
	if SecretPath(p) {
		return false
	}
	s := string(p)
	for _, r := range plainRoots {
		if strings.HasPrefix(s, r+"/") {
			return true
		}
	}
	if dir, name := path.Split(s); dir == "/boot/" {
		for _, pat := range plainBootPatterns {
			if ok, _ := path.Match(pat, name); ok {
				return true
			}
		}
	}
	return false
}

// secretExact are named secret-bearing files (ADR 0015 D6). The shadow
// backups "/etc/shadow-" and "/etc/gshadow-" hold the same password hashes
// and are added here as an implementation choice.
var secretExact = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-",
	"/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets",
	"/etc/ipsec.secrets",
	"/etc/postfix/sasl_passwd", "/etc/postfix/sasl_passwd.db", "/etc/postfix/sasl_passwd.lmdb",
	"/etc/mysql/debian.cnf", "/etc/krb5.keytab",
}

// secretTrees are named secret-bearing directories; everything below them
// is secret. All of /etc/nebula is treated as secret (conservative reading
// of "/etc/nebula/ secret files", D3).
var secretTrees = []string{
	"/etc/ssl/private", "/etc/wireguard", "/etc/NetworkManager/system-connections",
	"/etc/ipsec.d/private", "/etc/pve/priv", "/etc/nebula",
}

// SecretPath reports whether p is a named secret-bearing path of ADR 0015
// D6. Files named by a credentials= option in /etc/fstab are not covered
// here; that needs the fstab content and is decided by the caller.
func SecretPath(p []byte) bool {
	s := string(p)
	for _, e := range secretExact {
		if s == e {
			return true
		}
	}
	for _, t := range secretTrees {
		if strings.HasPrefix(s, t+"/") {
			return true
		}
	}
	if !strings.HasPrefix(s, "/etc/") {
		return false
	}
	dir, name := path.Split(s)
	if dir == "/etc/ssh/" {
		if ok, _ := path.Match("ssh_host_*_key", name); ok {
			return true
		}
	}
	if dir == "/etc/" && strings.HasPrefix(name, "cifs-credentials") {
		return true
	}
	return bytes.HasSuffix(p, []byte(".key")) || bytes.HasSuffix(p, []byte(".pem"))
}

// sealHash turns a plain host-reported SHA-256 into its D6 form for path p.
func sealHash(key []byte, p []byte, plain [sha256.Size]byte) Hash {
	h := Hash{Secret: SecretPath(p)}
	if !h.Secret && PlainHashAllowed(p) {
		h.Kind = HashPlain
		h.Sum = plain
		return h
	}
	m := hmac.New(sha256.New, key)
	m.Write(plain[:])
	h.Kind = HashKeyed
	copy(h.Sum[:], m.Sum(nil))
	return h
}
