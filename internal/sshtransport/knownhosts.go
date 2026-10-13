// SPDX-License-Identifier: AGPL-3.0-or-later

package sshtransport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // OpenSSH hashes known_hosts names with HMAC-SHA1
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// MaxKnownHostsSize bounds the known_hosts data ImportKnownHosts reads.
const MaxKnownHostsSize = 4 << 20

// KnownHostsMatch is the key ImportKnownHosts found for a host.
type KnownHostsMatch struct {
	Key ssh.PublicKey
	// Endpoints lists the endpoints that have an entry for Key.
	Endpoints []Endpoint
	// Ignored counts entries skipped as unusable for pinning: wildcard or
	// negated patterns, @cert-authority lines, keys CheckHostKey refuses.
	Ignored int
}

// ImportKnownHosts finds the key to pin for a host with the given endpoints
// in OpenSSH known_hosts data (plain or hashed names, "[host]:port" for
// non-default ports). Only exact names count; wildcard patterns are too
// broad to pin a single host from. @revoked keys are never chosen.
//
// If entries for the endpoints name more than one key, the preferred type
// wins (ed25519, ECDSA, RSA); two different keys of that type are a
// conflict and nothing is chosen.
func ImportKnownHosts(data []byte, endpoints []Endpoint) (KnownHostsMatch, error) {
	if len(data) > MaxKnownHostsSize {
		return KnownHostsMatch{}, fmt.Errorf("known_hosts larger than %d bytes", MaxKnownHostsSize)
	}
	if len(endpoints) == 0 || len(endpoints) > MaxEndpoints {
		return KnownHostsMatch{}, fmt.Errorf("need 1..%d endpoints", MaxEndpoints)
	}
	names := make([]string, len(endpoints))
	for i, ep := range endpoints {
		names[i] = knownhosts.Normalize(ep.Address())
	}

	type found struct {
		key ssh.PublicKey
		eps map[int]bool
	}
	var (
		keys    []*found
		revoked [][]byte
		ignored int
	)
	for n, line := range bytes.Split(data, []byte("\n")) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if errors.Is(err, io.EOF) {
			continue // blank line or comment
		}
		if err != nil {
			// Refuse rather than pin from a partly understood file: a line
			// skipped here could be the @revoked entry for the key we pick.
			return KnownHostsMatch{}, fmt.Errorf("known_hosts line %d: %w", n+1, err)
		}
		switch marker {
		case "revoked":
			revoked = append(revoked, key.Marshal())
			continue
		case "cert-authority":
			ignored++
			continue
		}
		matched := map[int]bool{}
		for _, h := range hosts {
			if strings.ContainsAny(h, "*?!") {
				ignored++
				continue
			}
			for i, n := range names {
				if hostMatches(h, n) {
					matched[i] = true
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		if CheckHostKey(key) != nil {
			ignored++
			continue
		}
		var f *found
		for _, k := range keys {
			if bytes.Equal(k.key.Marshal(), key.Marshal()) {
				f = k
			}
		}
		if f == nil {
			f = &found{key: key, eps: map[int]bool{}}
			keys = append(keys, f)
		}
		for i := range matched {
			f.eps[i] = true
		}
	}

	var usable []*found
	for _, k := range keys {
		isRevoked := false
		for _, r := range revoked {
			if bytes.Equal(r, k.key.Marshal()) {
				isRevoked = true
			}
		}
		if !isRevoked {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return KnownHostsMatch{Ignored: ignored}, errors.New("known_hosts has no usable entry for these endpoints")
	}
	for _, alg := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA} {
		var pick []*found
		for _, k := range usable {
			if k.key.Type() == alg {
				pick = append(pick, k)
			}
		}
		switch len(pick) {
		case 0:
			continue
		case 1:
			m := KnownHostsMatch{Key: pick[0].key, Ignored: ignored}
			for i, ep := range endpoints {
				if pick[0].eps[i] {
					m.Endpoints = append(m.Endpoints, ep)
				}
			}
			return m, nil
		default:
			fps := make([]string, len(pick))
			for i, k := range pick {
				fps[i] = Fingerprint(k.key)
			}
			return KnownHostsMatch{Ignored: ignored}, fmt.Errorf("known_hosts has conflicting %s keys for these endpoints: %s", alg, strings.Join(fps, ", "))
		}
	}
	return KnownHostsMatch{Ignored: ignored}, errors.New("known_hosts has no usable entry for these endpoints")
}

// hostMatches compares one known_hosts name (plain or "|1|salt|hash") with a
// normalized endpoint name.
func hostMatches(pattern, name string) bool {
	if strings.HasPrefix(pattern, "|1|") {
		parts := strings.Split(pattern[3:], "|")
		if len(parts) != 2 {
			return false
		}
		salt, err1 := base64.StdEncoding.DecodeString(parts[0])
		want, err2 := base64.StdEncoding.DecodeString(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		mac := hmac.New(sha1.New, salt)
		mac.Write([]byte(name))
		return hmac.Equal(mac.Sum(nil), want)
	}
	return strings.EqualFold(pattern, name)
}
