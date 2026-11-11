// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

// Checksum companion limits.
const (
	// MaxChecksumBytes caps a .sha256/.sha512 companion file.
	MaxChecksumBytes = 1024
	// ChecksumFetchTimeout bounds the companion fetch. It is far shorter
	// than the whole-feed timeout, so a slow-drip origin cannot stall a
	// sync for DefaultFetchTimeout on a 1 KiB file.
	ChecksumFetchTimeout = 60 * time.Second
)

// Checksum errors.
var (
	// ErrChecksumMismatch: the companion hash does not match the file.
	ErrChecksumMismatch = errors.New("vulnfeed: checksum mismatch")
	// ErrChecksumMalformed: the companion is not "<hex> [*]<name>".
	ErrChecksumMalformed = errors.New("vulnfeed: malformed checksum companion")
)

// checksumURL is the companion URL: the feed URL's path plus ".<alg>",
// on the same origin, without query or fragment.
func checksumURL(feedURL string, alg ChecksumAlg) (string, string, error) {
	u, err := url.Parse(feedURL)
	if err != nil {
		return "", "", fmt.Errorf("checksum URL: %w", ErrInvalidFeed)
	}
	c := *u
	c.RawQuery, c.Fragment, c.RawPath = "", "", ""
	c.Path = u.Path + "." + string(alg)
	return c.String(), path.Base(u.Path), nil
}

// parseChecksum parses a companion in sha256sum/sha512sum format: one
// hex digest of the algorithm's length, optionally followed by the file
// name (an optional leading '*' marks binary mode), which must be want.
func parseChecksum(b []byte, alg ChecksumAlg, want string) ([]byte, error) {
	for _, c := range b {
		if c > 0x7e || (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
			return nil, ErrChecksumMalformed
		}
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 || len(fields) > 2 {
		return nil, ErrChecksumMalformed
	}
	size := 32
	if alg == ChecksumSHA512 {
		size = 64
	}
	sum, err := hex.DecodeString(fields[0])
	if err != nil || len(sum) != size {
		return nil, ErrChecksumMalformed
	}
	if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") != want {
		return nil, ErrChecksumMalformed
	}
	return sum, nil
}

// verifyChecksum fetches feed's companion and compares it with the staged
// file's digest. Any failure rejects the file.
//
// The companion comes from the same origin as the feed, so this proves
// integrity (no truncation or corruption in transfer), not authenticity:
// a compromised origin can serve a matching pair. IntegrityChecksum must
// not be read as "signed"; only IntegritySigned feeds are authenticated.
func (s *Syncer) verifyChecksum(ctx context.Context, feed Feed, st *Staged) error {
	cu, name, err := checksumURL(feed.URL, feed.Checksum)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.checksumTimeout)
	defer cancel()
	var buf bytes.Buffer
	if _, err := s.fetcher.Fetch(ctx, cu, MaxChecksumBytes, Validators{}, &buf); err != nil {
		return fmt.Errorf("checksum companion: %w", err)
	}
	want, err := parseChecksum(buf.Bytes(), feed.Checksum, name)
	if err != nil {
		return fmt.Errorf("checksum companion of %s: %w", feed.Name, err)
	}
	gotHex, ok := st.digest(feed.Checksum)
	if !ok {
		return fmt.Errorf("checksum of %s: %w", feed.Name, ErrInvalidFeed)
	}
	got, _ := hex.DecodeString(gotHex)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("checksum of %s: %w", feed.Name, ErrChecksumMismatch)
	}
	return nil
}
