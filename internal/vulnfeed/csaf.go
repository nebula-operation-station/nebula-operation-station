// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Signed CSAF limits (ADR 0011 D4 `signed` mode).
const (
	// MaxCSAFMetadataBytes caps the provider-metadata.json download.
	MaxCSAFMetadataBytes = 1 << 20
	// MaxCSAFIndexBytes caps one ROLIE feed document.
	MaxCSAFIndexBytes = 64 << 20
	// MaxCSAFDocumentBytes caps one CSAF document.
	MaxCSAFDocumentBytes = 16 << 20
	// MaxCSAFSignatureBytes caps one armored detached signature (.asc).
	MaxCSAFSignatureBytes = 64 << 10
	// MaxCSAFPinnedKeyBytes caps one armored pinned public key block.
	MaxCSAFPinnedKeyBytes = 1 << 20
	// MaxCSAFPinnedKeys caps the pinned key blocks of one source.
	MaxCSAFPinnedKeys = 16
	// MinCSAFRSABits is the smallest accepted RSA key size.
	MinCSAFRSABits = 2048
	// MaxCSAFRolieFeeds caps the ROLIE feeds read from one provider.
	MaxCSAFRolieFeeds = 16
	// MaxCSAFDocuments caps the index entries of one provider sync.
	MaxCSAFDocuments = 50000
	// MaxCSAFRejectionsReported caps the rejection details of one sync;
	// further rejections are only counted.
	MaxCSAFRejectionsReported = 1000
	// MaxCSAFProducts caps the products of one document.
	MaxCSAFProducts = 20000
	// MaxCSAFVulnerabilities caps the vulnerabilities of one document.
	MaxCSAFVulnerabilities = 5000
	// MaxCSAFProductRefs caps the product IDs of one status list.
	MaxCSAFProductRefs = 20000
	// MaxCSAFBranchDepth caps the nesting of the product tree branches.
	MaxCSAFBranchDepth = 30
	// MaxCSAFTextBytes caps one text field (names, versions, ranges).
	MaxCSAFTextBytes = 1024
	// MaxCSAFURLBytes caps a document URL taken from an index.
	MaxCSAFURLBytes = 2048
	// CSAFFetchTimeout bounds each fetch of one document, signature or
	// hash file.
	CSAFFetchTimeout = 5 * time.Minute
)

// CSAF errors. Every per-document error rejects that document only; the
// previously accepted revision of the same tracking ID stays.
var (
	// ErrCSAFKeyring: the pinned key configuration is unusable.
	ErrCSAFKeyring = errors.New("vulnfeed: invalid pinned CSAF keyring")
	// ErrCSAFSignatureMissing: the document has no fetchable .asc.
	ErrCSAFSignatureMissing = errors.New("vulnfeed: CSAF signature missing")
	// ErrCSAFSignatureInvalid: the signature is unparseable, not made by a
	// pinned key, does not cover the bytes, or is otherwise unacceptable.
	ErrCSAFSignatureInvalid = errors.New("vulnfeed: CSAF signature invalid")
	// ErrCSAFKeyExpired: the signing key or the signature is expired or
	// revoked at verification time (also wraps ErrCSAFSignatureInvalid).
	ErrCSAFKeyExpired = errors.New("vulnfeed: CSAF signing key or signature expired or revoked")
	// ErrCSAFHashMissing: neither a .sha512 nor a .sha256 file exists.
	ErrCSAFHashMissing = errors.New("vulnfeed: CSAF hash file missing")
	// ErrCSAFOlderRevision: the document is not newer than the revision
	// already accepted for its tracking ID (lower version or date, or the
	// same revision with other content).
	ErrCSAFOlderRevision = errors.New("vulnfeed: CSAF revision not newer than accepted")
	// ErrCSAFMalformed: the metadata, index or document breaks the format
	// rules or limits.
	ErrCSAFMalformed = errors.New("vulnfeed: malformed CSAF data")
)

// CSAFVendor names a signed CSAF provider whose products are classified.
type CSAFVendor string

// CSAFVendor values.
const (
	CSAFVendorCisco    CSAFVendor = "cisco"
	CSAFVendorPaloAlto CSAFVendor = "paloalto"
)

// vendorBranchName is the product tree vendor branch name per vendor.
var vendorBranchName = map[CSAFVendor]string{
	CSAFVendorCisco:    "cisco",
	CSAFVendorPaloAlto: "palo alto networks",
}

// CSAFKeyring holds the pinned provider public keys of one source. Keys
// come only from configuration, fetched and checked out of band; keys
// announced by a provider's own metadata are never read.
type CSAFKeyring struct {
	entities openpgp.EntityList
}

// ParseCSAFKeyring parses armored public key blocks from configuration.
// It rejects an empty set, private key material, unparseable blocks and
// weak RSA keys.
func ParseCSAFKeyring(armored ...[]byte) (*CSAFKeyring, error) {
	if len(armored) == 0 || len(armored) > MaxCSAFPinnedKeys {
		return nil, fmt.Errorf("parse keyring: %d key blocks: %w", len(armored), ErrCSAFKeyring)
	}
	var all openpgp.EntityList
	for i, a := range armored {
		if len(a) == 0 || len(a) > MaxCSAFPinnedKeyBytes {
			return nil, fmt.Errorf("parse keyring: block %d size: %w", i, ErrCSAFKeyring)
		}
		ents, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(a))
		if err != nil || len(ents) == 0 {
			return nil, fmt.Errorf("parse keyring: block %d unreadable: %w", i, ErrCSAFKeyring)
		}
		for _, e := range ents {
			if err := checkPinnedEntity(e); err != nil {
				return nil, fmt.Errorf("parse keyring: block %d: %w", i, err)
			}
		}
		all = append(all, ents...)
	}
	return &CSAFKeyring{entities: all}, nil
}

// checkPinnedEntity rejects secret keys and weak public keys.
func checkPinnedEntity(e *openpgp.Entity) error {
	if e.PrimaryKey == nil {
		return fmt.Errorf("no primary key: %w", ErrCSAFKeyring)
	}
	if e.PrivateKey != nil {
		return fmt.Errorf("private key material in pinned keys: %w", ErrCSAFKeyring)
	}
	keys := []*packet.PublicKey{e.PrimaryKey}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil {
			return fmt.Errorf("private key material in pinned keys: %w", ErrCSAFKeyring)
		}
		keys = append(keys, sk.PublicKey)
	}
	for _, k := range keys {
		switch k.PubKeyAlgo {
		case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
			bits, err := k.BitLength()
			if err != nil || bits < MinCSAFRSABits {
				return fmt.Errorf("RSA key below %d bits: %w", MinCSAFRSABits, ErrCSAFKeyring)
			}
		case packet.PubKeyAlgoECDSA, packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519, packet.PubKeyAlgoEd448,
			packet.PubKeyAlgoECDH, packet.PubKeyAlgoX25519, packet.PubKeyAlgoX448, packet.PubKeyAlgoElGamal:
			// Signing algorithms are checked by the verifier; encryption
			// subkeys cannot sign (key flags).
		default:
			return fmt.Errorf("public key algorithm %d: %w", k.PubKeyAlgo, ErrCSAFKeyring)
		}
	}
	return nil
}

// Fingerprints returns the hex fingerprints of the pinned primary keys
// (public data, for logs and evidence).
func (k *CSAFKeyring) Fingerprints() []string {
	out := make([]string, 0, len(k.entities))
	for _, e := range k.entities {
		out = append(out, hex.EncodeToString(e.PrimaryKey.Fingerprint))
	}
	return out
}

// csafSignatureHashes are the accepted signature digest algorithms.
var csafSignatureHashes = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

// Verify checks an armored detached binary signature over doc against the
// pinned keys at time now. Any failure returns an error wrapping
// ErrCSAFSignatureInvalid; an expired or revoked key or signature also
// wraps ErrCSAFKeyExpired.
func (k *CSAFKeyring) Verify(doc, asc []byte, now time.Time) error {
	if k == nil || len(k.entities) == 0 {
		return fmt.Errorf("verify: no pinned keys: %w", ErrCSAFSignatureInvalid)
	}
	if len(asc) == 0 || len(asc) > MaxCSAFSignatureBytes {
		return fmt.Errorf("verify: signature size %d: %w", len(asc), ErrCSAFSignatureInvalid)
	}
	block, err := armor.Decode(bytes.NewReader(asc))
	if err != nil || block.Type != openpgp.SignatureType {
		return fmt.Errorf("verify: not an armored signature: %w", ErrCSAFSignatureInvalid)
	}
	body, err := io.ReadAll(io.LimitReader(block.Body, MaxCSAFSignatureBytes))
	if err != nil {
		return fmt.Errorf("verify: armor body: %w", ErrCSAFSignatureInvalid)
	}
	cfg := &packet.Config{Time: func() time.Time { return now }}
	sig, signer, err := openpgp.VerifyDetachedSignatureAndHash(k.entities, bytes.NewReader(doc), bytes.NewReader(body), csafSignatureHashes, cfg)
	switch {
	case errors.Is(err, pgperrors.ErrKeyExpired), errors.Is(err, pgperrors.ErrSignatureExpired), errors.Is(err, pgperrors.ErrKeyRevoked):
		return fmt.Errorf("verify: %w: %w", ErrCSAFKeyExpired, ErrCSAFSignatureInvalid)
	case err != nil:
		// The library's message can quote packet data; keep it out.
		return fmt.Errorf("verify: signature does not verify against the pinned keys: %w", ErrCSAFSignatureInvalid)
	case sig == nil || signer == nil:
		return fmt.Errorf("verify: no signer: %w", ErrCSAFSignatureInvalid)
	case sig.SigType != packet.SigTypeBinary:
		return fmt.Errorf("verify: signature type %d is not binary: %w", sig.SigType, ErrCSAFSignatureInvalid)
	case sig.CreationTime.After(now.Add(MaxFutureSkew)):
		return fmt.Errorf("verify: signature made in the future: %w", ErrCSAFSignatureInvalid)
	}
	return nil
}

// CSAFSource is one signed CSAF provider.
type CSAFSource struct {
	// Feed is the provider's signed feed: its URL is the provider's
	// provider-metadata.json. Its integrity mode must be signed.
	Feed Feed
	// Vendor selects the product classification.
	Vendor CSAFVendor
	// Keys are the pinned provider keys from configuration.
	Keys *CSAFKeyring
}

func (s CSAFSource) validate() error {
	if err := s.Feed.validate(); err != nil {
		return err
	}
	if s.Feed.Integrity != vulnfinding.IntegritySigned {
		return fmt.Errorf("csaf source %s: integrity mode must be signed: %w", s.Feed.Name, ErrInvalidFeed)
	}
	if _, ok := vendorBranchName[s.Vendor]; !ok {
		return fmt.Errorf("csaf source %s: vendor: %w", s.Feed.Name, ErrInvalidFeed)
	}
	if s.Keys == nil || len(s.Keys.entities) == 0 {
		return fmt.Errorf("csaf source %s: no pinned keys: %w", s.Feed.Name, ErrInvalidFeed)
	}
	return nil
}

// CSAFAccepted is the accepted revision of one tracking ID. It is also the
// per-document high-water mark: a later revision must not be lower.
type CSAFAccepted struct {
	TrackingID  string    `json:"tracking_id"`
	Version     string    `json:"version"`
	ReleaseDate time.Time `json:"current_release_date"`
	// URL the document was fetched from.
	URL string `json:"url"`
	// SHA256 of the signed document bytes (hex).
	SHA256 string `json:"sha256"`
	// IndexUpdated is the ROLIE entry's "updated" value when it was
	// fetched; an equal value later skips the refetch (an optimisation
	// only: a lying index can delay an update, never inject one).
	IndexUpdated string       `json:"index_updated,omitempty"`
	Advisory     CSAFAdvisory `json:"advisory"`
}

// CSAFState is the accepted state of one CSAF source, keyed by
// tracking ID. Entries are kept when they leave the index, so a document
// that returns with an older revision is still a rollback.
type CSAFState struct {
	Documents map[string]CSAFAccepted `json:"documents"`
}

// ContentDate is the newest current_release_date over the accepted
// documents (zero when there are none).
func (s CSAFState) ContentDate() time.Time {
	var d time.Time
	for _, a := range s.Documents {
		if a.ReleaseDate.After(d) {
			d = a.ReleaseDate
		}
	}
	return d
}

func (s CSAFState) clone() CSAFState {
	return CSAFState{Documents: maps.Clone(s.Documents)}
}

// CSAFRejection describes one rejected document.
type CSAFRejection struct {
	URL        string
	TrackingID string
	Err        error
}

// CSAFReport is the per-document outcome of one sync (run evidence).
type CSAFReport struct {
	Accepted  int
	Unchanged int
	// Rejected lists at most MaxCSAFRejectionsReported rejections;
	// RejectedTotal counts all of them.
	Rejected      []CSAFRejection
	RejectedTotal int
}

func (r *CSAFReport) reject(u, id string, err error) {
	r.RejectedTotal++
	// The URL comes from the untrusted index: keep only a valid one.
	if clean, cerr := csafURL(u); cerr == nil {
		u = clean
	} else {
		u = ""
	}
	if len(r.Rejected) < MaxCSAFRejectionsReported {
		r.Rejected = append(r.Rejected, CSAFRejection{URL: u, TrackingID: id, Err: err})
	}
}

// CSAFClient syncs signed CSAF providers through the allowlisted fetcher.
type CSAFClient struct {
	fetcher *Fetcher
	now     func() time.Time
	timeout time.Duration
}

// NewCSAFClient builds a CSAFClient; now is the verification clock.
func NewCSAFClient(f *Fetcher, now func() time.Time) (*CSAFClient, error) {
	if f == nil || now == nil {
		return nil, fmt.Errorf("new csaf client: fetcher and clock required: %w", ErrInvalidFeed)
	}
	return &CSAFClient{fetcher: f, now: now, timeout: CSAFFetchTimeout}, nil
}

// Sync reads the provider metadata and its WHITE/CLEAR ROLIE feeds,
// fetches each listed document with its .asc and .sha512 (or .sha256),
// verifies hash and signature against the pinned keys, and accepts it
// only if its revision is newer than the one accepted for its tracking ID.
//
// It returns the new state and the per-document report. A rejected
// document leaves the previous revision in place. If the metadata or an
// index cannot be read, or ctx ends, it returns prev unchanged with an
// error. prev is never modified.
func (c *CSAFClient) Sync(ctx context.Context, src CSAFSource, prev CSAFState) (CSAFState, CSAFReport, error) {
	var rep CSAFReport
	if err := src.validate(); err != nil {
		return prev, rep, err
	}
	feeds, err := c.rolieFeeds(ctx, src.Feed)
	if err != nil {
		return prev, rep, fmt.Errorf("csaf sync %s: %w", src.Feed.Name, err)
	}
	var entries []rolieEntry
	for _, fu := range feeds {
		es, err := c.rolieEntries(ctx, fu, MaxCSAFDocuments-len(entries))
		if err != nil {
			return prev, rep, fmt.Errorf("csaf sync %s: %w", src.Feed.Name, err)
		}
		entries = append(entries, es...)
	}

	next := prev.clone()
	if next.Documents == nil {
		next.Documents = map[string]CSAFAccepted{}
	}
	byURL := make(map[string]string, len(next.Documents))
	for id, a := range next.Documents {
		byURL[a.URL] = id
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return prev, rep, fmt.Errorf("csaf sync %s: %w", src.Feed.Name, err)
		}
		if seen[e.url] {
			continue
		}
		seen[e.url] = true
		if id, ok := byURL[e.url]; ok && e.updated != "" && next.Documents[id].IndexUpdated == e.updated {
			rep.Unchanged++
			continue
		}
		acc, err := c.fetchVerified(ctx, src, e.url)
		if err != nil {
			if ctx.Err() != nil {
				return prev, rep, fmt.Errorf("csaf sync %s: %w", src.Feed.Name, ctx.Err())
			}
			rep.reject(e.url, "", err)
			continue
		}
		acc.IndexUpdated = e.updated
		old, ok := next.Documents[acc.TrackingID]
		if ok {
			newer, err := revisionNewer(old, acc)
			if err != nil {
				rep.reject(e.url, acc.TrackingID, err)
				continue
			}
			if !newer {
				// Identical revision: keep it, remember the index value.
				old.IndexUpdated = e.updated
				old.URL = acc.URL
				next.Documents[acc.TrackingID] = old
				rep.Unchanged++
				continue
			}
		}
		next.Documents[acc.TrackingID] = acc
		byURL[acc.URL] = acc.TrackingID
		rep.Accepted++
	}
	return next, rep, nil
}

// revisionNewer reports whether cand replaces old: false for the identical
// revision, an ErrCSAFOlderRevision error when cand is lower in version
// or date, or the same revision with other bytes.
func revisionNewer(old, cand CSAFAccepted) (bool, error) {
	cmp, err := compareCSAFVersion(cand.Version, old.Version)
	if err != nil {
		return false, fmt.Errorf("tracking %s: %w", cand.TrackingID, err)
	}
	switch {
	case cmp < 0:
		return false, fmt.Errorf("tracking %s: version %s below accepted %s: %w", cand.TrackingID, cand.Version, old.Version, ErrCSAFOlderRevision)
	case cand.ReleaseDate.Before(old.ReleaseDate):
		return false, fmt.Errorf("tracking %s: release date below accepted: %w", cand.TrackingID, ErrCSAFOlderRevision)
	case cmp == 0 && cand.ReleaseDate.Equal(old.ReleaseDate):
		if cand.SHA256 != old.SHA256 {
			return false, fmt.Errorf("tracking %s: same revision with other content: %w", cand.TrackingID, ErrCSAFOlderRevision)
		}
		return false, nil
	}
	return true, nil
}

// fetchBounded fetches u into memory under the per-file timeout.
func (c *CSAFClient) fetchBounded(ctx context.Context, u string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var buf bytes.Buffer
	if _, err := c.fetcher.Fetch(ctx, u, limit, Validators{}, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// providerMetadata is the part of provider-metadata.json that is read.
// public_openpgp_keys is deliberately absent: keys come from config only.
type providerMetadata struct {
	Distributions []struct {
		Rolie *struct {
			Feeds []struct {
				TLPLabel string `json:"tlp_label"`
				URL      string `json:"url"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

// rolieFeeds returns the WHITE/CLEAR ROLIE feed URLs of the provider.
func (c *CSAFClient) rolieFeeds(ctx context.Context, feed Feed) ([]string, error) {
	b, err := c.fetchBounded(ctx, feed.URL, MaxCSAFMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("provider metadata: %w", err)
	}
	var m providerMetadata
	if err := decodeCSAFJSON(b, &m); err != nil {
		return nil, fmt.Errorf("provider metadata: %w", err)
	}
	var out []string
	for _, d := range m.Distributions {
		if d.Rolie == nil {
			continue
		}
		for _, f := range d.Rolie.Feeds {
			if l := strings.ToUpper(f.TLPLabel); l != "WHITE" && l != "CLEAR" {
				continue
			}
			u, err := csafURL(f.URL)
			if err != nil {
				return nil, fmt.Errorf("provider metadata: feed URL: %w", err)
			}
			if !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
	}
	if len(out) == 0 || len(out) > MaxCSAFRolieFeeds {
		return nil, fmt.Errorf("provider metadata: %d public ROLIE feeds: %w", len(out), ErrCSAFMalformed)
	}
	return out, nil
}

// rolieEntry is one index entry: the document URL and the index's
// "updated" value (untrusted, used only to skip unchanged refetches).
type rolieEntry struct {
	url     string
	updated string
}

type rolieFeedJSON struct {
	Feed struct {
		Entry []struct {
			Updated string `json:"updated"`
			Link    []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"link"`
			Content struct {
				Src string `json:"src"`
			} `json:"content"`
		} `json:"entry"`
	} `json:"feed"`
}

// rolieEntries reads one ROLIE feed, at most room entries.
func (c *CSAFClient) rolieEntries(ctx context.Context, feedURL string, room int) ([]rolieEntry, error) {
	b, err := c.fetchBounded(ctx, feedURL, MaxCSAFIndexBytes)
	if err != nil {
		return nil, fmt.Errorf("rolie feed: %w", err)
	}
	var f rolieFeedJSON
	if err := decodeCSAFJSON(b, &f); err != nil {
		return nil, fmt.Errorf("rolie feed: %w", err)
	}
	if len(f.Feed.Entry) > room {
		return nil, fmt.Errorf("rolie feed: more than %d entries: %w", MaxCSAFDocuments, ErrCSAFMalformed)
	}
	out := make([]rolieEntry, 0, len(f.Feed.Entry))
	for _, e := range f.Feed.Entry {
		raw := e.Content.Src
		if raw == "" {
			for _, l := range e.Link {
				if l.Rel == "self" {
					raw = l.Href
					break
				}
			}
		}
		updated := e.Updated
		if !printableASCII(updated) {
			updated = ""
		}
		// A bad URL is kept so the document is reported as rejected.
		out = append(out, rolieEntry{url: raw, updated: updated})
	}
	return out, nil
}

// csafURL checks a URL taken from metadata or an index: https, no
// credentials, query or fragment, bounded. The fetcher additionally
// enforces the origin allowlist.
func csafURL(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > MaxCSAFURLBytes {
		return "", fmt.Errorf("URL length: %w", ErrCSAFMalformed)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("URL must be plain https: %w", ErrCSAFMalformed)
	}
	return u.String(), nil
}

// fetchVerified fetches one document with its hash and signature, checks
// both, and parses it. The document is accepted only if all pass.
func (c *CSAFClient) fetchVerified(ctx context.Context, src CSAFSource, rawURL string) (CSAFAccepted, error) {
	docURL, err := csafURL(rawURL)
	if err != nil {
		return CSAFAccepted{}, fmt.Errorf("document URL: %w", err)
	}
	name := path.Base(mustPath(docURL))
	doc, err := c.fetchBounded(ctx, docURL, MaxCSAFDocumentBytes)
	if err != nil {
		return CSAFAccepted{}, fmt.Errorf("document: %w", err)
	}
	if err := c.verifyHash(ctx, docURL, name, doc); err != nil {
		return CSAFAccepted{}, err
	}
	asc, err := c.fetchBounded(ctx, docURL+".asc", MaxCSAFSignatureBytes)
	if err != nil {
		return CSAFAccepted{}, fmt.Errorf("signature: %w: %w", ErrCSAFSignatureMissing, err)
	}
	now := c.now()
	if err := src.Keys.Verify(doc, asc, now); err != nil {
		return CSAFAccepted{}, err
	}
	// Only bytes that passed the signature check are parsed.
	adv, err := ParseCSAFAdvisory(doc, src.Vendor)
	if err != nil {
		return CSAFAccepted{}, err
	}
	if csafFileName(adv.TrackingID) != name {
		return CSAFAccepted{}, fmt.Errorf("document file name does not match tracking ID: %w", ErrCSAFMalformed)
	}
	if adv.ReleaseDate.After(now.Add(MaxFutureSkew)) {
		return CSAFAccepted{}, fmt.Errorf("tracking %s: current_release_date: %w", adv.TrackingID, ErrFutureContentDate)
	}
	sum := sha256.Sum256(doc)
	return CSAFAccepted{
		TrackingID:  adv.TrackingID,
		Version:     adv.Version,
		ReleaseDate: adv.ReleaseDate,
		URL:         docURL,
		SHA256:      hex.EncodeToString(sum[:]),
		Advisory:    adv,
	}, nil
}

// mustPath returns the path of an already validated URL.
func mustPath(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Path
}

// verifyHash fetches <doc>.sha512, or <doc>.sha256 if the first is absent
// (HTTP status error), and compares it with doc. Any other failure or the
// absence of both rejects the document.
func (c *CSAFClient) verifyHash(ctx context.Context, docURL, name string, doc []byte) error {
	for _, alg := range []ChecksumAlg{ChecksumSHA512, ChecksumSHA256} {
		b, err := c.fetchBounded(ctx, docURL+"."+string(alg), MaxChecksumBytes)
		if errors.Is(err, ErrHTTPStatus) {
			continue
		}
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}
		want, err := parseChecksum(b, alg, name)
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}
		var got []byte
		if alg == ChecksumSHA512 {
			s := sha512.Sum512(doc)
			got = s[:]
		} else {
			s := sha256.Sum256(doc)
			got = s[:]
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fmt.Errorf("document %s: %w", alg, ErrChecksumMismatch)
		}
		return nil
	}
	return ErrCSAFHashMissing
}

// csafFileNameRe matches the runs that CSAF 2.0 (section 5.1) replaces by
// "_" when deriving a document's file name from its tracking ID.
var csafFileNameRe = regexp.MustCompile(`[^+\-a-z0-9]+`)

// csafFileName is the CSAF 2.0 file name of a tracking ID.
func csafFileName(id string) string {
	return csafFileNameRe.ReplaceAllString(strings.ToLower(id), "_") + ".json"
}

// decodeCSAFJSON decodes untrusted JSON after a UTF-8 check (the decoder
// would otherwise silently replace invalid bytes).
func decodeCSAFJSON(b []byte, v any) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("invalid UTF-8: %w", ErrCSAFMalformed)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("JSON: %w", ErrCSAFMalformed)
	}
	return nil
}

// Tracking version formats (CSAF 2.0 section 3.1.11): integer or semver.
var (
	csafIntVersionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	csafSemverRe     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$`)
)

// compareCSAFVersion compares two tracking versions of the same scheme.
// Mixed or malformed versions are an ErrCSAFMalformed error (the document
// is rejected rather than guessed).
func compareCSAFVersion(a, b string) (int, error) {
	if len(a) > MaxCSAFTextBytes || len(b) > MaxCSAFTextBytes {
		return 0, fmt.Errorf("tracking version length: %w", ErrCSAFMalformed)
	}
	if csafIntVersionRe.MatchString(a) && csafIntVersionRe.MatchString(b) {
		return compareNumeric(a, b), nil
	}
	ma, mb := csafSemverRe.FindStringSubmatch(a), csafSemverRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, fmt.Errorf("tracking versions %q and %q: %w", a, b, ErrCSAFMalformed)
	}
	for i := 1; i <= 3; i++ {
		if c := compareNumeric(ma[i], mb[i]); c != 0 {
			return c, nil
		}
	}
	return comparePrerelease(ma[4], mb[4]), nil
}

// compareNumeric compares decimal digit strings without leading zeros.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// comparePrerelease applies semver precedence to pre-release strings
// ("" ranks above any pre-release).
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := csafIntVersionRe.MatchString(pa[i]), csafIntVersionRe.MatchString(pb[i])
		var c int
		switch {
		case na && nb:
			c = compareNumeric(pa[i], pb[i])
		case na:
			c = -1
		case nb:
			c = 1
		default:
			c = strings.Compare(pa[i], pb[i])
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// CSAFProduct is one product of the product tree with the attributes of
// the branches above it.
type CSAFProduct struct {
	ProductID string `json:"product_id"`
	// Name is the full product name.
	Name string `json:"name"`
	// Vendor is the vendor branch name.
	Vendor string `json:"vendor,omitempty"`
	// Product is the product_name or, without one, the product_family
	// branch name.
	Product string `json:"product,omitempty"`
	// Version is an exact product_version.
	Version string `json:"version,omitempty"`
	// VersionRange is a product_version_range as published (for example
	// a "vers:" string); it is not interpreted here.
	VersionRange string `json:"version_range,omitempty"`
	// Train is the release train derived from Version or the lower bound
	// of VersionRange ("15.2M" for IOS 15.2(4)M3, "17.3" for IOS XE
	// 17.3.1, "10.2" for PAN-OS 10.2.9); empty when not derivable.
	Train string `json:"train,omitempty"`
	// Ecosystem is the D2 ecosystem (vendor:cisco:<os>,
	// vendor:paloalto:panos); empty when the product is not classified.
	Ecosystem string `json:"ecosystem,omitempty"`
}

// CSAFVulnerability is one vulnerability with its product status lists.
type CSAFVulnerability struct {
	CVE string `json:"cve,omitempty"`
	// Affected: known_affected, first_affected and last_affected IDs.
	Affected []string `json:"affected,omitempty"`
	// Fixed: fixed and first_fixed IDs.
	Fixed []string `json:"fixed,omitempty"`
	// NotAffected: known_not_affected IDs.
	NotAffected []string `json:"not_affected,omitempty"`
}

// CSAFAdvisory is the parsed, validated content of one signed document.
type CSAFAdvisory struct {
	TrackingID      string              `json:"tracking_id"`
	Version         string              `json:"version"`
	ReleaseDate     time.Time           `json:"current_release_date"`
	Title           string              `json:"title"`
	Products        []CSAFProduct       `json:"products"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// FixedProducts returns the products of v's fixed list known to the
// product tree, in list order.
func (a CSAFAdvisory) FixedProducts(v CSAFVulnerability) []CSAFProduct {
	var out []CSAFProduct
	for _, id := range v.Fixed {
		i, ok := slices.BinarySearchFunc(a.Products, id, func(p CSAFProduct, id string) int { return strings.Compare(p.ProductID, id) })
		if ok {
			out = append(out, a.Products[i])
		}
	}
	return out
}

type csafFullProductName struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type csafBranch struct {
	Category string               `json:"category"`
	Name     string               `json:"name"`
	Product  *csafFullProductName `json:"product"`
	Branches []csafBranch         `json:"branches"`
}

type csafDocumentJSON struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Title       string `json:"title"`
		Tracking    struct {
			ID                 string `json:"id"`
			Version            string `json:"version"`
			Status             string `json:"status"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches         []csafBranch          `json:"branches"`
		FullProductNames []csafFullProductName `json:"full_product_names"`
		Relationships    []struct {
			ProductReference string              `json:"product_reference"`
			FullProductName  csafFullProductName `json:"full_product_name"`
		} `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE           string `json:"cve"`
		ProductStatus struct {
			KnownAffected    []string `json:"known_affected"`
			FirstAffected    []string `json:"first_affected"`
			LastAffected     []string `json:"last_affected"`
			Fixed            []string `json:"fixed"`
			FirstFixed       []string `json:"first_fixed"`
			KnownNotAffected []string `json:"known_not_affected"`
		} `json:"product_status"`
	} `json:"vulnerabilities"`
}

var (
	csafTrackingIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$`)
	csafCVERe        = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
)

// ParseCSAFAdvisory parses and validates a CSAF 2.0 document (already
// signature-checked by the caller) and flattens its product tree. Every
// rule or limit violation is an ErrCSAFMalformed error.
func ParseCSAFAdvisory(doc []byte, vendor CSAFVendor) (CSAFAdvisory, error) {
	if len(doc) > MaxCSAFDocumentBytes {
		return CSAFAdvisory{}, fmt.Errorf("document size: %w", ErrCSAFMalformed)
	}
	var d csafDocumentJSON
	if err := decodeCSAFJSON(doc, &d); err != nil {
		return CSAFAdvisory{}, fmt.Errorf("document: %w", err)
	}
	tr := d.Document.Tracking
	if d.Document.CSAFVersion != "2.0" {
		return CSAFAdvisory{}, fmt.Errorf("csaf_version: %w", ErrCSAFMalformed)
	}
	if !csafTrackingIDRe.MatchString(tr.ID) {
		return CSAFAdvisory{}, fmt.Errorf("tracking id: %w", ErrCSAFMalformed)
	}
	if tr.Status != "final" && tr.Status != "interim" {
		return CSAFAdvisory{}, fmt.Errorf("tracking %s: status %q: %w", tr.ID, safeText(tr.Status), ErrCSAFMalformed)
	}
	if _, err := compareCSAFVersion(tr.Version, tr.Version); err != nil {
		return CSAFAdvisory{}, fmt.Errorf("tracking %s: version: %w", tr.ID, err)
	}
	rd, err := time.Parse(time.RFC3339Nano, tr.CurrentReleaseDate)
	if err != nil || rd.IsZero() {
		return CSAFAdvisory{}, fmt.Errorf("tracking %s: current_release_date: %w", tr.ID, ErrCSAFMalformed)
	}
	if err := checkCSAFText(d.Document.Title); err != nil {
		return CSAFAdvisory{}, fmt.Errorf("tracking %s: title: %w", tr.ID, err)
	}
	adv := CSAFAdvisory{TrackingID: tr.ID, Version: tr.Version, ReleaseDate: rd.UTC(), Title: d.Document.Title}

	w := treeWalker{vendor: vendor, byID: map[string]CSAFProduct{}}
	for _, b := range d.ProductTree.Branches {
		if err := w.walk(b, CSAFProduct{}, 1); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: product tree: %w", tr.ID, err)
		}
	}
	for _, fp := range d.ProductTree.FullProductNames {
		if err := w.add(fp, CSAFProduct{}); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: product tree: %w", tr.ID, err)
		}
	}
	for _, r := range d.ProductTree.Relationships {
		// A combined product inherits the attributes of the product it
		// refers to (for example a firmware version on a model).
		ctx := w.byID[r.ProductReference]
		ctx.ProductID, ctx.Name = "", ""
		if err := w.add(r.FullProductName, ctx); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: relationships: %w", tr.ID, err)
		}
	}
	adv.Products = slices.SortedFunc(maps.Values(w.byID), func(a, b CSAFProduct) int { return strings.Compare(a.ProductID, b.ProductID) })

	if len(d.Vulnerabilities) > MaxCSAFVulnerabilities {
		return CSAFAdvisory{}, fmt.Errorf("tracking %s: more than %d vulnerabilities: %w", tr.ID, MaxCSAFVulnerabilities, ErrCSAFMalformed)
	}
	for _, v := range d.Vulnerabilities {
		if v.CVE != "" && !csafCVERe.MatchString(v.CVE) {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: cve: %w", tr.ID, ErrCSAFMalformed)
		}
		ps := v.ProductStatus
		cv := CSAFVulnerability{CVE: v.CVE}
		var err error
		if cv.Affected, err = productRefs(ps.KnownAffected, ps.FirstAffected, ps.LastAffected); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: affected: %w", tr.ID, err)
		}
		if cv.Fixed, err = productRefs(ps.Fixed, ps.FirstFixed); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: fixed: %w", tr.ID, err)
		}
		if cv.NotAffected, err = productRefs(ps.KnownNotAffected); err != nil {
			return CSAFAdvisory{}, fmt.Errorf("tracking %s: not affected: %w", tr.ID, err)
		}
		adv.Vulnerabilities = append(adv.Vulnerabilities, cv)
	}
	return adv, nil
}

// productRefs joins status lists, validating and de-duplicating IDs in
// first-seen order.
func productRefs(lists ...[]string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, id := range l {
			if err := checkCSAFText(id); err != nil || id == "" {
				return nil, fmt.Errorf("product id: %w", ErrCSAFMalformed)
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
			if len(out) > MaxCSAFProductRefs {
				return nil, fmt.Errorf("more than %d product ids: %w", MaxCSAFProductRefs, ErrCSAFMalformed)
			}
		}
	}
	return out, nil
}

// treeWalker flattens product tree branches.
type treeWalker struct {
	vendor CSAFVendor
	byID   map[string]CSAFProduct
	nodes  int
}

func (w *treeWalker) walk(b csafBranch, ctx CSAFProduct, depth int) error {
	if depth > MaxCSAFBranchDepth {
		return fmt.Errorf("branches deeper than %d: %w", MaxCSAFBranchDepth, ErrCSAFMalformed)
	}
	w.nodes++
	if w.nodes > MaxCSAFProducts*4 {
		return fmt.Errorf("too many branches: %w", ErrCSAFMalformed)
	}
	if err := checkCSAFText(b.Name); err != nil {
		return fmt.Errorf("branch name: %w", err)
	}
	switch b.Category {
	case "vendor":
		ctx.Vendor = b.Name
	case "product_family":
		if ctx.Product == "" {
			ctx.Product = b.Name
		}
	case "product_name":
		ctx.Product = b.Name
	case "product_version":
		ctx.Version, ctx.VersionRange = b.Name, ""
	case "product_version_range":
		ctx.VersionRange, ctx.Version = b.Name, ""
	}
	if b.Product != nil {
		if err := w.add(*b.Product, ctx); err != nil {
			return err
		}
	}
	for _, c := range b.Branches {
		if err := w.walk(c, ctx, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// add records one product with the branch context ctx.
func (w *treeWalker) add(fp csafFullProductName, ctx CSAFProduct) error {
	if fp.ProductID == "" {
		return fmt.Errorf("empty product id: %w", ErrCSAFMalformed)
	}
	if err := checkCSAFText(fp.ProductID); err != nil {
		return fmt.Errorf("product id: %w", err)
	}
	if err := checkCSAFText(fp.Name); err != nil {
		return fmt.Errorf("product name: %w", err)
	}
	if _, dup := w.byID[fp.ProductID]; dup {
		return fmt.Errorf("duplicate product id: %w", ErrCSAFMalformed)
	}
	if len(w.byID) >= MaxCSAFProducts {
		return fmt.Errorf("more than %d products: %w", MaxCSAFProducts, ErrCSAFMalformed)
	}
	p := ctx
	p.ProductID, p.Name = fp.ProductID, fp.Name
	p.Ecosystem = classifyCSAFProduct(w.vendor, p)
	p.Train = csafTrain(p)
	w.byID[p.ProductID] = p
	return nil
}

// classifyCSAFProduct maps a product of the source's own vendor to its
// D2 ecosystem; anything else stays unclassified.
func classifyCSAFProduct(vendor CSAFVendor, p CSAFProduct) string {
	if !strings.EqualFold(strings.TrimSpace(p.Vendor), vendorBranchName[vendor]) {
		return ""
	}
	name := " " + strings.ToLower(p.Product) + " "
	switch vendor {
	case CSAFVendorPaloAlto:
		if strings.Contains(name, "pan-os") {
			return "vendor:paloalto:panos"
		}
	case CSAFVendorCisco:
		switch {
		case strings.Contains(name, " ios xe"):
			return "vendor:cisco:ios-xe"
		case strings.Contains(name, " ios xr"):
			return "vendor:cisco:ios-xr"
		case strings.Contains(name, " nx-os"):
			return "vendor:cisco:nx-os"
		case strings.Contains(name, " business ") && strings.Contains(name, "switch"),
			cbsModelRe.MatchString(name):
			return "vendor:cisco:cbs"
		case strings.Contains(name, " ios "):
			return "vendor:cisco:ios"
		}
	}
	return ""
}

var (
	cbsModelRe = regexp.MustCompile(` cbs[0-9]{3}`)
	// iosTrainRe: classic IOS "15.2(4)M3" → "15.2" + "M".
	iosTrainRe = regexp.MustCompile(`^([0-9]+\.[0-9]+)\([0-9]+[a-z]?\)([A-Z]+)`)
	// dottedTrainRe: "17.3.1", "10.2.9", "11.1.3-h4", "3.2.0.84" → major.minor.
	dottedTrainRe = regexp.MustCompile(`^([0-9]+\.[0-9]+)\.[0-9]`)
	// rangeLowerRe: the first ">=" bound of a version range.
	rangeLowerRe = regexp.MustCompile(`>=\s*([0-9]+\.[0-9]+)\.[0-9]`)
)

// csafTrain derives the release train of a classified product.
func csafTrain(p CSAFProduct) string {
	if p.Ecosystem == "" {
		return ""
	}
	if p.Version != "" {
		if m := iosTrainRe.FindStringSubmatch(p.Version); m != nil && p.Ecosystem == "vendor:cisco:ios" {
			return m[1] + m[2]
		}
		if m := dottedTrainRe.FindStringSubmatch(p.Version); m != nil {
			return m[1]
		}
		return ""
	}
	if m := rangeLowerRe.FindStringSubmatch(p.VersionRange); m != nil {
		return m[1]
	}
	return ""
}

// checkCSAFText bounds a text field and rejects control characters.
func checkCSAFText(s string) error {
	if len(s) > MaxCSAFTextBytes {
		return fmt.Errorf("text longer than %d bytes: %w", MaxCSAFTextBytes, ErrCSAFMalformed)
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return fmt.Errorf("control or invalid character in text: %w", ErrCSAFMalformed)
		}
	}
	return nil
}

// safeText returns s for an error message if it is short printable ASCII.
func safeText(s string) string {
	if len(s) > 32 || !printableASCII(s) {
		return "?"
	}
	return s
}
