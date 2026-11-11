// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
)

// Executor-local enrollment configuration (ADR 0013 D5, D6; EN-06). These
// values come only from executor flags read at start. Nothing here is
// settable or readable over RPC: the configuration stays in main and is
// handed to later enrollment code as plain values, never to the server.

// Limits of the enrollment configuration.
const (
	// enrollSourcesMax is the most enrollment source addresses accepted.
	enrollSourcesMax = 32
	// enrollSourceMaxLen bounds one source entry in bytes; the longest
	// valid entry, a full IPv6 address with /128, has 43 bytes.
	enrollSourceMaxLen = 64
	// netBirdMgmtURLMaxLen is NetBirdMgmtURLMaxLen of spec 03
	// "Render-input format".
	netBirdMgmtURLMaxLen = 256
	// netBirdCAFileMaxBytes bounds the pinned CA file.
	netBirdCAFileMaxBytes = 1 << 20
	// managedGroupMaxLen bounds the NetBird managed group name in bytes.
	managedGroupMaxLen = 64
	// dnsNameMaxLen and dnsLabelMaxLen are the DNS limits of RFC 1035.
	dnsNameMaxLen  = 253
	dnsLabelMaxLen = 63
)

// defaultManagedGroup is the NetBird group enrolled hosts join (ADR 0013
// Q3).
const defaultManagedGroup = "nos-managed"

// errInvalidEnrollConfig wraps every refusal of the enrollment
// configuration; the executor does not start with it.
var errInvalidEnrollConfig = errors.New("invalid enrollment configuration")

// managedGroupPattern is the accepted managed group name: ASCII letters,
// digits, '.', '_' and '-', starting with a letter or digit.
var managedGroupPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// reservedGroups are NetBird group names the managed group must not be:
// NetBird's built-in group of every peer and the NOS machine's own group
// (ADR 0013 D6). Compared case-insensitively.
var reservedGroups = []string{"All", "nos"}

// enrollConfig is the validated executor-local enrollment configuration.
type enrollConfig struct {
	// Sources are the enrollment source addresses (the key's from=
	// option), each one IP address or CIDR range in canonical form.
	Sources []string
	// NetBird is the NetBird management API access.
	NetBird netBirdConfig
	// ManagedGroup is the NetBird group enrolled hosts join.
	ManagedGroup string
}

// netBirdConfig is the NetBird management URL and its TLS trust.
type netBirdConfig struct {
	// ManagementURL is empty when NetBird is not configured.
	ManagementURL string
	// CAFile is the pinned CA (or leaf) file; empty means the system
	// trust store.
	CAFile string
	// RootCAs holds the certificates of CAFile; nil means the system
	// trust store.
	RootCAs *x509.CertPool
}

// Enabled reports whether a NetBird management URL is configured.
func (c netBirdConfig) Enabled() bool { return c.ManagementURL != "" }

// TrustName names the TLS trust: "system" or "ca-file".
func (c netBirdConfig) TrustName() string {
	if c.RootCAs != nil {
		return "ca-file"
	}
	return "system"
}

// enrollFlags holds the parsed enrollment flags.
type enrollFlags struct {
	sources      stringList
	mgmtURL      *string
	caFile       *string
	managedGroup *string
}

// registerEnrollFlags registers the enrollment flags on fs.
func registerEnrollFlags(fs *flag.FlagSet) *enrollFlags {
	f := &enrollFlags{}
	fs.Var(&f.sources, "enroll-source", "enrollment source address: IP address or CIDR range Nebula connects to enrolled hosts from (comma-separated, repeatable; goes into the key's from= option)")
	f.mgmtURL = fs.String("netbird-management-url", "", "NetBird management API URL (https only; empty disables the NetBird join)")
	f.caFile = fs.String("netbird-ca-file", "", "absolute path of a PEM file with the pinned CA or leaf certificate of the NetBird management API (empty: system trust store)")
	f.managedGroup = fs.String("netbird-managed-group", defaultManagedGroup, "NetBird group enrolled hosts join")
	return f
}

// load validates the parsed flags. Every refusal wraps
// errInvalidEnrollConfig and names the flag.
func (f *enrollFlags) load() (enrollConfig, error) {
	var cfg enrollConfig
	sources, err := parseEnrollSources(f.sources)
	if err != nil {
		return enrollConfig{}, fmt.Errorf("%w: -enroll-source: %w", errInvalidEnrollConfig, err)
	}
	cfg.Sources = sources
	if *f.mgmtURL != "" {
		if err := validNetBirdMgmtURL(*f.mgmtURL); err != nil {
			return enrollConfig{}, fmt.Errorf("%w: -netbird-management-url: %w", errInvalidEnrollConfig, err)
		}
		cfg.NetBird.ManagementURL = *f.mgmtURL
	}
	if *f.caFile != "" {
		if !cfg.NetBird.Enabled() {
			return enrollConfig{}, fmt.Errorf("%w: -netbird-ca-file is set without -netbird-management-url", errInvalidEnrollConfig)
		}
		pool, err := loadNetBirdCAFile(*f.caFile)
		if err != nil {
			return enrollConfig{}, fmt.Errorf("%w: -netbird-ca-file: %w", errInvalidEnrollConfig, err)
		}
		cfg.NetBird.CAFile = *f.caFile
		cfg.NetBird.RootCAs = pool
	}
	if err := validManagedGroup(*f.managedGroup); err != nil {
		return enrollConfig{}, fmt.Errorf("%w: -netbird-managed-group: %w", errInvalidEnrollConfig, err)
	}
	cfg.ManagedGroup = *f.managedGroup
	return cfg, nil
}

// parseEnrollSources splits the flag values at commas and validates each
// entry as `nebula host enroll-script --from` does (enrollscript.
// ValidAddress), then parses it with net/netip, refuses zone IDs,
// IPv4-mapped IPv6 addresses, CIDR ranges with host bits set and
// duplicates, and returns the canonical forms (spec 03 "Render-input
// format").
func parseEnrollSources(values []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, a := range strings.Split(v, ",") {
			a = strings.TrimSpace(a)
			canon, err := canonicalSource(a)
			if err != nil {
				return nil, err
			}
			if seen[canon] {
				return nil, fmt.Errorf("%q is listed twice", a)
			}
			seen[canon] = true
			out = append(out, canon)
			if len(out) > enrollSourcesMax {
				return nil, fmt.Errorf("more than %d addresses", enrollSourcesMax)
			}
		}
	}
	return out, nil
}

func canonicalSource(a string) (string, error) {
	if a == "" {
		return "", errors.New("empty address")
	}
	if len(a) > enrollSourceMaxLen {
		return "", fmt.Errorf("address longer than %d bytes", enrollSourceMaxLen)
	}
	if !enrollscript.ValidAddress(a) {
		return "", fmt.Errorf("%q is neither an IP address nor a CIDR range", a)
	}
	if strings.Contains(a, "/") {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return "", fmt.Errorf("%q: %w", a, err)
		}
		if p.Addr().Zone() != "" {
			return "", fmt.Errorf("%q has a zone ID", a)
		}
		if p.Addr().Is4In6() {
			return "", fmt.Errorf("%q is IPv4-mapped IPv6; use the IPv4 form", a)
		}
		if p != p.Masked() {
			return "", fmt.Errorf("%q has host bits set; did you mean %s?", a, p.Masked())
		}
		return p.String(), nil
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return "", fmt.Errorf("%q: %w", a, err)
	}
	if ip.Zone() != "" {
		return "", fmt.Errorf("%q has a zone ID", a)
	}
	if ip.Is4In6() {
		return "", fmt.Errorf("%q is IPv4-mapped IPv6; use the IPv4 form", a)
	}
	return ip.String(), nil
}

// urlByteAllowed reports whether c may appear in a management URL: the
// scheme, host, port and path characters of spec 03 "Render-input format".
// Everything else, including '%', '?', '#', '@', quotes, '$', backtick,
// backslash, whitespace, control and non-ASCII bytes, is refused.
func urlByteAllowed(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~/:[]", c) >= 0
}

// urlPathByteAllowed reports whether c may appear in the path of a
// management URL: A-Za-z0-9-._~/ only (spec 03 "Render-input format").
func urlPathByteAllowed(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~/", c) >= 0
}

// validNetBirdMgmtURL checks the NetBird management URL against spec 03
// "Render-input format": at most netBirdMgmtURLMaxLen bytes of ASCII,
// scheme exactly https, host a DNS name of LDH labels or an IP literal
// (IPv6 in brackets, no zone ID), optional port 1–65535, optional path of
// A-Za-z0-9-._~/ only, no userinfo, query, fragment or percent-encoding,
// and equal to its re-encoded form.
func validNetBirdMgmtURL(raw string) error {
	if len(raw) > netBirdMgmtURLMaxLen {
		return fmt.Errorf("longer than %d bytes", netBirdMgmtURLMaxLen)
	}
	for i := 0; i < len(raw); i++ {
		if !urlByteAllowed(raw[i]) {
			return fmt.Errorf("character %q at byte %d is not allowed", raw[i], i)
		}
	}
	if !strings.HasPrefix(raw, "https://") {
		return errors.New("scheme must be exactly https://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	switch {
	case u.Scheme != "https" || u.Opaque != "":
		return errors.New("scheme must be exactly https://")
	case u.User != nil:
		return errors.New("userinfo is not allowed")
	case u.RawQuery != "" || u.ForceQuery:
		return errors.New("query is not allowed")
	case u.Fragment != "" || u.RawFragment != "":
		return errors.New("fragment is not allowed")
	case u.RawPath != "":
		return errors.New("percent-encoding is not allowed")
	case u.Host == "":
		return errors.New("no host")
	}
	if err := validURLHost(u); err != nil {
		return err
	}
	// urlByteAllowed admits ':', '[' and ']' for the host and port only;
	// the path is held to its own, narrower set.
	for i := 0; i < len(u.Path); i++ {
		if !urlPathByteAllowed(u.Path[i]) {
			return fmt.Errorf("character %q is not allowed in the path", u.Path[i])
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return errors.New("dot segments are not allowed in the path")
		}
	}
	if u.String() != raw {
		return errors.New("not in canonical form")
	}
	return nil
}

func validURLHost(u *url.URL) error {
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("empty port")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return fmt.Errorf("port %q is not a number from 1 to 65535", p)
		}
	}
	name := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(name)
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" {
			return fmt.Errorf("host %q is not an IPv6 address", u.Host)
		}
		return nil
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		if !ip.Is4() {
			return fmt.Errorf("host %q: an IPv6 address needs brackets", name)
		}
		return nil
	}
	if !validDNSName(name) {
		return fmt.Errorf("host %q is not a DNS name of letters, digits and hyphens", name)
	}
	return nil
}

// validDNSName reports whether s is a DNS name of LDH labels: each label
// 1–63 letters, digits or hyphens, not starting or ending with a hyphen;
// no trailing dot.
func validDNSName(s string) bool {
	if s == "" || len(s) > dnsNameMaxLen {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > dnsLabelMaxLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// loadNetBirdCAFile reads the pinned CA (or leaf) certificates for the
// NetBird management API: an absolute path to a regular file that is not
// group- or world-writable, at most netBirdCAFileMaxBytes, holding one or
// more PEM CERTIFICATE blocks and nothing else. Errors never quote the
// file content.
func loadNetBirdCAFile(path string) (*x509.CertPool, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%q is not an absolute path", path)
	}
	// O_NONBLOCK: a FIFO in place of the file must not block the start.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is group- or world-writable (mode %04o)", path, st.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, netBirdCAFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > netBirdCAFileMaxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, netBirdCAFileMaxBytes)
	}
	pool := x509.NewCertPool()
	n := 0
	rest := data
	for {
		// pem.Decode skips text before a block; refuse it instead.
		start := bytes.Index(rest, []byte("-----BEGIN "))
		if start < 0 {
			break
		}
		if len(bytes.TrimSpace(rest[:start])) != 0 {
			return nil, fmt.Errorf("%s has content outside PEM certificate blocks", path)
		}
		block, r := pem.Decode(rest[start:])
		if block == nil {
			return nil, fmt.Errorf("%s has a malformed PEM block", path)
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("%s holds a PEM block that is not a certificate (block %d)", path, n+1)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: certificate %d does not parse", path, n+1)
		}
		pool.AddCert(cert)
		n++
		rest = r
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s has content outside PEM certificate blocks", path)
	}
	if n == 0 {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

// validManagedGroup checks the NetBird managed group name: 1 to
// managedGroupMaxLen bytes matching managedGroupPattern, and none of
// reservedGroups.
func validManagedGroup(g string) error {
	if len(g) > managedGroupMaxLen {
		return fmt.Errorf("longer than %d bytes", managedGroupMaxLen)
	}
	if !managedGroupPattern.MatchString(g) {
		return fmt.Errorf("%q is not a group name of ASCII letters, digits, '.', '_' and '-' starting with a letter or digit", g)
	}
	for _, r := range reservedGroups {
		if strings.EqualFold(g, r) {
			return fmt.Errorf("%q is reserved: enrolled hosts must not join NetBird's %q group", g, r)
		}
	}
	return nil
}
