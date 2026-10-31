// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executor — PVE admin credential lifecycle (ADR 0006, P1-06).
//
// PveAdmin implements the local, admin-only credential lifecycle for the
// PVE remotes registered in the executor's remote registry:
//
//   - add:      probe every endpoint WITHOUT credentials, show the
//     presented certificate chain fingerprints, require the admin to type
//     the trust-identity fingerprint back, validate the presented PVE API
//     token against the pinned endpoint, envelope-encrypt the token in the
//     vault and store only the opaque ref+version in the registry.
//   - rotate:   validate the new token against the pinned endpoint first;
//     the old version stays authoritative until the new one is validated
//     and stored, then the registry switches atomically.
//   - remove:   disable the remote, revoke its dependent grants, remove
//     the vault secrets, tombstone the id — in that order.
//   - repin:    require the current pin and a typed confirmation of the
//     newly presented trust identity, then bump the trust generation.
//   - list:     metadata only; secrets never leave the vault.
//
// Secrets (token values) never appear in replies, logs, errors or audit
// records: the registry stores opaque vault refs, and every error and log
// line here carries only ids, refs, versions and fingerprints.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Sentinel errors of the PVE admin lifecycle.
var (
	// ErrPvePinMismatch is returned when the trust identity presented by
	// the endpoints does not equal the fingerprint the admin confirmed
	// (typed confirmation) or the pin stored in the registry.
	ErrPvePinMismatch = errors.New("executor: presented trust identity does not match the confirmed fingerprint")
	// ErrPveTokenInvalid is returned when the pinned endpoint rejects the
	// presented PVE API token (401/403). The token value is not part of
	// the error.
	ErrPveTokenInvalid = errors.New("executor: pve token rejected by the pinned endpoint")
	// ErrPveTokenFormat is returned for malformed token strings. The
	// token value is not part of the error.
	ErrPveTokenFormat = errors.New("executor: malformed pve api token (want USER@REALM!TOKENID=VALUE)")
	// ErrPveTokenRejected is returned for tokens whose profile is refused
	// by policy (password realm, built-in admin users). The token value is
	// not part of the error.
	ErrPveTokenRejected = errors.New("executor: pve token profile is not accepted")
	// ErrPvePurpose is returned for a purpose other than read|action.
	ErrPvePurpose = errors.New("executor: pve purpose must be read or action")
	// ErrPveApprovalRequired means re-pinning has no bound HIGH approval.
	ErrPveApprovalRequired = errors.New("executor: pve re-pin requires a bound HIGH approval")
	// ErrPveResponse is a sanitized failure of an authenticated request.
	ErrPveResponse = errors.New("executor: pve authenticated request failed")
)

// Credential purposes of a PVE remote.
const (
	// PvePurposeRead is the token purpose for the read-only phase-1 API.
	PvePurposeRead = "read"
	// PvePurposeAction is the token purpose for the phase-2 action API.
	PvePurposeAction = "action"
)

// maxPveTokenLen bounds a PVE API token string (USER@REALM!TOKENID=VALUE).
const maxPveTokenLen = 256

const maxPveProfileBytes = canonical.MaxParametersSize

const maxPveACLPathBytes = 256

var pveTokenPattern = regexp.MustCompile(`^([A-Za-z0-9_.-]+@[A-Za-z][A-Za-z0-9_.-]*)!([A-Za-z][A-Za-z0-9_.-]*)=([A-Za-z0-9._~-]+)$`)

var pveACLPathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?$`)

// probeTimeout bounds the credential-free TLS probe of one endpoint.
const probeTimeout = 10 * time.Second

// PveVaultID is the deterministic vault id of one remote's credential for
// one purpose. It is opaque to the registry: the registry stores it as a
// ref and never sees the secret.
func PveVaultID(remoteID, purpose string) string {
	sum := sha256.Sum256([]byte(remoteID))
	return "pve-" + hex.EncodeToString(sum[:8]) + "-" + purpose
}

// PveProbeEndpoint is the presented chain of one probed endpoint,
// credential-free.
type PveProbeEndpoint struct {
	// Host and Port of the endpoint.
	Host string
	Port uint16
	// Leaf is the presented leaf certificate.
	Leaf *x509.Certificate
	// LeafFingerprint is the hex-encoded SHA-256 of the leaf DER.
	LeafFingerprint string
	// CA is the self-signed root of the presented chain, if any.
	CA *x509.Certificate
	// CAFingerprint is the hex-encoded SHA-256 of the CA DER, "" if none.
	CAFingerprint string
}

// PveProbeResult is the presented chain of every endpoint of a remote.
type PveProbeResult struct {
	// Endpoints is one entry per probed endpoint, in input order.
	Endpoints []PveProbeEndpoint
}

// TrustIdentity derives the trust identity of the probe for a remote kind:
// a cluster is identified by its CA (identical on every endpoint), a
// standalone by its leaf. It returns the fingerprint to confirm and pin
// and the pvetransport trust that enforces it.
func (r PveProbeResult) TrustIdentity(kind pvecontract.Kind) (string, pvetransport.Trust, error) {
	if len(r.Endpoints) == 0 {
		return "", pvetransport.Trust{}, errors.New("executor: no endpoints probed")
	}
	switch kind {
	case pvecontract.KindCluster:
		pin, ca := "", (*x509.Certificate)(nil)
		for i, ep := range r.Endpoints {
			if ep.CA == nil {
				return "", pvetransport.Trust{}, fmt.Errorf("executor: endpoint %s:%d presented no self-signed CA certificate", ep.Host, ep.Port)
			}
			if i == 0 {
				pin, ca = ep.CAFingerprint, ep.CA
			} else if ep.CAFingerprint != pin {
				return "", pvetransport.Trust{}, fmt.Errorf("%w: endpoints disagree on the cluster CA fingerprint", ErrPvePinMismatch)
			}
		}
		return pin, pvetransport.Trust{CA: ca}, nil
	case pvecontract.KindStandalone:
		pin, fp := "", [32]byte{}
		for i, ep := range r.Endpoints {
			if ep.Leaf == nil {
				return "", pvetransport.Trust{}, fmt.Errorf("executor: endpoint %s:%d presented no leaf certificate", ep.Host, ep.Port)
			}
			if i == 0 {
				pin, fp = ep.LeafFingerprint, pvetransport.Fingerprint(ep.Leaf)
			} else if ep.LeafFingerprint != pin {
				return "", pvetransport.Trust{}, fmt.Errorf("%w: endpoints disagree on the standalone leaf fingerprint", ErrPvePinMismatch)
			}
		}
		return pin, pvetransport.Trust{LeafFingerprint: fp}, nil
	default:
		return "", pvetransport.Trust{}, fmt.Errorf("executor: unknown pve kind %q", kind)
	}
}

// PveProbeFunc fetches the presented certificate chain of each endpoint
// without sending any credentials.
type PveProbeFunc func(ctx context.Context, endpoints []pvecontract.Endpoint) (PveProbeResult, error)

// DefaultPveProbe is the PveProbeFunc used when PveAdmin.Probe is nil: it
// performs a TLS handshake with each endpoint and parses the presented
// chain. No HTTP request is made, no credentials are sent, and no trust
// is established — trust is created only when the admin confirms the
// fingerprint out of band.
func DefaultPveProbe(ctx context.Context, endpoints []pvecontract.Endpoint) (PveProbeResult, error) {
	if len(endpoints) == 0 {
		return PveProbeResult{}, pvetransport.ErrNoEndpoints
	}
	res := PveProbeResult{}
	for _, ep := range endpoints {
		certs, err := fetchPresentedChain(ctx, ep.Host, ep.Port)
		if err != nil {
			return PveProbeResult{}, fmt.Errorf("executor: probe pve endpoint %s:%d: %w", ep.Host, ep.Port, err)
		}
		info := PveProbeEndpoint{Host: ep.Host, Port: ep.Port, Leaf: certs[0]}
		leafFP := pvetransport.Fingerprint(certs[0])
		info.LeafFingerprint = hex.EncodeToString(leafFP[:])
		for i := len(certs) - 1; i >= 0; i-- {
			if bytes.Equal(certs[i].RawIssuer, certs[i].RawSubject) {
				info.CA = certs[i]
				caFP := pvetransport.Fingerprint(certs[i])
				info.CAFingerprint = hex.EncodeToString(caFP[:])
				break
			}
		}
		res.Endpoints = append(res.Endpoints, info)
	}
	return res, nil
}

// fetchPresentedChain dials host:port and returns the certificates the
// server presented. The handshake skips verification on purpose: this is
// the credential-free fetch step of pinning, and the admin confirms the
// fingerprint afterwards.
func fetchPresentedChain(ctx context.Context, host string, port uint16) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // fetch-only; trust is the confirmed pin
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
	})
	hctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		tlsConn.Close()
		return nil, err
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	tlsConn.Close()
	if len(certs) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return certs, nil
}

// PveTokenValidateFunc validates a presented token against the pinned
// endpoint. It must not return the token value in any error.
type PveTokenValidateFunc func(ctx context.Context, endpoints []pvecontract.Endpoint, trust pvetransport.Trust, token []byte) error

// DefaultPveTokenValidate is the PveTokenValidateFunc used when
// PveAdmin.ValidateToken is nil for a read token. It verifies the version,
// token metadata and complete effective permission tree through pinned TLS.
// Unverifiable, expired, non-separated or excessive profiles are refused.
func DefaultPveTokenValidate(ctx context.Context, endpoints []pvecontract.Endpoint, trust pvetransport.Trust, token []byte) error {
	return defaultPveTokenValidate(ctx, endpoints, trust, token, PvePurposeRead, time.Now, token)
}

func defaultPveTokenValidate(ctx context.Context, endpoints []pvecontract.Endpoint, trust pvetransport.Trust, token []byte, purpose string, now func() time.Time, metadataToken []byte) error {
	if err := validatePveTokenFormat(token); err != nil {
		return err
	}
	if purpose != PvePurposeRead && purpose != PvePurposeAction {
		return ErrPvePurpose
	}
	urls := make([]*url.URL, 0, len(endpoints))
	for _, ep := range endpoints {
		u, err := pvetransport.ParseEndpoint("https://" + net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))))
		if err != nil {
			return fmt.Errorf("executor: pve token validate: %w", err)
		}
		urls = append(urls, u)
	}
	client, err := pvetransport.NewClient(pvetransport.Options{
		Trust:            trust,
		Endpoints:        urls,
		Auth:             func(context.Context) (string, error) { return "PVEAPIToken=" + string(token), nil },
		MaxResponseBytes: maxPveProfileBytes,
		Now:              now,
	})
	if err != nil {
		return fmt.Errorf("executor: pve token validate: %w", err)
	}
	var version struct {
		Version string `json:"version"`
	}
	if err := pveProfileGET(ctx, client, "/api2/json/version", &version); err != nil {
		return err
	}
	if version.Version == "" {
		return ErrPveTokenRejected
	}
	var permissions map[string]map[string]int
	if err := pveProfileGET(ctx, client, "/api2/json/access/permissions", &permissions); err != nil {
		return err
	}
	if err := validatePvePermissions(permissions, purpose); err != nil {
		return err
	}
	if err := validatePveTokenFormat(metadataToken); err != nil {
		return ErrPveTokenRejected
	}
	// The token-info endpoint's self rule does not apply to API token IDs.
	// NOSRead's Sys.Audit on / permits the full user/token metadata listing.
	metadataClient, err := pvetransport.NewClient(pvetransport.Options{Trust: trust, Endpoints: urls, Auth: func(context.Context) (string, error) { return "PVEAPIToken=" + string(metadataToken), nil }, MaxResponseBytes: maxPveProfileBytes, Now: now})
	if err != nil {
		return ErrPveResponse
	}
	var users []pveProfileUser
	if err := pveProfileGET(ctx, metadataClient, "/api2/json/access/users?full=1", &users); err != nil {
		return err
	}
	return validatePveTokenMetadata(users, token, now())
}

type pveProfileUser struct {
	UserID string `json:"userid"`
	Enable *int   `json:"enable"`
	Expire *int64 `json:"expire"`
	Tokens []struct {
		TokenID string `json:"tokenid"`
		Privsep *int   `json:"privsep"`
		Expire  *int64 `json:"expire"`
	} `json:"tokens"`
}

func validatePveTokenMetadata(users []pveProfileUser, token []byte, now time.Time) error {
	parts := pveTokenPattern.FindSubmatch(token)
	foundUser, foundToken := false, false
	for _, user := range users {
		if user.UserID != string(parts[1]) {
			continue
		}
		if foundUser || (user.Enable != nil && *user.Enable != 1) || (user.Expire != nil && *user.Expire != 0 && *user.Expire <= now.Unix()) {
			return ErrPveTokenRejected
		}
		foundUser = true
		for _, meta := range user.Tokens {
			if meta.TokenID != string(parts[2]) {
				continue
			}
			if foundToken || meta.Privsep == nil || *meta.Privsep != 1 {
				return ErrPveTokenRejected
			}
			expiry := meta.Expire
			if expiry == nil {
				expiry = user.Expire
			}
			if expiry == nil || *expiry <= now.Unix() {
				return ErrPveTokenRejected
			}
			foundToken = true
		}
	}
	if !foundUser || !foundToken {
		return ErrPveTokenRejected
	}
	return nil
}

// Never wrap errors from HTTP parsing or body decoding: a peer may reflect
// the Authorization header into a status line, header, chunk or JSON value.
func pveProfileGET(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://pve.invalid"+path, nil)
	if err != nil {
		return ErrPveResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, pvetransport.ErrTrustMismatch) {
			return pvetransport.ErrTrustMismatch
		}
		return ErrPveResponse
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrPveTokenInvalid
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ErrPveResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPveProfileBytes+1))
	if err != nil || len(raw) > maxPveProfileBytes || !utf8.Valid(raw) {
		return ErrPveResponse
	}
	if _, err := canonical.HashParameters(raw); err != nil {
		return ErrPveTokenRejected
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) || json.Unmarshal(envelope.Data, out) != nil {
		return ErrPveTokenRejected
	}
	return nil
}

func validatePvePermissions(perms map[string]map[string]int, purpose string) error {
	read := map[string]string{"Sys.Audit": "/", "VM.Audit": "/vms", "Datastore.Audit": "/storage", "Pool.Audit": "/pool"}
	if len(perms) == 0 {
		return ErrPveTokenRejected
	}
	action := false
	for path, rights := range perms {
		if len(path) > maxPveACLPathBytes || !pveACLPathPattern.MatchString(path) || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") || strings.Contains(path, "/./") || strings.HasSuffix(path, "/.") {
			return ErrPveTokenRejected
		}
		if len(rights) == 0 {
			continue
		}
		for privilege, propagate := range rights {
			if propagate != 0 && propagate != 1 {
				return ErrPveTokenRejected
			}
			if purpose == PvePurposeRead {
				base, ok := read[privilege]
				if !ok || !(path == base || (base == "/" && strings.HasPrefix(path, "/")) || strings.HasPrefix(path, base+"/")) {
					return ErrPveTokenRejected
				}
			} else {
				vmid := strings.TrimPrefix(path, "/vms/")
				id, err := strconv.ParseUint(vmid, 10, 32)
				if privilege != "VM.PowerMgmt" || !strings.HasPrefix(path, "/vms/") || err != nil || id == 0 || strconv.FormatUint(id, 10) != vmid {
					return ErrPveTokenRejected
				}
				action = true
			}
		}
	}
	if purpose == PvePurposeRead {
		for privilege, path := range read {
			if perms[path][privilege] != 1 {
				return ErrPveTokenRejected
			}
		}
	} else if !action {
		return ErrPveTokenRejected
	}
	return nil
}

// validatePveTokenFormat checks the shape of a PVE API token and the
// profile policy (password realm and built-in admin users are refused).
// The token value never appears in the returned error.
func validatePveTokenFormat(token []byte) error {
	if len(token) == 0 || len(token) > maxPveTokenLen {
		return ErrPveTokenFormat
	}
	parts := pveTokenPattern.FindSubmatch(token)
	if parts == nil {
		return ErrPveTokenFormat
	}
	user := string(parts[1])
	switch {
	case strings.HasSuffix(user, "@pam"):
		return fmt.Errorf("%w: password-realm user is refused", ErrPveTokenRejected)
	case strings.HasPrefix(user, "Administrator@") || strings.HasPrefix(user, "PVEVMAdmin@"):
		return fmt.Errorf("%w: built-in admin user is refused", ErrPveTokenRejected)
	}
	return nil
}

// PveAdmin implements the admin-only PVE credential lifecycle. It runs
// inside the executor; only the authenticated admin UID may reach it
// (peercred at the RPC boundary).
type PveAdmin struct {
	// DB is the executor database (remote registry, change trail).
	DB *executordb.DB
	// Vault is the executor's secret vault.
	Vault *vault.Vault
	// Probe fetches the presented chain without credentials.
	// Default: DefaultPveProbe.
	Probe PveProbeFunc
	// ValidateToken validates a token against the pinned endpoint.
	// Default: DefaultPveTokenValidate.
	ValidateToken PveTokenValidateFunc
	// AuthorizeRepin consumes an approval bound to the current remote,
	// old/new fingerprints, endpoints and generations. Nil refuses re-pin.
	AuthorizeRepin func(context.Context, executordb.PveRemote, PveRepin) error
	// RevokeGrants revokes the provider read grants that depend on the
	// remote's credentials or trust. Nil revokes nothing (tests); the
	// executor service wires permit.Authority.RevokeProviderGrants.
	RevokeGrants func(remoteID, reason string) error
	// Now is the clock. Default: time.Now.
	Now func() time.Time
	// Log receives non-secret lifecycle events. Default: a discarding
	// logger.
	Log *slog.Logger
}

// checkDeps verifies the required dependencies.
func (a *PveAdmin) checkDeps() error {
	if err := a.checkDB(); err != nil {
		return err
	}
	if a.Vault == nil {
		return errors.New("executor: pve admin: Vault is required")
	}
	st, err := a.Vault.State()
	if err != nil {
		return fmt.Errorf("executor: pve vault state: %w", err)
	}
	if st != vault.StateUnlocked {
		return vault.ErrLocked
	}
	return nil
}

// checkDB verifies the dependencies of the metadata-only operations.
func (a *PveAdmin) checkDB() error {
	if a.DB == nil {
		return errors.New("executor: pve admin: DB is required")
	}
	return nil
}

func (a *PveAdmin) probeFn() PveProbeFunc {
	if a.Probe == nil {
		return DefaultPveProbe
	}
	return a.Probe
}

func (a *PveAdmin) validateTokenFn(purpose string, metadataToken []byte) PveTokenValidateFunc {
	return func(ctx context.Context, eps []pvecontract.Endpoint, trust pvetransport.Trust, token []byte) error {
		if err := a.checkDeps(); err != nil {
			return err
		}
		if a.ValidateToken != nil {
			return a.ValidateToken(ctx, eps, trust, token)
		}
		now := a.Now
		if now == nil {
			now = time.Now
		}
		return defaultPveTokenValidate(ctx, eps, trust, token, purpose, now, metadataToken)
	}
}

func (a *PveAdmin) revoke(remoteID, reason string) error {
	if a.RevokeGrants == nil {
		return nil
	}
	return a.RevokeGrants(remoteID, reason)
}

func (a *PveAdmin) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return a.Log
}

// compensateVault removes a vault secret that this call just stored, but
// only if the stored version is still current, so a failed registry write
// leaves no orphaned secret and never deletes a newer version.
func (a *PveAdmin) compensateVault(id string, version int64) {
	infos, err := a.Vault.List()
	if err != nil {
		return
	}
	for _, info := range infos {
		if info.ID == id && info.Version == version {
			_ = a.Vault.Delete(id)
			return
		}
	}
}

// PveAddRemote carries one `pve remote add` request.
type PveAddRemote struct {
	// RemoteID is the new remote id.
	RemoteID string
	// Name is the optional label.
	Name string
	// Kind is cluster or standalone.
	Kind pvecontract.Kind
	// Endpoints is the endpoint set.
	Endpoints []pvecontract.Endpoint
	// ConfirmedPin is the trust-identity fingerprint the admin typed back
	// after out-of-band comparison. It must equal the presented identity.
	ConfirmedPin string
	// ReadToken is the PVE API token for the read purpose (required).
	ReadToken []byte
	// ActionToken is the optional PVE API token for the action purpose.
	ActionToken []byte
	// By is the authenticated admin identity. The RPC layer sets it from
	// peercred and ignores any client-supplied value.
	By string
}

// AddRemote registers a new PVE remote: it probes the endpoints without
// credentials, requires the confirmed pin to equal the presented trust
// identity, validates the token(s) against the pinned endpoint, stores
// the secrets in the vault and the opaque refs in the registry.
func (a *PveAdmin) AddRemote(ctx context.Context, in PveAddRemote) (executordb.PveRemote, error) {
	if err := a.checkDeps(); err != nil {
		return executordb.PveRemote{}, err
	}
	if len(in.ReadToken) == 0 {
		return executordb.PveRemote{}, errors.New("executor: pve add remote: the read token is required")
	}
	remote, err := pvecontract.ValidateRemote(pvecontract.Remote{
		RemoteID:        in.RemoteID,
		Name:            in.Name,
		Kind:            in.Kind,
		Endpoints:       in.Endpoints,
		TrustPin:        in.ConfirmedPin,
		TrustGeneration: 1,
	})
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: %w", err)
	}
	if old, ok, err := a.DB.GetRemote(remote.RemoteID); err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: %w", err)
	} else if ok && old.State != executordb.StateRemoved {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: %w", executordb.ErrRemoteExists)
	}
	// Refuse the token profile before touching the network: password-realm
	// and built-in admin tokens are never accepted, whatever the endpoint.
	if err := validatePveTokenFormat(in.ReadToken); err != nil {
		return executordb.PveRemote{}, err
	}
	if len(in.ActionToken) > 0 {
		if err := validatePveTokenFormat(in.ActionToken); err != nil {
			return executordb.PveRemote{}, err
		}
	}
	if len(in.ActionToken) > 0 && bytes.Equal(pveTokenPattern.FindSubmatch(in.ReadToken)[1], pveTokenPattern.FindSubmatch(in.ActionToken)[1]) {
		return executordb.PveRemote{}, ErrPveTokenRejected
	}
	res, err := a.probeFn()(ctx, remote.Endpoints)
	if err != nil {
		return executordb.PveRemote{}, err
	}
	pin, trust, err := res.TrustIdentity(remote.Kind)
	if err != nil {
		return executordb.PveRemote{}, err
	}
	if pin != remote.TrustPin {
		return executordb.PveRemote{}, fmt.Errorf("%w: presented %s, confirmed %s", ErrPvePinMismatch, pin, remote.TrustPin)
	}
	if err := a.validateTokenFn(PvePurposeRead, in.ReadToken)(ctx, remote.Endpoints, trust, in.ReadToken); err != nil {
		return executordb.PveRemote{}, err
	}
	readID := PveVaultID(remote.RemoteID, PvePurposeRead)
	readVersion, err := a.Vault.Put(readID, in.ReadToken, in.By)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: store read token: %w", err)
	}
	creds := executordb.PveRemoteCredentials{ReadRef: readID, ReadVersion: readVersion}
	if len(in.ActionToken) > 0 {
		if err := validatePveTokenFormat(in.ActionToken); err != nil {
			a.compensateVault(readID, readVersion)
			return executordb.PveRemote{}, err
		}
		if err := a.validateTokenFn(PvePurposeAction, in.ReadToken)(ctx, remote.Endpoints, trust, in.ActionToken); err != nil {
			a.compensateVault(readID, readVersion)
			return executordb.PveRemote{}, err
		}
		actionID := PveVaultID(remote.RemoteID, PvePurposeAction)
		actionVersion, err := a.Vault.Put(actionID, in.ActionToken, in.By)
		if err != nil {
			a.compensateVault(readID, readVersion)
			return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: store action token: %w", err)
		}
		creds.ActionRef, creds.ActionVersion = actionID, actionVersion
	}
	rm, err := a.DB.AddRemote(remote, creds, in.By)
	if err != nil {
		a.compensateVault(readID, readVersion)
		if creds.ActionRef != "" {
			a.compensateVault(creds.ActionRef, creds.ActionVersion)
		}
		return executordb.PveRemote{}, fmt.Errorf("executor: pve add remote: %w", err)
	}
	a.log().Info("pve remote added",
		"remote", rm.RemoteID, "pin", pin, "gen", rm.TrustGeneration,
		"read", fmt.Sprintf("%s@%d", readID, readVersion))
	return rm, nil
}

// PveRotateToken carries one `pve remote rotate-token` request.
type PveRotateToken struct {
	// RemoteID is the remote to rotate.
	RemoteID string
	// Purpose is read or action.
	Purpose string
	// Token is the new PVE API token.
	Token []byte
	// By is the authenticated admin identity.
	By string
}

// RotateToken replaces one purpose's token. The new token is validated
// against the pinned endpoint before anything changes; the old version
// stays authoritative in the registry until the new one is stored, then
// the registry switches atomically. Dependent grants bound to the old
// version are revoked afterwards.
func (a *PveAdmin) RotateToken(ctx context.Context, in PveRotateToken) (executordb.PveRemote, error) {
	if err := a.checkDeps(); err != nil {
		return executordb.PveRemote{}, err
	}
	if in.Purpose != PvePurposeRead && in.Purpose != PvePurposeAction {
		return executordb.PveRemote{}, ErrPvePurpose
	}
	if len(in.Token) == 0 {
		return executordb.PveRemote{}, errors.New("executor: pve rotate token: the token is required")
	}
	if err := validatePveTokenFormat(in.Token); err != nil {
		return executordb.PveRemote{}, err
	}
	rm, ok, err := a.DB.GetRemote(in.RemoteID)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve rotate token: %w", err)
	}
	if !ok {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve rotate token: %w: %s", executordb.ErrRemoteNotFound, in.RemoteID)
	}
	if rm.State != executordb.StateActive {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve rotate token: %w: %s is %s", executordb.ErrRemoteState, in.RemoteID, rm.State)
	}
	metadataToken := in.Token
	otherRef := rm.Credentials.ActionRef
	if in.Purpose == PvePurposeAction {
		otherRef = rm.Credentials.ReadRef
	}
	if otherRef != "" {
		other, err := a.Vault.Open(otherRef)
		if err != nil {
			return executordb.PveRemote{}, err
		}
		defer clear(other)
		if validatePveTokenFormat(other) != nil || bytes.Equal(pveTokenPattern.FindSubmatch(in.Token)[1], pveTokenPattern.FindSubmatch(other)[1]) {
			return executordb.PveRemote{}, ErrPveTokenRejected
		}
		if in.Purpose == PvePurposeAction {
			metadataToken = other
		}
	}
	res, err := a.probeFn()(ctx, rm.Endpoints)
	if err != nil {
		if errors.Is(err, pvetransport.ErrTrustMismatch) {
			return executordb.PveRemote{}, a.blockTrustFailure(rm.RemoteID, in.By, err)
		}
		return executordb.PveRemote{}, err
	}
	pin, trust, err := res.TrustIdentity(rm.Kind)
	if err != nil {
		return executordb.PveRemote{}, a.blockTrustFailure(rm.RemoteID, in.By, ErrPvePinMismatch)
	}
	if pin != rm.TrustPin {
		return executordb.PveRemote{}, a.blockTrustFailure(rm.RemoteID, in.By, ErrPvePinMismatch)
	}
	if err := a.validateTokenFn(in.Purpose, metadataToken)(ctx, rm.Endpoints, trust, in.Token); err != nil {
		if errors.Is(err, pvetransport.ErrTrustMismatch) {
			return executordb.PveRemote{}, a.blockTrustFailure(rm.RemoteID, in.By, pvetransport.ErrTrustMismatch)
		}
		return executordb.PveRemote{}, err
	}
	id := PveVaultID(in.RemoteID, in.Purpose)
	var rotated executordb.PveRemote
	version, err := a.Vault.PutWithCommit(id, in.Token, in.By, func(secret executordb.VaultSecret) error {
		var err error
		rotated, err = a.DB.RotateRemoteSecret(rm, in.Purpose, secret, in.By)
		return err
	})
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve rotate token: store token: %w", err)
	}
	rm = rotated
	if err := a.revoke(in.RemoteID, "pve credential rotation: "+in.Purpose+" token version "+strconv.FormatInt(version, 10)); err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve rotate token: revoke grants: %w", err)
	}
	a.log().Info("pve token rotated", "remote", in.RemoteID, "purpose", in.Purpose, "ref", id, "version", version)
	return rm, nil
}

func (a *PveAdmin) blockTrustFailure(remoteID, by string, cause error) error {
	if _, err := a.DB.BlockRemote(remoteID, "pve trust verification failed", by); err != nil {
		return fmt.Errorf("executor: persist pve trust block: %w", errors.Join(cause, err))
	}
	if err := a.revoke(remoteID, "pve trust verification failed"); err != nil {
		return fmt.Errorf("executor: revoke blocked pve authority: %w", errors.Join(cause, err))
	}
	a.log().Warn("pve remote blocked", "remote", remoteID, "reason", "trust verification failed")
	return cause
}

// PveRemove carries one `pve remote remove` request.
type PveRemove struct {
	// RemoteID is the remote to remove.
	RemoteID string
	// By is the authenticated admin identity.
	By string
}

// RemoveRemote removes a PVE remote in the mandated order: disable,
// revoke dependent grants, remove the vault secrets, tombstone the id.
// A locked vault refuses the whole operation before any side effect.
func (a *PveAdmin) RemoveRemote(ctx context.Context, in PveRemove) (executordb.PveRemote, error) {
	if err := a.checkDeps(); err != nil {
		return executordb.PveRemote{}, err
	}
	rm, ok, err := a.DB.GetRemote(in.RemoteID)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w", err)
	}
	if !ok {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w: %s", executordb.ErrRemoteNotFound, in.RemoteID)
	}
	if rm.State == executordb.StateRemoved {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w: %s is already removed", executordb.ErrRemoteState, in.RemoteID)
	}
	if rm.Credentials.ReadRef != "" || rm.Credentials.ActionRef != "" {
		st, err := a.Vault.State()
		if err != nil {
			return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w", err)
		}
		if st != vault.StateUnlocked {
			return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w", vault.ErrLocked)
		}
	}
	if rm.State == executordb.StateActive {
		if _, err := a.DB.BlockRemote(in.RemoteID, "remote removed: disabling and revoking authorizations", in.By); err != nil {
			return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: disable: %w", err)
		}
	}
	if err := a.revoke(in.RemoteID, "pve remote removed"); err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: revoke grants: %w", err)
	}
	for _, purpose := range []string{PvePurposeRead, PvePurposeAction} {
		err := a.Vault.Delete(PveVaultID(in.RemoteID, purpose))
		if errors.Is(err, vault.ErrNotFound) {
			continue
		}
		if err != nil {
			return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: remove vault secret: %w", err)
		}
	}
	rm, err = a.DB.RemoveRemote(in.RemoteID, in.By)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve remove remote: %w", err)
	}
	a.log().Info("pve remote removed", "remote", in.RemoteID)
	return rm, nil
}

// PveRepin carries one `pve remote repin` request.
type PveRepin struct {
	// RemoteID is the remote to re-pin.
	RemoteID string
	// OldPin is the current pin from the registry (typed by the admin).
	OldPin string
	// ConfirmedNewPin is the newly presented trust identity the admin
	// typed back after out-of-band comparison.
	ConfirmedNewPin string
	// By is the authenticated admin identity.
	By string
	// ApprovalDigest identifies the approved, single-use HIGH permit.
	ApprovalDigest string
}

// Repin re-pins a remote to the trust identity its endpoints present
// now. The admin must type the current pin and the newly presented
// fingerprint; the trust generation is bumped and the remote is
// unblocked.
func (a *PveAdmin) Repin(ctx context.Context, in PveRepin) (executordb.PveRemote, error) {
	if err := a.checkDeps(); err != nil {
		return executordb.PveRemote{}, err
	}
	rm, ok, err := a.DB.GetRemote(in.RemoteID)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: %w", err)
	}
	if !ok {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: %w: %s", executordb.ErrRemoteNotFound, in.RemoteID)
	}
	if rm.State == executordb.StateRemoved {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: %w: %s is removed", executordb.ErrRemoteState, in.RemoteID)
	}
	if in.OldPin != rm.TrustPin {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: %w: the remote is pinned to %s", executordb.ErrInvalid, rm.TrustPin)
	}
	res, err := a.probeFn()(ctx, rm.Endpoints)
	if err != nil {
		return executordb.PveRemote{}, err
	}
	pin, _, err := res.TrustIdentity(rm.Kind)
	if err != nil {
		return executordb.PveRemote{}, err
	}
	if pin != in.ConfirmedNewPin {
		return executordb.PveRemote{}, fmt.Errorf("%w: presented %s, confirmed %s", ErrPvePinMismatch, pin, in.ConfirmedNewPin)
	}
	if a.AuthorizeRepin == nil {
		return executordb.PveRemote{}, ErrPveApprovalRequired
	}
	if err := a.AuthorizeRepin(ctx, rm, in); err != nil {
		return executordb.PveRemote{}, err
	}
	if err := a.checkDeps(); err != nil {
		return executordb.PveRemote{}, err
	}
	rm, err = a.DB.RepinRemote(in.RemoteID, in.OldPin, pin, in.By)
	if err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: %w", err)
	}
	if err := a.revoke(in.RemoteID, "pve trust re-pin: generation "+strconv.FormatUint(rm.TrustGeneration, 10)); err != nil {
		return executordb.PveRemote{}, fmt.Errorf("executor: pve repin: revoke grants: %w", err)
	}
	a.log().Info("pve remote re-pinned", "remote", in.RemoteID, "pin", pin, "gen", rm.TrustGeneration)
	return rm, nil
}

// ListRemotes returns the registry metadata of every remote. Secrets
// never leave the vault: the result carries opaque refs only.
func (a *PveAdmin) ListRemotes(ctx context.Context) ([]executordb.PveRemote, error) {
	if err := a.checkDB(); err != nil {
		return nil, err
	}
	return a.DB.ListRemotes()
}
