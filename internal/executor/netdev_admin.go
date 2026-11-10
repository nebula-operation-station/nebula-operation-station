// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Network device administration RPCs (ADR 0010 D1, D2; ND-11).
//
// Every method is admin-only through the role table (MethodRoles), exactly
// like the PVE admin methods; the peercred interceptor refuses every other
// caller before a handler runs.
//
// Lifecycle (ND-11 part 2):
//
//   - probe:    dial the checked private IP literal (DialAddr rules, a host
//     name is resolved once) and read the presented trust identity: the
//     SSH host key (CBS, the handshake stops at the host key callback) or
//     the TLS chain (PAN-OS, the handshake stops once the chain is
//     recorded). No user name, credential or request is ever sent.
//   - register: the admin types "yes" and the exact observed pin; the
//     endpoint is probed again and must present that pin; the device is
//     stored through the ND-10 registry.
//   - credential: the read credential is stored envelope-encrypted under
//     the device-scoped vault id netDevReadCredRef. Set creates version 1
//     only; rotate replaces exactly the expected version. A rotation
//     revokes every grant of the device: leases bind the credential version
//     (ADR 0010 D4), and the explicit revocation covers the rest.
//   - re-pin: a HIGH permit bound to the device, its trust generation, the
//     credential version and both pins; commit bumps the trust generation
//     and revokes every grant of the device.
//   - block / unblock / remove: block stops every dial and revokes grants;
//     unblock and remove need a typed "yes"; remove blocks, revokes,
//     deletes the device's vault entries and tombstones the id.
//
// Secrets arrive only in the request fields marked SECRET (secret bytes);
// the handlers wipe them on return and never put them, a user name or a
// vault reference into a reply, an error or a log line. Replies carry
// ids, endpoint, pins, trust generation and credential version only.
// Events (audit log records, which the executor's event chain handler
// signs) carry the action and the device id only.

// netDevRPCFailed is the fixed message of an internal failure: store and
// vault errors are not passed to the caller.
const netDevRPCFailed = "network device operation failed"

const (
	// netDevConfirmWord is the exact word the admin types to confirm.
	netDevConfirmWord = "yes"
	// netDevProbeTimeout bounds one credential-free probe (connect plus
	// handshake; ADR 0010 D3: 10 s connect).
	netDevProbeTimeout = 10 * time.Second
	// maxNetDevSecretBytes bounds a read credential (a PAN-OS API key, a
	// CBS password or an OpenSSH private key).
	maxNetDevSecretBytes = 16 << 10
	// maxNetDevUsernameBytes bounds the device account name.
	maxNetDevUsernameBytes = 64
	// maxNetDevBlockReason bounds an admin block reason (executordb CHECK).
	maxNetDevBlockReason = 512
	// maxNetDevProbeCerts bounds the presented TLS chain length.
	maxNetDevProbeCerts = 8
	// maxNetDevFactBytes bounds one untrusted probe fact string.
	maxNetDevFactBytes = 256
	// maxNetDevFactNames bounds the DNS SANs reported from a probe.
	maxNetDevFactNames = 16
	// netDevRepinAction is the reserved action id of a device re-pin.
	netDevRepinAction = "nebula.netdev.repin"
)

// netDevRepinArtifact is the fixed "script" of a device re-pin: nothing
// runs on the device; the bytes name the operation for the permit hash.
var netDevRepinArtifact = []byte("nebula.netdev.repin 1.0.0\nReplace the pinned trust identity of the network device and invalidate dependent authority.\n")

var (
	// ErrNetDevConfirm is returned when the typed confirmation is not
	// exactly "yes".
	ErrNetDevConfirm = errors.New("executor: network device operation needs the typed confirmation \"yes\"")
	// ErrNetDevPinMismatch is returned when the endpoint does not present
	// the pin the admin confirmed, or the stored pin is not the one named.
	ErrNetDevPinMismatch = errors.New("executor: network device trust identity does not match")
	// ErrNetDevProbe is returned when the endpoint could not be probed.
	ErrNetDevProbe = errors.New("executor: network device probe failed")
	// ErrNetDevHostKey is returned when the presented SSH host key is of a
	// type or size spec 08 does not accept.
	ErrNetDevHostKey = errors.New("executor: network device host key refused")
	// ErrNetDevCredentialRequest marks a malformed credential request.
	ErrNetDevCredentialRequest = errors.New("executor: invalid network device credential request")
	// ErrNetDevCredentialExists is returned when a read credential is
	// already stored; it is replaced only by an explicit rotation.
	ErrNetDevCredentialExists = errors.New("executor: the network device already has a read credential; rotate it")
	// ErrNetDevCredentialVersion is returned when the stored credential is
	// not at the version the rotation names.
	ErrNetDevCredentialVersion = errors.New("executor: the network device credential is not at the expected version")
	// ErrNetDevCredentialFormat is returned for a stored credential that
	// is not a read credential envelope.
	ErrNetDevCredentialFormat = errors.New("executor: stored network device credential is malformed")
	// ErrNetDevRepinApproval is returned when no approved permit covers
	// exactly this re-pin.
	ErrNetDevRepinApproval = errors.New("executor: network device re-pin requires an approved HIGH permit")
	// ErrNetDevRevoke is returned when dependent authority could not be
	// revoked; the device is then blocked.
	ErrNetDevRevoke = errors.New("executor: network device authority could not be revoked")
	// ErrNetDevConcurrentChange is returned when the device's trust state
	// changed between the approved re-pin binding and its commit.
	ErrNetDevConcurrentChange = errors.New("executor: network device trust state changed concurrently")
	// ErrNetDevNoStore is returned when the service has no executor
	// database or vault.
	ErrNetDevNoStore = errors.New("executor: network device registry has no store")
)

// errNetDevProbeDone aborts a TLS handshake once the chain is recorded.
var errNetDevProbeDone = errors.New("probe: chain recorded")

// netDevAdminMu serializes the network device lifecycle operations of the
// executor, so that, for example, a credential set cannot interleave with
// a removal that is deleting the device's vault entries.
var netDevAdminMu sync.Mutex

// NetDevDialFunc opens a TCP connection. Tests inject a loopback mapper;
// production uses net.Dialer. The address is always the checked IP literal
// of the device.
type NetDevDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NetDevAdminStore is the persistence the lifecycle needs
// (executordb.DB). PutSecret must write to the vault's database.
type NetDevAdminStore interface {
	NetDeviceStore
	BumpTrustGeneration(id, newPin string) (executordb.NetDevice, error)
	BlockNetDevice(id, reason string) (executordb.NetDevice, error)
	UnblockNetDevice(id string) (executordb.NetDevice, error)
	TombstoneNetDevice(id string) (executordb.NetDevice, error)
	ListSecrets() ([]executordb.VaultSecret, error)
}

// NetDevAdmin implements the admin-only network device lifecycle. It runs
// inside the executor; only the authenticated admin UID reaches it.
type NetDevAdmin struct {
	// Store is the executor database. Required.
	Store NetDevAdminStore
	// Vault is the executor vault backed by Store. Required for register,
	// credential and remove operations; it must be unlocked.
	Vault *vault.Vault
	// Resolve resolves a host name endpoint once. Nil refuses host names.
	Resolve NetDeviceResolver
	// Dial opens the probe connection. Nil uses net.Dialer.
	Dial NetDevDialFunc
	// Revoke revokes every grant that depends on the device's trust or
	// credential. Nil revokes nothing (no grants exist without it).
	Revoke func(deviceID, reason string) error
	// AuthorizeRepin consumes the approved permit of exactly this re-pin.
	// Nil refuses every re-pin.
	AuthorizeRepin func(ctx context.Context, b NetDevRepinBinding, digest string) error
	// Log receives non-secret audit events. Default: discarded.
	Log *slog.Logger
	// CommitLock, if set, is held by Register for its store step only; the
	// RPC handlers hold it around every other lifecycle operation. Register
	// is then called without holding it.
	CommitLock sync.Locker
}

func (a *NetDevAdmin) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return a.Log
}

// event records one audit event with the action and the device id only.
func (a *NetDevAdmin) event(action, deviceID string) {
	a.log().Info("audit", "kind", "netdev_admin", "action", action, "device", deviceID)
}

func (a *NetDevAdmin) checkStore() error {
	if a.Store == nil {
		return ErrNetDevNoStore
	}
	return nil
}

// checkVault requires an unlocked vault before any side effect.
func (a *NetDevAdmin) checkVault() error {
	if err := a.checkStore(); err != nil {
		return err
	}
	if a.Vault == nil {
		return ErrNetDevNoStore
	}
	st, err := a.Vault.State()
	if err != nil {
		return fmt.Errorf("executor: netdev vault state: %w", err)
	}
	if st != vault.StateUnlocked {
		return vault.ErrLocked
	}
	return nil
}

func (a *NetDevAdmin) registry() *NetDeviceRegistry {
	return &NetDeviceRegistry{Store: a.Store, Vault: a.Vault, Resolve: a.Resolve, Log: a.Log}
}

func (a *NetDevAdmin) dial() NetDevDialFunc {
	if a.Dial != nil {
		return a.Dial
	}
	var d net.Dialer
	return d.DialContext
}

// netDevRevokePendingReason is the block reason recorded when a revocation
// failed on an unblocked device (a rotation or a re-pin), so the admin
// sees why the device is blocked.
//
// The durable "revocation pending" state is the block itself: the store
// never rewrites the reason of a blocked device, so a device that was
// already blocked when its revocation failed keeps its earlier reason.
// Hence Block on a blocked device retries the revocation, and Unblock
// never lifts any block without a successful revocation in the same call:
// a failed revocation can never be undone by Unblock, whichever reason the
// block carries.
const netDevRevokePendingReason = "authority revocation failed; revocation pending"

// revoke revokes the device's dependent authority. If that fails the
// device is blocked (fail closed; with netDevRevokePendingReason if it was
// not blocked yet) and the error wraps ErrNetDevRevoke.
func (a *NetDevAdmin) revoke(id, reason string) error {
	if a.Revoke == nil {
		return nil
	}
	err := a.Revoke(id, reason)
	if err == nil {
		return nil
	}
	cause := fmt.Errorf("%w: %w", ErrNetDevRevoke, err)
	if _, berr := a.Store.BlockNetDevice(id, netDevRevokePendingReason); berr != nil && !errors.Is(berr, executordb.ErrNetDeviceState) {
		return errors.Join(cause, fmt.Errorf("block network device %s: %w", id, berr))
	}
	a.event("revoke_failed_blocked", id)
	return cause
}

// liveDevice loads a live (not tombstoned) device.
func (a *NetDevAdmin) liveDevice(id string) (executordb.NetDevice, error) {
	if !netdevcontract.ValidDeviceID(id) {
		return executordb.NetDevice{}, fmt.Errorf("%w: device id is malformed", ErrNetDeviceRequest)
	}
	d, ok, err := a.Store.GetNetDevice(id)
	if err != nil {
		return executordb.NetDevice{}, fmt.Errorf("load network device %s: %w", id, err)
	}
	if !ok {
		return executordb.NetDevice{}, fmt.Errorf("load network device %s: %w", id, executordb.ErrNetDeviceNotFound)
	}
	if d.TombstonedAt != nil {
		return executordb.NetDevice{}, fmt.Errorf("load network device %s: %w", id, executordb.ErrNetDeviceTombstoned)
	}
	return d, nil
}

// --- probe ---

// NetDevProbe is the result of a credential-free probe.
type NetDevProbe struct {
	// Addr is the probed private IP literal and port.
	Addr netip.AddrPort
	// ResolvedFrom is the host name the address was resolved from.
	ResolvedFrom string
	// PinKind is ssh-host-key (CBS) or tls-leaf (PAN-OS).
	PinKind netdevcontract.PinKind
	// Pin is the lowercase hex SHA-256 of the presented identity.
	Pin string
	// CAPin is the hex SHA-256 of a self-signed issuer in the presented
	// TLS chain, empty if none.
	CAPin string
	// Facts are bounded, printable untrusted facts for display.
	Facts *pb.NetDeviceProbeFacts
}

// pinFor returns the presented pin of kind, or false.
func (p NetDevProbe) pinFor(kind netdevcontract.PinKind) (string, bool) {
	switch kind {
	case p.PinKind:
		return p.Pin, p.Pin != ""
	case netdevcontract.PinTLSCA:
		return p.CAPin, p.PinKind == netdevcontract.PinTLSLeaf && p.CAPin != ""
	}
	return "", false
}

// resolveEndpoint checks family, port and endpoint and returns the checked
// address to dial, resolving a host name exactly once.
func (a *NetDevAdmin) resolveEndpoint(ctx context.Context, family netdevcontract.Family, endpoint string, port uint32) (netip.AddrPort, string, error) {
	if family != netdevcontract.FamilyCBS && family != netdevcontract.FamilyPANOS {
		return netip.AddrPort{}, "", fmt.Errorf("%w: unknown device family", ErrNetDeviceRequest)
	}
	if port == 0 || port > 65535 {
		return netip.AddrPort{}, "", fmt.Errorf("%w: port must be in 1..65535", ErrNetDeviceRequest)
	}
	var addr netip.Addr
	name := ""
	if lit, err := netip.ParseAddr(endpoint); err == nil {
		addr = lit
	} else {
		n, ok := normalizeNetDevName(endpoint)
		if !ok {
			return netip.AddrPort{}, "", fmt.Errorf("%w: endpoint is neither an IP literal nor a host name", ErrNetDeviceRequest)
		}
		name = n
		addr, err = a.registry().resolveOnce(ctx, name)
		if err != nil {
			return netip.AddrPort{}, "", err
		}
	}
	// The same rules as every credentialed dial: a canonical private
	// literal, re-checked here, never resolved again.
	ap, err := DialAddr(executordb.NetDevice{ID: "probe", EndpointIP: addr.String(), Port: uint16(port)})
	if err != nil {
		return netip.AddrPort{}, "", err
	}
	return ap, name, nil
}

// Probe reads the trust identity endpoint presents, without sending a
// user name, a credential or a request.
func (a *NetDevAdmin) Probe(ctx context.Context, family netdevcontract.Family, endpoint string, port uint32) (NetDevProbe, error) {
	ap, name, err := a.resolveEndpoint(ctx, family, endpoint, port)
	if err != nil {
		return NetDevProbe{}, err
	}
	p, err := a.probeAddr(ctx, family, ap)
	if err != nil {
		return NetDevProbe{}, err
	}
	p.ResolvedFrom = name
	return p, nil
}

// probeAddr probes an already checked address.
func (a *NetDevAdmin) probeAddr(ctx context.Context, family netdevcontract.Family, ap netip.AddrPort) (NetDevProbe, error) {
	switch family {
	case netdevcontract.FamilyCBS:
		return a.probeSSH(ctx, ap)
	case netdevcontract.FamilyPANOS:
		return a.probeTLS(ctx, ap)
	default:
		return NetDevProbe{}, fmt.Errorf("%w: unknown device family", ErrNetDeviceRequest)
	}
}

// probeSSH reads the host key through sshtransport.Config.Probe, which
// aborts the handshake in the host key callback: no user name and no
// credential is sent.
func (a *NetDevAdmin) probeSSH(ctx context.Context, ap netip.AddrPort) (NetDevProbe, error) {
	cfg := sshtransport.Config{ConnectTimeout: netDevProbeTimeout, DialContext: a.dial()}
	key, err := cfg.Probe(ctx, sshtransport.Endpoint{Host: ap.Addr().String(), Port: ap.Port()})
	if err != nil {
		if sshtransport.ClassOf(err) == sshtransport.ClassInvalid {
			return NetDevProbe{}, fmt.Errorf("probe %s: %w", ap, ErrNetDevHostKey)
		}
		return NetDevProbe{}, fmt.Errorf("probe %s: %w", ap, ErrNetDevProbe)
	}
	return NetDevProbe{
		Addr:    ap,
		PinKind: netdevcontract.PinSSHHostKey,
		Pin:     netDevSSHPin(key),
		Facts:   &pb.NetDeviceProbeFacts{SshHostKeyType: netDevFact(key.Type())},
	}, nil
}

// netDevSSHPin is the hex SHA-256 of the host key in wire format.
func netDevSSHPin(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return hex.EncodeToString(sum[:])
}

// probeTLS is the unpinned first contact of a PAN-OS endpoint: it records
// the presented chain in the verification callback and aborts the
// handshake there, so no HTTP request, header or API key is ever sent.
// Trust comes only from the pin the admin confirms afterwards; every
// credentialed connection uses the pinned panapi client.
func (a *NetDevAdmin) probeTLS(ctx context.Context, ap netip.AddrPort) (NetDevProbe, error) {
	ctx, cancel := context.WithTimeout(ctx, netDevProbeTimeout)
	defer cancel()
	raw, err := a.dial()(ctx, "tcp", ap.String())
	if err != nil {
		return NetDevProbe{}, fmt.Errorf("probe %s: %w", ap, ErrNetDevProbe)
	}
	defer raw.Close()
	var chain []*x509.Certificate
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // first contact records the chain only; trust is the confirmed pin
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || len(rawCerts) > maxNetDevProbeCerts {
				return errors.New("presented chain length out of range")
			}
			for _, der := range rawCerts {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return errors.New("presented certificate unparseable")
				}
				chain = append(chain, c)
			}
			return errNetDevProbeDone
		},
	})
	_ = conn.HandshakeContext(ctx)
	if len(chain) == 0 {
		return NetDevProbe{}, fmt.Errorf("probe %s: %w", ap, ErrNetDevProbe)
	}
	leaf := chain[0]
	sum := sha256.Sum256(leaf.Raw)
	out := NetDevProbe{Addr: ap, PinKind: netdevcontract.PinTLSLeaf, Pin: hex.EncodeToString(sum[:])}
	facts := &pb.NetDeviceProbeFacts{TlsSubject: netDevFact(leaf.Subject.String()), TlsNotAfterUnix: leaf.NotAfter.Unix()}
	for _, n := range leaf.DNSNames {
		if len(facts.TlsDnsNames) == maxNetDevFactNames {
			break
		}
		facts.TlsDnsNames = append(facts.TlsDnsNames, netDevFact(n))
	}
	if ca := netDevChainCA(chain); ca != nil {
		sum := sha256.Sum256(ca.Raw)
		out.CAPin = hex.EncodeToString(sum[:])
		facts.TlsCaFingerprint = out.CAPin
	}
	out.Facts = facts
	return out, nil
}

// netDevChainCA returns the self-signed certificate of the presented chain
// that anchors the leaf, or nil. A candidate (outermost first) must carry
// a valid self-signature, and every element from the leaf up to it must be
// signed by the next one (CheckSignatureFrom: the signer must be a CA), so
// an unrelated self-signed certificate appended by the endpoint is never
// offered as the CA pin. A self-signed leaf alone is its own anchor.
func netDevChainCA(chain []*x509.Certificate) *x509.Certificate {
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		if string(c.RawIssuer) != string(c.RawSubject) || c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
			continue
		}
		linked := true
		for j := 0; j < i; j++ {
			if chain[j].CheckSignatureFrom(chain[j+1]) != nil {
				linked = false
				break
			}
		}
		if linked {
			return c
		}
	}
	return nil
}

// netDevFact renders an untrusted device string as bounded printable
// text: invalid UTF-8 and non-printable runes become '?', and the result
// is cut to maxNetDevFactBytes on a rune boundary.
func netDevFact(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		if !unicode.IsPrint(r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > maxNetDevFactBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// --- register ---

// NetDevRegister is an admin's confirmed registration.
type NetDevRegister struct {
	DeviceID     string
	Family       netdevcontract.Family
	Label        string
	Endpoint     string
	Port         uint32
	PinKind      netdevcontract.PinKind
	ConfirmedPin string
	// Confirm must be exactly "yes".
	Confirm string
	By      string
}

// Register stores a device after the typed confirmation, only if the
// endpoint presents exactly the confirmed pin now. Nothing is stored and
// no vault entry remains on any failure.
//
// Name resolution and the probe (up to netDevProbeTimeout) run without
// CommitLock; it is taken only for the re-checked store step, so a slow
// endpoint never stalls the other lifecycle operations.
func (a *NetDevAdmin) Register(ctx context.Context, in NetDevRegister) (executordb.NetDevice, error) {
	if in.Confirm != netDevConfirmWord {
		return executordb.NetDevice{}, ErrNetDevConfirm
	}
	if err := a.checkVault(); err != nil {
		return executordb.NetDevice{}, err
	}
	if !netdevcontract.ValidDeviceID(in.DeviceID) {
		return executordb.NetDevice{}, fmt.Errorf("%w: device id is malformed", ErrNetDeviceRequest)
	}
	if !netdevcontract.ValidTrustPin(in.ConfirmedPin) {
		return executordb.NetDevice{}, fmt.Errorf("%w: trust pin is not a lowercase hex SHA-256", ErrNetDeviceRequest)
	}
	if err := a.registerFree(in.DeviceID); err != nil {
		return executordb.NetDevice{}, err
	}
	ap, name, err := a.resolveEndpoint(ctx, in.Family, in.Endpoint, in.Port)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	label := in.Label
	if name != "" {
		if label != "" && label != name {
			return executordb.NetDevice{}, fmt.Errorf("%w: for a host name endpoint the label is the name", ErrNetDeviceRequest)
		}
		label = name
	}
	probe, err := a.probeAddr(ctx, in.Family, ap)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if pin, ok := probe.pinFor(in.PinKind); !ok || pin != in.ConfirmedPin {
		return executordb.NetDevice{}, fmt.Errorf("register network device %s: %w", in.DeviceID, ErrNetDevPinMismatch)
	}
	if a.CommitLock != nil {
		a.CommitLock.Lock()
		defer a.CommitLock.Unlock()
	}
	// Re-check under the lock: the vault may have been locked and the id
	// taken while the probe ran.
	if err := a.checkVault(); err != nil {
		return executordb.NetDevice{}, err
	}
	if err := a.registerFree(in.DeviceID); err != nil {
		return executordb.NetDevice{}, err
	}
	dev, err := a.registry().RegisterNetDevice(ctx, NetDeviceRegistration{
		DeviceID: in.DeviceID, Family: in.Family, Label: label, Endpoint: ap.Addr().String(),
		Port: ap.Port(), PinKind: in.PinKind, Pin: in.ConfirmedPin, By: in.By,
	})
	if err != nil {
		return executordb.NetDevice{}, err
	}
	a.event("registered", dev.ID)
	return dev, nil
}

// registerFree refuses an id that is live or tombstoned.
func (a *NetDevAdmin) registerFree(id string) error {
	if _, ok, err := a.Store.GetNetDevice(id); err != nil {
		return fmt.Errorf("register network device %s: %w", id, err)
	} else if ok {
		return fmt.Errorf("register network device %s: %w", id, executordb.ErrNetDeviceExists)
	}
	return nil
}

// --- credentials ---

// netDevCredMagic starts every stored read credential envelope.
const netDevCredMagic = "ndc1"

// netDevPurposeRead tags a read credential envelope. A change credential
// (ADR 0010 D5, phase 2) would get its own tag and vault id; a reader
// opens only the purpose it asks for.
const netDevPurposeRead byte = 'r'

// netDevReadCredRef returns the device-scoped vault id of the read
// credential: the row's credential reference if one is set, otherwise
// "netdev-<scope>-rc" with the same scoping as netDevKeyRefs. The suffix
// differs from the key suffixes, so it never names another device's key.
func netDevReadCredRef(d executordb.NetDevice) string {
	if d.CredentialRef != "" {
		return d.CredentialRef
	}
	dk, _ := netDevKeyRefs(d.ID)
	return strings.TrimSuffix(dk, "-dk") + "-rc"
}

// encodeNetDevCredential builds the vault value: magic, purpose, user
// name length and user name, then the secret. The caller wipes it.
func encodeNetDevCredential(purpose byte, username string, secret []byte) []byte {
	out := make([]byte, 0, len(netDevCredMagic)+3+len(username)+len(secret))
	out = append(out, netDevCredMagic...)
	out = append(out, purpose)
	out = binary.BigEndian.AppendUint16(out, uint16(len(username)))
	out = append(out, username...)
	return append(out, secret...)
}

// decodeNetDevCredential splits a vault value of the given purpose into
// user name and secret. The secret aliases value.
func decodeNetDevCredential(purpose byte, value []byte) (string, []byte, error) {
	h := len(netDevCredMagic) + 3
	if len(value) < h || string(value[:len(netDevCredMagic)]) != netDevCredMagic || value[len(netDevCredMagic)] != purpose {
		return "", nil, ErrNetDevCredentialFormat
	}
	n := int(binary.BigEndian.Uint16(value[len(netDevCredMagic)+1:]))
	if n > maxNetDevUsernameBytes || len(value) < h+n+1 {
		return "", nil, ErrNetDevCredentialFormat
	}
	return string(value[h : h+n]), value[h+n:], nil
}

// checkNetDevCredential validates a credential request.
func checkNetDevCredential(username string, secret []byte) error {
	if len(secret) == 0 || len(secret) > maxNetDevSecretBytes {
		return fmt.Errorf("%w: secret must be 1..%d bytes", ErrNetDevCredentialRequest, maxNetDevSecretBytes)
	}
	if username != "" && !validNetDevText(username, maxNetDevUsernameBytes) {
		return fmt.Errorf("%w: user name is not printable UTF-8 of at most %d bytes", ErrNetDevCredentialRequest, maxNetDevUsernameBytes)
	}
	return nil
}

// credentialVersion returns the vault version of ref, 0 if absent. It
// reads metadata only.
func (a *NetDevAdmin) credentialVersion(ref string) (int64, error) {
	rows, err := a.Store.ListSecrets()
	if err != nil {
		return 0, fmt.Errorf("credential version: %w", err)
	}
	for _, r := range rows {
		if r.ID == ref {
			return r.Version, nil
		}
	}
	return 0, nil
}

// NetDevCredential is one credential set or rotation. Secret is never
// copied into anything but the sealed vault value.
type NetDevCredential struct {
	DeviceID string
	Username string
	Secret   []byte
	// ExpectedVersion is the version a rotation replaces; 0 for a set.
	ExpectedVersion int64
	By              string
}

// SetCredential stores the first read credential of a live device as
// vault version 1. An existing entry is never adopted or overwritten.
func (a *NetDevAdmin) SetCredential(ctx context.Context, in NetDevCredential) (executordb.NetDevice, int64, error) {
	in.ExpectedVersion = 0
	return a.putCredential(ctx, in, "credential_set")
}

// RotateCredential replaces the read credential at exactly
// ExpectedVersion and revokes every grant of the device.
func (a *NetDevAdmin) RotateCredential(ctx context.Context, in NetDevCredential) (executordb.NetDevice, int64, error) {
	if in.ExpectedVersion < 1 {
		return executordb.NetDevice{}, 0, fmt.Errorf("%w: expected credential version must be at least 1", ErrNetDevCredentialRequest)
	}
	return a.putCredential(ctx, in, "credential_rotated")
}

func (a *NetDevAdmin) putCredential(ctx context.Context, in NetDevCredential, action string) (executordb.NetDevice, int64, error) {
	if err := ctx.Err(); err != nil {
		return executordb.NetDevice{}, 0, err
	}
	if err := checkNetDevCredential(in.Username, in.Secret); err != nil {
		return executordb.NetDevice{}, 0, err
	}
	if !validNetDevText(in.By, maxNetDevActorBytes) {
		return executordb.NetDevice{}, 0, fmt.Errorf("%w: actor is missing or malformed", ErrNetDevCredentialRequest)
	}
	if err := a.checkVault(); err != nil {
		return executordb.NetDevice{}, 0, err
	}
	dev, err := a.liveDevice(in.DeviceID)
	if err != nil {
		return executordb.NetDevice{}, 0, err
	}
	ref := netDevReadCredRef(dev)
	value := encodeNetDevCredential(netDevPurposeRead, in.Username, in.Secret)
	defer clear(value)
	want := in.ExpectedVersion + 1
	version, err := a.Vault.PutWithCommit(ref, value, in.By, func(s executordb.VaultSecret) error {
		switch {
		case s.Version != want && in.ExpectedVersion == 0:
			return ErrNetDevCredentialExists
		case s.Version != want:
			return ErrNetDevCredentialVersion
		}
		return a.Store.PutSecret(s)
	})
	if err != nil {
		return executordb.NetDevice{}, 0, fmt.Errorf("store credential of network device %s: %w", dev.ID, err)
	}
	a.event(action, dev.ID)
	if in.ExpectedVersion > 0 {
		if err := a.revoke(dev.ID, "network device credential rotated"); err != nil {
			return executordb.NetDevice{}, 0, err
		}
	}
	return dev, version, nil
}

// --- block, unblock, remove ---

// Block blocks every dial to a live device and revokes its grants. On a
// device that is already blocked it keeps the block and its reason and
// retries the revocation: any block may stand for a revocation that failed
// (its own, or one of a rotation or re-pin on the blocked device), so Block
// is the admin's retry and never refuses one.
func (a *NetDevAdmin) Block(_ context.Context, id, reason string) (executordb.NetDevice, error) {
	if err := a.checkStore(); err != nil {
		return executordb.NetDevice{}, err
	}
	if !validNetDevText(reason, maxNetDevBlockReason) {
		return executordb.NetDevice{}, fmt.Errorf("%w: block reason must be printable UTF-8 of 1..%d bytes", ErrNetDeviceRequest, maxNetDevBlockReason)
	}
	cur, err := a.liveDevice(id)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if cur.Blocked {
		if err := a.revoke(id, "network device blocked: retrying revocation"); err != nil {
			return executordb.NetDevice{}, err
		}
		a.event("revocation_retried", id)
		return cur, nil
	}
	dev, err := a.Store.BlockNetDevice(id, reason)
	if err != nil {
		return executordb.NetDevice{}, fmt.Errorf("block network device %s: %w", id, err)
	}
	a.event("blocked", id)
	if err := a.revoke(id, "network device blocked"); err != nil {
		return executordb.NetDevice{}, err
	}
	return dev, nil
}

// Unblock lifts a block after the typed confirmation. It first revokes
// the device's dependent authority and refuses (the device stays blocked)
// if that fails: a block may stand for a revocation that failed (see
// netDevRevokePendingReason), and lifting it must never make grants that
// were not revoked usable again.
func (a *NetDevAdmin) Unblock(_ context.Context, id, confirm string) (executordb.NetDevice, error) {
	if confirm != netDevConfirmWord {
		return executordb.NetDevice{}, ErrNetDevConfirm
	}
	if err := a.checkStore(); err != nil {
		return executordb.NetDevice{}, err
	}
	cur, err := a.liveDevice(id)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if !cur.Blocked {
		return executordb.NetDevice{}, fmt.Errorf("unblock network device %s: %w", id, executordb.ErrNetDeviceState)
	}
	if err := a.revoke(id, "network device unblocked: revoking authority issued before or during the block"); err != nil {
		return executordb.NetDevice{}, err
	}
	dev, err := a.Store.UnblockNetDevice(id)
	if err != nil {
		return executordb.NetDevice{}, fmt.Errorf("unblock network device %s: %w", id, err)
	}
	a.event("unblocked", id)
	return dev, nil
}

// Remove removes a device in the mandated order (ADR 0010 D2, as for PVE
// remotes): block, revoke dependent grants, delete the device's vault
// entries, tombstone the id. A locked vault refuses before any side
// effect; a failed step stops there with the device blocked, and a retry
// resumes (vault entries already deleted are skipped).
func (a *NetDevAdmin) Remove(_ context.Context, id, confirm string) (executordb.NetDevice, error) {
	if confirm != netDevConfirmWord {
		return executordb.NetDevice{}, ErrNetDevConfirm
	}
	if err := a.checkVault(); err != nil {
		return executordb.NetDevice{}, err
	}
	dev, err := a.liveDevice(id)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if !dev.Blocked {
		if _, err := a.Store.BlockNetDevice(id, "device removed: disabling and revoking authority"); err != nil {
			return executordb.NetDevice{}, fmt.Errorf("remove network device %s: block: %w", id, err)
		}
	}
	if err := a.revoke(id, "network device removed"); err != nil {
		return executordb.NetDevice{}, err
	}
	for _, ref := range []string{netDevReadCredRef(dev), dev.DigestKeyRef, dev.FingerprintKeyRef} {
		if err := a.Vault.Delete(ref); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return executordb.NetDevice{}, fmt.Errorf("remove network device %s: delete vault entry: %w", id, err)
		}
	}
	out, err := a.Store.TombstoneNetDevice(id)
	if err != nil {
		return executordb.NetDevice{}, fmt.Errorf("remove network device %s: tombstone: %w", id, err)
	}
	a.event("removed", id)
	return out, nil
}

// --- re-pin ---

// NetDevRepinBinding is everything a re-pin permit binds: the device's
// current trust state, its credential version and the new pin.
type NetDevRepinBinding struct {
	DeviceID          string                 `json:"device_id"`
	Family            netdevcontract.Family  `json:"family"`
	EndpointIP        string                 `json:"endpoint_ip"`
	Port              uint16                 `json:"port"`
	PinKind           netdevcontract.PinKind `json:"pin_kind"`
	OldPin            string                 `json:"old_pin"`
	NewPin            string                 `json:"new_pin"`
	TrustGeneration   uint64                 `json:"trust_generation"`
	CredentialVersion int64                  `json:"credential_version"`
	// credRef is the vault id the permit names; not part of the JSON.
	credRef string
}

// params returns the canonical permit parameters and target.
func (b NetDevRepinBinding) params() ([]byte, canonical.Target, error) {
	params, err := json.Marshal(b)
	if err != nil {
		return nil, canonical.Target{}, err
	}
	fp, err := hex.DecodeString(b.OldPin)
	if err != nil || len(fp) != sha256.Size {
		return nil, canonical.Target{}, ErrNetDevRepinApproval
	}
	return params, canonical.Target{HostID: netDevRepinTarget(b.DeviceID), HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp)}, nil
}

// netDevRepinTarget is the permit host id of a device re-pin.
func netDevRepinTarget(id string) string {
	dk, _ := netDevKeyRefs(id)
	return strings.TrimSuffix(dk, "-dk") + "-trust"
}

// RepinBinding probes the device credential-free and returns the binding
// of a re-pin from oldPin to newPin. The stored pin must be oldPin and the
// endpoint must present newPin now. A blocked device may be probed: re-pin
// is the way out of a pin-mismatch block.
func (a *NetDevAdmin) RepinBinding(ctx context.Context, id, oldPin, newPin string) (NetDevRepinBinding, error) {
	if err := a.checkStore(); err != nil {
		return NetDevRepinBinding{}, err
	}
	dev, err := a.liveDevice(id)
	if err != nil {
		return NetDevRepinBinding{}, err
	}
	if dev.PinValue != oldPin || !netdevcontract.ValidTrustPin(newPin) || newPin == oldPin {
		return NetDevRepinBinding{}, fmt.Errorf("re-pin network device %s: %w", id, ErrNetDevPinMismatch)
	}
	probeDev := dev
	probeDev.Blocked, probeDev.BlockReason = false, ""
	ap, err := DialAddr(probeDev)
	if err != nil {
		return NetDevRepinBinding{}, err
	}
	probe, err := a.probeAddr(ctx, dev.Family, ap)
	if err != nil {
		return NetDevRepinBinding{}, err
	}
	if pin, ok := probe.pinFor(dev.PinKind); !ok || pin != newPin {
		return NetDevRepinBinding{}, fmt.Errorf("re-pin network device %s: %w", id, ErrNetDevPinMismatch)
	}
	ref := netDevReadCredRef(dev)
	version, err := a.credentialVersion(ref)
	if err != nil {
		return NetDevRepinBinding{}, err
	}
	return NetDevRepinBinding{
		DeviceID: dev.ID, Family: dev.Family, EndpointIP: dev.EndpointIP, Port: dev.Port, PinKind: dev.PinKind,
		OldPin: oldPin, NewPin: newPin, TrustGeneration: dev.TrustGeneration, CredentialVersion: version, credRef: ref,
	}, nil
}

// Repin re-pins a device under the approved permit digest: the binding is
// rebuilt from the current record and a fresh probe, the permit is
// consumed, the trust generation is bumped and every grant is revoked. A
// block is kept; lifting it is a separate Unblock.
func (a *NetDevAdmin) Repin(ctx context.Context, id, oldPin, newPin, digest string) (executordb.NetDevice, error) {
	if a.AuthorizeRepin == nil {
		return executordb.NetDevice{}, ErrNetDevRepinApproval
	}
	b, err := a.RepinBinding(ctx, id, oldPin, newPin)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if err := a.AuthorizeRepin(ctx, b, digest); err != nil {
		return executordb.NetDevice{}, fmt.Errorf("re-pin network device %s: %w", id, ErrNetDevRepinApproval)
	}
	// The permit binds the trust generation and the old pin. The store's
	// bump compares the generation it loads itself, not the bound one, so
	// the bound state is compared here right before the bump, and the
	// bump's result is checked to be exactly one generation on from it. A
	// change in between (another writer than this process's lifecycle
	// lock covers) is caught after the fact and fails closed: the device
	// is blocked and its authority revoked.
	cur, err := a.liveDevice(id)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if !repinBindingCurrent(b, cur) {
		return executordb.NetDevice{}, fmt.Errorf("re-pin network device %s: %w", id, ErrNetDevConcurrentChange)
	}
	dev, err := a.Store.BumpTrustGeneration(id, newPin)
	if err != nil {
		return executordb.NetDevice{}, fmt.Errorf("re-pin network device %s: %w", id, err)
	}
	if dev.TrustGeneration != b.TrustGeneration+1 || dev.PinValue != newPin || dev.PinKind != b.PinKind {
		cause := fmt.Errorf("re-pin network device %s: %w", id, ErrNetDevConcurrentChange)
		a.event("repin_raced_blocked", id)
		if _, berr := a.Store.BlockNetDevice(id, "concurrent trust change during re-pin"); berr != nil && !errors.Is(berr, executordb.ErrNetDeviceState) {
			cause = errors.Join(cause, fmt.Errorf("block network device %s: %w", id, berr))
		}
		if rerr := a.revoke(id, "network device re-pin raced a concurrent trust change"); rerr != nil {
			return executordb.NetDevice{}, errors.Join(cause, rerr)
		}
		return executordb.NetDevice{}, cause
	}
	a.event("repinned", id)
	if err := a.revoke(id, "network device re-pinned"); err != nil {
		return executordb.NetDevice{}, err
	}
	return dev, nil
}

// repinBindingCurrent reports whether the stored device is still exactly
// in the trust state the re-pin permit binds.
func repinBindingCurrent(b NetDevRepinBinding, d executordb.NetDevice) bool {
	return d.ID == b.DeviceID && d.Family == b.Family && d.EndpointIP == b.EndpointIP && d.Port == b.Port &&
		d.PinKind == b.PinKind && d.PinValue == b.OldPin && d.TrustGeneration == b.TrustGeneration
}

// --- RPC wiring ---

// netDevAdmin builds the lifecycle over the service's database, vault,
// permit authority and transport dialer.
func (s *Service) netDevAdmin() *NetDevAdmin {
	a := &NetDevAdmin{Resolve: DefaultNetDeviceResolver, Dial: s.transport.DialContext, Log: s.log, CommitLock: &netDevAdminMu}
	if s.db != nil {
		a.Store = s.db
	}
	if s.vault != nil {
		a.Vault = s.vault
	}
	if s.auth != nil {
		a.Revoke = func(id, reason string) error {
			_, err := s.auth.RevokeProviderGrants(id, reason)
			return err
		}
		a.AuthorizeRepin = s.authorizeNetDevRepin
	}
	return a
}

func (s *Service) authorizeNetDevRepin(_ context.Context, b NetDevRepinBinding, digest string) error {
	d, err := canonical.ParseDigest(digest)
	if err != nil {
		return ErrNetDevRepinApproval
	}
	params, target, err := b.params()
	if err != nil {
		return ErrNetDevRepinApproval
	}
	if _, err := s.auth.AuthorizeGrant(d, permit.Run{HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint,
		ActionID: netDevRepinAction, ModuleVersion: repinVersion, Artifact: netDevRepinArtifact, ParametersJSON: params,
		CredentialRef: b.credRef}); err != nil {
		return ErrNetDevRepinApproval
	}
	return nil
}

// netDevRefRe matches a vault reference in an error text.
var netDevRefRe = regexp.MustCompile(`netdev-[a-z0-9_-]+`)

// netDevRPCError maps a lifecycle error to a fixed status text and logs
// the error with vault references masked. No store, vault or device text
// reaches the caller.
func (s *Service) netDevRPCError(method string, err error) error {
	code, msg := codes.Internal, netDevRPCFailed
	switch {
	case errors.Is(err, ErrNetDevRevoke):
		// First: whatever else the error wraps, the admin must learn that
		// authority is not revoked and the device stays blocked.
		code, msg = codes.Internal, "network device authority could not be revoked; the device is blocked"
	case errors.Is(err, ErrNetDevConcurrentChange):
		code, msg = codes.Aborted, "network device trust state changed concurrently; the device is blocked if the change was committed"
	case errors.Is(err, ErrNetDevConfirm):
		code, msg = codes.InvalidArgument, "confirmation must be exactly \"yes\""
	case errors.Is(err, ErrNetDevCredentialRequest):
		code, msg = codes.InvalidArgument, "invalid network device credential request"
	case errors.Is(err, ErrNetDeviceAddress):
		code, msg = codes.InvalidArgument, "network device address refused: a private IP literal is required"
	case errors.Is(err, ErrNetDeviceResolve):
		code, msg = codes.InvalidArgument, "network device name did not resolve to exactly one address"
	case errors.Is(err, ErrNetDeviceRequest), errors.Is(err, executordb.ErrInvalid):
		code, msg = codes.InvalidArgument, "invalid network device request"
	case errors.Is(err, ErrNetDevPinMismatch):
		code, msg = codes.FailedPrecondition, "network device trust identity does not match"
	case errors.Is(err, ErrNetDevHostKey):
		code, msg = codes.FailedPrecondition, "network device host key type or size is not accepted"
	case errors.Is(err, ErrNetDevProbe):
		code, msg = codes.Unavailable, "network device endpoint could not be probed"
	case errors.Is(err, ErrNetDevRepinApproval):
		code, msg = codes.FailedPrecondition, "network device re-pin requires an approved HIGH permit for exactly this change"
	case errors.Is(err, vault.ErrLocked):
		code, msg = codes.FailedPrecondition, "network device operation requires an unlocked vault"
	case errors.Is(err, executordb.ErrNetDeviceNotFound), errors.Is(err, executordb.ErrNetDeviceTombstoned):
		code, msg = codes.NotFound, "network device not found"
	case errors.Is(err, ErrNetDevCredentialExists):
		code, msg = codes.AlreadyExists, "network device already has a read credential; rotate it"
	case errors.Is(err, executordb.ErrNetDeviceExists), errors.Is(err, ErrNetDeviceKeyExists):
		code, msg = codes.AlreadyExists, "network device already exists"
	case errors.Is(err, ErrDuplicateTrustIdentity), errors.Is(err, executordb.ErrNetTrustIdentityInUse):
		code, msg = codes.AlreadyExists, "trust identity already registered for another network device"
	case errors.Is(err, ErrNetDevCredentialVersion), errors.Is(err, vault.ErrConcurrentChange):
		code, msg = codes.Aborted, "network device credential is not at the expected version"
	case errors.Is(err, executordb.ErrNetDeviceState):
		code, msg = codes.FailedPrecondition, "network device is not in the required block state"
	}
	if s.log != nil && (code == codes.Internal || code == codes.Aborted) {
		s.log.Error("netdev: "+method+" failed", "error", maskNetDevRefs(err))
	}
	return status.Error(code, msg)
}

// maskNetDevRefs renders err for a log line with every vault reference
// replaced.
func maskNetDevRefs(err error) string {
	return netDevRefRe.ReplaceAllString(err.Error(), "<vault-ref>")
}

func (s *Service) netDevInfo(a *NetDevAdmin, d executordb.NetDevice) *pb.NetDeviceInfo {
	// The version is display metadata; a failed read shows 0.
	v, _ := a.credentialVersion(netDevReadCredRef(d))
	return netDeviceInfo(d, v)
}

// ProbeNetDevice probes a device endpoint without credentials and returns
// the presented pin for the admin to confirm.
func (s *Service) ProbeNetDevice(ctx context.Context, in *pb.ProbeNetDeviceRequest) (*pb.ProbeNetDeviceResponse, error) {
	p, err := s.netDevAdmin().Probe(ctx, netdevcontract.Family(in.GetFamily()), in.GetEndpoint(), in.GetPort())
	if err != nil {
		return nil, s.netDevRPCError("probe", err)
	}
	return &pb.ProbeNetDeviceResponse{EndpointIp: p.Addr.Addr().String(), Port: uint32(p.Addr.Port()), ResolvedFrom: p.ResolvedFrom,
		PinKind: string(p.PinKind), ObservedPin: p.Pin, Facts: p.Facts}, nil
}

// RegisterNetDevice registers a probed device in the ND-10 registry after
// the typed "yes", only if the endpoint presents the confirmed pin.
func (s *Service) RegisterNetDevice(ctx context.Context, in *pb.RegisterNetDeviceRequest) (*pb.RegisterNetDeviceResponse, error) {
	// Not locked here: Register probes first and holds CommitLock
	// (netDevAdminMu) only for its re-checked store step.
	a := s.netDevAdmin()
	d, err := a.Register(ctx, NetDevRegister{DeviceID: in.GetDeviceId(), Family: netdevcontract.Family(in.GetFamily()), Label: in.GetLabel(),
		Endpoint: in.GetEndpoint(), Port: in.GetPort(), PinKind: netdevcontract.PinKind(in.GetPinKind()),
		ConfirmedPin: in.GetConfirmedPin(), Confirm: in.GetConfirm(), By: callerName(ctx)})
	if err != nil {
		return nil, s.netDevRPCError("register", err)
	}
	return &pb.RegisterNetDeviceResponse{Device: s.netDevInfo(a, d)}, nil
}

// SetNetDeviceCredential stores a device's first read credential. The
// secret buffer is wiped on return.
func (s *Service) SetNetDeviceCredential(ctx context.Context, in *pb.SetNetDeviceCredentialRequest) (*pb.SetNetDeviceCredentialResponse, error) {
	defer clear(in.GetSecret())
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	a := s.netDevAdmin()
	d, v, err := a.SetCredential(ctx, NetDevCredential{DeviceID: in.GetDeviceId(), Username: in.GetUsername(), Secret: in.GetSecret(), By: callerName(ctx)})
	if err != nil {
		return nil, s.netDevRPCError("set credential", err)
	}
	return &pb.SetNetDeviceCredentialResponse{Device: netDeviceInfo(d, v)}, nil
}

// RotateNetDeviceCredential replaces a device read credential at the
// expected version and revokes the device's grants. The secret buffer is
// wiped on return.
func (s *Service) RotateNetDeviceCredential(ctx context.Context, in *pb.RotateNetDeviceCredentialRequest) (*pb.RotateNetDeviceCredentialResponse, error) {
	defer clear(in.GetSecret())
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	a := s.netDevAdmin()
	d, v, err := a.RotateCredential(ctx, NetDevCredential{DeviceID: in.GetDeviceId(), Username: in.GetUsername(), Secret: in.GetSecret(),
		ExpectedVersion: in.GetExpectedCredentialVersion(), By: callerName(ctx)})
	if err != nil {
		return nil, s.netDevRPCError("rotate credential", err)
	}
	return &pb.RotateNetDeviceCredentialResponse{Device: netDeviceInfo(d, v)}, nil
}

// ProposeNetDeviceRepin proposes a re-pin and returns a HIGH permit bound
// to the device, its trust generation, its credential version and both
// pins (ADR 0010 D1, mirroring ProposePVERepin). The probe sends no
// credential.
func (s *Service) ProposeNetDeviceRepin(ctx context.Context, in *pb.ProposeNetDeviceRepinRequest) (*pb.ProposeNetDeviceRepinResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	if s.auth == nil {
		return nil, s.netDevRPCError("propose re-pin", ErrNetDevRepinApproval)
	}
	b, err := s.netDevAdmin().RepinBinding(ctx, in.GetDeviceId(), in.GetOldPin(), in.GetConfirmedNewPin())
	if err != nil {
		return nil, s.netDevRPCError("propose re-pin", err)
	}
	params, target, err := b.params()
	if err != nil {
		return nil, s.netDevRPCError("propose re-pin", err)
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return nil, s.netDevRPCError("propose re-pin", err)
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, s.netDevRPCError("propose re-pin", err)
	}
	rq := canonical.Request{ExecutionID: id, ActionID: netDevRepinAction, ModuleVersion: repinVersion, ArtifactSHA256: sha256Hex(netDevRepinArtifact),
		ParametersHash: ph, CredentialRefs: []string{b.credRef}, RiskClass: canonical.RiskHigh, StagePlanHash: stagePlanRepin,
		ExpiryUnix: s.clock().Add(repinLifetime).Unix(), ResolvedTargets: []canonical.Target{target}}
	res, err := s.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return nil, toStatus(err)
	}
	out, err := s.permitResponse(res.Permit)
	if err != nil {
		return nil, err
	}
	return &pb.ProposeNetDeviceRepinResponse{Permit: out}, nil
}

// CommitNetDeviceRepin replaces a device trust pin only under the
// approved, unexpired permit of a matching proposal (mirroring
// CommitPVERepin): it bumps the trust generation and revokes the device's
// grants.
func (s *Service) CommitNetDeviceRepin(ctx context.Context, in *pb.CommitNetDeviceRepinRequest) (*pb.CommitNetDeviceRepinResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	a := s.netDevAdmin()
	d, err := a.Repin(ctx, in.GetDeviceId(), in.GetOldPin(), in.GetConfirmedNewPin(), in.GetExecutionDigest())
	if err != nil {
		return nil, s.netDevRPCError("commit re-pin", err)
	}
	return &pb.CommitNetDeviceRepinResponse{Device: s.netDevInfo(a, d)}, nil
}

// BlockNetDevice blocks every dial to a device and revokes its grants.
func (s *Service) BlockNetDevice(ctx context.Context, in *pb.BlockNetDeviceRequest) (*pb.BlockNetDeviceResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	a := s.netDevAdmin()
	d, err := a.Block(ctx, in.GetDeviceId(), in.GetReason())
	if err != nil {
		return nil, s.netDevRPCError("block", err)
	}
	return &pb.BlockNetDeviceResponse{Device: s.netDevInfo(a, d)}, nil
}

// UnblockNetDevice lifts a device block after the typed "yes".
func (s *Service) UnblockNetDevice(ctx context.Context, in *pb.UnblockNetDeviceRequest) (*pb.UnblockNetDeviceResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	a := s.netDevAdmin()
	d, err := a.Unblock(ctx, in.GetDeviceId(), in.GetConfirm())
	if err != nil {
		return nil, s.netDevRPCError("unblock", err)
	}
	return &pb.UnblockNetDeviceResponse{Device: s.netDevInfo(a, d)}, nil
}

// RemoveNetDevice blocks a device, revokes its grants, deletes its vault
// entries and tombstones it, after the typed "yes".
func (s *Service) RemoveNetDevice(ctx context.Context, in *pb.RemoveNetDeviceRequest) (*pb.RemoveNetDeviceResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	d, err := s.netDevAdmin().Remove(ctx, in.GetDeviceId(), in.GetConfirm())
	if err != nil {
		return nil, s.netDevRPCError("remove", err)
	}
	return &pb.RemoveNetDeviceResponse{Device: netDeviceInfo(d, 0)}, nil
}

// --- list ---

// ListNetDevices returns the metadata of every live registry device,
// ordered by id. A store error or an invalid registry row returns no
// devices. A device whose credential vault entry is missing (also one
// removed concurrently with the list) is still listed, flagged
// credential_missing, so the admin can see and remove it.
func (s *Service) ListNetDevices(ctx context.Context, _ *pb.ListNetDevicesRequest) (*pb.ListNetDevicesResponse, error) {
	if s.db == nil {
		return nil, s.netDevListFailed(ErrNetDevNoStore)
	}
	out, err := listNetDevices(ctx, s.db)
	if err != nil {
		return nil, s.netDevListFailed(err)
	}
	return out, nil
}

func (s *Service) netDevListFailed(err error) error {
	if s.log != nil {
		s.log.Error("netdev: list failed", "error", maskNetDevRefs(err))
	}
	return status.Error(codes.Internal, netDevRPCFailed)
}

// netDevListStore is everything the list path may read. It deliberately
// has no GetSecret: credential versions come from the blob-free
// ListSecrets, so no wrapped data key or sealed value is ever loaded to
// answer a list.
type netDevListStore interface {
	ListNetDevices() ([]executordb.NetDevice, error)
	ListSecrets() ([]executordb.VaultSecret, error)
}

// listNetDevices reads the registry rows first and the vault versions
// second, each in one statement. A credential removed or rotated between
// the two reads therefore shows as missing or at its newer version; it
// never fails the list. The registry rows stay authoritative: a vault
// entry without a live device is not listed. A device without a
// credential reference on its row is looked up under its device-scoped
// read credential id; its absence there means "none enrolled", not
// missing.
func listNetDevices(ctx context.Context, store netDevListStore) (*pb.ListNetDevicesResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := store.ListNetDevices()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secrets, err := store.ListSecrets()
	if err != nil {
		return nil, fmt.Errorf("credential versions of network devices: %w", err)
	}
	versions := make(map[string]int64, len(secrets))
	for _, sec := range secrets {
		versions[sec.ID] = sec.Version
	}
	out := &pb.ListNetDevicesResponse{}
	for _, d := range rows {
		v, ok := versions[netDevReadCredRef(d)]
		info := netDeviceInfo(d, v)
		info.CredentialMissing = d.CredentialRef != "" && !ok
		out.Devices = append(out.Devices, info)
	}
	return out, nil
}

// netDeviceInfo is the reply form of a registry row. It deliberately
// leaves out the credential, digest and fingerprint key references.
func netDeviceInfo(d executordb.NetDevice, credentialVersion int64) *pb.NetDeviceInfo {
	return &pb.NetDeviceInfo{
		DeviceId:          d.ID,
		Family:            string(d.Family),
		Label:             d.Label,
		EndpointIp:        d.EndpointIP,
		Port:              uint32(d.Port),
		PinKind:           string(d.PinKind),
		TrustPin:          d.PinValue,
		TrustGeneration:   d.TrustGeneration,
		Blocked:           d.Blocked,
		BlockReason:       d.BlockReason,
		CredentialVersion: credentialVersion,
		CreatedAtUnix:     d.CreatedAt.Unix(),
		UpdatedAtUnix:     d.UpdatedAt.Unix(),
	}
}
