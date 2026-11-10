// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Network device registration (ADR 0010 D1, D2 and "Digest and fingerprint
// keys", ND-10). A device endpoint is stored and dialled as a private IP
// literal. A host name given at registration is resolved exactly once,
// here, and is kept only as the label; the dial path never resolves DNS
// and re-checks the stored literal every time, so neither a later DNS
// change nor a tampered row can redirect a credentialed connection.

var (
	// ErrNetDeviceRequest marks a malformed registration request.
	ErrNetDeviceRequest = errors.New("executor: invalid network device registration")
	// ErrNetDeviceAddress marks an endpoint address a device may not be
	// dialled at: not a canonical private (RFC 1918 or IPv6 ULA) literal.
	ErrNetDeviceAddress = errors.New("executor: network device address refused")
	// ErrNetDeviceResolve marks a host name that did not resolve to
	// exactly one address.
	ErrNetDeviceResolve = errors.New("executor: network device name did not resolve to exactly one address")
	// ErrNetDeviceKeyExists is returned when a vault entry for the
	// device's digest or fingerprint key already exists. It is never
	// adopted or overwritten: its origin is unknown.
	ErrNetDeviceKeyExists = errors.New("executor: a vault entry for the network device keys already exists")
	// ErrNetDeviceRollback is returned when a failed registration could
	// not delete the vault entries it had created. No device is stored;
	// the named entries must be removed by the admin.
	ErrNetDeviceRollback = errors.New("executor: network device registration could not roll back its vault entries")
	// ErrNetDeviceNotDialable is returned for a blocked or tombstoned
	// device.
	ErrNetDeviceNotDialable = errors.New("executor: network device is blocked or removed")
	// ErrDuplicateTrustIdentity is returned when the trust identity
	// (family, pin kind, pin) already belongs to another live device. It
	// wraps executordb.ErrNetTrustIdentityInUse.
	ErrDuplicateTrustIdentity = errors.New("executor: the trust identity is already registered for another network device")
)

const (
	// NetDeviceKeyBytes is the size of the per-device digest and
	// fingerprint keys.
	NetDeviceKeyBytes = 32
	// netDevResolveTimeout bounds the one name resolution at registration.
	netDevResolveTimeout = 10 * time.Second
	// maxNetDevNameBytes bounds a host name (RFC 1035).
	maxNetDevNameBytes = 253
	// maxNetDevNameLabel bounds one label of a host name (RFC 1035).
	maxNetDevNameLabel = 63
	// maxNetDevActorBytes bounds the admin name recorded with the keys.
	maxNetDevActorBytes = 64
	// maxNetDevVaultRef bounds a vault reference (executordb netVaultRefRe).
	maxNetDevVaultRef = 64
)

// NetDeviceResolver resolves a host name to its addresses. It is called at
// most once per registration and never on the dial path.
type NetDeviceResolver func(ctx context.Context, name string) ([]netip.Addr, error)

// DefaultNetDeviceResolver resolves name with the Go resolver. IPv4-mapped
// IPv6 results are unmapped before they are checked.
func DefaultNetDeviceResolver(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	return addrs, nil
}

// NetDeviceStore is the persistence the registry needs (executordb.DB).
// PutSecret must write to the same database as the registry's vault.
type NetDeviceStore interface {
	PutSecret(executordb.VaultSecret) error
	InsertNetDevice(executordb.NetDevice) (executordb.NetDevice, error)
	GetNetDevice(id string) (executordb.NetDevice, bool, error)
}

// NetDeviceRegistry registers network devices and hands out their checked
// dial addresses. It runs inside the executor; only the authenticated
// admin reaches RegisterNetDevice.
type NetDeviceRegistry struct {
	// Store is the executor database. Required.
	Store NetDeviceStore
	// Vault is the executor vault, backed by Store. Required; it must be
	// unlocked to register a device.
	Vault *vault.Vault
	// Resolve resolves a host name given as endpoint. Nil refuses host
	// names; the executor wires DefaultNetDeviceResolver.
	Resolve NetDeviceResolver
	// Log receives non-secret audit events. Default: discarded.
	Log *slog.Logger
}

// NetDeviceRegistration is an admin's request to register one device.
type NetDeviceRegistration struct {
	// DeviceID is the immutable device id (netdevcontract.ValidDeviceID).
	DeviceID string
	Family   netdevcontract.Family
	// Label is a display name. For a host name endpoint it must be empty
	// or equal the name: the name becomes the label.
	Label string
	// Endpoint is a private IP literal or a host name resolved once here.
	Endpoint string
	Port     uint16
	PinKind  netdevcontract.PinKind
	// Pin is the lowercase hex SHA-256 the admin confirmed.
	Pin string
	// By is the admin who registers the device.
	By string
}

func (r *NetDeviceRegistry) log() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return r.Log
}

// CheckDeviceAddr reports whether a device may be dialled at a. It refuses
// public addresses (anything outside RFC 1918 and fc00::/7), loopback,
// link-local, multicast and unspecified addresses, addresses with a zone,
// and IPv4-mapped IPv6 addresses. IPv4-compatible, NAT64, 6to4 and Teredo
// forms are not private and are refused as public. It is used at
// registration and, through DialAddr, at every dial.
func CheckDeviceAddr(a netip.Addr) error {
	class := ""
	switch {
	case !a.IsValid():
		return fmt.Errorf("%w: no address", ErrNetDeviceAddress)
	case a.Zone() != "":
		class = "zoned"
	case a.Is4In6():
		class = "IPv4-mapped IPv6"
	case a.IsUnspecified():
		class = "unspecified"
	case a.IsLoopback():
		class = "loopback"
	case a.IsLinkLocalUnicast():
		class = "link-local"
	case a.IsMulticast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		class = "multicast"
	case !a.IsPrivate():
		class = "public"
	default:
		return nil
	}
	return fmt.Errorf("%w: %s is a %s address", ErrNetDeviceAddress, a, class)
}

// DialAddr returns the address to dial dev at: its stored IP literal and
// port, re-checked on every call. It never resolves a name; a stored
// endpoint that is not a canonical private IP literal is refused, as is a
// blocked or tombstoned device.
func DialAddr(dev executordb.NetDevice) (netip.AddrPort, error) {
	if dev.TombstonedAt != nil || dev.Blocked {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w", dev.ID, ErrNetDeviceNotDialable)
	}
	a, err := netip.ParseAddr(dev.EndpointIP)
	if err != nil || a.String() != dev.EndpointIP {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w: stored endpoint is not a canonical IP literal", dev.ID, ErrNetDeviceAddress)
	}
	if err := CheckDeviceAddr(a); err != nil {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w", dev.ID, err)
	}
	if dev.Port == 0 {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w: port 0", dev.ID, ErrNetDeviceAddress)
	}
	return netip.AddrPortFrom(a, dev.Port), nil
}

// LookupDialAddr loads device id and returns its checked dial address
// (DialAddr). A stored row that fails validation is an error.
func (r *NetDeviceRegistry) LookupDialAddr(ctx context.Context, id string) (netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	if r.Store == nil {
		return netip.AddrPort{}, errors.New("executor: netdev registry: Store is required")
	}
	dev, ok, err := r.Store.GetNetDevice(id)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w", id, err)
	}
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("dial network device %s: %w", id, executordb.ErrNetDeviceNotFound)
	}
	return DialAddr(dev)
}

// netDevKeyRefs returns the device-scoped vault ids of the digest and
// fingerprint keys. Ids too long to embed use a SHA-256 of the id after a
// double dash, which no embedded id can produce (ids start with [a-z0-9]).
func netDevKeyRefs(id string) (digest, fingerprint string) {
	scope := id
	if len("netdev-")+len(id)+len("-dk") > maxNetDevVaultRef {
		sum := sha256.Sum256([]byte(id))
		scope = "-" + hex.EncodeToString(sum[:16])
	}
	return "netdev-" + scope + "-dk", "netdev-" + scope + "-fk"
}

// RegisterNetDevice validates req, resolves a host name endpoint exactly
// once, checks the address, creates the per-device digest and fingerprint
// keys in the vault and stores the device with references to them. On any
// failure no device is stored and every vault entry it created is deleted;
// if that deletion fails the error wraps ErrNetDeviceRollback.
func (r *NetDeviceRegistry) RegisterNetDevice(ctx context.Context, req NetDeviceRegistration) (executordb.NetDevice, error) {
	if r.Store == nil || r.Vault == nil {
		return executordb.NetDevice{}, errors.New("executor: netdev registry: Store and Vault are required")
	}
	name, label, addr, err := validateNetDevRequest(req)
	if err != nil {
		return executordb.NetDevice{}, err
	}
	if err := ctx.Err(); err != nil {
		return executordb.NetDevice{}, err
	}
	if _, ok, err := r.Store.GetNetDevice(req.DeviceID); err != nil {
		return executordb.NetDevice{}, fmt.Errorf("register network device %s: %w", req.DeviceID, err)
	} else if ok {
		return executordb.NetDevice{}, fmt.Errorf("register network device %s: %w", req.DeviceID, executordb.ErrNetDeviceExists)
	}

	if name != "" {
		addr, err = r.resolveOnce(ctx, name)
		if err != nil {
			return executordb.NetDevice{}, fmt.Errorf("register network device %s: %w", req.DeviceID, err)
		}
	}
	if err := CheckDeviceAddr(addr); err != nil {
		return executordb.NetDevice{}, fmt.Errorf("register network device %s: %w", req.DeviceID, err)
	}

	dRef, fRef := netDevKeyRefs(req.DeviceID)
	var created []string
	fail := func(cause error) (executordb.NetDevice, error) {
		return executordb.NetDevice{}, r.rollback(req.DeviceID, created, cause)
	}
	for _, ref := range []string{dRef, fRef} {
		if err := r.putNewKey(ref, req.By); err != nil {
			return fail(err)
		}
		created = append(created, ref)
	}
	dev, err := r.Store.InsertNetDevice(executordb.NetDevice{
		ID:                req.DeviceID,
		Family:            req.Family,
		Label:             label,
		EndpointIP:        addr.String(),
		Port:              req.Port,
		PinKind:           req.PinKind,
		PinValue:          req.Pin,
		DigestKeyRef:      dRef,
		FingerprintKeyRef: fRef,
	})
	if err != nil {
		if errors.Is(err, executordb.ErrNetTrustIdentityInUse) {
			err = fmt.Errorf("%w: %w", ErrDuplicateTrustIdentity, err)
		}
		return fail(err)
	}
	r.log().Info("audit", "kind", "netdev_registered", "by", req.By, "device", dev.ID,
		"family", string(dev.Family), "endpoint", dev.EndpointIP, "port", dev.Port, "resolved_from", name)
	return dev, nil
}

// putNewKey stores a fresh random key under ref. It refuses to write a new
// version over an existing entry (ErrNetDeviceKeyExists).
func (r *NetDeviceRegistry) putNewKey(ref, by string) error {
	key := make([]byte, NetDeviceKeyBytes)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("executor: network device key: random: %w", err)
	}
	_, err := r.Vault.PutWithCommit(ref, key, by, func(s executordb.VaultSecret) error {
		if s.Version != 1 {
			return fmt.Errorf("%w: %s", ErrNetDeviceKeyExists, ref)
		}
		return r.Store.PutSecret(s)
	})
	if err != nil {
		return fmt.Errorf("executor: store network device key %s: %w", ref, err)
	}
	return nil
}

// rollback deletes the vault entries a failed registration created and
// returns cause, joined with ErrNetDeviceRollback if any deletion failed.
func (r *NetDeviceRegistry) rollback(id string, created []string, cause error) error {
	var errs []error
	var orphans []string
	for _, ref := range created {
		if err := r.Vault.Delete(ref); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", ref, err))
			orphans = append(orphans, ref)
		}
	}
	if len(errs) == 0 {
		return fmt.Errorf("register network device %s: %w", id, cause)
	}
	r.log().Error("audit", "kind", "netdev_register_rollback_failed", "device", id, "orphaned_secrets", strings.Join(orphans, ","))
	return fmt.Errorf("register network device %s: %w (%w: %w)", id, cause, ErrNetDeviceRollback, errors.Join(errs...))
}

// resolveOnce resolves name and returns its single address.
func (r *NetDeviceRegistry) resolveOnce(ctx context.Context, name string) (netip.Addr, error) {
	if r.Resolve == nil {
		return netip.Addr{}, fmt.Errorf("%w: %s: host names are not accepted (no resolver)", ErrNetDeviceResolve, name)
	}
	ctx, cancel := context.WithTimeout(ctx, netDevResolveTimeout)
	defer cancel()
	addrs, err := r.Resolve(ctx, name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %s: %w", ErrNetDeviceResolve, name, err)
	}
	if len(addrs) != 1 {
		return netip.Addr{}, fmt.Errorf("%w: %s resolved to %d addresses", ErrNetDeviceResolve, name, len(addrs))
	}
	return addrs[0], nil
}

// validateNetDevRequest checks every field of req before anything is
// resolved or written. It returns the normalized host name (empty for an
// IP literal endpoint), the label to store and, for an IP literal, its
// parsed (not yet checked) address.
func validateNetDevRequest(req NetDeviceRegistration) (name, label string, addr netip.Addr, err error) {
	bad := func(format string, args ...any) (string, string, netip.Addr, error) {
		return "", "", netip.Addr{}, fmt.Errorf("%w: "+format, append([]any{ErrNetDeviceRequest}, args...)...)
	}
	if !netdevcontract.ValidDeviceID(req.DeviceID) {
		return bad("device id is malformed")
	}
	switch req.Family {
	case netdevcontract.FamilyCBS:
		if req.PinKind != netdevcontract.PinSSHHostKey {
			return bad("cbs device requires pin kind %s", netdevcontract.PinSSHHostKey)
		}
	case netdevcontract.FamilyPANOS:
		if req.PinKind != netdevcontract.PinTLSLeaf && req.PinKind != netdevcontract.PinTLSCA {
			return bad("panos device requires a tls pin kind")
		}
	default:
		return bad("unknown device family")
	}
	if !netdevcontract.ValidTrustPin(req.Pin) {
		return bad("trust pin is not a lowercase hex SHA-256")
	}
	if req.Port == 0 {
		return bad("port must be in 1..65535")
	}
	if !validNetDevText(req.By, maxNetDevActorBytes) {
		return bad("actor is missing or malformed")
	}
	if req.Label != "" && !validNetDevText(req.Label, netdevcontract.MaxLabelBytes) {
		return bad("label is not printable UTF-8 of at most %d bytes", netdevcontract.MaxLabelBytes)
	}
	if a, perr := netip.ParseAddr(req.Endpoint); perr == nil {
		if req.Label == "" {
			return bad("a label is required for an IP literal endpoint")
		}
		return "", req.Label, a, nil
	}
	name, ok := normalizeNetDevName(req.Endpoint)
	if !ok {
		return bad("endpoint is neither an IP literal nor a host name")
	}
	if req.Label != "" && req.Label != name {
		return bad("for a host name endpoint the label is the name")
	}
	return name, name, netip.Addr{}, nil
}

// validNetDevText reports whether s is 1..max bytes of printable UTF-8.
func validNetDevText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

// normalizeNetDevName returns s as a lowercase host name without the
// trailing dot. It refuses anything but ASCII letters, digits, hyphens and
// dots, labels longer than 63 bytes, and an all-numeric last label, so
// that no numeric IPv4 shorthand (10.1, 167772161, 0x0a.0.0.1) can reach
// a resolver that would read it as an address.
func normalizeNetDevName(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > maxNetDevNameBytes {
		return "", false
	}
	// Check the raw bytes before lowering: Unicode case mapping turns
	// some non-ASCII runes (KELVIN SIGN) into ASCII letters.
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.':
		default:
			return "", false
		}
	}
	s = string(b)
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > maxNetDevNameLabel || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
	}
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" {
		return "", false
	}
	return s, true
}
