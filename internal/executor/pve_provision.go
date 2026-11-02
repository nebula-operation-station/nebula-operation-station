// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// This file is guest provisioning (ADR 0008 section 3, PV-05).
// pve.guest.provision is a typed mutation of one node, run with the
// remote's action token through the mutation engine (pve_mutation.go). Its
// approved parameters bind exactly: the remote identity (the engine binds
// pin, generation, action token version and endpoints), node and storage,
// the prepared template record, the new VMID (reserved against the live
// guest list), name, size, NIC, the IPAM reservation or DHCP, the
// cloud-init fields, start-after-create, the observed capacity information
// and the digest of the complete configuration. The steps are full clone,
// allowlisted config set, disk resize and (optionally) start; each stores
// its UPID before the next one and reconciles without redispatch. A failed
// provisioning leaves the guest for inspection: no step ever deletes it.
//
// Access: cloud-init sshkeys always contains the NOS automation key. An
// optional password is entered only on the executor (SetGuestPassword, the
// CLI secret input path as for PVE tokens), kept in the vault and bound by
// vault reference and version only; DispatchProvisionStep opens it and
// sends it only as cipassword.

// Typed step methods of pve.guest.provision.
const (
	pveStepGuestClone  = "pve.guest.clone"
	pveStepGuestConfig = "pve.guest.config"
	pveStepGuestResize = "pve.guest.resize"
	pveStepGuestStart  = "pve.guest.start"
)

// pveProvisionTaskTypes are the PVE task types the provisioning steps
// create.
var pveProvisionTaskTypes = map[string]string{
	pveStepGuestClone:  "qmclone",
	pveStepGuestConfig: "qmconfig",
	pveStepGuestResize: "resize",
	pveStepGuestStart:  "qmstart",
}

// Provisioning limits and defaults.
const (
	// pveProvisionPlanVersion is the version of the approved parameters.
	pveProvisionPlanVersion = 1
	// pveDefaultDisk is the disk slot resized when none is named; the
	// image templates (pve.image.prepare) put the imported disk there.
	pveDefaultDisk = "scsi0"
	// maxPveProvisionStepArgs bounds the arguments of one provisioning
	// step (the config step carries up to pveapi.MaxSSHKeys keys).
	maxPveProvisionStepArgs = 64 << 10
	// maxPveGuestPasswordID bounds the operator's name for a guest
	// password.
	maxPveGuestPasswordID = 40
	// pveGuestPasswordPrefix is the vault namespace of guest passwords. A
	// step may only open vault entries in it.
	pveGuestPasswordPrefix = "pve-guestpw-"
	// maxPveIPAMByBytes bounds the reserving user of an IPAM binding.
	maxPveIPAMByBytes = 64
)

var (
	// ErrPveProvisionInvalid is returned for a provisioning request that
	// fails validation; nothing is reserved or sent.
	ErrPveProvisionInvalid = errors.New("executor: invalid provisioning request")
	// ErrPveProvisionUnsupported is returned for a requested feature the
	// allowlisted config set does not offer (PCI passthrough).
	ErrPveProvisionUnsupported = errors.New("executor: provisioning feature not offered")
	// ErrPveInventoryIncomplete is returned when the cluster guest list is
	// partial or truncated: a free VMID cannot be proven.
	ErrPveInventoryIncomplete = errors.New("executor: pve cluster inventory incomplete")
	// ErrPveGuestPassword is returned for a missing, malformed or changed
	// guest password. It never carries the value.
	ErrPveGuestPassword = errors.New("executor: guest password unavailable")
)

var (
	pveGuestPasswordIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	pveCIUserRe          = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	pveBridgeRe          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,14}$`)
	pveDiskRe            = regexp.MustCompile(`^(scsi([0-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5]|ide[0-3])$`)
	pveStorageIDRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	pveNetworkIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	pveIPAMByRe          = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)
)

// PveProvisionNIC is net0 of the new guest. MAC policy: an empty MAC lets
// PVE generate one; a fixed MAC must be a unicast EUI-48.
type PveProvisionNIC struct {
	// Model is "virtio" (default) or "e1000".
	Model string
	// Bridge is the Linux bridge or SDN vnet.
	Bridge string
	// VLAN is the 802.1Q tag; 0 means untagged.
	VLAN int
	// MAC is a fixed MAC address or empty.
	MAC string
}

// PveIPAMBinding is the IPAM reservation (ipam.Reservation) the server took
// for the guest. It is bound as given and is the only source of ipconfig0;
// the executor checks its consistency (address inside the prefix, gateway,
// VLAN equal to the NIC's tag).
type PveIPAMBinding struct {
	NetworkID      string
	Pool           string
	Prefix         netip.Prefix
	Gateway        netip.Addr // invalid when the network has none
	VLAN           int
	Address        netip.Addr
	ReservedBy     string
	ReservedAtUnix int64
}

// PveProvisionRequest selects one provisioning. The same request is
// presented to ProposalRequest and, with Digest, ExecutionID and the
// reserved VMID, to Provision.
type PveProvisionRequest struct {
	// Digest is the approved permit (Provision only).
	Digest canonical.Digest
	// ExecutionID is the execution of the proposal (Provision only); it
	// holds the VMID reservation.
	ExecutionID string

	RemoteID string
	Node     string
	// Storage receives the full clone's disks.
	Storage string
	// Template is the prepared template record to clone; it must be on
	// RemoteID and Node.
	Template PveTemplateBinding
	// VMID is the new guest; 0 asks ProposalRequest for the next free one.
	VMID uint64
	// Name is the guest name and hostname (lowercase DNS name).
	Name      string
	Cores     int
	MemoryMiB int
	// Disk is the disk slot to resize (default scsi0); DiskGiB its size.
	Disk    string
	DiskGiB int64
	NIC     PveProvisionNIC
	// IPAM is the reservation for a static address; nil means DHCP.
	IPAM *PveIPAMBinding
	// CIUser is the cloud-init default user.
	CIUser string
	// SSHKeys are further OpenSSH public keys; the NOS automation key is
	// always added first.
	SSHKeys       []string
	Nameservers   []netip.Addr
	SearchDomains []string
	// PasswordID names a guest password entered on the executor
	// (SetGuestPassword); empty keeps SSH-key-only access.
	PasswordID string
	// Start starts the guest after creation.
	Start bool
	// PCIPassthrough requests PCI passthrough. The allowlisted config set
	// does not offer it yet, so such a request is refused.
	PCIPassthrough bool
}

// PveProvisionReader is the read side provisioning needs, with the read
// token: the cluster guest list (pveapi.Client.EnumerateCluster) and one
// storage of a node (pveapi.Client.GetStorage).
type PveProvisionReader interface {
	ClusterInventory(ctx context.Context, rm executordb.PveRemote, read pveapi.TokenSupplier) (pveapi.ClusterInventory, error)
	NodeStorage(ctx context.Context, rm executordb.PveRemote, node, storage string, read pveapi.TokenSupplier) (pveapi.Storage, error)
}

// pveGuestPasswordVault is the part of the vault guest passwords use.
type pveGuestPasswordVault interface {
	pveSecrets
	Put(id string, value []byte, by string) (int64, error)
	Delete(id string) error
}

// PveProvisioner proposes and runs pve.guest.provision.
type PveProvisioner struct {
	// Mutations is the engine; its TaskIDs must be this provisioner, so a
	// lost step is narrowed to this provisioning's guest also after a
	// restart.
	Mutations *PveMutations
	// Images binds the template record.
	Images *PveImages
	Reader PveProvisionReader
	VMIDs  PveVMIDStore
	// Passwords is the vault holding guest passwords.
	Passwords pveGuestPasswordVault
	// AutomationKey is the NOS automation public key (authorized_keys
	// format) that cloud-init always installs.
	AutomationKey string
	// Artifact and ModuleVersion identify the action the permit binds.
	Artifact      []byte
	ModuleVersion string

	// settle serializes every decision about a started reservation (start,
	// settle after a run, releaseSettled) with the in-flight count it
	// relies on, so no check is acted on after it went stale.
	settle sync.Mutex
}

// PveProvisionProposal is a provisioning proposal built by the executor.
type PveProvisionProposal struct {
	Request    canonical.Request
	Parameters []byte
	// VMID is the reserved VMID of the new guest.
	VMID uint64
	// Capacity is the observed capacity information (display warnings
	// only; it does not change the risk).
	Capacity PveProvisionCapacity
}

// PveProvisionResult reports one provisioning run.
type PveProvisionResult struct {
	ExecutionID string
	RemoteID    string
	Node        string
	VMID        uint64
	Steps       []executordb.PveJob
	// GuestConfigDigest is the new guest's configuration digest after a
	// successful run.
	GuestConfigDigest string
	// GuestKept is set when the run failed after the clone may have
	// created the guest: it is left in PVE for inspection, never deleted.
	GuestKept bool
}

func (p *PveProvisioner) checkDeps() error {
	if p.Mutations == nil || p.Images == nil || p.Reader == nil || p.VMIDs == nil || p.Passwords == nil ||
		len(p.Artifact) == 0 || p.ModuleVersion == "" {
		return errors.New("executor: pve provisioner: Mutations, Images, Reader, VMIDs, Passwords, Artifact and ModuleVersion are required")
	}
	if _, err := canonicalAuthorizedKey(p.AutomationKey); err != nil {
		return errors.New("executor: pve provisioner: AutomationKey is not a valid public key")
	}
	if p.Mutations.TaskIDs != PveJobTaskIDs(p) {
		return errors.New("executor: pve provisioner: Mutations.TaskIDs must be the provisioner")
	}
	return p.Mutations.checkDeps()
}

// canonicalAuthorizedKey parses one OpenSSH public key without options and
// returns its canonical "type base64" form.
func canonicalAuthorizedKey(k string) (string, error) {
	if k == "" || len(k) > pveapi.MaxSSHKeysBytes || strings.ContainsAny(k, "\r\n") {
		return "", ErrPveProvisionInvalid
	}
	pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(k))
	if err != nil || len(opts) != 0 || strings.TrimSpace(string(rest)) != "" {
		return "", ErrPveProvisionInvalid
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

// validDNSName reports whether s is a lowercase DNS name (labels of
// [a-z0-9-], 1..63 bytes, no leading or trailing '-', at most 253 bytes).
func validDNSName(s string) bool {
	if s == "" || len(s) > pveapi.MaxGuestNameBytes {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// validGuestPassword accepts what pveapi sends as cipassword.
func validGuestPassword(p []byte) bool {
	if len(p) < pveapi.MinPasswordBytes || len(p) > pveapi.MaxPasswordBytes || !utf8.Valid(p) {
		return false
	}
	for _, r := range string(p) {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// PveGuestPasswordVaultID returns the vault ID of the guest password id.
func PveGuestPasswordVaultID(id string) (string, error) {
	if !pveGuestPasswordIDRe.MatchString(id) || len(id) > maxPveGuestPasswordID {
		return "", ErrPveProvisionInvalid
	}
	return pveGuestPasswordPrefix + id, nil
}

// SetGuestPassword stores a guest password entered on the executor host
// (CLI secret input) under id and returns its vault version. The value is
// never logged, returned or bound into a permit; a provisioning binds the
// vault reference and version.
func (p *PveProvisioner) SetGuestPassword(id string, password []byte, by string) (int64, error) {
	if p.Passwords == nil {
		return 0, errors.New("executor: pve provisioner: Passwords is required")
	}
	ref, err := PveGuestPasswordVaultID(id)
	if err != nil {
		return 0, err
	}
	if !validGuestPassword(password) {
		return 0, fmt.Errorf("set guest password %s: %w", id, ErrPveGuestPassword)
	}
	v, err := p.Passwords.Put(ref, password, by)
	if err != nil {
		return 0, fmt.Errorf("set guest password %s: %w", id, ErrPveGuestPassword)
	}
	p.Mutations.log().Info("audit", "kind", "pve_guest_password_set", "id", id, "version", v, "by", by)
	return v, nil
}

// DeleteGuestPassword removes a guest password from the vault.
func (p *PveProvisioner) DeleteGuestPassword(id, by string) error {
	if p.Passwords == nil {
		return errors.New("executor: pve provisioner: Passwords is required")
	}
	ref, err := PveGuestPasswordVaultID(id)
	if err != nil {
		return err
	}
	if err := p.Passwords.Delete(ref); err != nil {
		return fmt.Errorf("delete guest password %s: %w", id, err)
	}
	p.Mutations.log().Info("audit", "kind", "pve_guest_password_deleted", "id", id, "by", by)
	return nil
}

// Wire form of the approved parameters.
type (
	pveProvisionTemplate struct {
		RemoteID     string `json:"remote_id"`
		Node         string `json:"node"`
		Storage      string `json:"storage"`
		ImageID      string `json:"image_id"`
		VMID         uint64 `json:"vmid"`
		Generation   uint64 `json:"generation"`
		SourceSHA256 string `json:"source_sha256"`
		ConfigDigest string `json:"config_digest"`
	}
	pveProvisionNet0 struct {
		Model  string `json:"model"`
		Bridge string `json:"bridge"`
		Tag    int    `json:"tag"`
		MAC    string `json:"mac"`
	}
	pveProvisionGuest struct {
		VMID      uint64           `json:"vmid"`
		Name      string           `json:"name"`
		Storage   string           `json:"storage"`
		Cores     int              `json:"cores"`
		MemoryMiB int              `json:"memory_mib"`
		Disk      string           `json:"disk"`
		DiskGiB   int64            `json:"disk_gib"`
		Net0      pveProvisionNet0 `json:"net0"`
	}
	pveProvisionNetwork struct {
		Mode           string `json:"mode"` // "dhcp" or "ipam"
		NetworkID      string `json:"network_id,omitempty"`
		Pool           string `json:"pool,omitempty"`
		Prefix         string `json:"prefix,omitempty"`
		Address        string `json:"address,omitempty"`
		Gateway        string `json:"gateway,omitempty"`
		VLAN           int    `json:"vlan,omitempty"`
		ReservedBy     string `json:"reserved_by,omitempty"`
		ReservedAtUnix int64  `json:"reserved_at_unix,omitempty"`
	}
	pveProvisionIP struct {
		DHCP    bool   `json:"dhcp"`
		Address string `json:"address,omitempty"` // address/prefix
		Gateway string `json:"gateway,omitempty"`
	}
	pveProvisionPassword struct {
		Ref     string `json:"ref"`
		Version int64  `json:"version"`
	}
	pveProvisionCloudInit struct {
		CIUser        string                `json:"ciuser"`
		SSHKeys       []string              `json:"sshkeys"`
		IPConfig0     pveProvisionIP        `json:"ipconfig0"`
		Nameservers   []string              `json:"nameserver"`
		SearchDomains []string              `json:"searchdomain"`
		Password      *pveProvisionPassword `json:"password"`
	}
	pveProvisionConfig struct {
		Template  pveProvisionTemplate  `json:"template"`
		Guest     pveProvisionGuest     `json:"guest"`
		Network   pveProvisionNetwork   `json:"network"`
		CloudInit pveProvisionCloudInit `json:"cloud_init"`
		Start     bool                  `json:"start_after_create"`
	}
	pveProvisionPlan struct {
		Version int `json:"version"`
		pveProvisionConfig
		// Capacity is information for the reviewer, not a risk input.
		Capacity     PveProvisionCapacity `json:"capacity"`
		ConfigDigest string               `json:"config_digest"`
		Steps        []PveMutationStep    `json:"steps"`
	}
)

// Step arguments.
type (
	pveCloneArgs struct {
		SourceVMID int64  `json:"source_vmid"`
		NewVMID    int64  `json:"new_vmid"`
		Name       string `json:"name"`
		Storage    string `json:"storage"`
	}
	pveConfigArgs struct {
		VMID            int64            `json:"vmid"`
		Name            string           `json:"name"`
		Cores           int              `json:"cores"`
		MemoryMiB       int              `json:"memory_mib"`
		Agent           bool             `json:"agent"`
		Net0            pveProvisionNet0 `json:"net0"`
		IPConfig0       pveProvisionIP   `json:"ipconfig0"`
		CIUser          string           `json:"ciuser"`
		SSHKeys         []string         `json:"sshkeys"`
		Nameservers     []string         `json:"nameserver"`
		SearchDomains   []string         `json:"searchdomain"`
		PasswordRef     string           `json:"password_ref,omitempty"`
		PasswordVersion int64            `json:"password_version,omitempty"`
	}
	pveResizeArgs struct {
		VMID    int64  `json:"vmid"`
		Disk    string `json:"disk"`
		SizeGiB int64  `json:"size_gib"`
	}
	pveStartArgs struct {
		VMID int64 `json:"vmid"`
	}
)

// normalizeMAC returns the lowercase colon form of a unicast EUI-48.
func normalizeMAC(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 || string(hw) == "\x00\x00\x00\x00\x00\x00" {
		return "", false
	}
	return hw.String(), true
}

func validStaticIPv4(a netip.Addr) bool {
	return a.IsValid() && a.Is4() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

// network validates the network binding and returns its wire form and the
// ipconfig0 derived from it.
func (req PveProvisionRequest) network() (pveProvisionNetwork, pveProvisionIP, error) {
	b := req.IPAM
	if b == nil {
		return pveProvisionNetwork{Mode: "dhcp"}, pveProvisionIP{DHCP: true}, nil
	}
	p, a := b.Prefix, b.Address
	bits := p.Bits()
	switch {
	case !pveNetworkIDRe.MatchString(b.NetworkID) || (b.Pool != "" && !pveIPAMByRe.MatchString(b.Pool)):
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam network", ErrPveProvisionInvalid)
	case !p.IsValid() || !p.Addr().Is4() || bits < 1 || bits > 32 || p.Masked() != p:
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam prefix", ErrPveProvisionInvalid)
	case !validStaticIPv4(a) || !p.Contains(a):
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam address", ErrPveProvisionInvalid)
	case bits <= 30 && (a == p.Addr() || a == lastIPv4(p)):
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam address is the network or broadcast address", ErrPveProvisionInvalid)
	case b.Gateway.IsValid() && (!b.Gateway.Is4() || b.Gateway == a || !p.Contains(b.Gateway)):
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam gateway", ErrPveProvisionInvalid)
	case b.VLAN != req.NIC.VLAN:
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam network vlan %d differs from the nic tag %d", ErrPveProvisionInvalid, b.VLAN, req.NIC.VLAN)
	case !pveIPAMByRe.MatchString(b.ReservedBy) || len(b.ReservedBy) > maxPveIPAMByBytes || b.ReservedAtUnix <= 0:
		return pveProvisionNetwork{}, pveProvisionIP{}, fmt.Errorf("%w: ipam reservation", ErrPveProvisionInvalid)
	}
	n := pveProvisionNetwork{Mode: "ipam", NetworkID: b.NetworkID, Pool: b.Pool, Prefix: p.String(), Address: a.String(),
		VLAN: b.VLAN, ReservedBy: b.ReservedBy, ReservedAtUnix: b.ReservedAtUnix}
	ip := pveProvisionIP{Address: netip.PrefixFrom(a, bits).String()}
	if b.Gateway.IsValid() {
		n.Gateway, ip.Gateway = b.Gateway.String(), b.Gateway.String()
	}
	return n, ip, nil
}

func lastIPv4(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// config validates req and builds the complete configuration (without the
// password version and the template's live record).
func (p *PveProvisioner) config(req PveProvisionRequest, vmid uint64) (pveProvisionConfig, error) {
	bad := func(what string) (pveProvisionConfig, error) {
		return pveProvisionConfig{}, fmt.Errorf("%w: %s", ErrPveProvisionInvalid, what)
	}
	if req.PCIPassthrough {
		return pveProvisionConfig{}, fmt.Errorf("pci passthrough: %w", ErrPveProvisionUnsupported)
	}
	switch {
	case !pvecontract.ValidRemoteID(req.RemoteID) || !pvecontract.ValidNodeName(req.Node):
		return bad("remote or node")
	case !pveStorageIDRe.MatchString(req.Storage):
		return bad("storage")
	case req.Template.RemoteID != req.RemoteID || req.Template.Node != req.Node:
		return bad("the template is not on the target remote and node")
	case !validVMID(vmid) || vmid == req.Template.VMID:
		return bad("vmid")
	case !validDNSName(req.Name):
		return bad("name")
	case req.Cores < 1 || req.Cores > pveapi.MaxCores:
		return bad("cores")
	case req.MemoryMiB < pveapi.MinMemoryMiB || req.MemoryMiB > pveapi.MaxMemoryMiB:
		return bad("memory")
	case req.DiskGiB < 1 || req.DiskGiB > pveapi.MaxDiskGiB:
		return bad("disk size")
	case !pveCIUserRe.MatchString(req.CIUser):
		return bad("ciuser")
	case req.PasswordID != "" && !pveGuestPasswordIDRe.MatchString(req.PasswordID):
		return bad("password id")
	}
	disk := req.Disk
	if disk == "" {
		disk = pveDefaultDisk
	}
	if !pveDiskRe.MatchString(disk) {
		return bad("disk")
	}
	model := req.NIC.Model
	if model == "" {
		model = pveapi.NICVirtio
	}
	mac, ok := normalizeMAC(req.NIC.MAC)
	switch {
	case model != pveapi.NICVirtio && model != pveapi.NICE1000:
		return bad("nic model")
	case !pveBridgeRe.MatchString(req.NIC.Bridge):
		return bad("bridge")
	case req.NIC.VLAN < 0 || req.NIC.VLAN > pveapi.MaxVLANTag:
		return bad("vlan")
	case !ok:
		return bad("mac")
	}
	network, ip, err := req.network()
	if err != nil {
		return pveProvisionConfig{}, err
	}
	auto, err := canonicalAuthorizedKey(p.AutomationKey)
	if err != nil {
		return bad("automation key")
	}
	keys := []string{auto}
	if len(req.SSHKeys) > pveapi.MaxSSHKeys-1 {
		return bad("too many ssh keys")
	}
	for _, k := range req.SSHKeys {
		c, err := canonicalAuthorizedKey(k)
		if err != nil {
			return bad("ssh key")
		}
		if !slices.Contains(keys, c) {
			keys = append(keys, c)
		}
	}
	if len(req.Nameservers) > pveapi.MaxNameservers || len(req.SearchDomains) > pveapi.MaxSearchDomains {
		return bad("dns")
	}
	ns := []string{}
	for _, a := range req.Nameservers {
		if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return bad("nameserver")
		}
		ns = append(ns, a.Unmap().String())
	}
	sd := []string{}
	for _, d := range req.SearchDomains {
		if !validDNSName(d) {
			return bad("searchdomain")
		}
		sd = append(sd, d)
	}
	return pveProvisionConfig{
		Template: pveProvisionTemplate{RemoteID: req.Template.RemoteID, Node: req.Template.Node, Storage: req.Template.Storage,
			ImageID: req.Template.ImageID, VMID: req.Template.VMID, Generation: req.Template.Generation, SourceSHA256: req.Template.SourceSHA256},
		Guest: pveProvisionGuest{VMID: vmid, Name: req.Name, Storage: req.Storage, Cores: req.Cores, MemoryMiB: req.MemoryMiB,
			Disk: disk, DiskGiB: req.DiskGiB, Net0: pveProvisionNet0{Model: model, Bridge: req.NIC.Bridge, Tag: req.NIC.VLAN, MAC: mac}},
		Network:   network,
		CloudInit: pveProvisionCloudInit{CIUser: req.CIUser, SSHKeys: keys, IPConfig0: ip, Nameservers: ns, SearchDomains: sd},
		Start:     req.Start,
	}, nil
}

// password returns the vault binding of req's password at its current
// version, or nil.
func (p *PveProvisioner) password(req PveProvisionRequest) (*pveProvisionPassword, error) {
	if req.PasswordID == "" {
		return nil, nil
	}
	ref, err := PveGuestPasswordVaultID(req.PasswordID)
	if err != nil {
		return nil, err
	}
	secret, v, err := p.Passwords.OpenVersion(ref)
	ok := err == nil && validGuestPassword(secret)
	clear(secret)
	if !ok {
		return nil, fmt.Errorf("password %s: %w", req.PasswordID, ErrPveGuestPassword)
	}
	return &pveProvisionPassword{Ref: ref, Version: v}, nil
}

// observed is what the executor reads for one provisioning.
type pveProvisionObserved struct {
	rm   executordb.PveRemote
	tpl  PveTemplateRecord
	live map[uint64]bool
	cap  PveProvisionCapacity
	pw   *pveProvisionPassword
}

// observe binds the template and reads the guest list, the storage and the
// password version.
func (p *PveProvisioner) observe(ctx context.Context, req PveProvisionRequest) (pveProvisionObserved, error) {
	var o pveProvisionObserved
	rm, err := p.Mutations.activeRemote(req.RemoteID)
	if err != nil {
		return o, err
	}
	tpl, err := p.Images.BindTemplate(ctx, req.Template)
	if err != nil {
		return o, err
	}
	if tpl.RemoteID != req.RemoteID || tpl.Node != req.Node {
		return o, ErrPveTemplateChanged
	}
	read, err := p.Mutations.readToken(rm)
	if err != nil {
		return o, err
	}
	inv, err := p.Reader.ClusterInventory(ctx, rm, read)
	if err != nil {
		return o, ErrPveTargetChanged
	}
	if inv.Partial || inv.Truncated {
		return o, ErrPveInventoryIncomplete
	}
	live := make(map[uint64]bool, len(inv.Guests))
	for _, g := range inv.Guests {
		if g.VMID > 0 {
			live[uint64(g.VMID)] = true
		}
	}
	st, err := p.Reader.NodeStorage(ctx, rm, req.Node, req.Storage, read)
	if err != nil || st.ID != req.Storage {
		return o, ErrPveTargetChanged
	}
	pw, err := p.password(req)
	if err != nil {
		return o, err
	}
	o.cap.MemoryOvercommit, o.cap.StorageOvercommit = pveCapacityFacts(inv, st, req.Node, req.MemoryMiB, req.DiskGiB)
	o.rm, o.tpl, o.live, o.pw = rm, tpl, live, pw
	return o, nil
}

// mutation builds the exact mutation request: the complete configuration,
// its digest, the capacity information and the step plan.
func (p *PveProvisioner) mutation(req PveProvisionRequest, vmid uint64, o pveProvisionObserved) (PveMutationRequest, error) {
	cfg, err := p.config(req, vmid)
	if err != nil {
		return PveMutationRequest{}, err
	}
	cfg.Template.ConfigDigest = o.tpl.ConfigDigest
	cfg.CloudInit.Password = o.pw
	raw, err := json.Marshal(cfg)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	digest, err := canonical.HashParameters(raw)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	plan := pveProvisionPlan{Version: pveProvisionPlanVersion, pveProvisionConfig: cfg, ConfigDigest: digest,
		Capacity: o.cap}
	id := int64(vmid)
	g, ci := cfg.Guest, cfg.CloudInit
	ca := pveConfigArgs{VMID: id, Name: g.Name, Cores: g.Cores, MemoryMiB: g.MemoryMiB, Agent: true, Net0: g.Net0,
		IPConfig0: ci.IPConfig0, CIUser: ci.CIUser, SSHKeys: ci.SSHKeys, Nameservers: ci.Nameservers, SearchDomains: ci.SearchDomains}
	if ci.Password != nil {
		ca.PasswordRef, ca.PasswordVersion = ci.Password.Ref, ci.Password.Version
	}
	steps := []struct {
		method string
		args   any
	}{
		{pveStepGuestClone, pveCloneArgs{SourceVMID: int64(cfg.Template.VMID), NewVMID: id, Name: g.Name, Storage: g.Storage}},
		{pveStepGuestConfig, ca},
		{pveStepGuestResize, pveResizeArgs{VMID: id, Disk: g.Disk, SizeGiB: g.DiskGiB}},
	}
	if cfg.Start {
		steps = append(steps, struct {
			method string
			args   any
		}{pveStepGuestStart, pveStartArgs{VMID: id}})
	}
	for _, s := range steps {
		st, err := stepOf(s.method, s.args)
		if err != nil {
			return PveMutationRequest{}, err
		}
		plan.Steps = append(plan.Steps, st)
	}
	params, err := json.Marshal(plan)
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	return PveMutationRequest{
		Digest: req.Digest, RemoteID: req.RemoteID, Kind: permit.ProviderKindNode, Node: req.Node,
		ActionID: PveGuestProvisionAction, ModuleVersion: p.ModuleVersion, Artifact: p.Artifact, Parameters: params,
		ExecutionID: req.ExecutionID,
	}, nil
}

// ProposalRequest builds the canonical request and parameters of a new
// pve.guest.provision proposal for executionID. It binds the template
// record (checked live), reserves the VMID (req.VMID, or the next free one)
// against the complete live guest list and the open reservations, reads the
// node's capacity (information only). The risk is at least MEDIUM; the
// authority raises it for criticality (GuestProvisionRiskFloor). On error
// nothing stays reserved.
func (p *PveProvisioner) ProposalRequest(ctx context.Context, req PveProvisionRequest, executionID string, risk canonical.Risk, stagePlanHash string, expiry time.Time) (PveProvisionProposal, error) {
	if err := p.checkDeps(); err != nil {
		return PveProvisionProposal{}, err
	}
	// Validate everything before reserving anything; a VMID still to be
	// allocated is validated with a stand-in.
	probe := req.VMID
	if probe == 0 {
		probe = pvecontract.MinVMID
		if probe == req.Template.VMID {
			probe++
		}
	}
	if _, err := p.config(req, probe); err != nil {
		return PveProvisionProposal{}, err
	}
	o, err := p.observe(ctx, req)
	if err != nil {
		return PveProvisionProposal{}, err
	}
	// Best effort: reservations of settled provisionings are released
	// first; one that cannot be checked stays (fail closed).
	_, _ = p.releaseSettled(req.RemoteID, o.live)
	vmid, err := p.VMIDs.ReserveVMID(req.RemoteID, executionID, req.VMID, withTemplate(o.live, req.Template.VMID), expiry, p.Mutations.now())
	if err != nil {
		return PveProvisionProposal{}, err
	}
	release := func() { _ = p.VMIDs.ReleaseVMID(req.RemoteID, vmid, executionID) }
	req.Digest, req.ExecutionID = canonical.Digest{}, ""
	mr, err := p.mutation(req, vmid, o)
	if err != nil {
		release()
		return PveProvisionProposal{}, err
	}
	rq, params, err := p.Mutations.ProposalRequest(ctx, mr, executionID, canonical.MaxRisk(risk, pveProvisionBaseRisk), stagePlanHash, expiry)
	if err != nil {
		release()
		return PveProvisionProposal{}, err
	}
	p.Mutations.log().Info("audit", "kind", "pve_guest_provision_proposed", "remote", req.RemoteID, "node", req.Node, "vmid", vmid,
		"execution", executionID, "risk", string(rq.RiskClass), "password", o.pw != nil, "network", mrNetworkMode(req))
	return PveProvisionProposal{Request: rq, Parameters: params, VMID: vmid, Capacity: o.cap}, nil
}

func mrNetworkMode(req PveProvisionRequest) string {
	if req.IPAM == nil {
		return "dhcp"
	}
	return "ipam"
}

// withTemplate adds the template's VMID to the live set (it is a guest,
// but a hostile list might omit it).
func withTemplate(live map[uint64]bool, tpl uint64) map[uint64]bool {
	out := make(map[uint64]bool, len(live)+1)
	for k := range live {
		out[k] = true
	}
	out[tpl] = true
	return out
}

// Provision runs an approved pve.guest.provision. Before anything is sent
// it binds the template again, checks that the VMID is still absent from
// the complete live guest list and reserved for req.ExecutionID, and
// rebuilds the exact parameters from fresh reads (a changed template,
// password version, capacity warning or anything else refuses the permit).
// The steps then run through the mutation engine. A failure after the
// clone may have been sent leaves the guest in PVE (GuestKept): it is never
// deleted automatically.
func (p *PveProvisioner) Provision(ctx context.Context, req PveProvisionRequest) (PveProvisionResult, error) {
	res := PveProvisionResult{ExecutionID: req.ExecutionID, RemoteID: req.RemoteID, Node: req.Node, VMID: req.VMID}
	if err := p.checkDeps(); err != nil {
		return res, err
	}
	if !vmidExecRe.MatchString(req.ExecutionID) {
		return res, ErrPveProvisionInvalid
	}
	if _, err := p.config(req, req.VMID); err != nil {
		return res, err
	}
	o, err := p.observe(ctx, req)
	if err != nil {
		return res, err
	}
	if o.live[req.VMID] {
		return res, fmt.Errorf("vmid %d exists: %w", req.VMID, ErrPveVMIDTaken)
	}
	mr, err := p.mutation(req, req.VMID, o)
	if err != nil {
		return res, err
	}
	// Started before the run: the guest may exist from the first dispatch
	// on, so the reservation must not expire under it. It also records the
	// template, so a lost step can be narrowed after a restart. The
	// execution counts as running from here, so releaseSettled leaves it;
	// the holder check, the in-flight mark and the start happen under one
	// lock with releaseSettled.
	if err := p.start(req); err != nil {
		return res, err
	}
	defer p.Mutations.end(req.ExecutionID)
	run, runErr := p.Mutations.Run(ctx, mr)
	p.settle.Lock()
	defer p.settle.Unlock()
	res.Steps = run.Steps
	if run.ExecutionID != "" {
		res.ExecutionID = run.ExecutionID
	}
	// The durable steps decide the reservation, never the in-memory
	// result: a store that cannot be read keeps the VMID reserved.
	steps, err := p.Mutations.DB.PveJobSteps(req.ExecutionID)
	if err != nil {
		res.GuestKept = true
		p.Mutations.log().Error("audit", "kind", "pve_guest_provision_failed", "remote", req.RemoteID, "node", req.Node, "vmid", req.VMID,
			"execution", res.ExecutionID, "reason", "job_store_unreadable", "guest_kept", true)
		return res, ErrPveJobStore
	}
	res.Steps = steps
	release, mayExist := vmidSettlement(steps)
	if p.Mutations.inflightRuns(req.ExecutionID) > 1 || errors.Is(runErr, ErrPveMutationAlreadyRun) {
		// Another run of this execution holds the permit and may be
		// dispatching right now: it owns the reservation. Nothing here
		// releases or unstarts it.
		res.GuestKept = len(steps) > 0
		if runErr == nil {
			return res, nil
		}
		return res, runErr
	}
	if len(steps) == 0 && runErr != nil && !errors.Is(runErr, ErrPveMutationDenied) {
		// Nothing was sent, but the failure may be transient (store, vault,
		// token, remote read): the approved execution keeps its VMID for a
		// retry, and the reservation expires with the proposal again. Only
		// a refused permit releases it.
		release = false
		_ = p.VMIDs.UnstartVMID(req.RemoteID, req.VMID, req.ExecutionID)
	}
	if release {
		_ = p.VMIDs.ReleaseVMID(req.RemoteID, req.VMID, req.ExecutionID)
	}
	if runErr != nil {
		if len(steps) == 0 {
			return res, runErr
		}
		res.GuestKept = mayExist
		failed := steps[len(steps)-1]
		p.Mutations.log().Error("audit", "kind", "pve_guest_provision_failed", "remote", req.RemoteID, "node", req.Node, "vmid", req.VMID,
			"execution", res.ExecutionID, "step", failed.Step, "state", string(failed.State), "guest_kept", mayExist, "vmid_reserved", !release)
		return res, runErr
	}
	read, err := p.Mutations.readToken(o.rm)
	if err != nil {
		res.GuestKept = true
		return res, err
	}
	liveNode, digest, err := p.Mutations.Client.TargetState(ctx, o.rm, permit.ProviderKindQemu, req.Node, req.VMID, read)
	if err != nil || liveNode != req.Node || !validHexDigest(digest) {
		res.GuestKept = true
		p.Mutations.log().Error("audit", "kind", "pve_guest_provision_failed", "remote", req.RemoteID, "node", req.Node, "vmid", req.VMID,
			"execution", res.ExecutionID, "reason", "guest_unreadable_after_run", "guest_kept", true)
		return res, ErrPveTargetChanged
	}
	res.GuestConfigDigest = digest
	p.Mutations.log().Info("audit", "kind", "pve_guest_provisioned", "remote", req.RemoteID, "node", req.Node, "vmid", req.VMID,
		"execution", res.ExecutionID, "started", req.Start)
	return res, nil
}

// start checks under the settle lock that req's VMID is still reserved for
// its execution, marks the execution in flight and marks the reservation
// started. On success the caller must end the in-flight mark.
func (p *PveProvisioner) start(req PveProvisionRequest) error {
	p.settle.Lock()
	defer p.settle.Unlock()
	h, ok, err := p.VMIDs.VMIDHolder(req.RemoteID, req.VMID, p.Mutations.now())
	if err != nil {
		return ErrPveJobStore
	}
	if !ok || h.ExecutionID != req.ExecutionID {
		return fmt.Errorf("vmid %d not reserved for this execution: %w", req.VMID, ErrPveVMIDTaken)
	}
	p.Mutations.begin(req.ExecutionID)
	if err := p.VMIDs.StartVMID(req.RemoteID, req.VMID, req.ExecutionID, req.Template.VMID); err != nil {
		p.Mutations.end(req.ExecutionID)
		return ErrPveJobStore
	}
	return nil
}

// pveJobOpen reports whether a step has not reached a terminal state.
func pveJobOpen(j executordb.PveJob) bool {
	switch j.State {
	case executordb.PveJobDispatching, executordb.PveJobRunning, executordb.PveJobReconciling:
		return true
	}
	return false
}

// vmidSettlement decides from the durable steps of one provisioning
// whether its VMID reservation can be released and whether the guest may
// exist:
//
//   - no step: nothing was sent (the intent is durable before dispatch);
//   - a step still open: kept, reconciliation narrows it by the
//     reservation;
//   - clone succeeded: released, the live guest list protects the VMID;
//   - clone failed (PVE ran and refused it): released, no guest;
//   - clone unknown: kept until the guest is seen (releaseSettled).
func vmidSettlement(steps []executordb.PveJob) (release, guestMayExist bool) {
	if len(steps) == 0 {
		return true, false
	}
	for _, j := range steps {
		if pveJobOpen(j) {
			return false, true
		}
	}
	switch steps[0].State {
	case executordb.PveJobSucceeded:
		return true, true
	case executordb.PveJobFailed:
		return true, false
	}
	return false, true
}

// ReleaseSettledVMIDs releases the started VMID reservations of remoteID
// whose provisioning has settled (vmidSettlement), and those of an unknown
// clone once the guest is in the complete live guest list (it then
// protects the VMID). A reservation that cannot be checked stays. It
// returns the number released.
func (p *PveProvisioner) ReleaseSettledVMIDs(ctx context.Context, remoteID string) (int, error) {
	if err := p.checkDeps(); err != nil {
		return 0, err
	}
	rm, err := p.Mutations.activeRemote(remoteID)
	if err != nil {
		return 0, err
	}
	read, err := p.Mutations.readToken(rm)
	if err != nil {
		return 0, err
	}
	inv, err := p.Reader.ClusterInventory(ctx, rm, read)
	if err != nil {
		return 0, ErrPveTargetChanged
	}
	if inv.Partial || inv.Truncated {
		return 0, ErrPveInventoryIncomplete
	}
	live := make(map[uint64]bool, len(inv.Guests))
	for _, g := range inv.Guests {
		if g.VMID > 0 {
			live[uint64(g.VMID)] = true
		}
	}
	return p.releaseSettled(remoteID, live)
}

// releaseSettled implements ReleaseSettledVMIDs over a complete live guest
// set. Executions this engine is running are left alone.
func (p *PveProvisioner) releaseSettled(remoteID string, live map[uint64]bool) (int, error) {
	p.settle.Lock()
	defer p.settle.Unlock()
	recs, err := p.VMIDs.Reservations(remoteID, p.Mutations.now())
	if err != nil {
		return 0, ErrPveJobStore
	}
	n := 0
	for _, r := range recs {
		if !r.Started || p.Mutations.running(r.ExecutionID) {
			continue
		}
		steps, err := p.Mutations.DB.PveJobSteps(r.ExecutionID)
		if err != nil {
			return n, ErrPveJobStore
		}
		release, _ := vmidSettlement(steps)
		if !release && len(steps) == 1 && steps[0].State == executordb.PveJobUnknown && live[r.VMID] {
			// An unknown clone whose guest exists: the live list protects
			// the VMID. The reservation is also the marker that makes a
			// lost clone of the same template ambiguous (JobTaskID), since
			// this clone's task is unrecorded and may still be listed. It
			// goes only once that task can no longer fall into the window
			// of a later clone step, and while no other clone of the same
			// template is still being identified.
			busy, err := p.sameTemplateCloneOpen(recs, r)
			if err != nil {
				return n, err
			}
			release = !busy && p.Mutations.now().After(steps[0].CreatedAt.Add(pveTaskMatchWindow+2*pveTaskMatchSkew))
		}
		if !release {
			continue
		}
		if err := p.VMIDs.ReleaseVMID(remoteID, r.VMID, r.ExecutionID); err != nil {
			return n, ErrPveJobStore
		}
		p.Mutations.log().Info("audit", "kind", "pve_vmid_released", "remote", remoteID, "vmid", r.VMID, "execution", r.ExecutionID)
		n++
	}
	return n, nil
}

// sameTemplateCloneOpen reports whether another started provisioning of
// r's template has a clone step that is open without a recorded task.
func (p *PveProvisioner) sameTemplateCloneOpen(recs []PveVMIDReservation, r PveVMIDReservation) (bool, error) {
	for _, o := range recs {
		if o.ExecutionID == r.ExecutionID || !o.Started || o.TemplateVMID != r.TemplateVMID {
			continue
		}
		if p.Mutations.running(o.ExecutionID) {
			return true, nil
		}
		steps, err := p.Mutations.DB.PveJobSteps(o.ExecutionID)
		if err != nil {
			return false, ErrPveJobStore
		}
		if len(steps) > 0 && steps[0].UPID == "" && pveJobOpen(steps[0]) {
			return true, nil
		}
	}
	return false, nil
}

// JobTaskID implements PveJobTaskIDs for pve.guest.provision steps from the
// started VMID reservation of the step's execution: the config, resize and
// start tasks carry the new VMID, the clone task the template's VMID. PVE
// names a clone task by its source only, so two provisionings cloning the
// same template cannot be told apart by the task: while another started
// provisioning of that template has a clone without a recorded task, a
// lost clone is ambiguous and never matched. A missing or duplicated
// reservation is ambiguous as well.
func (p *PveProvisioner) JobTaskID(job executordb.PveJob) (string, bool, error) {
	if job.Action != PveGuestProvisionAction {
		return "", false, nil
	}
	if job.Kind != permit.ProviderKindNode || p.VMIDs == nil || p.Mutations == nil || p.Mutations.DB == nil {
		return "", false, ErrPveTaskIDAmbiguous
	}
	recs, err := p.VMIDs.Reservations(job.RemoteID, p.Mutations.now())
	if err != nil {
		return "", false, ErrPveJobStore
	}
	var own PveVMIDReservation
	found := 0
	for _, r := range recs {
		if r.ExecutionID == job.ExecutionID && r.Started {
			own, found = r, found+1
		}
	}
	if found != 1 || !validVMID(own.VMID) {
		return "", false, ErrPveTaskIDAmbiguous
	}
	switch job.TaskType {
	case pveProvisionTaskTypes[pveStepGuestConfig], pveProvisionTaskTypes[pveStepGuestResize], pveProvisionTaskTypes[pveStepGuestStart]:
		return fmt.Sprint(own.VMID), true, nil
	case pveProvisionTaskTypes[pveStepGuestClone]:
	default:
		return "", false, ErrPveTaskIDAmbiguous
	}
	if !validVMID(own.TemplateVMID) {
		return "", false, ErrPveTaskIDAmbiguous
	}
	for _, r := range recs {
		if r.ExecutionID == job.ExecutionID || !r.Started || r.TemplateVMID != own.TemplateVMID {
			continue
		}
		steps, err := p.Mutations.DB.PveJobSteps(r.ExecutionID)
		if err != nil {
			return "", false, ErrPveJobStore
		}
		if len(steps) == 0 || steps[0].UPID == "" {
			return "", false, ErrPveTaskIDAmbiguous
		}
	}
	return fmt.Sprint(own.TemplateVMID), true, nil
}

// ProvisionStepTaskType returns the PVE task type of a provisioning step
// method, for a PveMutationClient's TaskType.
func ProvisionStepTaskType(method string) (string, bool) {
	tt, ok := pveProvisionTaskTypes[method]
	return tt, ok
}

// ProvisionStepTaskID returns the ID field of the PVE task a provisioning
// step creates (the clone's source VMID, otherwise the new guest's VMID),
// for a PveMutationClient's PveStepTaskIDer.
func ProvisionStepTaskID(step PveMutationStep) (string, bool) {
	var a struct {
		SourceVMID int64 `json:"source_vmid"`
		VMID       int64 `json:"vmid"`
	}
	if _, ok := pveProvisionTaskTypes[step.Method]; !ok || json.Unmarshal(step.Args, &a) != nil {
		return "", false
	}
	id := a.VMID
	if step.Method == pveStepGuestClone {
		id = a.SourceVMID
	}
	if id < pvecontract.MinVMID {
		return "", false
	}
	return fmt.Sprint(id), true
}

// PveGuestWriter is the part of pveapi.Writer the provisioning steps use.
type PveGuestWriter interface {
	CloneVM(ctx context.Context, r pveapi.CloneRequest) (string, error)
	SetConfig(ctx context.Context, r pveapi.ConfigRequest) (string, error)
	ResizeDisk(ctx context.Context, r pveapi.ResizeRequest) (string, error)
	StartVM(ctx context.Context, node string, vmid int64) (string, error)
}

// DispatchProvisionStep decodes one provisioning step strictly and sends it
// with w, for a PveMutationClient's Dispatch. The config step's password is
// opened from secrets at exactly the bound vault reference (which must be
// a guest password) and version and is sent only as cipassword. A step
// refused before anything reached PVE, or refused by PVE, wraps
// ErrPveRejected; any other error means the request may have been
// received. Errors never carry the password.
func DispatchProvisionStep(ctx context.Context, w PveGuestWriter, secrets pveSecrets, node string, step PveMutationStep) (string, error) {
	var upid string
	var err error
	switch step.Method {
	case pveStepGuestClone:
		var a pveCloneArgs
		if err := decodeStepArgsMax(step.Args, &a, maxPveProvisionStepArgs); err != nil {
			return "", err
		}
		upid, err = w.CloneVM(ctx, pveapi.CloneRequest{Node: node, SourceVMID: a.SourceVMID, NewVMID: a.NewVMID, Name: a.Name, Storage: a.Storage})
	case pveStepGuestConfig:
		var a pveConfigArgs
		if err := decodeStepArgsMax(step.Args, &a, maxPveProvisionStepArgs); err != nil {
			return "", err
		}
		r, err := configRequest(node, a)
		if err != nil {
			return "", err
		}
		if a.PasswordRef != "" || a.PasswordVersion != 0 {
			pw, err := openGuestPassword(secrets, a.PasswordRef, a.PasswordVersion)
			if err != nil {
				return "", err
			}
			r.CIPassword = pw
		}
		upid, err = w.SetConfig(ctx, r)
		return pveWriteResult(step.Method, upid, err)
	case pveStepGuestResize:
		var a pveResizeArgs
		if err := decodeStepArgsMax(step.Args, &a, maxPveProvisionStepArgs); err != nil {
			return "", err
		}
		upid, err = w.ResizeDisk(ctx, pveapi.ResizeRequest{Node: node, VMID: a.VMID, Disk: a.Disk, SizeGiB: a.SizeGiB})
	case pveStepGuestStart:
		var a pveStartArgs
		if err := decodeStepArgsMax(step.Args, &a, maxPveProvisionStepArgs); err != nil {
			return "", err
		}
		upid, err = w.StartVM(ctx, node, a.VMID)
	default:
		return "", fmt.Errorf("dispatch provision step: %w", ErrPveRejected)
	}
	return pveWriteResult(step.Method, upid, err)
}

// configRequest converts the config step into the typed pveapi request.
func configRequest(node string, a pveConfigArgs) (pveapi.ConfigRequest, error) {
	agent := a.Agent
	ip := &pveapi.IPConfig{DHCP: a.IPConfig0.DHCP}
	if !a.IPConfig0.DHCP {
		pfx, err := netip.ParsePrefix(a.IPConfig0.Address)
		if err != nil {
			return pveapi.ConfigRequest{}, fmt.Errorf("decode config step: %w", ErrPveRejected)
		}
		ip.Address = pfx
		if a.IPConfig0.Gateway != "" {
			gw, err := netip.ParseAddr(a.IPConfig0.Gateway)
			if err != nil {
				return pveapi.ConfigRequest{}, fmt.Errorf("decode config step: %w", ErrPveRejected)
			}
			ip.Gateway = gw
		}
	}
	ns := make([]netip.Addr, 0, len(a.Nameservers))
	for _, s := range a.Nameservers {
		ad, err := netip.ParseAddr(s)
		if err != nil {
			return pveapi.ConfigRequest{}, fmt.Errorf("decode config step: %w", ErrPveRejected)
		}
		ns = append(ns, ad)
	}
	r := pveapi.ConfigRequest{
		Node: node, VMID: a.VMID, Name: a.Name, Cores: a.Cores, MemoryMiB: a.MemoryMiB, Agent: &agent,
		Net0:      &pveapi.NetConfig{Model: a.Net0.Model, Bridge: a.Net0.Bridge, Tag: a.Net0.Tag, MAC: a.Net0.MAC},
		IPConfig0: ip, CIUser: a.CIUser, SSHKeys: a.SSHKeys,
	}
	// Empty lists are not sent (PVE keeps its default resolver settings).
	if len(ns) > 0 {
		r.Nameservers = ns
	}
	if len(a.SearchDomains) > 0 {
		r.SearchDomains = a.SearchDomains
	}
	return r, nil
}

// openGuestPassword opens a guest password at exactly version. Only vault
// entries in the guest password namespace can be opened, so a step can
// never send another secret (such as a PVE token) as cipassword.
func openGuestPassword(secrets pveSecrets, ref string, version int64) (pveapi.Secret, error) {
	id, ok := strings.CutPrefix(ref, pveGuestPasswordPrefix)
	if !ok || !pveGuestPasswordIDRe.MatchString(id) || version < 1 || secrets == nil {
		return pveapi.Secret{}, fmt.Errorf("dispatch config step: %w: %w", ErrPveRejected, ErrPveGuestPassword)
	}
	if st, err := secrets.State(); err != nil || st != vault.StateUnlocked {
		return pveapi.Secret{}, fmt.Errorf("dispatch config step: %w: %w", ErrPveRejected, ErrPveGuestPassword)
	}
	secret, v, err := secrets.OpenVersion(ref)
	defer clear(secret)
	if err != nil || v != version || !validGuestPassword(secret) {
		return pveapi.Secret{}, fmt.Errorf("dispatch config step: %w: %w", ErrPveRejected, ErrPveGuestPassword)
	}
	return pveapi.NewSecret(string(secret)), nil
}
