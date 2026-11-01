// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Config-set limits, named next to the code that enforces them.
const (
	// MaxCores bounds the vCPU core count.
	MaxCores = 512
	// MinMemoryMiB is the smallest accepted guest memory.
	MinMemoryMiB = 64
	// MaxMemoryMiB bounds guest memory (4 TiB).
	MaxMemoryMiB = 4 << 20
	// MaxSSHKeys bounds the number of cloud-init SSH public keys.
	MaxSSHKeys = 32
	// MaxSSHKeysBytes bounds the encoded cloud-init sshkeys value.
	MaxSSHKeysBytes = 16 << 10
	// MaxNameservers bounds cloud-init DNS servers.
	MaxNameservers = 3
	// MaxSearchDomains bounds cloud-init DNS search domains.
	MaxSearchDomains = 6
	// MinPasswordBytes is the shortest accepted cloud-init password.
	MinPasswordBytes = 8
	// MaxPasswordBytes bounds the cloud-init password.
	MaxPasswordBytes = 256
	// MaxVLANTag is the highest 802.1Q VLAN id.
	MaxVLANTag = 4094
)

var (
	// bridgeRe allowlists Linux bridge / SDN vnet names (IFNAMSIZ-1).
	bridgeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,14}$`)
	// ciUserRe allowlists a Linux user name for cloud-init.
	ciUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// NIC models offered for net0.
const (
	// NICVirtio is the paravirtualized VirtIO NIC (default).
	NICVirtio = "virtio"
	// NICE1000 is the emulated Intel E1000 NIC.
	NICE1000 = "e1000"
)

// Secret holds a secret write value such as the cloud-init password. It
// never prints its value: fmt, %v, %+v, %#v and JSON all render
// "[redacted]".
type Secret struct{ v string }

// NewSecret wraps a secret value.
func NewSecret(s string) Secret { return Secret{v: s} }

// IsZero reports whether no secret is set.
func (s Secret) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer without revealing the value.
func (s Secret) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer without revealing the value.
func (s Secret) GoString() string { return "[redacted]" }

// MarshalText renders the redaction marker instead of the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// NetConfig is the allowlisted net0 definition: model, bridge, optional
// VLAN tag and optional fixed MAC. Firewall, rate and queue options are
// not offered.
type NetConfig struct {
	// Model is NICVirtio or NICE1000; empty means NICVirtio.
	Model string
	// Bridge is the Linux bridge or SDN vnet, e.g. "vmbr0".
	Bridge string
	// Tag is the VLAN tag 1..MaxVLANTag; 0 means untagged.
	Tag int
	// MAC is a fixed unicast MAC address; empty lets PVE generate one.
	MAC string
}

// IPConfig is the allowlisted cloud-init ipconfig0: IPv4 DHCP, or a static
// IPv4 address with an optional gateway inside the prefix.
type IPConfig struct {
	// DHCP selects DHCPv4. Address and Gateway must then be unset.
	DHCP bool
	// Address is the static IPv4 address with prefix length.
	Address netip.Prefix
	// Gateway is the optional IPv4 gateway.
	Gateway netip.Addr
}

// ConfigRequest sets an allowlisted subset of a QEMU guest's configuration
// (POST /nodes/{node}/qemu/{vmid}/config). Only these named fields exist;
// zero values are not sent. Nothing can be deleted through this call.
type ConfigRequest struct {
	// Node is the node holding the guest.
	Node string
	// VMID is the guest.
	VMID int64

	// Name is the guest name (DNS name).
	Name string
	// Cores is the vCPU core count, 1..MaxCores.
	Cores int
	// MemoryMiB is the guest memory, MinMemoryMiB..MaxMemoryMiB.
	MemoryMiB int
	// Agent enables or disables the QEMU guest agent option.
	Agent *bool
	// Net0 replaces the first network device.
	Net0 *NetConfig
	// IPConfig0 sets cloud-init addressing for net0.
	IPConfig0 *IPConfig
	// CIUser is the cloud-init default user.
	CIUser string
	// SSHKeys are OpenSSH public keys; each is re-encoded canonically, so
	// comments are dropped. Keys with authorized_keys options (command=,
	// from=, restrict, ...) are rejected: re-encoding would otherwise
	// install them without their restrictions.
	SSHKeys []string
	// CIPassword is the cloud-init password. It is sent only as
	// "cipassword" and never appears in errors.
	CIPassword Secret
	// Nameservers are the cloud-init DNS servers.
	Nameservers []netip.Addr
	// SearchDomains are the cloud-init DNS search domains.
	SearchDomains []string
}

// SetConfig applies the allowlisted configuration and returns the UPID of
// the qmconfig task. At least one field must be set.
func (w *Writer) SetConfig(ctx context.Context, r ConfigRequest) (string, error) {
	const op = "config"
	path, err := guestPath(op, r.Node, r.VMID)
	if err != nil {
		return "", err
	}
	form, err := r.form()
	if err != nil {
		return "", err
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/config", form: form},
		r.Node, "qmconfig", strconv.FormatInt(r.VMID, 10))
}

// form validates every set field and encodes the PVE parameters.
func (r ConfigRequest) form() (url.Values, error) {
	const op = "config"
	f := url.Values{}
	if r.Name != "" {
		if !validDNSName(r.Name) {
			return nil, invalid(op, "name")
		}
		f.Set("name", r.Name)
	}
	if r.Cores != 0 {
		if r.Cores < 1 || r.Cores > MaxCores {
			return nil, invalid(op, "cores")
		}
		f.Set("cores", strconv.Itoa(r.Cores))
	}
	if r.MemoryMiB != 0 {
		if r.MemoryMiB < MinMemoryMiB || r.MemoryMiB > MaxMemoryMiB {
			return nil, invalid(op, "memory")
		}
		f.Set("memory", strconv.Itoa(r.MemoryMiB))
	}
	if r.Agent != nil {
		if *r.Agent {
			f.Set("agent", "enabled=1")
		} else {
			f.Set("agent", "enabled=0")
		}
	}
	if r.Net0 != nil {
		v, err := r.Net0.encode()
		if err != nil {
			return nil, err
		}
		f.Set("net0", v)
	}
	if r.IPConfig0 != nil {
		v, err := r.IPConfig0.encode()
		if err != nil {
			return nil, err
		}
		f.Set("ipconfig0", v)
	}
	if r.CIUser != "" {
		if !ciUserRe.MatchString(r.CIUser) {
			return nil, invalid(op, "ciuser")
		}
		f.Set("ciuser", r.CIUser)
	}
	if r.SSHKeys != nil {
		v, err := encodeSSHKeys(r.SSHKeys)
		if err != nil {
			return nil, err
		}
		f.Set("sshkeys", v)
	}
	if !r.CIPassword.IsZero() {
		if !validPassword(r.CIPassword.v) {
			return nil, invalid(op, "cipassword")
		}
		f.Set("cipassword", r.CIPassword.v)
	}
	if r.Nameservers != nil {
		if len(r.Nameservers) == 0 || len(r.Nameservers) > MaxNameservers {
			return nil, invalid(op, "nameserver")
		}
		parts := make([]string, 0, len(r.Nameservers))
		for _, a := range r.Nameservers {
			if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
				return nil, invalid(op, "nameserver")
			}
			parts = append(parts, a.Unmap().String())
		}
		f.Set("nameserver", strings.Join(parts, " "))
	}
	if r.SearchDomains != nil {
		if len(r.SearchDomains) == 0 || len(r.SearchDomains) > MaxSearchDomains {
			return nil, invalid(op, "searchdomain")
		}
		for _, d := range r.SearchDomains {
			if !validDNSName(d) {
				return nil, invalid(op, "searchdomain")
			}
		}
		f.Set("searchdomain", strings.Join(r.SearchDomains, " "))
	}
	if len(f) == 0 {
		return nil, invalid(op, "no fields set")
	}
	return f, nil
}

// encode validates and renders the net0 property string.
func (n NetConfig) encode() (string, error) {
	const op = "config"
	model := n.Model
	if model == "" {
		model = NICVirtio
	}
	if model != NICVirtio && model != NICE1000 {
		return "", invalid(op, "net0 model")
	}
	if !bridgeRe.MatchString(n.Bridge) {
		return "", invalid(op, "net0 bridge")
	}
	if n.Tag < 0 || n.Tag > MaxVLANTag {
		return "", invalid(op, "net0 tag")
	}
	v := model
	if n.MAC != "" {
		hw, err := net.ParseMAC(n.MAC)
		// Unicast (I/G bit clear), EUI-48 only, never all-zero.
		if err != nil || len(hw) != 6 || hw[0]&1 != 0 || string(hw) == "\x00\x00\x00\x00\x00\x00" {
			return "", invalid(op, "net0 mac")
		}
		v += "=" + strings.ToUpper(hw.String())
	}
	v += ",bridge=" + n.Bridge
	if n.Tag != 0 {
		v += ",tag=" + strconv.Itoa(n.Tag)
	}
	return v, nil
}

// encode validates and renders the ipconfig0 property string.
func (c IPConfig) encode() (string, error) {
	const op = "config"
	if c.DHCP {
		if c.Address.IsValid() || c.Gateway.IsValid() {
			return "", invalid(op, "ipconfig0")
		}
		return "ip=dhcp", nil
	}
	p := c.Address
	a := p.Addr()
	if !p.IsValid() || !a.Is4() || p.Bits() < 1 || p.Bits() > 32 ||
		a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return "", invalid(op, "ipconfig0 ip")
	}
	v := "ip=" + p.String()
	if c.Gateway.IsValid() {
		g := c.Gateway
		if !g.Is4() || g == a || !p.Masked().Contains(g) {
			return "", invalid(op, "ipconfig0 gw")
		}
		v += ",gw=" + g.String()
	}
	return v, nil
}

// encodeSSHKeys parses each key, rejects keys with authorized_keys
// options, re-encodes it canonically (type and base64 only) and
// percent-encodes the newline-joined list, which is the
// encoding PVE expects for the sshkeys parameter.
func encodeSSHKeys(keys []string) (string, error) {
	const op = "config"
	if len(keys) == 0 || len(keys) > MaxSSHKeys {
		return "", invalid(op, "sshkeys")
	}
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		if len(k) > MaxSSHKeysBytes || strings.ContainsAny(k, "\r\n") {
			return "", invalid(op, "sshkeys")
		}
		pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil || len(opts) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
			return "", invalid(op, "sshkeys")
		}
		lines = append(lines, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
	}
	v := strings.ReplaceAll(url.QueryEscape(strings.Join(lines, "\n")), "+", "%20")
	if len(v) > MaxSSHKeysBytes {
		return "", invalid(op, "sshkeys")
	}
	return v, nil
}

// validPassword accepts MinPasswordBytes..MaxPasswordBytes of valid UTF-8
// without control characters.
func validPassword(p string) bool {
	if len(p) < MinPasswordBytes || len(p) > MaxPasswordBytes || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7F {
			return false
		}
	}
	return true
}
