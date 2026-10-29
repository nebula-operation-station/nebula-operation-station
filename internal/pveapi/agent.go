// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrAgentMalformed indicates the guest agent answered but the response
// does not match the expected schema.
var ErrAgentMalformed = errors.New("pveapi: guest agent response malformed")

// Limits for guest agent responses.
const (
	MaxAgentInterfaces    = 64
	MaxAgentIPsPerIF      = 32
	MaxAgentFlagsPerIF    = 16
	MaxAgentFilesystems   = 64
	MaxAgentOSVersionLen  = 64
	MaxAgentOSNameLen     = 128
	MaxAgentFSNameLen     = 128
	MaxAgentMountpointLen = 255
	MaxAgentFSTypeLen     = 32
	MaxAgentMTU           = 65535
)

// AgentIPAddress is one address on a guest interface.
type AgentIPAddress struct {
	IP     string
	Prefix int
}

// AgentInterface is one network interface reported by the QEMU guest
// agent (network-get-interfaces).
type AgentInterface struct {
	Name  string
	MAC   string
	MTU   int
	IPs   []AgentIPAddress
	Flags []string
}

// AgentInterfaces is the result of a network-get-interfaces query. When
// Available is false, Reason holds the sanitized cause.
type AgentInterfaces struct {
	Available  bool
	Reason     string
	Interfaces []AgentInterface
}

// AgentOSInfo is the result of a get-osinfo query.
type AgentOSInfo struct {
	Available bool
	Reason    string
	Version   string
	Name      string
}

// AgentFilesystem is one filesystem reported by get-fsinfo.
type AgentFilesystem struct {
	Name       string
	Mountpoint string
	Type       string
	Size       int64
	Used       int64
}

// AgentFilesystems is the result of a get-fsinfo query.
type AgentFilesystems struct {
	Available   bool
	Reason      string
	Filesystems []AgentFilesystem
}

// AgentNetworkInterfaces queries the guest agent of QEMU guest vmid on
// node for its network interfaces. An unavailable agent returns
// Available=false with a reason, not an error.
func (c *Client) AgentNetworkInterfaces(ctx context.Context, node string, vmid int) (*AgentInterfaces, error) {
	data, err := c.agentGet(ctx, node, vmid, "network-get-interfaces")
	if err != nil {
		if reason, ok := agentUnavailable(err); ok {
			return &AgentInterfaces{Reason: reason}, nil
		}
		return nil, err
	}
	ifs, err := parseAgentInterfaces(data)
	if err != nil {
		return nil, err
	}
	return &AgentInterfaces{Available: true, Interfaces: ifs}, nil
}

// AgentOSInfo queries the guest agent of QEMU guest vmid on node for its
// OS version. An unavailable agent returns Available=false with a reason,
// not an error.
func (c *Client) AgentOSInfo(ctx context.Context, node string, vmid int) (*AgentOSInfo, error) {
	data, err := c.agentGet(ctx, node, vmid, "get-osinfo")
	if err != nil {
		if reason, ok := agentUnavailable(err); ok {
			return &AgentOSInfo{Reason: reason}, nil
		}
		return nil, err
	}
	version, name, err := parseAgentOSInfo(data)
	if err != nil {
		return nil, err
	}
	return &AgentOSInfo{Available: true, Version: version, Name: name}, nil
}

// AgentFSInfo queries the guest agent of QEMU guest vmid on node for its
// filesystems. An unavailable agent returns Available=false with a
// reason, not an error.
func (c *Client) AgentFSInfo(ctx context.Context, node string, vmid int) (*AgentFilesystems, error) {
	data, err := c.agentGet(ctx, node, vmid, "get-fsinfo")
	if err != nil {
		if reason, ok := agentUnavailable(err); ok {
			return &AgentFilesystems{Reason: reason}, nil
		}
		return nil, err
	}
	fss, err := parseAgentFSInfo(data)
	if err != nil {
		return nil, err
	}
	return &AgentFilesystems{Available: true, Filesystems: fss}, nil
}

// agentGet runs one QEMU guest agent command.
func (c *Client) agentGet(ctx context.Context, node string, vmid int, cmd string) (json.RawMessage, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	if err := validateVMID(vmid); err != nil {
		return nil, err
	}
	return c.do(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/agent/%s", node, vmid, cmd))
}

// agentUnavailable reports whether err means the guest agent is not
// reachable and returns the sanitized reason.
func agentUnavailable(err error) (string, bool) {
	var se *StatusError
	if !errors.As(err, &se) {
		return "", false
	}
	if se.Code == http.StatusNotFound {
		return "guest agent endpoint not found (guest stopped?)", true
	}
	if se.Code >= 500 {
		msg := strings.ToLower(se.Message)
		for _, hint := range []string{"agent", "not running", "node is down"} {
			if strings.Contains(msg, hint) {
				return se.Message, true
			}
		}
	}
	return "", false
}

// parseAgentInterfaces decodes a network-get-interfaces response.
func parseAgentInterfaces(data json.RawMessage) ([]AgentInterface, error) {
	var raw []struct {
		Name      string `json:"name"`
		MAC       string `json:"mac-address"`
		MTU       *int   `json:"mtu"`
		IPAddress []struct {
			IP     string `json:"ip-address"`
			Prefix *int   `json:"prefix"`
		} `json:"ip-address"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentMalformed, err)
	}
	if len(raw) > MaxAgentInterfaces {
		return nil, fmt.Errorf("%w: %d interfaces > %d", ErrAgentMalformed, len(raw), MaxAgentInterfaces)
	}
	out := make([]AgentInterface, 0, len(raw))
	for _, r := range raw {
		iface := AgentInterface{Name: sanitizeText(r.Name, 64)}
		if macPattern.MatchString(r.MAC) {
			iface.MAC = strings.ToLower(r.MAC)
		}
		if r.MTU != nil {
			if *r.MTU < 0 || *r.MTU > MaxAgentMTU {
				return nil, fmt.Errorf("%w: bad mtu %d", ErrAgentMalformed, *r.MTU)
			}
			iface.MTU = *r.MTU
		}
		if len(r.IPAddress) > MaxAgentIPsPerIF {
			return nil, fmt.Errorf("%w: %d ips on %s > %d",
				ErrAgentMalformed, len(r.IPAddress), iface.Name, MaxAgentIPsPerIF)
		}
		for _, ip := range r.IPAddress {
			if net.ParseIP(ip.IP) == nil {
				return nil, fmt.Errorf("%w: bad ip %q", ErrAgentMalformed, ip.IP)
			}
			prefix := 0
			if ip.Prefix != nil {
				if *ip.Prefix < 0 || *ip.Prefix > 128 {
					return nil, fmt.Errorf("%w: bad prefix %d", ErrAgentMalformed, *ip.Prefix)
				}
				prefix = *ip.Prefix
			}
			iface.IPs = append(iface.IPs, AgentIPAddress{IP: ip.IP, Prefix: prefix})
		}
		if len(r.Flags) > MaxAgentFlagsPerIF {
			return nil, fmt.Errorf("%w: %d flags on %s > %d",
				ErrAgentMalformed, len(r.Flags), iface.Name, MaxAgentFlagsPerIF)
		}
		for _, f := range r.Flags {
			f = sanitizeText(f, 32)
			if f != "" {
				iface.Flags = append(iface.Flags, f)
			}
		}
		out = append(out, iface)
	}
	return out, nil
}

// parseAgentOSInfo decodes a get-osinfo response.
func parseAgentOSInfo(data json.RawMessage) (version, name string, err error) {
	var raw struct {
		Version string `json:"version"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrAgentMalformed, err)
	}
	return sanitizeText(raw.Version, MaxAgentOSVersionLen),
		sanitizeText(raw.Name, MaxAgentOSNameLen), nil
}

// parseAgentFSInfo decodes a get-fsinfo response.
func parseAgentFSInfo(data json.RawMessage) ([]AgentFilesystem, error) {
	var raw []struct {
		Name       string `json:"name"`
		Mountpoint string `json:"mountpoint"`
		Type       string `json:"type"`
		Size       *int64 `json:"size"`
		Used       *int64 `json:"used"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentMalformed, err)
	}
	if len(raw) > MaxAgentFilesystems {
		return nil, fmt.Errorf("%w: %d filesystems > %d",
			ErrAgentMalformed, len(raw), MaxAgentFilesystems)
	}
	out := make([]AgentFilesystem, 0, len(raw))
	for _, r := range raw {
		fs := AgentFilesystem{
			Name:       sanitizeText(r.Name, MaxAgentFSNameLen),
			Mountpoint: sanitizeText(r.Mountpoint, MaxAgentMountpointLen),
			Type:       sanitizeText(r.Type, MaxAgentFSTypeLen),
		}
		if r.Size != nil {
			if *r.Size < 0 {
				return nil, fmt.Errorf("%w: negative size", ErrAgentMalformed)
			}
			fs.Size = *r.Size
		}
		if r.Used != nil {
			if *r.Used < 0 {
				return nil, fmt.Errorf("%w: negative used", ErrAgentMalformed)
			}
			fs.Used = *r.Used
		}
		out = append(out, fs)
	}
	return out, nil
}
