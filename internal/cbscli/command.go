// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrNotAllowed marks a command that is not on the phase-1 allowlist or an
// argument that fails validation. Nothing is sent to the device.
var ErrNotAllowed = errors.New("cbscli: command not allowed")

// Limits of ADR 0010 D3. They mirror internal/netdevcontract (ND-04), which
// is not yet on main; TestLimitsMirrorTheND04Contract pins the values.
// Replace them with the netdevcontract constants once ND-04 is merged.
const (
	// MaxLineBytes bounds one line of CBS output (netdevcontract.MaxLineBytes).
	MaxLineBytes = 4 << 10
	// MaxConfigLines bounds the lines of show running-config and show
	// startup-config (netdevcontract.MaxConfigLines).
	MaxConfigLines = 100000
	// MaxConfigOutputBytes caps the output of show running-config and show
	// startup-config (netdevcontract.MaxCBSConfigOutputBytes).
	MaxConfigOutputBytes = 4 << 20
	// MaxCommandOutputBytes caps the output of every other command
	// (netdevcontract.MaxCBSCommandOutputBytes).
	MaxCommandOutputBytes = 1 << 20
	// MaxInterfaceNameBytes bounds an interface name argument
	// (netdevcontract.MaxInterfaceNameBytes).
	MaxInterfaceNameBytes = 64
)

// Command is one read command from the phase-1 allowlist of ADR 0010 D3.
// It can only be built by the constructors below; the zero value is
// refused.
type Command struct {
	text   string
	config bool
}

// String returns the exact command line sent to the device.
func (c Command) String() string { return c.text }

// outputCap is the transport byte cap of the command's output.
func (c Command) outputCap() int {
	if c.config {
		return MaxConfigOutputBytes
	}
	return MaxCommandOutputBytes
}

// fixedCommands is the allowlist of commands without arguments, with
// whether the command prints a configuration. Exact strings, verify each on
// the lab firmware (ND-03).
var fixedCommands = map[string]bool{
	"show version":                false,
	"show system":                 false,
	"show running-config":         true,
	"show startup-config":         true,
	"show vlan":                   false,
	"show interfaces status":      false,
	"show interfaces description": false,
	"show mac address-table":      false,
	"show lldp neighbors":         false,
	"show ip interface":           false,
}

// interfaceCommands are the allowlisted prefixes taking one interface name.
var interfaceCommands = []string{
	"show interfaces switchport ",
	"show lldp neighbors ",
}

// interfaceRE is the CBS interface name shape: a type keyword (gi, te, fa,
// Po, GigabitEthernet, ...) and one to three numbers separated by '/'.
// Synthetic until ND-03 records the lab interface names.
var interfaceRE = regexp.MustCompile(`^[A-Za-z]{2,32}[0-9]{1,3}(/[0-9]{1,3}){0,2}$`)

func validInterface(name string) bool {
	return len(name) <= MaxInterfaceNameBytes && interfaceRE.MatchString(name)
}

// check re-validates c against the allowlist right before it is sent.
func (c Command) check() error {
	if cfg, ok := fixedCommands[c.text]; ok && cfg == c.config {
		return nil
	}
	if !c.config {
		for _, p := range interfaceCommands {
			if len(c.text) > len(p) && c.text[:len(p)] == p && validInterface(c.text[len(p):]) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %q", ErrNotAllowed, c.text)
}

func fixed(text string) Command { return Command{text: text, config: fixedCommands[text]} }

// ShowVersion is "show version".
func ShowVersion() Command { return fixed("show version") }

// ShowSystem is "show system".
func ShowSystem() Command { return fixed("show system") }

// ShowRunningConfig is "show running-config" (4 MiB cap).
func ShowRunningConfig() Command { return fixed("show running-config") }

// ShowStartupConfig is "show startup-config" (4 MiB cap).
func ShowStartupConfig() Command { return fixed("show startup-config") }

// ShowVLAN is "show vlan".
func ShowVLAN() Command { return fixed("show vlan") }

// ShowInterfacesStatus is "show interfaces status".
func ShowInterfacesStatus() Command { return fixed("show interfaces status") }

// ShowInterfacesDescription is "show interfaces description".
func ShowInterfacesDescription() Command { return fixed("show interfaces description") }

// ShowMACAddressTable is "show mac address-table".
func ShowMACAddressTable() Command { return fixed("show mac address-table") }

// ShowLLDPNeighbors is "show lldp neighbors".
func ShowLLDPNeighbors() Command { return fixed("show lldp neighbors") }

// ShowIPInterface is "show ip interface".
func ShowIPInterface() Command { return fixed("show ip interface") }

// ShowInterfacesSwitchport is "show interfaces switchport <ifname>". The
// name must have the CBS interface shape; anything else is ErrNotAllowed.
func ShowInterfacesSwitchport(ifname string) (Command, error) {
	return withInterface("show interfaces switchport ", ifname)
}

// ShowLLDPNeighborsOf is "show lldp neighbors <ifname>".
func ShowLLDPNeighborsOf(ifname string) (Command, error) {
	return withInterface("show lldp neighbors ", ifname)
}

func withInterface(prefix, ifname string) (Command, error) {
	if !validInterface(ifname) {
		return Command{}, fmt.Errorf("%w: invalid interface name (%d bytes)", ErrNotAllowed, len(ifname))
	}
	return Command{text: prefix + ifname}, nil
}
