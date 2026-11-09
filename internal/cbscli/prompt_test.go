// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"errors"
	"strings"
	"testing"
)

// The prompts below are SYNTHETIC. They follow the shape described in the
// Cisco CBS CLI guides (hostname followed by '#' or '>') and will be
// replaced by sanitized lab output once ND-03 has recorded it.

func TestParsePromptAcceptsHostnamePrompts(t *testing.T) {
	for _, p := range []string{
		"switch#",
		"switch>",
		"sw-lab-01#",
		"SW1.lab>",
		"a#",
		strings.Repeat("h", MaxHostnameBytes) + "#",
		"sw1#  ", // trailing blanks after the prompt character
	} {
		got, ok := parsePrompt(p)
		if !ok {
			t.Errorf("parsePrompt(%q) rejected", p)
			continue
		}
		if got != strings.TrimRight(p, " ") {
			t.Errorf("parsePrompt(%q) = %q", p, got)
		}
	}
}

func TestParsePromptRejectsOtherShapes(t *testing.T) {
	for _, p := range []string{
		"",
		"#",
		">",
		"switch",
		"switch(config)#",
		"switch(config-if)#",
		"-switch#",
		"sw itch#",
		"sw1#x",
		"User Name:",
		"Password:",
		"--More--",
		"More: <space>,  Quit: q or CTRL+Z, One line: <return>",
		"sw1\x1b[0m#",
		"swîtch#",
		strings.Repeat("h", MaxHostnameBytes+1) + "#",
	} {
		if got, ok := parsePrompt(p); ok {
			t.Errorf("parsePrompt(%q) accepted as %q", p, got)
		}
	}
}

func TestLooksInteractiveFlagsPagersConfirmationsAndLogins(t *testing.T) {
	for _, tail := range []string{
		"--More--",
		" --More-- ",
		"More: <space>,  Quit: q or CTRL+Z, One line: <return> ",
		"Overwrite file [startup-config].... (Y/N)[N] ?",
		"Are you sure? [y/n]",
		"Proceed with reload? [confirm]",
		"User Name:",
		"Username: ",
		"Password:",
		"login:",
		"switch(config)#",
		"switch(config-if)#",
		"other-switch#",
		"switch>",
		"Press any key to continue",
		"Continue? ",
	} {
		if !looksInteractive(tail) {
			t.Errorf("looksInteractive(%q) = false", tail)
		}
	}
	for _, tail := range []string{
		"",
		"gi1/0/1   connected   1   a-full  a-1000",
		"   Unit    MAC address",
	} {
		if looksInteractive(tail) {
			t.Errorf("looksInteractive(%q) = true", tail)
		}
	}
}

func TestFixedCommandsAreExactlyThePhaseOneAllowlist(t *testing.T) {
	want := []string{
		"show version",
		"show system",
		"show running-config",
		"show startup-config",
		"show vlan",
		"show interfaces status",
		"show interfaces description",
		"show mac address-table",
		"show lldp neighbors",
		"show ip interface",
	}
	got := map[string]bool{}
	for _, c := range []Command{
		ShowVersion(), ShowSystem(), ShowRunningConfig(), ShowStartupConfig(),
		ShowVLAN(), ShowInterfacesStatus(), ShowInterfacesDescription(),
		ShowMACAddressTable(), ShowLLDPNeighbors(), ShowIPInterface(),
	} {
		if err := c.check(); err != nil {
			t.Errorf("%q: %v", c, err)
		}
		got[c.String()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing allowlisted command %q", w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d fixed commands, want %d", len(got), len(want))
	}
}

func TestOnlyConfigCommandsGetTheConfigCap(t *testing.T) {
	for _, c := range []Command{ShowRunningConfig(), ShowStartupConfig()} {
		if c.outputCap() != MaxConfigOutputBytes || !c.config {
			t.Errorf("%q: cap %d config %v", c, c.outputCap(), c.config)
		}
	}
	for _, c := range []Command{ShowVersion(), ShowVLAN(), ShowMACAddressTable()} {
		if c.outputCap() != MaxCommandOutputBytes || c.config {
			t.Errorf("%q: cap %d config %v", c, c.outputCap(), c.config)
		}
	}
}

func TestInterfaceCommandsValidateTheName(t *testing.T) {
	for _, name := range []string{"gi1/0/1", "GigabitEthernet1/0/24", "te1/0/2", "Po1", "fa1", "gi0/1"} {
		c, err := ShowInterfacesSwitchport(name)
		if err != nil {
			t.Errorf("ShowInterfacesSwitchport(%q): %v", name, err)
			continue
		}
		if c.String() != "show interfaces switchport "+name {
			t.Errorf("got %q", c)
		}
		l, err := ShowLLDPNeighborsOf(name)
		if err != nil || l.String() != "show lldp neighbors "+name {
			t.Errorf("ShowLLDPNeighborsOf(%q) = %q, %v", name, l, err)
		}
	}
	for _, name := range []string{
		"",
		"gi1/0/1\n",
		"gi1/0/1\rreload",
		"gi1/0/1 ; reload",
		"gi1/0/1 | include x",
		"gi1/0/1\x00",
		"1/0/1",
		"gi",
		"gi1//1",
		"gi1/0/1/2/3",
		"gi1/0/",
		"gï1/0/1",
		"gi1/0/1?",
		strings.Repeat("g", MaxInterfaceNameBytes) + "1",
	} {
		if _, err := ShowInterfacesSwitchport(name); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("ShowInterfacesSwitchport(%q) err = %v, want ErrNotAllowed", name, err)
		}
		if _, err := ShowLLDPNeighborsOf(name); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("ShowLLDPNeighborsOf(%q) err = %v, want ErrNotAllowed", name, err)
		}
	}
}

func TestZeroOrForgedCommandIsNotAllowed(t *testing.T) {
	for _, c := range []Command{
		{},
		{text: "configure terminal"},
		{text: "reload"},
		{text: "copy running-config startup-config"},
		{text: "terminal datadump"},
		{text: "show running-config | include password"},
		{text: "show version\nreload"},
		{text: "show interfaces switchport gi1/0/1 x"},
	} {
		if err := c.check(); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("check(%q) = %v, want ErrNotAllowed", c.text, err)
		}
	}
}

func TestLimitsMirrorTheND04Contract(t *testing.T) {
	// Values of internal/netdevcontract (ND-04, ADR 0010 D3). This test
	// fails if a mirror drifts; switch to the import once ND-04 is merged.
	cases := []struct {
		name      string
		got, want int
	}{
		{"MaxLineBytes", MaxLineBytes, 4 << 10},
		{"MaxConfigLines", MaxConfigLines, 100000},
		{"MaxConfigOutputBytes", MaxConfigOutputBytes, 4 << 20},
		{"MaxCommandOutputBytes", MaxCommandOutputBytes, 1 << 20},
		{"MaxInterfaceNameBytes", MaxInterfaceNameBytes, 64},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
