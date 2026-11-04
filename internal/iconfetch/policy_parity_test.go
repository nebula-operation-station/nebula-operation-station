// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"net/netip"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/servicecheck"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netpolicy"
)

// TestPolicyParityWithServicecheck ties iconfetch to servicecheck: every
// address servicecheck treats as internal must be refused by the icon
// dialer, and every host name servicecheck refuses must be refused by
// ValidateURL even when it is on the allowlist, and both must agree with
// internal/netpolicy (servicecheck with Reserved, the dialer with NonPublic).
func TestPolicyParityWithServicecheck(t *testing.T) {
	addrs := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "100.127.255.255",
		"172.16.0.1", "172.31.255.255", "192.168.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:224.0.0.1",
		"::", "::1", "fe80::1", "fc00::1", "ff02::1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001::1", "2606:4700::1111",
		"1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "192.169.0.1",
		"192.0.2.1", "192.88.99.1", "198.18.0.1", "203.0.113.1", "223.255.255.255", "::ffff:140.82.112.3",
	}
	for _, s := range addrs {
		scErr := servicecheck.ValidateCheck(servicecheck.Check{Protocol: "tcp", Destination: s, Port: 443})
		_, refused := forbiddenAddr(netip.MustParseAddr(s))
		if scErr != nil && !refused {
			t.Errorf("%s: servicecheck refuses (%v) but the icon dialer would connect", s, scErr)
		}
		a := netip.MustParseAddr(s)
		if _, res := netpolicy.Reserved(a); res != (scErr != nil) {
			t.Errorf("%s: servicecheck error %v, netpolicy.Reserved %v", s, scErr, res)
		}
		if _, np := netpolicy.NonPublic(a); np != refused {
			t.Errorf("%s: icon dialer refused %v, netpolicy.NonPublic %v", s, refused, np)
		}
	}

	hosts := []string{
		"a..b", "-a.example", "a-.example", "exa_mple.com", "example.com.", "2130706433", "0x7f000001", "0x7f.1",
		"127.1", "017700000001", "ex%41mple.com", "avatars.githubusercontent.com", "icons.example",
	}
	for _, h := range hosts {
		scErr := servicecheck.ValidateCheck(servicecheck.Check{Protocol: "https", Destination: h, Port: 443})
		_, urlErr := ValidateURL("https://"+h+"/i.png", []string{h})
		if scErr != nil && urlErr == nil {
			t.Errorf("%q: servicecheck refuses (%v) but ValidateURL accepts it", h, scErr)
		}
		if scErr == nil && urlErr != nil {
			t.Errorf("%q: servicecheck accepts it but ValidateURL refuses it (%v)", h, urlErr)
		}
	}
}
