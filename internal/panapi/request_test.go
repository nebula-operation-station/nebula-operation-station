// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestValidateNameAcceptsPANOSNames(t *testing.T) {
	for _, name := range []string{
		"a",
		"allow-dns",
		"Rule 12",
		"host_10.0.0.1",
		"_internal",
		strings.Repeat("x", MaxNameLength),
	} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateNameRejectsInjectionAndLimits(t *testing.T) {
	for _, tc := range []struct{ desc, name string }{
		{"empty", ""},
		{"over limit", strings.Repeat("x", MaxNameLength+1)},
		{"single quote", "a' or '1'='1"},
		{"double quote", `a"b`},
		{"bracket", "a]/../entry[@name='b"},
		{"slash", "a/b"},
		{"angle", "<x/>"},
		{"ampersand", "a&amp;b"},
		{"newline", "a\nb"},
		{"tab", "a\tb"},
		{"nul", "a\x00b"},
		{"non-ascii", "regel-ä"},
		{"invalid utf-8", "a\xffb"},
		{"leading space", " a"},
		{"trailing space", "a "},
		{"at", "@name"},
		{"star", "*"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := ValidateName(tc.name)
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("ValidateName(%q) = %v, want ErrInvalidName", tc.name, err)
			}
			if tc.name != "" && strings.Contains(err.Error(), tc.name) {
				t.Fatalf("error echoes the rejected name: %v", err)
			}
		})
	}
}

func TestXPathLiteralRefusesQuote(t *testing.T) {
	if got, err := xpathLiteral("allow dns"); err != nil || got != "'allow dns'" {
		t.Fatalf("xpathLiteral = %q, %v", got, err)
	}
	if _, err := xpathLiteral("a'b"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("xpathLiteral with quote = %v, want ErrInvalidName", err)
	}
}

func TestReadRequestsUseFixedForms(t *testing.T) {
	const dev = "/config/devices/entry[@name='localhost.localdomain']"
	const vsys = dev + "/vsys/entry[@name='vsys1']"
	for _, tc := range []struct {
		desc string
		req  Request
		want url.Values
		max  int64
	}{
		{"system info", SystemInfoRequest(), url.Values{"type": {"op"}, "cmd": {"<show><system><info/></system></show>"}}, MaxOtherResponseBytes},
		{"pending changes", PendingChangesRequest(), url.Values{"type": {"op"}, "cmd": {"<show><config><list><changes/></list></config></show>"}}, MaxOtherResponseBytes},
		{"config audit", ConfigAuditRequest(), url.Values{"type": {"op"}, "cmd": {"<show><config><audit><info/></audit></config></show>"}}, MaxOtherResponseBytes},
		{"hit counts", RuleHitCountRequest(), url.Values{"type": {"op"}, "cmd": {"<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"}}, MaxOtherResponseBytes},
		{"running vsys", mustReq(t)(RunningConfigRequest(SubtreeVsys)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {dev + "/vsys"}}, MaxConfigResponseBytes},
		{"running shared", mustReq(t)(RunningConfigRequest(SubtreeShared)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {"/config/shared"}}, MaxConfigResponseBytes},
		{"running security", mustReq(t)(RunningConfigRequest(SubtreeSecurityRules)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/rulebase/security/rules"}}, MaxConfigResponseBytes},
		{"running nat", mustReq(t)(RunningConfigRequest(SubtreeNATRules)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/rulebase/nat/rules"}}, MaxConfigResponseBytes},
		{"running address", mustReq(t)(RunningConfigRequest(SubtreeAddresses)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/address"}}, MaxConfigResponseBytes},
		{"running address-group", mustReq(t)(RunningConfigRequest(SubtreeAddressGroups)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/address-group"}}, MaxConfigResponseBytes},
		{"running service", mustReq(t)(RunningConfigRequest(SubtreeServices)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/service"}}, MaxConfigResponseBytes},
		{"running service-group", mustReq(t)(RunningConfigRequest(SubtreeServiceGroups)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/service-group"}}, MaxConfigResponseBytes},
		{"running zone", mustReq(t)(RunningConfigRequest(SubtreeZones)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/zone"}}, MaxConfigResponseBytes},
		{"running interfaces", mustReq(t)(RunningConfigRequest(SubtreeInterfaces)), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {dev + "/network/interface"}}, MaxConfigResponseBytes},
		{"candidate security", mustReq(t)(CandidateConfigRequest(SubtreeSecurityRules)), url.Values{"type": {"config"}, "action": {"get"}, "xpath": {vsys + "/rulebase/security/rules"}}, MaxConfigResponseBytes},
		{"rule entry", mustReq(t)(RunningEntryRequest(SubtreeSecurityRules, "allow dns")), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/rulebase/security/rules/entry[@name='allow dns']"}}, MaxOtherResponseBytes},
		{"address entry", mustReq(t)(RunningEntryRequest(SubtreeAddresses, "h-10.0.0.1")), url.Values{"type": {"config"}, "action": {"show"}, "xpath": {vsys + "/address/entry[@name='h-10.0.0.1']"}}, MaxOtherResponseBytes},
		{"zone entry candidate", mustReq(t)(CandidateEntryRequest(SubtreeZones, "trust")), url.Values{"type": {"config"}, "action": {"get"}, "xpath": {vsys + "/zone/entry[@name='trust']"}}, MaxOtherResponseBytes},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if !tc.req.valid() {
				t.Fatal("request not valid")
			}
			got, err := url.ParseQuery(tc.req.body())
			if err != nil {
				t.Fatal(err)
			}
			if got.Encode() != tc.want.Encode() {
				t.Fatalf("body = %s\nwant   %s", got.Encode(), tc.want.Encode())
			}
			if tc.req.maxBytes != tc.max {
				t.Fatalf("maxBytes = %d, want %d", tc.req.maxBytes, tc.max)
			}
			if got.Has("key") {
				t.Fatal("body carries a key parameter")
			}
			for _, a := range []string{"set", "edit", "delete", "rename", "move", "override", "clone", "multi-move", "complete"} {
				if got.Get("action") == a {
					t.Fatalf("write action %q in a read request", a)
				}
			}
			if typ := got.Get("type"); typ != "op" && typ != "config" {
				t.Fatalf("type %q not a read type", typ)
			}
		})
	}
}

func mustReq(t *testing.T) func(Request, error) Request {
	return func(r Request, err error) Request {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
}

func TestEntryRequestRejectsBadName(t *testing.T) {
	for _, name := range []string{"", "a']/../../entry[@name='b", "x\n", strings.Repeat("a", 64)} {
		if _, err := RunningEntryRequest(SubtreeSecurityRules, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("RunningEntryRequest(%q) = %v, want ErrInvalidName", name, err)
		}
		if _, err := CandidateEntryRequest(SubtreeAddresses, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("CandidateEntryRequest(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestEntryRequestRejectsSubtreeWithoutEntries(t *testing.T) {
	for _, s := range []Subtree{SubtreeVsys, SubtreeShared, SubtreeInterfaces, 0, Subtree(99)} {
		if _, err := RunningEntryRequest(s, "a"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("RunningEntryRequest(%d) = %v, want ErrInvalidRequest", s, err)
		}
	}
}

func TestConfigRequestRejectsUnknownSubtree(t *testing.T) {
	for _, s := range []Subtree{0, -1, Subtree(99)} {
		if _, err := RunningConfigRequest(s); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("RunningConfigRequest(%d) = %v, want ErrInvalidRequest", s, err)
		}
		if _, err := CandidateConfigRequest(s); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("CandidateConfigRequest(%d) = %v, want ErrInvalidRequest", s, err)
		}
	}
}

func TestZeroRequestIsInvalid(t *testing.T) {
	if (Request{}).valid() {
		t.Fatal("zero Request is valid")
	}
}
