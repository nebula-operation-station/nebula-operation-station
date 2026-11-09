// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

const validPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func baseCBSDevice() Device {
	return Device{
		DeviceID:        "sw-core-1",
		Name:            "Core switch",
		Family:          FamilyCBS,
		Endpoints:       []Endpoint{{Address: "10.0.0.2", Port: 22}},
		PinKind:         PinSSHHostKey,
		TrustPin:        validPin,
		TrustGeneration: 1,
	}
}

func basePANOSDevice() Device {
	return Device{
		DeviceID:        "fw-1",
		Family:          FamilyPANOS,
		Endpoints:       []Endpoint{{Address: "fd00::1", Port: 443}, {Address: "192.168.1.1", Port: 443}},
		TLSServerName:   "fw.lab.internal",
		PinKind:         PinTLSLeaf,
		TrustPin:        validPin,
		TrustGeneration: 3,
	}
}

func TestValidDevicesRoundTrip(t *testing.T) {
	for _, d := range []Device{baseCBSDevice(), basePANOSDevice()} {
		raw, err := MarshalDevice(d)
		if err != nil {
			t.Fatalf("marshal %s: %v", d.DeviceID, err)
		}
		got, err := DecodeDevice(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", d.DeviceID, err)
		}
		if got.DeviceID != d.DeviceID || len(got.Endpoints) != len(d.Endpoints) || got.Endpoints[0] != d.Endpoints[0] {
			t.Fatalf("round trip changed device: %+v", got)
		}
	}
}

func TestDeviceIDValidation(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"a", true},
		{"sw-1", true},
		{strings.Repeat("a", MaxDeviceIDBytes), true},
		{strings.Repeat("a", MaxDeviceIDBytes+1), false},
		{"", false},
		{"-sw", false},
		{"sw-", false},
		{"SW1", false},
		{"sw_1", false},
		{"sw 1", false},
		{"sw/1", false},
		{"sw.1", false},
		{"sw\x001", false},
		{"sw\n1", false},
		{"swé", false},
		{"\xff", false},
	}
	for _, c := range cases {
		d := baseCBSDevice()
		d.DeviceID = c.id
		_, err := ValidateDevice(d)
		if c.ok != (err == nil) {
			t.Errorf("device_id %q: ok=%v err=%v", c.id, c.ok, err)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("device_id %q: error %v does not match ErrInvalid", c.id, err)
		}
	}
}

func TestEndpointAddressValidation(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.10.1", true},
		{"fd12:3456::1", true},
		{"8.8.8.8", false},         // public
		{"2001:db8::1", false},     // not private
		{"127.0.0.1", false},       // loopback
		{"::1", false},             // loopback
		{"169.254.1.1", false},     // link-local
		{"fe80::1", false},         // link-local
		{"fe80::1%eth0", false},    // zone
		{"224.0.0.1", false},       // multicast
		{"ff02::1", false},         // multicast
		{"0.0.0.0", false},         // unspecified
		{"::", false},              // unspecified
		{"::ffff:10.0.0.1", false}, // mapped
		{"010.000.000.001", false},
		{"FD12::1", false}, // not canonical
		{"switch.lab", false},
		{"", false},
		{"10.0.0.1:22", false},
	}
	for _, c := range cases {
		if got := ValidEndpointAddress(c.addr); got != c.ok {
			t.Errorf("ValidEndpointAddress(%q) = %v, want %v", c.addr, got, c.ok)
		}
	}
}

func TestDeviceValidationRejects(t *testing.T) {
	cases := map[string]func(*Device){
		"unknown family":        func(d *Device) { d.Family = "pfsense" },
		"cbs with tls pin":      func(d *Device) { d.PinKind = PinTLSLeaf },
		"cbs with server name":  func(d *Device) { d.TLSServerName = "sw.lab" },
		"no endpoints":          func(d *Device) { d.Endpoints = nil },
		"public endpoint":       func(d *Device) { d.Endpoints[0].Address = "1.1.1.1" },
		"zero port":             func(d *Device) { d.Endpoints[0].Port = 0 },
		"duplicate endpoint":    func(d *Device) { d.Endpoints = append(d.Endpoints, d.Endpoints[0]) },
		"uppercase pin":         func(d *Device) { d.TrustPin = strings.ToUpper(validPin) },
		"short pin":             func(d *Device) { d.TrustPin = validPin[:63] },
		"zero generation":       func(d *Device) { d.TrustGeneration = 0 },
		"huge generation":       func(d *Device) { d.TrustGeneration = MaxTrustGeneration + 1 },
		"name control char":     func(d *Device) { d.Name = "core\x1b[2J" },
		"name invalid utf8":     func(d *Device) { d.Name = "core\xff" },
		"name too long":         func(d *Device) { d.Name = strings.Repeat("n", MaxLabelBytes+1) },
		"panos with ssh pin":    func(d *Device) { d.Family = FamilyPANOS },
		"panos bad server name": func(d *Device) { *d = basePANOSDevice(); d.TLSServerName = "FW..lab" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := baseCBSDevice()
			d.Endpoints = append([]Endpoint(nil), d.Endpoints...)
			mutate(&d)
			if _, err := ValidateDevice(d); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if _, err := MarshalDevice(d); err == nil {
				t.Fatal("marshal accepted an invalid device")
			}
		})
	}
}

func TestEndpointsPerDeviceLimit(t *testing.T) {
	mk := func(n int) Device {
		d := baseCBSDevice()
		d.Endpoints = nil
		for i := range n {
			d.Endpoints = append(d.Endpoints, Endpoint{Address: fmt.Sprintf("10.0.0.%d", i+1), Port: 22})
		}
		return d
	}
	if _, err := ValidateDevice(mk(MaxEndpointsPerDevice)); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if _, err := ValidateDevice(mk(MaxEndpointsPerDevice + 1)); !errors.Is(err, ErrOverLimit) {
		t.Fatalf("limit+1: got %v, want ErrOverLimit", err)
	}
}

func TestDecodeDeviceRejectsMalformedDocuments(t *testing.T) {
	good, err := MarshalDevice(baseCBSDevice())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	withField := func(k string, v any) []byte {
		c := map[string]any{}
		for kk, vv := range m {
			c[kk] = vv
		}
		c[k] = v
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string][]byte{
		"unknown field":          withField("password", "x"),
		"unknown endpoint field": []byte(strings.Replace(string(good), `"port":22`, `"port":22,"host":"x"`, 1)),
		"null name":              withField("name", nil),
		"duplicate key":          []byte(strings.Replace(string(good), `{"device_id"`, `{"device_id":"a","device_id"`, 1)),
		"invalid utf8":           []byte(strings.Replace(string(good), "Core switch", "Core \xff", 1)),
		"escaped control":        []byte(strings.Replace(string(good), "Core switch", `Core\u001b`, 1)),
		"lone surrogate":         []byte(strings.Replace(string(good), "Core switch", `Core\ud800`, 1)),
		"port out of range":      []byte(strings.Replace(string(good), `"port":22`, `"port":65536`, 1)),
		"negative generation":    withField("trust_generation", -1),
		"string generation":      withField("trust_generation", "1"),
		"trailing data":          append(append([]byte{}, good...), []byte(`{}`)...),
		"array":                  []byte(`[]`),
		"empty":                  nil,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDevice(raw); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidationErrorProblemListIsCapped(t *testing.T) {
	for _, c := range []struct {
		n, want int
	}{
		{MaxProblems, MaxProblems},
		{MaxProblems + 1, MaxProblems + 1},
		{100 * MaxProblems, MaxProblems + 1},
	} {
		var p problems
		for i := range c.n {
			p.add("problem %d", i)
		}
		var ve *ValidationError
		if !errors.As(p.err(), &ve) {
			t.Fatalf("n=%d: no ValidationError", c.n)
		}
		if len(ve.Problems) != c.want {
			t.Fatalf("n=%d: %d problems listed, want %d", c.n, len(ve.Problems), c.want)
		}
		if c.n > MaxProblems {
			last := ve.Problems[len(ve.Problems)-1]
			if want := fmt.Sprintf("and %d more problems", c.n-MaxProblems); last != want {
				t.Fatalf("n=%d: last entry %q, want %q", c.n, last, want)
			}
		}
	}
}

func TestOverlongListsAreNotWalkedWhenProblemsAreCapped(t *testing.T) {
	var p problems
	for range MaxProblems {
		p.add("filler")
	}
	validatePolicy(&p, FirewallPolicy{SecurityRules: make([]SecurityRule, MaxSecurityRules+1)})
	var ve *ValidationError
	if err := p.err(); !errors.As(err, &ve) || !errors.Is(err, ErrOverLimit) {
		t.Fatalf("got %v, want ErrOverLimit", err)
	}
	// only the count problem is added; the empty rules are not walked
	if got := ve.Problems[len(ve.Problems)-1]; got != "and 1 more problems" {
		t.Fatalf("last entry %q: the overlong rule list was walked", got)
	}
}

// maxErrorBytes is the largest Error() a ValidationError from decodeError
// may have: the package prefix plus one shortened problem.
const maxErrorBytes = len("netdevcontract: ") + MaxProblemBytes

func TestMultiMegabyteNumberLiteralGivesShortError(t *testing.T) {
	huge := strings.Repeat("9", 4<<20)
	good, err := MarshalDevice(baseCBSDevice())
	if err != nil {
		t.Fatal(err)
	}
	ogood, err := MarshalObservation(baseCBSObservation())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		raw    string
		decode func([]byte) error
	}{
		"device uint64 generation": {strings.Replace(string(good), `"trust_generation":1`, `"trust_generation":`+huge, 1), decodeDev},
		"device uint16 port":       {strings.Replace(string(good), `"port":22`, `"port":`+huge, 1), decodeDev},
		"device negative port":     {strings.Replace(string(good), `"port":22`, `"port":-`+huge, 1), decodeDev},
		"device string field":      {strings.Replace(string(good), `"name":"Core switch"`, `"name":`+huge, 1), decodeDev},
		"observation generation":   {strings.Replace(string(ogood), `"trust_generation":1`, `"trust_generation":`+huge, 1), decodeObs},
		"observation nested speed": {strings.Replace(string(ogood), `"speed_mbps":1000`, `"speed_mbps":`+huge, 1), decodeObs},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(c.raw, huge) {
				t.Fatal("test case did not insert the number")
			}
			err := c.decode([]byte(c.raw))
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrOverLimit) {
				t.Fatalf("got %.200v, want ErrInvalid and ErrOverLimit", err)
			}
			if n := len(err.Error()); n > maxErrorBytes {
				t.Fatalf("error is %d bytes, want at most %d", n, maxErrorBytes)
			}
			if strings.Contains(err.Error(), strings.Repeat("9", MaxJSONNumberBytes+1)) {
				t.Fatalf("error echoes the number literal: %.200v", err)
			}
		})
	}
}

func decodeDev(raw []byte) error { _, err := DecodeDevice(raw); return err }
func decodeObs(raw []byte) error { _, err := DecodeObservation(raw); return err }

func TestDecodeErrorProblemIsBounded(t *testing.T) {
	cases := map[string]error{
		"ascii":          errors.New(strings.Repeat("x", 1<<20)),
		"multibyte cut":  errors.New(strings.Repeat("ä", 1<<19)),
		"over limit":     fmt.Errorf("%w: %s", ErrOverLimit, strings.Repeat("y", 1<<20)),
		"short":          errors.New("decode: short"),
		"invalid utf8":   errors.New(strings.Repeat("\xff", 1<<10)),
		"exactly at cap": errors.New(strings.Repeat("z", MaxProblemBytes)),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			err := decodeError(in)
			var ve *ValidationError
			if !errors.As(err, &ve) || len(ve.Problems) != 1 {
				t.Fatalf("got %v, want one problem", err)
			}
			p := ve.Problems[0]
			if len(p) > MaxProblemBytes {
				t.Fatalf("problem is %d bytes, want at most %d", len(p), MaxProblemBytes)
			}
			if !utf8.ValidString(p) {
				t.Fatal("shortened problem is not valid UTF-8")
			}
			if len(in.Error()) <= MaxProblemBytes && utf8.ValidString(in.Error()) && p != in.Error() {
				t.Fatalf("short problem changed: %q", p)
			}
			if errors.Is(in, ErrOverLimit) != errors.Is(err, ErrOverLimit) {
				t.Fatal("ErrOverLimit marker lost")
			}
		})
	}
}

func TestProblemsAreShortened(t *testing.T) {
	var p problems
	p.add("%s", strings.Repeat("x", 1<<20))
	var ve *ValidationError
	if !errors.As(p.err(), &ve) || len(ve.Problems[0]) > MaxProblemBytes {
		t.Fatalf("problem not shortened to %d bytes", MaxProblemBytes)
	}
}

func TestDeviceErrorsDoNotEchoUntrustedText(t *testing.T) {
	d := baseCBSDevice()
	d.Family = Family(strings.Repeat("secret", 20))
	_, err := ValidateDevice(d)
	if err == nil || strings.Contains(err.Error(), "secretsecret") {
		t.Fatalf("error echoes long untrusted value: %v", err)
	}
}
