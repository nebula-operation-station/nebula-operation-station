// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

const (
	rgID  = "00000000-0000-4000-8000-0000000000aa"
	rgID2 = "00000000-0000-4000-8000-0000000000bb"
)

func readGrantDocAt(t *testing.T, now time.Time, lifetime time.Duration) ReadGrantDoc {
	t.Helper()
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	return ReadGrantDoc{
		Grant:       ReadGrantFormat,
		ID:          rgID,
		Issuer:      "root",
		CreatedUnix: now.Unix(),
		ExpiryUnix:  now.Add(lifetime).Unix(),
		Trigger:     TriggerBoth,
		Actions: []ReadGrantAction{
			{ActionID: "core.facts", ModuleVersion: "1.0.0", ArtifactSHA256: hexSum(artifact), ParametersHash: ph},
		},
		Targets: []canonical.Target{
			{HostID: "dockerflux", HostKeyFingerprint: fpA},
			{HostID: "strompi", HostKeyFingerprint: fpB},
		},
		MinIntervalS: 900,
		RunBudget:    DefaultRunBudget,
	}
}

func readGrantRaw(t *testing.T, d ReadGrantDoc) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadGrantDocParses(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	doc, canon, digest, err := ParseReadGrant(readGrantRaw(t, d), now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc, d) || len(digest) != 64 || len(canon) == 0 {
		t.Fatalf("%+v %q", doc, digest)
	}
	// The canonical form is deterministic and key-order independent: the
	// same document with alphabetically sorted members gets the same digest.
	var sorted map[string]json.RawMessage
	if err := json.Unmarshal(readGrantRaw(t, d), &sorted); err != nil {
		t.Fatal(err)
	}
	sortedRaw, err := json.Marshal(sorted)
	if err != nil {
		t.Fatal(err)
	}
	_, c2, h2, err := ParseReadGrant(sortedRaw, now)
	if err != nil || h2 != digest || !bytes.Equal(c2, canon) {
		t.Fatalf("reordered: %v %s %s", err, h2, digest)
	}
	// Any field change changes the digest.
	d2 := d
	d2.Issuer = "alice"
	_, _, h3, err := ParseReadGrant(readGrantRaw(t, d2), now)
	if err != nil || h3 == digest {
		t.Fatalf("issuer change kept the digest: %v", err)
	}
}

func TestReadGrantDocRules(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	base := func() ReadGrantDoc { return readGrantDocAt(t, now, DefaultReadGrantLifetime) }
	cases := map[string]func(ReadGrantDoc) ReadGrantDoc{
		"wrong format":      func(d ReadGrantDoc) ReadGrantDoc { d.Grant = "read-schedule-v1"; return d },
		"uppercase id":      func(d ReadGrantDoc) ReadGrantDoc { d.ID = strings.ToUpper(rgID); return d },
		"non-v4 id":         func(d ReadGrantDoc) ReadGrantDoc { d.ID = "00000000-0000-1000-8000-0000000000aa"; return d },
		"empty id":          func(d ReadGrantDoc) ReadGrantDoc { d.ID = ""; return d },
		"empty issuer":      func(d ReadGrantDoc) ReadGrantDoc { d.Issuer = ""; return d },
		"uppercase issuer":  func(d ReadGrantDoc) ReadGrantDoc { d.Issuer = "Root"; return d },
		"long issuer":       func(d ReadGrantDoc) ReadGrantDoc { d.Issuer = strings.Repeat("a", 65); return d },
		"dash-first issuer": func(d ReadGrantDoc) ReadGrantDoc { d.Issuer = "-root"; return d },
		"created zero":      func(d ReadGrantDoc) ReadGrantDoc { d.CreatedUnix = 0; return d },
		"created in the future": func(d ReadGrantDoc) ReadGrantDoc {
			d.CreatedUnix = now.Add(time.Hour).Unix()
			d.ExpiryUnix = now.Add(time.Hour + DefaultReadGrantLifetime).Unix()
			return d
		},
		"expiry before created": func(d ReadGrantDoc) ReadGrantDoc { d.ExpiryUnix = d.CreatedUnix; return d },
		"already expired": func(d ReadGrantDoc) ReadGrantDoc {
			d.CreatedUnix = now.Add(-2 * 24 * time.Hour).Unix()
			d.ExpiryUnix = now.Add(-24 * time.Hour).Unix()
			return d
		},
		"lifetime under an hour":    func(d ReadGrantDoc) ReadGrantDoc { d.ExpiryUnix = now.Add(30 * time.Minute).Unix(); return d },
		"lifetime over 30 days":     func(d ReadGrantDoc) ReadGrantDoc { d.ExpiryUnix = now.Add(31 * 24 * time.Hour).Unix(); return d },
		"bad trigger":               func(d ReadGrantDoc) ReadGrantDoc { d.Trigger = "whenever"; return d },
		"no actions":                func(d ReadGrantDoc) ReadGrantDoc { d.Actions = nil; return d },
		"no targets":                func(d ReadGrantDoc) ReadGrantDoc { d.Targets = nil; return d },
		"interval under 15 minutes": func(d ReadGrantDoc) ReadGrantDoc { d.MinIntervalS = 899; return d },
		"interval over 7 days":      func(d ReadGrantDoc) ReadGrantDoc { d.MinIntervalS = 7*24*3600 + 1; return d },
		"budget zero":               func(d ReadGrantDoc) ReadGrantDoc { d.RunBudget = 0; return d },
		"budget over 240":           func(d ReadGrantDoc) ReadGrantDoc { d.RunBudget = 241; return d },
		"non-read-only action": func(d ReadGrantDoc) ReadGrantDoc {
			d.Actions[0].ActionID = "patching.install_security"
			return d
		},
		"bad artifact hash": func(d ReadGrantDoc) ReadGrantDoc {
			d.Actions[0].ArtifactSHA256 = strings.Repeat("0", 63) + "g"
			return d
		},
		"bad params hash": func(d ReadGrantDoc) ReadGrantDoc {
			d.Actions[0].ParametersHash = strings.ToUpper(strings.Repeat("a", 64))
			return d
		},
		"malformed target": func(d ReadGrantDoc) ReadGrantDoc {
			d.Targets[0].HostID = "docker flux"
			return d
		},
		"bad fingerprint": func(d ReadGrantDoc) ReadGrantDoc {
			d.Targets[0].HostKeyFingerprint = "SHA256:short"
			return d
		},
	}
	for name, mutate := range cases {
		d := mutate(base())
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadGrantDocBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	// 32 actions and 1000 targets are accepted; one more is refused.
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	ph, _ := canonical.HashParameters(params)
	ids := []string{"core.facts", "package.list_updates", "docker.list", "docker.inspect", "docker.check_updates", "service.list", "service.status"}
	d.Actions = nil
	for i := 0; i < 32; i++ {
		d.Actions = append(d.Actions, ReadGrantAction{ActionID: ids[i%len(ids)], ModuleVersion: "1.0." + itoa(i),
			ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	}
	d.Targets = nil
	for i := 0; i < 1000; i++ {
		d.Targets = append(d.Targets, canonical.Target{HostID: "h" + itoa(i), HostKeyFingerprint: fpA})
	}
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("32 actions / 1000 targets: %v", err)
	}
	d = readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = append(d.Actions, ReadGrantAction{ActionID: "core.facts", ModuleVersion: "1.0.0",
		ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Fatal("duplicate action accepted")
	}
	d = readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Targets = append(d.Targets, canonical.Target{HostID: "dockerflux", HostKeyFingerprint: fpB})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Fatal("duplicate host accepted")
	}
	// 30-day lifetime and budget 240 are the upper bounds.
	d = readGrantDocAt(t, now, ReadGrantMaxLifetime)
	d.RunBudget = MaxRunBudget
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("30 days / budget 240: %v", err)
	}
}

func TestReadGrantDocMissingMember(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := readGrantRaw(t, readGrantDocAt(t, now, DefaultReadGrantLifetime))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "grant")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ParseReadGrant(raw, now); err == nil {
		t.Fatal("document without the grant member accepted")
	}
}

func TestReadGrantDocMalformedJSON(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	valid := string(readGrantRaw(t, readGrantDocAt(t, now, DefaultReadGrantLifetime)))
	cases := map[string]string{
		"empty":             "",
		"not an object":     `[]`,
		"truncated":         valid[:len(valid)/2],
		"trailing data":     valid + "x",
		"unknown member":    `{"extra":true,` + valid[1:],
		"duplicate member":  `{"issuer":"root",` + valid[1:],
		"wrong case member": `{"Grant":"read-grant-v1","id":"x"}`,
	}
	// A float where an integer is expected decodes to nothing valid.
	if idx := strings.Index(valid, `"created_unix":`); idx >= 0 {
		end := strings.Index(valid[idx:], ",")
		cases["float in int field"] = valid[:idx] + `"created_unix":1.5` + valid[idx+len(`"created_unix":`)+end:]
	}
	for name, raw := range cases {
		if _, _, _, err := ParseReadGrant([]byte(raw), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
