// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// readFixture loads a synthetic fixture from testdata/.
func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// wrapResult wraps body in a success response with a <result> element.
func wrapResult(body string) []byte {
	return []byte(`<response status="success"><result>` + body + `</result></response>`)
}

func TestDecodeConfigRefusesStatusError(t *testing.T) {
	data := readFixture(t, "status-error.xml")
	_, _, err := decodeConfig(data)
	if !errors.Is(err, ErrAPIStatus) {
		t.Fatalf("err = %v, want ErrAPIStatus", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "7" {
		t.Fatalf("err = %v, want APIError code 7", err)
	}
	if strings.Contains(err.Error(), "example-secret-body-text") {
		t.Fatalf("error repeats response body: %v", err)
	}
}

func TestDecodeConfigRefusesMalformedInput(t *testing.T) {
	deep := strings.Repeat("<a>", netdevcontract.MaxXMLDepth+1) + strings.Repeat("</a>", netdevcontract.MaxXMLDepth+1)
	cases := []struct {
		name string
		data string
		want error
	}{
		{"status missing", `<response><result/></response>`, ErrMalformedResponse},
		{"status unknown", `<response status="partial"><result/></response>`, ErrMalformedResponse},
		{"wrong root", `<reply status="success"><result/></reply>`, ErrMalformedResponse},
		{"result missing", `<response status="success"/>`, ErrMalformedResponse},
		{"not xml", `this is not xml`, ErrMalformedResponse},
		{"truncated", `<response status="success"><result>`, ErrMalformedResponse},
		{"invalid utf-8", "<response status=\"success\"><result><zone><entry name=\"\xff\"/></zone></result></response>", ErrMalformedResponse},
		{"foreign charset", `<?xml version="1.0" encoding="ISO-8859-1"?><response status="success"><result/></response>`, ErrMalformedResponse},
		{"doctype entity expansion",
			`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>` +
				`<response status="success"><result><tag><entry name="&b;"/></tag></result></response>`,
			ErrMalformedResponse},
		{"undefined entity", `<response status="success"><result><tag><entry name="&xxe;"/></tag></result></response>`, ErrMalformedResponse},
		{"external entity", `<!DOCTYPE r SYSTEM "file:///etc/passwd"><response status="success"><result/></response>`, ErrMalformedResponse},
		{"deep nesting", `<response status="success"><result>` + deep + `</result></response>`, ErrXMLLimit},
		{"oversize text", `<response status="success"><result><zone><entry name="z"><network><layer3><member>` +
			strings.Repeat("x", netdevcontract.MaxXMLTextBytes+1) + `</member></layer3></network></entry></zone></result></response>`, ErrXMLLimit},
		{"oversize attribute", `<response status="success"><result><zone><entry name="` +
			strings.Repeat("x", netdevcontract.MaxXMLTextBytes+1) + `"/></zone></result></response>`, ErrXMLLimit},
		{"two vsys entries", `<response status="success"><result><vsys><entry name="vsys1"/><entry name="vsys2"/></vsys></result></response>`, ErrInvalidConfig},
		{"foreign vsys", `<response status="success"><result><vsys><entry name="vsys2"/></vsys></result></response>`, ErrInvalidConfig},
		{"vsys and direct content", `<response status="success"><result><vsys><entry name="vsys1"/></vsys><tag/></result></response>`, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decodeConfig([]byte(tc.data))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeConfigRefusesOversizeResponse(t *testing.T) {
	pad := strings.Repeat(" ", netdevcontract.MaxPANOSConfigResponseBytes)
	_, _, err := decodeConfig([]byte(`<response status="success"><result/></response>` + pad))
	if !errors.Is(err, ErrXMLLimit) || !errors.Is(err, netdevcontract.ErrOverLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit wrapping ErrOverLimit", err)
	}
}

func TestDecodeConfigRefusesTooManyElements(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<response status="success"><result><tag>`)
	for range netdevcontract.MaxXMLElements {
		b.WriteString(`<x/>`)
	}
	b.WriteString(`</tag></result></response>`)
	_, _, err := decodeConfig([]byte(b.String()))
	if !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit", err)
	}
}

func TestDecodeConfigErrorsNeverEchoBody(t *testing.T) {
	const marker = "SECRETMARKER"
	inputs := []string{
		`<response status="success"><result><` + marker + `></wrong></result></response>`,
		`<response status="` + marker + `"><result/></response>`,
		`<response status="success"><result><vsys><entry name="` + marker + `"/></vsys></result></response>`,
		`<response status="success"><result><tag><entry name="` + marker + `/"/></tag></result></response>`,
	}
	for _, in := range inputs[:3] {
		_, _, err := decodeConfig([]byte(in))
		if err == nil {
			t.Fatalf("decodeConfig(%q) succeeded", in)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error repeats response content: %v", err)
		}
	}
	// The tag name check happens in ParseObjects; it must not echo either.
	_, err := ParseObjects([]byte(inputs[3]))
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("ParseObjects err = %v, want an error without the name", err)
	}
}

func TestDecodeConfigAcceptsDirectAndVsysForms(t *testing.T) {
	direct, incomplete, err := decodeConfig(wrapResult(`<tag><entry name="a"/></tag>`))
	if err != nil || incomplete {
		t.Fatalf("direct form: incomplete %v, %v", incomplete, err)
	}
	wrapped, incomplete, err := decodeConfig(wrapResult(`<vsys><entry name="vsys1"><tag><entry name="a"/></tag></entry></vsys>`))
	if err != nil || incomplete {
		t.Fatalf("vsys form: incomplete %v, %v", incomplete, err)
	}
	if direct.Tag == nil || wrapped.Tag == nil || len(direct.Tag.Entries) != 1 || len(wrapped.Tag.Entries) != 1 {
		t.Fatalf("tags not decoded: direct %+v, wrapped %+v", direct.Tag, wrapped.Tag)
	}
	empty, incomplete, err := decodeConfig(wrapResult(``))
	if err != nil || incomplete || empty.Zone != nil || empty.Address != nil {
		t.Fatalf("empty result: %+v, incomplete %v, %v", empty, incomplete, err)
	}
}

func TestDecodeConfigMissingVsysOrForeignContentIsIncomplete(t *testing.T) {
	cases := map[string]string{
		"vsys without entry":       `<vsys/>`,
		"vsys with only text":      `<vsys> </vsys>`,
		"only non-allowlisted":     `<rulebase><security/></rulebase>`,
		"non-allowlisted and text": `x<profiles/>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sec, incomplete, err := decodeConfig(wrapResult(body))
			if err != nil || !incomplete || !sec.empty() {
				t.Fatalf("decodeConfig = %+v, incomplete %v, %v; want empty and incomplete", sec, incomplete, err)
			}
			z, err := ParseZones(wrapResult(body))
			if err != nil || !z.Incomplete || len(z.List) != 0 {
				t.Fatalf("ParseZones = %+v, %v; want empty and incomplete", z, err)
			}
			o, err := ParseObjects(wrapResult(body))
			if err != nil || !o.Incomplete || len(o.Addresses) != 0 {
				t.Fatalf("ParseObjects = %+v, %v; want empty and incomplete", o, err)
			}
		})
	}
	// an allowlisted container next to dropped content stays complete
	if _, incomplete, err := decodeConfig(wrapResult(`<zone/><rulebase/>`)); err != nil || incomplete {
		t.Fatalf("zone with dropped sibling: incomplete %v, %v", incomplete, err)
	}
}

func TestDecodeConfigRefusesRepeatedContainers(t *testing.T) {
	cases := map[string]string{
		"second result":            `<response status="success"><result><zone/></result><result><address/></result></response>`,
		"second vsys":              `<response status="success"><result><vsys><entry name="vsys1"/></vsys><vsys><entry name="vsys1"/></vsys></result></response>`,
		"repeated direct subtree":  `<response status="success"><result><address/><address/></result></response>`,
		"repeated vsys subtree":    `<response status="success"><result><vsys><entry name="vsys1"><zone/><zone/></entry></vsys></result></response>`,
		"repeated service subtree": `<response status="success"><result><service-group/><tag/><service-group/></result></response>`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := decodeConfig([]byte(data))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
