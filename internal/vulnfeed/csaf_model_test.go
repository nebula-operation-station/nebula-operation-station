// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// treeDoc wraps a product_tree JSON object into a minimal valid CSAF
// document of the given vendor's shape.
func treeDoc(tree string) []byte {
	return []byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","title":"t",
"tracking":{"id":"tree-test","version":"1","status":"final","current_release_date":"2026-01-01T00:00:00Z"}},
"product_tree":` + tree + `,"vulnerabilities":[]}`)
}

// productScope is the part of a product the model tests compare.
type productScope struct {
	Ecosystem, OS, Version string
	Models                 []string
	Incomplete             bool
}

func scopeOf(p CSAFProduct) productScope {
	return productScope{Ecosystem: p.Ecosystem, OS: p.OS, Version: p.Version, Models: p.Models, Incomplete: p.ModelsIncomplete}
}

// TestCSAFProductModelsFromTree: models and the OS come from the structured
// product tree only: a product_name below an OS family or above the OS
// branch, the identification helper (model_numbers, skus, a hardware CPE)
// and relationships. The full product name never yields a model, and a
// scope that cannot be read exactly is marked incomplete.
func TestCSAFProductModelsFromTree(t *testing.T) {
	const panos, iosxe, cbs = "vendor:paloalto:panos", "vendor:cisco:ios-xe", "vendor:cisco:cbs"
	pan := func(inner string) string {
		return `{"branches":[{"category":"vendor","name":"Palo Alto Networks","branches":[` + inner + `]}]}`
	}
	panOS := func(helper string) string {
		return pan(`{"category":"product_name","name":"PAN-OS","branches":[{"category":"product_version","name":"10.2.9",
"product":{"product_id":"P","name":"PAN-OS 10.2.9 on PA-440"` + helper + `}}]}`)
	}
	tests := []struct {
		name   string
		vendor CSAFVendor
		tree   string
		id     string
		want   productScope
	}{
		{"OS product_name, no model: OS-wide; the full name is never a model", CSAFVendorPaloAlto, panOS(""), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9"}},
		{"model_numbers", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"model_numbers":["PA-440","PA-450","PA-440"]}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"PA-440", "PA-450"}}},
		{"skus", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"skus":["PAN-PA-440"]}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"PAN-PA-440"}}},
		{"wildcard model number is incomplete", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"model_numbers":["PA-4*"]}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true}},
		{"blank sku is incomplete", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"skus":[" "]}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true}},
		{"hardware CPE 2.3", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:2.3:h:paloaltonetworks:pa-440:-:*:*:*:*:*:*:*"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"pa-440"}}},
		{"hardware CPE 2.3 with escaped character", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:2.3:h:paloaltonetworks:pa\\-440:-:*:*:*:*:*:*:*"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"pa-440"}}},
		{"hardware CPE 2.2", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:/h:paloaltonetworks:pa-440"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"pa-440"}}},
		{"wildcard hardware CPE is incomplete", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:2.3:h:paloaltonetworks:pa-4*:-:*:*:*:*:*:*:*"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true}},
		{"any-product hardware CPE is incomplete", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:2.3:h:paloaltonetworks:*:*:*:*:*:*:*:*:*"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true}},
		{"OS CPE names no model", CSAFVendorPaloAlto, panOS(`,"product_identification_helper":{"cpe":"cpe:2.3:o:paloaltonetworks:pan-os:10.2.9:*:*:*:*:*:*:*"}`), "P",
			productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9"}},
		{"product_name below an OS family is the model", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_family","name":"Cisco IOS XE Software","branches":[
{"category":"product_name","name":"Catalyst 9300-24T","branches":[{"category":"product_version","name":"17.9.1","product":{"product_id":"C","name":"x"}}]}]}]}]}`,
			"C", productScope{Ecosystem: iosxe, OS: "Cisco IOS XE Software", Version: "17.9.1", Models: []string{"Catalyst 9300-24T"}}},
		{"product_name above the OS branch is the model", CSAFVendorPaloAlto,
			pan(`{"category":"product_name","name":"PA-440","branches":[{"category":"product_name","name":"PAN-OS","branches":[
{"category":"product_version","name":"10.2.9","product":{"product_id":"P","name":"x"}}]}]}`),
			"P", productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"PA-440"}}},
		{"named product below a named OS is incomplete", CSAFVendorPaloAlto,
			pan(`{"category":"product_name","name":"PAN-OS","branches":[{"category":"product_name","name":"GlobalProtect","branches":[
{"category":"product_version","name":"10.2.9","product":{"product_id":"P","name":"x"}}]}]}`),
			"P", productScope{Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true}},
		{"hardware product_family is no OS; it is the model scope", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_family","name":"Cisco Catalyst 9300 Series Switches","branches":[
{"category":"product_version","name":"17.9.1","product":{"product_id":"C","name":"Cisco IOS XE Software 17.9.1"}}]}]}]}`,
			"C", productScope{Version: "17.9.1", Models: []string{"Cisco Catalyst 9300 Series Switches"}}},
		{"CBS hardware family is model-scoped, not OS-wide", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_family","name":"Cisco Business 350 Series Managed Switches","branches":[
{"category":"product_version","name":"3.4.0.17","product":{"product_id":"C","name":"x"}}]}]}]}`,
			"C", productScope{Ecosystem: cbs, OS: "Cisco Business 350 Series Managed Switches", Version: "3.4.0.17", Models: []string{"Cisco Business 350 Series Managed Switches"}}},
		{"CBS hardware product_name is the model, not the OS", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_name","name":"Cisco Business 350 Series Managed Switches","branches":[
{"category":"product_version","name":"3.4.0.17","product":{"product_id":"C","name":"x"}}]}]}]}`,
			"C", productScope{Ecosystem: cbs, OS: "Cisco Business 350 Series Managed Switches", Version: "3.4.0.17", Models: []string{"Cisco Business 350 Series Managed Switches"}}},
		{"hardware family above the OS family scopes the OS product", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_family","name":"Catalyst 9300 Series Switches","branches":[
{"category":"product_family","name":"Cisco IOS XE Software","branches":[{"category":"product_version","name":"17.9.1","product":{"product_id":"C","name":"x"}}]}]}]}]}`,
			"C", productScope{Ecosystem: iosxe, OS: "Cisco IOS XE Software", Version: "17.9.1", Models: []string{"Catalyst 9300 Series Switches"}}},
		{"software name with a series word stays the OS", CSAFVendorCisco,
			`{"branches":[{"category":"vendor","name":"Cisco","branches":[{"category":"product_family","name":"Cisco IOS XE Software for Catalyst 9300 Series Switches","branches":[
{"category":"product_version","name":"17.9.1","product":{"product_id":"C","name":"x"}}]}]}]}`,
			"C", productScope{Ecosystem: iosxe, OS: "Cisco IOS XE Software for Catalyst 9300 Series Switches", Version: "17.9.1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adv, err := ParseCSAFAdvisory(treeDoc(tc.tree), tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			p := productByID(t, adv, tc.id)
			if got := scopeOf(p); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("product = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestCSAFRelationshipScopesToRelatedModel: a relationship's combined
// product carries the OS and version of the referenced product and the
// model of the related product. A related product that is unknown, is
// itself an OS, or names no model is an incomplete scope.
func TestCSAFRelationshipScopesToRelatedModel(t *testing.T) {
	const tree = `{"branches":[{"category":"vendor","name":"Palo Alto Networks","branches":[
{"category":"product_name","name":"PAN-OS","branches":[{"category":"product_version","name":"10.2.9","product":{"product_id":"OS","name":"PAN-OS 10.2.9"}}]},
{"category":"product_family","name":"Next-Generation Firewalls","branches":[
  {"category":"product_name","name":"PA-440","product":{"product_id":"HW","name":"PA-440"}},
  {"category":"product_name","name":"PA-5450","product":{"product_id":"HWSKU","name":"PA-5450","product_identification_helper":{"skus":["PAN-PA-5450"]}}}]},
{"category":"product_family","name":"Appliances","product":{"product_id":"NOMODEL","name":"Appliances"}}]}],
"relationships":[
{"category":"installed_on","product_reference":"OS","relates_to_product_reference":"HW","full_product_name":{"product_id":"R1","name":"PAN-OS 10.2.9 on PA-440"}},
{"category":"installed_on","product_reference":"OS","relates_to_product_reference":"HWSKU","full_product_name":{"product_id":"R2","name":"x"}},
{"category":"installed_on","product_reference":"OS","relates_to_product_reference":"MISSING","full_product_name":{"product_id":"R3","name":"x"}},
{"category":"installed_with","product_reference":"OS","relates_to_product_reference":"OS","full_product_name":{"product_id":"R4","name":"x"}},
{"category":"installed_on","product_reference":"OS","relates_to_product_reference":"NOMODEL","full_product_name":{"product_id":"R5","name":"x"}}]}`
	adv, err := ParseCSAFAdvisory(treeDoc(tree), CSAFVendorPaloAlto)
	if err != nil {
		t.Fatal(err)
	}
	const panos = "vendor:paloalto:panos"
	want := map[string]productScope{
		"OS": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9"},
		"R1": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"PA-440"}},
		"R2": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Models: []string{"PA-5450", "PAN-PA-5450"}},
		"R3": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true},
		"R4": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true},
		"R5": {Ecosystem: panos, OS: "PAN-OS", Version: "10.2.9", Incomplete: true},
	}
	for id, w := range want {
		if got := scopeOf(productByID(t, adv, id)); !reflect.DeepEqual(got, w) {
			t.Errorf("%s = %+v, want %+v", id, got, w)
		}
	}
	// Hardware products themselves have no OS and stay unclassified.
	if p := productByID(t, adv, "HW"); p.Ecosystem != "" || p.OS != "" {
		t.Fatalf("hardware product classified: %+v", p)
	}
}

// TestCSAFModelLimits: more models than MaxCSAFModelsPerProduct mark the
// product incomplete; a model field with a control character rejects the
// document.
func TestCSAFModelLimits(t *testing.T) {
	many := make([]string, MaxCSAFModelsPerProduct+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"PA-%d"`, i)
	}
	doc := func(helper string) []byte {
		return treeDoc(`{"branches":[{"category":"vendor","name":"Palo Alto Networks","branches":[{"category":"product_name","name":"PAN-OS","branches":[
{"category":"product_version","name":"10.2.9","product":{"product_id":"P","name":"x","product_identification_helper":` + helper + `}}]}]}]}`)
	}
	adv, err := ParseCSAFAdvisory(doc(`{"model_numbers":[`+strings.Join(many, ",")+`]}`), CSAFVendorPaloAlto)
	if err != nil {
		t.Fatal(err)
	}
	if p := productByID(t, adv, "P"); !p.ModelsIncomplete || len(p.Models) != 0 {
		t.Fatalf("over-limit models not incomplete: %+v", p)
	}
	for _, h := range []string{`{"model_numbers":["PA-440\u0007"]}`, `{"skus":["PA\n440"]}`, `{"cpe":"cpe:2.3:h:x:y\u0000:-"}`} {
		if _, err := ParseCSAFAdvisory(doc(h), CSAFVendorPaloAlto); !errors.Is(err, ErrCSAFMalformed) {
			t.Fatalf("helper %s: err = %v, want ErrCSAFMalformed", h, err)
		}
	}
}

func productByID(t *testing.T, adv CSAFAdvisory, id string) CSAFProduct {
	t.Helper()
	for _, p := range adv.Products {
		if p.ProductID == id {
			return p
		}
	}
	t.Fatalf("product %s missing: %+v", id, adv.Products)
	return CSAFProduct{}
}
