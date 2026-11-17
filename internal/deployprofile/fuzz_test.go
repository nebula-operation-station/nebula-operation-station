// SPDX-License-Identifier: AGPL-3.0-or-later

package deployprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// FuzzValidateDoc checks the canonical round trip of a deploy profile.
// When a decoded profile validates and its document is produced, the
// document must decode back to a profile that validates, must stay within
// MaxDoc bytes, and must encode to the same bytes again (Doc is a fixpoint).
func FuzzValidateDoc(f *testing.F) {
	seed := func(p Profile) {
		b, err := json.Marshal(p)
		if err != nil {
			f.Fatalf("seed: %v", err)
		}
		f.Add(b)
	}
	seed(profile())
	seed(Profile{ // no optional fields, DHCP, preset size
		Slug: "a", Title: "t", Image: "i", Size: Size{Preset: "S"},
		StorageClass: "s", Network: Network{Bridge: "b", DHCP: true},
	})
	seed(Profile{ // custom size at both limits, empty lists
		Slug: "web", Title: "t", Image: "i", Size: Size{VCPU: MaxVCPUs, RAMGiB: MaxRAMGiB, DiskGiB: MaxDiskGiB},
		StorageClass: "s", Network: Network{Bridge: "b", VLAN: MaxVLAN, IPAMPool: "p"},
		DNS:       DNS{Nameservers: []string{}},
		Bootstrap: []BootstrapModule{}, Runbooks: []RunbookRef{}, VaultRefs: []VaultRef{},
	})
	seed(Profile{ // at the bootstrap and vault limits
		Slug: "full", Title: "t", Image: "i", Size: Size{Preset: "XL"},
		StorageClass: "s", Network: Network{Bridge: "b", IPAMPool: "p"},
		Bootstrap: allModules(), VaultRefs: numberedVaultRefs(MaxVaultRefs),
	})
	seed(docLimitProfile(f, MaxDoc)) // a document at the size limit
	for _, s := range []string{
		`{}`, `null`, `[]`, `""`, `{"slug":"a","slug":"b"}`,
		`{"bootstrap":null,"runbooks":null,"vault_refs":null}`,
		`{"size":{"preset":"M","vcpu":2},"network":{"bridge":"b","dhcp":true}}`,
		`{"dns":{"nameservers":["10.0.0.2","10.0.0.2"]}}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Profile
		if err := json.Unmarshal(data, &p); err != nil {
			return
		}
		if err := Validate(p); err != nil {
			return
		}
		doc, err := p.Doc()
		if err != nil {
			var ie *InvalidError
			if !errors.As(err, &ie) {
				t.Fatalf("Doc of a valid profile failed without InvalidError: %v", err)
			}
			return
		}
		if len(doc) > MaxDoc {
			t.Fatalf("document is %d bytes, above MaxDoc %d", len(doc), MaxDoc)
		}
		var q Profile
		if err := json.Unmarshal(doc, &q); err != nil {
			t.Fatalf("canonical document does not decode: %v\n%s", err, doc)
		}
		if err := Validate(q); err != nil {
			t.Fatalf("canonical document does not validate: %v\n%s", err, doc)
		}
		again, err := q.Doc()
		if err != nil {
			t.Fatalf("Doc of the decoded document: %v\n%s", err, doc)
		}
		if !bytes.Equal(doc, again) {
			t.Fatalf("Doc is not a fixpoint:\nfirst:  %s\nsecond: %s", doc, again)
		}
	})
}
