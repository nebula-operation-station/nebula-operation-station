// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestPVEReadCredentialVersionMatchesReadPVECondition: the listed version
// is the registry ReadVersion only when ReadPVE would accept the read
// credential (own read ref and version >= 1); otherwise it is 0.
func TestPVEReadCredentialVersionMatchesReadPVECondition(t *testing.T) {
	const id = "pve-a"
	own := PveVaultID(id, PvePurposeRead)
	for _, tc := range []struct {
		name  string
		creds executordb.PveRemoteCredentials
		want  int64
	}{
		{"valid", executordb.PveRemoteCredentials{ReadRef: own, ReadVersion: 3}, 3},
		{"valid with action credential", executordb.PveRemoteCredentials{ReadRef: own, ReadVersion: 2, ActionRef: PveVaultID(id, PvePurposeAction), ActionVersion: 9}, 2},
		{"no credential", executordb.PveRemoteCredentials{}, 0},
		{"own ref version 0", executordb.PveRemoteCredentials{ReadRef: own}, 0},
		{"own ref negative version", executordb.PveRemoteCredentials{ReadRef: own, ReadVersion: -1}, 0},
		{"version without ref", executordb.PveRemoteCredentials{ReadVersion: 4}, 0},
		{"foreign remote ref", executordb.PveRemoteCredentials{ReadRef: PveVaultID("pve-b", PvePurposeRead), ReadVersion: 4}, 0},
		{"action purpose ref", executordb.PveRemoteCredentials{ReadRef: PveVaultID(id, PvePurposeAction), ReadVersion: 4}, 0},
		{"arbitrary ref", executordb.PveRemoteCredentials{ReadRef: "other-ref", ReadVersion: 4}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pveReadCredentialVersion(executordb.PveRemote{RemoteID: id, Credentials: tc.creds})
			if got != tc.want {
				t.Fatalf("version = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestListPVERemotesReportsReadCredentialVersionOnly: ListPVERemotes
// reports the read credential version of a remote with a valid read
// credential, 0 for remotes without one, and never a credential reference.
func TestListPVERemotesReportsReadCredentialVersionOnly(t *testing.T) {
	e := newReconcileEnv(t)
	refs := []string{
		PveVaultID("valid", PvePurposeRead), PveVaultID("valid", PvePurposeAction),
		PveVaultID("other", PvePurposeRead), PveVaultID("purpose", PvePurposeAction),
	}
	for i, tc := range []struct {
		id    string
		creds executordb.PveRemoteCredentials
	}{
		{"valid", executordb.PveRemoteCredentials{ReadRef: refs[0], ReadVersion: 5, ActionRef: refs[1], ActionVersion: 7}},
		{"none", executordb.PveRemoteCredentials{}},
		{"foreign", executordb.PveRemoteCredentials{ReadRef: refs[2], ReadVersion: 6}},
		{"purpose", executordb.PveRemoteCredentials{ReadRef: refs[3], ReadVersion: 8}},
	} {
		r := pvecontract.Remote{RemoteID: tc.id, Name: tc.id, Kind: pvecontract.KindStandalone,
			Endpoints: []pvecontract.Endpoint{{Host: "pve.lab", Port: 8006}}, TrustPin: strings.Repeat(string(rune('a'+i)), 64), TrustGeneration: 1}
		if _, err := e.svc.db.AddRemote(r, tc.creds, "test"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := e.svc.ListPVERemotes(context.Background(), &pb.ListPVERemotesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"valid": 5, "none": 0, "foreign": 0, "purpose": 0}
	if len(got.Remotes) != len(want) {
		t.Fatalf("got %d remotes, want %d", len(got.Remotes), len(want))
	}
	for _, r := range got.Remotes {
		w, ok := want[r.RemoteId]
		if !ok || r.ReadCredentialVersion != w {
			t.Fatalf("remote %q: read_credential_version = %d, want %d", r.RemoteId, r.ReadCredentialVersion, w)
		}
	}
	text, err := prototext.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if strings.Contains(string(text), ref) {
			t.Fatalf("response exposes credential reference %q", ref)
		}
	}
	for _, leak := range []string{"pve-", "_ref", "ref:", "action"} {
		if strings.Contains(string(text), leak) {
			t.Fatalf("response contains %q: %s", leak, text)
		}
	}
}
