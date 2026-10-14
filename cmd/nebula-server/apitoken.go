// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// newAPIToken creates a random API token for spec "NAME:SCOPE[,SCOPE]" and
// prints it once, with the server.json entry that holds only its hash.
func newAPIToken(spec string, w io.Writer) error {
	name, scopeList, ok := strings.Cut(spec, ":")
	if !ok || name == "" || scopeList == "" {
		return errors.New("-api-token: give NAME:SCOPE[,SCOPE], scopes inventory.read, operations.read, execution_logs.read")
	}
	scopes := strings.Split(scopeList, ",")
	entry := serverconfig.APIToken{Name: name, Scopes: scopes}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	tok := "nos_" + base64.RawURLEncoding.EncodeToString(b[:])
	entry.SHA256 = api.HashToken(tok)
	if p := (serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{entry}}).Problems(); len(p) > 0 {
		return fmt.Errorf("-api-token: %s", strings.Join(p, "; "))
	}
	js, err := json.MarshalIndent(entry, "      ", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "API token (shown once; give it to the client as \"Authorization: Bearer <token>\"):\n\n  %s\n\n", tok)
	fmt.Fprintf(w, "Add this to \"api\": {\"enabled\": true, \"tokens\": [ ... ]} in server.json and restart nebula-server:\n\n      %s\n", js)
	return nil
}
