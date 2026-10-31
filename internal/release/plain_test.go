// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genPlain(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	return ed25519.GenerateKey(rand.Reader)
}

// plainSign signs msg with a plain Ed25519 key in the release namespace.
func plainSign(t *testing.T, priv ed25519.PrivateKey, msg []byte) []byte {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.Sum512(msg)
	var m [6]byte
	copy(m[:], "SSHSIG")
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, Namespace, "", "sha512", h[:]})
	sig, err := signer.Sign(rand.Reader, signed)
	if err != nil {
		t.Fatal(err)
	}
	raw := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{m, 1, signer.PublicKey().Marshal(), Namespace, "", "sha512", ssh.Marshal(sig)})
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END SSH SIGNATURE-----\n")
}
