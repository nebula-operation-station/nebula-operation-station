// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestDecodeBase64IsStrict(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
		ok   bool
	}{
		{"L2V0Yw==", 16, "/etc", true},
		{"L2V0Yy9h", 16, "/etc/a", true},
		{"L2V0Yy8=", 16, "/etc/", true},
		{"", 16, "", false},
		{"L2V0Yw", 16, "", false},     // unpadded
		{"L2V0Yw=", 16, "", false},    // short padding
		{"L2V0Yx==", 16, "", false},   // non-zero padding bits
		{"L2V0\nYw==", 16, "", false}, // newline ignored by encoding/base64
		{"L2V0\rYw==", 16, "", false},
		{"L2V0 Yw==", 16, "", false},
		{"L2V0Y-==", 16, "", false}, // URL alphabet
		{"L2V0Y_==", 16, "", false},
		{"L2=0Yw==", 16, "", false}, // padding inside
		{"L2V0Y===", 16, "", false}, // three padding characters
		{"====", 16, "", false},
		{"L2V0Yw==", 3, "", false}, // over the decoded limit
	}
	for _, tt := range tests {
		got, err := decodeBase64(tt.in, tt.max)
		if (err == nil) != tt.ok || string(got) != tt.want {
			t.Errorf("decodeBase64(%q) = %q, %v; want %q ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestDecodeBase64RejectsOversizeBeforeDecoding(t *testing.T) {
	s := strings.Repeat("A", 4*((MaxPathBytes+2)/3)+4)
	if _, err := decodeBase64(s, MaxPathBytes); err == nil {
		t.Fatal("oversized base64 accepted")
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		p   string
		err error
	}{
		{"/etc", nil},
		{"/etc/\xff", nil},
		{"/etc/ a", nil},
		{"/", errPathComponent},
		{"", errPathEmpty},
		{"etc", errPathRelative},
		{"/etc/", errPathComponent},
		{"//etc", errPathComponent},
		{"/etc/.", errPathComponent},
		{"/etc/..", errPathComponent},
		{"/./etc", errPathComponent},
		{"/etc/\x00", errPathNUL},
		{"/" + strings.Repeat("a", MaxPathBytes), errPathTooLong},
		{strings.Repeat("/a", MaxPathDepth), nil},
		{strings.Repeat("/a", MaxPathDepth+1), errPathDepth},
	}
	for _, tt := range tests {
		if err := validatePath([]byte(tt.p)); err != tt.err {
			t.Errorf("validatePath(%q) = %v, want %v", tt.p, err, tt.err)
		}
	}
}

func TestMatchRootComparesComponents(t *testing.T) {
	tests := []struct {
		root, p string
		want    bool
	}{
		{"/etc", "/etc", true},
		{"/etc", "/etc/ssh/sshd_config", true},
		{"/etc", "/etcx", false},
		{"/etc/ssh", "/etc", false},
		{"/home/*/.ssh/authorized_keys*", "/home/alice/.ssh/authorized_keys", true},
		{"/home/*/.ssh/authorized_keys*", "/home/alice/.ssh/authorized_keys2", true},
		{"/home/*/.ssh/authorized_keys*", "/home/alice/.ssh/known_hosts", false},
		{"/home/*/.ssh/authorized_keys*", "/home/alice/.ssh", false},
		{"/home/*/.ssh/authorized_keys*", "/home/a/b/.ssh/authorized_keys", false},
		{"/home/*", "/home/\xff", true},
	}
	for _, tt := range tests {
		if got := matchRoot(tt.root, []byte(tt.p)); got != tt.want {
			t.Errorf("matchRoot(%q, %q) = %v, want %v", tt.root, tt.p, got, tt.want)
		}
	}
}

func TestEscapePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/etc/passwd", "/etc/passwd"},
		{"/etc/gr\xc3\xbc\xc3\x9fe", "/etc/gr\xc3\xbc\xc3\x9fe"}, // printable UTF-8 stays
		{"/etc/a b", "/etc/a b"},
		{"/etc/\xff\xfe", `/etc/\xff\xfe`},
		{"/etc/a\nb", `/etc/a\x0ab`},
		{"/etc/a\x1b[31m", `/etc/a\x1b[31m`},
		{"/etc/a\\x41", `/etc/a\x5cx41`},
		{"/etc/\xe2\x80\xaeevil", `/etc/\xe2\x80\xaeevil`},                   // RIGHT-TO-LEFT OVERRIDE
		{"/etc/\xe2\x81\xa6x\xe2\x81\xa9", `/etc/\xe2\x81\xa6x\xe2\x81\xa9`}, // isolates
		{"/etc/a\xe2\x80\x8bb", `/etc/a\xe2\x80\x8bb`},                       // zero width space
		{"/etc/a\xc2\xa0b", `/etc/a\xc2\xa0b`},                               // no-break space
		{"/etc/\xed\xa0\x80", `/etc/\xed\xa0\x80`},                           // surrogate half
		{"/etc/\x7f", `/etc/\x7f`},
	}
	for _, tt := range tests {
		if got := EscapePath([]byte(tt.in)); got != tt.want {
			t.Errorf("EscapePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHashClassification(t *testing.T) {
	tests := []struct {
		p             string
		plain, secret bool
	}{
		{"/usr/bin/ls", true, false},
		{"/usr/sbin/sshd", true, false},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", true, false},
		{"/usr/libexec/x", true, false},
		{"/usr/bin", false, false}, // the root itself is a dir, never hashed
		{"/usr/binx/a", false, false},
		{"/usr/local/bin/tool", false, false},
		{"/opt/app/bin", false, false},
		{"/boot/vmlinuz-6.1.0-18-amd64", true, false},
		{"/boot/initrd.img-6.1.0-18-amd64", true, false},
		{"/boot/System.map-6.1.0-18-amd64", true, false},
		{"/boot/config-6.1.0-18-amd64", true, false},
		{"/boot/grub/grub.cfg", false, false},
		{"/boot/grub/vmlinuz-x", false, false},
		{"/boot/efi/EFI/debian/grubx64.efi", false, false},
		{"/etc/passwd", false, false},
		{"/etc/shadow", false, true},
		{"/etc/shadow-", false, true},
		{"/etc/gshadow", false, true},
		{"/etc/ssh/ssh_host_ed25519_key", false, true},
		{"/etc/ssh/ssh_host_ed25519_key.pub", false, false},
		{"/etc/ssl/private/site.key", false, true},
		{"/etc/ssl/private/x", false, true},
		{"/etc/wireguard/wg0.conf", false, true},
		{"/etc/NetworkManager/system-connections/home.nmconnection", false, true},
		{"/etc/ppp/chap-secrets", false, true},
		{"/etc/ipsec.secrets", false, true},
		{"/etc/ipsec.d/private/k", false, true},
		{"/etc/postfix/sasl_passwd.lmdb", false, true},
		{"/etc/cifs-credentials-nas", false, true},
		{"/etc/mysql/debian.cnf", false, true},
		{"/etc/krb5.keytab", false, true},
		{"/etc/pve/priv/authkey.key", false, true},
		{"/etc/nebula/x", false, true},
		{"/etc/apache2/site.pem", false, true},
		{"/etc/a/b/c.key", false, true},
		{"/usr/lib/ssl/x.pem", true, false},
	}
	for _, tt := range tests {
		if got := PlainHashAllowed([]byte(tt.p)); got != tt.plain {
			t.Errorf("PlainHashAllowed(%q) = %v, want %v", tt.p, got, tt.plain)
		}
		if got := SecretPath([]byte(tt.p)); got != tt.secret {
			t.Errorf("SecretPath(%q) = %v, want %v", tt.p, got, tt.secret)
		}
	}
}

func TestSealHashNeverReturnsPlainForKeyedPath(t *testing.T) {
	key := testOpts().HostKey
	plain := sha256.Sum256([]byte("secret"))
	for _, p := range []string{"/etc/shadow", "/etc/passwd", "/opt/x", "/boot/grub/grub.cfg"} {
		h := sealHash(key, []byte(p), plain)
		if h.Kind != HashKeyed || h.Sum == plain {
			t.Errorf("%s: kind %v, plain leaked %v", p, h.Kind, h.Sum == plain)
		}
	}
	if h := sealHash(key, []byte("/usr/bin/ls"), plain); h.Kind != HashPlain || h.Sum != plain {
		t.Errorf("allowlisted path: %+v", h)
	}
}
