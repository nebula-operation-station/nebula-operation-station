// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"errors"
	"strings"
	"testing"
)

func TestNewKey(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Key
		wantErr bool
	}{
		{"single letter", "a", "a", false},
		{"single digit", "0", "0", false},
		{"simple", "postgres", "postgres", false},
		{"with separators", "proxmox-ve", "proxmox-ve", false},
		{"dots and underscores", "a.b_c", "a.b_c", false},
		{"max length 64", strings.Repeat("a", 64), Key(strings.Repeat("a", 64)), false},
		{"empty", "", "", true},
		{"too long 65", strings.Repeat("a", 65), "", true},
		{"uppercase", "Postgres", "", true},
		{"leading dot", ".a", "", true},
		{"leading dash", "-a", "", true},
		{"leading underscore", "_a", "", true},
		{"space", "a b", "", true},
		{"control char", "a\x00b", "", true},
		{"unicode", "pöstgres", "", true},
		{"slash", "a/b", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKey(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidKey) {
					t.Fatalf("NewKey(%q) error = %v, want ErrInvalidKey", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewKey(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NewKey(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFromOSRelease(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		proxmox   bool
		wantKey   Key
		wantDisp  string
		wantKnown bool
	}{
		{"ubuntu", "ubuntu", false, "ubuntu", "Ubuntu", true},
		{"debian", "debian", false, "debian", "Debian", true},
		{"alpine", "alpine", false, "alpine", "Alpine Linux", true},
		{"proxmox flag", "proxmox", true, "proxmox-ve", "Proxmox VE", true},
		{"proxmox flag overrides id", "debian", true, "proxmox-ve", "Proxmox VE", true},
		{"proxmox id without flag", "proxmox", false, "proxmox-ve", "Proxmox VE", true},
		{"unknown os", "arch", false, "arch", "", false},
		{"uppercase id", "Ubuntu", false, "ubuntu", "Ubuntu", true},
		{"id with spaces", "openSUSE Leap", false, "opensuse-leap", "", false},
		{"empty", "", false, "unknown", "", false},
		{"control chars", "ub\x00untu", false, "ub-untu", "", false},
		{"unicode", "Übontü", false, "bont", "", false},
		{"trailing separators", "foo!?", false, "foo", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromOSRelease(tt.id, tt.proxmox)
			if got.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", got.Key, tt.wantKey)
			}
			if got.Display != tt.wantDisp {
				t.Errorf("Display = %q, want %q", got.Display, tt.wantDisp)
			}
			if got.Known != tt.wantKnown {
				t.Errorf("Known = %v, want %v", got.Known, tt.wantKnown)
			}
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("result key %q invalid: %v", got.Key, err)
			}
		})
	}
}

func TestFromOSReleaseHostileInput(t *testing.T) {
	long := strings.Repeat("ubuntu-", 2000) // ~14 KB
	got := FromOSRelease(long, false)
	if len(got.Key) > 64 {
		t.Fatalf("key too long: %d bytes", len(got.Key))
	}
	if _, err := NewKey(string(got.Key)); err != nil {
		t.Fatalf("key invalid: %v", err)
	}
	// Truncation is deterministic: same prefix, same key.
	if again := FromOSRelease(long, false); again != got {
		t.Fatalf("non-deterministic: %v vs %v", got, again)
	}
}

func TestFromImage(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantKey   Key
		wantDisp  string
		wantKnown bool
	}{
		{"library tag", "docker.io/library/postgres:16", "postgres", "PostgreSQL", true},
		{"registry digest", "ghcr.io/foo/bar@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "bar", "", false},
		{"user image", "netbirdio/netbird", "netbird", "Netbird", true},
		{"bare name", "postgres", "postgres", "PostgreSQL", true},
		{"bare with tag", "redis:7", "redis", "Redis", true},
		{"local registry port", "localhost:5000/nginx:latest", "nginx", "Nginx", true},
		{"local registry no tag", "192.168.0.10:5000/gitea/gitea", "gitea", "Gitea", true},
		{"library no tag", "docker.io/library/ollama", "ollama", "Ollama", true},
		{"multi segment", "ghcr.io/netbirdio/netbird:v0.30", "netbird", "Netbird", true},
		{"uppercase", "Docker.io/Library/Postgres:16", "postgres", "PostgreSQL", true},
		{"digest only", "postgres@sha256:0123456789abcdef", "postgres", "PostgreSQL", true},
		{"tag before slash is port", "registry.local:5000/foo", "foo", "", false},
		{"trailing slash", "docker.io/library/", "unknown", "", false},
		{"empty", "", "unknown", "", false},
		{"digest only", "@sha256:0123456789abcdef", "unknown", "", false},
		{"control chars", "dock\x00er.io/library/post:gres", "post", "", false},
		{"unicode", "döcker.io/library/pöstgres:16", "p-stgres", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromImage(tt.ref)
			if got.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", got.Key, tt.wantKey)
			}
			if got.Display != tt.wantDisp {
				t.Errorf("Display = %q, want %q", got.Display, tt.wantDisp)
			}
			if got.Known != tt.wantKnown {
				t.Errorf("Known = %v, want %v", got.Known, tt.wantKnown)
			}
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("result key %q invalid: %v", got.Key, err)
			}
		})
	}
}

func TestFromImageHostileInput(t *testing.T) {
	long := strings.Repeat("docker.io/library/postgres:", 500) // ~15 KB
	got := FromImage(long)
	if len(got.Key) > 64 {
		t.Fatalf("key too long: %d bytes", len(got.Key))
	}
	if _, err := NewKey(string(got.Key)); err != nil {
		t.Fatalf("key invalid: %v", err)
	}
	if again := FromImage(long); again != got {
		t.Fatalf("non-deterministic: %v vs %v", got, again)
	}
}

func TestFromPackage(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantKey   Key
		wantDisp  string
		wantKnown bool
	}{
		{"plain", "nginx", "nginx", "Nginx", true},
		{"nvidia driver versioned", "nvidia-driver-550", "nvidia", "NVIDIA", true},
		{"nvidia driver versioned dot", "nvidia-driver-550.54.15", "nvidia", "NVIDIA", true},
		{"nvidia utils versioned", "nvidia-utils-550", "nvidia", "NVIDIA", true},
		{"influxdb2", "influxdb2", "influxdb", "InfluxDB", true},
		{"influxdb2 versioned", "influxdb2-2.7.1", "influxdb", "InfluxDB", true},
		{"postgresql versioned", "postgresql-16", "postgres", "PostgreSQL", true},
		{"docker ce", "docker-ce", "docker", "Docker", true},
		{"docker.io package", "docker.io", "docker", "Docker", true},
		{"redis server", "redis-server", "redis", "Redis", true},
		{"rabbitmq server", "rabbitmq-server", "rabbitmq", "RabbitMQ", true},
		{"proxmox backup server", "proxmox-backup-server", "proxmox-backup", "Proxmox Backup Server", true},
		{"ceph osd", "ceph-osd", "ceph", "Ceph", true},
		{"unknown", "libfoo-bar", "libfoo-bar", "", false},
		{"unknown versioned strips version", "libfoo-bar-1.2", "libfoo-bar", "", false},
		{"uppercase", "NGINX", "nginx", "Nginx", true},
		{"empty", "", "unknown", "", false},
		{"control chars", "ng\x00inx", "ng-inx", "", false},
		{"unicode", "nğinx", "n-inx", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromPackage(tt.in)
			if got.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", got.Key, tt.wantKey)
			}
			if got.Display != tt.wantDisp {
				t.Errorf("Display = %q, want %q", got.Display, tt.wantDisp)
			}
			if got.Known != tt.wantKnown {
				t.Errorf("Known = %v, want %v", got.Known, tt.wantKnown)
			}
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("result key %q invalid: %v", got.Key, err)
			}
		})
	}
}

func TestFromUnit(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantKey   Key
		wantDisp  string
		wantKnown bool
	}{
		{"service", "nginx.service", "nginx", "Nginx", true},
		{"template service", "postgresql@16.service", "postgres", "PostgreSQL", true},
		{"socket", "docker.socket", "docker", "Docker", true},
		{"timer", "netbird.timer", "netbird", "Netbird", true},
		{"target", "netbird.target", "netbird", "Netbird", true},
		{"mount", "minio.mount", "minio", "MinIO", true},
		{"plain service", "netbird.service", "netbird", "Netbird", true},
		{"grafana", "grafana-server.service", "grafana", "Grafana", true},
		{"unknown unit", "foo-bar.service", "foo-bar", "", false},
		{"uppercase", "NGINX.SERVICE", "nginx", "Nginx", true},
		{"template only", "postgresql@", "postgres", "PostgreSQL", true},
		{"empty", "", "unknown", "", false},
		{"control chars", "ng\x00inx.service", "ng-inx", "", false},
		{"no suffix", "traefik", "traefik", "Traefik", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromUnit(tt.in)
			if got.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", got.Key, tt.wantKey)
			}
			if got.Display != tt.wantDisp {
				t.Errorf("Display = %q, want %q", got.Display, tt.wantDisp)
			}
			if got.Known != tt.wantKnown {
				t.Errorf("Known = %v, want %v", got.Known, tt.wantKnown)
			}
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("result key %q invalid: %v", got.Key, err)
			}
		})
	}
}

func TestUnknownHandling(t *testing.T) {
	// Every normalizer must return a valid, bounded key and
	// Known=false for identifiers the seed map does not know.
	cases := []Result{
		FromOSRelease("totally-unknown-os", false),
		FromImage("example.com/nobody/never-seen:1"),
		FromPackage("never-heard-of-9.9"),
		FromUnit("mystery-unit.service"),
		FromOSRelease("", false),
		FromImage(""),
		FromPackage(""),
		FromUnit(""),
	}
	for i, r := range cases {
		if r.Known {
			t.Errorf("case %d: unknown identifier reported known: %+v", i, r)
		}
		if r.Display != "" {
			t.Errorf("case %d: unknown identifier has display name %q", i, r.Display)
		}
		if _, err := NewKey(string(r.Key)); err != nil {
			t.Errorf("case %d: key %q invalid: %v", i, r.Key, err)
		}
	}
}

func TestDeterministic(t *testing.T) {
	images := []string{
		"docker.io/library/postgres:16",
		"ghcr.io/foo/bar@sha256:0123456789abcdef",
		"netbirdio/netbird",
		"LOCALHOST:5000/Redis:7",
		"\x00\xff docker.io/library/Postgres:16",
		strings.Repeat("a", 1000),
	}
	for _, in := range images {
		a, b := FromImage(in), FromImage(in)
		if a != b {
			t.Fatalf("FromImage not deterministic for %q", in)
		}
	}
	for _, in := range []string{"nvidia-driver-550", "", "Ü\tx"} {
		a, b := FromPackage(in), FromPackage(in)
		if a != b {
			t.Fatalf("FromPackage not deterministic for %q", in)
		}
		a, b = FromUnit(in), FromUnit(in)
		if a != b {
			t.Fatalf("FromUnit not deterministic for %q", in)
		}
	}
}

func TestSeedMap(t *testing.T) {
	if err := SeedError(); err != nil {
		t.Fatalf("embedded seed map failed to load: %v", err)
	}
	if len(seed) == 0 {
		t.Fatal("seed map is empty")
	}
	// Every identifier and key must be a valid key; every display name
	// must be plain text: non-empty, no URLs, no markup.
	for id, e := range seed {
		if _, err := NewKey(id); err != nil {
			t.Errorf("seed identifier %q invalid: %v", id, err)
		}
		if _, err := NewKey(e.key); err != nil {
			t.Errorf("seed key %q (for %q) invalid: %v", e.key, id, err)
		}
		if e.display == "" {
			t.Errorf("seed entry %q has empty display name", id)
		}
		if strings.Contains(e.display, "http") || strings.Contains(e.display, "://") {
			t.Errorf("seed entry %q display name contains a URL: %q", id, e.display)
		}
		if strings.ContainsAny(e.display, "<>") {
			t.Errorf("seed entry %q display name contains markup: %q", id, e.display)
		}
	}
	// The required catalog keys from ADR 0009 D5 must be reachable.
	required := map[string]string{
		"ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine",
		"proxmox-ve": "proxmox-ve", "proxmox-backup": "proxmox-backup",
		"docker": "docker", "nvidia": "nvidia", "netbird": "netbird",
		"influxdb": "influxdb", "grafana": "grafana", "postgres": "postgres",
		"redis": "redis", "nginx": "nginx", "traefik": "traefik",
		"gitea": "gitea", "rabbitmq": "rabbitmq", "ollama": "ollama",
		"keycloak": "keycloak", "minio": "minio", "ceph": "ceph",
		"wireguard": "wireguard",
	}
	for key := range required {
		found := false
		for _, e := range seed {
			if e.key == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required catalog key %q not present in seed map", key)
		}
	}
}

// normalizers lists every normalizer under one signature so tests can
// check they agree with each other.
var normalizers = []struct {
	name string
	fn   func(string) Result
}{
	{"FromOSRelease", func(s string) Result { return FromOSRelease(s, false) }},
	{"FromImage", FromImage},
	{"FromPackage", FromPackage},
	{"FromUnit", FromUnit},
}

func TestNoUnicodeFolding(t *testing.T) {
	// Homoglyphs that Unicode case folding maps onto ASCII must never
	// resolve to a seed entry, in any normalizer.
	inputs := []string{
		// Kelvin sign K (U+212A), plain and uppercase rest.
		"\u212Aeycloak",
		"\u212AEYCLOAK",
		// Dotted capital I (U+0130) and dotless small i (U+0131).
		"M\u0130N\u0130O",
		"m\u0131n\u0131o",
		// Image tag and unit suffix variants.
		"\u212Aeycloak:24",
		"\u212Aeycloak.service",
	}
	for _, in := range inputs {
		for _, n := range normalizers {
			got := n.fn(in)
			if got.Known {
				t.Errorf("%s(%q) = %+v, homoglyph mapped to a known entry", n.name, in, got)
			}
			if got.Key == "keycloak" || got.Key == "minio" {
				t.Errorf("%s(%q) key = %q, homoglyph folded into ASCII", n.name, in, got.Key)
			}
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("%s(%q) key %q invalid: %v", n.name, in, got.Key, err)
			}
		}
	}
}

func TestNormalizersAgree(t *testing.T) {
	// For bare names without image, unit or version syntax, every
	// normalizer must produce the same result.
	inputs := []string{
		"keycloak", "KEYCLOAK", "\u212Aeycloak", "M\u0130N\u0130O",
		"Übontü", "ng\x00inx", "\xff\xfeRedis", "foo bar", "",
		strings.Repeat("Ab", 1000),
	}
	for _, in := range inputs {
		want := normalizers[0].fn(in)
		for _, n := range normalizers[1:] {
			if got := n.fn(in); got != want {
				t.Errorf("%s(%q) = %+v, %s gives %+v", n.name, in, got, normalizers[0].name, want)
			}
		}
	}
}

func TestInputTruncatedBeforeProcessing(t *testing.T) {
	// A known name that only appears after maxInputLen bytes must not
	// be seen by any normalizer.
	pad := strings.Repeat("x", maxInputLen)
	for _, n := range normalizers {
		for _, in := range []string{pad + "/keycloak", pad + "@keycloak", pad + "keycloak"} {
			got := n.fn(in)
			if got.Known {
				t.Errorf("%s: name after byte %d was processed: %+v", n.name, maxInputLen, got)
			}
		}
	}
	// Multi-KB hostile input is handled by every normalizer, and
	// invalid UTF-8 does not change the processed window.
	hostile := []string{
		strings.Repeat("\u212A", 4000),
		strings.Repeat("\xff", 8000),
		strings.Repeat("A/", 4000),
		strings.Repeat("@:", 4000),
	}
	for _, n := range normalizers {
		for _, in := range hostile {
			got := n.fn(in)
			if _, err := NewKey(string(got.Key)); err != nil {
				t.Errorf("%s: hostile input gave invalid key %q: %v", n.name, got.Key, err)
			}
			if got.Known {
				t.Errorf("%s: hostile input mapped to known entry %+v", n.name, got)
			}
		}
	}
	if got := FromImage(strings.Repeat("\xff", maxInputLen-8) + "keycloak"); got.Key != "keycloak" {
		t.Errorf("FromImage window shifted by invalid UTF-8: key %q", got.Key)
	}
}

func TestLoadSeedAllOrNothing(t *testing.T) {
	bad := []byte("a:\n  key: a\n  display: A\nb:\n  key: \"B!\"\n  display: B\n")
	m, err := loadSeed(bad)
	if err == nil {
		t.Fatal("loadSeed accepted an invalid entry")
	}
	if len(m) != 0 {
		t.Fatalf("loadSeed returned partial map on error: %v", m)
	}
	if _, err := loadSeed([]byte("{")); err == nil {
		t.Fatal("loadSeed accepted malformed YAML")
	}
}
