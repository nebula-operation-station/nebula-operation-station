// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const notifyJSON = `{
  "public_origin": "https://nebula.example.org",
  "data_dir": "/var/lib/nebula/server",
  "executor_socket": "/run/nebula/executor.sock",
  "executor_user": "nebula-executor",
  "notifications": {
    "webhook": {"url": "https://hooks.example.org/nebula", "secret": "0123456789abcdef0123456789abcdef"},
    "ntfy": {"url": "http://ntfy.lan", "topic": "nebula-ops", "token": "tk_secret"},
    "telegram": {"bot_token": "123456:ABCdefGHIjklMNOpqrSTUvwxYZ012345", "chat_id": "-100123"}
  }
}`

func TestNotificationsParseAndRedact(t *testing.T) {
	cfg, err := Parse([]byte(notifyJSON))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.Notifications
	if n.Webhook == nil || n.Ntfy == nil || n.Telegram == nil || !n.HasSecrets() {
		t.Fatalf("%+v", n)
	}
	out := fmt.Sprintf("%v %+v %#v", cfg, n.Telegram, n.Webhook)
	for _, s := range []string{"0123456789abcdef", "tk_secret", "ABCdef"} {
		if strings.Contains(out, s) {
			t.Fatalf("secret %q printed: %s", s, out)
		}
	}
}

func TestNotificationsValidation(t *testing.T) {
	for name, repl := range map[string][2]string{
		"short secret":   {`"secret": "0123456789abcdef0123456789abcdef"`, `"secret": "short"`},
		"webhook scheme": {`"https://hooks.example.org/nebula"`, `"ftp://hooks.example.org"`},
		"credentials":    {`"https://hooks.example.org/nebula"`, `"https://u:p@hooks.example.org"`},
		"topic":          {`"topic": "nebula-ops"`, `"topic": "a/b"`},
		"chat id":        {`"chat_id": "-100123"`, `"chat_id": "abc"`},
		"bot token":      {`"123456:ABCdefGHIjklMNOpqrSTUvwxYZ012345"`, `"nope"`},
	} {
		_, err := Parse([]byte(strings.Replace(notifyJSON, repl[0], repl[1], 1)))
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "tk_secret") || strings.Contains(err.Error(), "ABCdef") {
			t.Errorf("%s: error leaks a secret: %v", name, err)
		}
	}
}

func TestSecretsNeedAPrivateConfigFile(t *testing.T) {
	path := writeConfigFile(t, notifyJSON)
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o644: false, 0o666: false} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if (err == nil) != ok {
			t.Errorf("mode %04o: %v", mode, err)
		}
		_, err = LoadWithFlags(path, parseFlags(t))
		if (err == nil) != ok {
			t.Errorf("mode %04o with flags: %v", mode, err)
		}
	}
	// Without secrets the installer's world-readable default stays fine.
	plain := writeConfigFile(t, validJSON)
	if err := os.Chmod(plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(plain); err != nil {
		t.Fatal(err)
	}
}
