// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testHostKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@web1\n"

// fileReadServer answers the file-read endpoint with body and records the
// requested path and query.
func fileReadServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, &seen
}

func TestAgentFileReadReturnsContent(t *testing.T) {
	ts, seen := fileReadServer(t, http.StatusOK, `{"data":{"content":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@web1\n"}}`)
	got, err := clientFor(t, ts).AgentFileRead(context.Background(), "pve1", 101, "/etc/ssh/ssh_host_ed25519_key.pub", 1024)
	if err != nil {
		t.Fatalf("AgentFileRead: %v", err)
	}
	if string(got) != testHostKeyLine {
		t.Fatalf("content = %q", got)
	}
	if len(*seen) != 1 || (*seen)[0] != "/api2/json/nodes/pve1/qemu/101/agent/file-read?file=%2Fetc%2Fssh%2Fssh_host_ed25519_key.pub" {
		t.Fatalf("requests = %v", *seen)
	}
}

func TestAgentFileReadAcceptsExplicitlyUntruncated(t *testing.T) {
	for _, flag := range []string{"0", "false"} {
		ts, _ := fileReadServer(t, http.StatusOK, `{"data":{"content":"x","truncated":`+flag+`}}`)
		if got, err := clientFor(t, ts).AgentFileRead(context.Background(), "pve1", 101, "/etc/hostname", 16); err != nil || string(got) != "x" {
			t.Fatalf("truncated=%s: %q, %v", flag, got, err)
		}
	}
}

func TestAgentFileReadRejectsUnsafeAnswers(t *testing.T) {
	cases := []struct {
		name string
		body string
		want error
	}{
		{"truncated true", `{"data":{"content":"ssh-ed25519 AAAA","truncated":true}}`, ErrAgentFileTruncated},
		{"truncated 1", `{"data":{"content":"ssh-ed25519 AAAA","truncated":1}}`, ErrAgentFileTruncated},
		{"truncated junk", `{"data":{"content":"x","truncated":"yes"}}`, ErrAgentMalformed},
		{"oversize", `{"data":{"content":"` + strings.Repeat("A", 1025) + `"}}`, ErrAgentFileTooLarge},
		{"unknown member", `{"data":{"content":"x","bytes-read":1}}`, ErrAgentMalformed},
		{"missing content", `{"data":{"truncated":0}}`, ErrAgentMalformed},
		{"content not a string", `{"data":{"content":42}}`, ErrAgentMalformed},
		{"data not an object", `{"data":"ssh-ed25519 AAAA"}`, ErrAgentMalformed},
		{"whitespace after value", `{"data":{"content":"x"}  }`, nil},
		{"invalid UTF-8", "{\"data\":{\"content\":\"r\xffoot\"}}", ErrAgentMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts, _ := fileReadServer(t, http.StatusOK, c.body)
			got, err := clientFor(t, ts).AgentFileRead(context.Background(), "pve1", 101, "/etc/ssh/ssh_host_ed25519_key.pub", 1024)
			if c.want == nil {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("got %q, err = %v, want %v", got, err, c.want)
			}
		})
	}
}

func TestParseAgentFileReadRejectsTrailingData(t *testing.T) {
	if _, err := parseAgentFileRead([]byte(`{"content":"x"}{"content":"y"}`), 16); !errors.Is(err, ErrAgentMalformed) {
		t.Fatalf("err = %v, want ErrAgentMalformed", err)
	}
}

func TestAgentFileReadUnavailableAgent(t *testing.T) {
	ts, _ := fileReadServer(t, http.StatusInternalServerError, `{"message":"QEMU guest agent is not running"}`)
	_, err := clientFor(t, ts).AgentFileRead(context.Background(), "pve1", 101, "/etc/hostname", 16)
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("err = %v, want ErrAgentUnavailable", err)
	}
}

func TestAgentFileReadValidatesBeforeIO(t *testing.T) {
	ts, seen := fileReadServer(t, http.StatusOK, `{"data":{"content":"x"}}`)
	c := clientFor(t, ts)
	cases := map[string]func() error{
		"relative path": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1", 101, "etc/hostname", 16)
			return err
		},
		"dot dot": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1", 101, "/etc/../shadow", 16)
			return err
		},
		"space": func() error { _, err := c.AgentFileRead(context.Background(), "pve1", 101, "/etc/a b", 16); return err },
		"query": func() error { _, err := c.AgentFileRead(context.Background(), "pve1", 101, "/etc/x\n", 16); return err },
		"node": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1/../x", 101, "/etc/hostname", 16)
			return err
		},
		"vmid": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1", 0, "/etc/hostname", 16)
			return err
		},
		"zero limit": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1", 101, "/etc/hostname", 0)
			return err
		},
		"huge limit": func() error {
			_, err := c.AgentFileRead(context.Background(), "pve1", 101, "/etc/hostname", MaxAgentFileReadBytes+1)
			return err
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("a rejected request must not reach the remote: %v", *seen)
	}
}
