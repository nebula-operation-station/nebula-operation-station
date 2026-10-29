// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testClient returns a Client bound to the test server with a short
// request timeout.
func testClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(&http.Client{}, ts.URL, func(ctx context.Context) (string, error) {
		return "PVEAPIToken=nos@pam!test-token-value", nil
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.RequestTimeout = 2 * time.Second
	return c
}

func TestNewClientRejectsInvalidArguments(t *testing.T) {
	token := func(ctx context.Context) (string, error) { return "tok", nil }
	tests := []struct {
		name    string
		http    *http.Client
		baseURL string
		token   TokenSupplier
	}{
		{"nil http client", nil, "https://pve.example:8006", token},
		{"relative base url", &http.Client{}, "api/", token},
		{"wrong scheme", &http.Client{}, "ftp://pve.example", token},
		{"missing host", &http.Client{}, "https://", token},
		{"nil token supplier", &http.Client{}, "https://pve.example:8006", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClient(tt.http, tt.baseURL, tt.token); err == nil {
				t.Fatal("NewClient: expected error, got nil")
			}
		})
	}
}

func TestGetSendsTokenHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	if err := c.get(context.Background(), "/nodes/n1/storage", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if gotAuth != "PVEAPIToken=nos@pam!test-token-value" {
		t.Fatalf("Authorization header = %q, want injected token", gotAuth)
	}
	if r_method := "GET"; r_method != http.MethodGet {
		t.Fatal("only GET is allowed")
	}
}

func TestGetDropsUnknownFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"local","type":"dir","some_future_field":{"nested":true},"another":"x"}`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := c.get(context.Background(), "/nodes/n1/storage/local", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if out.ID != "local" || out.Type != "dir" {
		t.Fatalf("decoded = %+v", out)
	}
}

func TestGetUnavailableHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/error_403.json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("err type = %T, want *UnavailableError", err)
	}
	if ue.Reason != ReasonHTTPError || ue.Status != http.StatusForbidden {
		t.Fatalf("reason/status = %q/%d, want %q/403", ue.Reason, ue.Status, ReasonHTTPError)
	}
	// The PVE error body must not leak into the error text.
	if strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("error leaks response body: %v", err)
	}
}

func TestGetErrorDoesNotLeakBodyOrToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/error_500.json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	msg := err.Error()
	for _, secret := range []string{"secret-token-leak-abc123", "test-token-value"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error leaks %q: %v", secret, err)
		}
	}
}

func TestGetUnavailableTransport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close()
	c, err := NewClient(&http.Client{}, url, func(ctx context.Context) (string, error) {
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var out []string
	err = c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonTransport {
		t.Fatalf("err = %v, want reason %q", err, ReasonTransport)
	}
}

func TestGetUnavailableTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	c.RequestTimeout = 50 * time.Millisecond
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonTimeout {
		t.Fatalf("err = %v, want reason %q", err, ReasonTimeout)
	}
}

func TestGetUnavailableCallerContextCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out []string
	err := c.get(ctx, "/nodes/n1/storage", &out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("caller cancellation must not be reported as unavailable: %v", err)
	}
}

func TestGetUnavailableOversize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1 MiB + 1 byte of valid JSON array padding.
		w.Write(make([]byte, MaxResponseBytes+1))
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonOversize {
		t.Fatalf("err = %v, want reason %q", err, ReasonOversize)
	}
}

func TestGetUnavailableInvalidUTF8(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/invalid_utf8.json")
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonInvalidUTF8 {
		t.Fatalf("err = %v, want reason %q", err, ReasonInvalidUTF8)
	}
}

func TestGetUnavailableInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("testdata/invalid_json.json")
		w.Write(body)
	}))
	defer ts.Close()
	c := testClient(t, ts)
	var out []string
	err := c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonInvalidJSON {
		t.Fatalf("err = %v, want reason %q", err, ReasonInvalidJSON)
	}
}

func TestGetUnavailableNoToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()
	c, err := NewClient(&http.Client{}, ts.URL, func(ctx context.Context) (string, error) {
		return "", errors.New("vault offline")
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var out []string
	err = c.get(context.Background(), "/nodes/n1/storage", &out)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Reason != ReasonNoToken {
		t.Fatalf("err = %v, want reason %q", err, ReasonNoToken)
	}
	if strings.Contains(err.Error(), "vault offline") {
		t.Fatalf("error leaks supplier detail: %v", err)
	}
}

func TestUnavailableErrorIsAndAs(t *testing.T) {
	ue := &UnavailableError{Endpoint: "/nodes/n1/storage", Reason: ReasonHTTPError, Status: 403}
	if !errors.Is(ue, ErrUnavailable) {
		t.Fatal("errors.Is(ue, ErrUnavailable) = false")
	}
	if !strings.Contains(ue.Error(), "/nodes/n1/storage") {
		t.Fatalf("error text missing endpoint: %v", ue)
	}
}
