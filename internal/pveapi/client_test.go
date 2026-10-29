// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "PVEAPIToken=nos@pve!inventory=testvalue"

// newTestClient starts an httptest server and returns a Client pointed at
// it. The token supplier records how often it was called via calls.
func newTestClient(t *testing.T, handler http.Handler, calls *int) *Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := New(ts.URL, ts.Client(), func(ctx context.Context) (string, error) {
		if calls != nil {
			*calls++
		}
		return testToken, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// serveData wraps the given JSON payload in the PVE response envelope.
func serveData(t *testing.T, payload string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, payload)
	})
}

func TestNewRejectsBadBase(t *testing.T) {
	token := func(ctx context.Context) (string, error) { return testToken, nil }
	for _, base := range []string{
		"ftp://pve.example:8006",
		"pve.example:8006",
		"https://pve.example:8006?x=1",
		"https://pve.example:8006#frag",
		"",
	} {
		if _, err := New(base, http.DefaultClient, token); err == nil {
			t.Errorf("New(%q): expected error", base)
		}
	}
	if _, err := New("https://pve.example:8006", nil, token); err == nil {
		t.Error("New(nil client): expected error")
	}
	if _, err := New("https://pve.example:8006", http.DefaultClient, nil); err == nil {
		t.Error("New(nil token): expected error")
	}
}

func TestRequestUsesGETAndTokenHeader(t *testing.T) {
	var method, path, auth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"data":[]}`))
	})
	c := newTestClient(t, handler, nil)
	if _, err := c.ListNodes(context.Background()); err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if method != http.MethodGet {
		t.Errorf("method = %q, want GET", method)
	}
	if path != "/api2/json/nodes" {
		t.Errorf("path = %q, want /api2/json/nodes", path)
	}
	if auth != testToken {
		t.Errorf("Authorization = %q, want token supplier value", auth)
	}
}

func TestTokenErrorStopsWithoutRequest(t *testing.T) {
	requested := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		w.Write([]byte(`{"data":[]}`))
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := New(ts.URL, ts.Client(), func(ctx context.Context) (string, error) {
		return "", errors.New("vault unavailable")
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.ListNodes(context.Background())
	if err == nil {
		t.Fatal("ListNodes: expected token error")
	}
	if !strings.Contains(err.Error(), "vault unavailable") {
		t.Errorf("error = %v, want wrapped token error", err)
	}
	if requested {
		t.Error("request reached the server despite token failure")
	}
}

func TestResponseTooLarge(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, MaxResponseBytes+1))
	})
	c := newTestClient(t, handler, nil)
	_, err := c.ListNodes(context.Background())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestCallTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte(`{"data":[]}`))
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := New(ts.URL, ts.Client(), func(ctx context.Context) (string, error) {
		return testToken, nil
	}, WithTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.ListNodes(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestStatusErrorCarriesSanitizedMessage(t *testing.T) {
	long := strings.Repeat("x", 2000)
	body := `{"errors":{"/nodes/pve1/qemu":"node is down\u0001\u0002` + long + `"}}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(body))
	})
	c := newTestClient(t, handler, nil)
	_, err := c.ListQemu(context.Background(), "pve1")
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want *StatusError", err)
	}
	if se.Code != http.StatusInternalServerError {
		t.Errorf("Code = %d, want 500", se.Code)
	}
	if !strings.Contains(se.Message, "node is down") {
		t.Errorf("Message = %q, want to contain 'node is down'", se.Message)
	}
	if len(se.Message) > MaxErrorMessageBytes {
		t.Errorf("Message length = %d, want <= %d", len(se.Message), MaxErrorMessageBytes)
	}
	if strings.ContainsAny(se.Message, "\x01\x02") {
		t.Error("Message contains control characters")
	}
}

func TestStatusErrorPlainBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"permission denied (required privilege: VM.Audit)"}`))
	})
	c := newTestClient(t, handler, nil)
	_, err := c.ListNodes(context.Background())
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want *StatusError", err)
	}
	if se.Code != http.StatusForbidden || !strings.Contains(se.Message, "permission denied") {
		t.Errorf("StatusError = %+v, want 403 with permission message", se)
	}
}

func TestEnvelopeDecodeError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`this is not json`))
	})
	c := newTestClient(t, handler, nil)
	if _, err := c.ListNodes(context.Background()); err == nil {
		t.Fatal("ListNodes: expected decode error")
	}
}

func TestSanitizeText(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"abcdef", 5, "ab…"},
		{"a\x00b\x7fc", 10, "abc"},
		{"héllo", 10, "héllo"},
	}
	for _, tc := range cases {
		if got := sanitizeText(tc.in, tc.max); got != tc.want {
			t.Errorf("sanitizeText(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

func TestStatusErrorPVEMessageIsSanitizedAndBounded(t *testing.T) {
	for _, body := range []string{
		`{"data":null,"errors":null,"message":"failure\u0000` + strings.Repeat("x", 2000) + `"}`,
		`{"message":"failure\u0000` + strings.Repeat("x", 2000) + `","errors":{"field":"validation detail"}}`,
	} {
		err := apiStatusError("/nodes", http.StatusInternalServerError, []byte(body))
		var se *StatusError
		if !errors.As(err, &se) {
			t.Fatal("expected StatusError")
		}
		if !strings.HasPrefix(se.Message, "failure") || len(se.Message) > MaxErrorMessageBytes || strings.ContainsRune(se.Message, 0) {
			t.Errorf("invalid sanitized message: %q", se.Message)
		}
	}
}
