// SPDX-License-Identifier: AGPL-3.0-or-later

package llmclient

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// decodeErrTexts is the complete set of messages decodeResponse may return.
// They are constants: no part of the response body is ever interpolated into
// them, so an error can never carry the body (doc.go).
var decodeErrTexts = map[string]bool{
	"llm call: malformed response":       true,
	"llm call: no choice":                true,
	"llm call: malformed tool arguments": true,
}

// oracleResponse is the test's own view of the wire format. It is decoded
// independently of decodeResponse so the oracle does not reuse the code under
// test.
type oracleResponse struct {
	Choices []struct {
		Message struct {
			Content   *string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

// FuzzDecodeResponse feeds arbitrary bytes to the chat-completions decoder.
// The endpoint's answer is untrusted. The oracle: no panic; a failure is
// ErrCall with one of the constant messages (so it never carries the input);
// a success has non-negative usage and tool arguments that are exactly the
// decoded JSON string, or the raw JSON text for an object.
func FuzzDecodeResponse(f *testing.F) {
	seeds := []string{
		// Text answer.
		`{"choices":[{"message":{"content":"hello"}}]}`,
		// Tool call with arguments as a JSON string (OpenAI form).
		`{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"kev_epss","arguments":"{\"cve\":\"CVE-2024-1\"}"}}]}}]}`,
		// Tool call with arguments as a JSON object (compatible servers).
		`{"choices":[{"message":{"content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"kev_epss","arguments":{"cve":"CVE-2024-1","n":[1,2,{"x":null}]}}}]}}]}`,
		// Tool call arguments: null, escaped quotes and unicode, invalid string.
		`{"choices":[{"message":{"tool_calls":[{"id":"c2","function":{"name":"t","arguments":null}}]}}]}`,
		`{"choices":[{"message":{"tool_calls":[{"id":"c3","function":{"name":"t","arguments":"é\"\\\n"}}]}}]}`,
		`{"choices":[{"message":{"tool_calls":[{"id":"c4","function":{"name":"t","arguments":"{"}}]}}]}`,
		// No choices.
		`{"choices":[]}`,
		`{}`,
		// Usage, and negative usage.
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":120,"completion_tokens":7}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":-9223372036854775808,"completion_tokens":-5}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":"x"}`,
		// Not JSON, and empty input.
		`not json`,
		``,
		`{"choices":[{"message":{"content":"x"}}]} trailing`,
		// Long and nested values.
		`{"choices":[{"message":{"content":"` + strings.Repeat("a", 4096) + `"}}]}`,
		`{"choices":[{"message":{"content":"x","extra":` + strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200) + `}}]}`,
		`{"choices":[{"message":{"tool_calls":[{"function":{"arguments":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}}]}}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := decodeResponse(data)
		if err != nil {
			if !errors.Is(err, ErrCall) {
				t.Fatalf("decode error is not ErrCall: %v", err)
			}
			if !decodeErrTexts[err.Error()] {
				t.Fatalf("decode error text is not a constant message: %q", err.Error())
			}
			return
		}
		checkDecodedResponse(t, data, resp)
	})
}

// checkDecodedResponse compares a successful decode with an independent
// decode of the same bytes.
func checkDecodedResponse(t *testing.T, data []byte, resp Response) {
	t.Helper()
	var want oracleResponse
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("decodeResponse accepted input json.Unmarshal rejects: %v", err)
	}
	if len(want.Choices) == 0 {
		t.Fatalf("decodeResponse accepted input without choices")
	}
	first := want.Choices[0].Message
	if first.Content != nil && resp.Content != *first.Content {
		t.Fatalf("content: got %q, want %q", resp.Content, *first.Content)
	}
	if len(resp.ToolCalls) != len(first.ToolCalls) {
		t.Fatalf("tool calls: got %d, want %d", len(resp.ToolCalls), len(first.ToolCalls))
	}
	for i, tc := range first.ToolCalls {
		raw := tc.Function.Arguments
		wantArgs := string(raw)
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("tool call %d: decodeResponse accepted an invalid argument string: %v", i, err)
			}
			wantArgs = s
		}
		got := resp.ToolCalls[i]
		if got.ID != tc.ID || got.Name != tc.Function.Name {
			t.Fatalf("tool call %d: got id %q name %q, want %q %q", i, got.ID, got.Name, tc.ID, tc.Function.Name)
		}
		if got.Arguments != wantArgs {
			t.Fatalf("tool call %d arguments: got %q, want %q", i, got.Arguments, wantArgs)
		}
	}
	if resp.Usage == nil {
		if want.Usage != nil {
			t.Fatalf("usage dropped")
		}
		return
	}
	if resp.Usage.PromptTokens < 0 || resp.Usage.CompletionTokens < 0 {
		t.Fatalf("negative usage: %+v", *resp.Usage)
	}
	if want.Usage == nil {
		t.Fatalf("usage invented")
	}
}
