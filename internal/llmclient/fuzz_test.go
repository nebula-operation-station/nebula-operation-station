// SPDX-License-Identifier: AGPL-3.0-or-later

package llmclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// decodeErrTexts is the complete set of messages decodeResponse may return.
// They are constants: no part of the response body is ever interpolated into
// them, so an error can never carry the body (doc.go).
var decodeErrTexts = map[string]bool{
	"llm call: malformed response":       true,
	"llm call: no choice":                true,
	"llm call: malformed tool arguments": true,
}

// The oracle below is the test's own reading of the chat-completions wire
// format. It does not reuse wireResponse, its struct tags or a typed struct
// decode. Objects are parsed into map[string]json.RawMessage, the field names
// are literals, and leaves are converted with json.Unmarshal into a plain
// string or int64.
//
// Rules the oracle encodes; the decoder must match them:
//   - A field is found by its exact name, else by a case-insensitive match
//     (strings.EqualFold), as encoding/json binds struct fields.
//   - An object with two keys equal under strings.EqualFold (this includes
//     exact duplicates) is ambiguous. encoding/json merges such objects field
//     by field, and the oracle does not model that merge. For such inputs the
//     oracle checks no values; the error contract and UTF-8 are still checked.
//   - A null or absent content, message, tool_calls, function or id gives the
//     empty value. An absent or null usage gives no Usage; an absent or null
//     counter gives zero.
//   - Tool call arguments: absent gives "", a JSON string gives its decoded
//     value, and any other value gives its raw JSON text. A null argument is
//     the text "null".
//   - Negative token counts are clamped to zero.

// oracleObject is a JSON object: its raw field values by key.
type oracleObject struct {
	fields map[string]json.RawMessage
}

// isNull reports whether a raw value is absent or the JSON literal null.
func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

// parseObject parses raw as a JSON object. An absent or null value is an empty
// object. ambiguous reports whether two keys are equal under strings.EqualFold.
func parseObject(t *testing.T, raw json.RawMessage) (obj oracleObject, ambiguous bool) {
	t.Helper()
	obj.fields = map[string]json.RawMessage{}
	if isNull(raw) {
		return obj, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("decoder accepted a value that is not a JSON object where the wire format has one")
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		key, isString := tok.(string)
		if err != nil || !isString {
			t.Fatalf("oracle: object key: %v", err)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("oracle: object value: %v", err)
		}
		keys = append(keys, key)
		obj.fields[key] = v
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if strings.EqualFold(keys[i], keys[j]) {
				return obj, true
			}
		}
	}
	return obj, false
}

// get returns the raw value bound to name: nil when absent, the text null when
// the JSON value is null. An unambiguous object has at most one key that binds
// to name, so the fold match is unique.
func (o oracleObject) get(name string) json.RawMessage {
	if v, ok := o.fields[name]; ok {
		return v
	}
	for k, v := range o.fields {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// parseArray parses raw as a JSON array. An absent or null value is empty.
func parseArray(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	if isNull(raw) {
		return nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		t.Fatalf("decoder accepted a value that is not a JSON array where the wire format has one: %v", err)
	}
	return elems
}

// parseString returns the string a raw value holds; absent or null is "".
func parseString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	if isNull(raw) {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("decoder accepted a value that is not a JSON string where the wire format has one: %v", err)
	}
	return s
}

// parseCount returns the int64 a raw value holds; absent or null is 0.
func parseCount(t *testing.T, raw json.RawMessage) int64 {
	t.Helper()
	if isNull(raw) {
		return 0
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("decoder accepted a value that is not an int64 where the wire format has one: %v", err)
	}
	return n
}

// wantToolCall is one expected tool call.
type wantToolCall struct {
	id, name, args string
}

// wantUsage is the expected usage, clamped to non-negative counts.
type wantUsage struct {
	prompt, completion int64
}

// wantResponse is what the first choice must decode to.
type wantResponse struct {
	content   string
	toolCalls []wantToolCall
	usage     *wantUsage
}

// oracleDecode computes the expected result for a document that decodeResponse
// accepted. comparable is false when an object on the path is ambiguous.
func oracleDecode(t *testing.T, data []byte) (want wantResponse, comparable bool) {
	t.Helper()
	top, ambiguous := parseObject(t, data)
	if ambiguous {
		return want, false
	}
	choices := parseArray(t, top.get("choices"))
	if len(choices) == 0 {
		t.Fatalf("decoder accepted input without a choice")
	}
	choice, ambiguous := parseObject(t, choices[0])
	if ambiguous {
		return want, false
	}
	msg, ambiguous := parseObject(t, choice.get("message"))
	if ambiguous {
		return want, false
	}
	want.content = parseString(t, msg.get("content"))
	for _, el := range parseArray(t, msg.get("tool_calls")) {
		tc, ambiguous := parseObject(t, el)
		if ambiguous {
			return want, false
		}
		fn, ambiguous := parseObject(t, tc.get("function"))
		if ambiguous {
			return want, false
		}
		args := ""
		if raw := fn.get("arguments"); raw != nil {
			if raw[0] == '"' {
				args = parseString(t, raw)
			} else {
				args = string(raw)
			}
		}
		want.toolCalls = append(want.toolCalls, wantToolCall{
			id:   parseString(t, tc.get("id")),
			name: parseString(t, fn.get("name")),
			args: args,
		})
	}
	if raw := top.get("usage"); !isNull(raw) {
		u, ambiguous := parseObject(t, raw)
		if ambiguous {
			return want, false
		}
		want.usage = &wantUsage{
			prompt:     max(parseCount(t, u.get("prompt_tokens")), 0),
			completion: max(parseCount(t, u.get("completion_tokens")), 0),
		}
	}
	return want, true
}

// FuzzDecodeResponse feeds arbitrary bytes to the chat-completions decoder.
// The endpoint's answer is untrusted. The oracle (see the rules above):
//   - no panic;
//   - a failure is ErrCall with one of the constant messages, and the error
//     has no cause, so no part of the input can be reached through the error;
//   - a success matches the independent decode of the same bytes in content,
//     tool calls (ID, name, arguments) and usage (exact clamped counts, or no
//     usage at all), with every string valid UTF-8.
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
		// Tool call with no id, no name and no arguments; then a second call.
		`{"choices":[{"message":{"tool_calls":[{"function":{}},{"id":"x","function":{"name":"n","arguments":"{}"}}]}}]}`,
		// Null and absent content, message and choice.
		`{"choices":[{"message":{"content":null}}]}`,
		`{"choices":[{"message":null}]}`,
		`{"choices":[null]}`,
		`{"choices":[{}]}`,
		// Wrong JSON types for typed fields: the document must be rejected.
		`{"choices":[{"message":{"content":5}}]}`,
		`{"choices":[{"message":{"tool_calls":{}}}]}`,
		`{"choices":[{"message":"x"}]}`,
		// No choices.
		`{"choices":[]}`,
		`{"choices":null}`,
		`{}`,
		// Usage: present, absent, null, partial, negative, fractional, string.
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":120,"completion_tokens":7}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":-9223372036854775808,"completion_tokens":-5}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":null}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":{}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":null,"completion_tokens":3}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":123.5}}`,
		`{"choices":[{"message":{"content":"x"}}],"usage":"x"}`,
		// Case-insensitive field names, as encoding/json accepts them.
		`{"CHOICES":[{"Message":{"CONTENT":"up","Tool_Calls":[{"ID":"c","Function":{"NAME":"n","ARGUMENTS":"{}"}}]}}],"Usage":{"PROMPT_TOKENS":4,"completion_tokens":2}}`,
		// Duplicate keys: ambiguous, so only the error contract is checked.
		`{"choices":[{"message":{"content":"a","content":"b"}}]}`,
		`{"choices":[{"message":{"content":"a"}}],"choices":[{"message":{"content":"b"}}]}`,
		`{"choices":[{"message":{"content":"a"}}],"Choices":[]}`,
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
			if cause := errors.Unwrap(err); cause != nil {
				t.Fatalf("decode error has a cause (it could carry body bytes): %T", cause)
			}
			return
		}
		checkDecodedResponse(t, data, resp)
	})
}

// checkDecodedResponse compares a successful decode with the oracle's decode of
// the same bytes.
func checkDecodedResponse(t *testing.T, data []byte, resp Response) {
	t.Helper()
	if !json.Valid(data) {
		t.Fatalf("decodeResponse accepted input that is not valid JSON")
	}
	checkUTF8(t, "content", resp.Content)
	for _, tc := range resp.ToolCalls {
		checkUTF8(t, "tool call ID", tc.ID)
		checkUTF8(t, "tool call name", tc.Name)
		checkUTF8(t, "tool call arguments", tc.Arguments)
	}
	want, comparable := oracleDecode(t, data)
	if !comparable {
		return
	}
	if resp.Content != want.content {
		t.Fatalf("content: got %q, want %q", resp.Content, want.content)
	}
	if len(resp.ToolCalls) != len(want.toolCalls) {
		t.Fatalf("tool calls: got %d, want %d", len(resp.ToolCalls), len(want.toolCalls))
	}
	for i, w := range want.toolCalls {
		got := resp.ToolCalls[i]
		if got.ID != w.id || got.Name != w.name {
			t.Fatalf("tool call %d: got id %q name %q, want %q %q", i, got.ID, got.Name, w.id, w.name)
		}
		if got.Arguments != w.args {
			t.Fatalf("tool call %d arguments: got %q, want %q", i, got.Arguments, w.args)
		}
	}
	if (resp.Usage == nil) != (want.usage == nil) {
		t.Fatalf("usage present: got %v, want %v", resp.Usage != nil, want.usage != nil)
	}
	if want.usage == nil {
		return
	}
	if resp.Usage.PromptTokens != want.usage.prompt || resp.Usage.CompletionTokens != want.usage.completion {
		t.Fatalf("usage: got prompt %d completion %d, want prompt %d completion %d",
			resp.Usage.PromptTokens, resp.Usage.CompletionTokens, want.usage.prompt, want.usage.completion)
	}
}

// checkUTF8 fails the test when a decoded string is not valid UTF-8 (AGENTS
// rule 6: managed-host and endpoint data is text).
func checkUTF8(t *testing.T, what, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s is not valid UTF-8", what)
	}
}
