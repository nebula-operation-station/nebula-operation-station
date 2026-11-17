// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
)

// The prompt budget counts the bytes that tool definitions and tool calls
// take on the wire. These shapes mirror the OpenAI encoding that
// internal/llmclient sends, for measurement only; the client encodes the
// requests.
type (
	wireFunction struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	wireToolCall struct {
		ID       string       `json:"id"`
		Type     string       `json:"type"`
		Function wireFunction `json:"function"`
	}
	wireToolDef struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"function"`
	}
)

// encodeTools converts tool definitions to their wire shape.
func encodeTools(defs []ToolDef) []wireToolDef {
	out := make([]wireToolDef, len(defs))
	for i, d := range defs {
		out[i].Type = "function"
		out[i].Function.Name = d.Name
		out[i].Function.Description = d.Description
		out[i].Function.Parameters = d.Parameters
	}
	return out
}
