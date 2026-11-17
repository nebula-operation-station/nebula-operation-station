// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/llmclient"
)

// MaxLLMResponseBytes bounds one chat-completions response body; the
// shared client enforces it (llmclient.MaxResponseBytes).
const MaxLLMResponseBytes = llmclient.MaxResponseBytes

// ErrLLM reports a failed LLM call. Its messages never hold the API key,
// the response body or model text.
var ErrLLM = errors.New("vulnagent/agent: llm call failed")

// Message is one chat message (the shared llmclient type).
type Message = llmclient.Message

// ToolCall is one tool call returned by the model (the shared llmclient type).
type ToolCall = llmclient.ToolCall

// Usage is the token usage an endpoint reports.
type Usage struct {
	// PromptTokens is the reported prompt token count.
	PromptTokens int64
	// CompletionTokens is the reported completion token count.
	CompletionTokens int64
}

// Request is one chat-completions request.
type Request struct {
	// Messages is the history.
	Messages []Message
	// Tools are the tool definitions.
	Tools []ToolDef
	// MaxTokens is the max_tokens of the call.
	MaxTokens int
}

// Response is the first choice of a chat-completions answer.
type Response struct {
	// Content is free model text (always discarded by the loop).
	Content string
	// ToolCalls are the returned tool calls in response order.
	ToolCalls []ToolCall
	// Usage is nil when the endpoint reported none.
	Usage *Usage
}

// LLM is a chat-completions endpoint with tool calling.
type LLM interface {
	// Complete makes one call.
	Complete(ctx context.Context, req Request) (Response, error)
}

// NewLLM builds the assessor's LLM client from the shared client
// (internal/llmclient) and keeps the error texts and sentinels of this
// package: a failed call matches ErrLLM, a refused configuration
// ErrInvalidConfig.
func NewLLM(opts llmclient.Options) (LLM, error) {
	c, err := llmclient.New(opts)
	if err != nil {
		return nil, mapClientErr(err)
	}
	return &clientLLM{c: c}, nil
}

// clientLLM adapts llmclient.Client to LLM.
type clientLLM struct {
	c *llmclient.Client
}

// Complete makes one chat call with parallel_tool_calls = false.
func (l *clientLLM) Complete(ctx context.Context, req Request) (Response, error) {
	tools := make([]llmclient.Tool, len(req.Tools))
	for i, d := range req.Tools {
		tools[i] = llmclient.Tool{Name: d.Name, Description: d.Description, Parameters: d.Parameters}
	}
	r, err := l.c.Chat(ctx, llmclient.Request{Messages: req.Messages, Tools: tools, MaxTokens: req.MaxTokens})
	if err != nil {
		return Response{}, mapClientErr(err)
	}
	resp := Response{Content: r.Content, ToolCalls: r.ToolCalls}
	if r.Usage != nil {
		resp.Usage = &Usage{PromptTokens: r.Usage.PromptTokens, CompletionTokens: r.Usage.CompletionTokens}
	}
	return resp, nil
}

// mapClientErr reproduces the message of a shared-client error and appends
// this package's sentinel, so the texts match those before the extraction.
// Errors without a sentinel (context errors) pass through unchanged.
func mapClientErr(err error) error {
	var ce *llmclient.Error
	if !errors.As(err, &ce) {
		return err
	}
	switch {
	case errors.Is(err, llmclient.ErrCall):
		return fmt.Errorf("%s: %w", ce.Error(), ErrLLM)
	case errors.Is(err, llmclient.ErrConfig):
		return fmt.Errorf("%s: %w", ce.Error(), ErrInvalidConfig)
	}
	return err
}
