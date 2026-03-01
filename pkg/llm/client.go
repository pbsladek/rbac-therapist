// Package llm provides a unified LLM client for rbac-therapist CLI commands.
//
// It currently supports Anthropic Claude.
// The client is used by `rbact explain` and `rbact audit` commands.
//
// API key configuration:
//   - Anthropic: set ANTHROPIC_API_KEY
package llm

import (
	"context"
	"fmt"
	"os"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	// DefaultModel is the default Anthropic model used for completions.
	DefaultModel = anthropic.ModelClaude3_5HaikuLatest

	// DefaultMaxTokens is the maximum number of tokens in LLM responses.
	DefaultMaxTokens = 2048
)

// Client is the rbac-therapist LLM client interface.
type Client interface {
	// Complete sends a prompt and returns the completion text.
	Complete(ctx context.Context, prompt string) (string, error)
}

// NewClient creates the Anthropic LLM client.
func NewClient(apiKey string) (Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		key = apiKey
	}
	if key == "" {
		return nil, fmt.Errorf("no supported LLM API key found — set ANTHROPIC_API_KEY")
	}
	return newAnthropicClient(key), nil
}

// anthropicClient is the Anthropic Claude client implementation.
type anthropicClient struct {
	client anthropic.Client
	model  anthropic.Model
}

func newAnthropicClient(apiKey string) *anthropicClient {
	c := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &anthropicClient{
		client: c,
		model:  DefaultModel,
	}
}

func (a *anthropicClient) Complete(ctx context.Context, prompt string) (string, error) {
	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: DefaultMaxTokens,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("anthropic API error: %w", err)
	}

	if len(msg.Content) == 0 {
		return "", fmt.Errorf("empty response from LLM")
	}

	// Extract text from the first content block.
	for _, block := range msg.Content {
		if text, ok := block.AsAny().(anthropic.TextBlock); ok {
			return text.Text, nil
		}
	}

	return "", fmt.Errorf("no text content in LLM response")
}
