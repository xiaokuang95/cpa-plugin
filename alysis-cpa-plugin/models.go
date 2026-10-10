package main

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type authModelRequestWire struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func alysisModels() []pluginapi.ModelInfo {
	mk := func(id, name, desc string) pluginapi.ModelInfo {
		return pluginapi.ModelInfo{
			ID:                         id,
			Name:                       id,
			DisplayName:                name,
			Description:                desc,
			OwnedBy:                    providerName,
			Type:                       "chat",
			Object:                     "model",
			SupportedGenerationMethods: []string{"chat"},
			ContextLength:              1_000_000,
		}
	}
	return []pluginapi.ModelInfo{
		mk("deepseek-flash", "DeepSeek V4.1 Flash", "vision and reasoning, 1M context"),
		mk("glm-5.3-flash", "GLM 5.3 Flash", "coding and reasoning, 1M context"),
		mk("gpt-6-luna", "GPT-6 Luna", "efficient coding; OpenAI Responses"),
		mk("claude-haiku-5-5", "Claude Haiku 5.5", "fast coding; Anthropic Messages"),
	}
}

func handleModelStatic(raw []byte) ([]byte, error) {
	var req pluginapi.StaticModelRequest
	_ = json.Unmarshal(raw, &req)
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: alysisModels()})
}

func handleModelForAuth(raw []byte) ([]byte, error) {
	var req authModelRequestWire
	_ = json.Unmarshal(raw, &req)
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: alysisModels()})
}

type upstreamProto struct {
	Format sdktranslator.Format
	Path   string
}

func protocolForModel(model string) upstreamProto {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	switch m {
	case "gpt-6-luna":
		return upstreamProto{Format: sdktranslator.FormatOpenAIResponse, Path: "/responses"}
	case "claude-haiku-5-5", "claude-sonnet-5-5", "claude-haiku-4-5":
		return upstreamProto{Format: sdktranslator.FormatClaude, Path: "/messages"}
	default:
		return upstreamProto{Format: sdktranslator.FormatOpenAI, Path: "/chat/completions"}
	}
}

func canonicalModel(model string) string {
	m := strings.TrimSpace(model)
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	switch strings.ToLower(m) {
	case "deepseek-v4-flash", "deepseek-v4-flash-vision-exp", "deepseek-v4.1-flash-expires-on-0910":
		return "deepseek-flash"
	default:
		return m
	}
}

func normalizeFormat(raw string) sdktranslator.Format {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "chat-completions", "chat_completions", "openai-chat-completions", "openai_chat_completions", "openai":
		return sdktranslator.FormatOpenAI
	case "responses", "openai-responses", "openai_responses", "openai-response":
		return sdktranslator.FormatOpenAIResponse
	case "anthropic", "claude":
		return sdktranslator.FormatClaude
	default:
		return sdktranslator.FromString(strings.TrimSpace(raw))
	}
}
