package main

import (
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type authModelRequestWire struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

var staticModels = []pluginapi.ModelInfo{
	mkModel("mimo-v2.5:free", 262144),
	mkModel("mimo-v2.6-flash:free", 262144),
	mkModel("deepseek-v4-flash:free", 1048576),
	mkModel("deepseek-v4.1-flash:free", 1048576),
}

func mkModel(id string, ctx int64) pluginapi.ModelInfo {
	return pluginapi.ModelInfo{
		ID:                         id,
		Name:                       id,
		DisplayName:                id,
		OwnedBy:                    providerName,
		Type:                       "chat",
		Object:                     "model",
		SupportedGenerationMethods: []string{"chat"},
		ContextLength:              ctx,
	}
}

func handleModelStatic(_ []byte) ([]byte, error) {
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: staticModels})
}

func handleModelForAuth(raw []byte) ([]byte, error) {
	var req authModelRequestWire
	_ = json.Unmarshal(raw, &req)
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: staticModels})
	}
	models := fetchModels(sa, req.HostCallbackID)
	if len(models) == 0 {
		models = staticModels
	}
	return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: models})
}

func fetchModels(sa *storedAuth, callbackID string) []pluginapi.ModelInfo {
	resp, err := getJSON(gatewayBase+"/models", map[string]string{
		"Authorization": "Bearer " + sa.Auth.AccessToken,
	}, callbackID)
	if err != nil || resp.StatusCode >= 400 {
		return nil
	}
	var wrap struct {
		Data []struct {
			ID            string `json:"id"`
			ContextLength int64  `json:"context_length"`
			ContextWindow int64  `json:"context_window"`
		} `json:"data"`
	}
	if json.Unmarshal(resp.Body, &wrap) != nil {
		return nil
	}
	out := make([]pluginapi.ModelInfo, 0, len(wrap.Data))
	for _, m := range wrap.Data {
		if m.ID == "" {
			continue
		}
		ctx := m.ContextLength
		if ctx == 0 {
			ctx = m.ContextWindow
		}
		out = append(out, mkModel(m.ID, ctx))
	}
	return out
}
