package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type authLoginStartWire struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type authLoginPollWire struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type authRefreshWire struct {
	pluginapi.AuthRefreshRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURL         string `json:"verification_url"`
	VerificationURLComplete string `json:"verification_url_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type deviceTokenResponse struct {
	Status string `json:"status"`
	Key    string `json:"key"`
}

func approvalURL(userCode string, serverURL string) string {
	path, query := "/activate", "code="+url.QueryEscape(userCode)
	if serverURL != "" {
		if u, err := url.Parse(serverURL); err == nil {
			if u.Path != "" {
				if strings.HasPrefix(u.Path, "/") {
					path = u.Path
				} else {
					path = "/" + u.Path
				}
			}
			if u.RawQuery != "" {
				query = u.RawQuery
			}
		}
	}
	return siteURL + path + "?" + query
}

func handleStartLogin(raw []byte) ([]byte, error) {
	var req authLoginStartWire
	_ = json.Unmarshal(raw, &req)
	clientName := "CLIProxyAPI"
	if req.Metadata != nil {
		if v, ok := req.Metadata["client_name"].(string); ok && strings.TrimSpace(v) != "" {
			clientName = strings.TrimSpace(v)
		}
	}
	resp, err := postJSON(fnBase+"/device-code", fnHeaders(), map[string]string{"client_name": clientName}, req.HostCallbackID)
	if err != nil {
		return nil, fmt.Errorf("device-code: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("device-code: HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	var out deviceCodeResponse
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("device-code parse: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return nil, fmt.Errorf("device-code returned no code")
	}
	ttl := loginTTL
	if out.ExpiresIn > 0 {
		ttl = time.Duration(out.ExpiresIn) * time.Second
	}
	now := time.Now()
	state := fmt.Sprintf("alysis-%d", now.UnixNano())
	loginStates.Store(state, &loginCtx{
		deviceCode: out.DeviceCode,
		userCode:   out.UserCode,
		expires:    now.Add(ttl),
	})
	authURL := approvalURL(out.UserCode, firstNonEmpty(out.VerificationURLComplete, out.VerificationURL))
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerName,
		URL:       authURL,
		State:     state,
		ExpiresAt: now.Add(ttl).UTC(),
		Metadata: map[string]any{
			"logo":      pluginLogoURL,
			"user_code": out.UserCode,
			"prompt":    "在打开的页面登录 Alysis 并批准设备码 " + out.UserCode + "。完成后此窗口会自动关闭。",
		},
	})
}

func handlePollLogin(raw []byte) ([]byte, error) {
	var req authLoginPollWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		return nil, fmt.Errorf("poll: empty state")
	}
	v, ok := loginStates.Load(state)
	if !ok {
		return nil, fmt.Errorf("poll: unknown state (restart login)")
	}
	lc := v.(*loginCtx)
	if time.Now().After(lc.expires) {
		loginStates.Delete(state)
		return nil, fmt.Errorf("poll: login expired")
	}

	resp, err := postJSON(fnBase+"/device-token", fnHeaders(), map[string]string{"device_code": lc.deviceCode}, req.HostCallbackID)
	if err != nil {
		return nil, fmt.Errorf("device-token: %w", err)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("device-token: HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 200))
	}
	var tok deviceTokenResponse
	_ = json.Unmarshal(resp.Body, &tok)
	status := strings.ToLower(strings.TrimSpace(tok.Status))
	switch status {
	case "approved":
		key := strings.TrimSpace(tok.Key)
		if key == "" {
			return nil, fmt.Errorf("device-token approved but no key")
		}
		loginStates.Delete(state)
		sa := storedFromKey(key, uidFromKey(key), lc.userCode)
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusSuccess,
			Message: "ok",
			Auth:    toAuthDataForLoginPoll(sa),
		})
	case "denied":
		loginStates.Delete(state)
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "login denied"})
	case "expired", "not_found", "already_claimed":
		loginStates.Delete(state)
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "device code " + status})
	default:
		return okEnvelope(pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: firstNonEmpty(status, "pending")})
	}
}

func handleRefreshAuth(raw []byte) ([]byte, error) {
	var req authRefreshWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	// slk_ keys do not expire. Probe /models so a revoked key surfaces.
	resp, err := getJSON(gatewayBase+"/models", map[string]string{
		"Authorization": "Bearer " + sa.Auth.AccessToken,
	}, req.HostCallbackID)
	if err != nil {
		return nil, fmt.Errorf("refresh probe: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("refresh: key rejected (HTTP %d) — re-login required", resp.StatusCode)
	}
	return okEnvelope(pluginapi.AuthRefreshResponse{
		Auth:             toAuthDataForRefresh(sa),
		NextRefreshAfter: time.Now().Add(24 * time.Hour).UTC(),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
