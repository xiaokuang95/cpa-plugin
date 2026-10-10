package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

//go:embed panel.html
var panelHTML []byte

var (
	mgmtBase = "/v0/management"
	resBase  = "/v0/resource/plugins/" + providerName
)

type managementRequestWire struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type managementRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description,omitempty"`
}

type resourceRoute struct {
	Path        string `json:"path"`
	Menu        string `json:"menu,omitempty"`
	Description string `json:"description,omitempty"`
}

type managementRegistrationResponse struct {
	Routes    []managementRoute `json:"routes,omitempty"`
	Resources []resourceRoute   `json:"resources,omitempty"`
}

func managementRegistration() managementRegistrationResponse {
	base := "/plugins/" + providerName
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: base + "/accounts", Description: "List TokenHarbor keys (local only)."},
			{Method: http.MethodPost, Path: base + "/plan", Description: "One account GET /api/me/free-tier."},
			{Method: http.MethodPost, Path: base + "/import", Description: "Import a thk_live_ API key."},
		},
		Resources: []resourceRoute{
			{Path: "/panel", Menu: "TokenHarbor", Description: "TokenHarbor free-tier usage."},
		},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequestWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	path := strings.TrimRight(req.Path, "/")
	if req.Method == http.MethodGet && strings.HasPrefix(path, resBase) {
		sub := strings.TrimPrefix(path, resBase)
		return okEnvelope(mgmtHTMLResponse(servePanel(sub)))
	}
	base := mgmtBase + "/plugins/" + providerName
	switch {
	case req.Method == http.MethodGet && path == base+"/accounts":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleAccounts()))
	case req.Method == http.MethodPost && path == base+"/plan":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handlePlan(req)))
	case req.Method == http.MethodPost && path == base+"/import":
		return okEnvelope(mgmtJSONResponse(http.StatusOK, handleImport(req.ManagementRequest)))
	default:
		return okEnvelope(mgmtJSONResponse(http.StatusNotFound, map[string]any{"error": "not found: " + path}))
	}
}

func handleAccounts() map[string]any {
	files, err := hostAuthList()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	accounts := make([]map[string]any, 0, len(files))
	for _, f := range files {
		row := map[string]any{"auth_index": f.AuthIndex, "name": f.Name, "label": f.Label, "disabled": f.Disabled}
		raw, err := hostAuthGetJSON(f.AuthIndex)
		if err == nil {
			if sa, err := parseStored(raw); err == nil {
				row["uid"] = sa.Account.UID
				row["nickname"] = sa.Account.Nickname
				row["email"] = sa.Account.Email
				row["key_prefix"] = prefixKey(sa.Auth.AccessToken)
				row["has_session"] = sa.Auth.SessionCookie != ""
			}
		}
		accounts = append(accounts, row)
	}
	return map[string]any{"accounts": accounts, "site": siteURL, "count": len(accounts)}
}

func handlePlan(req managementRequestWire) map[string]any {
	var body struct {
		AuthIndex string `json:"auth_index"`
		Login     bool   `json:"login"`
	}
	_ = json.Unmarshal(req.Body, &body)
	id := strings.TrimSpace(body.AuthIndex)
	if id == "" && req.Query != nil {
		id = strings.TrimSpace(req.Query.Get("auth_index"))
	}
	if id == "" {
		return map[string]any{"error": "missing auth_index"}
	}
	name, raw, err := hostAuthGet(id)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	sa, err := parseStored(raw)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	alive, detail := true, ""
	if body.Login {
		alive, detail = probeKey(sa.Auth.AccessToken, req.HostCallbackID)
	}
	plan := fetchDashboard(sa, name, req.HostCallbackID, body.Login)
	applyCooldown(name, sa, plan)
	return map[string]any{"auth_index": id, "name": name, "alive": alive, "probe": shortErr(detail), "plan": plan, "disabled": plan.Cooled}
}

func prefixKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "…" + key[len(key)-4:]
}

func probeKey(key, callbackID string) (bool, string) {
	resp, err := getJSON(gatewayBase+"/models", map[string]string{"Authorization": "Bearer " + key}, callbackID)
	if err != nil {
		return false, err.Error()
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("HTTP %d %s", resp.StatusCode, shortErr(string(resp.Body)))
	}
	return true, "ok"
}

func handleImport(req pluginapi.ManagementRequest) map[string]any {
	raw := bytesTrimSpace(req.Body)
	var wrap struct {
		JSON json.RawMessage `json:"json"`
		Raw  string          `json:"raw"`
		Key  string          `json:"key"`
	}
	if json.Unmarshal(raw, &wrap) == nil {
		switch {
		case len(wrap.JSON) > 0:
			raw = wrap.JSON
		case strings.TrimSpace(wrap.Raw) != "":
			raw = []byte(strings.TrimSpace(wrap.Raw))
		case strings.TrimSpace(wrap.Key) != "":
			raw = []byte(strings.TrimSpace(wrap.Key))
		}
	}
	sa, err := parseStored(raw)
	if err != nil {
		return map[string]any{"success": false, "error": err.Error()}
	}
	fileJSON, err := buildAuthFileJSON(sa, false, "")
	if err != nil {
		return map[string]any{"success": false, "error": err.Error()}
	}
	name := authFileNameFor(sa)
	if err := hostAuthSaveJSON(name, fileJSON); err != nil {
		return map[string]any{"success": false, "error": err.Error()}
	}
	return map[string]any{"success": true, "file": name, "uid": sa.Account.UID}
}

func servePanel(sub string) []byte {
	if sub != "" && sub != "/" && sub != "/panel" && sub != "/panel.html" {
		return []byte("<h1>404</h1>")
	}
	base, _ := json.Marshal(mgmtBase)
	return bytes.ReplaceAll(panelHTML, []byte("__TH_MANAGEMENT_BASE_PATH_JSON__"), base)
}

func mgmtJSONResponse(status int, v any) pluginapi.ManagementResponse {
	body, _ := json.Marshal(v)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return pluginapi.ManagementResponse{StatusCode: status, Headers: h, Body: body}
}

func mgmtHTMLResponse(body []byte) pluginapi.ManagementResponse {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: h, Body: body}
}
