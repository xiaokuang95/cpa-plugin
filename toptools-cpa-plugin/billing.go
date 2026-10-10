package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	clerkTokens = siteURL + "/api/__clerk/v1/client/sessions/"
	clerkClient = siteURL + "/api/__clerk/v1/client"
)

type usageRPC struct {
	Requests               int64 `json:"requests"`
	TokensUsed             int64 `json:"tokensUsed"`
	ImagesUsed             int64 `json:"imagesUsed"`
	WelcomeTokensLimit     int64 `json:"welcomeTokensLimit"`
	WelcomeTokensRemaining int64 `json:"welcomeTokensRemaining"`
	TokenLimit             int64 `json:"tokenLimit"`
	TokensRemaining        int64 `json:"tokensRemaining"`
	WelcomePopupPending    bool  `json:"welcomePopupPending"`
}

type ownedModel struct {
	ModelName       string `json:"modelName"`
	Tier            string `json:"tier"`
	AccessType      string `json:"accessType"`
	TokensRemaining int64  `json:"tokensRemaining"`
	TokenLimit      int64  `json:"tokenLimit"`
	TokensUsed      int64  `json:"tokensUsed"`
	ExpiresAt       string `json:"expiresAt"`
}

type planView struct {
	Requests         int64        `json:"requests"`
	TokensUsed       int64        `json:"tokens_used"`
	ImagesUsed       int64        `json:"images_used"`
	WelcomeLimit     int64        `json:"welcome_limit"`
	WelcomeRemaining int64        `json:"welcome_remaining"`
	DailyLimit       int64        `json:"daily_limit"`
	DailyRemaining   int64        `json:"daily_remaining"`
	DailyUsed        int64        `json:"daily_used"`
	BalanceCents     int64        `json:"balance_cents"`
	BalanceUSD       string       `json:"balance_usd"`
	Owned            []ownedModel `json:"owned"`
	Cooled           bool         `json:"cooled,omitempty"`
	CoolReason       string       `json:"cool_reason,omitempty"`
	Error            string       `json:"error,omitempty"`
}

type dashCacheEntry struct {
	at   time.Time
	view planView
}

var dashCache sync.Map

func jwtPayload(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	p := parts[1]
	switch len(p) % 4 {
	case 2:
		p += "=="
	case 3:
		p += "="
	}
	raw, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func isClientTok(tok string) bool {
	m := jwtPayload(tok)
	if m == nil {
		return false
	}
	if _, ok := m["rotating_token"]; ok {
		return true
	}
	id, _ := m["id"].(string)
	return strings.HasPrefix(id, "client_")
}

func isSessionTok(tok string) bool {
	m := jwtPayload(tok)
	if m == nil {
		return false
	}
	sid, _ := m["sid"].(string)
	return strings.HasPrefix(sid, "sess_")
}

func clerkJWT(sa *storedAuth) string {
	if sa == nil {
		return ""
	}
	if s := strings.TrimSpace(sa.Auth.SessionAccess); isSessionTok(s) {
		return s
	}
	return ""
}

func clerkClientTok(sa *storedAuth) string {
	if sa == nil {
		return ""
	}
	for _, s := range []string{sa.Auth.ClientToken, sa.Auth.RefreshToken} {
		if isClientTok(strings.TrimSpace(s)) {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func clerkDo(method, url, bearer string, body io.Reader) (*hostHTTPResponse, error) {
	var raw []byte
	if body != nil {
		var err error
		raw, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return hostHTTPDoDirect(req, raw)
}

func persistAuth(sa *storedAuth, fileName string) {
	if fileName == "" || sa == nil {
		return
	}
	disabled, note := false, ""
	if _, raw, err := hostAuthGet(fileName); err == nil {
		disabled = parseDisabledFromAuthJSON(raw)
		note = parseNoteFromAuthJSON(raw)
	}
	out, err := buildAuthFileJSON(sa, disabled, note)
	if err == nil {
		_ = hostAuthSaveJSON(fileName, out)
	}
}

func applyClerkAuthHeader(sa *storedAuth, h http.Header) {
	auth := strings.TrimSpace(h.Get("Authorization"))
	auth = strings.TrimPrefix(auth, "Bearer ")
	if isClientTok(auth) {
		sa.Auth.ClientToken = auth
		sa.Auth.RefreshToken = auth
	}
}

func mintSessionJWT(sa *storedAuth, fileName string) (string, error) {
	client := clerkClientTok(sa)
	if client == "" {
		if jwt := clerkJWT(sa); jwt != "" {
			return jwt, nil
		}
		return "", fmt.Errorf("no clerk client token")
	}
	sid := strings.TrimSpace(sa.Auth.SessionID)
	if sid == "" {
		resp, err := clerkDo(http.MethodGet, clerkClient, client, nil)
		if err != nil {
			return "", err
		}
		applyClerkAuthHeader(sa, resp.Headers)
		var wrap struct {
			Response struct {
				Sessions []struct {
					ID string `json:"id"`
				} `json:"sessions"`
			} `json:"response"`
			Client struct {
				Sessions []struct {
					ID string `json:"id"`
				} `json:"sessions"`
			} `json:"client"`
		}
		_ = json.Unmarshal(resp.Body, &wrap)
		if len(wrap.Client.Sessions) > 0 {
			sid = wrap.Client.Sessions[0].ID
		} else if len(wrap.Response.Sessions) > 0 {
			sid = wrap.Response.Sessions[0].ID
		}
		if sid != "" {
			sa.Auth.SessionID = sid
		}
	}
	if sid == "" {
		return "", fmt.Errorf("no clerk session id")
	}
	resp, err := clerkDo(http.MethodPost, clerkTokens+sid+"/tokens", clerkClientTok(sa), nil)
	if err != nil {
		return "", err
	}
	applyClerkAuthHeader(sa, resp.Headers)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("clerk tokens HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 160))
	}
	var tok struct {
		JWT      string `json:"jwt"`
		Response struct {
			JWT string `json:"jwt"`
		} `json:"response"`
	}
	_ = json.Unmarshal(resp.Body, &tok)
	jwt := tok.JWT
	if jwt == "" {
		jwt = tok.Response.JWT
	}
	if jwt == "" {
		return "", fmt.Errorf("clerk tokens: empty jwt")
	}
	sa.Auth.SessionAccess = jwt
	persistAuth(sa, fileName)
	return jwt, nil
}

func fetchDashboard(sa *storedAuth, fileName, callbackID string) planView {
	_ = callbackID
	uid := ""
	if sa != nil {
		uid = sa.Account.UID
	}
	if uid != "" {
		if v, ok := dashCache.Load(uid); ok {
			e := v.(dashCacheEntry)
			if time.Since(e.at) < 20*time.Second && e.view.Error == "" {
				return e.view
			}
		}
	}
	view := planView{}
	jwt, err := mintSessionJWT(sa, fileName)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	usageResp, err := clerkDo(http.MethodGet, siteURL+"/api/usage", jwt, nil)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	if usageResp.StatusCode == 401 || usageResp.StatusCode == 403 {
		view.Error = fmt.Sprintf("usage HTTP %d", usageResp.StatusCode)
		return view
	}
	if usageResp.StatusCode >= 400 {
		view.Error = fmt.Sprintf("usage HTTP %d: %s", usageResp.StatusCode, truncate(string(usageResp.Body), 160))
		return view
	}
	var u usageRPC
	_ = json.Unmarshal(usageResp.Body, &u)
	view.Requests = u.Requests
	view.TokensUsed = u.TokensUsed
	view.ImagesUsed = u.ImagesUsed
	view.WelcomeLimit = u.WelcomeTokensLimit
	view.WelcomeRemaining = u.WelcomeTokensRemaining
	view.DailyLimit = u.TokenLimit
	view.DailyRemaining = u.TokensRemaining
	if view.DailyLimit == 0 {
		view.DailyLimit = 10_000_000
	}
	view.DailyUsed = u.TokensUsed
	if u.TokenLimit > 0 {
		view.DailyUsed = u.TokenLimit - u.TokensRemaining
		if view.DailyUsed < 0 {
			view.DailyUsed = 0
		}
	}

	if bal, err := clerkDo(http.MethodGet, siteURL+"/api/balance", jwt, nil); err == nil && bal.StatusCode < 400 {
		var b struct {
			BalanceCents int64 `json:"balanceCents"`
		}
		if json.Unmarshal(bal.Body, &b) == nil {
			view.BalanceCents = b.BalanceCents
			view.BalanceUSD = fmt.Sprintf("$%.2f", float64(b.BalanceCents)/100)
		}
	}

	if own, err := clerkDo(http.MethodGet, siteURL+"/api/active-model", jwt, nil); err == nil && own.StatusCode < 400 {
		var models []ownedModel
		if json.Unmarshal(own.Body, &models) == nil {
			view.Owned = models
		} else {
			var wrap struct {
				Models []ownedModel `json:"models"`
				Data   []ownedModel `json:"data"`
			}
			if json.Unmarshal(own.Body, &wrap) == nil {
				if len(wrap.Models) > 0 {
					view.Owned = wrap.Models
				} else {
					view.Owned = wrap.Data
				}
			}
		}
	}

	cool, why := cooldownFromPlan(view)
	view.Cooled = cool
	view.CoolReason = why
	if uid != "" {
		dashCache.Store(uid, dashCacheEntry{at: time.Now(), view: view})
	}
	return view
}

func cooldownFromPlan(p planView) (bool, string) {
	if p.Error != "" {
		return false, ""
	}
	if p.BalanceCents > 0 {
		return false, ""
	}
	paid := false
	freeLeft := false
	for _, m := range p.Owned {
		if m.AccessType == "free" {
			if m.TokensRemaining > 0 {
				freeLeft = true
			}
		} else if strings.TrimSpace(m.ExpiresAt) != "" {
			paid = true
		}
	}
	if paid || freeLeft {
		return false, ""
	}
	if p.DailyLimit > 0 && p.DailyRemaining <= 0 {
		return true, "daily cap"
	}
	return false, ""
}

func applyCooldown(fileName string, sa *storedAuth, plan planView) {
	if sa == nil || strings.TrimSpace(fileName) == "" || plan.Error != "" {
		return
	}
	note := ""
	if plan.Cooled {
		note = "cooldown: " + plan.CoolReason
	}
	_, raw, err := hostAuthGet(fileName)
	if err == nil && parseDisabledFromAuthJSON(raw) == plan.Cooled && parseNoteFromAuthJSON(raw) == note {
		return
	}
	out, err := buildAuthFileJSON(sa, plan.Cooled, note)
	if err == nil {
		_ = hostAuthSaveJSON(fileName, out)
	}
}

func reconcileAuth(authID string, sa *storedAuth, callbackID string) {
	if sa == nil {
		return
	}
	name := strings.TrimSpace(authID)
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		if n, _, err := hostAuthGet(authID); err == nil && n != "" {
			name = n
		} else if files, err := hostAuthList(); err == nil {
			for _, f := range files {
				if f.AuthIndex == authID || f.ID == authID || f.Name == authID {
					name = f.Name
					break
				}
			}
		}
	}
	if name == "" {
		return
	}
	plan := fetchDashboard(sa, name, callbackID)
	applyCooldown(name, sa, plan)
}

func reconcileAll() {
	files, err := hostAuthList()
	if err != nil {
		return
	}
	for _, f := range files {
		raw, err := hostAuthGetJSON(firstNonEmpty(f.AuthIndex, f.ID, f.Name))
		if err != nil {
			continue
		}
		sa, err := parseStored(raw)
		if err != nil {
			continue
		}
		reconcileAuth(f.Name, sa, "")
	}
}
