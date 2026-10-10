package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	freeTierURL = siteURL + "/api/me/free-tier"
	authAPI     = "https://auth.tokenharbor.ai/auth/v1"
	anonKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlzYm56bXdqbXRpdWlwZXNnbW1nIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY3NjU1MzYsImV4cCI6MjA5MjM0MTUzNn0.CodUcchio6jNW_k68vaAb--LshBQXK51tZ6VTxNSz_A"
	cookieChunk = 3180
)

type planView struct {
	UsedPct         int      `json:"used_pct"`
	ReqUsed         int64    `json:"req_used"`
	Exhausted       bool     `json:"exhausted"`
	Activated       bool     `json:"activated"`
	ResetAt         string   `json:"reset_at"`
	PeriodStartedAt string   `json:"period_started_at"`
	PeriodEndsAt    string   `json:"period_ends_at"`
	Models          []string `json:"models"`
	Cooled          bool     `json:"cooled,omitempty"`
	CoolReason      string   `json:"cool_reason,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type dashCacheEntry struct {
	at   time.Time
	view planView
}

var dashCache sync.Map

type freeTierRPC struct {
	OK              bool     `json:"ok"`
	UsedPct         int      `json:"used_pct"`
	ReqUsed         int64    `json:"req_used"`
	Exhausted       bool     `json:"exhausted"`
	Activated       bool     `json:"activated"`
	ResetAt         string   `json:"reset_at"`
	PeriodStartedAt string   `json:"period_started_at"`
	PeriodEndsAt    string   `json:"period_ends_at"`
	Labels          []string `json:"allowance_model_labels"`
}

func fetchDashboard(sa *storedAuth, fileName, callbackID string, allowPassword bool) planView {
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
	cookie, err := sessionCookie(sa, fileName, callbackID, false, allowPassword)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	resp, err := getJSON(freeTierURL, map[string]string{"Cookie": cookie}, callbackID)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		cookie, err = sessionCookie(sa, fileName, callbackID, true, allowPassword)
		if err != nil {
			view.Error = err.Error()
			return view
		}
		resp, err = getJSON(freeTierURL, map[string]string{"Cookie": cookie}, callbackID)
		if err != nil {
			view.Error = err.Error()
			return view
		}
	}
	if resp.StatusCode >= 400 {
		view.Error = fmt.Sprintf("free-tier HTTP %d: %s", resp.StatusCode, shortErr(string(resp.Body)))
		return view
	}
	var rpc freeTierRPC
	if err := json.Unmarshal(resp.Body, &rpc); err != nil {
		view.Error = err.Error()
		return view
	}
	view.UsedPct = rpc.UsedPct
	view.ReqUsed = rpc.ReqUsed
	view.Exhausted = rpc.Exhausted
	view.Activated = rpc.Activated
	view.ResetAt = rpc.ResetAt
	view.PeriodStartedAt = rpc.PeriodStartedAt
	view.PeriodEndsAt = rpc.PeriodEndsAt
	view.Models = rpc.Labels
	cool, why := cooldownFromPlan(view)
	view.Cooled = cool
	view.CoolReason = why
	if uid != "" {
		dashCache.Store(uid, dashCacheEntry{at: time.Now(), view: view})
	}
	return view
}

func cookieFresh(sa *storedAuth) bool {
	if sa == nil || sa.Auth.SessionCookie == "" {
		return false
	}
	if sa.Auth.SessionExpiresAt == 0 {
		return true
	}
	return sa.Auth.SessionExpiresAt > time.Now().Add(2*time.Minute).Unix()
}

var loginBackoffUntil time.Time

func sessionCookie(sa *storedAuth, fileName, callbackID string, force, allowPassword bool) (string, error) {
	if sa == nil {
		return "", fmt.Errorf("no auth")
	}
	if !force && cookieFresh(sa) {
		return sa.Auth.SessionCookie, nil
	}
	sa.Auth.SessionCookie = ""
	sa.Auth.SessionExpiresAt = 0
	var sess map[string]any
	var last error
	if rt := strings.TrimSpace(sa.Auth.RefreshToken); rt != "" {
		sess, last = grantToken(map[string]string{"refresh_token": rt}, "refresh_token", callbackID)
	}
	if sess == nil && allowPassword {
		if time.Now().Before(loginBackoffUntil) {
			return "", fmt.Errorf("password login 429, wait until %s", loginBackoffUntil.Format(time.RFC3339))
		}
		email := strings.TrimSpace(sa.Account.Email)
		pass := strings.TrimSpace(sa.Account.Password)
		if email == "" || pass == "" {
			if last != nil {
				return "", last
			}
			return "", fmt.Errorf("need email+password for /api/me/free-tier (API key is not a session)")
		}
		sess, last = grantToken(map[string]string{"email": email, "password": pass}, "password", callbackID)
		if last != nil {
			return "", last
		}
	}
	if sess == nil {
		if last != nil {
			return "", last
		}
		return "", fmt.Errorf("no session cookie (click card to login)")
	}
	cookie := encodeSBCookie(sess)
	exp := time.Now().Add(50 * time.Minute).Unix()
	if v, ok := sess["expires_at"].(float64); ok && v > 0 {
		exp = int64(v)
	}
	sa.Auth.SessionCookie = cookie
	sa.Auth.SessionExpiresAt = exp
	if nrt, _ := sess["refresh_token"].(string); nrt != "" {
		sa.Auth.RefreshToken = nrt
	}
	persistSession(sa, fileName)
	return cookie, nil
}

func grantToken(body map[string]string, grant, callbackID string) (map[string]any, error) {
	resp, err := postJSON(authAPI+"/token?grant_type="+grant, map[string]string{
		"apikey":        anonKey,
		"Authorization": "Bearer " + anonKey,
	}, body, callbackID)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 429 {
		loginBackoffUntil = time.Now().Add(10 * time.Minute)
		return nil, fmt.Errorf("%s HTTP 429 rate limit, pause logins 10m", grant)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s HTTP %d: %s", grant, resp.StatusCode, shortErr(string(resp.Body)))
	}
	var sess map[string]any
	if err := json.Unmarshal(resp.Body, &sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func encodeSBCookie(sess map[string]any) string {
	keep := map[string]any{}
	for _, k := range []string{"access_token", "token_type", "expires_in", "expires_at", "refresh_token", "user"} {
		if v, ok := sess[k]; ok {
			keep[k] = v
		}
	}
	raw, _ := json.Marshal(keep)
	val := "base64-" + base64.StdEncoding.EncodeToString(raw)
	if len(val) <= cookieChunk {
		return "sb-auth-auth-token=" + val
	}
	var parts []string
	for i := 0; i*cookieChunk < len(val); i++ {
		end := (i + 1) * cookieChunk
		if end > len(val) {
			end = len(val)
		}
		parts = append(parts, fmt.Sprintf("sb-auth-auth-token.%d=%s", i, val[i*cookieChunk:end]))
	}
	return strings.Join(parts, "; ")
}

func persistSession(sa *storedAuth, fileName string) {
	if sa == nil || strings.TrimSpace(fileName) == "" {
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

func shortErr(s string) string {
	t := strings.TrimSpace(s)
	low := strings.ToLower(t)
	if strings.HasPrefix(t, "<!") || strings.Contains(low, "<html") {
		return "cloudflare/html block"
	}
	if len(t) > 160 {
		return t[:160]
	}
	return t
}

func cooldownFromPlan(p planView) (bool, string) {
	if p.Error != "" {
		return false, ""
	}
	if p.Exhausted {
		until := p.PeriodEndsAt
		if until == "" {
			until = p.ResetAt
		}
		if until != "" {
			return true, "exhausted until " + until
		}
		return true, "allowance exhausted"
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
	plan := fetchDashboard(sa, name, callbackID, false)
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
