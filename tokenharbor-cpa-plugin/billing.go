package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	freeTierURL = siteURL + "/api/me/free-tier"
	loginURL    = siteURL + "/login"
	loginUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
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
	return sa != nil && strings.TrimSpace(sa.Auth.SessionCookie) != ""
}

var (
	loginBackoffUntil time.Time
	loginMu           sync.Mutex
	lastPasswordLogin time.Time
)

var (
	actionRefRe = regexp.MustCompile(`name="\$ACTION_1:0"\s+value="([^"]*)"`)
	actionKeyRe = regexp.MustCompile(`name="\$ACTION_KEY"\s+value="([^"]*)"`)
	signupErrRe = regexp.MustCompile(`(?m)^1:\{"error":"([^"]+)"`)
)

func sessionCookie(sa *storedAuth, fileName, callbackID string, force, allowPassword bool) (string, error) {
	if sa == nil {
		return "", fmt.Errorf("no auth")
	}
	if sa.Auth.SessionCookie != "" && !force {
		return sa.Auth.SessionCookie, nil
	}
	if !allowPassword {
		if sa.Auth.SessionCookie != "" {
			return sa.Auth.SessionCookie, nil
		}
		return "", fmt.Errorf("no session cookie (click card to login)")
	}
	if time.Now().Before(loginBackoffUntil) {
		return "", fmt.Errorf("password login 429, wait until %s", loginBackoffUntil.Format(time.RFC3339))
	}
	email := strings.TrimSpace(sa.Account.Email)
	pass := strings.TrimSpace(sa.Account.Password)
	if email == "" || pass == "" {
		return "", fmt.Errorf("need email+password for /api/me/free-tier (API key is not a session)")
	}
	loginMu.Lock()
	wait := 15*time.Second - time.Since(lastPasswordLogin)
	if wait > 0 {
		time.Sleep(wait)
	}
	cookie, exp, err := loginSessionCookie(email, pass, callbackID)
	lastPasswordLogin = time.Now()
	loginMu.Unlock()
	if err != nil {
		return "", err
	}
	sa.Auth.SessionCookie = cookie
	sa.Auth.SessionExpiresAt = exp
	persistSession(sa, fileName)
	return cookie, nil
}

func loginSessionCookie(email, password, callbackID string) (string, int64, error) {
	_ = callbackID
	page, err := loginDo(http.MethodGet, loginURL, nil, map[string]string{"Accept": "text/html"})
	if err != nil {
		return "", 0, err
	}
	cookie := cookieHeader(page.Headers)
	ref, key, err := parseLoginAction(string(page.Body))
	if err != nil {
		return "", 0, err
	}
	body, boundary := buildLoginForm(email, password, ref, key)
	headers := map[string]string{
		"Content-Type": "multipart/form-data; boundary=" + boundary,
		"Accept":       "text/html",
		"Origin":       siteURL,
		"Referer":      loginURL,
	}
	if cookie != "" {
		headers["Cookie"] = cookie
	}
	resp, err := loginDo(http.MethodPost, loginURL, strings.NewReader(body), headers)
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode == 429 {
		loginBackoffUntil = time.Now().Add(10 * time.Minute)
		return "", 0, fmt.Errorf("password login 429, pause 10m")
	}
	text := string(resp.Body)
	if m := signupErrRe.FindStringSubmatch(text); len(m) == 2 {
		return "", 0, fmt.Errorf("login: %s", m[1])
	}
	if joined := cookieHeader(resp.Headers); joined != "" {
		cookie = mergeCookies(cookie, joined)
	}
	if !sessionCookiePresent(cookie) {
		return "", 0, fmt.Errorf("login HTTP %d: no session cookie %s", resp.StatusCode, shortErr(text))
	}
	return cookie, time.Now().Add(50 * time.Minute).Unix(), nil
}

func loginDo(method, rawURL string, body io.Reader, headers map[string]string) (*hostHTTPResponse, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", loginUA)
	c := *sharedHTTPClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &hostHTTPResponse{StatusCode: resp.StatusCode, Headers: resp.Header.Clone(), Body: raw}, nil
}

func parseLoginAction(html string) (ref, key string, err error) {
	rm := actionRefRe.FindStringSubmatch(html)
	km := actionKeyRe.FindStringSubmatch(html)
	if len(rm) < 2 || len(km) < 2 {
		return "", "", fmt.Errorf("login page missing $ACTION_1:0")
	}
	return htmlUnescape(rm[1]), htmlUnescape(km[1]), nil
}

func htmlUnescape(s string) string {
	r := strings.NewReplacer("&quot;", `"`, "&#x27;", "'", "&lt;", "<", "&gt;", ">", "&amp;", "&")
	return r.Replace(s)
}

func buildLoginForm(email, password, ref, key string) (string, string) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	boundary := "----WebKitFormBoundary" + strings.ToUpper(hex.EncodeToString(b[:]))
	fp := hex.EncodeToString(b[:4])
	af := func(name, value string) string {
		return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value
	}
	parts := []string{
		af("$ACTION_REF_1", ""),
		af("$ACTION_1:0", ref),
		af("$ACTION_1:1", `["$undefined"]`),
		af("$ACTION_KEY", key),
		af("device_fingerprint", fp),
		af("timezone", "Asia/Shanghai"),
		af("next", ""),
		af("email", email),
		af("password", password),
	}
	return strings.Join(parts, "\r\n") + "\r\n--" + boundary + "--\r\n", boundary
}

func cookieHeader(h http.Header) string {
	if h == nil {
		return ""
	}
	var parts []string
	for _, raw := range h.Values("Set-Cookie") {
		pair := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		if pair != "" {
			parts = append(parts, pair)
		}
	}
	return strings.Join(parts, "; ")
}

func mergeCookies(old, neu string) string {
	m := map[string]string{}
	var order []string
	add := func(s string) {
		for _, p := range strings.Split(s, ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			k, _, _ := strings.Cut(p, "=")
			if _, ok := m[k]; !ok {
				order = append(order, k)
			}
			m[k] = p
		}
	}
	add(old)
	add(neu)
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, m[k])
	}
	return strings.Join(out, "; ")
}

func sessionCookiePresent(cookie string) bool {
	return strings.Contains(cookie, "auth-token") || strings.Contains(cookie, "sb-access-token")
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
