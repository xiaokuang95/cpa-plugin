package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const microusdPerCredit = 10_000

type billingRPC struct {
	Tier                      string `json:"tier"`
	Status                    string `json:"status"`
	IsPeakNow                 bool   `json:"is_peak_now"`
	Cap5hMicrousd             int64  `json:"cap_5h_microusd"`
	Cap7dMicrousd             int64  `json:"cap_7d_microusd"`
	BalanceMicrousd           int64  `json:"balance_microusd"`
	Burn5hMicrousd            int64  `json:"burn_5h_microusd"`
	Burn7dMicrousd            int64  `json:"burn_7d_microusd"`
	CycleBurnMicrousd         int64  `json:"cycle_burn_microusd"`
	MonthBurnMicrousd         int64  `json:"month_burn_microusd"`
	UnlimitedCredits          bool   `json:"unlimited_credits"`
	FreeGrantedPeriod         bool   `json:"free_granted_period"`
	FreeNextRefillAt          string `json:"free_next_refill_at"`
	FreeAllowanceMicrousd     int64  `json:"free_allowance_microusd"`
	BaseFreeAllowanceMicrousd int64  `json:"base_free_allowance_microusd"`
	ModelPromotions           []struct {
		Label      string  `json:"label"`
		Model      string  `json:"model"`
		Multiplier float64 `json:"multiplier"`
	} `json:"model_promotions"`
}

type modelUsageView struct {
	Model      string  `json:"model"`
	Label      string  `json:"label"`
	Multiplier float64 `json:"multiplier"`
	Badge      string  `json:"badge"`
	FiveHUsed  float64 `json:"five_h_used"`
	FiveHLimit float64 `json:"five_h_limit"`
	WeekUsed   float64 `json:"week_used"`
	WeekLimit  float64 `json:"week_limit"`
	MonthUsed  float64 `json:"month_used"`
	MonthLimit float64 `json:"month_limit"`
}

type planView struct {
	Plan           string           `json:"plan"`
	Tagline        string           `json:"tagline"`
	Unlimited      bool             `json:"unlimited"`
	CreditsLeft    float64          `json:"credits_left"`
	Allowance      float64          `json:"allowance"`
	UsedCycle      float64          `json:"used_cycle"`
	Burn5h         float64          `json:"burn_5h"`
	Cap5h          float64          `json:"cap_5h"`
	Burn7d         float64          `json:"burn_7d"`
	Cap7d          float64          `json:"cap_7d"`
	RefillAt       string           `json:"refill_at"`
	IsPeakNow      bool             `json:"is_peak_now"`
	PromotionsNote string           `json:"promotions_note"`
	Models         []modelUsageView `json:"models"`
	Cooled         bool             `json:"cooled"`
	CoolReason     string           `json:"cool_reason,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type billingCacheEntry struct {
	at   time.Time
	view planView
}

var billingCache sync.Map

func creditsOf(micro int64) float64 {
	return math.Round(float64(micro)/microusdPerCredit*10) / 10
}

func jwtFresh(sa *storedAuth) bool {
	if sa == nil || strings.TrimSpace(sa.Auth.SessionAccess) == "" {
		return false
	}
	if sa.Auth.SessionExpiresAt == 0 {
		return true
	}
	return sa.Auth.SessionExpiresAt > time.Now().Add(2*time.Minute).Unix()
}

var loginBackoffUntil time.Time

func sessionJWT(sa *storedAuth, fileName, callbackID string, force, allowPassword bool) (string, error) {
	if sa == nil {
		return "", fmt.Errorf("no supabase session")
	}
	if !force && jwtFresh(sa) {
		return sa.Auth.SessionAccess, nil
	}
	sa.Auth.SessionAccess = ""
	sa.Auth.SessionExpiresAt = 0
	var last error
	var tok struct {
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		ExpiresAt    float64 `json:"expires_at"`
		ExpiresIn    float64 `json:"expires_in"`
	}
	apply := func(resp *hostHTTPResponse, what string) error {
		if resp.StatusCode >= 400 {
			return fmt.Errorf("%s HTTP %d: %s", what, resp.StatusCode, truncate(string(resp.Body), 180))
		}
		if err := json.Unmarshal(resp.Body, &tok); err != nil || tok.AccessToken == "" {
			return fmt.Errorf("%s: no access_token", what)
		}
		return nil
	}
	if rt := strings.TrimSpace(sa.Auth.SessionRefresh); rt != "" {
		resp, err := postJSON(AUTH+"/token?grant_type=refresh_token", fnHeaders(), map[string]string{"refresh_token": rt}, callbackID)
		if err != nil {
			last = err
		} else {
			last = apply(resp, "session refresh")
		}
	}
	if tok.AccessToken == "" && allowPassword {
		if time.Now().Before(loginBackoffUntil) {
			return "", fmt.Errorf("password login 429, wait until %s", loginBackoffUntil.Format(time.RFC3339))
		}
		email := strings.TrimSpace(sa.Account.Email)
		pass := strings.TrimSpace(sa.Account.Password)
		if email == "" || pass == "" {
			if last != nil {
				return "", last
			}
			return "", fmt.Errorf("no supabase session")
		}
		resp, err := postJSON(AUTH+"/token?grant_type=password", fnHeaders(), map[string]string{"email": email, "password": pass}, callbackID)
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 429 {
			loginBackoffUntil = time.Now().Add(10 * time.Minute)
		}
		if err := apply(resp, "password login"); err != nil {
			return "", err
		}
	}
	if tok.AccessToken == "" {
		if last != nil {
			return "", last
		}
		return "", fmt.Errorf("no session jwt")
	}
	sa.Auth.SessionAccess = tok.AccessToken
	if tok.RefreshToken != "" {
		sa.Auth.SessionRefresh = tok.RefreshToken
	}
	exp := time.Now().Add(50 * time.Minute).Unix()
	if tok.ExpiresAt > 0 {
		exp = int64(tok.ExpiresAt)
	} else if tok.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	sa.Auth.SessionExpiresAt = exp
	persistAuth(fileName, sa, false, "")
	return tok.AccessToken, nil
}

func persistAuth(fileName string, sa *storedAuth, forceDisabled bool, note string) {
	if strings.TrimSpace(fileName) == "" || sa == nil {
		return
	}
	disabled := forceDisabled
	if !forceDisabled {
		if _, raw, err := hostAuthGet(fileName); err == nil {
			disabled = parseDisabledFromAuthJSON(raw)
			if note == "" {
				note = parseNoteFromAuthJSON(raw)
			}
		}
	}
	raw, err := buildAuthFileJSON(sa, disabled, note)
	if err == nil {
		_ = hostAuthSaveJSON(fileName, raw)
	}
}

func fetchBilling(sa *storedAuth, fileName, callbackID string, bust, allowPassword bool) planView {
	uid := ""
	if sa != nil {
		uid = sa.Account.UID
	}
	if uid != "" {
		if bust {
			billingCache.Delete(uid)
		} else if v, ok := billingCache.Load(uid); ok {
			e := v.(billingCacheEntry)
			if time.Since(e.at) < 2*time.Minute {
				return e.view
			}
		}
	}
	view := planView{Plan: "Free plan"}
	jwt, err := sessionJWT(sa, fileName, callbackID, false, allowPassword)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	resp, err := postJSON(supabaseURL+"/rest/v1/rpc/get_billing_summary", map[string]string{
		"apikey":        anonKey,
		"Authorization": "Bearer " + jwt,
		"Content-Type":  "application/json",
	}, map[string]any{}, callbackID)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		jwt, err = sessionJWT(sa, fileName, callbackID, true, allowPassword)
		if err != nil {
			view.Error = err.Error()
			return view
		}
		resp, err = postJSON(supabaseURL+"/rest/v1/rpc/get_billing_summary", map[string]string{
			"apikey":        anonKey,
			"Authorization": "Bearer " + jwt,
			"Content-Type":  "application/json",
		}, map[string]any{}, callbackID)
		if err != nil {
			view.Error = err.Error()
			return view
		}
	}
	if resp.StatusCode >= 400 {
		view.Error = fmt.Sprintf("billing HTTP %d: %s", resp.StatusCode, truncate(string(resp.Body), 180))
		return view
	}
	var b billingRPC
	if err := json.Unmarshal(resp.Body, &b); err != nil {
		view.Error = err.Error()
		return view
	}
	view = planFromRPC(b)
	if uid != "" {
		billingCache.Store(uid, billingCacheEntry{at: time.Now(), view: view})
	}
	return view
}

func planFromRPC(b billingRPC) planView {
	allow := b.FreeAllowanceMicrousd
	if allow <= 0 {
		allow = b.BaseFreeAllowanceMicrousd
	}
	if allow <= 0 {
		allow = 500_000
	}
	left := allow
	if b.FreeGrantedPeriod {
		if b.BalanceMicrousd > 0 {
			left = b.BalanceMicrousd
		} else {
			left = 0
		}
	}
	refill := ""
	if t, err := time.Parse(time.RFC3339Nano, b.FreeNextRefillAt); err == nil {
		refill = t.Format("Jan 2")
	} else if t, err := time.Parse(time.RFC3339, b.FreeNextRefillAt); err == nil {
		refill = t.Format("Jan 2")
	}
	plan := "Free plan"
	if b.Tier != "" && b.Tier != "free" && b.Status != "" && b.Status != "none" {
		plan = strings.ToUpper(b.Tier[:1]) + b.Tier[1:]
	}
	tagline := fmt.Sprintf("%s free credits every 30 days — no card required.", fmtCredits(creditsOf(b.BaseFreeAllowanceMicrousd)))
	if b.BaseFreeAllowanceMicrousd <= 0 {
		tagline = fmt.Sprintf("%s free credits every 30 days — no card required.", fmtCredits(creditsOf(allow)))
	}
	note := []string{}
	models := make([]modelUsageView, 0, len(b.ModelPromotions))
	for _, p := range b.ModelPromotions {
		if p.Model == "" || p.Multiplier < 1 {
			continue
		}
		m := p.Multiplier
		badge := "Standard"
		if m > 1 {
			badge = fmt.Sprintf("%.0f× usage", m)
			note = append(note, fmt.Sprintf("%s: %.0f usage credits spend 1 base credit", p.Label, m))
		}
		monthLimit := creditsOf(int64(float64(allow) * m))
		if b.UnlimitedCredits {
			monthLimit = 0
		}
		models = append(models, modelUsageView{
			Model:      p.Model,
			Label:      p.Label,
			Multiplier: m,
			Badge:      badge,
			FiveHUsed:  creditsOf(int64(float64(b.Burn5hMicrousd) * m)),
			FiveHLimit: creditsOf(int64(float64(b.Cap5hMicrousd) * m)),
			WeekUsed:   creditsOf(int64(float64(b.Burn7dMicrousd) * m)),
			WeekLimit:  creditsOf(int64(float64(b.Cap7dMicrousd) * m)),
			MonthUsed:  creditsOf(int64(float64(b.CycleBurnMicrousd) * m)),
			MonthLimit: monthLimit,
		})
	}
	cool, why := cooldownFromRPC(b)
	return planView{
		Plan:           plan,
		Tagline:        tagline,
		Unlimited:      b.UnlimitedCredits,
		CreditsLeft:    creditsOf(left),
		Allowance:      creditsOf(allow),
		UsedCycle:      creditsOf(b.CycleBurnMicrousd),
		Burn5h:         creditsOf(b.Burn5hMicrousd),
		Cap5h:          creditsOf(b.Cap5hMicrousd),
		Burn7d:         creditsOf(b.Burn7dMicrousd),
		Cap7d:          creditsOf(b.Cap7dMicrousd),
		RefillAt:       refill,
		IsPeakNow:      b.IsPeakNow,
		PromotionsNote: strings.Join(note, ". "),
		Models:         models,
		Cooled:         cool,
		CoolReason:     why,
	}
}

func cooldownFromRPC(b billingRPC) (bool, string) {
	if b.UnlimitedCredits {
		return false, ""
	}
	if b.Cap5hMicrousd > 0 && b.Burn5hMicrousd >= b.Cap5hMicrousd {
		return true, "5-hour cap"
	}
	if b.Cap7dMicrousd > 0 && b.Burn7dMicrousd >= b.Cap7dMicrousd {
		return true, "weekly cap"
	}
	allow := b.FreeAllowanceMicrousd
	if allow <= 0 {
		allow = b.BaseFreeAllowanceMicrousd
	}
	if allow > 0 && b.FreeGrantedPeriod && b.BalanceMicrousd <= 0 {
		return true, "monthly cap"
	}
	if allow > 0 && b.CycleBurnMicrousd >= allow {
		return true, "monthly cap"
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

func reconcileAuth(authID string, sa *storedAuth, callbackID string, bust bool) {
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
		name = authFileNameFor(sa)
	}
	plan := fetchBilling(sa, name, callbackID, bust, false)
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
		reconcileAuth(f.Name, sa, "", false)
	}
}

func fmtCredits(n float64) string {
	if n == math.Trunc(n) {
		return fmt.Sprintf("%.0f", n)
	}
	return fmt.Sprintf("%.1f", n)
}
