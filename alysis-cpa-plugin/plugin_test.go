package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestParseStoredShapes(t *testing.T) {
	nested := []byte(`{"auth":{"accessToken":"slk_abc_def"},"account":{"uid":"u1","nickname":"n"}}`)
	sa, err := parseStored(nested)
	if err != nil || sa.Auth.AccessToken != "slk_abc_def" || sa.Account.UID != "u1" {
		t.Fatalf("nested: %#v %v", sa, err)
	}
	flat := []byte(`{"accessToken":"slk_flat","uid":"u2"}`)
	sa, err = parseStored(flat)
	if err != nil || sa.Auth.AccessToken != "slk_flat" || sa.Account.UID != "u2" {
		t.Fatalf("flat: %#v %v", sa, err)
	}
	keyed := []byte(`{"key":"slk_keyed"}`)
	sa, err = parseStored(keyed)
	if err != nil || sa.Auth.AccessToken != "slk_keyed" {
		t.Fatalf("key: %#v %v", sa, err)
	}
	raw := []byte(" slk_rawtoken ")
	sa, err = parseStored(raw)
	if err != nil || sa.Auth.AccessToken != "slk_rawtoken" {
		t.Fatalf("raw: %#v %v", sa, err)
	}
}

func TestParseAuthOwnership(t *testing.T) {
	body, err := handleParseAuth(mustJSON(pluginapi.AuthParseRequest{
		Provider: "other",
		FileName: "qoderwork-1.json",
		RawJSON:  []byte(`{"type":"qoderwork","auth":{"accessToken":"x"}}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(body, &env)
	var resp pluginapi.AuthParseResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.Handled {
		t.Fatal("claimed foreign type")
	}

	body, err = handleParseAuth(mustJSON(pluginapi.AuthParseRequest{
		FileName: "alysis-u1.json",
		RawJSON:  []byte(`{"key":"slk_abc123456789"}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(body, &env)
	_ = json.Unmarshal(env.Result, &resp)
	if !resp.Handled {
		t.Fatal("did not claim alysis- prefix")
	}
	if resp.Auth.ID != "" {
		t.Fatalf("ID must be empty, got %q", resp.Auth.ID)
	}
	if resp.Auth.FileName != "alysis-u1.json" {
		t.Fatalf("filename echo: %q", resp.Auth.FileName)
	}
}

func TestJwtFresh(t *testing.T) {
	sa := &storedAuth{Auth: storedTokens{SessionAccess: "jwt", SessionExpiresAt: time.Now().Add(time.Hour).Unix()}}
	if !jwtFresh(sa) {
		t.Fatal("fresh jwt should reuse")
	}
	sa.Auth.SessionExpiresAt = time.Now().Add(time.Minute).Unix()
	if jwtFresh(sa) {
		t.Fatal("near-expiry jwt should refresh")
	}
}

func TestSanitizeAndProtocol(t *testing.T) {
	if got := sanitizeUIDForFileName("../etc/passwd"); got == "../etc/passwd" || strings.Contains(got, "/") {
		t.Fatalf("sanitize leaked: %q", got)
	}
	if protocolForModel("gpt-6-luna").Path != "/responses" {
		t.Fatal("luna path")
	}
	if protocolForModel("alysis/claude-haiku-5-5").Format != sdktranslator.FormatClaude {
		t.Fatal("haiku format")
	}
	if protocolForModel("deepseek-flash").Path != "/chat/completions" {
		t.Fatal("deepseek path")
	}
	if canonicalModel("foo/deepseek-v4-flash") != "deepseek-flash" {
		t.Fatal("alias")
	}
}

func TestChatToResponses(t *testing.T) {
	in := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":16}`)
	out := chatToResponses(in, "gpt-6-luna", true)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != "gpt-6-luna" {
		t.Fatalf("model %v", m["model"])
	}
	if _, ok := m["input"]; !ok {
		t.Fatalf("missing input: %s", out)
	}
	if _, ok := m["messages"]; ok {
		t.Fatal("messages still present")
	}
	if m["stream"] != true {
		t.Fatal("stream")
	}
}

func TestPlanFromRPC(t *testing.T) {
	b := billingRPC{
		Tier:                      "free",
		Status:                    "none",
		Cap5hMicrousd:             250000,
		Cap7dMicrousd:             500000,
		BalanceMicrousd:           499000,
		Burn5hMicrousd:            1000,
		Burn7dMicrousd:            1000,
		CycleBurnMicrousd:         1000,
		FreeGrantedPeriod:         true,
		FreeNextRefillAt:          "2026-11-08T07:02:06.014484+00:00",
		FreeAllowanceMicrousd:     500000,
		BaseFreeAllowanceMicrousd: 500000,
		ModelPromotions: []struct {
			Label      string  `json:"label"`
			Model      string  `json:"model"`
			Multiplier float64 `json:"multiplier"`
		}{
			{Label: "GPT-6 Luna", Model: "gpt-6-luna", Multiplier: 2},
			{Label: "DeepSeek V4.1 Flash", Model: "deepseek-flash", Multiplier: 1},
		},
	}
	p := planFromRPC(b)
	if p.Plan != "Free plan" || p.CreditsLeft != 49.9 || p.Allowance != 50 || p.UsedCycle != 0.1 {
		t.Fatalf("plan %#v", p)
	}
	if p.RefillAt != "Nov 8" {
		t.Fatalf("refill %q", p.RefillAt)
	}
	if len(p.Models) != 2 || p.Models[0].FiveHUsed != 0.2 || p.Models[0].FiveHLimit != 50 {
		t.Fatalf("luna window %#v", p.Models[0])
	}
	if p.Cooled {
		t.Fatal("should not cool at 0.1/25")
	}
	full := b
	full.Burn5hMicrousd = 250000
	if cool, why := cooldownFromRPC(full); !cool || why != "5-hour cap" {
		t.Fatalf("5h %v %q", cool, why)
	}
	full = b
	full.Burn7dMicrousd = 500000
	if cool, why := cooldownFromRPC(full); !cool || why != "weekly cap" {
		t.Fatalf("7d %v %q", cool, why)
	}
	full = b
	full.BalanceMicrousd = 0
	full.CycleBurnMicrousd = 500000
	if cool, why := cooldownFromRPC(full); !cool || why != "monthly cap" {
		t.Fatalf("month %v %q", cool, why)
	}
}

func TestUidFromKey(t *testing.T) {
	if uidFromKey("slk_ABC-def_1234567890") == "" {
		t.Fatal("empty uid")
	}
}

func TestBuiltinTranslators(t *testing.T) {
	if !sdktranslator.HasRequestTransformer(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude) {
		t.Fatal("missing openai→claude request translator")
	}
	// Register(client, provider): stream converter is provider→client.
	if !sdktranslator.HasStreamResponseTransformer(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude) {
		t.Fatal("missing claude→openai stream translator")
	}
}

func TestApplyUpstreamHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example", nil)
	req.Header.Set("User-Agent", "Go-http-client/1.1")
	req.Header.Set("Accept", "application/json")
	applyUpstreamHeaders(req, &storedAuth{Auth: storedTokens{AccessToken: "slk_x"}}, sdktranslator.FormatClaude)
	if req.Header.Get("User-Agent") != alysisCodeUA {
		t.Fatalf("ua %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Accept-Encoding") != "identity" || req.Header.Get("Accept") != "" {
		t.Fatalf("headers %#v", req.Header)
	}
	if req.Header.Get("anthropic-version") != anthropicVersion {
		t.Fatal("missing anthropic-version")
	}
}
