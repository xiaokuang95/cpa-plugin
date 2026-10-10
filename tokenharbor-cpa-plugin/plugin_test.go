package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestParseStored(t *testing.T) {
	sa, err := parseStored([]byte(`{"auth":{"accessToken":"thk_live_abc"},"account":{"uid":"u1"}}`))
	if err != nil || sa.Auth.AccessToken != "thk_live_abc" {
		t.Fatalf("nested %#v %v", sa, err)
	}
	sa, err = parseStored([]byte(`{"key":"thk_live_flat"}`))
	if err != nil || sa.Auth.AccessToken != "thk_live_flat" {
		t.Fatalf("key %#v %v", sa, err)
	}
	sa, err = parseStored([]byte(" thk_live_raw "))
	if err != nil || sa.Auth.AccessToken != "thk_live_raw" {
		t.Fatalf("raw %#v %v", sa, err)
	}
}

func TestParseAuthSkipForeign(t *testing.T) {
	body, err := handleParseAuth(mustJSON(pluginapi.AuthParseRequest{
		FileName: "alysis-1.json",
		RawJSON:  []byte(`{"type":"alysis","auth":{"accessToken":"slk_x"}}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(body, &env)
	var resp pluginapi.AuthParseResponse
	_ = json.Unmarshal(env.Result, &resp)
	if resp.Handled {
		t.Fatal("claimed alysis file")
	}
}

func TestParseAuthClaim(t *testing.T) {
	body, err := handleParseAuth(mustJSON(pluginapi.AuthParseRequest{
		FileName: "tokenharbor-u1.json",
		RawJSON:  []byte(`{"key":"thk_live_abcdef1234567890"}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(body, &env)
	var resp pluginapi.AuthParseResponse
	_ = json.Unmarshal(env.Result, &resp)
	if !resp.Handled || resp.Auth.ID != "" || resp.Auth.FileName != "tokenharbor-u1.json" {
		t.Fatalf("%#v", resp)
	}
}

func TestCookieFresh(t *testing.T) {
	sa := &storedAuth{Auth: storedTokens{SessionCookie: "sb-auth-auth-token=x", SessionExpiresAt: time.Now().Add(time.Hour).Unix()}}
	if !cookieFresh(sa) {
		t.Fatal("fresh cookie should reuse")
	}
	sa.Auth.SessionExpiresAt = time.Now().Add(time.Minute).Unix()
	if cookieFresh(sa) {
		t.Fatal("cookie near expiry should not reuse")
	}
}

func TestCooldownFromPlan(t *testing.T) {
	cool, why := cooldownFromPlan(planView{Exhausted: true, PeriodEndsAt: "2026-10-12T00:00:00Z"})
	if !cool || why == "" {
		t.Fatalf("%v %s", cool, why)
	}
	if cool, _ := cooldownFromPlan(planView{Exhausted: false, UsedPct: 99}); cool {
		t.Fatal("not exhausted should stay enabled")
	}
}

func TestRewriteModel(t *testing.T) {
	out := rewriteModel([]byte(`{"messages":[]}`), "mimo-v2.5:free", true)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != "mimo-v2.5:free" || m["stream"] != true {
		t.Fatalf("%s", out)
	}
}
