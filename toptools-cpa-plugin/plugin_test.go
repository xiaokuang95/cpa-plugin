package main

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestParseStored(t *testing.T) {
	sa, err := parseStored([]byte(`{"auth":{"accessToken":"sk-abc"},"account":{"uid":"u1"}}`))
	if err != nil || sa.Auth.AccessToken != "sk-abc" {
		t.Fatalf("nested %#v %v", sa, err)
	}
	sa, err = parseStored([]byte(`{"key":"sk-flat"}`))
	if err != nil || sa.Auth.AccessToken != "sk-flat" {
		t.Fatalf("key %#v %v", sa, err)
	}
	sa, err = parseStored([]byte(" sk-raw "))
	if err != nil || sa.Auth.AccessToken != "sk-raw" {
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
		FileName: "toptools-u1.json",
		RawJSON:  []byte(`{"key":"sk-abcdef1234567890"}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	_ = json.Unmarshal(body, &env)
	var resp pluginapi.AuthParseResponse
	_ = json.Unmarshal(env.Result, &resp)
	if !resp.Handled || resp.Auth.ID != "" || resp.Auth.FileName != "toptools-u1.json" {
		t.Fatalf("%#v", resp)
	}
}

func TestParseClerkSession(t *testing.T) {
	sa, err := parseStored([]byte(`{"key":"sk-abc","jwt":"eyJ","sessionId":"sess_1","clientToken":"eyJclient"}`))
	if err != nil || sa.Auth.SessionAccess != "eyJ" || sa.Auth.SessionID != "sess_1" || sa.Auth.ClientToken != "eyJclient" {
		t.Fatalf("%#v %v", sa, err)
	}
}

func TestCooldownFromPlan(t *testing.T) {
	cool, why := cooldownFromPlan(planView{DailyLimit: 10_000_000, DailyRemaining: 0})
	if !cool || why != "daily cap" {
		t.Fatalf("%v %s", cool, why)
	}
	if cool, _ := cooldownFromPlan(planView{DailyLimit: 10_000_000, DailyRemaining: 1}); cool {
		t.Fatal("still cooling with remaining")
	}
	if cool, _ := cooldownFromPlan(planView{DailyLimit: 10_000_000, DailyRemaining: 0, BalanceCents: 100}); cool {
		t.Fatal("PAYG should skip cooldown")
	}
}

func TestRewriteModel(t *testing.T) {
	out := rewriteModel([]byte(`{"messages":[]}`), "GLM-5.3-Flash", true)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != "GLM-5.3-Flash" || m["stream"] != true {
		t.Fatalf("%s", out)
	}
}
