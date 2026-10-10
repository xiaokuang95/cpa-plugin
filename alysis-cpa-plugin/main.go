// Package main is the Alysis CPA plugin (c-shared).
//
// Device-code login yields a long-lived slk_ gateway key. Chat is forwarded
// to the Alysis LLM gateway; CPA translates client protocols, and this plugin
// maps each model onto the gateway path it actually speaks.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

static int alysis_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}
static void alysis_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	providerName  = "alysis"
	authFileName  = "alysis.json"
	pluginLogoURL = "https://alysiscode.com/favicon.ico"

	supabaseURL = "https://vzigujbcjjmpntxhmyvr.supabase.co"
	siteURL     = "https://alysiscode.com"
	anonKey     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZ6aWd1amJjamptcG50eGhteXZyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA5Mzc0NTIsImV4cCI6MjA5NjUxMzQ1Mn0." +
		"vLH9q-BNO8IWIZrVlvCw8pZWXdLgmKG4Tl9toTTD3pg"
	gatewayBase = supabaseURL + "/functions/v1/llm/v1"
	fnBase      = supabaseURL + "/functions/v1"
	AUTH        = supabaseURL + "/auth/v1"

	anthropicVersion = "2023-06-01"
	loginTTL         = 15 * time.Minute
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "0.1.0"

type storedAuth struct {
	Auth    storedTokens  `json:"auth"`
	Account storedAccount `json:"account"`
}

type storedTokens struct {
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	ExpiresAt        int64  `json:"expiresAt"`
	Domain           string `json:"domain"`
	SessionRefresh   string `json:"sessionRefresh,omitempty"`
	SessionAccess    string `json:"sessionAccess,omitempty"`
	SessionExpiresAt int64  `json:"sessionExpiresAt,omitempty"`
}

type storedAccount struct {
	UID      string `json:"uid"`
	Nickname string `json:"nickname"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

type loginCtx struct {
	deviceCode string
	userCode   string
	expires    time.Time
}

var (
	hostAPI     *C.cliproxy_host_api
	loginStates sync.Map
)

func init() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			loginStates.Range(func(key, value any) bool {
				if lc, ok := value.(*loginCtx); ok && now.After(lc.expires) {
					loginStates.Delete(key)
				}
				return true
			})
		}
	}()
	go func() {
		t := time.NewTicker(3 * time.Minute)
		defer t.Stop()
		for range t.C {
			reconcileAll()
		}
	}()
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	hostAPI = host
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	// Host calls this on its own exit path then dlclose()s. Touching Go
	// runtime state here has SIGSEGV'd other plugins.
}

func hostCall(method string, request []byte) ([]byte, error) {
	if hostAPI == nil || hostAPI.call == nil {
		return nil, fmt.Errorf("host API unavailable")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cReq unsafe.Pointer
	var reqLen C.size_t
	if len(request) > 0 {
		cReq = C.CBytes(request)
		defer C.free(cReq)
		reqLen = C.size_t(len(request))
	}
	var resp C.cliproxy_buffer
	rc := C.alysis_call_host(hostAPI, cMethod, (*C.uint8_t)(cReq), reqLen, &resp)
	var out []byte
	if resp.ptr != nil && resp.len > 0 {
		out = C.GoBytes(resp.ptr, C.int(resp.len))
	}
	if resp.ptr != nil && hostAPI.free_buffer != nil {
		C.alysis_free_host_buffer(hostAPI, resp.ptr, resp.len)
	}
	if rc != 0 {
		return out, fmt.Errorf("host call %s returned %d", method, int(rc))
	}
	return out, nil
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodModelStatic:
		return handleModelStatic(request)
	case pluginabi.MethodModelForAuth:
		return handleModelForAuth(request)
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier:
		return okEnvelope(identifierResponse{Identifier: providerName})
	case pluginabi.MethodAuthParse:
		return handleParseAuth(request)
	case pluginabi.MethodAuthLoginStart:
		return handleStartLogin(request)
	case pluginabi.MethodAuthLoginPoll:
		return handlePollLogin(request)
	case pluginabi.MethodAuthRefresh:
		return handleRefreshAuth(request)
	case pluginabi.MethodExecutorExecute:
		return handleExecExecute(request)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecStream(request)
	case pluginabi.MethodExecutorCountTokens:
		return errorEnvelope("unsupported_method", "alysis has no count_tokens API"), nil
	case pluginabi.MethodManagementRegister:
		var regReq pluginapi.ManagementRegistrationRequest
		if err := json.Unmarshal(request, &regReq); err == nil {
			if regReq.BasePath != "" {
				mgmtBase = strings.TrimRight(regReq.BasePath, "/")
			}
			if regReq.ResourceBasePath != "" {
				resBase = strings.TrimRight(regReq.ResourceBasePath, "/")
			}
		}
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
	ManagementAPI         bool                         `json:"management_api"`
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             providerName,
			Version:          version,
			Author:           "alysis-cpa-plugin",
			GitHubRepository: "https://alysiscode.com",
			Logo:             pluginLogoURL,
			ConfigFields: []pluginapi.ConfigField{
				{Name: "client_name", Type: pluginapi.ConfigFieldTypeString, Description: "Device-code client_name (default CLIProxyAPI)."},
			},
		},
		Capabilities: registrationCapability{
			ModelProvider:      true,
			AuthProvider:       true,
			Executor:           true,
			ExecutorModelScope: pluginapi.ExecutorModelScopeOAuth,
			// CPA translates the client protocol into one of these before
			// calling the executor, and translates our output back.
			ExecutorInputFormats:  []string{"chat-completions", "claude", "openai-response"},
			ExecutorOutputFormats: []string{"chat-completions", "claude", "openai-response"},
			ManagementAPI:         true,
		},
	}
}

func parseStored(raw []byte) (*storedAuth, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty auth storage")
	}
	if raw[0] != '{' {
		key := strings.TrimSpace(string(raw))
		if strings.HasPrefix(key, "slk_") {
			return storedFromKey(key, "", ""), nil
		}
		return nil, fmt.Errorf("storage_parse_error: not JSON")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("storage_parse_error: %w", err)
	}
	var sa storedAuth
	if _, nested := probe["auth"]; nested {
		if err := json.Unmarshal(raw, &sa); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
	} else {
		var flat struct {
			AccessToken    string `json:"accessToken"`
			RefreshToken   string `json:"refreshToken"`
			SessionRefresh string `json:"sessionRefresh"`
			ExpiresAt      int64  `json:"expiresAt"`
			Domain         string `json:"domain"`
			Key            string `json:"key"`
			Token          string `json:"token"`
			UID            string `json:"uid"`
			Nickname       string `json:"nickname"`
			Email          string `json:"email"`
			Password       string `json:"password"`
		}
		if err := json.Unmarshal(raw, &flat); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		tok := firstNonEmpty(flat.AccessToken, flat.Key, flat.Token)
		sa.Auth = storedTokens{AccessToken: tok, RefreshToken: flat.RefreshToken, SessionRefresh: flat.SessionRefresh, ExpiresAt: flat.ExpiresAt, Domain: flat.Domain}
		sa.Account = storedAccount{UID: flat.UID, Nickname: flat.Nickname, Email: flat.Email, Password: flat.Password}
	}
	if sa.Auth.AccessToken == "" {
		return nil, fmt.Errorf("parse_error: missing accessToken")
	}
	if sa.Auth.Domain == "" {
		sa.Auth.Domain = gatewayBase
	}
	if sa.Account.UID == "" {
		sa.Account.UID = uidFromKey(sa.Auth.AccessToken)
	}
	return &sa, nil
}

func storedFromKey(key, uid, nick string) *storedAuth {
	key = strings.TrimSpace(key)
	if uid == "" {
		uid = uidFromKey(key)
	}
	if nick == "" {
		nick = uid
	}
	return &storedAuth{
		Auth:    storedTokens{AccessToken: key, Domain: gatewayBase},
		Account: storedAccount{UID: uid, Nickname: nick},
	}
}

func uidFromKey(key string) string {
	k := strings.TrimPrefix(strings.TrimSpace(key), "slk_")
	k = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, k)
	if len(k) > 12 {
		k = k[len(k)-12:]
	}
	if k == "" {
		return "alysis"
	}
	return k
}

func sanitizeUIDForFileName(uid string) string {
	uid = strings.TrimSpace(uid)
	if uid == "" || uid == "." || uid == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range uid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return ""
	}
	return out
}

func authFileNameFor(sa *storedAuth) string {
	if sa != nil {
		if uid := sanitizeUIDForFileName(sa.Account.UID); uid != "" {
			return providerName + "-" + uid + ".json"
		}
	}
	return authFileName
}

func handleParseAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	var probeType struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(req.RawJSON, &probeType)
	declared := strings.ToLower(strings.TrimSpace(probeType.Type))
	if declared != "" && declared != providerName {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	if declared == "" {
		routed := strings.EqualFold(strings.TrimSpace(req.Provider), providerName)
		prefixed := strings.HasPrefix(strings.ToLower(strings.TrimSpace(req.FileName)), providerName+"-")
		legacy := strings.EqualFold(strings.TrimSpace(req.FileName), authFileName)
		if !routed && !prefixed && !legacy {
			return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
		}
	}
	sa, err := parseStored(req.RawJSON)
	if err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	ad := toAuthData(sa)
	ad.ID = ""
	if fn := strings.TrimSpace(req.FileName); fn != "" {
		ad.FileName = fn
	}
	return okEnvelope(pluginapi.AuthParseResponse{Handled: true, Auth: ad})
}

func toAuthData(sa *storedAuth) pluginapi.AuthData {
	storage, _ := json.Marshal(sa)
	fileName := authFileNameFor(sa)
	label := providerName
	if sa != nil {
		if n := strings.TrimSpace(sa.Account.Nickname); n != "" {
			label = n
		} else if sa.Account.UID != "" {
			label = sa.Account.UID
		}
	}
	return pluginapi.AuthData{
		Provider:    providerName,
		FileName:    fileName,
		Label:       label,
		StorageJSON: storage,
		Metadata: map[string]any{
			"type":     providerName,
			"provider": providerName,
			"logo":     pluginLogoURL,
			"note":     "Alysis gateway key (slk_)",
		},
	}
}

func toAuthDataForLoginPoll(sa *storedAuth) pluginapi.AuthData {
	ad := toAuthData(sa)
	ad.ID = ""
	return ad
}

func toAuthDataForRefresh(sa *storedAuth) pluginapi.AuthData {
	ad := toAuthData(sa)
	ad.FileName = ""
	ad.ID = ""
	return ad
}

func buildAuthFileJSON(sa *storedAuth, disabled bool, note string) ([]byte, error) {
	if sa == nil {
		return nil, fmt.Errorf("nil storedAuth")
	}
	out := map[string]any{
		"type":     providerName,
		"provider": providerName,
		"logo":     pluginLogoURL,
		"disabled": disabled,
		"auth":     sa.Auth,
		"account":  sa.Account,
	}
	if note != "" {
		out["note"] = note
	}
	return json.Marshal(out)
}

func parseDisabledFromAuthJSON(raw []byte) bool {
	var d struct {
		Disabled bool `json:"disabled"`
	}
	_ = json.Unmarshal(raw, &d)
	return d.Disabled
}

func parseNoteFromAuthJSON(raw []byte) string {
	var d struct {
		Note string `json:"note"`
	}
	_ = json.Unmarshal(raw, &d)
	return strings.TrimSpace(d.Note)
}

func okEnvelope(v any) ([]byte, error) {
	result, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: result})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func errorEnvelopeWithStatus(code, message string, status int) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func bytesTrimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}
