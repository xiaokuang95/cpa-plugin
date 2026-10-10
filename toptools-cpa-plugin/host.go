package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	httpClientOnce sync.Once
	sharedClient   *http.Client
)

func sharedHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		sharedClient = &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 5,
			},
		}
	})
	return sharedClient
}

type hostHTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type rpcHostHTTPRequestWire struct {
	HostCallbackID string            `json:"host_callback_id,omitempty"`
	Request        *rpcHostHTTPInner `json:"request,omitempty"`
}

type rpcHostHTTPInner struct {
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    []byte              `json:"body,omitempty"`
}

type rpcHostHTTPBufferedResponseWire struct {
	StatusCodeSnake  int                 `json:"status_code"`
	StatusCodePascal int                 `json:"StatusCode"`
	Headers          map[string][]string `json:"headers,omitempty"`
	Body             []byte              `json:"body,omitempty"`
}

type rpcHostHTTPStreamResponseWire struct {
	StatusCode int                         `json:"status_code"`
	Headers    map[string][]string         `json:"headers,omitempty"`
	StreamID   string                      `json:"stream_id,omitempty"`
	Chunks     []pluginapi.HTTPStreamChunk `json:"chunks,omitempty"`
}

type rpcHostHTTPStreamReadResponseWire struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

func hostBridgeAvailable() bool {
	return hostAPI != nil && hostAPI.call != nil
}

func hostBridgeUnwrap(raw []byte, method string) (json.RawMessage, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: decode envelope: %w", method, err)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: host error %s: %s", method, env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("%s: host returned not-ok", method)
	}
	return env.Result, nil
}

func decodeBufferedHostHTTPResponse(result []byte) (*hostHTTPResponse, error) {
	var wire rpcHostHTTPBufferedResponseWire
	if err := json.Unmarshal(result, &wire); err != nil {
		return nil, fmt.Errorf("decode host.http.do response: %w", err)
	}
	statusCode := wire.StatusCodeSnake
	if statusCode == 0 {
		statusCode = wire.StatusCodePascal
	}
	return &hostHTTPResponse{
		StatusCode: statusCode,
		Headers:    http.Header(wire.Headers),
		Body:       wire.Body,
	}, nil
}

func hostHTTPDo(req *http.Request) (*hostHTTPResponse, error) {
	return hostHTTPDoWithCallback(req, "")
}

func hostHTTPDoWithCallback(req *http.Request, callbackID string) (*hostHTTPResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		_ = req.Body.Close()
		bodyBytes = b
	}
	if !hostBridgeAvailable() || runtime.GOOS == "windows" {
		return hostHTTPDoDirect(req, bodyBytes)
	}
	wire := rpcHostHTTPRequestWire{
		HostCallbackID: strings.TrimSpace(callbackID),
		Request: &rpcHostHTTPInner{
			Method:  req.Method,
			URL:     req.URL.String(),
			Headers: map[string][]string(req.Header),
			Body:    bodyBytes,
		},
	}
	raw, err := hostCall(pluginabi.MethodHostHTTPDo, mustJSON(wire))
	if err != nil {
		return nil, fmt.Errorf("host.http.do: %w", err)
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPDo)
	if err != nil {
		return nil, err
	}
	return decodeBufferedHostHTTPResponse(result)
}

func hostHTTPDoDirect(req *http.Request, bodyBytes []byte) (*hostHTTPResponse, error) {
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header.Clone()
	resp, err := sharedHTTPClient().Do(newReq)
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

type hostHTTPStream struct {
	streamID  string
	direct    io.ReadCloser
	directErr error
}

func hostHTTPDoStreamWithCallback(req *http.Request, callbackID string) (*hostHTTPStream, int, http.Header, error) {
	if req == nil {
		return nil, 0, nil, fmt.Errorf("nil request")
	}
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("read request body: %w", err)
		}
		_ = req.Body.Close()
		bodyBytes = b
	}
	if !hostBridgeAvailable() {
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, 0, nil, err
		}
		newReq.Header = req.Header.Clone()
		resp, err := sharedHTTPClient().Do(newReq)
		if err != nil {
			return nil, 0, nil, err
		}
		return &hostHTTPStream{direct: resp.Body}, resp.StatusCode, resp.Header.Clone(), nil
	}
	wire := rpcHostHTTPRequestWire{
		HostCallbackID: strings.TrimSpace(callbackID),
		Request: &rpcHostHTTPInner{
			Method:  req.Method,
			URL:     req.URL.String(),
			Headers: map[string][]string(req.Header),
			Body:    bodyBytes,
		},
	}
	raw, err := hostCall(pluginabi.MethodHostHTTPDoStream, mustJSON(wire))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("host.http.do_stream: %w", err)
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPDoStream)
	if err != nil {
		return nil, 0, nil, err
	}
	var resp rpcHostHTTPStreamResponseWire
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, 0, nil, fmt.Errorf("decode host.http.do_stream response: %w", err)
	}
	if resp.StreamID == "" {
		return nil, resp.StatusCode, http.Header(resp.Headers), fmt.Errorf("host stream bridge unavailable")
	}
	return &hostHTTPStream{streamID: resp.StreamID}, resp.StatusCode, http.Header(resp.Headers), nil
}

func (s *hostHTTPStream) Read() ([]byte, bool, error) {
	if s == nil {
		return nil, true, fmt.Errorf("stream closed")
	}
	if s.direct != nil {
		if s.directErr != nil {
			err := s.directErr
			s.directErr = nil
			return nil, true, err
		}
		buf := make([]byte, 32*1024)
		n, err := s.direct.Read(buf)
		if n > 0 {
			if err == io.EOF {
				return buf[:n], true, nil
			}
			if err != nil {
				s.directErr = err
			}
			return buf[:n], false, nil
		}
		if err == io.EOF {
			return nil, true, nil
		}
		if err != nil {
			return nil, true, err
		}
		return nil, false, nil
	}
	if s.streamID == "" {
		return nil, true, fmt.Errorf("stream closed")
	}
	raw, err := hostCall(pluginabi.MethodHostHTTPStreamRead, mustJSON(map[string]any{"stream_id": s.streamID}))
	if err != nil {
		return nil, true, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostHTTPStreamRead)
	if err != nil {
		return nil, true, err
	}
	var resp rpcHostHTTPStreamReadResponseWire
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, true, fmt.Errorf("decode host.http.stream_read response: %w", err)
	}
	if resp.Error != "" {
		return nil, true, fmt.Errorf("%s", resp.Error)
	}
	return resp.Payload, resp.Done, nil
}

func (s *hostHTTPStream) Close() {
	if s == nil {
		return
	}
	if s.direct != nil {
		_ = s.direct.Close()
		s.direct = nil
		return
	}
	if s.streamID == "" {
		return
	}
	_, _ = hostCall(pluginabi.MethodHostHTTPStreamClose, mustJSON(map[string]any{"stream_id": s.streamID}))
	s.streamID = ""
}

type hostStreamReader struct {
	s    *hostHTTPStream
	buf  []byte
	done bool
	err  error
}

func newHostStreamReader(s *hostHTTPStream) *hostStreamReader {
	return &hostStreamReader{s: s}
}

func (r *hostStreamReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	if r.done {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	chunk, done, err := r.s.Read()
	if err != nil {
		r.done = true
		r.err = err
		return 0, err
	}
	if len(chunk) > 0 {
		n := copy(p, chunk)
		if n < len(chunk) {
			r.buf = append(r.buf[:0], chunk[n:]...)
		}
		if done {
			r.done = true
		}
		return n, nil
	}
	if done {
		r.done = true
		return 0, io.EOF
	}
	return r.Read(p)
}

func streamEmit(streamID string, payload []byte) error {
	if streamID == "" {
		return fmt.Errorf("no stream id")
	}
	_, err := hostCall(pluginabi.MethodHostStreamEmit, mustJSON(map[string]any{"stream_id": streamID, "payload": payload}))
	return err
}

func streamEmitError(streamID, message string) {
	if streamID == "" {
		return
	}
	_, _ = hostCall(pluginabi.MethodHostStreamEmit, mustJSON(map[string]any{"stream_id": streamID, "error": message}))
}

func streamClose(streamID string) {
	if streamID == "" {
		return
	}
	_, _ = hostCall(pluginabi.MethodHostStreamClose, mustJSON(map[string]any{"stream_id": streamID}))
}

func hostAuthList() ([]pluginapi.HostAuthFileEntry, error) {
	raw, err := hostCall(pluginabi.MethodHostAuthList, nil)
	if err != nil {
		return nil, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostAuthList)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, err
	}
	out := make([]pluginapi.HostAuthFileEntry, 0, len(resp.Files))
	for _, f := range resp.Files {
		name := strings.ToLower(strings.TrimSpace(f.Name))
		if name == authFileName || strings.HasPrefix(name, providerName+"-") || strings.EqualFold(f.Type, providerName) || strings.EqualFold(f.Provider, providerName) {
			out = append(out, f)
		}
	}
	return out, nil
}

func hostAuthGetJSON(authIndex string) ([]byte, error) {
	_, raw, err := hostAuthGet(authIndex)
	return raw, err
}

func hostAuthGet(authIndex string) (string, []byte, error) {
	raw, err := hostCall(pluginabi.MethodHostAuthGet, mustJSON(map[string]string{"auth_index": authIndex}))
	if err != nil {
		return "", nil, err
	}
	result, err := hostBridgeUnwrap(raw, pluginabi.MethodHostAuthGet)
	if err != nil {
		return "", nil, err
	}
	var resp struct {
		Name string          `json:"name"`
		JSON json.RawMessage `json:"json"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return "", nil, err
	}
	return resp.Name, resp.JSON, nil
}

func hostAuthSaveJSON(name string, raw []byte) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty auth file name")
	}
	body, err := json.Marshal(pluginapi.HostAuthSaveRequest{Name: name, JSON: raw})
	if err != nil {
		return err
	}
	resp, err := hostCall(pluginabi.MethodHostAuthSave, body)
	if err != nil {
		return fmt.Errorf("host.auth.save: %w", err)
	}
	if _, err := hostBridgeUnwrap(resp, pluginabi.MethodHostAuthSave); err != nil {
		return err
	}
	return nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func postJSON(url string, headers map[string]string, body any, callbackID string) (*hostHTTPResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return hostHTTPDoWithCallback(req, callbackID)
}

func getJSON(url string, headers map[string]string, callbackID string) (*hostHTTPResponse, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return hostHTTPDoWithCallback(req, callbackID)
}
