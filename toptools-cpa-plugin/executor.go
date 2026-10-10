package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type executorRequestWire struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type streamResponse struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

func handleExecExecute(raw []byte) ([]byte, error) {
	var req executorRequestWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body = rewriteModel(body, req.Model, false)
	httpReq, err := http.NewRequest(http.MethodPost, gatewayBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+sa.Auth.AccessToken)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := hostHTTPDoWithCallback(httpReq, req.HostCallbackID)
	if err != nil {
		return nil, fmt.Errorf("http_error: %w", err)
	}
	if resp.StatusCode >= 400 {
		go reconcileAuth(req.AuthID, sa, req.HostCallbackID)
		return errorEnvelopeWithStatus("http_error", fmt.Sprintf("upstream %d: %s", resp.StatusCode, truncate(string(resp.Body), 300)), resp.StatusCode), nil
	}
	go reconcileAuth(req.AuthID, sa, req.HostCallbackID)
	return okEnvelope(pluginapi.ExecutorResponse{Payload: resp.Body})
}

func handleExecStream(raw []byte) ([]byte, error) {
	var req executorRequestWire
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body = rewriteModel(body, req.Model, true)
	headers := http.Header{}
	headers.Set("Content-Type", "text/event-stream")
	headers.Set("Cache-Control", "no-cache")

	httpReq, err := http.NewRequest(http.MethodPost, gatewayBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+sa.Auth.AccessToken)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	if req.StreamID == "" {
		stream, status, _, err := hostHTTPDoStreamWithCallback(httpReq, req.HostCallbackID)
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		if status >= 400 {
			payload, _ := io.ReadAll(newHostStreamReader(stream))
			go reconcileAuth(req.AuthID, sa, req.HostCallbackID)
			return errorEnvelopeWithStatus("http_error", fmt.Sprintf("upstream %d: %s", status, truncate(string(payload), 300)), status), nil
		}
		payload, _ := io.ReadAll(newHostStreamReader(stream))
		go reconcileAuth(req.AuthID, sa, req.HostCallbackID)
		return okEnvelope(streamResponse{Headers: headers, Chunks: []pluginapi.ExecutorStreamChunk{{Payload: payload}}})
	}

	ctx, cancel := context.WithCancel(context.Background())
	httpReq = httpReq.WithContext(ctx)
	go pumpStream(httpReq, cancel, req.StreamID, req.HostCallbackID, req.AuthID, sa)
	return okEnvelope(streamResponse{Headers: headers})
}

func pumpStream(httpReq *http.Request, cancel context.CancelFunc, streamID, callbackID, authID string, sa *storedAuth) {
	defer cancel()
	defer streamClose(streamID)
	stream, status, _, err := hostHTTPDoStreamWithCallback(httpReq, callbackID)
	if err != nil {
		streamEmitError(streamID, err.Error())
		return
	}
	defer stream.Close()
	defer reconcileAuth(authID, sa, callbackID)
	if status >= 400 {
		payload, _ := io.ReadAll(newHostStreamReader(stream))
		streamEmitError(streamID, fmt.Sprintf("upstream %d: %s", status, truncate(string(payload), 300)))
		return
	}
	sc := bufio.NewScanner(newHostStreamReader(stream))
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		frame := append(append([]byte(nil), line...), '\n')
		if err := streamEmit(streamID, frame); err != nil {
			return
		}
	}
}

func rewriteModel(body []byte, model string, stream bool) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if strings.TrimSpace(model) != "" {
		m["model"] = model
	}
	if stream {
		m["stream"] = true
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}
