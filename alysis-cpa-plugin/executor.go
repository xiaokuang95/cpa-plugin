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
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
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
	model := canonicalModel(req.Model)
	up := protocolForModel(model)
	inFmt := normalizeFormat(firstNonEmpty(req.SourceFormat, "openai"))
	emitFmt := normalizeFormat(firstNonEmpty(req.Format, req.SourceFormat, "openai"))
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body = prepareUpstreamBody(body, inFmt, up.Format, model, false)

	httpReq, err := http.NewRequest(http.MethodPost, gatewayBase+up.Path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyUpstreamHeaders(httpReq, sa, up.Format)
	resp, err := hostHTTPDoWithCallback(httpReq, req.HostCallbackID)
	if err != nil {
		return nil, fmt.Errorf("http_error: %w", err)
	}
	if resp.StatusCode >= 400 {
		go reconcileAuth(req.AuthID, sa, req.HostCallbackID, true)
		return errorEnvelopeWithStatus("http_error", fmt.Sprintf("upstream %d: %s", resp.StatusCode, truncate(string(resp.Body), 300)), resp.StatusCode), nil
	}
	out := convertResponse(up.Format, emitFmt, model, body, resp.Body)
	go reconcileAuth(req.AuthID, sa, req.HostCallbackID, true)
	return okEnvelope(pluginapi.ExecutorResponse{Payload: out})
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
	model := canonicalModel(req.Model)
	up := protocolForModel(model)
	inFmt := normalizeFormat(firstNonEmpty(req.SourceFormat, "openai"))
	emitFmt := normalizeFormat(firstNonEmpty(req.Format, req.SourceFormat, "openai"))
	body := req.Payload
	if len(body) == 0 {
		body = req.OriginalRequest
	}
	body = prepareUpstreamBody(body, inFmt, up.Format, model, true)
	headers := streamHeaders()

	httpReq, err := http.NewRequest(http.MethodPost, gatewayBase+up.Path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyUpstreamHeaders(httpReq, sa, up.Format)

	if req.StreamID == "" {
		stream, status, _, err := hostHTTPDoStreamWithCallback(httpReq, req.HostCallbackID)
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		if status >= 400 {
			payload, _ := io.ReadAll(newHostStreamReader(stream))
			go reconcileAuth(req.AuthID, sa, req.HostCallbackID, true)
			return errorEnvelopeWithStatus("http_error", fmt.Sprintf("upstream %d: %s", status, truncate(string(payload), 300)), status), nil
		}
		chunks, err := collectConvertedStream(newHostStreamReader(stream), up.Format, emitFmt, model, body)
		go reconcileAuth(req.AuthID, sa, req.HostCallbackID, true)
		if err != nil {
			return nil, err
		}
		return okEnvelope(streamResponse{Headers: headers, Chunks: chunks})
	}

	ctx, cancel := context.WithCancel(context.Background())
	httpReq = httpReq.WithContext(ctx)
	go func() {
		pumpConvertedStream(httpReq, cancel, req.StreamID, up.Format, emitFmt, model, body, req.HostCallbackID)
		reconcileAuth(req.AuthID, sa, req.HostCallbackID, true)
	}()
	return okEnvelope(streamResponse{Headers: headers})
}

func streamHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	return h
}

func applyUpstreamHeaders(req *http.Request, sa *storedAuth, upFmt sdktranslator.Format) {
	// 对齐 alysis-code LLM 客户端：UA + identity，不带 Go/httpx 默认头。
	req.Header.Set("Authorization", "Bearer "+sa.Auth.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", alysisCodeUA)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Del("Accept")
	if upFmt == sdktranslator.FormatClaude {
		req.Header.Set("anthropic-version", anthropicVersion)
	}
}

func prepareUpstreamBody(body []byte, from, to sdktranslator.Format, model string, stream bool) []byte {
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	if from != to {
		if sdktranslator.HasRequestTransformer(from, to) {
			body = sdktranslator.TranslateRequest(from, to, model, body, stream)
		} else if from == sdktranslator.FormatOpenAI && to == sdktranslator.FormatOpenAIResponse {
			body = chatToResponses(body, model, stream)
		} else if from == sdktranslator.FormatOpenAIResponse && to == sdktranslator.FormatOpenAI {
			body = responsesToChatRequest(body, model, stream)
		}
	}
	return rewriteJSONModelStream(body, model, stream)
}

func convertResponse(from, to sdktranslator.Format, model string, reqBody, respBody []byte) []byte {
	if from == to || len(respBody) == 0 {
		return respBody
	}
	var param any
	out := sdktranslator.TranslateNonStream(context.Background(), from, to, model, reqBody, reqBody, respBody, &param)
	if from == sdktranslator.FormatOpenAIResponse && to == sdktranslator.FormatOpenAI {
		if bytes.Equal(out, respBody) || !bytes.Contains(out, []byte(`"chat.completion"`)) {
			return responsesToChatCompletion(respBody, model)
		}
	}
	return out
}

func rewriteJSONModelStream(body []byte, model string, stream bool) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if model != "" {
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

func chatToResponses(body []byte, model string, stream bool) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if _, ok := m["input"]; !ok {
		m["input"] = m["messages"]
	}
	delete(m, "messages")
	if v, ok := m["max_tokens"]; ok {
		m["max_output_tokens"] = v
		delete(m, "max_tokens")
	}
	if model != "" {
		m["model"] = model
	}
	if stream {
		m["stream"] = true
	}
	out, _ := json.Marshal(m)
	return out
}

func responsesToChatRequest(body []byte, model string, stream bool) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if _, ok := m["messages"]; !ok {
		m["messages"] = m["input"]
	}
	delete(m, "input")
	if v, ok := m["max_output_tokens"]; ok {
		m["max_tokens"] = v
		delete(m, "max_output_tokens")
	}
	if model != "" {
		m["model"] = model
	}
	if stream {
		m["stream"] = true
	}
	out, _ := json.Marshal(m)
	return out
}

func responsesToChatCompletion(body []byte, model string) []byte {
	if bytes.Contains(body, []byte(`"chat.completion"`)) {
		return body
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body
	}
	text := extractResponsesText(root)
	id, _ := root["id"].(string)
	usage := map[string]any{}
	if u, ok := root["usage"].(map[string]any); ok {
		in, _ := asInt(u["input_tokens"])
		out, _ := asInt(u["output_tokens"])
		usage = map[string]any{
			"prompt_tokens":     in,
			"completion_tokens": out,
			"total_tokens":      in + out,
		}
	}
	out, _ := json.Marshal(map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
		"usage":   usage,
	})
	return out
}

func extractResponsesText(root map[string]any) string {
	var b strings.Builder
	var rec func(any)
	rec = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if typ, _ := t["type"].(string); typ == "output_text" {
				if s, ok := t["text"].(string); ok {
					b.WriteString(s)
				}
			}
			for _, x := range t {
				rec(x)
			}
		case []any:
			for _, x := range t {
				rec(x)
			}
		}
	}
	rec(root["output"])
	if b.Len() == 0 {
		if s, ok := root["output_text"].(string); ok {
			return s
		}
	}
	return b.String()
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func pumpConvertedStream(httpReq *http.Request, cancel context.CancelFunc, streamID string, from, to sdktranslator.Format, model string, reqBody []byte, callbackID string) {
	defer cancel()
	defer streamClose(streamID)
	stream, status, _, err := hostHTTPDoStreamWithCallback(httpReq, callbackID)
	if err != nil {
		streamEmitError(streamID, err.Error())
		return
	}
	defer stream.Close()
	if status >= 400 {
		payload, _ := io.ReadAll(newHostStreamReader(stream))
		streamEmitError(streamID, fmt.Sprintf("upstream %d: %s", status, truncate(string(payload), 300)))
		return
	}
	if err := emitConvertedSSE(newHostStreamReader(stream), streamID, from, to, model, reqBody); err != nil {
		streamEmitError(streamID, err.Error())
	}
}

func collectConvertedStream(r io.Reader, from, to sdktranslator.Format, model string, reqBody []byte) ([]pluginapi.ExecutorStreamChunk, error) {
	var chunks []pluginapi.ExecutorStreamChunk
	var param any
	err := scanSSE(r, func(data []byte) error {
		for _, frame := range convertStreamFrame(from, to, model, reqBody, data, &param) {
			chunks = append(chunks, pluginapi.ExecutorStreamChunk{Payload: frame})
		}
		return nil
	})
	return chunks, err
}

func emitConvertedSSE(r io.Reader, streamID string, from, to sdktranslator.Format, model string, reqBody []byte) error {
	var param any
	return scanSSE(r, func(data []byte) error {
		for _, frame := range convertStreamFrame(from, to, model, reqBody, data, &param) {
			if err := streamEmit(streamID, frame); err != nil {
				return err
			}
		}
		return nil
	})
}

func scanSSE(r io.Reader, fn func([]byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) && !bytes.HasPrefix(line, []byte("data: ")) {
			// Anthropic also sends `event:` lines; skip, data carries type.
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if err := fn(payload); err != nil {
			return err
		}
	}
	return sc.Err()
}

func convertStreamFrame(from, to sdktranslator.Format, model string, reqBody, data []byte, param *any) [][]byte {
	if bytes.Equal(data, []byte("[DONE]")) {
		if to == sdktranslator.FormatOpenAI {
			return [][]byte{[]byte("data: [DONE]\n\n")}
		}
		return nil
	}
	if from == to {
		return [][]byte{sseFrame(data)}
	}
	if from == sdktranslator.FormatOpenAIResponse && to == sdktranslator.FormatOpenAI {
		if frame, ok := responsesDeltaToChat(data, model); ok {
			return [][]byte{frame}
		}
		return nil
	}
	raw := data
	if !bytes.HasPrefix(raw, []byte("data:")) {
		raw = append([]byte("data: "), data...)
	}
	frames := sdktranslator.TranslateStream(context.Background(), from, to, model, reqBody, reqBody, raw, param)
	if len(frames) == 1 && bytes.Equal(frames[0], raw) {
		return [][]byte{sseFrame(data)}
	}
	out := make([][]byte, 0, len(frames))
	for _, f := range frames {
		if len(f) == 0 {
			continue
		}
		out = append(out, sseFrame(f))
	}
	return out
}

func sseFrame(data []byte) []byte {
	data = bytes.TrimSpace(data)
	if bytes.HasPrefix(data, []byte("data:")) {
		if !bytes.HasSuffix(data, []byte("\n")) {
			return append(data, '\n', '\n')
		}
		return data
	}
	buf := make([]byte, 0, 6+len(data)+2)
	buf = append(buf, "data: "...)
	buf = append(buf, data...)
	buf = append(buf, '\n', '\n')
	return buf
}

func responsesDeltaToChat(data []byte, model string) ([]byte, bool) {
	var ev map[string]any
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, false
	}
	typ, _ := ev["type"].(string)
	switch typ {
	case "response.output_text.delta":
		delta, _ := ev["delta"].(string)
		if delta == "" {
			return nil, false
		}
		chunk, _ := json.Marshal(map[string]any{
			"id":      ev["item_id"],
			"object":  "chat.completion.chunk",
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": delta}, "finish_reason": nil}},
		})
		return sseFrame(chunk), true
	case "response.completed", "response.done":
		chunk, _ := json.Marshal(map[string]any{
			"id":      ev["item_id"],
			"object":  "chat.completion.chunk",
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
		})
		return bytes.Join([][]byte{sseFrame(chunk), []byte("data: [DONE]\n\n")}, nil), true
	default:
		return nil, false
	}
}
