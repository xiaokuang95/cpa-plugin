# toptools CPA plugin

Top Tools AI (`https://top-tools-ai.com`) for CliProxyAPI.

Auth: `sk-` API key. Chat: `POST /v1/chat/completions`. CPA 转协议。余额在网站 Dashboard（Clerk JWT，key 查不到）。

```bash
make build   # toptools.so
```

103 上 Debian 现编。config:

```yaml
plugins:
  configs:
    toptools:
      enabled: true
```
