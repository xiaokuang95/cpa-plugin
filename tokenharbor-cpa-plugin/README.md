# tokenharbor CPA plugin

TokenHarbor (`https://tokenharbor.ai`) for CliProxyAPI.

Auth: `thk_live_` API key. Chat: `POST /v1/chat/completions`. 面板额度走 `GET /api/me/free-tier`。

```bash
make test
make build   # tokenharbor.so
```

103 上 Debian 现编。config:

```yaml
plugins:
  configs:
    tokenharbor:
      enabled: true
```
