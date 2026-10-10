# alysis CPA plugin

CliProxyAPI plugin for [alysiscode.com](https://alysiscode.com).

Device-code login → `slk_` gateway key (does not expire). CPA translates client protocols; this plugin routes each model to the path the gateway actually speaks:

| model | upstream |
|---|---|
| `deepseek-flash` / `glm-5.3-flash` | `/chat/completions` |
| `gpt-6-luna` | `/responses` |
| `claude-haiku-5-5` | `/messages` |

Remaining credits live on https://alysiscode.com/account (session JWT). `slk_` only talks to the LLM gateway. Management: `/v0/management/plugins/alysis/credits|catalog|import` and `/v0/resource/plugins/alysis/panel`.

```bash
make build   # alysis.so
```

Drop `alysis.so` into CPA `plugins/`. Config:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    alysis:
      enabled: true
```

Auth file (or CPA Auth → login):

```json
{"type":"alysis","auth":{"accessToken":"slk_..."},"account":{"uid":"u1"}}
```
