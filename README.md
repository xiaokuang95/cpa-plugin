# cpa-plugin

CLIProxyAPI plugins:

| directory | site |
|---|---|
| `alysis-cpa-plugin` | https://alysiscode.com |
| `tokenharbor-cpa-plugin` | https://tokenharbor.ai |
| `toptools-cpa-plugin` | https://top-tools-ai.com |

Build on the CPA host (Debian), not macOS:

```bash
cd alysis-cpa-plugin && make build
```

Drop the `.so` into CPA `plugins/` and enable `plugins.configs.<id>.enabled`.
