# Demo run-spec (demo.json) — contract v1

The seamless demo flow is driven by one JSON document. `obs demo up` generates it
from provisioned state; the POC runner consumes it (CLI flags still override).

Path: `~/.config/openbox-sandbox/demo.json` (CONFIG_ROOT/demo.json).

## Schema

```json
{
  "schema_version": 1,
  "service": {
    "config": "/…/.config/openbox-sandbox/service.json",
    "ca": "/…/.config/openbox-sandbox/tls/ca.crt"
  },
  "adapter": {
    "socket": "/…/.local/state/openbox-sandbox/demo/adapter.sock",
    "pid_file": "/…/.local/state/openbox-sandbox/demo/adapter.pid"
  },
  "core_identity": {
    "ca": "/…/.local/state/openbox-sandbox/demo-core-identity/poc-ca.crt",
    "certificate": "/…/.local/state/openbox-sandbox/demo-core-identity/core.crt",
    "private_key": "/…/.local/state/openbox-sandbox/demo-core-identity/core.key"
  },
  "policy_registry": {
    "directory": "/…/.local/state/openbox-sandbox/demo-registry",
    "policy_file": "policy-temporal-activity-worker-dev.yaml",
    "policy_sha256": "<sha256 of the policy file>",
    "fingerprint": "fed07f6a1c5780db7cfc276f1350eaae4df2d7c870424b9e3da8b11aec9c02b8"
  },
  "llm": {
    "api_key_file": "/…/.config/openbox/openai.key",
    "model": "gpt-4o"
  },
  "demo": {
    "repo": "/…/openbox-sandbox-poc-current",
    "evidence_dir": "/…/.local/state/openbox-sandbox/demo",
    "console_otel": true,
    "temporal_cli": "/…/.local/bin/temporal"
  }
}
```

## Semantics

- `schema_version`: 1. Consumers reject unknown versions.
- `service.config`: the sandbox service config (provisioned) — runner `--config`.
- `service.ca`: the service TLS CA (provisioned) — informational for the adapter.
- `adapter.socket`: UDS the SDK agent-server listens on (dispatcher → adapter).
- `core_identity.*`: mock-governance Core identity (POC CA + leaf signed by it). The
  CA carries `keyUsage` (strict OpenSSL 3.5+ consumers); the leaf is the runner's
  `--core-certificate`/`--core-private-material`; `ca` is the runner's `--ca`.
- `policy_registry.directory`: directory holding `policy_file` — the runner's
  `--policy-registry-dir`. `fingerprint` is the constant the adapter validates
  (`sha256("openbox-temporal-constrain-poc-registry-v1")`).
- `llm.api_key_file`: read at run time; when present and non-empty, the runner uses
  the LLM-backed Core (like `OPENAI_API_KEY`). `llm.model` maps to
  `OPENBOX_DEMO_LLM_MODEL` (default `gpt-4o`; e.g. `gpt-5.6-luna`).
- `demo.repo`: the pinned POC checkout used to run the demo (its venv provides the
  SDK `agent_server` adapter and the runner entry point).
- `demo.evidence_dir`: evidence files land here as `evidence-<scenario>-<ts>.json`
  (default scenario filename `evidence.json` stays valid for single runs).
- `demo.console_otel`: when true, the full-proof mode is enabled (worker OTel
  console exporters, trace-join verification, bounded telemetry retention). The
  runner must honor it like `OPENBOX_POC_GOVERNED_OTEL_CONSOLE=1`.
- `demo.temporal_cli`: absolute path to the temporal CLI the dev server should use;
  empty/absent lets the runner fall back to PATH or the SDK download.

## Precedence

Runner: explicit CLI flag > spec value > built-in default.
