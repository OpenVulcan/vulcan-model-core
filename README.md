# Vulcan Model Core

Vulcan Model Core is the provider-scoped execution core for the OpenVulcan toolchain.
It exposes only Vulcan-owned APIs and translates them to provider-native protocols.

## Design principles

- A request selects exactly one provider before execution starts.
- Failover may rotate plans, endpoints, regions, and credentials only within that provider.
- The core never performs automatic cross-provider model fusion or fallback.
- Provider protocols are internal adapter details and are never public client APIs.
- CLIProxyAPI is a behavioral reference for authentication, cooldown, retry, streaming, and error cases; it is not a runtime dependency.
- SQLite is the only concrete infrastructure dependency and uses a CGO-free driver through `database/sql`.

## Current milestone

The current core implements the first provider-scoped unified capability milestone. It establishes:

- an immutable provider-scoped execution target;
- a thread-safe provider adapter registry;
- a router that cannot accept cross-provider candidates;
- immutable protocol metadata and trusted system-provider registries;
- persisted custom-provider definitions constrained to user-configurable runtime-ready protocols;
- provider instances, endpoints, multi-credential metadata, secret references, and access bindings;
- provider models, channel offerings, selectable execution profiles, account entitlements, plans, arbitrary allowance shapes, and pool summaries;
- atomic provider catalogs and a same-instance target resolver that enforces profile, entitlement, context, allowance, binding, and health boundaries;
- replaceable repository interfaces with thread-safe in-memory and durable SQLite implementations;
- transactional schema migrations with WAL, foreign keys, and busy timeout configuration;
- a Windows DPAPI-protected local `SecretStore` with metadata-write compensation;
- configuration application services for custom definitions, instances, endpoints, credentials, bindings, activation, credential state, and user-declared custom model catalogs;
- trusted provider metadata refresh coordination and derived account-pool summaries;
- client-safe VulcanCode discovery DTOs that omit secret references and upstream account identifiers;
- separate authenticated local management and call-plane HTTP namespaces with independent bearer keys;
- a React + Vite local management page that keeps its management key in browser memory only;
- graceful process shutdown;
- tests that keep legacy protocol endpoints absent.
- typed conversation, media analysis, image, video, non-realtime speech, music, Embedding, Rerank, and Web Search operations;
- Router-owned resources, deterministic input plans, synchronous/streaming/asynchronous execution, event replay, idempotency, polling, cancellation, and restart recovery;
- code-owned provider action bindings for OpenAI, Anthropic, Google, xAI, Alibaba Model Studio, OpenRouter, MiniMax, and Tavily where current evidence exists;
- protected-at-rest provider task IDs, prepared-workflow handles, provider asset handles, and credentials;
- separate model and special-service discovery with exact provider-instance ownership and runtime availability.

The service is expected to report `503` from `/readyz` until a production provider adapter is registered.

## HTTP surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `HEAD` | `/healthz` | Process liveness |
| `GET`, `HEAD` | `/readyz` | Provider execution readiness |
| `GET` | `/vulcan/meta/providers` | Registered provider identifiers |
| `GET`, `POST`, `PUT` | `/vulcan/manage/provider-definitions` and `/vulcan/manage/provider-definitions/{provider_definition_id}` | Management-only custom provider definitions; system definitions remain immutable |
| `GET` | `/vulcan/manage/protocol-profiles` | Management-only custom-provider protocol choices |
| `GET`, `POST`, `PUT` | `/vulcan/manage/provider-instances/...` | Management-only instances, endpoints, credentials, bindings, activation, and local model enablement |
| `GET`, `PUT` | `/vulcan/manage/provider-instances/{provider_instance_id}/custom-catalog` | Management-only complete user-declared model catalog for a custom provider instance; system provider catalogs remain read-only |
| `GET`, `POST`, `PUT`, `DELETE` | `/vulcan/manage/api-keys/...` | Management-only plaintext call-plane API key lifecycle |
| `GET` | `/vulcan/v1/models` | Call-plane provider-scoped enabled models and capabilities |
| `GET` | `/vulcan/v1/services` | Call-plane provider-scoped special services, including unified `search.web` offerings |
| `POST`, `GET`, `DELETE` | `/vulcan/v1/resources...` | Call-plane resource upload/import, safe metadata, content retrieval, and deletion |
| `POST` | `/vulcan/v1/input-plans` | Resolve and freeze one deterministic media materialization plan |
| `POST`, `GET` | `/vulcan/v1/executions...` | Create, inspect, cancel, and replay typed execution events |
| `GET` | `/vulcan/manage/diagnostics/resources` | Management-only metadata-safe resource diagnostics |
| `GET` | `/vulcan/manage/diagnostics/executions` | Management-only content-free execution diagnostics |

Claude Messages, OpenAI Chat Completions, OpenAI Responses compatibility aliases, Gemini GenerateContent, and Codex client routes are intentionally absent.

Every `/vulcan/manage` request requires `Authorization: Bearer <management-key>`. Every `/vulcan/v1` request requires an enabled call-plane key in the same header. The two key namespaces cannot authorize each other.

## Local control-plane bootstrap

Create the ignored startup configuration before the first start, then replace both placeholders:

```powershell
make config
# Edit .\output\configs\vulcan-model-core.yaml
```

`make config` never overwrites an existing file. The startup YAML is always `output/configs/vulcan-model-core.yaml`; the compiled executable runs from `output/bin/` and resolves that configuration as `../configs/vulcan-model-core.yaml`. The whole `output/` directory is ignored by Git.

`management.secret-key` starts as a plaintext bootstrap value. On the first successful process load it is replaced atomically by a bcrypt hash and is subsequently verified only with bcrypt. `api.keys` deliberately remains plaintext because the management API edits those call-plane keys.

| 位置 | 用途 |
| --- | --- |
| `output/bin/vulcan-model-core.exe` | 每次 `make run` 重新编译的核心程序 |
| `output/configs/vulcan-model-core.yaml` | 启动 YAML 配置 |
| `~/.vulcan/router/database/data.db` | 持久化 SQLite 数据库 |
| `~/.vulcan/router/secrets/` | DPAPI 保护的上游供应商凭据、任务 ID 与准备句柄 |
| `~/.vulcan/router/resources/` | Router 管理的二进制资源对象 |

The process defaults to the loopback-only listener `127.0.0.1:13514`. On Windows, upstream provider secrets are persisted using DPAPI; an unsupported operating system returns an explicit startup error rather than falling back to plaintext.

Start the core through Make after configuring it:

```powershell
make run
```

## Local management page

The management page is an independent React + Vite development service in `web/manage`. It provides the administrator login and management workspace in one application, proxies only `/vulcan/manage` to the core, and is fixed to `127.0.0.1:13520`.

```powershell
make vite start
# ... use http://127.0.0.1:13520 ...
make vite stop
```

`make vite start` installs locked frontend dependencies with `npm ci` only when the package-local Vite entry is missing. It starts Vite as a hidden process and records its PID plus start time in ignored `output/vite-state.json`; `make vite stop` stops only that exact recorded process. The management key remains in memory by default. If the administrator explicitly enables “Remember credential”, the page shows a plaintext-localStorage warning and stores the key only after successful validation; an authentication rejection clears the saved value while a network failure does not.

## Development

```bash
gofmt -w .
go test ./...
cd web/manage && npm test
```

Run with the default local control-plane listener and prescribed local paths:

```bash
make run
```

For an ad-hoc direct process invocation, supply its configuration and persistence paths explicitly:

```bash
go run ./cmd/vulcan-model-core --listen-address 127.0.0.1:8080 --config ./output/configs/vulcan-model-core.yaml --database-path ~/.vulcan/router/database/data.db --secret-directory ~/.vulcan/router/secrets
```

The business database stores only opaque secret references. The in-memory `SecretStore` exists only for tests and explicit ephemeral use; the production local process uses the platform-protected SecretStore described above.

The complete VCP operation examples, discovery flow, resource/input-plan lifecycle, execution states, and safe error contract are documented in [Unified capability execution](docs/architecture/0010-unified-capability-execution.md). The frozen provider evidence and regression mapping are recorded in [Provider capability evidence matrix](docs/evidence/20260720-provider-capability-matrix.md).

## Migration strategy

Provider support will be added one provider at a time. Before implementing an adapter, the relevant CLIProxyAPI behavior will be converted into focused behavioral specifications and regression fixtures. The new implementation will satisfy those requirements without importing the legacy protocol-conversion graph.

See [ADR 0001](docs/architecture/0001-independent-vulcan-core.md) for the architectural boundary.
The accepted provider configuration and model capability structure is documented in
[ADR 0002](docs/architecture/0002-provider-domain-architecture.md).
SQLite persistence, secret isolation, and management query boundaries are documented in
[ADR 0003](docs/architecture/0003-sqlite-secret-management-boundary.md).
