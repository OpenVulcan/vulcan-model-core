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

The current framework intentionally contains no production provider adapter and no incomplete Responses or media schema.
It establishes:

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
- an isolated `SecretStore` contract with metadata-write compensation;
- configuration application services for custom definitions, instances, endpoints, credentials, bindings, activation, credential state, and user-declared custom model catalogs;
- trusted provider metadata refresh coordination and derived account-pool summaries;
- client-safe VulcanCode discovery DTOs that omit secret references and upstream account identifiers;
- liveness, readiness, provider metadata, management, and model catalog endpoints;
- graceful process shutdown;
- tests that keep legacy protocol endpoints absent.

The service is expected to report `503` from `/readyz` until a production provider adapter is registered.

## HTTP surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `HEAD` | `/healthz` | Process liveness |
| `GET`, `HEAD` | `/readyz` | Provider execution readiness |
| `GET` | `/vulcan/meta/providers` | Registered provider identifiers |
| `GET` | `/vulcan/management/provider-definitions` | System and custom provider definitions |
| `GET` | `/vulcan/management/provider-instances` | Provider instance configuration summaries |
| `GET` | `/vulcan/management/provider-instances/{provider_instance_id}` | One provider instance summary |
| `GET` | `/vulcan/catalog/provider-instances/{provider_instance_id}` | Models, profiles, plan aggregates, allowances, and pool summaries |

Claude Messages, OpenAI Chat Completions, OpenAI Responses compatibility aliases, Gemini GenerateContent, and Codex client routes are intentionally absent.

## Development

```bash
gofmt -w .
go test ./...
go build -o test-output ./cmd/vulcan-model-core
```

Run with a random loopback port:

```bash
go run ./cmd/vulcan-model-core
```

Run with an explicit address:

```bash
go run ./cmd/vulcan-model-core --listen-address 127.0.0.1:8080
```

Use an explicit SQLite path:

```bash
go run ./cmd/vulcan-model-core --database-path ./data/vulcan-model-core.db
```

The business database stores only opaque secret references. The current in-memory `SecretStore` exists for tests and explicit ephemeral use; a production encrypted file or operating-system key store is intentionally deferred to a dedicated security design.

## Migration strategy

Provider support will be added one provider at a time. Before implementing an adapter, the relevant CLIProxyAPI behavior will be converted into focused behavioral specifications and regression fixtures. The new implementation will satisfy those requirements without importing the legacy protocol-conversion graph.

See [ADR 0001](docs/architecture/0001-independent-vulcan-core.md) for the architectural boundary.
The accepted provider configuration and model capability structure is documented in
[ADR 0002](docs/architecture/0002-provider-domain-architecture.md).
SQLite persistence, secret isolation, and management query boundaries are documented in
[ADR 0003](docs/architecture/0003-sqlite-secret-management-boundary.md).
