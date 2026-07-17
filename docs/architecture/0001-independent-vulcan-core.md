# ADR 0001: Build an Independent Vulcan-Only Model Core

- Status: Accepted
- Date: 2026-07-17

## Context

The previous router was derived from CLIProxyAPI. Its architecture supports multiple public client protocols, pairwise protocol conversion, provider fusion, model alias rewriting, and broad compatibility repair. Vulcan tools require provider-native integration and resilience, but they do not require the general compatibility proxy or automatic routing between different providers that expose similarly named models.

Continuing to reuse the CLIProxyAPI runtime would retain its mixed-provider execution semantics and make the unused compatibility graph part of every future change.

## Decision

Vulcan Model Core will be implemented as an independent Go runtime with no code dependency on CLIProxyAPI.

The execution invariant is:

> One execution selects one provider, and the provider cannot change until that execution terminates.

The core may select or fail over between plans, endpoints, regions, and credentials owned by the selected provider. It must not select another provider after the request starts.

Public APIs are owned by the Vulcan protocol suite. Claude, Gemini, OpenAI Chat Completions, OpenAI Responses, Codex, and other provider or client protocols are internal adapter concerns only.

## Reference policy

CLIProxyAPI remains a reference for observed failure behavior, including:

- credential refresh and concurrent refresh suppression;
- account cooldown and quota recovery;
- `Retry-After` handling;
- stream bootstrap failure and post-output retry boundaries;
- provider error classification;
- request cancellation;
- signature replay and cache usage accounting;
- sensitive logging protections.

Before a behavior is implemented, it should be captured as a Vulcan-owned specification or regression fixture. Runtime packages, mixed-provider abstractions, and pairwise protocol converters must not be imported as dependencies.

## Consequences

### Positive

- The public surface contains only Vulcan APIs.
- Provider failover semantics are explicit and testable.
- The conversion graph grows linearly with supported providers.
- Legacy compatibility behavior cannot silently affect Vulcan clients.

### Negative

- Provider integrations must be migrated incrementally.
- Historical edge cases must be rediscovered and documented deliberately.
- The new core will temporarily coexist with the previous router during migration.

## First milestone

The first milestone contains only the provider boundary, adapter registry, exact-provider router, framework HTTP endpoints, graceful shutdown, and invariant tests. Production provider adapters and protocol schemas are intentionally deferred until their requirements are documented.
