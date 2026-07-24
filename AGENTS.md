# AGENTS.md

Go 1.26+ provider-scoped model execution core for the OpenVulcan toolchain.

## Commands

```bash
gofmt -w .
go test ./...
go build -o test-output ./cmd/vulcan-model-core
```

## Architectural invariants

- Public HTTP APIs must be owned by the Vulcan protocol suite.
- Do not add public Claude, Gemini, OpenAI Chat Completions, Codex, or other compatibility endpoints.
- One execution has one immutable provider identifier.
- Failover may occur only between plans, endpoints, regions, and credentials owned by that provider.
- Do not add a provider candidate list or automatic cross-provider fallback to the core router.
- Do not create a generic `map[string]any` execution protocol.
- CLIProxyAPI may be consulted for behavioral evidence but must not become a Go module or runtime dependency.

## Engineering rules

- Prefer the Go standard library until a concrete requirement justifies a dependency.
- Keep provider-specific logic inside `internal/provider/<provider>`.
- Convert historical provider bugs into focused tests before implementing compatibility behavior.
- Return explicit errors instead of silently rewriting unsupported input.
- Keep logs free of credentials, tokens, prompts, tool arguments, and generated resources by default.
- All Go types, interfaces, functions, methods, and non-obvious variables require bilingual comments: English first, Chinese second.
- Run `gofmt`, `go test ./...`, and a command build after Go changes.


## 测试用秘钥
管理端秘钥：a123456
API秘钥：sk-testapikey