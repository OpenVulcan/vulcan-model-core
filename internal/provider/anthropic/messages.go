// Package anthropic contains Anthropic-specific execution drivers.
// Package anthropic 包含 Anthropic 特定执行驱动。
package anthropic

import (
	protocolmessages "github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/google/uuid"
)

const (
	// anthropicDefaultBetas is copied from CLIProxyAPI applyClaudeHeaders at the fixed upstream commit.
	// anthropicDefaultBetas 从固定上游提交的 CLIProxyAPI applyClaudeHeaders 复制而来。
	anthropicDefaultBetas = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15,fast-mode-2026-02-01,redact-thinking-2026-02-12,token-efficient-tools-2026-03-28"
)

// MessagesDriver executes Anthropic Messages through copied CLIProxyAPI translation behavior.
// MessagesDriver 通过复制的 CLIProxyAPI 转换行为执行 Anthropic Messages。
type MessagesDriver struct {
	// Driver owns shared immutable translated-response execution mechanics.
	// Driver 管理共享的不可变转换响应执行机制。
	*translateddriver.Driver
}

// NewMessagesDriver constructs an Anthropic Messages driver with copied endpoint and header behavior.
// NewMessagesDriver 使用复制的端点和 Header 行为构造 Anthropic Messages 驱动。
func NewMessagesDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities) (*MessagesDriver, error) {
	return newMessagesDriver(definitionID, client, capabilities, transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "x-api-key"}, []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodHeaderKey})
}

// NewBearerMessagesDriver constructs an Anthropic-compatible driver authenticated by a provider-issued Bearer token.
// NewBearerMessagesDriver 构建一个使用供应商签发 Bearer Token 认证的 Anthropic 兼容 Driver。
func NewBearerMessagesDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities, allowedAuthMethods []providerconfig.AuthMethodType) (*MessagesDriver, error) {
	return newMessagesDriver(definitionID, client, capabilities, transport.Authentication{Mode: transport.AuthenticationBearer}, allowedAuthMethods)
}

// newMessagesDriver constructs the shared copied Messages translation with an explicit authentication boundary.
// newMessagesDriver 使用显式认证边界构建共享的已复制 Messages 翻译。
func newMessagesDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities, authentication transport.Authentication, allowedAuthMethods []providerconfig.AuthMethodType) (*MessagesDriver, error) {
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolmessages.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/v1/messages?beta=true",
		StreamPath:   "/v1/messages?beta=true",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Anthropic-Version", Value: "2023-06-01"},
			{Name: "Anthropic-Beta", Value: anthropicDefaultBetas},
			{Name: "Anthropic-Dangerous-Direct-Browser-Access", Value: "true"},
			{Name: "X-App", Value: "cli"},
		},
		Authentication:         authentication,
		AllowedAuthMethods:     append([]providerconfig.AuthMethodType(nil), allowedAuthMethods...),
		StreamInputMode:        translateddriver.StreamInputLine,
		ForceTranslationStream: true,
		AdaptRequest:           adaptClaudeRequestHeaders,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &MessagesDriver{Driver: driver}, nil
}

// adaptClaudeRequestHeaders preserves CLIProxyAPI's stable session and per-request identity headers without exposing secrets.
// adaptClaudeRequestHeaders 在不暴露 Secret 的前提下保留 CLIProxyAPI 的稳定会话和逐请求身份 Header。
func adaptClaudeRequestHeaders(execution provider.ExecutionRequest, outbound transport.Request) (transport.Request, error) {
	// sessionID remains stable for one immutable credential while avoiding secret-derived identifiers in logs or metadata.
	// sessionID 对一个不可变 Credential 保持稳定，同时避免在日志或元数据中使用 Secret 派生标识。
	sessionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("vulcan:claude-session:"+execution.Binding.Credential.ID)).String()
	outbound.Headers = append(outbound.Headers,
		transport.Header{Name: "X-Claude-Code-Session-Id", Value: sessionID},
		transport.Header{Name: "x-client-request-id", Value: uuid.NewString()},
		transport.Header{Name: "X-Stainless-Retry-Count", Value: "0"},
		transport.Header{Name: "X-Stainless-Runtime", Value: "node"},
		transport.Header{Name: "X-Stainless-Lang", Value: "js"},
		transport.Header{Name: "X-Stainless-Timeout", Value: "600"},
	)
	return outbound, nil
}
