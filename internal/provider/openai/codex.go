package openai

import (
	"fmt"
	"strings"

	protocolcodex "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	translateddriver "github.com/OpenVulcan/vulcan-model-core/internal/provider/translatedresponses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/google/uuid"
)

const (
	// codexUserAgent is copied from CLIProxyAPI's fixed Codex executor fingerprint.
	// codexUserAgent 从 CLIProxyAPI 固定的 Codex 执行器指纹复制而来。
	codexUserAgent = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"
)

// CodexDriver executes the Codex Responses dialect through copied CLIProxyAPI behavior.
// CodexDriver 通过复制的 CLIProxyAPI 行为执行 Codex Responses 方言。
type CodexDriver struct {
	// Driver owns shared immutable translated-response execution mechanics.
	// Driver 管理共享的不可变转换响应执行机制。
	*translateddriver.Driver
}

// NewCodexDriver constructs a Codex driver that preserves its always-streaming upstream contract.
// NewCodexDriver 构造保留上游始终流式合同的 Codex 驱动。
func NewCodexDriver(definitionID string, client *transport.Client, capabilities openairesponses.ProfileCapabilities) (*CodexDriver, error) {
	driver, errDriver := translateddriver.NewDriver(translateddriver.Configuration{
		DefinitionID: definitionID,
		Profile:      protocolcodex.Profile(),
		Client:       client,
		Capabilities: capabilities,
		Path:         "/responses",
		StreamPath:   "/responses",
		Headers: []transport.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "User-Agent", Value: codexUserAgent},
			{Name: "Originator", Value: "codex-tui"},
			{Name: "Connection", Value: "Keep-Alive"},
		},
		Authentication:         transport.Authentication{Mode: transport.AuthenticationBearer},
		AllowedAuthMethods:     []providerconfig.AuthMethodType{providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodOAuth, providerconfig.AuthMethodBearer},
		StreamInputMode:        translateddriver.StreamInputLine,
		ForceUpstreamStream:    true,
		ForceTranslationStream: true,
		AdaptRequest:           adaptCodexRequestHeaders,
	})
	if errDriver != nil {
		return nil, errDriver
	}
	return &CodexDriver{Driver: driver}, nil
}

// adaptCodexRequestHeaders preserves copied Codex client identity and OAuth account scoping.
// adaptCodexRequestHeaders 保留复制的 Codex 客户端身份和 OAuth 账号作用域。
func adaptCodexRequestHeaders(execution provider.ExecutionRequest, outbound transport.Request) (transport.Request, error) {
	// authType is resolved from the credential's exact declared authentication method.
	// authType 根据 Credential 精确声明的认证方法解析。
	authType := providerconfig.AuthMethodType("")
	for _, authMethod := range execution.Definition.AuthMethods {
		if authMethod.ID != execution.Binding.Credential.AuthMethodID {
			continue
		}
		if authType != "" {
			return transport.Request{}, fmt.Errorf("%w: Codex credential auth method is ambiguous", translateddriver.ErrInvalidDriver)
		}
		authType = authMethod.Type
	}
	if authType == "" {
		return transport.Request{}, fmt.Errorf("%w: Codex credential auth method is missing", translateddriver.ErrInvalidDriver)
	}
	outbound.Headers = append(outbound.Headers,
		transport.Header{Name: "Session_id", Value: uuid.NewString()},
		transport.Header{Name: "X-Client-Request-Id", Value: uuid.NewString()},
	)
	if authType == providerconfig.AuthMethodAPIKey {
		return outbound, nil
	}
	// accountID is the unique explicit ChatGPT account scope required for non-API-key Codex authentication.
	// accountID 是非 API Key Codex 认证要求的唯一显式 ChatGPT 账号作用域。
	accountID := ""
	for _, scope := range execution.Binding.Credential.ScopeRefs {
		if scope.Kind != "account" {
			continue
		}
		if strings.TrimSpace(scope.ID) == "" || accountID != "" {
			return transport.Request{}, fmt.Errorf("%w: Codex requires exactly one non-empty account scope", translateddriver.ErrInvalidDriver)
		}
		accountID = scope.ID
	}
	if accountID == "" {
		return transport.Request{}, fmt.Errorf("%w: Codex account scope is required for non-API-key authentication", translateddriver.ErrInvalidDriver)
	}
	outbound.Headers = append(outbound.Headers, transport.Header{Name: "Chatgpt-Account-Id", Value: accountID})
	return outbound, nil
}
