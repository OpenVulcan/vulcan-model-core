package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
)

const (
	// maximumControlRequestBytes bounds control-plane JSON bodies before they reach secret workflows.
	// maximumControlRequestBytes 在请求进入 Secret 工作流前限制控制面 JSON 正文大小。
	maximumControlRequestBytes = 1 << 20
)

// KeyAuthenticator verifies bearer credentials independently for management and call-plane routes.
// KeyAuthenticator 分别为管理和调用面路由校验 Bearer 凭据。
type KeyAuthenticator interface {
	// AuthenticateManagementKey verifies one management-plane bearer value.
	// AuthenticateManagementKey 校验一个管理面 Bearer 值。
	AuthenticateManagementKey(string) bool
	// AuthenticateAPIKey verifies one call-plane bearer value.
	// AuthenticateAPIKey 校验一个调用面 Bearer 值。
	AuthenticateAPIKey(string) bool
}

// APIKeyManager exposes management-only call-plane API key lifecycle operations.
// APIKeyManager 暴露仅限管理面的调用面 API 密钥生命周期操作。
type APIKeyManager interface {
	// ListAPIKeys returns management-visible plaintext API keys.
	// ListAPIKeys 返回管理面可见的明文 API 密钥。
	ListAPIKeys() []runtimeconfig.APIKey
	// CreateAPIKey persists one caller-supplied API key.
	// CreateAPIKey 持久化一个调用方提供的 API 密钥。
	CreateAPIKey(runtimeconfig.APIKeyInput) (runtimeconfig.APIKey, error)
	// UpdateAPIKey replaces one API key by its immutable identifier.
	// UpdateAPIKey 按不可变标识替换一个 API 密钥。
	UpdateAPIKey(string, runtimeconfig.APIKeyInput) (runtimeconfig.APIKey, error)
	// DeleteAPIKey removes one API key by its immutable identifier.
	// DeleteAPIKey 按不可变标识删除一个 API 密钥。
	DeleteAPIKey(string) error
}

// ManagementCommands exposes typed provider configuration mutations to the management HTTP boundary.
// ManagementCommands 向管理 HTTP 边界暴露类型化供应商配置变更。
type ManagementCommands interface {
	// OnboardSystemProvider atomically creates one complete system-provider access path.
	// OnboardSystemProvider 原子创建一条完整系统供应商访问路径。
	OnboardSystemProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardKimiDeviceProvider accepts only a server-acquired and validated Kimi device credential.
	// OnboardKimiDeviceProvider 仅接受由服务端获取并校验的 Kimi 设备凭据。
	OnboardKimiDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardXAIDeviceProvider accepts only a server-acquired and validated xAI device credential.
	// OnboardXAIDeviceProvider 仅接受由服务端获取并校验的 xAI 设备凭据。
	OnboardXAIDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardCodexDeviceProvider accepts only a server-acquired and validated Codex device credential.
	// OnboardCodexDeviceProvider 仅接受由服务端获取并校验的 Codex 设备凭据。
	OnboardCodexDeviceProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardCodexOAuthProvider accepts only a server-acquired and validated Codex browser OAuth credential.
	// OnboardCodexOAuthProvider 仅接受由服务端获取并校验的 Codex 浏览器 OAuth 凭据。
	OnboardCodexOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardClaudeOAuthProvider accepts only a server-acquired and validated Claude Code OAuth credential.
	// OnboardClaudeOAuthProvider 仅接受由服务端获取并校验的 Claude Code OAuth 凭据。
	OnboardClaudeOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardAntigravityOAuthProvider accepts only a server-acquired and validated Antigravity OAuth credential.
	// OnboardAntigravityOAuthProvider 仅接受由服务端获取并校验的 Antigravity OAuth 凭据。
	OnboardAntigravityOAuthProvider(context.Context, management.OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error)
	// OnboardVertexServiceAccountProvider accepts only a normalized Google service-account document and location.
	// OnboardVertexServiceAccountProvider 仅接受规范化的 Google 服务账号文档与区域。
	OnboardVertexServiceAccountProvider(context.Context, management.OnboardSystemProviderInput, string) (providerconfig.SystemOnboarding, error)
	// OnboardCustomProvider atomically creates one executable custom compatibility provider and initial model.
	// OnboardCustomProvider 原子创建一个可执行自定义兼容供应商与初始模型。
	OnboardCustomProvider(context.Context, management.OnboardCustomProviderInput) (management.CustomProviderOnboardingResult, error)
	// CreateCustomDefinition creates one user-owned provider definition.
	// CreateCustomDefinition 创建一个用户拥有的供应商定义。
	CreateCustomDefinition(context.Context, management.CreateCustomDefinitionInput) (providerconfig.ProviderDefinition, error)
	// UpdateCustomDefinition replaces one user-owned provider definition.
	// UpdateCustomDefinition 替换一个用户拥有的供应商定义。
	UpdateCustomDefinition(context.Context, management.UpdateCustomDefinitionInput) (providerconfig.ProviderDefinition, error)
	// CreateInstance creates one provider instance.
	// CreateInstance 创建一个供应商实例。
	CreateInstance(context.Context, management.CreateInstanceInput) (providerconfig.ProviderInstance, error)
	// UpdateInstance replaces editable provider instance identity fields.
	// UpdateInstance 替换可编辑供应商实例身份字段。
	UpdateInstance(context.Context, management.UpdateInstanceInput) (providerconfig.ProviderInstance, error)
	// SetInstanceEnabled changes local instance availability.
	// SetInstanceEnabled 更改本地实例可用性。
	SetInstanceEnabled(context.Context, string, bool) (providerconfig.ProviderInstance, error)
	// AddEndpoint creates one upstream endpoint.
	// AddEndpoint 创建一个上游端点。
	AddEndpoint(context.Context, management.AddEndpointInput) (providerconfig.Endpoint, error)
	// UpdateEndpoint replaces one upstream endpoint.
	// UpdateEndpoint 替换一个上游端点。
	UpdateEndpoint(context.Context, management.UpdateEndpointInput) (providerconfig.Endpoint, error)
	// AddCredential creates one provider credential from transient secret bytes.
	// AddCredential 根据临时 Secret 字节创建一个供应商凭据。
	AddCredential(context.Context, management.AddCredentialInput) (providerconfig.Credential, error)
	// UpdateCredential replaces one credential's non-secret metadata.
	// UpdateCredential 替换一个凭据的非秘密元数据。
	UpdateCredential(context.Context, management.UpdateCredentialInput) (providerconfig.Credential, error)
	// RotateCredentialSecret replaces one credential's protected secret bytes.
	// RotateCredentialSecret 替换一个凭据的受保护 Secret 字节。
	RotateCredentialSecret(context.Context, management.RotateCredentialSecretInput) (providerconfig.Credential, error)
	// SetCredentialStatus changes one credential lifecycle state.
	// SetCredentialStatus 更改一个凭据生命周期状态。
	SetCredentialStatus(context.Context, management.SetCredentialStatusInput) (providerconfig.Credential, error)
	// AddBinding creates one credential-to-endpoint access binding.
	// AddBinding 创建一个凭据到端点的访问绑定。
	AddBinding(context.Context, management.AddBindingInput) (providerconfig.AccessBinding, error)
	// UpdateBinding replaces one credential-to-endpoint access binding.
	// UpdateBinding 替换一个凭据到端点的访问绑定。
	UpdateBinding(context.Context, management.UpdateBindingInput) (providerconfig.AccessBinding, error)
}

// KimiDeviceFlows owns transient Coding Plan authorization sessions without exposing provider tokens.
// KimiDeviceFlows 管理临时 Coding Plan 授权会话且不暴露供应商令牌。
type KimiDeviceFlows interface {
	// Start creates one management-safe provider verification session.
	// Start 创建一个管理安全的供应商验证会话。
	Start(context.Context) (providerkimi.Flow, error)
	// Poll performs one bounded provider token exchange.
	// Poll 执行一次有界供应商令牌交换。
	Poll(context.Context, string) (providerkimi.Token, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local authorization session.
	// Cancel 消费一个未完成或已完成的本地授权会话。
	Cancel(string)
}

// KimiTokenCommands refreshes completed Coding Plan credentials behind the protected secret boundary.
// KimiTokenCommands 在受保护秘密边界后刷新已完成的 Coding Plan 凭据。
type KimiTokenCommands interface {
	// RefreshCredential replaces one exact refreshable credential.
	// RefreshCredential 替换一个精确可刷新凭据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// XAIDeviceFlows owns transient xAI account authorization sessions without exposing provider tokens.
// XAIDeviceFlows 管理临时 xAI 账号授权会话且不暴露供应商 Token。
type XAIDeviceFlows interface {
	// Start creates one management-safe xAI verification session.
	// Start 创建一个管理安全的 xAI 验证会话。
	Start(context.Context) (providerxai.Flow, error)
	// Poll performs one bounded xAI token exchange.
	// Poll 执行一次有界 xAI Token 交换。
	Poll(context.Context, string) (providerxai.Token, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local authorization session.
	// Cancel 消费一个未完成或已完成的本地授权会话。
	Cancel(string)
}

// XAITokenCommands refreshes completed xAI credentials behind the protected secret boundary.
// XAITokenCommands 在受保护 Secret 边界后刷新已完成 xAI 凭据。
type XAITokenCommands interface {
	// RefreshCredential replaces one exact refreshable xAI credential.
	// RefreshCredential 替换一个精确可刷新 xAI 凭据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// CodexDeviceFlows owns transient Codex account authorization sessions without exposing provider tokens.
// CodexDeviceFlows 管理临时 Codex 账号授权会话且不暴露供应商 Token。
type CodexDeviceFlows interface {
	// Start creates one management-safe Codex verification session.
	// Start 创建一个管理安全的 Codex 验证会话。
	Start(context.Context) (provideropenai.CodexDeviceFlow, error)
	// Poll performs one bounded Codex token exchange.
	// Poll 执行一次有界 Codex Token 交换。
	Poll(context.Context, string) (provideropenai.CodexToken, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local authorization session.
	// Cancel 消费一个未完成或已完成的本地授权会话。
	Cancel(string)
}

// CodexOAuthFlows owns transient Codex browser PKCE state without exposing provider tokens.
// CodexOAuthFlows 管理临时 Codex 浏览器 PKCE 状态且不暴露供应商 Token。
type CodexOAuthFlows interface {
	// Start creates one management-safe Codex browser authorization session.
	// Start 创建一个管理安全的 Codex 浏览器授权会话。
	Start(context.Context) (provideropenai.CodexOAuthFlow, error)
	// Complete validates one pasted localhost callback and performs the provider exchange.
	// Complete 校验一个粘贴的 localhost 回调并执行供应商交换。
	Complete(context.Context, string, string) (provideropenai.CodexToken, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local authorization session.
	// Cancel 消费一个未完成或已完成的本地授权会话。
	Cancel(string)
}

// CodexTokenCommands refreshes completed Codex credentials behind the protected secret boundary.
// CodexTokenCommands 在受保护 Secret 边界后刷新已完成 Codex 凭据。
type CodexTokenCommands interface {
	// RefreshCredential replaces one exact refreshable Codex credential.
	// RefreshCredential 替换一个精确可刷新 Codex 凭据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// ClaudeOAuthFlows owns transient Claude PKCE and consent state without exposing provider tokens.
// ClaudeOAuthFlows 管理临时 Claude PKCE 与同意授权状态且不暴露供应商 Token。
type ClaudeOAuthFlows interface {
	// Start creates one management-safe Claude browser authorization session.
	// Start 创建一个管理安全的 Claude 浏览器授权会话。
	Start(context.Context) (provideranthropic.ClaudeOAuthFlow, error)
	// Complete validates one callback or code#state value and performs the provider exchange.
	// Complete 校验一个回调或 code#state 值并执行供应商交换。
	Complete(context.Context, string, string) (provideranthropic.ClaudeToken, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local Claude authorization session.
	// Cancel 消费一个未完成或已完成的本地 Claude 授权会话。
	Cancel(string)
}

// ClaudeTokenCommands refreshes completed Claude Code credentials behind the protected secret boundary.
// ClaudeTokenCommands 在受保护 Secret 边界后刷新已完成 Claude Code 凭据。
type ClaudeTokenCommands interface {
	// RefreshCredential replaces one exact refreshable Claude OAuth credential.
	// RefreshCredential 替换一个精确可刷新 Claude OAuth 凭据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// AntigravityOAuthFlows owns transient Google consent state without exposing provider tokens.
// AntigravityOAuthFlows 管理临时 Google 同意授权状态且不暴露供应商 Token。
type AntigravityOAuthFlows interface {
	// Start creates one management-safe browser authorization session.
	// Start 创建一个管理安全的浏览器授权会话。
	Start(context.Context) (providergoogle.AntigravityOAuthFlow, error)
	// Complete validates one pasted callback and performs bounded provider exchanges.
	// Complete 校验一个粘贴回调并执行有界供应商交换。
	Complete(context.Context, string, string) (providergoogle.AntigravityToken, error)
	// Release returns a delivered token lease when atomic onboarding fails.
	// Release 在原子录入失败时归还已交付的 Token 租约。
	Release(string)
	// Cancel consumes one incomplete or completed local authorization session.
	// Cancel 消费一个未完成或已完成的本地授权会话。
	Cancel(string)
}

// AntigravityTokenCommands refreshes completed Antigravity credentials behind the protected secret boundary.
// AntigravityTokenCommands 在受保护 Secret 边界后刷新已完成 Antigravity 凭据。
type AntigravityTokenCommands interface {
	// RefreshCredential replaces one exact refreshable Antigravity credential.
	// RefreshCredential 替换一个精确可刷新 Antigravity 凭据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// ModelAccessCommands exposes typed instance model enablement operations.
// ModelAccessCommands 暴露类型化实例模型启停操作。
type ModelAccessCommands interface {
	// SetModelEnabled updates one exact provider model policy.
	// SetModelEnabled 更新一个精确供应商模型策略。
	SetModelEnabled(context.Context, management.SetModelEnabledInput) (providerconfig.ProviderInstance, error)
}

// CustomCatalogOperations exposes complete user-declared catalog read and write operations.
// CustomCatalogOperations 暴露完整用户声明目录的读写操作。
type CustomCatalogOperations interface {
	// GetCustomCatalog returns the current catalog only for a custom provider instance.
	// GetCustomCatalog 仅为自定义供应商实例返回当前目录。
	GetCustomCatalog(context.Context, string) (catalog.Snapshot, error)
	// SaveCustomCatalog replaces one complete custom-provider catalog revision.
	// SaveCustomCatalog 替换一份完整的自定义供应商目录修订。
	SaveCustomCatalog(context.Context, management.SaveCustomCatalogInput) (catalog.Snapshot, error)
}

// ProviderMetadataRefresh refreshes provider-native plan, entitlement, and allowance snapshots.
// ProviderMetadataRefresh 刷新供应商原生套餐、授权与额度快照。
type ProviderMetadataRefresh interface {
	// Refresh atomically replaces metadata for one exact provider instance.
	// Refresh 原子替换一个精确供应商实例的元数据。
	Refresh(context.Context, string, time.Time) (catalog.Snapshot, error)
}

// ProtocolProfileQuery exposes immutable process-owned protocol metadata to the management surface.
// ProtocolProfileQuery 向管理接口面暴露不可变的进程拥有协议元数据。
type ProtocolProfileQuery interface {
	// List returns an isolated stable snapshot of registered protocol profiles.
	// List 返回已注册协议 Profile 的隔离稳定快照。
	List() []providerconfig.ProtocolProfile
}

// ControlPlane groups every dependency required by authenticated management and call-plane routes.
// ControlPlane 聚合认证管理和调用面路由所需的全部依赖。
type ControlPlane struct {
	// Query supplies redacted configuration and catalog views.
	// Query 提供脱敏配置和目录视图。
	Query ManagementQuery
	// Commands applies provider configuration mutations.
	// Commands 应用供应商配置变更。
	Commands ManagementCommands
	// ModelAccess applies instance-level model policies.
	// ModelAccess 应用实例级模型策略。
	ModelAccess ModelAccessCommands
	// CustomCatalogs reads and writes user-declared model metadata for custom providers only.
	// CustomCatalogs 仅为自定义供应商读取和写入用户声明模型元数据。
	CustomCatalogs CustomCatalogOperations
	// MetadataRefresh refreshes provider-native account metadata when a trusted reader exists.
	// MetadataRefresh 在存在受信任读取器时刷新供应商原生账号元数据。
	MetadataRefresh ProviderMetadataRefresh
	// Protocols exposes custom-provider-selectable protocol metadata.
	// Protocols 暴露可供自定义供应商选择的协议元数据。
	Protocols ProtocolProfileQuery
	// APIKeys owns plaintext call-plane key lifecycle operations.
	// APIKeys 管理明文调用面密钥生命周期操作。
	APIKeys APIKeyManager
	// Auth verifies route-scoped bearer values.
	// Auth 校验路由作用域 Bearer 值。
	Auth KeyAuthenticator
	// KimiDeviceFlows optionally enables server-owned Coding Plan device authorization routes.
	// KimiDeviceFlows 可选启用服务端拥有的 Coding Plan 设备授权路由。
	KimiDeviceFlows KimiDeviceFlows
	// KimiTokens optionally enables explicit protected Coding Plan token refresh.
	// KimiTokens 可选启用显式受保护 Coding Plan 令牌刷新。
	KimiTokens KimiTokenCommands
	// XAIDeviceFlows optionally enables server-owned xAI device authorization routes.
	// XAIDeviceFlows 可选启用服务端拥有的 xAI 设备授权路由。
	XAIDeviceFlows XAIDeviceFlows
	// XAITokens optionally enables explicit protected xAI token refresh.
	// XAITokens 可选启用显式受保护 xAI Token 刷新。
	XAITokens XAITokenCommands
	// CodexDeviceFlows optionally enables server-owned Codex device authorization routes.
	// CodexDeviceFlows 可选启用服务端拥有的 Codex 设备授权路由。
	CodexDeviceFlows CodexDeviceFlows
	// CodexOAuthFlows optionally enables server-owned Codex browser authorization routes.
	// CodexOAuthFlows 可选启用服务端拥有的 Codex 浏览器授权路由。
	CodexOAuthFlows CodexOAuthFlows
	// CodexTokens optionally enables explicit protected Codex token refresh.
	// CodexTokens 可选启用显式受保护 Codex Token 刷新。
	CodexTokens CodexTokenCommands
	// ClaudeOAuthFlows optionally enables server-owned Claude Code consent routes.
	// ClaudeOAuthFlows 可选启用服务端拥有的 Claude Code 同意授权路由。
	ClaudeOAuthFlows ClaudeOAuthFlows
	// ClaudeTokens optionally enables explicit protected Claude token refresh.
	// ClaudeTokens 可选启用显式受保护 Claude Token 刷新。
	ClaudeTokens ClaudeTokenCommands
	// AntigravityOAuthFlows optionally enables server-owned Google consent routes.
	// AntigravityOAuthFlows 可选启用服务端拥有的 Google 同意授权路由。
	AntigravityOAuthFlows AntigravityOAuthFlows
	// AntigravityTokens optionally enables explicit protected Antigravity token refresh.
	// AntigravityTokens 可选启用显式受保护 Antigravity Token 刷新。
	AntigravityTokens AntigravityTokenCommands
}

// validate verifies the complete authenticated control-plane dependency graph.
// validate 校验完整的认证控制面依赖图。
func (c ControlPlane) validate() error {
	// requiredDependencies contains every interface called unconditionally by registered control-plane routes.
	// requiredDependencies 包含注册控制面路由会无条件调用的全部接口。
	requiredDependencies := []any{c.Query, c.Commands, c.ModelAccess, c.CustomCatalogs, c.Protocols, c.APIKeys, c.Auth}
	for _, dependency := range requiredDependencies {
		if isNilHTTPDependency(dependency) {
			return errors.New("complete authenticated control plane is required")
		}
	}
	// optionalDependencies may be absent, but a typed nil would register or dispatch an unusable service.
	// optionalDependencies 可以缺省，但带类型的 nil 会注册或分派一个不可用服务。
	optionalDependencies := []any{c.MetadataRefresh, c.KimiDeviceFlows, c.KimiTokens, c.XAIDeviceFlows, c.XAITokens, c.CodexDeviceFlows, c.CodexOAuthFlows, c.CodexTokens, c.ClaudeOAuthFlows, c.ClaudeTokens, c.AntigravityOAuthFlows, c.AntigravityTokens}
	for _, dependency := range optionalDependencies {
		if dependency != nil && isNilHTTPDependency(dependency) {
			return errors.New("control-plane optional dependency must not contain a typed nil reference")
		}
	}
	return nil
}

// protocolProfileListResponse returns client-safe immutable profile metadata.
// protocolProfileListResponse 返回客户端安全的不可变 Profile 元数据。
type protocolProfileListResponse struct {
	// ProtocolProfiles contains process-owned profile views in stable identifier order.
	// ProtocolProfiles 包含按稳定标识排序的进程拥有 Profile 视图。
	ProtocolProfiles []protocolProfileView `json:"protocol_profiles"`
}

// protocolProfileView describes one custom-provider selectable protocol without exposing internal adapters.
// protocolProfileView 描述一个可供自定义供应商选择的协议且不暴露内部 Adapter。
type protocolProfileView struct {
	// ID is the stable protocol profile identifier.
	// ID 是稳定协议 Profile 标识。
	ID string `json:"id"`
	// Version is the process-owned protocol behavior version.
	// Version 是进程拥有的协议行为版本。
	Version string `json:"version"`
	// DisplayName is the management-facing protocol label.
	// DisplayName 是管理界面显示的协议名称。
	DisplayName string `json:"display_name"`
	// UserConfigurable reports whether custom provider definitions may select this profile.
	// UserConfigurable 表示自定义供应商定义是否可以选择此 Profile。
	UserConfigurable bool `json:"user_configurable"`
	// RuntimeReady reports whether the process has an executable profile implementation.
	// RuntimeReady 表示进程是否拥有可执行的 Profile 实现。
	RuntimeReady bool `json:"runtime_ready"`
	// ModelDiscovery reports profile-level upstream model discovery availability.
	// ModelDiscovery 报告 Profile 级上游模型发现可用性。
	ModelDiscovery providerconfig.SupportStatus `json:"model_discovery"`
	// Capabilities contains explicitly registered profile-global capability facts.
	// Capabilities 包含显式注册的 Profile 全局能力事实。
	Capabilities []protocolCapabilityView `json:"capabilities"`
	// AllowedAuthMethods contains the exact credential mechanisms allowed for custom definitions.
	// AllowedAuthMethods 包含自定义定义允许的精确凭据机制。
	AllowedAuthMethods []providerconfig.AuthMethodType `json:"allowed_auth_methods"`
}

// protocolCapabilityView describes one closed protocol behavior availability fact.
// protocolCapabilityView 描述一个封闭协议行为可用性事实。
type protocolCapabilityView struct {
	// Capability is the closed protocol behavior identifier.
	// Capability 是封闭协议行为标识。
	Capability providerconfig.ProtocolCapability `json:"capability"`
	// Status reports the verified behavior availability.
	// Status 报告经过验证的行为可用性。
	Status providerconfig.SupportStatus `json:"status"`
}

// identifierResponse returns one non-secret newly created management identifier.
// identifierResponse 返回一个非秘密的新建管理标识。
type identifierResponse struct {
	// ID is the immutable identifier allocated or accepted by the management service.
	// ID 是由管理服务分配或接受的不可变标识。
	ID string `json:"id"`
}

// providerDefinitionListResponse returns custom and system definition views.
// providerDefinitionListResponse 返回自定义和系统定义视图。
type providerDefinitionListResponse struct {
	// ProviderDefinitions contains only management-safe provider definition metadata.
	// ProviderDefinitions 仅包含管理安全的供应商定义元数据。
	ProviderDefinitions []management.ProviderDefinitionView `json:"provider_definitions"`
}

// providerGroupListResponse returns management-only system provider groups and their selectable variants.
// providerGroupListResponse 返回仅供管理使用的系统供应商分组及其可选择变体。
type providerGroupListResponse struct {
	// ProviderGroups contains grouped definitions without execution fallback semantics.
	// ProviderGroups 包含不带执行降级语义的分组定义。
	ProviderGroups []management.ProviderGroupView `json:"provider_groups"`
}

// providerInstanceListResponse returns management-safe provider instance views.
// providerInstanceListResponse 返回管理安全的供应商实例视图。
type providerInstanceListResponse struct {
	// ProviderInstances contains provider instances without credential secret material.
	// ProviderInstances 包含不带凭据 Secret 材料的供应商实例。
	ProviderInstances []management.ProviderInstanceView `json:"provider_instances"`
}

// endpointListResponse returns management-safe endpoint views.
// endpointListResponse 返回管理安全端点视图。
type endpointListResponse struct {
	// Endpoints contains endpoints owned by one provider instance.
	// Endpoints 包含一个供应商实例拥有的端点。
	Endpoints []management.EndpointView `json:"endpoints"`
}

// credentialListResponse returns management-safe credential views.
// credentialListResponse 返回管理安全凭据视图。
type credentialListResponse struct {
	// Credentials contains non-secret credential metadata only.
	// Credentials 仅包含非秘密凭据元数据。
	Credentials []management.CredentialView `json:"credentials"`
}

// bindingListResponse returns management-safe access binding views.
// bindingListResponse 返回管理安全访问绑定视图。
type bindingListResponse struct {
	// Bindings contains credential-to-endpoint relationships without secret material.
	// Bindings 包含不带 Secret 材料的凭据到端点关系。
	Bindings []management.BindingView `json:"bindings"`
}

// apiKeyListResponse returns plaintext API keys only to the management plane.
// apiKeyListResponse 仅向管理面返回明文 API 密钥。
type apiKeyListResponse struct {
	// APIKeys contains management-authorized plaintext call-plane keys.
	// APIKeys 包含经管理授权的明文调用面密钥。
	APIKeys []runtimeconfig.APIKey `json:"api_keys"`
}

// callModelListResponse returns provider-scoped models usable by the authenticated call plane.
// callModelListResponse 返回认证调用面可使用的供应商作用域模型。
type callModelListResponse struct {
	// Models contains non-fused models from individually selected provider instances.
	// Models 包含来自各自选定供应商实例且未融合的模型。
	Models []callModelView `json:"models"`
}

// callModelView identifies one selected provider instance and its local model capability view.
// callModelView 标识一个选定供应商实例及其本地模型能力视图。
type callModelView struct {
	// ProviderInstanceID is required for every subsequent provider-scoped request.
	// ProviderInstanceID 是每个后续供应商作用域请求所必需的字段。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderHandle is the stable workspace-visible provider instance alias.
	// ProviderHandle 是稳定的工作区可见供应商实例别名。
	ProviderHandle string `json:"provider_handle"`
	// ProviderDefinitionID identifies the underlying system or custom provider definition.
	// ProviderDefinitionID 标识底层系统或自定义供应商定义。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// Model contains the exact non-fused model, offering, and capability shape.
	// Model 包含精确未融合的模型、产品和能力形态。
	Model management.ModelView `json:"model"`
}

// customCatalogDocument is the complete management-facing configuration for one custom-provider model catalog.
// customCatalogDocument 是一个自定义供应商模型目录的完整管理面配置。
type customCatalogDocument struct {
	// Models contains logical models declared by the local operator.
	// Models 包含由本地操作员声明的逻辑模型。
	Models []customCatalogModel `json:"models"`
	// Offerings binds declared models to exact configured provider channels.
	// Offerings 将声明模型绑定到精确已配置供应商通道。
	Offerings []customCatalogOffering `json:"offerings"`
	// Profiles contains client-selectable capability shapes for declared offerings.
	// Profiles 包含声明产品可供客户端选择的能力形态。
	Profiles []customCatalogProfile `json:"profiles"`
}

// customCatalogModel describes one user-declared logical model without server-owned metadata.
// customCatalogModel 描述一个不包含服务端拥有元数据的用户声明逻辑模型。
type customCatalogModel struct {
	// ID is the stable model_ identifier supplied by the operator.
	// ID 是由操作员提供的稳定 model_ 标识。
	ID string `json:"id"`
	// UpstreamModelID is the exact model identifier sent to the upstream provider.
	// UpstreamModelID 是发送给上游供应商的精确模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// DisplayName is the local management-facing model label.
	// DisplayName 是本地管理界面的模型名称。
	DisplayName string `json:"display_name"`
}

// customCatalogOffering describes one channel-specific custom model offering.
// customCatalogOffering 描述一个通道特定的自定义模型产品。
type customCatalogOffering struct {
	// ID is the stable offer_ identifier supplied by the operator.
	// ID 是由操作员提供的稳定 offer_ 标识。
	ID string `json:"id"`
	// ProviderModelID references a model in the same submitted document.
	// ProviderModelID 引用同一提交文档内的一个模型。
	ProviderModelID string `json:"provider_model_id"`
	// UpstreamModelID is the exact upstream model identifier for this channel.
	// UpstreamModelID 是此通道的精确上游模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// Capabilities explicitly declares the channel baseline without inferred values.
	// Capabilities 显式声明通道基线能力且不推导缺失值。
	Capabilities management.CapabilityView `json:"capabilities"`
}

// customCatalogProfile describes one selectable custom model capability shape.
// customCatalogProfile 描述一个可选择的自定义模型能力形态。
type customCatalogProfile struct {
	// ID is the stable profile_ identifier supplied by the operator.
	// ID 是由操作员提供的稳定 profile_ 标识。
	ID string `json:"id"`
	// OfferingID references an offering in the same submitted document.
	// OfferingID 引用同一提交文档内的一个产品。
	OfferingID string `json:"offering_id"`
	// DisplayName is the client-visible profile label.
	// DisplayName 是客户端可见的规格名称。
	DisplayName string `json:"display_name"`
	// Default reports whether clients may omit an explicit profile selection.
	// Default 表示客户端是否可以省略显式规格选择。
	Default bool `json:"default"`
	// Capabilities explicitly declares the effective profile capability ceiling.
	// Capabilities 显式声明有效规格能力上限。
	Capabilities management.CapabilityView `json:"capabilities"`
	// RequiredEntitlementClasses optionally limits this profile to named account classes.
	// RequiredEntitlementClasses 可选地将此规格限制到命名账号类别。
	RequiredEntitlementClasses []string `json:"required_entitlement_classes"`
	// SwitchPolicy defines active-conversation profile-switch behavior.
	// SwitchPolicy 定义活动会话的规格切换行为。
	SwitchPolicy catalog.ProfileSwitchPolicy `json:"switch_policy"`
	// PoolPolicy defines credential selection behavior within this profile.
	// PoolPolicy 定义此规格内的凭据选择行为。
	PoolPolicy catalog.PoolPolicy `json:"pool_policy"`
}

// createCustomDefinitionRequest decodes a typed custom-provider creation request.
// createCustomDefinitionRequest 解码一个类型化自定义供应商创建请求。
type createCustomDefinitionRequest struct {
	// ID optionally supplies a stable custom_ identifier.
	// ID 可选提供稳定的 custom_ 标识。
	ID string `json:"id"`
	// DisplayName is the management-facing provider name.
	// DisplayName 是管理界面供应商名称。
	DisplayName string `json:"display_name"`
	// ProtocolProfileID selects one registered user-configurable protocol profile.
	// ProtocolProfileID 选择一个已注册且用户可配置的协议规格。
	ProtocolProfileID string `json:"protocol_profile_id"`
	// AuthMethod selects one declared upstream authentication mechanism.
	// AuthMethod 选择一个声明的上游认证机制。
	AuthMethod providerconfig.AuthMethodType `json:"auth_method"`
}

// onboardCustomProviderRequest decodes one complete custom compatibility provider and initial model.
// onboardCustomProviderRequest 解码一个完整自定义兼容供应商与初始模型。
type onboardCustomProviderRequest struct {
	// DisplayName is the sole provider, instance, and credential display label.
	// DisplayName 是唯一的供应商、实例与凭据显示标签。
	DisplayName string `json:"display_name"`
	// Handle is the stable workspace-visible routing identifier.
	// Handle 是工作区可见的稳定路由标识。
	Handle string `json:"handle"`
	// ProtocolProfileID selects OpenAICompatibility or VertexCompat execution.
	// ProtocolProfileID 选择 OpenAICompatibility 或 VertexCompat 执行。
	ProtocolProfileID string `json:"protocol_profile_id"`
	// BaseURL is the operator-owned compatibility endpoint.
	// BaseURL 是操作员拥有的兼容 Endpoint。
	BaseURL string `json:"base_url"`
	// Secret is transient credential material and is never returned.
	// Secret 是临时凭据材料且绝不返回。
	Secret string `json:"secret"`
	// UpstreamModelID is the exact model identifier sent on the wire.
	// UpstreamModelID 是在 Wire 上发送的精确模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// ModelDisplayName is an optional management-facing model label.
	// ModelDisplayName 是可选的管理界面模型标签。
	ModelDisplayName string `json:"model_display_name"`
}

// customProviderOnboardingResponse contains only identifiers from one committed custom onboarding transaction.
// customProviderOnboardingResponse 仅包含一次已提交自定义录入事务的标识。
type customProviderOnboardingResponse struct {
	// ProviderDefinitionID identifies the committed custom definition.
	// ProviderDefinitionID 标识已提交的自定义 Definition。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// ProviderInstanceID identifies the committed provider instance.
	// ProviderInstanceID 标识已提交的供应商实例。
	ProviderInstanceID string `json:"provider_instance_id"`
	// CredentialID identifies the committed non-secret credential metadata.
	// CredentialID 标识已提交的非秘密凭据元数据。
	CredentialID string `json:"credential_id"`
	// EndpointID identifies the committed compatibility endpoint.
	// EndpointID 标识已提交的兼容 Endpoint。
	EndpointID string `json:"endpoint_id"`
	// BindingID identifies the committed executable access binding.
	// BindingID 标识已提交的可执行访问绑定。
	BindingID string `json:"binding_id"`
	// ProviderModelID identifies the sole initial user-declared model.
	// ProviderModelID 标识唯一初始用户声明模型。
	ProviderModelID string `json:"provider_model_id"`
}

// updateCustomDefinitionRequest decodes a typed custom-provider replacement request.
// updateCustomDefinitionRequest 解码一个类型化自定义供应商替换请求。
type updateCustomDefinitionRequest struct {
	// DisplayName is the replacement management-facing provider name.
	// DisplayName 是替换后的管理界面供应商名称。
	DisplayName string `json:"display_name"`
	// ProtocolProfileID selects the replacement registered protocol profile.
	// ProtocolProfileID 选择替换后的已注册协议规格。
	ProtocolProfileID string `json:"protocol_profile_id"`
	// AuthMethod selects the replacement upstream authentication mechanism.
	// AuthMethod 选择替换后的上游认证机制。
	AuthMethod providerconfig.AuthMethodType `json:"auth_method"`
}

// createInstanceRequest decodes a typed provider-instance creation request.
// createInstanceRequest 解码一个类型化供应商实例创建请求。
type createInstanceRequest struct {
	// ID optionally supplies a stable pvi_ identifier.
	// ID 可选提供稳定的 pvi_ 标识。
	ID string `json:"id"`
	// DefinitionID selects one system or custom provider definition.
	// DefinitionID 选择一个系统或自定义供应商定义。
	DefinitionID string `json:"definition_id"`
	// Handle is the stable workspace routing alias.
	// Handle 是稳定工作区路由别名。
	Handle string `json:"handle"`
	// DisplayName is the management-facing instance name.
	// DisplayName 是管理界面实例名称。
	DisplayName string `json:"display_name"`
}

// onboardSystemProviderRequest decodes one complete API-key onboarding request with a single operator-visible name.
// onboardSystemProviderRequest 解码一次仅包含一个操作员可见名称的完整 API Key 录入请求。
type onboardSystemProviderRequest struct {
	// DefinitionID selects one exact system provider variant.
	// DefinitionID 选择一个精确系统供应商变体。
	DefinitionID string `json:"provider_definition_id"`
	// Name is reused as the instance and credential label because API keys expose no provider identity.
	// Name 同时作为实例与凭据标签，因为 API Key 不提供供应商身份。
	Name string `json:"name"`
	// AuthMethodID selects one definition-owned authentication method.
	// AuthMethodID 选择一种由定义拥有的认证方式。
	AuthMethodID string `json:"auth_method_id"`
	// Secret contains transient credential material and is never returned.
	// Secret 包含临时凭据材料且绝不返回。
	Secret string `json:"secret"`
}

// onboardVertexServiceAccountRequest decodes one server-validated Vertex service-account upload.
// onboardVertexServiceAccountRequest 解码一次由服务端校验的 Vertex 服务账号上传。
type onboardVertexServiceAccountRequest struct {
	// DefinitionID must select the code-owned Google Vertex AI product.
	// DefinitionID 必须选择代码拥有的 Google Vertex AI 产品。
	DefinitionID string `json:"provider_definition_id"`
	// Location selects global or one normalized Google Vertex region.
	// Location 选择 global 或一个规范化 Google Vertex 区域。
	Location string `json:"location"`
	// ServiceAccount contains one transient JSON object and is never returned.
	// ServiceAccount 包含一个临时 JSON 对象且绝不返回。
	ServiceAccount json.RawMessage `json:"service_account"`
}

// deviceFlowOnboardRequest contains the exact product and an optional sole name for providers without account identity.
// deviceFlowOnboardRequest 包含精确产品，以及不提供账号身份的供应商所需的可选唯一名称。
type deviceFlowOnboardRequest struct {
	// DefinitionID must select the exact device-flow system product.
	// DefinitionID 必须选择精确的设备授权系统产品。
	DefinitionID string `json:"provider_definition_id"`
	// Name is required for Kimi and is the xAI fallback when its optional ID-token identity is absent.
	// Name 对 Kimi 必填，并在 xAI 的可选 ID Token 身份缺失时作为回退名称。
	Name string `json:"name"`
}

// antigravityOAuthOnboardRequest contains the pasted callback while Google supplies the account display identity.
// antigravityOAuthOnboardRequest 包含粘贴回调，账号显示身份由 Google 提供。
type antigravityOAuthOnboardRequest struct {
	// DefinitionID must select the code-owned Google Antigravity product.
	// DefinitionID 必须选择代码拥有的 Google Antigravity 产品。
	DefinitionID string `json:"provider_definition_id"`
	// CallbackURL is the exact localhost callback copied after Google consent.
	// CallbackURL 是 Google 同意授权后复制的精确 localhost 回调地址。
	CallbackURL string `json:"callback_url"`
}

// claudeOAuthOnboardRequest contains one pasted callback or code#state value while Claude supplies account identity.
// claudeOAuthOnboardRequest 包含一个粘贴回调或 code#state 值，账号身份由 Claude 提供。
type claudeOAuthOnboardRequest struct {
	// DefinitionID must select the code-owned Claude Code product.
	// DefinitionID 必须选择代码拥有的 Claude Code 产品。
	DefinitionID string `json:"provider_definition_id"`
	// CallbackURL is the exact localhost callback or CLIProxyAPI code#state value.
	// CallbackURL 是精确本地回调或 CLIProxyAPI code#state 值。
	CallbackURL string `json:"callback_url"`
}

// codexOAuthOnboardRequest contains one pasted localhost callback while OpenAI supplies account identity.
// codexOAuthOnboardRequest 包含一个粘贴的 localhost 回调，账号身份由 OpenAI 提供。
type codexOAuthOnboardRequest struct {
	// DefinitionID must select the code-owned Codex Account product.
	// DefinitionID 必须选择代码拥有的 Codex Account 产品。
	DefinitionID string `json:"provider_definition_id"`
	// CallbackURL is the exact provider-registered localhost callback copied from the browser.
	// CallbackURL 是从浏览器复制的精确供应商注册 localhost 回调。
	CallbackURL string `json:"callback_url"`
}

// onboardSystemProviderResponse returns only non-secret identifiers created by one atomic onboarding.
// onboardSystemProviderResponse 仅返回一次原子录入创建的非秘密标识。
type onboardSystemProviderResponse struct {
	// ProviderInstanceID identifies the created exact provider instance.
	// ProviderInstanceID 标识创建的精确供应商实例。
	ProviderInstanceID string `json:"provider_instance_id"`
	// CredentialID identifies the created protected credential metadata.
	// CredentialID 标识创建的受保护凭据元数据。
	CredentialID string `json:"credential_id"`
	// EndpointIDs identify the created fixed endpoints.
	// EndpointIDs 标识创建的固定端点。
	EndpointIDs []string `json:"endpoint_ids"`
	// BindingIDs identify the created closed access paths.
	// BindingIDs 标识创建的闭合访问路径。
	BindingIDs []string `json:"binding_ids"`
}

// updateInstanceRequest decodes editable provider-instance identity fields.
// updateInstanceRequest 解码可编辑供应商实例身份字段。
type updateInstanceRequest struct {
	// Handle is the replacement stable workspace routing alias.
	// Handle 是替换后的稳定工作区路由别名。
	Handle string `json:"handle"`
	// DisplayName is the replacement management-facing instance name.
	// DisplayName 是替换后的管理界面实例名称。
	DisplayName string `json:"display_name"`
}

// setEnabledRequest decodes one explicit enabled state.
// setEnabledRequest 解码一个显式启用状态。
type setEnabledRequest struct {
	// Enabled is the exact replacement availability state.
	// Enabled 是精确替换可用性状态。
	Enabled bool `json:"enabled"`
}

// createEndpointRequest decodes a typed endpoint creation request.
// createEndpointRequest 解码一个类型化端点创建请求。
type createEndpointRequest struct {
	// ID optionally supplies a stable ep_ identifier.
	// ID 可选提供稳定的 ep_ 标识。
	ID string `json:"id"`
	// BaseURL is the validated upstream base URL.
	// BaseURL 是已校验的上游基础 URL。
	BaseURL string `json:"base_url"`
	// Region is an optional provider-defined region label.
	// Region 是可选供应商定义区域标签。
	Region string `json:"region"`
}

// updateEndpointRequest decodes every editable endpoint field.
// updateEndpointRequest 解码全部可编辑端点字段。
type updateEndpointRequest struct {
	// BaseURL is the replacement validated upstream base URL.
	// BaseURL 是替换后的已校验上游基础 URL。
	BaseURL string `json:"base_url"`
	// Region is the replacement optional provider-defined region label.
	// Region 是替换后的可选供应商定义区域标签。
	Region string `json:"region"`
	// Status is the replacement endpoint availability state.
	// Status 是替换后的端点可用性状态。
	Status providerconfig.EndpointStatus `json:"status"`
}

// createCredentialRequest decodes a typed upstream credential creation request.
// createCredentialRequest 解码一个类型化上游凭据创建请求。
type createCredentialRequest struct {
	// ID optionally supplies a stable cred_ identifier.
	// ID 可选提供稳定的 cred_ 标识。
	ID string `json:"id"`
	// AuthMethodID identifies the provider definition authentication method.
	// AuthMethodID 标识供应商定义认证方式。
	AuthMethodID string `json:"auth_method_id"`
	// Label is the management-facing credential label.
	// Label 是管理界面凭据标签。
	Label string `json:"label"`
	// PrincipalKey is an optional upstream account identity accepted only for metadata persistence.
	// PrincipalKey 是仅用于元数据持久化的可选上游账号身份。
	PrincipalKey string `json:"principal_key"`
	// ScopeRefs contains explicit commercial and organizational scope references.
	// ScopeRefs 包含显式商业和组织作用域引用。
	ScopeRefs []providerconfig.ScopeReference `json:"scope_refs"`
	// Secret is transient upstream credential material and is never returned.
	// Secret 是临时上游凭据材料且绝不返回。
	Secret string `json:"secret"`
}

// updateCredentialRequest decodes editable non-secret credential fields.
// updateCredentialRequest 解码可编辑非秘密凭据字段。
type updateCredentialRequest struct {
	// Label is the replacement management-facing credential label.
	// Label 是替换后的管理界面凭据标签。
	Label string `json:"label"`
	// PrincipalKey replaces operator-owned identity and may only echo provider-derived identity.
	// PrincipalKey 替换操作员拥有的身份；对供应商派生身份只能原样回传。
	PrincipalKey string `json:"principal_key"`
	// ScopeRefs replaces operator-owned scopes and may only echo provider-derived scopes.
	// ScopeRefs 替换操作员拥有的作用域；对供应商派生作用域只能原样回传。
	ScopeRefs []providerconfig.ScopeReference `json:"scope_refs"`
}

// rotateCredentialSecretRequest decodes one secret rotation request.
// rotateCredentialSecretRequest 解码一个 Secret 轮换请求。
type rotateCredentialSecretRequest struct {
	// Secret is transient replacement upstream credential material and is never returned.
	// Secret 是临时替换上游凭据材料且绝不返回。
	Secret string `json:"secret"`
}

// setCredentialStatusRequest decodes one explicit credential lifecycle transition.
// setCredentialStatusRequest 解码一个显式凭据生命周期转换。
type setCredentialStatusRequest struct {
	// Status is the replacement credential lifecycle state.
	// Status 是替换后的凭据生命周期状态。
	Status providerconfig.CredentialStatus `json:"status"`
	// CoolingUntil is required only for a cooling state.
	// CoolingUntil 仅在冷却状态时必填。
	CoolingUntil *time.Time `json:"cooling_until"`
}

// createBindingRequest decodes a typed access-binding creation request.
// createBindingRequest 解码一个类型化访问绑定创建请求。
type createBindingRequest struct {
	// ID optionally supplies a stable bind_ identifier.
	// ID 可选提供稳定的 bind_ 标识。
	ID string `json:"id"`
	// EndpointID identifies the same-instance endpoint.
	// EndpointID 标识同实例端点。
	EndpointID string `json:"endpoint_id"`
	// CredentialID identifies the same-instance credential.
	// CredentialID 标识同实例凭据。
	CredentialID string `json:"credential_id"`
	// AllowedModelIDs restricts the binding to explicit models when non-empty.
	// AllowedModelIDs 非空时将绑定限制到明确模型。
	AllowedModelIDs []string `json:"allowed_model_ids"`
	// Priority is the deterministic same-pool selection order.
	// Priority 是确定性的同账号池选择顺序。
	Priority int `json:"priority"`
}

// updateBindingRequest decodes every editable access-binding field.
// updateBindingRequest 解码全部可编辑访问绑定字段。
type updateBindingRequest struct {
	// EndpointID identifies the replacement same-instance endpoint.
	// EndpointID 标识替换后的同实例端点。
	EndpointID string `json:"endpoint_id"`
	// CredentialID identifies the replacement same-instance credential.
	// CredentialID 标识替换后的同实例凭据。
	CredentialID string `json:"credential_id"`
	// AllowedModelIDs restricts the replacement binding to explicit models when non-empty.
	// AllowedModelIDs 非空时将替换绑定限制到明确模型。
	AllowedModelIDs []string `json:"allowed_model_ids"`
	// Priority is the replacement deterministic same-pool selection order.
	// Priority 是替换后的确定性同账号池选择顺序。
	Priority int `json:"priority"`
	// Enabled controls whether the replacement binding participates in resolution.
	// Enabled 控制替换绑定是否参与解析。
	Enabled bool `json:"enabled"`
}

// apiKeyRequest decodes one plaintext call-plane API key mutation.
// apiKeyRequest 解码一个明文调用面 API 密钥变更。
type apiKeyRequest struct {
	// Name is the management-facing API key label.
	// Name 是管理界面 API 密钥标签。
	Name string `json:"name"`
	// Key is the explicit plaintext call-plane bearer value.
	// Key 是显式明文调用面 Bearer 值。
	Key string `json:"key"`
	// Enabled controls immediate call-plane authentication availability.
	// Enabled 控制立即调用面认证可用性。
	Enabled bool `json:"enabled"`
}

// requireManagement authenticates one request only against the management credential namespace.
// requireManagement 仅针对管理凭据命名空间认证一个请求。
func (s *Server) requireManagement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if s.control == nil || !s.control.Auth.AuthenticateManagementKey(bearerToken(request)) {
			writeUnauthorized(writer)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// requireAPIKey authenticates one request only against enabled call-plane API keys.
// requireAPIKey 仅针对启用的调用面 API 密钥认证一个请求。
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if s.control == nil || !s.control.Auth.AuthenticateAPIKey(bearerToken(request)) {
			writeUnauthorized(writer)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// bearerToken extracts exactly one standard Bearer value without accepting duplicate or alternate credential headers.
// bearerToken 精确提取一个标准 Bearer 值，且不接受重复或替代凭据头。
func bearerToken(request *http.Request) string {
	// authorizationValues rejects intermediary-dependent interpretation when the same credential header appears more than once.
	// authorizationValues 在同一凭据头出现多次时拒绝依赖中间代理的歧义解释。
	authorizationValues := request.Header.Values("Authorization")
	if len(authorizationValues) != 1 {
		return ""
	}
	// authorization is the sole header value permitted to enter Bearer parsing.
	// authorization 是唯一允许进入 Bearer 解析的请求头值。
	authorization := strings.TrimSpace(authorizationValues[0])
	if authorization == "" {
		return ""
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// writeUnauthorized writes one credential-agnostic unauthorized response.
// writeUnauthorized 写入一个不泄露凭据细节的未授权响应。
func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(writer, http.StatusUnauthorized, errorResponse{Error: "unauthorized"})
}

// decodeControlJSON decodes exactly one bounded typed JSON body and rejects unknown fields.
// decodeControlJSON 解码一个有界类型化 JSON 正文并拒绝未知字段。
func decodeControlJSON[T any](writer http.ResponseWriter, request *http.Request) (T, error) {
	var payload T
	// boundedBody caps secret-bearing requests before JSON allocates arbitrarily large values.
	// boundedBody 在 JSON 任意分配大值前限制携带 Secret 的请求。
	boundedBody := http.MaxBytesReader(writer, request.Body, maximumControlRequestBytes)
	defer boundedBody.Close()
	decoder := json.NewDecoder(boundedBody)
	decoder.DisallowUnknownFields()
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return payload, fmt.Errorf("decode JSON request: %w", errDecode)
	}
	var trailing struct{}
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		if errTrailing == nil {
			return payload, errors.New("JSON request contains multiple values")
		}
		return payload, fmt.Errorf("decode trailing JSON request: %w", errTrailing)
	}
	return payload, nil
}

// writeControlError maps expected domain failures to non-sensitive control-plane HTTP errors.
// writeControlError 将预期领域失败映射为不敏感的控制面 HTTP 错误。
func writeControlError(writer http.ResponseWriter, err error) {
	statusCode := http.StatusBadRequest
	errorCode := "invalid_request"
	if errors.Is(err, providerconfig.ErrNotFound) || errors.Is(err, catalog.ErrSnapshotNotFound) || errors.Is(err, management.ErrProviderModelNotFound) || errors.Is(err, runtimeconfig.ErrAPIKeyNotFound) {
		statusCode = http.StatusNotFound
		errorCode = "not_found"
	} else if errors.Is(err, providerkimi.ErrFlowNotFound) || errors.Is(err, providerxai.ErrFlowNotFound) || errors.Is(err, provideropenai.ErrCodexFlowNotFound) {
		statusCode = http.StatusNotFound
		errorCode = "device_flow_not_found"
	} else if errors.Is(err, providergoogle.ErrAntigravityFlowNotFound) || errors.Is(err, provideranthropic.ErrClaudeOAuthFlowNotFound) || errors.Is(err, provideropenai.ErrCodexOAuthFlowNotFound) {
		statusCode = http.StatusNotFound
		errorCode = "oauth_flow_not_found"
	} else if errors.Is(err, providerkimi.ErrAuthorizationExpired) || errors.Is(err, providerxai.ErrAuthorizationExpired) {
		statusCode = http.StatusGone
		errorCode = "device_flow_expired"
	} else if errors.Is(err, providerkimi.ErrAuthorizationDenied) || errors.Is(err, providerxai.ErrAuthorizationDenied) {
		statusCode = http.StatusForbidden
		errorCode = "device_flow_denied"
	} else if errors.Is(err, providerkimi.ErrAuthorizationPending) || errors.Is(err, providerxai.ErrAuthorizationPending) || errors.Is(err, provideropenai.ErrCodexAuthorizationPending) {
		statusCode = http.StatusConflict
		errorCode = "device_flow_pending"
	} else if errors.Is(err, providergoogle.ErrAntigravityFlowInProgress) || errors.Is(err, provideranthropic.ErrClaudeOAuthFlowInProgress) || errors.Is(err, provideropenai.ErrCodexOAuthFlowInProgress) {
		statusCode = http.StatusConflict
		errorCode = "oauth_flow_in_progress"
	} else if errors.Is(err, providerkimi.ErrFlowLimitReached) || errors.Is(err, providerxai.ErrFlowLimitReached) || errors.Is(err, provideropenai.ErrCodexFlowLimitReached) {
		statusCode = http.StatusTooManyRequests
		errorCode = "device_flow_limit_reached"
	} else if errors.Is(err, providergoogle.ErrAntigravityFlowLimitReached) || errors.Is(err, provideranthropic.ErrClaudeOAuthFlowLimitReached) || errors.Is(err, provideropenai.ErrCodexOAuthFlowLimitReached) {
		statusCode = http.StatusTooManyRequests
		errorCode = "oauth_flow_limit_reached"
	} else if errors.Is(err, provider.ErrAuthenticationRejected) {
		statusCode = http.StatusFailedDependency
		errorCode = "provider_authentication_rejected"
	} else if errors.Is(err, provider.ErrAuthenticationUnavailable) {
		statusCode = http.StatusServiceUnavailable
		errorCode = "provider_authentication_unavailable"
	} else if errors.Is(err, provider.ErrAuthenticationResponseInvalid) {
		statusCode = http.StatusBadGateway
		errorCode = "provider_authentication_invalid_response"
	} else if errors.Is(err, provider.ErrMetadataAuthentication) {
		statusCode = http.StatusFailedDependency
		errorCode = "provider_metadata_authentication_failed"
	} else if errors.Is(err, provider.ErrMetadataUnavailable) {
		statusCode = http.StatusServiceUnavailable
		errorCode = "provider_metadata_unavailable"
	} else if errors.Is(err, provider.ErrMetadataResponseInvalid) {
		statusCode = http.StatusBadGateway
		errorCode = "provider_metadata_invalid_response"
	} else if errors.Is(err, management.ErrSystemDefinitionImmutable) {
		statusCode = http.StatusConflict
		errorCode = "immutable_resource"
	}
	writeJSON(writer, statusCode, errorResponse{Error: errorCode})
}

// handleProtocolProfiles returns immutable metadata for profiles selectable by custom provider definitions.
// handleProtocolProfiles 返回可供自定义供应商定义选择的不可变 Profile 元数据。
func (s *Server) handleProtocolProfiles(writer http.ResponseWriter, _ *http.Request) {
	// profiles isolates the registry snapshot before it is translated into the HTTP contract.
	// profiles 在转换为 HTTP 合同前隔离注册表快照。
	profiles := s.control.Protocols.List()
	sort.Slice(profiles, func(left int, right int) bool {
		return profiles[left].ID < profiles[right].ID
	})
	// views contains only data that management needs to create or edit a provider definition.
	// views 仅包含管理面创建或编辑供应商定义所需的数据。
	views := make([]protocolProfileView, 0, len(profiles))
	for _, profile := range profiles {
		views = append(views, protocolProfileViewFrom(profile))
	}
	writeJSON(writer, http.StatusOK, protocolProfileListResponse{ProtocolProfiles: views})
}

// protocolProfileViewFrom translates immutable domain metadata into an explicit wire representation.
// protocolProfileViewFrom 将不可变领域元数据转换为显式 Wire 表示。
func protocolProfileViewFrom(profile providerconfig.ProtocolProfile) protocolProfileView {
	// capabilities isolates capability facts before JSON encoding.
	// capabilities 在 JSON 编码前隔离能力事实。
	capabilities := make([]protocolCapabilityView, 0, len(profile.Capabilities))
	for _, capability := range profile.Capabilities {
		capabilities = append(capabilities, protocolCapabilityView{Capability: capability.Capability, Status: capability.Status})
	}
	return protocolProfileView{
		ID:                 profile.ID,
		Version:            profile.Version,
		DisplayName:        profile.DisplayName,
		UserConfigurable:   profile.UserConfigurable,
		RuntimeReady:       profile.RuntimeReady,
		ModelDiscovery:     profile.ModelDiscovery,
		Capabilities:       capabilities,
		AllowedAuthMethods: append([]providerconfig.AuthMethodType(nil), profile.AllowedAuthMethods...),
	}
}

// handleProviderDefinitions returns all management-safe system and custom provider definitions.
// handleProviderDefinitions 返回全部管理安全的系统和自定义供应商定义。
func (s *Server) handleProviderDefinitions(writer http.ResponseWriter, request *http.Request) {
	definitions, errDefinitions := s.control.Query.ListDefinitions(request.Context())
	if errDefinitions != nil {
		writeControlError(writer, errDefinitions)
		return
	}
	writeJSON(writer, http.StatusOK, providerDefinitionListResponse{ProviderDefinitions: definitions})
}

// handleProviderGroups returns system provider brand groups without exposing secrets or routing internals.
// handleProviderGroups 返回系统供应商品牌分组，且不暴露 Secret 或路由内部实现。
func (s *Server) handleProviderGroups(writer http.ResponseWriter, request *http.Request) {
	groups, errGroups := s.control.Query.ListProviderGroups(request.Context())
	if errGroups != nil {
		writeControlError(writer, errGroups)
		return
	}
	writeJSON(writer, http.StatusOK, providerGroupListResponse{ProviderGroups: groups})
}

// handleCreateCustomDefinition creates one constrained user-owned custom provider definition.
// handleCreateCustomDefinition 创建一个受约束的用户拥有自定义供应商定义。
func (s *Server) handleCreateCustomDefinition(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createCustomDefinitionRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	definition, errCreate := s.control.Commands.CreateCustomDefinition(request.Context(), management.CreateCustomDefinitionInput{
		ID: payload.ID, DisplayName: payload.DisplayName, ProtocolProfileID: payload.ProtocolProfileID, AuthMethod: payload.AuthMethod,
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: definition.ID})
}

// handleOnboardCustomProvider atomically commits one whitelisted compatibility provider without exposing its secret.
// handleOnboardCustomProvider 原子提交一个白名单兼容供应商且不暴露其 Secret。
func (s *Server) handleOnboardCustomProvider(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[onboardCustomProviderRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	result, errOnboard := s.control.Commands.OnboardCustomProvider(request.Context(), management.OnboardCustomProviderInput{
		DisplayName: payload.DisplayName, Handle: payload.Handle, ProtocolProfileID: payload.ProtocolProfileID,
		BaseURL: payload.BaseURL, Secret: []byte(payload.Secret), UpstreamModelID: payload.UpstreamModelID, ModelDisplayName: payload.ModelDisplayName,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	configuration := result.Configuration
	writeJSON(writer, http.StatusCreated, customProviderOnboardingResponse{
		ProviderDefinitionID: configuration.Definition.ID, ProviderInstanceID: configuration.Instance.ID,
		CredentialID: configuration.Credential.ID, EndpointID: configuration.Endpoint.ID,
		BindingID: configuration.Binding.ID, ProviderModelID: result.ProviderModelID,
	})
}

// handleUpdateCustomDefinition replaces one existing custom definition only.
// handleUpdateCustomDefinition 仅替换一个既有自定义定义。
func (s *Server) handleUpdateCustomDefinition(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[updateCustomDefinitionRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	definition, errUpdate := s.control.Commands.UpdateCustomDefinition(request.Context(), management.UpdateCustomDefinitionInput{
		DefinitionID: request.PathValue("provider_definition_id"), DisplayName: payload.DisplayName, ProtocolProfileID: payload.ProtocolProfileID, AuthMethod: payload.AuthMethod,
	})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: definition.ID})
}

// handleProviderInstances returns all management-safe provider instance views.
// handleProviderInstances 返回全部管理安全供应商实例视图。
func (s *Server) handleProviderInstances(writer http.ResponseWriter, request *http.Request) {
	instances, errInstances := s.control.Query.ListInstances(request.Context())
	if errInstances != nil {
		writeControlError(writer, errInstances)
		return
	}
	writeJSON(writer, http.StatusOK, providerInstanceListResponse{ProviderInstances: instances})
}

// handleCreateInstance creates one provider instance from a system or custom definition.
// handleCreateInstance 根据系统或自定义定义创建一个供应商实例。
func (s *Server) handleCreateInstance(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createInstanceRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instance, errCreate := s.control.Commands.CreateInstance(request.Context(), management.CreateInstanceInput{
		ID: payload.ID, DefinitionID: payload.DefinitionID, Handle: payload.Handle, DisplayName: payload.DisplayName,
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: instance.ID})
}

// handleOnboardSystemProvider creates one complete system-provider configuration without exposing its secret.
// handleOnboardSystemProvider 创建一份完整系统供应商配置且不暴露其秘密。
func (s *Server) handleOnboardSystemProvider(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[onboardSystemProviderRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	onboarding, errOnboard := s.control.Commands.OnboardSystemProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, DisplayName: body.Name, AuthMethodID: body.AuthMethodID,
		CredentialLabel: body.Name, Secret: []byte(body.Secret),
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleOnboardVertexServiceAccount normalizes one uploaded document and returns only safe persisted identifiers.
// handleOnboardVertexServiceAccount 规范化一个上传文档并仅返回安全的持久化标识。
func (s *Server) handleOnboardVertexServiceAccount(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[onboardVertexServiceAccountRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	onboarding, errOnboard := s.control.Commands.OnboardVertexServiceAccountProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, AuthMethodID: "service_account", Secret: []byte(body.ServiceAccount),
	}, body.Location)
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleStartKimiDeviceFlow starts one server-owned Coding Plan verification session.
// handleStartKimiDeviceFlow 启动一个服务端拥有的 Coding Plan 验证会话。
func (s *Server) handleStartKimiDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.KimiDeviceFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardKimiDeviceFlow polls authorization once and atomically onboards a completed token.
// handleOnboardKimiDeviceFlow 轮询一次授权并原子录入已完成令牌。
func (s *Server) handleOnboardKimiDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[deviceFlowOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errPoll := s.control.KimiDeviceFlows.Poll(request.Context(), flowID)
	if errors.Is(errPoll, providerkimi.ErrAuthorizationPending) {
		writeJSON(writer, http.StatusAccepted, map[string]string{"status": "authorization_pending"})
		return
	}
	if errPoll != nil {
		writeControlError(writer, errPoll)
		return
	}
	defer s.control.KimiDeviceFlows.Release(flowID)
	secretValue, errMarshal := providerkimi.MarshalToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardKimiDeviceProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, DisplayName: body.Name, AuthMethodID: "device_flow",
		Secret: secretValue,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.KimiDeviceFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelKimiDeviceFlow removes one incomplete local verification session.
// handleCancelKimiDeviceFlow 删除一个未完成的本地验证会话。
func (s *Server) handleCancelKimiDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.KimiDeviceFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleStartXAIDeviceFlow starts one server-owned xAI account verification session.
// handleStartXAIDeviceFlow 启动一个服务端拥有的 xAI 账号验证会话。
func (s *Server) handleStartXAIDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.XAIDeviceFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardXAIDeviceFlow polls once and atomically onboards a completed xAI token.
// handleOnboardXAIDeviceFlow 轮询一次并原子录入已完成的 xAI Token。
func (s *Server) handleOnboardXAIDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[deviceFlowOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errPoll := s.control.XAIDeviceFlows.Poll(request.Context(), flowID)
	if errors.Is(errPoll, providerxai.ErrAuthorizationPending) {
		writeJSON(writer, http.StatusAccepted, map[string]string{"status": "authorization_pending"})
		return
	}
	if errPoll != nil {
		writeControlError(writer, errPoll)
		return
	}
	defer s.control.XAIDeviceFlows.Release(flowID)
	secretValue, errMarshal := providerxai.MarshalToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardXAIDeviceProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, DisplayName: body.Name, AuthMethodID: "device_flow",
		Secret: secretValue,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.XAIDeviceFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelXAIDeviceFlow removes one incomplete local xAI verification session.
// handleCancelXAIDeviceFlow 删除一个未完成的本地 xAI 验证会话。
func (s *Server) handleCancelXAIDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.XAIDeviceFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleStartCodexDeviceFlow starts one server-owned Codex verification session.
// handleStartCodexDeviceFlow 启动一个服务端拥有的 Codex 验证会话。
func (s *Server) handleStartCodexDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.CodexDeviceFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardCodexDeviceFlow polls once and atomically onboards a completed Codex token.
// handleOnboardCodexDeviceFlow 轮询一次并原子录入已完成的 Codex Token。
func (s *Server) handleOnboardCodexDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[deviceFlowOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errPoll := s.control.CodexDeviceFlows.Poll(request.Context(), flowID)
	if errors.Is(errPoll, provideropenai.ErrCodexAuthorizationPending) {
		writeJSON(writer, http.StatusAccepted, map[string]string{"status": "authorization_pending"})
		return
	}
	if errPoll != nil {
		writeControlError(writer, errPoll)
		return
	}
	defer s.control.CodexDeviceFlows.Release(flowID)
	secretValue, errMarshal := provideropenai.MarshalCodexToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardCodexDeviceProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, DisplayName: body.Name, AuthMethodID: "device_flow",
		Secret: secretValue,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.CodexDeviceFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelCodexDeviceFlow removes one incomplete local Codex verification session.
// handleCancelCodexDeviceFlow 删除一个未完成的本地 Codex 验证会话。
func (s *Server) handleCancelCodexDeviceFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.CodexDeviceFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleStartCodexOAuthFlow starts one server-owned Codex browser PKCE session.
// handleStartCodexOAuthFlow 启动一个服务端拥有的 Codex 浏览器 PKCE 会话。
func (s *Server) handleStartCodexOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.CodexOAuthFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardCodexOAuthFlow completes PKCE exchange and atomically stores one Codex account credential.
// handleOnboardCodexOAuthFlow 完成 PKCE 交换并原子存储一个 Codex 账号凭据。
func (s *Server) handleOnboardCodexOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[codexOAuthOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errComplete := s.control.CodexOAuthFlows.Complete(request.Context(), flowID, body.CallbackURL)
	if errComplete != nil {
		writeControlError(writer, errComplete)
		return
	}
	defer s.control.CodexOAuthFlows.Release(flowID)
	secretValue, errMarshal := provideropenai.MarshalCodexToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardCodexOAuthProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, AuthMethodID: "oauth", Secret: secretValue,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.CodexOAuthFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelCodexOAuthFlow removes one local Codex browser authorization session.
// handleCancelCodexOAuthFlow 删除一个本地 Codex 浏览器授权会话。
func (s *Server) handleCancelCodexOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.CodexOAuthFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleStartClaudeOAuthFlow starts one server-owned Claude Code PKCE authorization session.
// handleStartClaudeOAuthFlow 启动一个服务端拥有的 Claude Code PKCE 授权会话。
func (s *Server) handleStartClaudeOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.ClaudeOAuthFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardClaudeOAuthFlow completes PKCE exchange and atomically stores one Claude Code account credential.
// handleOnboardClaudeOAuthFlow 完成 PKCE 交换并原子存储一个 Claude Code 账号凭据。
func (s *Server) handleOnboardClaudeOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[claudeOAuthOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errComplete := s.control.ClaudeOAuthFlows.Complete(request.Context(), flowID, body.CallbackURL)
	if errComplete != nil {
		writeControlError(writer, errComplete)
		return
	}
	defer s.control.ClaudeOAuthFlows.Release(flowID)
	secretValue, errMarshal := provideranthropic.MarshalClaudeToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardClaudeOAuthProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, AuthMethodID: "oauth", Secret: secretValue,
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.ClaudeOAuthFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelClaudeOAuthFlow removes one incomplete local Claude authorization session.
// handleCancelClaudeOAuthFlow 删除一个未完成的本地 Claude 授权会话。
func (s *Server) handleCancelClaudeOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.ClaudeOAuthFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleStartAntigravityOAuthFlow starts one server-owned Google consent session.
// handleStartAntigravityOAuthFlow 启动一个服务端拥有的 Google 同意授权会话。
func (s *Server) handleStartAntigravityOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	flow, errStart := s.control.AntigravityOAuthFlows.Start(request.Context())
	if errStart != nil {
		writeControlError(writer, errStart)
		return
	}
	writeJSON(writer, http.StatusCreated, flow)
}

// handleOnboardAntigravityOAuthFlow completes consent and atomically stores the account and project credential.
// handleOnboardAntigravityOAuthFlow 完成同意授权并原子存储账号与项目凭据。
func (s *Server) handleOnboardAntigravityOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[antigravityOAuthOnboardRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	flowID := request.PathValue("flow_id")
	token, errComplete := s.control.AntigravityOAuthFlows.Complete(request.Context(), flowID, body.CallbackURL)
	if errComplete != nil {
		writeControlError(writer, errComplete)
		return
	}
	defer s.control.AntigravityOAuthFlows.Release(flowID)
	secretValue, errMarshal := providergoogle.MarshalAntigravityToken(token)
	if errMarshal != nil {
		writeControlError(writer, errMarshal)
		return
	}
	defer clear(secretValue)
	onboarding, errOnboard := s.control.Commands.OnboardAntigravityOAuthProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, AuthMethodID: "oauth", Secret: secretValue,
		ScopeRefs: []providerconfig.ScopeReference{{Kind: "project", ID: token.ProjectID}},
	})
	if errOnboard != nil {
		writeControlError(writer, errOnboard)
		return
	}
	s.control.AntigravityOAuthFlows.Cancel(flowID)
	response := onboardSystemProviderResponse{ProviderInstanceID: onboarding.Instance.ID, CredentialID: onboarding.Credential.ID}
	for _, endpoint := range onboarding.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	for _, binding := range onboarding.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleCancelAntigravityOAuthFlow removes one incomplete local consent session.
// handleCancelAntigravityOAuthFlow 删除一个未完成的本地同意授权会话。
func (s *Server) handleCancelAntigravityOAuthFlow(writer http.ResponseWriter, request *http.Request) {
	s.control.AntigravityOAuthFlows.Cancel(request.PathValue("flow_id"))
	writer.WriteHeader(http.StatusNoContent)
}

// handleRefreshProviderCredential refreshes one supported protected provider token and returns only its metadata identifier.
// handleRefreshProviderCredential 刷新一个受支持的受保护供应商 Token 并仅返回其元数据标识。
func (s *Server) handleRefreshProviderCredential(writer http.ResponseWriter, request *http.Request) {
	instanceID := request.PathValue("provider_instance_id")
	credentialID := request.PathValue("credential_id")
	instance, errInstance := s.control.Query.GetInstance(request.Context(), instanceID)
	if errInstance != nil {
		writeControlError(writer, errInstance)
		return
	}
	var credential providerconfig.Credential
	var errRefresh error
	switch instance.DefinitionID {
	case bootstrap.KimiCodingDefinitionID:
		if s.control.KimiTokens == nil {
			errRefresh = errors.New("Kimi token refresh is unavailable")
		} else {
			credential, errRefresh = s.control.KimiTokens.RefreshCredential(request.Context(), instanceID, credentialID)
		}
	case bootstrap.XAIOAuthDefinitionID:
		if s.control.XAITokens == nil {
			errRefresh = errors.New("xAI token refresh is unavailable")
		} else {
			credential, errRefresh = s.control.XAITokens.RefreshCredential(request.Context(), instanceID, credentialID)
		}
	case bootstrap.OpenAICodexDefinitionID:
		if s.control.CodexTokens == nil {
			errRefresh = errors.New("Codex token refresh is unavailable")
		} else {
			credential, errRefresh = s.control.CodexTokens.RefreshCredential(request.Context(), instanceID, credentialID)
		}
	case bootstrap.AnthropicClaudeCodeDefinitionID:
		if s.control.ClaudeTokens == nil {
			errRefresh = errors.New("Claude token refresh is unavailable")
		} else {
			credential, errRefresh = s.control.ClaudeTokens.RefreshCredential(request.Context(), instanceID, credentialID)
		}
	case bootstrap.GoogleAntigravityDefinitionID:
		if s.control.AntigravityTokens == nil {
			errRefresh = errors.New("Antigravity token refresh is unavailable")
		} else {
			credential, errRefresh = s.control.AntigravityTokens.RefreshCredential(request.Context(), instanceID, credentialID)
		}
	default:
		errRefresh = errors.New("provider credential does not support explicit refresh")
	}
	if errRefresh != nil {
		writeControlError(writer, errRefresh)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// handleRefreshProviderMetadata refreshes provider-native account metadata and returns the safe catalog view.
// handleRefreshProviderMetadata 刷新供应商原生账号元数据并返回安全目录视图。
func (s *Server) handleRefreshProviderMetadata(writer http.ResponseWriter, request *http.Request) {
	if s.control.MetadataRefresh == nil {
		writeJSON(writer, http.StatusNotImplemented, errorResponse{Error: "provider_metadata_refresh_unavailable"})
		return
	}
	instanceID := request.PathValue("provider_instance_id")
	if _, errRefresh := s.control.MetadataRefresh.Refresh(request.Context(), instanceID, time.Now().UTC()); errRefresh != nil {
		writeControlError(writer, errRefresh)
		return
	}
	view, errView := s.control.Query.GetCatalog(request.Context(), instanceID)
	if errView != nil {
		writeControlError(writer, errView)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

// handleProviderInstance returns one management-safe provider instance view.
// handleProviderInstance 返回一个管理安全供应商实例视图。
func (s *Server) handleProviderInstance(writer http.ResponseWriter, request *http.Request) {
	instance, errInstance := s.control.Query.GetInstance(request.Context(), request.PathValue("provider_instance_id"))
	if errInstance != nil {
		writeControlError(writer, errInstance)
		return
	}
	writeJSON(writer, http.StatusOK, instance)
}

// handleUpdateInstance replaces editable provider instance identity fields.
// handleUpdateInstance 替换可编辑供应商实例身份字段。
func (s *Server) handleUpdateInstance(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[updateInstanceRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instance, errUpdate := s.control.Commands.UpdateInstance(request.Context(), management.UpdateInstanceInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), Handle: payload.Handle, DisplayName: payload.DisplayName,
	})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: instance.ID})
}

// handleSetInstanceEnabled enables a locally complete instance or disables one immediately.
// handleSetInstanceEnabled 启用一个本地闭合实例或立即禁用一个实例。
func (s *Server) handleSetInstanceEnabled(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[setEnabledRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instance, errSet := s.control.Commands.SetInstanceEnabled(request.Context(), request.PathValue("provider_instance_id"), payload.Enabled)
	if errSet != nil {
		writeControlError(writer, errSet)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: instance.ID})
}

// handleProviderCatalog returns one management-safe catalog including local model enablement state.
// handleProviderCatalog 返回一个包含本地模型启停状态的管理安全目录。
func (s *Server) handleProviderCatalog(writer http.ResponseWriter, request *http.Request) {
	providerCatalog, errCatalog := s.control.Query.GetCatalog(request.Context(), request.PathValue("provider_instance_id"))
	if errCatalog != nil {
		writeControlError(writer, errCatalog)
		return
	}
	writeJSON(writer, http.StatusOK, providerCatalog)
}

// handleCustomCatalog returns the complete operator-managed catalog document for one custom provider instance.
// handleCustomCatalog 为一个自定义供应商实例返回完整的操作员管理目录文档。
func (s *Server) handleCustomCatalog(writer http.ResponseWriter, request *http.Request) {
	snapshot, errCatalog := s.control.CustomCatalogs.GetCustomCatalog(request.Context(), request.PathValue("provider_instance_id"))
	if errCatalog != nil {
		writeControlError(writer, errCatalog)
		return
	}
	writeJSON(writer, http.StatusOK, customCatalogDocumentFromSnapshot(snapshot))
}

// handleSaveCustomCatalog validates and atomically replaces one complete user-declared catalog document.
// handleSaveCustomCatalog 校验并原子替换一份完整的用户声明目录文档。
func (s *Server) handleSaveCustomCatalog(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[customCatalogDocument](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	// observedAt records the server acceptance instant instead of trusting a browser-provided clock.
	// observedAt 记录服务端接受时刻，而不信任浏览器提供的时钟。
	observedAt := time.Now().UTC()
	snapshot, errSave := s.control.CustomCatalogs.SaveCustomCatalog(request.Context(), customCatalogInput(request.PathValue("provider_instance_id"), payload, observedAt))
	if errSave != nil {
		writeControlError(writer, errSave)
		return
	}
	writeJSON(writer, http.StatusOK, customCatalogDocumentFromSnapshot(snapshot))
}

// customCatalogInput converts the strict management document into server-owned catalog records.
// customCatalogInput 将严格管理文档转换为服务端拥有的目录记录。
func customCatalogInput(providerInstanceID string, document customCatalogDocument, observedAt time.Time) management.SaveCustomCatalogInput {
	// models receive ownership, provenance, entitlement semantics, and revisions exclusively from the service boundary.
	// models 仅从服务边界获得归属、来源、授权语义和修订号。
	models := make([]catalog.ProviderModel, 0, len(document.Models))
	for _, model := range document.Models {
		models = append(models, catalog.ProviderModel{
			ID:                 model.ID,
			ProviderInstanceID: providerInstanceID,
			UpstreamModelID:    model.UpstreamModelID,
			DisplayName:        model.DisplayName,
			Source:             catalog.ModelSourceUserDeclared,
			EntitlementMode:    catalog.EntitlementAllBoundCredentials,
		})
	}
	// offerings receive the exact parent instance and service-owned revision fields.
	// offerings 获得精确父实例和服务端拥有的修订字段。
	offerings := make([]catalog.ModelOffering, 0, len(document.Offerings))
	for _, offering := range document.Offerings {
		offerings = append(offerings, catalog.ModelOffering{
			ID:                 offering.ID,
			ProviderInstanceID: providerInstanceID,
			ProviderModelID:    offering.ProviderModelID,
			UpstreamModelID:    offering.UpstreamModelID,
			Capabilities:       capabilityFromView(offering.Capabilities),
		})
	}
	// profiles receive the exact parent instance and service-owned revision fields.
	// profiles 获得精确父实例和服务端拥有的修订字段。
	profiles := make([]catalog.ExecutionProfile, 0, len(document.Profiles))
	for _, profile := range document.Profiles {
		profiles = append(profiles, catalog.ExecutionProfile{
			ID:                         profile.ID,
			ProviderInstanceID:         providerInstanceID,
			OfferingID:                 profile.OfferingID,
			DisplayName:                profile.DisplayName,
			Default:                    profile.Default,
			Capabilities:               capabilityFromView(profile.Capabilities),
			RequiredEntitlementClasses: append([]string(nil), profile.RequiredEntitlementClasses...),
			SwitchPolicy:               profile.SwitchPolicy,
			PoolPolicy:                 profile.PoolPolicy,
		})
	}
	return management.SaveCustomCatalogInput{
		ProviderInstanceID: providerInstanceID,
		Models:             models,
		Offerings:          offerings,
		Profiles:           profiles,
		ObservedAt:         observedAt,
	}
}

// customCatalogDocumentFromSnapshot converts server-owned records into the editable non-secret document shape.
// customCatalogDocumentFromSnapshot 将服务端拥有记录转换为可编辑的非秘密文档形态。
func customCatalogDocumentFromSnapshot(snapshot catalog.Snapshot) customCatalogDocument {
	// document is initialized with allocated slices so management responses stay JSON-array stable.
	// document 使用已分配切片初始化，以保持管理响应中的 JSON 数组稳定。
	document := customCatalogDocument{
		Models:    make([]customCatalogModel, 0, len(snapshot.Models)),
		Offerings: make([]customCatalogOffering, 0, len(snapshot.Offerings)),
		Profiles:  make([]customCatalogProfile, 0, len(snapshot.Profiles)),
	}
	for _, model := range snapshot.Models {
		document.Models = append(document.Models, customCatalogModel{ID: model.ID, UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName})
	}
	for _, offering := range snapshot.Offerings {
		document.Offerings = append(document.Offerings, customCatalogOffering{
			ID: offering.ID, ProviderModelID: offering.ProviderModelID, UpstreamModelID: offering.UpstreamModelID,
			Capabilities: capabilityView(offering.Capabilities),
		})
	}
	for _, profile := range snapshot.Profiles {
		document.Profiles = append(document.Profiles, customCatalogProfile{
			ID: profile.ID, OfferingID: profile.OfferingID, DisplayName: profile.DisplayName, Default: profile.Default,
			Capabilities: capabilityView(profile.Capabilities), RequiredEntitlementClasses: append([]string{}, profile.RequiredEntitlementClasses...),
			SwitchPolicy: profile.SwitchPolicy, PoolPolicy: profile.PoolPolicy,
		})
	}
	sort.Slice(document.Models, func(left int, right int) bool {
		return document.Models[left].ID < document.Models[right].ID
	})
	sort.Slice(document.Offerings, func(left int, right int) bool {
		return document.Offerings[left].ID < document.Offerings[right].ID
	})
	sort.Slice(document.Profiles, func(left int, right int) bool {
		return document.Profiles[left].ID < document.Profiles[right].ID
	})
	return document
}

// capabilityFromView converts the explicit HTTP DTO without filling in absent capability facts.
// capabilityFromView 转换显式 HTTP DTO，且不填充缺失的能力事实。
func capabilityFromView(view management.CapabilityView) catalog.ModelCapabilities {
	return catalog.ModelCapabilities{
		Tokens: catalog.TokenLimits{
			ContextWindow:      catalog.OptionalTokenLimit{Known: view.ContextWindow.Known, Value: view.ContextWindow.Value},
			MaxInputTokens:     catalog.OptionalTokenLimit{Known: view.MaxInputTokens.Known, Value: view.MaxInputTokens.Value},
			MaxOutputTokens:    catalog.OptionalTokenLimit{Known: view.MaxOutputTokens.Known, Value: view.MaxOutputTokens.Value},
			MaxReasoningTokens: catalog.OptionalTokenLimit{Known: view.MaxReasoningTokens.Known, Value: view.MaxReasoningTokens.Value},
		},
		Recommendations: catalog.TokenRecommendations{
			OutputTokens:    catalog.OptionalTokenLimit{Known: view.RecommendedOutputTokens.Known, Value: view.RecommendedOutputTokens.Value},
			ReasoningTokens: catalog.OptionalTokenLimit{Known: view.RecommendedReasoningTokens.Known, Value: view.RecommendedReasoningTokens.Value},
		},
		ToolCalling:            view.ToolCalling,
		ParallelToolCalls:      view.ParallelToolCalls,
		StreamingToolArguments: view.StreamingToolArguments,
		StrictJSONSchema:       view.StrictJSONSchema,
		Reasoning:              view.Reasoning,
		InputModalities:        append([]string{}, view.InputModalities...),
		OutputModalities:       append([]string{}, view.OutputModalities...),
	}
}

// capabilityView converts catalog capability metadata into the editable explicit HTTP DTO.
// capabilityView 将目录能力元数据转换为可编辑的显式 HTTP DTO。
func capabilityView(capabilities catalog.ModelCapabilities) management.CapabilityView {
	return management.CapabilityView{
		ContextWindow:              management.TokenLimitView{Known: capabilities.Tokens.ContextWindow.Known, Value: capabilities.Tokens.ContextWindow.Value},
		MaxInputTokens:             management.TokenLimitView{Known: capabilities.Tokens.MaxInputTokens.Known, Value: capabilities.Tokens.MaxInputTokens.Value},
		MaxOutputTokens:            management.TokenLimitView{Known: capabilities.Tokens.MaxOutputTokens.Known, Value: capabilities.Tokens.MaxOutputTokens.Value},
		MaxReasoningTokens:         management.TokenLimitView{Known: capabilities.Tokens.MaxReasoningTokens.Known, Value: capabilities.Tokens.MaxReasoningTokens.Value},
		RecommendedOutputTokens:    management.TokenLimitView{Known: capabilities.Recommendations.OutputTokens.Known, Value: capabilities.Recommendations.OutputTokens.Value},
		RecommendedReasoningTokens: management.TokenLimitView{Known: capabilities.Recommendations.ReasoningTokens.Known, Value: capabilities.Recommendations.ReasoningTokens.Value},
		ToolCalling:                capabilities.ToolCalling,
		ParallelToolCalls:          capabilities.ParallelToolCalls,
		StreamingToolArguments:     capabilities.StreamingToolArguments,
		StrictJSONSchema:           capabilities.StrictJSONSchema,
		Reasoning:                  capabilities.Reasoning,
		InputModalities:            append([]string{}, capabilities.InputModalities...),
		OutputModalities:           append([]string{}, capabilities.OutputModalities...),
	}
}

// handleSetModelEnabled updates one instance-level provider model availability policy.
// handleSetModelEnabled 更新一个实例级供应商模型可用性策略。
func (s *Server) handleSetModelEnabled(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[setEnabledRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instance, errSet := s.control.ModelAccess.SetModelEnabled(request.Context(), management.SetModelEnabledInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), ProviderModelID: request.PathValue("provider_model_id"), Enabled: payload.Enabled,
	})
	if errSet != nil {
		writeControlError(writer, errSet)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: instance.ID})
}

// handleEndpoints returns management-safe endpoints for one provider instance.
// handleEndpoints 返回一个供应商实例的管理安全端点。
func (s *Server) handleEndpoints(writer http.ResponseWriter, request *http.Request) {
	endpoints, errEndpoints := s.control.Query.ListEndpoints(request.Context(), request.PathValue("provider_instance_id"))
	if errEndpoints != nil {
		writeControlError(writer, errEndpoints)
		return
	}
	writeJSON(writer, http.StatusOK, endpointListResponse{Endpoints: endpoints})
}

// handleCreateEndpoint creates one endpoint for a provider instance.
// handleCreateEndpoint 为一个供应商实例创建一个端点。
func (s *Server) handleCreateEndpoint(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createEndpointRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	endpoint, errCreate := s.control.Commands.AddEndpoint(request.Context(), management.AddEndpointInput{
		ID: payload.ID, ProviderInstanceID: request.PathValue("provider_instance_id"), BaseURL: payload.BaseURL, Region: payload.Region,
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: endpoint.ID})
}

// handleUpdateEndpoint replaces one endpoint for a provider instance.
// handleUpdateEndpoint 替换一个供应商实例端点。
func (s *Server) handleUpdateEndpoint(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[updateEndpointRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	endpoint, errUpdate := s.control.Commands.UpdateEndpoint(request.Context(), management.UpdateEndpointInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), EndpointID: request.PathValue("endpoint_id"),
		BaseURL: payload.BaseURL, Region: payload.Region, Status: payload.Status,
	})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: endpoint.ID})
}

// handleCredentials returns management-safe credentials for one provider instance.
// handleCredentials 返回一个供应商实例的管理安全凭据。
func (s *Server) handleCredentials(writer http.ResponseWriter, request *http.Request) {
	credentials, errCredentials := s.control.Query.ListCredentials(request.Context(), request.PathValue("provider_instance_id"))
	if errCredentials != nil {
		writeControlError(writer, errCredentials)
		return
	}
	writeJSON(writer, http.StatusOK, credentialListResponse{Credentials: credentials})
}

// handleCreateCredential stores transient upstream auth material through the protected SecretStore.
// handleCreateCredential 通过受保护 SecretStore 存储临时上游认证材料。
func (s *Server) handleCreateCredential(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createCredentialRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errCreate := s.control.Commands.AddCredential(request.Context(), management.AddCredentialInput{
		ID: payload.ID, ProviderInstanceID: request.PathValue("provider_instance_id"), AuthMethodID: payload.AuthMethodID, Label: payload.Label,
		PrincipalKey: payload.PrincipalKey, ScopeRefs: payload.ScopeRefs, Secret: []byte(payload.Secret),
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: credential.ID})
}

// handleUpdateCredential replaces non-secret metadata and never reads secret bytes.
// handleUpdateCredential 替换非秘密元数据且绝不读取 Secret 字节。
func (s *Server) handleUpdateCredential(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[updateCredentialRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errUpdate := s.control.Commands.UpdateCredential(request.Context(), management.UpdateCredentialInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), CredentialID: request.PathValue("credential_id"), Label: payload.Label,
		PrincipalKey: payload.PrincipalKey, ScopeRefs: payload.ScopeRefs,
	})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// handleRotateCredentialSecret replaces protected credential bytes and never returns them.
// handleRotateCredentialSecret 替换受保护凭据字节且绝不返回它们。
func (s *Server) handleRotateCredentialSecret(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[rotateCredentialSecretRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errRotate := s.control.Commands.RotateCredentialSecret(request.Context(), management.RotateCredentialSecretInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), CredentialID: request.PathValue("credential_id"), Secret: []byte(payload.Secret),
	})
	if errRotate != nil {
		writeControlError(writer, errRotate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// handleSetCredentialStatus changes one credential lifecycle status without reading secret material.
// handleSetCredentialStatus 更改一个凭据生命周期状态且不读取 Secret 材料。
func (s *Server) handleSetCredentialStatus(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[setCredentialStatusRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errSet := s.control.Commands.SetCredentialStatus(request.Context(), management.SetCredentialStatusInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), CredentialID: request.PathValue("credential_id"), Status: payload.Status, CoolingUntil: payload.CoolingUntil,
	})
	if errSet != nil {
		writeControlError(writer, errSet)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// handleBindings returns management-safe bindings for one provider instance.
// handleBindings 返回一个供应商实例的管理安全绑定。
func (s *Server) handleBindings(writer http.ResponseWriter, request *http.Request) {
	bindings, errBindings := s.control.Query.ListBindings(request.Context(), request.PathValue("provider_instance_id"))
	if errBindings != nil {
		writeControlError(writer, errBindings)
		return
	}
	writeJSON(writer, http.StatusOK, bindingListResponse{Bindings: bindings})
}

// handleCreateBinding creates one credential-to-endpoint binding.
// handleCreateBinding 创建一个凭据到端点绑定。
func (s *Server) handleCreateBinding(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createBindingRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	binding, errCreate := s.control.Commands.AddBinding(request.Context(), management.AddBindingInput{
		ID: payload.ID, ProviderInstanceID: request.PathValue("provider_instance_id"), EndpointID: payload.EndpointID,
		CredentialID: payload.CredentialID, AllowedModelIDs: payload.AllowedModelIDs, Priority: payload.Priority,
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: binding.ID})
}

// handleUpdateBinding replaces one credential-to-endpoint binding.
// handleUpdateBinding 替换一个凭据到端点绑定。
func (s *Server) handleUpdateBinding(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[updateBindingRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	binding, errUpdate := s.control.Commands.UpdateBinding(request.Context(), management.UpdateBindingInput{
		ProviderInstanceID: request.PathValue("provider_instance_id"), BindingID: request.PathValue("binding_id"),
		EndpointID: payload.EndpointID, CredentialID: payload.CredentialID, AllowedModelIDs: payload.AllowedModelIDs, Priority: payload.Priority, Enabled: payload.Enabled,
	})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, identifierResponse{ID: binding.ID})
}

// handleAPIKeys returns plaintext call-plane API keys only after management authentication.
// handleAPIKeys 仅在管理认证后返回明文调用面 API 密钥。
func (s *Server) handleAPIKeys(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, apiKeyListResponse{APIKeys: s.control.APIKeys.ListAPIKeys()})
}

// handleCreateAPIKey stores one explicit plaintext call-plane API key.
// handleCreateAPIKey 存储一个显式明文调用面 API 密钥。
func (s *Server) handleCreateAPIKey(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[apiKeyRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	apiKey, errCreate := s.control.APIKeys.CreateAPIKey(runtimeconfig.APIKeyInput{Name: payload.Name, Key: payload.Key, Enabled: payload.Enabled})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, apiKey)
}

// handleUpdateAPIKey replaces one explicit plaintext call-plane API key.
// handleUpdateAPIKey 替换一个显式明文调用面 API 密钥。
func (s *Server) handleUpdateAPIKey(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[apiKeyRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	apiKey, errUpdate := s.control.APIKeys.UpdateAPIKey(request.PathValue("api_key_id"), runtimeconfig.APIKeyInput{Name: payload.Name, Key: payload.Key, Enabled: payload.Enabled})
	if errUpdate != nil {
		writeControlError(writer, errUpdate)
		return
	}
	writeJSON(writer, http.StatusOK, apiKey)
}

// handleDeleteAPIKey removes one call-plane API key by immutable identifier.
// handleDeleteAPIKey 按不可变标识删除一个调用面 API 密钥。
func (s *Server) handleDeleteAPIKey(writer http.ResponseWriter, request *http.Request) {
	if errDelete := s.control.APIKeys.DeleteAPIKey(request.PathValue("api_key_id")); errDelete != nil {
		writeControlError(writer, errDelete)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// handleCallModels returns enabled models and capabilities without fusing identically named provider models.
// handleCallModels 返回启用模型和能力，且不融合名称相同的供应商模型。
func (s *Server) handleCallModels(writer http.ResponseWriter, request *http.Request) {
	instances, errInstances := s.control.Query.ListInstances(request.Context())
	if errInstances != nil {
		writeControlError(writer, errInstances)
		return
	}
	models := make([]callModelView, 0)
	for _, instance := range instances {
		if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
			continue
		}
		providerCatalog, errCatalog := s.control.Query.GetCatalog(request.Context(), instance.ID)
		if errors.Is(errCatalog, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCatalog != nil {
			writeControlError(writer, errCatalog)
			return
		}
		for _, model := range providerCatalog.Models {
			if !model.Enabled {
				continue
			}
			models = append(models, callModelView{
				ProviderInstanceID:   instance.ID,
				ProviderHandle:       instance.Handle,
				ProviderDefinitionID: instance.DefinitionID,
				Model:                model,
			})
		}
	}
	writeJSON(writer, http.StatusOK, callModelListResponse{Models: models})
}
