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
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
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
	// AuthenticateAPIKeyID verifies one call-plane bearer and returns its non-secret identifier.
	// AuthenticateAPIKeyID 校验一个调用面 Bearer 并返回其非秘密标识。
	AuthenticateAPIKeyID(string) (string, bool)
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
	// ConfigureProvider creates one credential-independent provider configuration and catalog.
	// ConfigureProvider 创建一个独立于凭据的供应商配置与目录。
	ConfigureProvider(context.Context, management.ConfigureProviderInput) (management.ProviderConfigurationResult, error)
	// DeleteProviderConfiguration removes one credential-free provider configuration.
	// DeleteProviderConfiguration 删除一个不含凭据的供应商配置。
	DeleteProviderConfiguration(context.Context, string) error
	// DiscoverCustomProviderModels reads a standard model list with one explicit same-instance credential.
	// DiscoverCustomProviderModels 使用一个显式同实例凭据读取标准模型清单。
	DiscoverCustomProviderModels(context.Context, string, string) (catalog.Snapshot, error)
	// SaveCustomProviderModels replaces one custom provider's simplified model catalog.
	// SaveCustomProviderModels 替换一个自定义供应商的简化模型目录。
	SaveCustomProviderModels(context.Context, string, []management.InitialProviderModelInput) (catalog.Snapshot, error)
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
	// AttachCredential creates one credential, closes its access bindings, and activates the provider configuration.
	// AttachCredential 创建一个凭据、闭合其访问绑定并激活供应商配置。
	AttachCredential(context.Context, management.AddCredentialInput) (management.CredentialAttachment, error)
	// AttachAcquiredCredential attaches one server-acquired provider credential to an existing configuration.
	// AttachAcquiredCredential 将一个服务端获取的供应商凭据附加到既有配置。
	AttachAcquiredCredential(context.Context, management.AttachAcquiredCredentialInput) (management.CredentialAttachment, error)
	// UpdateCredential replaces one credential's non-secret metadata.
	// UpdateCredential 替换一个凭据的非秘密元数据。
	UpdateCredential(context.Context, management.UpdateCredentialInput) (providerconfig.Credential, error)
	// RotateCredentialSecret replaces one credential's protected secret bytes.
	// RotateCredentialSecret 替换一个凭据的受保护 Secret 字节。
	RotateCredentialSecret(context.Context, management.RotateCredentialSecretInput) (providerconfig.Credential, error)
	// ReauthorizeCredential replaces one provider-owned token after exact account validation.
	// ReauthorizeCredential 在精确账号校验后替换一个供应商拥有的 Token。
	ReauthorizeCredential(context.Context, management.ReauthorizeCredentialInput) (providerconfig.Credential, error)
	// DeleteCredential removes one credential graph while retaining its provider configuration.
	// DeleteCredential 删除一个凭据图，同时保留其供应商配置。
	DeleteCredential(context.Context, string, string) (providerconfig.CredentialDeletion, error)
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

// ProviderCredentialModelDiscovery refreshes model metadata with one explicitly selected provider credential.
// ProviderCredentialModelDiscovery 使用一个显式选择的供应商凭据刷新模型元数据。
type ProviderCredentialModelDiscovery interface {
	// RefreshWithCredential atomically discovers models with a same-instance credential.
	// RefreshWithCredential 使用同实例凭据原子发现模型。
	RefreshWithCredential(context.Context, string, string, time.Time) (catalog.Snapshot, error)
}

// ProviderMetadataRefreshScheduler accepts deduplicated immediate refresh triggers.
// ProviderMetadataRefreshScheduler 接收去重后的即时刷新触发。
type ProviderMetadataRefreshScheduler interface {
	// Trigger queues one provider instance unless it is already pending.
	// Trigger 将一个供应商实例入队，除非它已经待处理。
	Trigger(string) bool
}

// ProtocolProfileQuery exposes immutable process-owned protocol metadata to the management surface.
// ProtocolProfileQuery 向管理接口面暴露不可变的进程拥有协议元数据。
type ProtocolProfileQuery interface {
	// List returns an isolated stable snapshot of registered protocol profiles.
	// List 返回已注册协议 Profile 的隔离稳定快照。
	List() []providerconfig.ProtocolProfile
}

// RoutingManagement exposes persisted scheduling and manual plan mutations.
// RoutingManagement 暴露持久化调度与人工套餐变更。
type RoutingManagement interface {
	// GetSettings returns Router-wide scheduling settings.
	// GetSettings 返回 Router 全局调度设置。
	GetSettings(context.Context) (routingstate.Settings, error)
	// SetDefaultRoutingStrategy changes the inherited scheduling strategy.
	// SetDefaultRoutingStrategy 修改继承的调度策略。
	SetDefaultRoutingStrategy(context.Context, providerconfig.RoutingStrategy) (routingstate.Settings, error)
	// SetInstanceRoutingStrategy sets or clears one provider override.
	// SetInstanceRoutingStrategy 设置或清除一个供应商覆盖策略。
	SetInstanceRoutingStrategy(context.Context, string, providerconfig.RoutingStrategy) (providerconfig.ProviderInstance, error)
	// SetCredentialPriority updates account ordering independently from endpoints.
	// SetCredentialPriority 独立于入口更新账号顺序。
	SetCredentialPriority(context.Context, string, string, int) (providerconfig.Credential, error)
	// SetCredentialPlan replaces one manual plan and exact entitlement matrix.
	// SetCredentialPlan 替换一个人工套餐与精确权益矩阵。
	SetCredentialPlan(context.Context, string, string, string) (providerconfig.Credential, error)
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
	// Routing optionally exposes scheduling and manual-plan settings.
	// Routing 可选暴露调度与人工套餐设置。
	Routing RoutingManagement
	// Protocols exposes custom-provider-selectable protocol metadata.
	// Protocols 暴露可供自定义供应商选择的协议元数据。
	Protocols ProtocolProfileQuery
	// APIKeys owns plaintext call-plane key lifecycle operations.
	// APIKeys 管理明文调用面密钥生命周期操作。
	APIKeys APIKeyManager
	// Auth verifies route-scoped bearer values.
	// Auth 校验路由作用域 Bearer 值。
	Auth KeyAuthenticator
	// Resources owns authenticated Router resource ingestion and lifecycle operations.
	// Resources 拥有已认证 Router 资源接收与生命周期操作。
	Resources ResourceGateway
	// InputPlans owns authenticated conditional media planning.
	// InputPlans 拥有已认证条件媒体规划。
	InputPlans InputPlanService
	// Executions owns authenticated durable execution lifecycle operations.
	// Executions 拥有已认证持久化执行生命周期操作。
	Executions ExecutionService
	// ResourceDiagnostics optionally exposes management-safe resource metadata without call-plane owner secrets.
	// ResourceDiagnostics 可选暴露不含调用面所有者秘密的管理安全资源元数据。
	ResourceDiagnostics ResourceDiagnostics
	// ExecutionDiagnostics optionally exposes management-safe execution lifecycle snapshots.
	// ExecutionDiagnostics 可选暴露管理安全执行生命周期快照。
	ExecutionDiagnostics ExecutionDiagnostics
	// Targets verifies that discovery profiles are currently executable.
	// Targets 校验发现规格当前可执行。
	Targets TargetAvailability
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
	requiredDependencies := []any{c.Query, c.Commands, c.ModelAccess, c.CustomCatalogs, c.Protocols, c.APIKeys, c.Auth, c.Resources, c.InputPlans, c.Executions, c.Targets}
	for _, dependency := range requiredDependencies {
		if isNilHTTPDependency(dependency) {
			return errors.New("complete authenticated control plane is required")
		}
	}
	// optionalDependencies may be absent, but a typed nil would register or dispatch an unusable service.
	// optionalDependencies 可以缺省，但带类型的 nil 会注册或分派一个不可用服务。
	optionalDependencies := []any{c.MetadataRefresh, c.Routing, c.KimiDeviceFlows, c.KimiTokens, c.XAIDeviceFlows, c.XAITokens, c.CodexDeviceFlows, c.CodexOAuthFlows, c.CodexTokens, c.ClaudeOAuthFlows, c.ClaudeTokens, c.AntigravityOAuthFlows, c.AntigravityTokens}
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

// callInformationKind identifies one closed read-only Vulcan information projection.
// callInformationKind 标识一种封闭的只读 Vulcan 信息投影。
type callInformationKind string

const (
	// callInformationInstances selects configured provider instances.
	// callInformationInstances 选择已配置供应商实例。
	callInformationInstances callInformationKind = "instances"
	// callInformationModels selects executable provider-scoped models.
	// callInformationModels 选择可执行的供应商作用域模型。
	callInformationModels callInformationKind = "models"
	// callInformationAccounts selects context profiles and their authorized accounts for one exact model.
	// callInformationAccounts 选择一个精确模型的上下文规格及其已授权账号。
	callInformationAccounts callInformationKind = "accounts"
	// callInformationServices selects executable provider-scoped special services.
	// callInformationServices 选择可执行的供应商作用域特殊服务。
	callInformationServices callInformationKind = "services"
	// callInformationUsage selects current usage for one exact model-account pair.
	// callInformationUsage 选择一个精确模型账号组合的当前用量。
	callInformationUsage callInformationKind = "usage"
)

// callInformationRequest selects one information shape and its exact provider-owned identifiers.
// callInformationRequest 选择一种信息形态及其精确供应商所属标识。
type callInformationRequest struct {
	// Get selects exactly one registered information shape.
	// Get 精确选择一种已注册信息形态。
	Get callInformationKind `json:"get"`
	// ProviderInstanceID optionally constrains models or services and is required by account-scoped projections.
	// ProviderInstanceID 可选约束模型或服务，并且是账号作用域投影的必填项。
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	// ProviderModelID optionally selects one exact model and is required by accounts and usage.
	// ProviderModelID 可选选择一个精确模型，并且是 accounts 与 usage 的必填项。
	ProviderModelID string `json:"provider_model_id,omitempty"`
	// CredentialID selects one exact local account only for usage.
	// CredentialID 仅为 usage 选择一个精确本地账号。
	CredentialID string `json:"credential_id,omitempty"`
	// ProviderServiceID optionally selects one exact special service.
	// ProviderServiceID 可选选择一个精确特殊服务。
	ProviderServiceID string `json:"provider_service_id,omitempty"`
}

// callInformationInstancesResponse returns the instances branch of the information union.
// callInformationInstancesResponse 返回信息联合中的实例分支。
type callInformationInstancesResponse struct {
	// Get echoes the selected projection.
	// Get 回显已选投影。
	Get callInformationKind `json:"get"`
	// Instances contains safe configured provider instances.
	// Instances 包含安全的已配置供应商实例。
	Instances []management.ProviderInstanceView `json:"instances"`
}

// callInformationModelsResponse returns the models branch of the information union.
// callInformationModelsResponse 返回信息联合中的模型分支。
type callInformationModelsResponse struct {
	// Get echoes the selected projection.
	// Get 回显已选投影。
	Get callInformationKind `json:"get"`
	// Models contains non-fused models from individually selected provider instances.
	// Models 包含来自各自选定供应商实例且未融合的模型。
	Models []callModelView `json:"models"`
}

// callInformationAccountsResponse returns model contexts grouped with their concrete accounts.
// callInformationAccountsResponse 返回与具体账号分组的模型上下文。
type callInformationAccountsResponse struct {
	// Get echoes the selected projection.
	// Get 回显已选投影。
	Get callInformationKind `json:"get"`
	// Accounts contains context profiles and the authorized account set under each profile.
	// Accounts 包含上下文规格以及每个规格下的已授权账号集合。
	Accounts management.ModelContextsView `json:"accounts"`
}

// callInformationUsageResponse returns the usage branch of the information union.
// callInformationUsageResponse 返回信息联合中的用量分支。
type callInformationUsageResponse struct {
	// Get echoes the selected projection.
	// Get 回显已选投影。
	Get callInformationKind `json:"get"`
	// Usage contains current usage for the exact selected model and account.
	// Usage 包含精确选定模型与账号的当前用量。
	Usage management.ModelCredentialUsageView `json:"usage"`
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

// callInformationServicesResponse returns the services branch of the information union.
// callInformationServicesResponse 返回信息联合中的服务分支。
type callInformationServicesResponse struct {
	// Get echoes the selected projection.
	// Get 回显已选投影。
	Get callInformationKind `json:"get"`
	// Services contains non-fused exact service offerings.
	// Services 包含未融合精确服务产品。
	Services []callServiceView `json:"services"`
}

// callServiceView identifies one provider instance and one special service.
// callServiceView 标识一个供应商实例与一个特殊服务。
type callServiceView struct {
	// ProviderInstanceID fixes every later service execution.
	// ProviderInstanceID 固定每次后续服务执行。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderHandle is the stable workspace-visible instance alias.
	// ProviderHandle 是稳定工作区可见实例别名。
	ProviderHandle string `json:"provider_handle"`
	// ProviderDefinitionID identifies the underlying provider definition.
	// ProviderDefinitionID 标识底层供应商定义。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// Service contains the exact non-fused service capability view.
	// Service 包含精确未融合服务能力视图。
	Service management.ServiceView `json:"service"`
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

// configureProviderRequest decodes one credential-independent provider configuration.
// configureProviderRequest 解码一个独立于凭据的供应商配置。
type configureProviderRequest struct {
	// DefinitionID selects one exact provider definition.
	// DefinitionID 选择一个精确的供应商定义。
	DefinitionID string `json:"provider_definition_id"`
	// Handle is the stable call-plane routing identifier.
	// Handle 是稳定的调用面路由标识。
	Handle string `json:"handle"`
	// DisplayName is the management-facing provider instance name.
	// DisplayName 是管理界面显示的供应商实例名称。
	DisplayName string `json:"display_name"`
	// BaseURL supplies the endpoint only for custom providers.
	// BaseURL 仅为自定义供应商提供入口地址。
	BaseURL string `json:"base_url,omitempty"`
	// Region supplies optional custom-provider regional metadata.
	// Region 提供可选的自定义供应商区域元数据。
	Region string `json:"region,omitempty"`
	// EndpointParameters contains exact values declared by a system endpoint preset.
	// EndpointParameters 包含系统入口预设声明的精确参数值。
	EndpointParameters []endpointParameterValueRequest `json:"endpoint_parameters,omitempty"`
	// InitialModel optionally declares one exact custom-provider model and known limits.
	// InitialModel 可选声明一个精确自定义供应商模型及已知限制。
	InitialModel *initialProviderModelRequest `json:"initial_model,omitempty"`
}

// initialProviderModelRequest decodes one user-declared custom model without inferred capability values.
// initialProviderModelRequest 解码一个不推断能力值的用户声明自定义模型。
type initialProviderModelRequest struct {
	// UpstreamModelID is the exact provider wire model identifier.
	// UpstreamModelID 是精确的供应商 Wire 模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// DisplayName is the management-facing model name.
	// DisplayName 是管理界面显示的模型名称。
	DisplayName string `json:"display_name"`
	// ContextWindow is zero only when unknown.
	// ContextWindow 仅在未知时为零。
	ContextWindow int64 `json:"context_window,omitempty"`
	// MaxOutputTokens is zero only when unknown.
	// MaxOutputTokens 仅在未知时为零。
	MaxOutputTokens int64 `json:"max_output_tokens,omitempty"`
	// ToolCalling is one explicit normalized capability level.
	// ToolCalling 是一个显式规范化能力级别。
	ToolCalling catalog.CapabilityLevel `json:"tool_calling"`
	// Reasoning is one explicit normalized capability level.
	// Reasoning 是一个显式规范化能力级别。
	Reasoning catalog.CapabilityLevel `json:"reasoning"`
}

// customProviderModelsRequest decodes one complete simplified custom model replacement.
// customProviderModelsRequest 解码一个完整的简化自定义模型替换请求。
type customProviderModelsRequest struct {
	// Models contains the exact desired custom model set; an empty array deletes every model.
	// Models 包含精确期望的自定义模型集合；空数组会删除全部模型。
	Models []initialProviderModelRequest `json:"models"`
}

// endpointParameterValueRequest decodes one declared non-secret system endpoint parameter.
// endpointParameterValueRequest 解码一个已声明的非秘密系统端点参数。
type endpointParameterValueRequest struct {
	// ID identifies the exact parameter declared by the selected endpoint preset.
	// ID 标识所选端点预设声明的精确参数。
	ID string `json:"id"`
	// Value contains the operator-supplied non-secret parameter value.
	// Value 包含操作员提供的非秘密参数值。
	Value string `json:"value"`
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
	// PlanOptionID selects one code-owned plan when the authentication method requires manual declaration.
	// PlanOptionID 在认证方式要求人工声明时选择一个代码拥有套餐。
	PlanOptionID string `json:"plan_option_id,omitempty"`
	// CredentialPriority orders this account within its provider instance.
	// CredentialPriority 在供应商实例内排列该账号。
	CredentialPriority int `json:"credential_priority,omitempty"`
	// EndpointParameters contains only values declared by the selected system endpoint preset.
	// EndpointParameters 仅包含所选系统端点预设声明的值。
	EndpointParameters []endpointParameterValueRequest `json:"endpoint_parameters,omitempty"`
}

// onboardVertexServiceAccountRequest decodes one server-validated Vertex service-account upload.
// onboardVertexServiceAccountRequest 解码一次由服务端校验的 Vertex 服务账号上传。
type onboardVertexServiceAccountRequest struct {
	credentialReauthorizationTarget
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
	credentialReauthorizationTarget
	// DefinitionID must select the exact device-flow system product.
	// DefinitionID 必须选择精确的设备授权系统产品。
	DefinitionID string `json:"provider_definition_id"`
	// Name is required for Kimi and is the xAI fallback when its optional ID-token identity is absent.
	// Name 对 Kimi 必填，并在 xAI 的可选 ID Token 身份缺失时作为回退名称。
	Name string `json:"name"`
}

// credentialReauthorizationTarget optionally selects an existing credential instead of creating a provider instance.
// credentialReauthorizationTarget 可选选择一个既有凭据而不是创建供应商实例。
type credentialReauthorizationTarget struct {
	// ProviderInstanceID owns the credential being reauthorized.
	// ProviderInstanceID 拥有正在重新授权的凭据。
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	// CredentialID identifies the exact credential being reauthorized.
	// CredentialID 标识正在重新授权的精确凭据。
	CredentialID string `json:"credential_id,omitempty"`
}

// routingStrategyRequest decodes one closed global or instance scheduling strategy.
// routingStrategyRequest 解码一个封闭的全局或实例调度策略。
type routingStrategyRequest struct {
	// Strategy is round_robin, fill_first, or empty only for instance inheritance.
	// Strategy 是 round_robin、fill_first，或仅在实例继承时为空。
	Strategy providerconfig.RoutingStrategy `json:"strategy"`
}

// credentialPriorityRequest decodes one nonnegative account ordering value.
// credentialPriorityRequest 解码一个非负账号排序值。
type credentialPriorityRequest struct {
	// Priority orders accounts before endpoint paths.
	// Priority 在入口路径之前排列账号。
	Priority int `json:"priority"`
}

// credentialPlanRequest decodes one immutable code-owned plan option identifier.
// credentialPlanRequest 解码一个不可变的代码拥有套餐选项标识。
type credentialPlanRequest struct {
	// PlanOptionID selects one exact system plan.
	// PlanOptionID 选择一个精确系统套餐。
	PlanOptionID string `json:"plan_option_id"`
}

// credentialModelDiscoveryRequest selects one exact same-instance credential for provider model discovery.
// credentialModelDiscoveryRequest 为供应商模型发现选择一个精确同实例凭据。
type credentialModelDiscoveryRequest struct {
	// CredentialID identifies the account used by the upstream model-list operation.
	// CredentialID 标识上游模型清单操作使用的账号。
	CredentialID string `json:"credential_id"`
}

// routingSettingsResponse exposes Router-wide scheduling settings.
// routingSettingsResponse 暴露 Router 全局调度设置。
type routingSettingsResponse struct {
	// Strategy is the inherited credential selection strategy.
	// Strategy 是继承的凭据选择策略。
	Strategy providerconfig.RoutingStrategy `json:"strategy"`
	// Revision is the persisted settings revision.
	// Revision 是持久化设置修订号。
	Revision uint64 `json:"revision"`
	// UpdatedAt is the latest mutation time.
	// UpdatedAt 是最新变更时间。
	UpdatedAt time.Time `json:"updated_at"`
}

// credentialRoutingResponse contains only safe updated routing metadata.
// credentialRoutingResponse 仅包含安全的已更新路由元数据。
type credentialRoutingResponse struct {
	// CredentialID identifies the updated credential.
	// CredentialID 标识已更新凭据。
	CredentialID string `json:"credential_id"`
	// Priority is the updated account ordering value.
	// Priority 是更新后的账号排序值。
	Priority int `json:"priority"`
	// DeclaredPlan contains safe manual plan metadata when changed.
	// DeclaredPlan 在变更后包含安全的人工套餐元数据。
	DeclaredPlan *providerconfig.DeclaredPlanSelection `json:"declared_plan,omitempty"`
	// Revision is the updated credential revision.
	// Revision 是更新后的凭据修订号。
	Revision uint64 `json:"revision"`
}

// instanceRoutingResponse contains one safe updated scheduling override.
// instanceRoutingResponse 包含一个安全的已更新调度覆盖值。
type instanceRoutingResponse struct {
	// ProviderInstanceID identifies the updated instance.
	// ProviderInstanceID 标识已更新实例。
	ProviderInstanceID string `json:"provider_instance_id"`
	// Strategy is empty when the instance inherits the Router default.
	// Strategy 在实例继承 Router 默认值时为空。
	Strategy providerconfig.RoutingStrategy `json:"strategy"`
	// Revision is the updated instance revision.
	// Revision 是更新后的实例修订号。
	Revision uint64 `json:"revision"`
}

// antigravityOAuthOnboardRequest contains the pasted callback while Google supplies the account display identity.
// antigravityOAuthOnboardRequest 包含粘贴回调，账号显示身份由 Google 提供。
type antigravityOAuthOnboardRequest struct {
	credentialReauthorizationTarget
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
	credentialReauthorizationTarget
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
	credentialReauthorizationTarget
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

// providerConfigurationResponse returns only identifiers created by credential-independent provider configuration.
// providerConfigurationResponse 仅返回独立于凭据的供应商配置所创建的标识。
type providerConfigurationResponse struct {
	// ProviderInstanceID identifies the created provider configuration root.
	// ProviderInstanceID 标识创建的供应商配置根。
	ProviderInstanceID string `json:"provider_instance_id"`
	// EndpointIDs identify the created non-secret upstream endpoints.
	// EndpointIDs 标识创建的非秘密上游入口。
	EndpointIDs []string `json:"endpoint_ids"`
}

// credentialReplacementResponse returns stable empty collection fields for a credential-only replacement.
// credentialReplacementResponse 为仅替换凭据的响应返回稳定的空集合字段。
func credentialReplacementResponse(credential providerconfig.Credential) onboardSystemProviderResponse {
	return onboardSystemProviderResponse{
		ProviderInstanceID: credential.ProviderInstanceID,
		CredentialID:       credential.ID,
		EndpointIDs:        []string{},
		BindingIDs:         []string{},
	}
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
	// Priority orders this account within its provider instance.
	// Priority 在供应商实例内排列该账号。
	Priority int `json:"priority,omitempty"`
	// PlanOptionID selects one code-owned manual plan when required.
	// PlanOptionID 在需要时选择一个代码拥有的人工套餐。
	PlanOptionID string `json:"plan_option_id,omitempty"`
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
		if s.control == nil {
			writeUnauthorized(writer)
			return
		}
		apiKeyID, authenticated := s.control.Auth.AuthenticateAPIKeyID(bearerToken(request))
		if !authenticated || strings.TrimSpace(apiKeyID) == "" {
			writeUnauthorized(writer)
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), callAPIKeyIDContextKey{}, apiKeyID)))
	})
}

// callAPIKeyIDContextKey isolates the non-secret authenticated owner identifier from caller context values.
// callAPIKeyIDContextKey 将非秘密已认证所有者标识与调用方 Context 值隔离。
type callAPIKeyIDContextKey struct{}

// authenticatedAPIKeyID returns the identifier installed only by call-plane authentication middleware.
// authenticatedAPIKeyID 返回仅由调用面认证中间件写入的标识。
func authenticatedAPIKeyID(ctx context.Context) (string, bool) {
	identifier, ok := ctx.Value(callAPIKeyIDContextKey{}).(string)
	return identifier, ok && strings.TrimSpace(identifier) != ""
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
	if errors.Is(err, providerconfig.ErrNotFound) || errors.Is(err, catalog.ErrSnapshotNotFound) || errors.Is(err, management.ErrProviderModelNotFound) || errors.Is(err, resolve.ErrModelNotFound) || errors.Is(err, resolve.ErrProfileNotFound) || errors.Is(err, runtimeconfig.ErrAPIKeyNotFound) {
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
		if !profile.UserConfigurable || !profile.RuntimeReady {
			continue
		}
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

// handleConfigureProvider creates one complete provider configuration without accepting credential material.
// handleConfigureProvider 创建一份完整供应商配置，且不接收凭据材料。
func (s *Server) handleConfigureProvider(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[configureProviderRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	parameters := make([]providerconfig.EndpointParameterValue, 0, len(payload.EndpointParameters))
	for _, parameter := range payload.EndpointParameters {
		parameters = append(parameters, providerconfig.EndpointParameterValue{ID: parameter.ID, Value: parameter.Value})
	}
	var initialModel *management.InitialProviderModelInput
	if payload.InitialModel != nil {
		initialModel = &management.InitialProviderModelInput{
			UpstreamModelID: payload.InitialModel.UpstreamModelID, DisplayName: payload.InitialModel.DisplayName,
			ContextWindow: payload.InitialModel.ContextWindow, MaxOutputTokens: payload.InitialModel.MaxOutputTokens,
			ToolCalling: payload.InitialModel.ToolCalling, Reasoning: payload.InitialModel.Reasoning,
		}
	}
	result, errConfigure := s.control.Commands.ConfigureProvider(request.Context(), management.ConfigureProviderInput{
		DefinitionID: payload.DefinitionID, Handle: payload.Handle, DisplayName: payload.DisplayName,
		BaseURL: payload.BaseURL, Region: payload.Region, EndpointParameters: parameters, InitialModel: initialModel,
	})
	if errConfigure != nil {
		writeControlError(writer, errConfigure)
		return
	}
	response := providerConfigurationResponse{ProviderInstanceID: result.Configuration.Instance.ID}
	for _, endpoint := range result.Configuration.Endpoints {
		response.EndpointIDs = append(response.EndpointIDs, endpoint.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
}

// handleDeleteProviderConfiguration deletes one provider configuration after the service proves it owns no credentials.
// handleDeleteProviderConfiguration 在服务证明供应商配置不拥有凭据后删除该配置。
func (s *Server) handleDeleteProviderConfiguration(writer http.ResponseWriter, request *http.Request) {
	if errDelete := s.control.Commands.DeleteProviderConfiguration(request.Context(), request.PathValue("provider_instance_id")); errDelete != nil {
		writeControlError(writer, errDelete)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// handleOnboardSystemProvider creates one complete system-provider configuration without exposing its secret.
// handleOnboardSystemProvider 创建一份完整系统供应商配置且不暴露其秘密。
func (s *Server) handleOnboardSystemProvider(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[onboardSystemProviderRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	endpointParameters := make([]providerconfig.EndpointParameterValue, 0, len(body.EndpointParameters))
	for _, parameter := range body.EndpointParameters {
		endpointParameters = append(endpointParameters, providerconfig.EndpointParameterValue{ID: parameter.ID, Value: parameter.Value})
	}
	onboarding, errOnboard := s.control.Commands.OnboardSystemProvider(request.Context(), management.OnboardSystemProviderInput{
		DefinitionID: body.DefinitionID, DisplayName: body.Name, AuthMethodID: body.AuthMethodID,
		CredentialLabel: body.Name, Secret: []byte(body.Secret), PlanOptionID: body.PlanOptionID, CredentialPriority: body.CredentialPriority, EndpointParameters: endpointParameters,
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	if body.ProviderInstanceID != "" || body.CredentialID != "" {
		vertexCredential, errCredential := providergoogle.ParseVertexCredential(body.ServiceAccount, body.Location)
		if errCredential != nil {
			writeControlError(writer, errCredential)
			return
		}
		protectedValue, errMarshal := providergoogle.MarshalVertexCredential(vertexCredential)
		if errMarshal != nil {
			writeControlError(writer, errMarshal)
			return
		}
		defer clear(protectedValue)
		credential, _, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "service_account", "", protectedValue)
		if errReauthorize != nil {
			writeControlError(writer, errReauthorize)
			return
		}
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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

// reauthorizeCredential attaches to an instance-only target or replaces an exact existing credential target.
// reauthorizeCredential 向仅实例目标附加凭据，或替换一个精确既有凭据目标。
func (s *Server) reauthorizeCredential(ctx context.Context, target credentialReauthorizationTarget, authMethodID string, label string, secretValue []byte) (providerconfig.Credential, bool, error) {
	if target.ProviderInstanceID == "" && target.CredentialID == "" {
		return providerconfig.Credential{}, false, nil
	}
	if target.ProviderInstanceID == "" {
		return providerconfig.Credential{}, true, errors.New("credential authorization target requires a provider instance identifier")
	}
	if target.CredentialID == "" {
		attachment, errAttach := s.control.Commands.AttachAcquiredCredential(ctx, management.AttachAcquiredCredentialInput{
			ProviderInstanceID: target.ProviderInstanceID, AuthMethodID: authMethodID, Label: label, Secret: secretValue,
		})
		return attachment.Credential, true, errAttach
	}
	credential, errReauthorize := s.control.Commands.ReauthorizeCredential(ctx, management.ReauthorizeCredentialInput{ProviderInstanceID: target.ProviderInstanceID, CredentialID: target.CredentialID, AuthMethodID: authMethodID, Secret: secretValue})
	return credential, true, errReauthorize
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "device_flow", body.Name, secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.KimiDeviceFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "device_flow", body.Name, secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.XAIDeviceFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "device_flow", body.Name, secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.CodexDeviceFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "oauth", "", secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.CodexOAuthFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "oauth", "", secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.ClaudeOAuthFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	credential, reauthorized, errReauthorize := s.reauthorizeCredential(request.Context(), body.credentialReauthorizationTarget, "oauth", "", secretValue)
	if errReauthorize != nil {
		writeControlError(writer, errReauthorize)
		return
	}
	if reauthorized {
		s.control.AntigravityOAuthFlows.Cancel(flowID)
		s.triggerMetadataRefresh(credential.ProviderInstanceID)
		writeJSON(writer, http.StatusOK, credentialReplacementResponse(credential))
		return
	}
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
	s.triggerMetadataRefresh(onboarding.Instance.ID)
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
	s.triggerMetadataRefresh(instanceID)
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// triggerMetadataRefresh queues account metadata replacement after a successful credential mutation.
// triggerMetadataRefresh 在凭据变更成功后将账号元数据替换任务入队。
func (s *Server) triggerMetadataRefresh(instanceID string) {
	scheduler, supportsScheduling := s.control.MetadataRefresh.(ProviderMetadataRefreshScheduler)
	if supportsScheduling {
		scheduler.Trigger(instanceID)
	}
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

// handleDiscoverProviderModels performs credential-scoped discovery without allowing implicit account selection.
// handleDiscoverProviderModels 执行凭据作用域发现且不允许隐式选择账号。
func (s *Server) handleDiscoverProviderModels(writer http.ResponseWriter, request *http.Request) {
	discovery, supported := s.control.MetadataRefresh.(ProviderCredentialModelDiscovery)
	if !supported {
		writeJSON(writer, http.StatusNotImplemented, errorResponse{Error: "provider_model_discovery_unavailable"})
		return
	}
	payload, errDecode := decodeControlJSON[credentialModelDiscoveryRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instanceID := request.PathValue("provider_instance_id")
	if _, errDiscover := discovery.RefreshWithCredential(request.Context(), instanceID, payload.CredentialID, time.Now().UTC()); errDiscover != nil {
		writeControlError(writer, errDiscover)
		return
	}
	view, errView := s.control.Query.GetCatalog(request.Context(), instanceID)
	if errView != nil {
		writeControlError(writer, errView)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

// handleDiscoverCustomProviderModels reads a standard custom-provider model list without implicit credential selection.
// handleDiscoverCustomProviderModels 读取标准自定义供应商模型清单且不隐式选择凭据。
func (s *Server) handleDiscoverCustomProviderModels(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[credentialModelDiscoveryRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instanceID := request.PathValue("provider_instance_id")
	if _, errDiscover := s.control.Commands.DiscoverCustomProviderModels(request.Context(), instanceID, payload.CredentialID); errDiscover != nil {
		writeControlError(writer, errDiscover)
		return
	}
	view, errView := s.control.Query.GetCatalog(request.Context(), instanceID)
	if errView != nil {
		writeControlError(writer, errView)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

// handleSaveCustomProviderModels replaces one simplified custom model set with explicit capability declarations.
// handleSaveCustomProviderModels 使用显式能力声明替换一个简化自定义模型集合。
func (s *Server) handleSaveCustomProviderModels(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[customProviderModelsRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	models := make([]management.InitialProviderModelInput, 0, len(payload.Models))
	for _, model := range payload.Models {
		models = append(models, management.InitialProviderModelInput{
			UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName,
			ContextWindow: model.ContextWindow, MaxOutputTokens: model.MaxOutputTokens,
			ToolCalling: model.ToolCalling, Reasoning: model.Reasoning,
		})
	}
	instanceID := request.PathValue("provider_instance_id")
	if _, errSave := s.control.Commands.SaveCustomProviderModels(request.Context(), instanceID, models); errSave != nil {
		writeControlError(writer, errSave)
		return
	}
	view, errView := s.control.Query.GetCatalog(request.Context(), instanceID)
	if errView != nil {
		writeControlError(writer, errView)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

// handleRoutingSettings returns the persisted Router-wide credential selection strategy.
// handleRoutingSettings 返回持久化 Router 全局凭据选择策略。
func (s *Server) handleRoutingSettings(writer http.ResponseWriter, request *http.Request) {
	settings, errSettings := s.control.Routing.GetSettings(request.Context())
	if errSettings != nil {
		writeControlError(writer, errSettings)
		return
	}
	writeJSON(writer, http.StatusOK, routingSettingsResponse{Strategy: settings.DefaultRoutingStrategy, Revision: settings.Revision, UpdatedAt: settings.UpdatedAt})
}

// handleSetRoutingSettings changes the inherited Router-wide credential selection strategy.
// handleSetRoutingSettings 修改继承的 Router 全局凭据选择策略。
func (s *Server) handleSetRoutingSettings(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[routingStrategyRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	settings, errSettings := s.control.Routing.SetDefaultRoutingStrategy(request.Context(), body.Strategy)
	if errSettings != nil {
		writeControlError(writer, errSettings)
		return
	}
	writeJSON(writer, http.StatusOK, routingSettingsResponse{Strategy: settings.DefaultRoutingStrategy, Revision: settings.Revision, UpdatedAt: settings.UpdatedAt})
}

// handleSetInstanceRouting sets or clears one provider-instance scheduling override.
// handleSetInstanceRouting 设置或清除一个供应商实例调度覆盖值。
func (s *Server) handleSetInstanceRouting(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[routingStrategyRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	instance, errInstance := s.control.Routing.SetInstanceRoutingStrategy(request.Context(), request.PathValue("provider_instance_id"), body.Strategy)
	if errInstance != nil {
		writeControlError(writer, errInstance)
		return
	}
	writeJSON(writer, http.StatusOK, instanceRoutingResponse{ProviderInstanceID: instance.ID, Strategy: instance.RoutingStrategy, Revision: instance.Revision})
}

// handleSetCredentialPriority changes account ordering without changing endpoint path priority.
// handleSetCredentialPriority 修改账号顺序且不改变入口路径优先级。
func (s *Server) handleSetCredentialPriority(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[credentialPriorityRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errCredential := s.control.Routing.SetCredentialPriority(request.Context(), request.PathValue("provider_instance_id"), request.PathValue("credential_id"), body.Priority)
	if errCredential != nil {
		writeControlError(writer, errCredential)
		return
	}
	writeJSON(writer, http.StatusOK, credentialRoutingResponse{CredentialID: credential.ID, Priority: credential.Priority, Revision: credential.Revision})
}

// handleSetCredentialPlan changes one manual plan and atomically rebuilt entitlement snapshot.
// handleSetCredentialPlan 修改一个人工套餐与原子重建的权益快照。
func (s *Server) handleSetCredentialPlan(writer http.ResponseWriter, request *http.Request) {
	body, errDecode := decodeControlJSON[credentialPlanRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	credential, errCredential := s.control.Routing.SetCredentialPlan(request.Context(), request.PathValue("provider_instance_id"), request.PathValue("credential_id"), body.PlanOptionID)
	if errCredential != nil {
		writeControlError(writer, errCredential)
		return
	}
	writeJSON(writer, http.StatusOK, credentialRoutingResponse{CredentialID: credential.ID, Priority: credential.Priority, DeclaredPlan: credential.DeclaredPlan, Revision: credential.Revision})
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
		MediaInputs:            append([]catalog.MediaInputCapability(nil), view.MediaInputs...),
		Delivery:               view.Delivery,
		Embedding:              view.Embedding,
		Rerank:                 view.Rerank,
		MediaOutputs:           append([]catalog.MediaOutputCapability(nil), view.MediaOutputs...),
		Parameters:             append([]catalog.ParameterDescriptor(nil), view.Parameters...),
		ParameterRules:         append([]catalog.ParameterRule(nil), view.ParameterRules...),
		UsageMetrics:           append([]catalog.UsageMetricCapability(nil), view.UsageMetrics...),
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
		MediaInputs:                append([]catalog.MediaInputCapability(nil), capabilities.MediaInputs...),
		Delivery:                   capabilities.Delivery,
		Embedding:                  capabilities.Embedding,
		Rerank:                     capabilities.Rerank,
		MediaOutputs:               append([]catalog.MediaOutputCapability(nil), capabilities.MediaOutputs...),
		Parameters:                 append([]catalog.ParameterDescriptor(nil), capabilities.Parameters...),
		ParameterRules:             append([]catalog.ParameterRule(nil), capabilities.ParameterRules...),
		UsageMetrics:               append([]catalog.UsageMetricCapability(nil), capabilities.UsageMetrics...),
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
		PrincipalKey: payload.PrincipalKey, ScopeRefs: payload.ScopeRefs, Priority: payload.Priority, PlanOptionID: payload.PlanOptionID, Secret: []byte(payload.Secret),
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	s.triggerMetadataRefresh(credential.ProviderInstanceID)
	writeJSON(writer, http.StatusCreated, identifierResponse{ID: credential.ID})
}

// handleAttachCredential creates one complete credential access path for an existing provider configuration.
// handleAttachCredential 为既有供应商配置创建一条完整凭据访问路径。
func (s *Server) handleAttachCredential(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[createCredentialRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	attachment, errCreate := s.control.Commands.AttachCredential(request.Context(), management.AddCredentialInput{
		ID: payload.ID, ProviderInstanceID: request.PathValue("provider_instance_id"), AuthMethodID: payload.AuthMethodID, Label: payload.Label,
		PrincipalKey: payload.PrincipalKey, ScopeRefs: payload.ScopeRefs, Priority: payload.Priority, PlanOptionID: payload.PlanOptionID, Secret: []byte(payload.Secret),
	})
	if errCreate != nil {
		writeControlError(writer, errCreate)
		return
	}
	s.triggerMetadataRefresh(attachment.Credential.ProviderInstanceID)
	response := onboardSystemProviderResponse{ProviderInstanceID: attachment.Credential.ProviderInstanceID, CredentialID: attachment.Credential.ID, EndpointIDs: []string{}}
	for _, binding := range attachment.Bindings {
		response.BindingIDs = append(response.BindingIDs, binding.ID)
	}
	writeJSON(writer, http.StatusCreated, response)
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
	s.triggerMetadataRefresh(credential.ProviderInstanceID)
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
	s.triggerMetadataRefresh(credential.ProviderInstanceID)
	writeJSON(writer, http.StatusOK, identifierResponse{ID: credential.ID})
}

// handleDeleteCredential deletes one credential graph and its protected secret.
// handleDeleteCredential 删除一个凭据图及其受保护 Secret。
func (s *Server) handleDeleteCredential(writer http.ResponseWriter, request *http.Request) {
	instanceID := request.PathValue("provider_instance_id")
	_, errDelete := s.control.Commands.DeleteCredential(request.Context(), instanceID, request.PathValue("credential_id"))
	if errDelete != nil {
		writeControlError(writer, errDelete)
		return
	}
	s.triggerMetadataRefresh(instanceID)
	writer.WriteHeader(http.StatusNoContent)
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
	s.triggerMetadataRefresh(credential.ProviderInstanceID)
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

// Validate enforces the exact identifier contract for the selected information projection.
// Validate 强制执行已选信息投影的精确标识契约。
func (r callInformationRequest) Validate() error {
	switch r.Get {
	case callInformationInstances:
		if r.ProviderInstanceID != "" || r.ProviderModelID != "" || r.CredentialID != "" || r.ProviderServiceID != "" {
			return errors.New("instances information does not accept selectors")
		}
	case callInformationModels:
		if r.CredentialID != "" || r.ProviderServiceID != "" || (r.ProviderModelID != "" && r.ProviderInstanceID == "") {
			return errors.New("models information accepts an optional instance and an instance-owned model only")
		}
	case callInformationAccounts:
		if r.ProviderInstanceID == "" || r.ProviderModelID == "" || r.CredentialID != "" || r.ProviderServiceID != "" {
			return errors.New("accounts information requires provider_instance_id and provider_model_id only")
		}
	case callInformationServices:
		if r.ProviderModelID != "" || r.CredentialID != "" || (r.ProviderServiceID != "" && r.ProviderInstanceID == "") {
			return errors.New("services information accepts an optional instance and an instance-owned service only")
		}
	case callInformationUsage:
		if r.ProviderInstanceID == "" || r.ProviderModelID == "" || r.CredentialID == "" || r.ProviderServiceID != "" {
			return errors.New("usage information requires provider_instance_id, provider_model_id, and credential_id only")
		}
	default:
		return errors.New("get must be one of instances, models, accounts, services, or usage")
	}
	return nil
}

// handleCallInformation dispatches one strong information union selected exclusively by the get field.
// handleCallInformation 仅根据 get 字段分派一个强类型信息联合。
func (s *Server) handleCallInformation(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[callInformationRequest](writer, request)
	if errDecode != nil {
		writeControlError(writer, errDecode)
		return
	}
	if errValidate := payload.Validate(); errValidate != nil {
		writeControlError(writer, errValidate)
		return
	}
	switch payload.Get {
	case callInformationInstances:
		instances, errInstances := s.control.Query.ListInstances(request.Context())
		if errInstances != nil {
			writeControlError(writer, errInstances)
			return
		}
		writeJSON(writer, http.StatusOK, callInformationInstancesResponse{Get: payload.Get, Instances: instances})
	case callInformationModels:
		models, errModels := s.callModels(request.Context(), payload.ProviderInstanceID, payload.ProviderModelID)
		if errModels != nil {
			writeControlError(writer, errModels)
			return
		}
		writeJSON(writer, http.StatusOK, callInformationModelsResponse{Get: payload.Get, Models: models})
	case callInformationAccounts:
		accounts, errAccounts := s.control.Query.GetModelContexts(request.Context(), payload.ProviderInstanceID, payload.ProviderModelID)
		if errAccounts != nil {
			writeControlError(writer, errAccounts)
			return
		}
		writeJSON(writer, http.StatusOK, callInformationAccountsResponse{Get: payload.Get, Accounts: accounts})
	case callInformationServices:
		services, errServices := s.callServices(request.Context(), payload.ProviderInstanceID, payload.ProviderServiceID)
		if errServices != nil {
			writeControlError(writer, errServices)
			return
		}
		writeJSON(writer, http.StatusOK, callInformationServicesResponse{Get: payload.Get, Services: services})
	case callInformationUsage:
		usage, errUsage := s.control.Query.GetModelCredentialUsage(request.Context(), payload.ProviderInstanceID, payload.ProviderModelID, payload.CredentialID)
		if errUsage != nil {
			writeControlError(writer, errUsage)
			return
		}
		writeJSON(writer, http.StatusOK, callInformationUsageResponse{Get: payload.Get, Usage: usage})
	}
}

// callModels returns enabled models and capabilities without fusing identically named provider models.
// callModels 返回启用模型和能力，且不融合名称相同的供应商模型。
func (s *Server) callModels(ctx context.Context, providerInstanceID string, providerModelID string) ([]callModelView, error) {
	instances, errInstances := s.control.Query.ListInstances(ctx)
	if errInstances != nil {
		return nil, errInstances
	}
	models := make([]callModelView, 0)
	// discoveryTime freezes one availability instant across the complete response.
	// discoveryTime 为完整响应冻结同一个可用性判断时刻。
	discoveryTime := time.Now().UTC()
	for _, instance := range instances {
		if providerInstanceID != "" && instance.ID != providerInstanceID {
			continue
		}
		if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
			continue
		}
		providerCatalog, errCatalog := s.control.Query.GetCatalog(ctx, instance.ID)
		if errors.Is(errCatalog, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCatalog != nil {
			return nil, errCatalog
		}
		for _, model := range providerCatalog.Models {
			if providerModelID != "" && model.ID != providerModelID {
				continue
			}
			if !model.Enabled || model.AuthorizationStatus != catalog.AuthorizationAuthorized {
				continue
			}
			filteredModel, executable, errFilter := s.executableModelView(ctx, instance.ID, model, discoveryTime)
			if errFilter != nil {
				return nil, errFilter
			}
			if !executable {
				continue
			}
			models = append(models, callModelView{
				ProviderInstanceID:   instance.ID,
				ProviderHandle:       instance.Handle,
				ProviderDefinitionID: instance.DefinitionID,
				Model:                filteredModel,
			})
		}
	}
	return models, nil
}

// callServices returns executable provider-scoped special services without entering the model list.
// callServices 返回可执行供应商作用域特殊服务且不进入模型列表。
func (s *Server) callServices(ctx context.Context, providerInstanceID string, providerServiceID string) ([]callServiceView, error) {
	instances, errInstances := s.control.Query.ListInstances(ctx)
	if errInstances != nil {
		return nil, errInstances
	}
	services := make([]callServiceView, 0)
	// discoveryTime freezes one availability instant across the complete response.
	// discoveryTime 为完整响应冻结同一个可用性判断时刻。
	discoveryTime := time.Now().UTC()
	for _, instance := range instances {
		if providerInstanceID != "" && instance.ID != providerInstanceID {
			continue
		}
		if instance.Status != providerconfig.LifecycleReady && instance.Status != providerconfig.LifecycleDegraded {
			continue
		}
		providerCatalog, errCatalog := s.control.Query.GetCatalog(ctx, instance.ID)
		if errors.Is(errCatalog, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCatalog != nil {
			return nil, errCatalog
		}
		for _, service := range providerCatalog.Services {
			if providerServiceID != "" && service.ID != providerServiceID {
				continue
			}
			if !service.Enabled || service.AuthorizationStatus != catalog.AuthorizationAuthorized {
				continue
			}
			filteredService, executable, errFilter := s.executableServiceView(ctx, instance.ID, service, discoveryTime)
			if errFilter != nil {
				return nil, errFilter
			}
			if !executable {
				continue
			}
			services = append(services, callServiceView{ProviderInstanceID: instance.ID, ProviderHandle: instance.Handle, ProviderDefinitionID: instance.DefinitionID, Service: filteredService})
		}
	}
	return services, nil
}

// executableModelView retains only offerings and profiles whose exact target currently resolves.
// executableModelView 仅保留当前能够解析精确 Target 的产品与规格。
func (s *Server) executableModelView(ctx context.Context, providerInstanceID string, model management.ModelView, discoveryTime time.Time) (management.ModelView, bool, error) {
	filteredOfferings := make([]management.OfferingView, 0, len(model.Offerings))
	for _, offering := range model.Offerings {
		filteredProfiles := make([]management.ExecutionProfileView, 0, len(offering.Profiles))
		for _, profile := range offering.Profiles {
			if _, _, errResolve := s.control.Targets.Resolve(ctx, resolve.Request{ProviderInstanceID: providerInstanceID, ProviderModelID: model.ID, Operation: profile.Operation, ExecutionProfileID: profile.ID, Now: discoveryTime}); errResolve == nil {
				filteredProfiles = append(filteredProfiles, profile)
			} else if !targetIneligible(errResolve) {
				return management.ModelView{}, false, errResolve
			}
		}
		if len(filteredProfiles) == 0 {
			continue
		}
		offering.Profiles = filteredProfiles
		filteredOfferings = append(filteredOfferings, offering)
	}
	model.Offerings = filteredOfferings
	return model, len(filteredOfferings) > 0, nil
}

// executableServiceView retains only offerings and profiles whose exact service target currently resolves.
// executableServiceView 仅保留当前能够解析精确服务 Target 的产品与规格。
func (s *Server) executableServiceView(ctx context.Context, providerInstanceID string, service management.ServiceView, discoveryTime time.Time) (management.ServiceView, bool, error) {
	filteredOfferings := make([]management.ServiceOfferingView, 0, len(service.Offerings))
	for _, offering := range service.Offerings {
		filteredProfiles := make([]management.ServiceExecutionProfileView, 0, len(offering.Profiles))
		for _, profile := range offering.Profiles {
			if _, _, errResolve := s.control.Targets.Resolve(ctx, resolve.Request{ProviderInstanceID: providerInstanceID, ProviderServiceID: service.ID, ServiceOfferingID: offering.ID, Operation: profile.Operation, ExecutionProfileID: profile.ID, Now: discoveryTime}); errResolve == nil {
				filteredProfiles = append(filteredProfiles, profile)
			} else if !targetIneligible(errResolve) {
				return management.ServiceView{}, false, errResolve
			}
		}
		if len(filteredProfiles) == 0 {
			continue
		}
		offering.Profiles = filteredProfiles
		filteredOfferings = append(filteredOfferings, offering)
	}
	service.Offerings = filteredOfferings
	return service, len(filteredOfferings) > 0, nil
}

// targetIneligible reports only resolver classifications that safely mean one discovery profile is currently unavailable.
// targetIneligible 仅报告可安全表示某个发现规格当前不可用的解析器分类。
func targetIneligible(errValue error) bool {
	return errors.Is(errValue, resolve.ErrInstanceNotExecutable) ||
		errors.Is(errValue, resolve.ErrModelNotFound) ||
		errors.Is(errValue, resolve.ErrModelDisabled) ||
		errors.Is(errValue, resolve.ErrServiceNotFound) ||
		errors.Is(errValue, resolve.ErrServiceDisabled) ||
		errors.Is(errValue, resolve.ErrProfileNotFound) ||
		errors.Is(errValue, resolve.ErrNoEligibleTarget)
}
