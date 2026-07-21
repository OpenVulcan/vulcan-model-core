// Package provider defines trusted system-provider library contracts and registration.
// Package provider 定义受信任系统供应商库合同和注册机制。
package provider

import (
	"context"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// Driver is the minimum trusted library contract for one system provider.
// Driver 是一个系统供应商的最小受信任库合同。
type Driver interface {
	// Definition returns the immutable code-owned provider definition.
	// Definition 返回代码拥有的不可变供应商定义。
	Definition() providerconfig.ProviderDefinition
	// ClassifyError converts one protocol-neutral upstream observation into provider semantics.
	// ClassifyError 将一个协议无关上游观测转换为供应商语义。
	ClassifyError(ErrorObservation) (ClassifiedError, bool)
}

// DiscoveryRequest identifies one provider instance and optional credential discovery scope.
// DiscoveryRequest 标识一个供应商实例和可选凭据发现作用域。
type DiscoveryRequest struct {
	// ProviderInstance is the exact provider configuration being inspected.
	// ProviderInstance 是正在检查的精确供应商配置。
	ProviderInstance providerconfig.ProviderInstance
	// Credential optionally narrows discovery to one account-specific scope.
	// Credential 可选地将发现范围限制到一个账号特定作用域。
	Credential *providerconfig.Credential
}

// ModelDiscoveryResult contains provider-scoped model metadata without protocol payloads.
// ModelDiscoveryResult 包含不带协议 Payload 的供应商作用域模型元数据。
type ModelDiscoveryResult struct {
	// Models contains logical provider models discovered by the driver.
	// Models 包含 Driver 发现的逻辑供应商模型。
	Models []catalog.ProviderModel
	// Offerings contains channel-specific products discovered by the driver.
	// Offerings 包含 Driver 发现的通道特定产品。
	Offerings []catalog.ModelOffering
	// Profiles contains provider-defined client-selectable capability shapes.
	// Profiles 包含供应商定义的客户端可选能力形态。
	Profiles []catalog.ExecutionProfile
	// ObservedAt records when discovery completed.
	// ObservedAt 记录发现完成时间。
	ObservedAt time.Time
}

// ModelDiscoverer is implemented by drivers that can query provider-native models.
// ModelDiscoverer 由可以查询供应商原生模型的 Driver 实现。
type ModelDiscoverer interface {
	// DiscoverModels returns provider-scoped model metadata for one instance or credential.
	// DiscoverModels 返回一个实例或凭据的供应商作用域模型元数据。
	DiscoverModels(context.Context, DiscoveryRequest) (ModelDiscoveryResult, error)
}

// PlanReader is implemented by drivers that can query commercial plan metadata.
// PlanReader 由可以查询商业套餐元数据的 Driver 实现。
type PlanReader interface {
	// ReadPlan returns the current commercial plan snapshot for one credential.
	// ReadPlan 返回一个凭据的当前商业套餐快照。
	ReadPlan(context.Context, providerconfig.ProviderInstance, providerconfig.Credential) (catalog.PlanSnapshot, error)
}

// EntitlementReader is implemented by drivers that can query account-specific model authorization.
// EntitlementReader 由可以查询账号特定模型授权的 Driver 实现。
type EntitlementReader interface {
	// ReadEntitlements returns model authorization snapshots for one credential.
	// ReadEntitlements 返回一个凭据的模型授权快照。
	ReadEntitlements(context.Context, providerconfig.ProviderInstance, providerconfig.Credential) ([]catalog.ModelEntitlement, error)
}

// AllowanceReader is implemented by drivers that can query quotas, balances, or credits.
// AllowanceReader 由可以查询额度、余额或 Credit 的 Driver 实现。
type AllowanceReader interface {
	// ReadAllowances returns arbitrary consumable resource snapshots for one credential and its shared scopes.
	// ReadAllowances 返回一个凭据及其共享作用域的任意可消费资源快照。
	ReadAllowances(context.Context, providerconfig.ProviderInstance, providerconfig.Credential) ([]catalog.AllowanceSnapshot, error)
}

// CredentialMetadataResult contains every account fact decoded from one provider observation.
// CredentialMetadataResult 包含从一次供应商观测解码出的全部账号事实。
type CredentialMetadataResult struct {
	// Plan is the optional commercial plan returned by the provider observation.
	// Plan 是供应商观测返回的可选商业套餐。
	Plan *catalog.PlanSnapshot
	// Entitlements contains account-specific model authorization observations.
	// Entitlements 包含账号特定模型授权观测。
	Entitlements []catalog.ModelEntitlement
	// ServiceEntitlements contains account-specific special-service authorization observations.
	// ServiceEntitlements 包含账号特定特殊服务授权观测。
	ServiceEntitlements []catalog.ServiceEntitlement
	// Allowances contains quota, balance, or credit observations from the same response.
	// Allowances 包含来自同一响应的额度、余额或积分观测。
	Allowances []catalog.AllowanceSnapshot
}

// CredentialMetadataReader is implemented when one provider call returns multiple account capability classes.
// CredentialMetadataReader 由一次供应商调用返回多类账号能力的 Driver 实现。
type CredentialMetadataReader interface {
	// ReadCredentialMetadata returns one internally consistent account observation for one credential.
	// ReadCredentialMetadata 为一个凭据返回一份内部一致的账号观测。
	ReadCredentialMetadata(context.Context, providerconfig.ProviderInstance, providerconfig.Credential) (CredentialMetadataResult, error)
}

// ErrorObservation contains protocol-neutral upstream failure evidence.
// ErrorObservation 包含协议无关的上游失败证据。
type ErrorObservation struct {
	// HTTPStatus is the upstream HTTP status when available.
	// HTTPStatus 是可用时的上游 HTTP 状态。
	HTTPStatus int
	// Code is the structured provider error code when available.
	// Code 是可用时的结构化供应商错误码。
	Code string
	// Type is the structured provider error type when available.
	// Type 是可用时的结构化供应商错误类型。
	Type string
	// Message is a redacted provider error message used by trusted rules only.
	// Message 是仅供受信任规则使用的脱敏供应商错误消息。
	Message string
	// RetryAfter is the parsed provider retry delay when available.
	// RetryAfter 是可用时解析出的供应商重试延迟。
	RetryAfter *time.Duration
	// ProviderRequestID is the upstream request identifier when available.
	// ProviderRequestID 是可用时的上游请求标识。
	ProviderRequestID string
}

// ErrorScope identifies which provider-owned resource is affected by a failure.
// ErrorScope 标识失败影响的供应商拥有资源。
type ErrorScope string

const (
	// ErrorScopeRequest affects only the current logical request.
	// ErrorScopeRequest 只影响当前逻辑请求。
	ErrorScopeRequest ErrorScope = "request"
	// ErrorScopeCredential affects one account or API key.
	// ErrorScopeCredential 影响一个账号或 API Key。
	ErrorScopeCredential ErrorScope = "credential"
	// ErrorScopeSubscription affects credentials sharing one subscription.
	// ErrorScopeSubscription 影响共享一个订阅的凭据。
	ErrorScopeSubscription ErrorScope = "subscription"
	// ErrorScopeBillingAccount affects credentials sharing one billing account.
	// ErrorScopeBillingAccount 影响共享一个计费账号的凭据。
	ErrorScopeBillingAccount ErrorScope = "billing_account"
	// ErrorScopeEndpoint affects one upstream endpoint.
	// ErrorScopeEndpoint 影响一个上游端点。
	ErrorScopeEndpoint ErrorScope = "endpoint"
	// ErrorScopeModel affects one provider model.
	// ErrorScopeModel 影响一个供应商模型。
	ErrorScopeModel ErrorScope = "model"
	// ErrorScopeProvider affects the complete selected provider instance.
	// ErrorScopeProvider 影响完整的所选供应商实例。
	ErrorScopeProvider ErrorScope = "provider"
)

// RetryAction identifies one explicit same-provider recovery recommendation.
// RetryAction 标识一个显式同供应商恢复建议。
type RetryAction string

const (
	// RetryStop recommends returning the failure without internal retry.
	// RetryStop 建议不进行内部重试并返回失败。
	RetryStop RetryAction = "stop"
	// RetrySameTarget recommends retrying the same credential and endpoint.
	// RetrySameTarget 建议重试相同凭据和端点。
	RetrySameTarget RetryAction = "retry_same_target"
	// RetryOtherCredential recommends another credential in the same provider instance.
	// RetryOtherCredential 建议使用同一供应商实例中的其他凭据。
	RetryOtherCredential RetryAction = "retry_other_credential"
	// RetryOtherEndpoint recommends another endpoint in the same provider instance.
	// RetryOtherEndpoint 建议使用同一供应商实例中的其他端点。
	RetryOtherEndpoint RetryAction = "retry_other_endpoint"
	// RetryAfterReset recommends waiting until a known provider recovery time.
	// RetryAfterReset 建议等待已知供应商恢复时间。
	RetryAfterReset RetryAction = "retry_after_reset"
)

// ClassifiedError contains stable provider semantics and retry boundaries.
// ClassifiedError 包含稳定供应商语义和重试边界。
type ClassifiedError struct {
	// Category is the stable Vulcan provider error category.
	// Category 是稳定的 Vulcan 供应商错误类别。
	Category string
	// Scope identifies the provider-owned resource affected by the failure.
	// Scope 标识失败影响的供应商拥有资源。
	Scope ErrorScope
	// Action is the recommended same-provider recovery behavior.
	// Action 是建议的同供应商恢复行为。
	Action RetryAction
	// RetryAt is the earliest known safe retry time.
	// RetryAt 是最早的已知安全重试时间。
	RetryAt *time.Time
	// RuleID identifies the trusted provider rule that produced the classification.
	// RuleID 标识产生分类的受信任供应商规则。
	RuleID string
	// ProviderRequestID preserves the upstream request identifier for diagnostics.
	// ProviderRequestID 为诊断保留上游请求标识。
	ProviderRequestID string
}
