// Package resolve builds immutable provider-scoped execution targets from configuration snapshots.
// Package resolve 从配置快照构建不可变的供应商作用域执行目标。
package resolve

import (
	"errors"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

var (
	// ErrInstanceNotExecutable reports a provider instance that is not ready for resolution.
	// ErrInstanceNotExecutable 表示供应商实例尚未准备好参与解析。
	ErrInstanceNotExecutable = errors.New("provider instance is not executable")
	// ErrModelNotFound reports a provider model outside the selected instance catalog.
	// ErrModelNotFound 表示所选实例目录中不存在供应商模型。
	ErrModelNotFound = errors.New("provider model not found")
	// ErrModelDisabled reports a provider model explicitly disabled by local management policy.
	// ErrModelDisabled 表示供应商模型被本地管理策略显式禁用。
	ErrModelDisabled = errors.New("provider model is disabled")
	// ErrProfileNotFound reports an absent or ambiguous execution profile.
	// ErrProfileNotFound 表示执行规格不存在或存在歧义。
	ErrProfileNotFound = errors.New("execution profile not found")
	// ErrNoEligibleTarget reports that no same-provider access target satisfies all constraints.
	// ErrNoEligibleTarget 表示没有同供应商访问目标满足全部约束。
	ErrNoEligibleTarget = errors.New("no eligible provider execution target")
)

// Request describes one exact provider-scoped target resolution request.
// Request 描述一次精确的供应商作用域目标解析请求。
type Request struct {
	// ProviderInstanceID fixes the provider boundary for the complete request.
	// ProviderInstanceID 固定整个请求的供应商边界。
	ProviderInstanceID string
	// ProviderModelID identifies one model inside the selected provider instance.
	// ProviderModelID 标识所选供应商实例内的一个模型。
	ProviderModelID string
	// ExecutionProfileID optionally selects one client-visible capability shape.
	// ExecutionProfileID 可选地选择一个客户端可见能力形态。
	ExecutionProfileID string
	// RequiredContextTokens is the validated minimum context capacity required by the request.
	// RequiredContextTokens 是请求所需且已经校验的最小上下文容量。
	RequiredContextTokens int64
	// RequiredCapabilities lists normalized capability identifiers needed by the request.
	// RequiredCapabilities 列出请求需要的规范化能力标识。
	RequiredCapabilities []string
	// Now fixes time-dependent cooldown and snapshot evaluation.
	// Now 固定依赖时间的冷却和快照评估时刻。
	Now time.Time
}

// Diagnostics contains typed candidate counts and allowance blockers for one resolution attempt.
// Diagnostics 包含一次解析尝试的类型化候选数量和资源阻塞信息。
type Diagnostics struct {
	// ConfiguredCredentials is the total credential count in the selected instance.
	// ConfiguredCredentials 是所选实例中的凭据总数。
	ConfiguredCredentials int
	// BoundCandidates is the count with valid access bindings for the selected offering.
	// BoundCandidates 是对所选产品具有有效访问绑定的数量。
	BoundCandidates int
	// EntitledCandidates is the count authorized for the selected model and profile.
	// EntitledCandidates 是获得所选模型和规格授权的数量。
	EntitledCandidates int
	// CapabilityCandidates is the count satisfying context and capability requirements.
	// CapabilityCandidates 是满足上下文和能力要求的数量。
	CapabilityCandidates int
	// AllowanceCandidates is the count not blocked by mandatory consumable resources.
	// AllowanceCandidates 是未被强制可消费资源阻塞的数量。
	AllowanceCandidates int
	// ReadyCandidates is the final immediately executable target count.
	// ReadyCandidates 是最终可以立即执行的目标数量。
	ReadyCandidates int
	// BlockingAllowanceKinds lists unique resource shapes that blocked candidates.
	// BlockingAllowanceKinds 列出阻塞候选的唯一资源形态。
	BlockingAllowanceKinds []catalog.AllowanceKind
	// EarliestResetAt is the earliest known recovery time among blocked candidates.
	// EarliestResetAt 是阻塞候选中最早的已知恢复时间。
	EarliestResetAt *time.Time
}

// Target is an immutable value snapshot of one exact same-provider execution destination.
// Target 是一个精确同供应商执行目标的不可变值快照。
type Target struct {
	// ProviderDefinitionID identifies the system or custom provider definition.
	// ProviderDefinitionID 标识系统或自定义供应商定义。
	ProviderDefinitionID string
	// ProviderInstanceID fixes the provider instance boundary.
	// ProviderInstanceID 固定供应商实例边界。
	ProviderInstanceID string
	// ChannelID identifies the selected provider channel.
	// ChannelID 标识所选供应商通道。
	ChannelID string
	// EndpointID identifies the selected endpoint.
	// EndpointID 标识所选端点。
	EndpointID string
	// CredentialID identifies the selected credential.
	// CredentialID 标识所选凭据。
	CredentialID string
	// ProviderModelID identifies the selected logical model.
	// ProviderModelID 标识所选逻辑模型。
	ProviderModelID string
	// OfferingID identifies the selected channel-specific model offering.
	// OfferingID 标识所选通道特定模型产品。
	OfferingID string
	// ExecutionProfileID identifies the selected client-visible capability shape.
	// ExecutionProfileID 标识所选客户端可见能力形态。
	ExecutionProfileID string
	// UpstreamModelID is the exact model identifier sent by a future protocol adapter.
	// UpstreamModelID 是未来协议 Adapter 发送的精确模型标识。
	UpstreamModelID string
	// EffectiveContextWindow is the smallest authoritative profile and account ceiling.
	// EffectiveContextWindow 是规格和账号权威上限中的最小值。
	EffectiveContextWindow catalog.OptionalTokenLimit
	// TokenLimits contains the selected profile's independently known hard token ceilings.
	// TokenLimits 包含所选规格独立已知的硬 Token 上限。
	TokenLimits catalog.TokenLimits
	// TokenRecommendations contains the selected profile's provider-evidenced defaults.
	// TokenRecommendations 包含所选规格由供应商证据支持的默认值。
	TokenRecommendations catalog.TokenRecommendations
	// CapabilityRevision records the capability evidence used for resolution.
	// CapabilityRevision 记录解析使用的能力证据修订号。
	CapabilityRevision uint64
	// ProviderConfigRevision records the provider instance configuration revision.
	// ProviderConfigRevision 记录供应商实例配置修订号。
	ProviderConfigRevision uint64
	// CatalogRevision records the atomic catalog revision.
	// CatalogRevision 记录原子目录修订号。
	CatalogRevision uint64
}
