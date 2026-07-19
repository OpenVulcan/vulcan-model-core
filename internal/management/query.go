package management

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// QueryService builds client-safe provider and model discovery views.
// QueryService 构建客户端安全的供应商与模型发现视图。
type QueryService struct {
	// configurations supplies provider definitions and instance configuration.
	// configurations 提供供应商定义与实例配置。
	configurations providerconfig.Store
	// catalogs supplies atomic provider model and resource snapshots.
	// catalogs 提供原子供应商模型与资源快照。
	catalogs catalog.Store
}

// NewQueryService creates one client-safe management query service.
// NewQueryService 创建一个客户端安全的管理查询服务。
func NewQueryService(configurations providerconfig.Store, catalogs catalog.Store) (*QueryService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	return &QueryService{configurations: configurations, catalogs: catalogs}, nil
}

// ProviderDefinitionView is a client-safe system or custom provider definition.
// ProviderDefinitionView 是一个客户端安全的系统或自定义供应商定义。
type ProviderDefinitionView struct {
	// ID is the immutable system_ or custom_ identifier.
	// ID 是不可变的 system_ 或 custom_ 标识。
	ID string `json:"id"`
	// Kind identifies code-owned or user-owned definition semantics.
	// Kind 标识代码拥有或用户拥有的定义语义。
	Kind providerconfig.DefinitionKind `json:"kind"`
	// DisplayName is the management-facing provider name.
	// DisplayName 是管理界面显示的供应商名称。
	DisplayName string `json:"display_name"`
	// GroupID identifies optional management-only brand grouping.
	// GroupID 标识可选且仅供管理使用的品牌分组。
	GroupID string `json:"group_id,omitempty"`
	// VariantName is the concise locale-neutral label within the group.
	// VariantName 是分组内简洁且与区域设置无关的标签。
	VariantName string `json:"variant_name,omitempty"`
	// VariantDescription explains the exact site or product boundary.
	// VariantDescription 说明精确的站点或产品边界。
	VariantDescription string `json:"variant_description,omitempty"`
	// VariantDescriptionKey identifies authored client localization for this variant.
	// VariantDescriptionKey 标识此变体的客户端编写本地化文本。
	VariantDescriptionKey string `json:"variant_description_key,omitempty"`
	// ModelCatalogID identifies shared code-owned model metadata.
	// ModelCatalogID 标识共享的代码拥有模型元数据。
	ModelCatalogID string `json:"model_catalog_id,omitempty"`
	// SortOrder is the stable ordering inside the provider group.
	// SortOrder 是供应商分组内的稳定排序值。
	SortOrder int `json:"sort_order"`
	// ProtocolProfileID identifies the provider's sole executable protocol.
	// ProtocolProfileID 标识供应商唯一的可执行协议。
	ProtocolProfileID string `json:"protocol_profile_id"`
	// EndpointPresets contains safe code-owned onboarding destinations.
	// EndpointPresets 包含安全的代码拥有录入目标。
	EndpointPresets []EndpointPresetView `json:"endpoint_presets"`
	// AuthMethods contains supported credential acquisition shapes.
	// AuthMethods 包含支持的凭据获取形态。
	AuthMethods []AuthMethodView `json:"auth_methods"`
	// Features reports optional system-provider management capabilities.
	// Features 报告可选系统供应商管理能力。
	Features FeatureView `json:"features"`
	// Revision is the immutable definition revision.
	// Revision 是不可变定义修订号。
	Revision uint64 `json:"revision"`
}

// ProviderGroupView contains one management group and its selectable system provider definitions.
// ProviderGroupView 包含一个管理分组及其可选择的系统供应商定义。
type ProviderGroupView struct {
	// ID is the immutable management-only group identifier.
	// ID 是不可变且仅供管理使用的分组标识。
	ID string `json:"id"`
	// DisplayName is the locale-neutral provider brand name.
	// DisplayName 是与区域设置无关的供应商品牌名称。
	DisplayName string `json:"display_name"`
	// Description explains the shared brand represented by this group.
	// Description 说明此分组代表的共享品牌。
	Description string `json:"description"`
	// DescriptionKey identifies authored client localization for this group.
	// DescriptionKey 标识此分组的客户端编写本地化文本。
	DescriptionKey string `json:"description_key,omitempty"`
	// SortOrder is the stable management catalog ordering value.
	// SortOrder 是稳定的管理目录排序值。
	SortOrder int `json:"sort_order"`
	// ProviderDefinitions contains exact selectable execution definitions in this group.
	// ProviderDefinitions 包含此分组内可精确选择的执行定义。
	ProviderDefinitions []ProviderDefinitionView `json:"provider_definitions"`
	// Revision is the immutable group metadata revision.
	// Revision 是不可变的分组元数据修订号。
	Revision uint64 `json:"revision"`
}

// EndpointPresetView exposes one safe default destination during provider onboarding.
// EndpointPresetView 在供应商录入期间暴露一个安全的默认目标。
type EndpointPresetView struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string `json:"id"`
	// BaseURL is the default absolute upstream address.
	// BaseURL 是默认的上游绝对地址。
	BaseURL string `json:"base_url"`
	// Region is the locale-neutral site label.
	// Region 是与区域设置无关的站点标签。
	Region string `json:"region"`
	// UserEditable reports whether management clients may replace the address.
	// UserEditable 表示管理客户端是否可以替换该地址。
	UserEditable bool `json:"user_editable"`
}

// AuthMethodView describes one supported authentication method.
// AuthMethodView 描述一种支持的认证方式。
type AuthMethodView struct {
	// ID is stable within the provider definition.
	// ID 在供应商定义内保持稳定。
	ID string `json:"id"`
	// Type identifies OAuth, API key, bearer, or another declared mechanism.
	// Type 标识 OAuth、API Key、Bearer 或其他已声明机制。
	Type providerconfig.AuthMethodType `json:"type"`
	// Refreshable reports whether the provider can refresh the credential.
	// Refreshable 报告供应商是否可以刷新凭据。
	Refreshable bool `json:"refreshable"`
	// MultipleCredentials reports whether one instance accepts an account pool.
	// MultipleCredentials 报告一个实例是否接受账号池。
	MultipleCredentials bool `json:"multiple_credentials"`
}

// FeatureView reports optional trusted provider management features.
// FeatureView 报告可选的受信任供应商管理能力。
type FeatureView struct {
	// ModelDiscovery reports model listing support.
	// ModelDiscovery 报告模型列表支持状态。
	ModelDiscovery providerconfig.SupportStatus `json:"model_discovery"`
	// PlanReader reports commercial plan reading support.
	// PlanReader 报告商业套餐读取支持状态。
	PlanReader providerconfig.SupportStatus `json:"plan_reader"`
	// EntitlementReader reports account-model entitlement support.
	// EntitlementReader 报告账号模型授权支持状态。
	EntitlementReader providerconfig.SupportStatus `json:"entitlement_reader"`
	// AllowanceReader reports quota and balance reading support.
	// AllowanceReader 报告额度与余额读取支持状态。
	AllowanceReader providerconfig.SupportStatus `json:"allowance_reader"`
}

// ProviderInstanceView contains client-safe configuration state and aggregate counts.
// ProviderInstanceView 包含客户端安全的配置状态与聚合数量。
type ProviderInstanceView struct {
	// ID is the immutable provider instance identifier.
	// ID 是不可变供应商实例标识。
	ID string `json:"id"`
	// DefinitionID identifies the exact system or custom definition.
	// DefinitionID 标识精确系统或自定义定义。
	DefinitionID string `json:"definition_id"`
	// Handle is the stable workspace routing alias.
	// Handle 是稳定的工作区路由别名。
	Handle string `json:"handle"`
	// DisplayName is the editable instance name.
	// DisplayName 是可编辑实例名称。
	DisplayName string `json:"display_name"`
	// Status is the current configuration lifecycle state.
	// Status 是当前配置生命周期状态。
	Status providerconfig.LifecycleStatus `json:"status"`
	// DisabledModelIDs lists models disabled by local management policy.
	// DisabledModelIDs 列出被本地管理策略禁用的模型。
	DisabledModelIDs []string `json:"disabled_model_ids"`
	// EndpointCount is the configured endpoint count.
	// EndpointCount 是已配置端点数量。
	EndpointCount int `json:"endpoint_count"`
	// CredentialCount is the configured credential count without account identities.
	// CredentialCount 是不包含账号身份的已配置凭据数量。
	CredentialCount int `json:"credential_count"`
	// BindingCount is the configured access binding count.
	// BindingCount 是已配置访问绑定数量。
	BindingCount int `json:"binding_count"`
	// Revision is the persisted configuration revision.
	// Revision 是持久化配置修订号。
	Revision uint64 `json:"revision"`
}

// EndpointView contains one management-safe upstream endpoint record.
// EndpointView 包含一个管理安全的上游端点记录。
type EndpointView struct {
	// ID is the immutable endpoint identifier.
	// ID 是不可变端点标识。
	ID string `json:"id"`
	// ProviderInstanceID identifies the exact endpoint owner.
	// ProviderInstanceID 标识精确端点所有者。
	ProviderInstanceID string `json:"provider_instance_id"`
	// BaseURL is the validated upstream base URL.
	// BaseURL 是已校验的上游基础 URL。
	BaseURL string `json:"base_url"`
	// Region is the optional provider-defined region label.
	// Region 是可选供应商定义区域标签。
	Region string `json:"region"`
	// Status is the current local endpoint availability state.
	// Status 是当前本地端点可用性状态。
	Status providerconfig.EndpointStatus `json:"status"`
	// Revision identifies the persisted endpoint revision.
	// Revision 标识持久化端点修订号。
	Revision uint64 `json:"revision"`
}

// CredentialView contains management-safe non-secret credential metadata.
// CredentialView 包含管理安全的非秘密凭据元数据。
type CredentialView struct {
	// ID is the immutable credential identifier.
	// ID 是不可变凭据标识。
	ID string `json:"id"`
	// ProviderInstanceID identifies the exact credential owner.
	// ProviderInstanceID 标识精确凭据所有者。
	ProviderInstanceID string `json:"provider_instance_id"`
	// AuthMethodID identifies the configured provider authentication method.
	// AuthMethodID 标识配置的供应商认证方式。
	AuthMethodID string `json:"auth_method_id"`
	// Label is the management-facing credential label.
	// Label 是管理界面凭据标签。
	Label string `json:"label"`
	// Status is the current local credential eligibility state.
	// Status 是当前本地凭据资格状态。
	Status providerconfig.CredentialStatus `json:"status"`
	// ExpiresAt is the provider-reported expiration when it is known.
	// ExpiresAt 是已知时供应商报告的到期时间。
	ExpiresAt *time.Time `json:"expires_at"`
	// CoolingUntil is the local recovery time for a cooling credential when applicable.
	// CoolingUntil 是适用时处于冷却状态凭据的本地恢复时间。
	CoolingUntil *time.Time `json:"cooling_until"`
	// Revision identifies the persisted credential revision.
	// Revision 标识持久化凭据修订号。
	Revision uint64 `json:"revision"`
}

// BindingView contains one management-safe access binding without any secret material.
// BindingView 包含一个不带任何 Secret 材料的管理安全访问绑定。
type BindingView struct {
	// ID is the immutable access binding identifier.
	// ID 是不可变访问绑定标识。
	ID string `json:"id"`
	// ProviderInstanceID identifies the exact binding owner.
	// ProviderInstanceID 标识精确绑定所有者。
	ProviderInstanceID string `json:"provider_instance_id"`
	// EndpointID identifies the bound same-instance endpoint.
	// EndpointID 标识绑定的同实例端点。
	EndpointID string `json:"endpoint_id"`
	// CredentialID identifies the bound same-instance credential.
	// CredentialID 标识绑定的同实例凭据。
	CredentialID string `json:"credential_id"`
	// AllowedModelIDs lists explicit model restrictions when present.
	// AllowedModelIDs 列出存在时的显式模型限制。
	AllowedModelIDs []string `json:"allowed_model_ids"`
	// Priority is the deterministic same-pool selection order.
	// Priority 是确定性的同账号池选择顺序。
	Priority int `json:"priority"`
	// Enabled reports whether the binding participates in resolution.
	// Enabled 报告该绑定是否参与解析。
	Enabled bool `json:"enabled"`
	// Revision identifies the persisted binding revision.
	// Revision 标识持久化绑定修订号。
	Revision uint64 `json:"revision"`
}

// CatalogView contains one client-safe atomic provider model catalog.
// CatalogView 包含一个客户端安全的原子供应商模型目录。
type CatalogView struct {
	// ProviderInstanceID owns every returned model and resource.
	// ProviderInstanceID 是全部返回模型与资源的所有者。
	ProviderInstanceID string `json:"provider_instance_id"`
	// Models contains logical provider models and selectable execution shapes.
	// Models 包含逻辑供应商模型与可选执行形态。
	Models []ModelView `json:"models"`
	// Allowances contains redacted quota, balance, and credit state.
	// Allowances 包含已经脱敏的额度、余额与 Credit 状态。
	Allowances []AllowanceView `json:"allowances"`
	// Plans contains account-identity-free commercial plan aggregates.
	// Plans 包含不带账号身份的商业套餐聚合。
	Plans []PlanView `json:"plans"`
	// Revision identifies the complete atomic catalog revision.
	// Revision 标识完整原子目录修订号。
	Revision uint64 `json:"revision"`
	// ObservedAt records when the catalog was produced.
	// ObservedAt 记录目录生成时间。
	ObservedAt time.Time `json:"observed_at"`
}

// ModelView describes one logical provider model and its channel offerings.
// ModelView 描述一个逻辑供应商模型及其通道产品。
type ModelView struct {
	// ID is the provider-scoped model identifier selected by VulcanCode.
	// ID 是 VulcanCode 选择的供应商作用域模型标识。
	ID string `json:"id"`
	// UpstreamModelID is the provider's stable model identifier.
	// UpstreamModelID 是供应商稳定模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// DisplayName is the client-facing model name.
	// DisplayName 是客户端显示的模型名称。
	DisplayName string `json:"display_name"`
	// EntitlementMode reports whether account-specific authorization is required.
	// EntitlementMode 报告是否要求账号特定授权。
	EntitlementMode catalog.EntitlementMode `json:"entitlement_mode"`
	// Enabled reports whether local management policy allows call-plane use of this model.
	// Enabled 报告本地管理策略是否允许调用面使用该模型。
	Enabled bool `json:"enabled"`
	// ProviderAuthorized reports whether provider evidence permits at least one configured account to use this model.
	// ProviderAuthorized 报告供应商证据是否允许至少一个已配置账号使用此模型。
	ProviderAuthorized bool `json:"provider_authorized"`
	// Offerings contains channel-specific products and selectable profiles.
	// Offerings 包含通道特定产品与可选规格。
	Offerings []OfferingView `json:"offerings"`
}

// OfferingView describes one model product on one provider channel.
// OfferingView 描述一个供应商通道上的模型产品。
type OfferingView struct {
	// ID is the immutable offering identifier.
	// ID 是不可变产品标识。
	ID string `json:"id"`
	// UpstreamModelID is the exact model value used by the channel.
	// UpstreamModelID 是通道使用的精确模型值。
	UpstreamModelID string `json:"upstream_model_id"`
	// Profiles contains client-selectable capability shapes.
	// Profiles 包含客户端可选能力形态。
	Profiles []ExecutionProfileView `json:"profiles"`
}

// ExecutionProfileView describes one selectable context and capability shape.
// ExecutionProfileView 描述一种可选上下文与能力形态。
type ExecutionProfileView struct {
	// ID is submitted explicitly by VulcanCode when multiple shapes exist.
	// ID 在存在多种形态时由 VulcanCode 显式提交。
	ID string `json:"id"`
	// DisplayName is the client-visible profile name.
	// DisplayName 是客户端可见规格名称。
	DisplayName string `json:"display_name"`
	// Default reports whether profile selection may be omitted.
	// Default 报告是否可以省略规格选择。
	Default bool `json:"default"`
	// Capabilities contains normalized client-visible behavior.
	// Capabilities 包含规范化的客户端可见行为。
	Capabilities CapabilityView `json:"capabilities"`
	// SwitchPolicy describes active-conversation profile switching.
	// SwitchPolicy 描述活动会话规格切换行为。
	SwitchPolicy catalog.ProfileSwitchPolicy `json:"switch_policy"`
	// PoolPolicy describes local credential selection within this profile.
	// PoolPolicy 描述该规格内的本地凭据选择策略。
	PoolPolicy catalog.PoolPolicy `json:"pool_policy"`
	// Pool reports aggregate account eligibility without account identifiers.
	// Pool 报告不含账号标识的聚合账号资格。
	Pool *PoolView `json:"pool,omitempty"`
}

// CapabilityView contains normalized capability and token limits.
// CapabilityView 包含规范化能力与 Token 限制。
type CapabilityView struct {
	// ContextWindow is the explicit or unknown total context ceiling.
	// ContextWindow 是明确或未知的总上下文上限。
	ContextWindow TokenLimitView `json:"context_window"`
	// MaxInputTokens is the independently known input ceiling.
	// MaxInputTokens 是独立已知的输入上限。
	MaxInputTokens TokenLimitView `json:"max_input_tokens"`
	// MaxOutputTokens is the independently known output ceiling.
	// MaxOutputTokens 是独立已知的输出上限。
	MaxOutputTokens TokenLimitView `json:"max_output_tokens"`
	// MaxReasoningTokens is the independently known reasoning ceiling.
	// MaxReasoningTokens 是独立已知的推理上限。
	MaxReasoningTokens TokenLimitView `json:"max_reasoning_tokens"`
	// RecommendedOutputTokens is the provider-evidenced default output budget.
	// RecommendedOutputTokens 是供应商证据支持的默认输出预算。
	RecommendedOutputTokens TokenLimitView `json:"recommended_output_tokens"`
	// RecommendedReasoningTokens is the provider-evidenced default reasoning budget.
	// RecommendedReasoningTokens 是供应商证据支持的默认推理预算。
	RecommendedReasoningTokens TokenLimitView `json:"recommended_reasoning_tokens"`
	// ToolCalling reports normalized tool call support.
	// ToolCalling 报告规范化工具调用支持。
	ToolCalling catalog.CapabilityLevel `json:"tool_calling"`
	// ParallelToolCalls reports parallel tool execution support.
	// ParallelToolCalls 报告并行工具执行支持。
	ParallelToolCalls catalog.CapabilityLevel `json:"parallel_tool_calls"`
	// StreamingToolArguments reports incremental argument support.
	// StreamingToolArguments 报告增量参数支持。
	StreamingToolArguments catalog.CapabilityLevel `json:"streaming_tool_arguments"`
	// StrictJSONSchema reports strict structured output support.
	// StrictJSONSchema 报告严格结构化输出支持。
	StrictJSONSchema catalog.CapabilityLevel `json:"strict_json_schema"`
	// Reasoning reports reasoning behavior support.
	// Reasoning 报告推理行为支持。
	Reasoning catalog.CapabilityLevel `json:"reasoning"`
	// InputModalities lists normalized accepted input modalities.
	// InputModalities 列出规范化输入模态。
	InputModalities []string `json:"input_modalities"`
	// OutputModalities lists normalized produced output modalities.
	// OutputModalities 列出规范化输出模态。
	OutputModalities []string `json:"output_modalities"`
}

// TokenLimitView preserves the distinction between unknown and zero.
// TokenLimitView 保留未知值与零值之间的区别。
type TokenLimitView struct {
	// Known reports whether Value is authoritative.
	// Known 报告 Value 是否具有权威性。
	Known bool `json:"known"`
	// Value is the positive token ceiling when Known is true.
	// Value 是 Known 为真时的正 Token 上限。
	Value int64 `json:"value,omitempty"`
}

// PoolView contains aggregate account readiness for one execution profile.
// PoolView 包含一个执行规格的聚合账号就绪状态。
type PoolView struct {
	// ConfiguredCredentials is the total configured account count.
	// ConfiguredCredentials 是已配置账号总数。
	ConfiguredCredentials int `json:"configured_credentials"`
	// EntitledCredentials is the authorized account count.
	// EntitledCredentials 是已授权账号数量。
	EntitledCredentials int `json:"entitled_credentials"`
	// ReadyCredentials is the immediately executable account count.
	// ReadyCredentials 是立即可执行账号数量。
	ReadyCredentials int `json:"ready_credentials"`
	// CoolingCredentials is the temporary cooldown account count.
	// CoolingCredentials 是临时冷却账号数量。
	CoolingCredentials int `json:"cooling_credentials"`
	// ExhaustedCredentials is the allowance-blocked account count.
	// ExhaustedCredentials 是被额度阻塞账号数量。
	ExhaustedCredentials int `json:"exhausted_credentials"`
	// InvalidCredentials is the invalid or expired account count.
	// InvalidCredentials 是无效或过期账号数量。
	InvalidCredentials int `json:"invalid_credentials"`
	// BlockingAllowanceKinds lists resource shapes blocking the pool.
	// BlockingAllowanceKinds 列出阻塞账号池的资源形态。
	BlockingAllowanceKinds []catalog.AllowanceKind `json:"blocking_allowance_kinds"`
	// EarliestResetAt is the earliest known recovery time.
	// EarliestResetAt 是最早已知恢复时间。
	EarliestResetAt *time.Time `json:"earliest_reset_at,omitempty"`
}

// AllowanceView contains resource state without upstream account identifiers.
// AllowanceView 包含不暴露上游账号标识的资源状态。
type AllowanceView struct {
	// Kind identifies a window quota, balance, credit, or provider-defined resource.
	// Kind 标识窗口额度、余额、Credit 或供应商自定义资源。
	Kind catalog.AllowanceKind `json:"kind"`
	// Scope identifies the owner type without returning its sensitive identifier.
	// Scope 标识所有者类型且不返回其敏感标识。
	Scope catalog.AllowanceScope `json:"scope"`
	// Metric is the normalized resource metric.
	// Metric 是规范化资源指标。
	Metric string `json:"metric"`
	// Unit identifies the accounting unit.
	// Unit 标识计量单位。
	Unit catalog.AllowanceUnit `json:"unit"`
	// Currency is present only for minor currency units.
	// Currency 仅在货币最小单位时存在。
	Currency string `json:"currency,omitempty"`
	// Limit is an exact optional decimal string.
	// Limit 是精确的可选十进制字符串。
	Limit *string `json:"limit,omitempty"`
	// Used is an exact optional decimal string.
	// Used 是精确的可选十进制字符串。
	Used *string `json:"used,omitempty"`
	// Remaining is an exact optional decimal string.
	// Remaining 是精确的可选十进制字符串。
	Remaining *string `json:"remaining,omitempty"`
	// RemainingRatio is the optional normalized remaining ratio.
	// RemainingRatio 是可选规范化剩余比例。
	RemainingRatio *float64 `json:"remaining_ratio,omitempty"`
	// Status is the normalized resource state.
	// Status 是规范化资源状态。
	Status catalog.AllowanceStatus `json:"status"`
	// Mandatory reports whether exhaustion blocks execution.
	// Mandatory 报告资源耗尽是否阻塞执行。
	Mandatory bool `json:"mandatory"`
	// Window contains reset semantics for a window quota.
	// Window 包含窗口额度的重置语义。
	Window *AllowanceWindowView `json:"window,omitempty"`
	// ObservedAt records when the resource state was obtained.
	// ObservedAt 记录资源状态获取时间。
	ObservedAt time.Time `json:"observed_at"`
	// ExpiresAt records when the resource state becomes stale.
	// ExpiresAt 记录资源状态失效时间。
	ExpiresAt time.Time `json:"expires_at"`
}

// PlanView aggregates equal commercial plans without returning credential identities.
// PlanView 聚合相同商业套餐且不返回凭据身份。
type PlanView struct {
	// PlanCode is the provider-normalized commercial tier code.
	// PlanCode 是供应商规范化商业等级代码。
	PlanCode string `json:"plan_code"`
	// PlanName is the provider-facing plan name.
	// PlanName 是供应商显示套餐名称。
	PlanName string `json:"plan_name"`
	// Status is the normalized plan lifecycle state.
	// Status 是规范化套餐生命周期状态。
	Status string `json:"status"`
	// CredentialCount is the number of configured accounts on this plan.
	// CredentialCount 是属于该套餐的已配置账号数量。
	CredentialCount int `json:"credential_count"`
}

// AllowanceWindowView contains client-safe quota reset semantics.
// AllowanceWindowView 包含客户端安全的额度重置语义。
type AllowanceWindowView struct {
	// Kind identifies rolling, calendar, or provider-defined window semantics.
	// Kind 标识滚动、日历或供应商自定义窗口语义。
	Kind catalog.WindowKind `json:"kind"`
	// Duration is the exact base-10 nanosecond length of a rolling window.
	// Duration 是滚动窗口精确的十进制纳秒时长。
	Duration string `json:"duration"`
	// CalendarUnit is the provider-normalized calendar unit.
	// CalendarUnit 是供应商规范化日历单位。
	CalendarUnit string `json:"calendar_unit,omitempty"`
	// TimeZone identifies the provider calendar time zone when known.
	// TimeZone 标识已知时的供应商日历时区。
	TimeZone string `json:"time_zone,omitempty"`
	// ResetAt is the next known reset time.
	// ResetAt 是下一次已知重置时间。
	ResetAt *time.Time `json:"reset_at,omitempty"`
}

// ListDefinitions returns all visible system and custom provider definitions.
// ListDefinitions 返回全部可见系统与自定义供应商定义。
func (q *QueryService) ListDefinitions(ctx context.Context) ([]ProviderDefinitionView, error) {
	definitions, errDefinitions := q.configurations.ListDefinitions(ctx)
	if errDefinitions != nil {
		return nil, errDefinitions
	}
	views := make([]ProviderDefinitionView, 0, len(definitions))
	for _, definition := range definitions {
		views = append(views, definitionView(definition))
	}
	return views, nil
}

// ListProviderGroups returns code-owned provider groups with their exact selectable definitions.
// ListProviderGroups 返回代码拥有的供应商分组及其精确可选择定义。
func (q *QueryService) ListProviderGroups(ctx context.Context) ([]ProviderGroupView, error) {
	groups, errGroups := q.configurations.ListProviderGroups(ctx)
	if errGroups != nil {
		return nil, errGroups
	}
	definitions, errDefinitions := q.configurations.ListDefinitions(ctx)
	if errDefinitions != nil {
		return nil, errDefinitions
	}
	// definitionsByGroup owns only system definitions that explicitly reference a registered group.
	// definitionsByGroup 仅管理显式引用已注册分组的系统定义。
	definitionsByGroup := make(map[string][]ProviderDefinitionView, len(groups))
	for _, definition := range definitions {
		if definition.Kind != providerconfig.DefinitionKindSystem || definition.GroupID == "" {
			continue
		}
		definitionsByGroup[definition.GroupID] = append(definitionsByGroup[definition.GroupID], definitionView(definition))
	}
	views := make([]ProviderGroupView, 0, len(groups))
	for _, group := range groups {
		groupDefinitions := definitionsByGroup[group.ID]
		sort.Slice(groupDefinitions, func(left int, right int) bool {
			if groupDefinitions[left].SortOrder != groupDefinitions[right].SortOrder {
				return groupDefinitions[left].SortOrder < groupDefinitions[right].SortOrder
			}
			return groupDefinitions[left].ID < groupDefinitions[right].ID
		})
		views = append(views, ProviderGroupView{
			ID:                  group.ID,
			DisplayName:         group.DisplayName,
			Description:         group.Description,
			DescriptionKey:      group.DescriptionKey,
			SortOrder:           group.SortOrder,
			ProviderDefinitions: groupDefinitions,
			Revision:            group.Revision,
		})
	}
	return views, nil
}

// ListInstances returns client-safe aggregate views for all provider instances.
// ListInstances 返回全部供应商实例的客户端安全聚合视图。
func (q *QueryService) ListInstances(ctx context.Context) ([]ProviderInstanceView, error) {
	instances, errInstances := q.configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return nil, errInstances
	}
	views := make([]ProviderInstanceView, 0, len(instances))
	for _, instance := range instances {
		view, errView := q.instanceView(ctx, instance)
		if errView != nil {
			return nil, errView
		}
		views = append(views, view)
	}
	return views, nil
}

// GetInstance returns one client-safe provider instance aggregate.
// GetInstance 返回一个客户端安全的供应商实例聚合。
func (q *QueryService) GetInstance(ctx context.Context, instanceID string) (ProviderInstanceView, error) {
	instance, errInstance := q.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return ProviderInstanceView{}, errInstance
	}
	return q.instanceView(ctx, instance)
}

// GetCatalog returns one client-safe provider model, profile, pool, and allowance view.
// GetCatalog 返回一个客户端安全的供应商模型、规格、账号池与额度视图。
func (q *QueryService) GetCatalog(ctx context.Context, instanceID string) (CatalogView, error) {
	instance, errInstance := q.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return CatalogView{}, errInstance
	}
	snapshot, errSnapshot := q.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return CatalogView{}, errSnapshot
	}
	return catalogView(snapshot, instance.DisabledModelIDs), nil
}

// ListEndpoints returns management-safe endpoint records for one exact provider instance.
// ListEndpoints 返回一个精确供应商实例的管理安全端点记录。
func (q *QueryService) ListEndpoints(ctx context.Context, instanceID string) ([]EndpointView, error) {
	endpoints, errEndpoints := q.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return nil, errEndpoints
	}
	views := make([]EndpointView, 0, len(endpoints))
	for _, endpoint := range endpoints {
		views = append(views, EndpointView{
			ID:                 endpoint.ID,
			ProviderInstanceID: endpoint.ProviderInstanceID,
			BaseURL:            endpoint.BaseURL,
			Region:             endpoint.Region,
			Status:             endpoint.Status,
			Revision:           endpoint.Revision,
		})
	}
	return views, nil
}

// ListCredentials returns management-safe credential metadata without SecretRef, fingerprint, or account identity.
// ListCredentials 返回管理安全凭据元数据且不包含 SecretRef、指纹或账号身份。
func (q *QueryService) ListCredentials(ctx context.Context, instanceID string) ([]CredentialView, error) {
	credentials, errCredentials := q.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return nil, errCredentials
	}
	views := make([]CredentialView, 0, len(credentials))
	for _, credential := range credentials {
		views = append(views, CredentialView{
			ID:                 credential.ID,
			ProviderInstanceID: credential.ProviderInstanceID,
			AuthMethodID:       credential.AuthMethodID,
			Label:              credential.Label,
			Status:             credential.Status,
			ExpiresAt:          cloneTime(credential.ExpiresAt),
			CoolingUntil:       cloneTime(credential.CoolingUntil),
			Revision:           credential.Revision,
		})
	}
	return views, nil
}

// ListBindings returns management-safe access bindings for one exact provider instance.
// ListBindings 返回一个精确供应商实例的管理安全访问绑定。
func (q *QueryService) ListBindings(ctx context.Context, instanceID string) ([]BindingView, error) {
	bindings, errBindings := q.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return nil, errBindings
	}
	views := make([]BindingView, 0, len(bindings))
	for _, binding := range bindings {
		views = append(views, BindingView{
			ID:                 binding.ID,
			ProviderInstanceID: binding.ProviderInstanceID,
			EndpointID:         binding.EndpointID,
			CredentialID:       binding.CredentialID,
			AllowedModelIDs:    append([]string(nil), binding.AllowedModelIDs...),
			Priority:           binding.Priority,
			Enabled:            binding.Enabled,
			Revision:           binding.Revision,
		})
	}
	return views, nil
}

// instanceView builds aggregate counts without exposing credential identities.
// instanceView 构建不暴露凭据身份的聚合数量。
func (q *QueryService) instanceView(ctx context.Context, instance providerconfig.ProviderInstance) (ProviderInstanceView, error) {
	endpoints, errEndpoints := q.configurations.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil {
		return ProviderInstanceView{}, errEndpoints
	}
	credentials, errCredentials := q.configurations.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		return ProviderInstanceView{}, errCredentials
	}
	bindings, errBindings := q.configurations.ListBindings(ctx, instance.ID)
	if errBindings != nil {
		return ProviderInstanceView{}, errBindings
	}
	return ProviderInstanceView{
		ID:           instance.ID,
		DefinitionID: instance.DefinitionID,
		Handle:       instance.Handle,
		DisplayName:  instance.DisplayName,
		Status:       instance.Status,
		// DisabledModelIDs starts from a non-nil slice so the public JSON contract emits [] instead of null.
		// DisabledModelIDs 从非 nil 切片开始，以便公共 JSON 合同输出 [] 而不是 null。
		DisabledModelIDs: append([]string{}, instance.DisabledModelIDs...),
		EndpointCount:    len(endpoints),
		CredentialCount:  len(credentials),
		BindingCount:     len(bindings),
		Revision:         instance.Revision,
	}, nil
}

// definitionView converts one internal provider definition to a safe DTO.
// definitionView 将一个内部供应商定义转换为安全 DTO。
func definitionView(definition providerconfig.ProviderDefinition) ProviderDefinitionView {
	authMethods := make([]AuthMethodView, 0, len(definition.AuthMethods))
	for _, authMethod := range definition.AuthMethods {
		authMethods = append(authMethods, AuthMethodView{
			ID:                  authMethod.ID,
			Type:                authMethod.Type,
			Refreshable:         authMethod.Refreshable,
			MultipleCredentials: authMethod.MultipleCredentials,
		})
	}
	endpointPresets := make([]EndpointPresetView, 0, len(definition.EndpointPresets))
	for _, preset := range definition.EndpointPresets {
		endpointPresets = append(endpointPresets, EndpointPresetView{
			ID:           preset.ID,
			BaseURL:      preset.BaseURL,
			Region:       preset.Region,
			UserEditable: preset.UserEditable,
		})
	}
	return ProviderDefinitionView{
		ID:                    definition.ID,
		Kind:                  definition.Kind,
		DisplayName:           definition.DisplayName,
		GroupID:               definition.GroupID,
		VariantName:           definition.VariantName,
		VariantDescription:    definition.VariantDescription,
		VariantDescriptionKey: definition.VariantDescriptionKey,
		ModelCatalogID:        definition.ModelCatalogID,
		SortOrder:             definition.SortOrder,
		ProtocolProfileID:     definition.ProtocolProfileID,
		EndpointPresets:       endpointPresets,
		AuthMethods:           authMethods,
		Features: FeatureView{
			ModelDiscovery:    definition.Features.ModelDiscovery,
			PlanReader:        definition.Features.PlanReader,
			EntitlementReader: definition.Features.EntitlementReader,
			AllowanceReader:   definition.Features.AllowanceReader,
		},
		Revision: definition.Revision,
	}
}

// catalogView converts one atomic internal snapshot to a redacted client view.
// catalogView 将一个原子内部快照转换为脱敏客户端视图。
func catalogView(snapshot catalog.Snapshot, disabledModelIDs []string) CatalogView {
	offeringsByModel := make(map[string][]catalog.ModelOffering)
	for _, offering := range snapshot.Offerings {
		offeringsByModel[offering.ProviderModelID] = append(offeringsByModel[offering.ProviderModelID], offering)
	}
	profilesByOffering := make(map[string][]catalog.ExecutionProfile)
	for _, profile := range snapshot.Profiles {
		profilesByOffering[profile.OfferingID] = append(profilesByOffering[profile.OfferingID], profile)
	}
	poolsByProfile := make(map[string]catalog.PoolSummary)
	for _, pool := range snapshot.Pools {
		poolsByProfile[pool.ExecutionProfileID] = pool
	}
	// explicitlyAuthorizedModels records models allowed by at least one credential-specific provider entitlement.
	// explicitlyAuthorizedModels 记录至少被一个凭据特定供应商授权允许的模型。
	explicitlyAuthorizedModels := make(map[string]struct{})
	for _, entitlement := range snapshot.Entitlements {
		if entitlement.Availability == catalog.AvailabilityAllowed {
			explicitlyAuthorizedModels[entitlement.ProviderModelID] = struct{}{}
		}
	}
	models := make([]ModelView, 0, len(snapshot.Models))
	for _, model := range snapshot.Models {
		offeringViews := make([]OfferingView, 0, len(offeringsByModel[model.ID]))
		for _, offering := range offeringsByModel[model.ID] {
			profileViews := make([]ExecutionProfileView, 0, len(profilesByOffering[offering.ID]))
			for _, profile := range profilesByOffering[offering.ID] {
				profileView := ExecutionProfileView{
					ID:           profile.ID,
					DisplayName:  profile.DisplayName,
					Default:      profile.Default,
					Capabilities: capabilityView(profile.Capabilities),
					SwitchPolicy: profile.SwitchPolicy,
					PoolPolicy:   profile.PoolPolicy,
				}
				if pool, exists := poolsByProfile[profile.ID]; exists {
					poolValue := poolView(pool)
					profileView.Pool = &poolValue
				}
				profileViews = append(profileViews, profileView)
			}
			sort.Slice(profileViews, func(left int, right int) bool {
				if profileViews[left].Default != profileViews[right].Default {
					return profileViews[left].Default
				}
				leftContext := profileViews[left].Capabilities.ContextWindow
				rightContext := profileViews[right].Capabilities.ContextWindow
				if leftContext.Known && rightContext.Known && leftContext.Value != rightContext.Value {
					return leftContext.Value < rightContext.Value
				}
				return profileViews[left].ID < profileViews[right].ID
			})
			offeringViews = append(offeringViews, OfferingView{ID: offering.ID, UpstreamModelID: offering.UpstreamModelID, Profiles: profileViews})
		}
		sort.Slice(offeringViews, func(left int, right int) bool {
			return offeringViews[left].ID < offeringViews[right].ID
		})
		// explicitlyAuthorized records whether a credential-specific entitlement allows this exact model.
		// explicitlyAuthorized 记录凭据特定授权是否允许此精确模型。
		_, explicitlyAuthorized := explicitlyAuthorizedModels[model.ID]
		// providerAuthorized keeps provider authorization separate from the local disabled-model policy.
		// providerAuthorized 将供应商授权与本地停用模型策略保持分离。
		providerAuthorized := model.EntitlementMode == catalog.EntitlementAllBoundCredentials || explicitlyAuthorized
		models = append(models, ModelView{ID: model.ID, UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName, EntitlementMode: model.EntitlementMode, Enabled: !modelDisabled(disabledModelIDs, model.ID), ProviderAuthorized: providerAuthorized, Offerings: offeringViews})
	}
	sort.Slice(models, func(left int, right int) bool {
		return models[left].ID < models[right].ID
	})
	allowances := make([]AllowanceView, 0, len(snapshot.Allowances))
	for _, allowance := range snapshot.Allowances {
		allowanceView := AllowanceView{
			Kind:           allowance.Kind,
			Scope:          allowance.Scope,
			Metric:         allowance.Metric,
			Unit:           allowance.Unit,
			Currency:       allowance.Currency,
			Limit:          cloneString(allowance.Limit),
			Used:           cloneString(allowance.Used),
			Remaining:      cloneString(allowance.Remaining),
			RemainingRatio: cloneFloat(allowance.RemainingRatio),
			Status:         allowance.Status,
			Mandatory:      allowance.Mandatory,
			ObservedAt:     allowance.ObservedAt,
			ExpiresAt:      allowance.ExpiresAt,
		}
		if allowance.Window != nil {
			allowanceView.Window = &AllowanceWindowView{Kind: allowance.Window.Kind, Duration: strconv.FormatInt(int64(allowance.Window.Duration), 10), CalendarUnit: allowance.Window.CalendarUnit, TimeZone: allowance.Window.TimeZone, ResetAt: cloneTime(allowance.Window.ResetAt)}
		}
		allowances = append(allowances, allowanceView)
	}
	plansByKey := make(map[string]*PlanView)
	for _, plan := range snapshot.Plans {
		planKey := plan.PlanCode + "\x00" + plan.PlanName + "\x00" + plan.Status
		if existing, exists := plansByKey[planKey]; exists {
			existing.CredentialCount++
			continue
		}
		plansByKey[planKey] = &PlanView{PlanCode: plan.PlanCode, PlanName: plan.PlanName, Status: plan.Status, CredentialCount: 1}
	}
	plans := make([]PlanView, 0, len(plansByKey))
	for _, plan := range plansByKey {
		plans = append(plans, *plan)
	}
	sort.Slice(plans, func(left int, right int) bool {
		if plans[left].PlanCode != plans[right].PlanCode {
			return plans[left].PlanCode < plans[right].PlanCode
		}
		if plans[left].PlanName != plans[right].PlanName {
			return plans[left].PlanName < plans[right].PlanName
		}
		return plans[left].Status < plans[right].Status
	})
	return CatalogView{ProviderInstanceID: snapshot.ProviderInstanceID, Models: models, Allowances: allowances, Plans: plans, Revision: snapshot.Revision, ObservedAt: snapshot.ObservedAt}
}

// modelDisabled reports whether local management policy explicitly disables one model identifier.
// modelDisabled 返回本地管理策略是否显式禁用一个模型标识。
func modelDisabled(disabledModelIDs []string, modelID string) bool {
	for _, disabledModelID := range disabledModelIDs {
		if disabledModelID == modelID {
			return true
		}
	}
	return false
}

// capabilityView converts internal capability metadata to an explicit client DTO.
// capabilityView 将内部能力元数据转换为显式客户端 DTO。
func capabilityView(capabilities catalog.ModelCapabilities) CapabilityView {
	return CapabilityView{
		ContextWindow:              tokenLimitView(capabilities.Tokens.ContextWindow),
		MaxInputTokens:             tokenLimitView(capabilities.Tokens.MaxInputTokens),
		MaxOutputTokens:            tokenLimitView(capabilities.Tokens.MaxOutputTokens),
		MaxReasoningTokens:         tokenLimitView(capabilities.Tokens.MaxReasoningTokens),
		RecommendedOutputTokens:    tokenLimitView(capabilities.Recommendations.OutputTokens),
		RecommendedReasoningTokens: tokenLimitView(capabilities.Recommendations.ReasoningTokens),
		ToolCalling:                capabilities.ToolCalling,
		ParallelToolCalls:          capabilities.ParallelToolCalls,
		StreamingToolArguments:     capabilities.StreamingToolArguments,
		StrictJSONSchema:           capabilities.StrictJSONSchema,
		Reasoning:                  capabilities.Reasoning,
		InputModalities:            append([]string(nil), capabilities.InputModalities...),
		OutputModalities:           append([]string(nil), capabilities.OutputModalities...),
	}
}

// tokenLimitView preserves explicit unknown token ceilings.
// tokenLimitView 保留显式未知 Token 上限。
func tokenLimitView(limit catalog.OptionalTokenLimit) TokenLimitView {
	return TokenLimitView{Known: limit.Known, Value: limit.Value}
}

// poolView converts one client-safe aggregate pool summary.
// poolView 转换一个客户端安全的聚合账号池摘要。
func poolView(pool catalog.PoolSummary) PoolView {
	return PoolView{
		ConfiguredCredentials:  pool.ConfiguredCredentials,
		EntitledCredentials:    pool.EntitledCredentials,
		ReadyCredentials:       pool.ReadyCredentials,
		CoolingCredentials:     pool.CoolingCredentials,
		ExhaustedCredentials:   pool.ExhaustedCredentials,
		InvalidCredentials:     pool.InvalidCredentials,
		BlockingAllowanceKinds: append([]catalog.AllowanceKind(nil), pool.BlockingAllowanceKinds...),
		EarliestResetAt:        cloneTime(pool.EarliestResetAt),
	}
}

// cloneString copies one optional exact decimal string.
// cloneString 复制一个可选精确十进制字符串。
func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// cloneFloat copies one optional normalized ratio.
// cloneFloat 复制一个可选规范化比例。
func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// cloneTime copies one optional timestamp.
// cloneTime 复制一个可选时间戳。
func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
