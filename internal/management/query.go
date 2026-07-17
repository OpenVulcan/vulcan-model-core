package management

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
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
	if configurations == nil || catalogs == nil {
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
	// Channels contains executable protocol metadata without adapter internals.
	// Channels 包含不暴露 Adapter 内部信息的可执行协议元数据。
	Channels []ChannelView `json:"channels"`
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

// ChannelView describes one provider channel without implementation details.
// ChannelView 描述一个不包含实现细节的供应商通道。
type ChannelView struct {
	// ID is stable within the provider definition.
	// ID 在供应商定义内保持稳定。
	ID string `json:"id"`
	// ProtocolProfileID identifies the internal upstream protocol contract.
	// ProtocolProfileID 标识内部上游协议合同。
	ProtocolProfileID string `json:"protocol_profile_id"`
	// RuntimeReady reports local implementation readiness.
	// RuntimeReady 报告本地实现就绪状态。
	RuntimeReady bool `json:"runtime_ready"`
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
	// ChannelID identifies the selected provider access path.
	// ChannelID 标识所选供应商访问路径。
	ChannelID string `json:"channel_id"`
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
	// Duration is the rolling window length.
	// Duration 是滚动窗口长度。
	Duration time.Duration `json:"duration"`
	// CalendarUnit is the provider-normalized calendar unit.
	// CalendarUnit 是供应商规范化日历单位。
	CalendarUnit string `json:"calendar_unit,omitempty"`
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
	if _, errInstance := q.configurations.GetInstance(ctx, instanceID); errInstance != nil {
		return CatalogView{}, errInstance
	}
	snapshot, errSnapshot := q.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return CatalogView{}, errSnapshot
	}
	return catalogView(snapshot), nil
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
		ID:              instance.ID,
		DefinitionID:    instance.DefinitionID,
		Handle:          instance.Handle,
		DisplayName:     instance.DisplayName,
		Status:          instance.Status,
		EndpointCount:   len(endpoints),
		CredentialCount: len(credentials),
		BindingCount:    len(bindings),
		Revision:        instance.Revision,
	}, nil
}

// definitionView converts one internal provider definition to a safe DTO.
// definitionView 将一个内部供应商定义转换为安全 DTO。
func definitionView(definition providerconfig.ProviderDefinition) ProviderDefinitionView {
	channels := make([]ChannelView, 0, len(definition.Channels))
	for _, channel := range definition.Channels {
		channels = append(channels, ChannelView{ID: channel.ID, ProtocolProfileID: channel.ProtocolProfileID, RuntimeReady: channel.RuntimeReady})
	}
	authMethods := make([]AuthMethodView, 0, len(definition.AuthMethods))
	for _, authMethod := range definition.AuthMethods {
		authMethods = append(authMethods, AuthMethodView{
			ID:                  authMethod.ID,
			Type:                authMethod.Type,
			Refreshable:         authMethod.Refreshable,
			MultipleCredentials: authMethod.MultipleCredentials,
		})
	}
	return ProviderDefinitionView{
		ID:          definition.ID,
		Kind:        definition.Kind,
		DisplayName: definition.DisplayName,
		Channels:    channels,
		AuthMethods: authMethods,
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
func catalogView(snapshot catalog.Snapshot) CatalogView {
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
			offeringViews = append(offeringViews, OfferingView{ID: offering.ID, ChannelID: offering.ChannelID, UpstreamModelID: offering.UpstreamModelID, Profiles: profileViews})
		}
		sort.Slice(offeringViews, func(left int, right int) bool {
			return offeringViews[left].ID < offeringViews[right].ID
		})
		models = append(models, ModelView{ID: model.ID, UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName, EntitlementMode: model.EntitlementMode, Offerings: offeringViews})
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
			allowanceView.Window = &AllowanceWindowView{Kind: allowance.Window.Kind, Duration: allowance.Window.Duration, CalendarUnit: allowance.Window.CalendarUnit, ResetAt: cloneTime(allowance.Window.ResetAt)}
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
		return plans[left].Status < plans[right].Status
	})
	return CatalogView{ProviderInstanceID: snapshot.ProviderInstanceID, Models: models, Allowances: allowances, Plans: plans, Revision: snapshot.Revision, ObservedAt: snapshot.ObservedAt}
}

// capabilityView converts internal capability metadata to an explicit client DTO.
// capabilityView 将内部能力元数据转换为显式客户端 DTO。
func capabilityView(capabilities catalog.ModelCapabilities) CapabilityView {
	return CapabilityView{
		ContextWindow:          tokenLimitView(capabilities.Tokens.ContextWindow),
		MaxInputTokens:         tokenLimitView(capabilities.Tokens.MaxInputTokens),
		MaxOutputTokens:        tokenLimitView(capabilities.Tokens.MaxOutputTokens),
		MaxReasoningTokens:     tokenLimitView(capabilities.Tokens.MaxReasoningTokens),
		ToolCalling:            capabilities.ToolCalling,
		ParallelToolCalls:      capabilities.ParallelToolCalls,
		StreamingToolArguments: capabilities.StreamingToolArguments,
		StrictJSONSchema:       capabilities.StrictJSONSchema,
		Reasoning:              capabilities.Reasoning,
		InputModalities:        append([]string(nil), capabilities.InputModalities...),
		OutputModalities:       append([]string(nil), capabilities.OutputModalities...),
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
