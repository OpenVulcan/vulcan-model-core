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
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
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
	// resolver derives live pool readiness from persisted runtime routing state.
	// resolver 从持久化运行时路由状态派生实时账号池就绪情况。
	resolver *resolve.Resolver
	// now returns the authoritative evaluation time for expiring commercial metadata.
	// now 返回评估商业元数据过期状态的权威时间。
	now func() time.Time
}

// NewQueryService creates one client-safe management query service.
// NewQueryService 创建一个客户端安全的管理查询服务。
func NewQueryService(configurations providerconfig.Store, catalogs catalog.Store) (*QueryService, error) {
	return NewQueryServiceWithRuntimeState(configurations, catalogs, nil)
}

// NewQueryServiceWithRuntimeState creates a management query service whose pool views include live cooldown state.
// NewQueryServiceWithRuntimeState 创建一个账号池视图包含实时冷却状态的管理查询服务。
func NewQueryServiceWithRuntimeState(configurations providerconfig.Store, catalogs catalog.Store, runtimeState routingstate.Store) (*QueryService, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	targetResolver, errResolver := resolve.NewWithRuntimeState(configurations, catalogs, runtimeState)
	if errResolver != nil {
		return nil, errResolver
	}
	return &QueryService{configurations: configurations, catalogs: catalogs, resolver: targetResolver, now: time.Now}, nil
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
	// PlanOptions contains immutable commercial tiers accepted by declared credentials.
	// PlanOptions 包含声明式凭据可选择的不可变商业档位。
	PlanOptions []PlanOptionView `json:"plan_options"`
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

// EndpointParameterDefinitionView exposes one safe non-secret endpoint input contract.
// EndpointParameterDefinitionView 暴露一个安全的非秘密端点输入契约。
type EndpointParameterDefinitionView struct {
	// ID is the stable request-field identifier.
	// ID 是稳定的请求字段标识。
	ID string `json:"id"`
	// Kind identifies the closed client validation rule.
	// Kind 标识封闭的客户端校验规则。
	Kind providerconfig.EndpointParameterKind `json:"kind"`
	// Required reports whether onboarding must provide the value.
	// Required 表示录入时是否必须提供该值。
	Required bool `json:"required"`
}

// EndpointParameterValueView exposes one persisted non-secret endpoint value.
// EndpointParameterValueView 暴露一个持久化的非秘密端点值。
type EndpointParameterValueView struct {
	// ID identifies the matching endpoint parameter definition.
	// ID 标识匹配的端点参数定义。
	ID string `json:"id"`
	// Value is the validated non-secret parameter value.
	// Value 是经过校验的非秘密参数值。
	Value string `json:"value"`
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
	// RegionEditable reports whether management may select a provider-owned regional origin.
	// RegionEditable 表示管理端是否可以选择供应商拥有的区域 Origin。
	RegionEditable bool `json:"region_editable"`
	// Parameters declares the exact non-secret values required during onboarding.
	// Parameters 声明录入时所需的精确非秘密值。
	Parameters []EndpointParameterDefinitionView `json:"parameters,omitempty"`
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
	// PlanAcquisition declares whether plan evidence is detected, required manually, optional, or unavailable.
	// PlanAcquisition 声明套餐证据是自动识别、人工必选、人工可选还是不可获得。
	PlanAcquisition providerconfig.PlanAcquisitionMode `json:"plan_acquisition"`
}

// PlanOptionView exposes one safe code-owned commercial plan choice.
// PlanOptionView 暴露一个安全的代码拥有商业套餐选项。
type PlanOptionView struct {
	// ID is the stable request value.
	// ID 是稳定的请求值。
	ID string `json:"id"`
	// DisplayName is the provider's locale-neutral plan name.
	// DisplayName 是供应商与语言环境无关的套餐名称。
	DisplayName string `json:"display_name"`
	// DisplayNameKey identifies authored client localization.
	// DisplayNameKey 标识客户端编写的本地化文本。
	DisplayNameKey string `json:"display_name_key,omitempty"`
	// AuthMethodIDs lists exact authentication methods associated with this tier.
	// AuthMethodIDs 列出与该档位关联的精确认证方式。
	AuthMethodIDs []string `json:"auth_method_ids"`
	// ManuallySelectable reports whether management clients may submit this option.
	// ManuallySelectable 表示管理客户端是否可以提交该选项。
	ManuallySelectable bool `json:"manually_selectable"`
	// SortOrder is the stable display ordering.
	// SortOrder 是稳定的显示顺序。
	SortOrder int `json:"sort_order"`
	// Revision identifies the immutable option schema revision.
	// Revision 标识不可变选项 Schema 修订号。
	Revision uint64 `json:"revision"`
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
	// RoutingStrategy optionally overrides the Router-wide credential selection strategy.
	// RoutingStrategy 可选覆盖 Router 全局凭据选择策略。
	RoutingStrategy providerconfig.RoutingStrategy `json:"routing_strategy"`
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
	// Parameters contains the validated non-secret values used to derive the endpoint.
	// Parameters 包含用于派生端点且经过校验的非秘密值。
	Parameters []EndpointParameterValueView `json:"parameters,omitempty"`
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
	// Priority orders this account before endpoint paths; lower values win.
	// Priority 在入口路径之前排列该账号；较小值优先。
	Priority int `json:"priority"`
	// DeclaredPlan contains safe operator-authored membership metadata when present.
	// DeclaredPlan 在存在时包含安全的操作员声明会员元数据。
	DeclaredPlan *providerconfig.DeclaredPlanSelection `json:"declared_plan,omitempty"`
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
	// AllowedServiceIDs lists explicit special-service restrictions when present.
	// AllowedServiceIDs 列出存在时的明确特殊服务限制。
	AllowedServiceIDs []string `json:"allowed_service_ids"`
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
	// DefaultAdditionalParameters contains provider-wide request mutations inherited by every model.
	// DefaultAdditionalParameters 包含由每个模型继承的供应商级请求变更。
	DefaultAdditionalParameters catalog.AdditionalPayloadProjection `json:"default_additional_parameters"`
	// Models contains logical provider models and selectable execution shapes.
	// Models 包含逻辑供应商模型与可选执行形态。
	Models []ModelView `json:"models"`
	// Services contains logical special services and exact offerings.
	// Services 包含逻辑特殊服务与精确产品。
	Services []ServiceView `json:"services"`
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

// ServiceView describes one provider-scoped special service.
// ServiceView 描述一个供应商作用域特殊服务。
type ServiceView struct {
	// ID is the provider-scoped service identifier.
	// ID 是供应商作用域服务标识。
	ID string `json:"id"`
	// DisplayName is the client-facing service name.
	// DisplayName 是客户端显示服务名称。
	DisplayName string `json:"display_name"`
	// Operation is the sole public VCP operation.
	// Operation 是唯一公共 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// EntitlementMode reports account-specific authorization requirements.
	// EntitlementMode 报告账号特定授权要求。
	EntitlementMode catalog.EntitlementMode `json:"entitlement_mode"`
	// Enabled reports local management policy.
	// Enabled 报告本地管理策略。
	Enabled bool `json:"enabled"`
	// AuthorizationStatus preserves authorized, denied, and unknown provider evidence.
	// AuthorizationStatus 保留已授权、已拒绝与未知三种供应商证据状态。
	AuthorizationStatus catalog.AuthorizationStatus `json:"authorization_status"`
	// Offerings contains exact channel implementations.
	// Offerings 包含精确通道实现。
	Offerings []ServiceOfferingView `json:"offerings"`
}

// ServiceOfferingView describes one exact special-service implementation.
// ServiceOfferingView 描述一个精确特殊服务实现。
type ServiceOfferingView struct {
	// ID is the immutable service offering identifier.
	// ID 是不可变服务产品标识。
	ID string `json:"id"`
	// UpstreamServiceID is the exact safe upstream engine or model handle.
	// UpstreamServiceID 是精确安全上游引擎或模型句柄。
	UpstreamServiceID string `json:"upstream_service_id"`
	// Capabilities contains the closed service capability variant.
	// Capabilities 包含封闭服务能力变体。
	Capabilities catalog.ServiceCapabilities `json:"capabilities"`
	// Profiles contains client-selectable executable shapes.
	// Profiles 包含客户端可选择执行形态。
	Profiles []ServiceExecutionProfileView `json:"profiles"`
}

// ServiceExecutionProfileView describes one exact service profile.
// ServiceExecutionProfileView 描述一个精确服务规格。
type ServiceExecutionProfileView struct {
	// ID is the exact profile identifier.
	// ID 是精确规格标识。
	ID string `json:"id"`
	// DisplayName is the client-visible profile name.
	// DisplayName 是客户端可见规格名称。
	DisplayName string `json:"display_name"`
	// Default reports whether selection may be omitted.
	// Default 报告是否可以省略选择。
	Default bool `json:"default"`
	// Operation identifies the exact VCP operation.
	// Operation 标识精确 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// ActionBindingID identifies the immutable provider action.
	// ActionBindingID 标识不可变供应商动作。
	ActionBindingID string `json:"action_binding_id"`
	// Capabilities contains the effective service contract.
	// Capabilities 包含有效服务契约。
	Capabilities catalog.ServiceCapabilities `json:"capabilities"`
	// Pool reports aggregate runtime eligibility.
	// Pool 报告聚合运行资格。
	Pool *PoolView `json:"pool,omitempty"`
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
	// AuthorizationStatus preserves authorized, denied, and unknown provider evidence.
	// AuthorizationStatus 保留已授权、已拒绝与未知三种供应商证据状态。
	AuthorizationStatus catalog.AuthorizationStatus `json:"authorization_status"`
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
	// RequestProjection contains editable provider-channel outbound parameter rules.
	// RequestProjection 包含可编辑的供应商通道出站参数规则。
	RequestProjection catalog.RequestProjection `json:"request_projection"`
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
	// Operation identifies the exact VCP operation when this is a typed profile.
	// Operation 标识类型化 Profile 的精确 VCP 操作。
	Operation vcp.OperationKind `json:"operation,omitempty"`
	// ActionBindingID identifies the immutable provider action implementation.
	// ActionBindingID 标识不可变供应商动作实现。
	ActionBindingID string `json:"action_binding_id,omitempty"`
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
	// ReasoningEfforts lists exact accepted reasoning control values.
	// ReasoningEfforts 列出精确接受的推理控制值。
	ReasoningEfforts []string `json:"reasoning_efforts"`
	// ReasoningSummaryModes lists exact supported visible reasoning summary values.
	// ReasoningSummaryModes 列出精确支持的可见推理摘要值。
	ReasoningSummaryModes []string `json:"reasoning_summary_modes"`
	// InputModalities lists normalized accepted input modalities.
	// InputModalities 列出规范化输入模态。
	InputModalities []string `json:"input_modalities"`
	// OutputModalities lists normalized produced output modalities.
	// OutputModalities 列出规范化输出模态。
	OutputModalities []string `json:"output_modalities"`
	// MediaInputs contains typed media input contracts.
	// MediaInputs 包含类型化媒体输入合同。
	MediaInputs []catalog.MediaInputCapability `json:"media_inputs,omitempty"`
	// Delivery declares real execution delivery modes.
	// Delivery 声明真实执行交付模式。
	Delivery catalog.DeliveryCapabilities `json:"delivery"`
	// Embedding contains vectorization constraints when applicable.
	// Embedding 在适用时包含向量化约束。
	Embedding *catalog.EmbeddingCapabilities `json:"embedding,omitempty"`
	// Rerank contains ranking constraints when applicable.
	// Rerank 在适用时包含排序约束。
	Rerank *catalog.RerankCapabilities `json:"rerank,omitempty"`
	// MediaOutputs contains typed generated-media contracts.
	// MediaOutputs 包含类型化生成媒体合同。
	MediaOutputs []catalog.MediaOutputCapability `json:"media_outputs,omitempty"`
	// Parameters contains closed operation parameter descriptors.
	// Parameters 包含封闭操作参数描述。
	Parameters []catalog.ParameterDescriptor `json:"parameters,omitempty"`
	// ParameterRules contains typed cross-parameter conditions.
	// ParameterRules 包含类型化跨参数条件。
	ParameterRules []catalog.ParameterRule `json:"parameter_rules,omitempty"`
	// UsageMetrics lists independently observable usage dimensions.
	// UsageMetrics 列出可独立观察的用量维度。
	UsageMetrics []catalog.UsageMetricCapability `json:"usage_metrics,omitempty"`
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
	// CredentialID is the local management identifier for credential-scoped resources.
	// CredentialID 是凭据作用域资源的本地管理标识。
	CredentialID string `json:"credential_id,omitempty"`
	// CredentialLabel is the operator-authored local credential name.
	// CredentialLabel 是操作员编写的本地凭据名称。
	CredentialLabel string `json:"credential_label,omitempty"`
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

// ModelContextsView describes every client-selectable context profile and its concrete authorized accounts.
// ModelContextsView 描述每个客户端可选上下文规格及其具体已授权账号。
type ModelContextsView struct {
	// ProviderInstanceID fixes the provider boundary for every returned account.
	// ProviderInstanceID 固定每个返回账号的供应商边界。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderModelID identifies the exact non-fused model.
	// ProviderModelID 标识精确且未融合的模型。
	ProviderModelID string `json:"provider_model_id"`
	// UpstreamModelID is the safe provider-facing model identifier.
	// UpstreamModelID 是安全的供应商侧模型标识。
	UpstreamModelID string `json:"upstream_model_id"`
	// DisplayName is the client-facing model name.
	// DisplayName 是客户端显示模型名称。
	DisplayName string `json:"display_name"`
	// ContextProfiles contains every model context shape and its exact account set.
	// ContextProfiles 包含每个模型上下文形态及其精确账号集合。
	ContextProfiles []ModelContextProfileView `json:"context_profiles"`
	// CatalogRevision identifies the atomic evidence revision used by this response.
	// CatalogRevision 标识该响应使用的原子证据修订号。
	CatalogRevision uint64 `json:"catalog_revision"`
	// ObservedAt records when the underlying catalog was produced.
	// ObservedAt 记录底层目录生成时间。
	ObservedAt time.Time `json:"observed_at"`
}

// ModelContextProfileView describes one context type and every account authorized to execute it.
// ModelContextProfileView 描述一种上下文类型及每个有权执行它的账号。
type ModelContextProfileView struct {
	// ID is the exact execution profile identifier submitted by clients.
	// ID 是客户端提交的精确执行规格标识。
	ID string `json:"id"`
	// OfferingID identifies the model channel product that owns this profile.
	// OfferingID 标识拥有该规格的模型通道产品。
	OfferingID string `json:"offering_id"`
	// DisplayName is the client-visible context type name.
	// DisplayName 是客户端可见的上下文类型名称。
	DisplayName string `json:"display_name"`
	// Default reports whether clients may omit explicit profile selection.
	// Default 报告客户端是否可以省略显式规格选择。
	Default bool `json:"default"`
	// Operation is the exact VCP operation supported by this context type.
	// Operation 是该上下文类型支持的精确 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// Capabilities contains token boundaries, modalities, and normalized features.
	// Capabilities 包含 Token 边界、模态与规范化功能。
	Capabilities CapabilityView `json:"capabilities"`
	// SwitchPolicy describes active-conversation profile switching.
	// SwitchPolicy 描述活动会话规格切换行为。
	SwitchPolicy catalog.ProfileSwitchPolicy `json:"switch_policy"`
	// PoolPolicy describes account selection inside this profile.
	// PoolPolicy 描述该规格内部的账号选择方式。
	PoolPolicy catalog.PoolPolicy `json:"pool_policy"`
	// Accounts contains concrete authorized local accounts without secret material.
	// Accounts 包含不带秘密材料的具体已授权本地账号。
	Accounts []ModelContextAccountView `json:"accounts"`
}

// ModelContextAccountView contains one safe concrete account under a model context profile.
// ModelContextAccountView 包含模型上下文规格下的一个安全具体账号。
type ModelContextAccountView struct {
	// CredentialID is the local identifier used for account-specific V1 queries.
	// CredentialID 是账号专属 V1 查询使用的本地标识。
	CredentialID string `json:"credential_id"`
	// Label is the operator-authored local account name.
	// Label 是操作员编写的本地账号名称。
	Label string `json:"label"`
	// CredentialStatus is the persisted credential lifecycle state.
	// CredentialStatus 是持久化凭据生命周期状态。
	CredentialStatus providerconfig.CredentialStatus `json:"credential_status"`
	// CredentialExpiresAt is the provider-reported credential expiry when known.
	// CredentialExpiresAt 是已知时供应商报告的凭据到期时间。
	CredentialExpiresAt *time.Time `json:"credential_expires_at,omitempty"`
	// Priority is the account routing preference; lower values win.
	// Priority 是账号路由偏好；较小值优先。
	Priority int `json:"priority"`
	// PlanCode is the current provider or operator-evidenced commercial plan.
	// PlanCode 是当前供应商或操作员证据支持的商业套餐。
	PlanCode string `json:"plan_code,omitempty"`
	// EntitlementClass is the provider-normalized authorization class.
	// EntitlementClass 是供应商规范化授权类别。
	EntitlementClass string `json:"entitlement_class,omitempty"`
	// EffectiveContextWindow is the account-specific effective context ceiling.
	// EffectiveContextWindow 是账号专属有效上下文上限。
	EffectiveContextWindow TokenLimitView `json:"effective_context_window"`
	// RuntimeStatus explains current execution readiness.
	// RuntimeStatus 说明当前执行就绪状态。
	RuntimeStatus resolve.ContextAccountRuntimeStatus `json:"runtime_status"`
	// CoolingUntil is the known credential recovery time when present.
	// CoolingUntil 是存在时已知的凭据恢复时间。
	CoolingUntil *time.Time `json:"cooling_until,omitempty"`
	// BlockingAllowanceKinds lists mandatory exhausted resources.
	// BlockingAllowanceKinds 列出强制且已耗尽的资源。
	BlockingAllowanceKinds []catalog.AllowanceKind `json:"blocking_allowance_kinds"`
	// EarliestResetAt is the earliest known allowance recovery time.
	// EarliestResetAt 是已知最早额度恢复时间。
	EarliestResetAt *time.Time `json:"earliest_reset_at,omitempty"`
	// UsageAvailable reports whether current catalog usage applies to this model context and account.
	// UsageAvailable 报告当前目录是否存在适用于此模型上下文与账号的用量。
	UsageAvailable bool `json:"usage_available"`
}

// ModelCredentialUsageView contains usage applicable to one exact model-account pair.
// ModelCredentialUsageView 包含适用于一个精确模型账号组合的用量。
type ModelCredentialUsageView struct {
	// ProviderInstanceID fixes the provider boundary.
	// ProviderInstanceID 固定供应商边界。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderModelID identifies the exact provider-scoped model.
	// ProviderModelID 标识精确的供应商作用域模型。
	ProviderModelID string `json:"provider_model_id"`
	// CredentialID identifies the exact configured account.
	// CredentialID 标识精确配置账号。
	CredentialID string `json:"credential_id"`
	// CredentialLabel is the operator-authored local account name.
	// CredentialLabel 是操作员编写的本地账号名称。
	CredentialLabel string `json:"credential_label"`
	// CredentialStatus is the current persisted lifecycle state.
	// CredentialStatus 是当前持久化生命周期状态。
	CredentialStatus providerconfig.CredentialStatus `json:"credential_status"`
	// CredentialExpiresAt is the provider-reported credential expiry when known.
	// CredentialExpiresAt 是已知时供应商报告的凭据到期时间。
	CredentialExpiresAt *time.Time `json:"credential_expires_at,omitempty"`
	// PlanCode is the current commercial plan evidence for this account.
	// PlanCode 是该账号当前商业套餐证据。
	PlanCode string `json:"plan_code,omitempty"`
	// SupportedContextProfileIDs lists the exact contexts under which this account can serve the model.
	// SupportedContextProfileIDs 列出该账号可服务此模型的精确上下文。
	SupportedContextProfileIDs []string `json:"supported_context_profile_ids"`
	// Allowances contains every current model-applicable usage observation.
	// Allowances 包含每个当前适用于该模型的用量观测。
	Allowances []ModelUsageAllowanceView `json:"allowances"`
	// CatalogRevision identifies the atomic evidence revision used by this response.
	// CatalogRevision 标识该响应使用的原子证据修订号。
	CatalogRevision uint64 `json:"catalog_revision"`
	// ObservedAt records when the underlying catalog was produced.
	// ObservedAt 记录底层目录生成时间。
	ObservedAt time.Time `json:"observed_at"`
}

// ModelUsageAllowanceView binds one usage observation to the model contexts where it applies.
// ModelUsageAllowanceView 将一条用量观测绑定到其适用的模型上下文。
type ModelUsageAllowanceView struct {
	// Usage contains the redacted normalized allowance values.
	// Usage 包含脱敏后的规范化额度值。
	Usage AllowanceView `json:"usage"`
	// ContextProfileIDs lists exact model contexts affected by this observation.
	// ContextProfileIDs 列出受该观测影响的精确模型上下文。
	ContextProfileIDs []string `json:"context_profile_ids"`
	// RequiredCapability identifies a conditional capability-scoped allowance.
	// RequiredCapability 标识一个条件能力作用域额度。
	RequiredCapability string `json:"required_capability,omitempty"`
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
	// EvidenceSource identifies whether the plan was provider-detected or operator-declared.
	// EvidenceSource 标识套餐是供应商自动识别还是操作员声明。
	EvidenceSource catalog.MetadataEvidenceSource `json:"evidence_source"`
	// ObservedAt is the newest observation represented by this aggregate.
	// ObservedAt 是该聚合所代表的最新观测时间。
	ObservedAt time.Time `json:"observed_at"`
	// ExpiresAt is the earliest nonzero expiry represented by this aggregate.
	// ExpiresAt 是该聚合所代表的最早非零到期时间。
	ExpiresAt time.Time `json:"expires_at,omitempty"`
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
	evaluatedAt := q.now().UTC()
	pools, errPools := q.resolver.SummarizeSnapshot(ctx, snapshot, evaluatedAt, snapshot.Revision)
	if errPools != nil {
		return CatalogView{}, errPools
	}
	snapshot.Pools = pools
	credentials, errCredentials := q.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return CatalogView{}, errCredentials
	}
	credentialIDs := make([]string, 0, len(credentials))
	credentialLabels := make(map[string]string, len(credentials))
	for _, credential := range credentials {
		credentialIDs = append(credentialIDs, credential.ID)
		credentialLabels[credential.ID] = credential.Label
	}
	return catalogView(snapshot, instance.DisabledModelIDs, instance.DisabledServiceIDs, credentialIDs, credentialLabels, evaluatedAt), nil
}

// GetModelContexts returns every context profile and the exact configured accounts authorized beneath it.
// GetModelContexts 返回每个上下文规格及其下方精确获得授权的配置账号。
func (q *QueryService) GetModelContexts(ctx context.Context, instanceID string, modelID string) (ModelContextsView, error) {
	snapshot, errSnapshot := q.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return ModelContextsView{}, errSnapshot
	}
	model, modelExists := queryModelByID(snapshot.Models, modelID)
	if !modelExists {
		return ModelContextsView{}, errors.Join(ErrProviderModelNotFound, errors.New(modelID))
	}
	evaluatedAt := q.now().UTC()
	contextStates, errContexts := q.resolver.InspectModelContexts(ctx, instanceID, modelID, evaluatedAt)
	if errContexts != nil {
		return ModelContextsView{}, errContexts
	}
	credentials, errCredentials := q.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return ModelContextsView{}, errCredentials
	}
	credentialByID := make(map[string]providerconfig.Credential, len(credentials))
	for _, credential := range credentials {
		credentialByID[credential.ID] = credential
	}
	planByCredential := currentPlanCodes(snapshot.Plans, evaluatedAt)
	profileByID := make(map[string]catalog.ExecutionProfile)
	for _, profile := range snapshot.Profiles {
		profileByID[profile.ID] = profile
	}
	profiles := make([]ModelContextProfileView, 0, len(contextStates))
	for _, contextState := range contextStates {
		profile, profileExists := profileByID[contextState.ProfileID]
		if !profileExists {
			return ModelContextsView{}, errors.New("resolved model context profile is missing from its catalog")
		}
		accounts := make([]ModelContextAccountView, 0, len(contextState.Accounts))
		for _, accountState := range contextState.Accounts {
			credential, credentialExists := credentialByID[accountState.CredentialID]
			if !credentialExists {
				return ModelContextsView{}, errors.New("resolved model context account is missing from provider configuration")
			}
			usageProfiles := applicableAllowanceProfiles(snapshot.Allowances, credential, model.ID, []catalog.ExecutionProfile{profile}, evaluatedAt)
			accounts = append(accounts, ModelContextAccountView{
				CredentialID: accountState.CredentialID, Label: credential.Label, CredentialStatus: accountState.CredentialStatus, CredentialExpiresAt: cloneTime(credential.ExpiresAt), Priority: accountState.Priority,
				PlanCode: planByCredential[accountState.CredentialID], EntitlementClass: accountState.EntitlementClass, EffectiveContextWindow: tokenLimitView(accountState.EffectiveContextWindow), RuntimeStatus: accountState.RuntimeStatus,
				CoolingUntil: cloneTime(accountState.CoolingUntil), BlockingAllowanceKinds: append([]catalog.AllowanceKind{}, accountState.BlockingAllowanceKinds...), EarliestResetAt: cloneTime(accountState.EarliestResetAt), UsageAvailable: len(usageProfiles) > 0,
			})
		}
		profiles = append(profiles, ModelContextProfileView{ID: profile.ID, OfferingID: profile.OfferingID, DisplayName: profile.DisplayName, Default: profile.Default, Operation: profile.Operation, Capabilities: capabilityView(profile.Capabilities), SwitchPolicy: profile.SwitchPolicy, PoolPolicy: profile.PoolPolicy, Accounts: accounts})
	}
	sort.Slice(profiles, func(left int, right int) bool {
		if profiles[left].Default != profiles[right].Default {
			return profiles[left].Default
		}
		leftContext := profiles[left].Capabilities.ContextWindow
		rightContext := profiles[right].Capabilities.ContextWindow
		if leftContext.Known && rightContext.Known && leftContext.Value != rightContext.Value {
			return leftContext.Value < rightContext.Value
		}
		return profiles[left].ID < profiles[right].ID
	})
	return ModelContextsView{ProviderInstanceID: instanceID, ProviderModelID: model.ID, UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName, ContextProfiles: profiles, CatalogRevision: snapshot.Revision, ObservedAt: snapshot.ObservedAt}, nil
}

// GetModelCredentialUsage returns every usage observation applicable to one exact model-account pair.
// GetModelCredentialUsage 返回适用于一个精确模型账号组合的全部用量观测。
func (q *QueryService) GetModelCredentialUsage(ctx context.Context, instanceID string, modelID string, credentialID string) (ModelCredentialUsageView, error) {
	snapshot, errSnapshot := q.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return ModelCredentialUsageView{}, errSnapshot
	}
	model, modelExists := queryModelByID(snapshot.Models, modelID)
	if !modelExists {
		return ModelCredentialUsageView{}, errors.Join(ErrProviderModelNotFound, errors.New(modelID))
	}
	evaluatedAt := q.now().UTC()
	contextStates, errContexts := q.resolver.InspectModelContexts(ctx, instanceID, modelID, evaluatedAt)
	if errContexts != nil {
		return ModelCredentialUsageView{}, errContexts
	}
	profileByID := make(map[string]catalog.ExecutionProfile)
	for _, profile := range snapshot.Profiles {
		profileByID[profile.ID] = profile
	}
	supportedProfiles := make([]catalog.ExecutionProfile, 0)
	for _, contextState := range contextStates {
		for _, account := range contextState.Accounts {
			if account.CredentialID != credentialID {
				continue
			}
			profile, profileExists := profileByID[contextState.ProfileID]
			if !profileExists {
				return ModelCredentialUsageView{}, errors.New("resolved model context profile is missing from its catalog")
			}
			supportedProfiles = append(supportedProfiles, profile)
			break
		}
	}
	if len(supportedProfiles) == 0 {
		return ModelCredentialUsageView{}, errors.Join(providerconfig.ErrNotFound, errors.New("credential is not authorized for the selected model"))
	}
	credentials, errCredentials := q.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return ModelCredentialUsageView{}, errCredentials
	}
	credential, credentialExists := queryCredentialByID(credentials, credentialID)
	if !credentialExists {
		return ModelCredentialUsageView{}, errors.Join(providerconfig.ErrNotFound, errors.New(credentialID))
	}
	credentialLabels := map[string]string{credential.ID: credential.Label}
	allowances := make([]ModelUsageAllowanceView, 0)
	for _, allowance := range snapshot.Allowances {
		profileIDs := applicableAllowanceProfiles([]catalog.AllowanceSnapshot{allowance}, credential, model.ID, supportedProfiles, evaluatedAt)
		if len(profileIDs) == 0 {
			continue
		}
		requiredCapability := ""
		if allowance.Scope == catalog.ScopeCapability {
			requiredCapability = allowance.ScopeID
		}
		allowances = append(allowances, ModelUsageAllowanceView{Usage: allowanceViewFrom(allowance, credentialLabels), ContextProfileIDs: profileIDs, RequiredCapability: requiredCapability})
	}
	sort.Slice(allowances, func(left int, right int) bool {
		if allowances[left].Usage.Metric != allowances[right].Usage.Metric {
			return allowances[left].Usage.Metric < allowances[right].Usage.Metric
		}
		return allowances[left].Usage.Kind < allowances[right].Usage.Kind
	})
	profileIDs := make([]string, 0, len(supportedProfiles))
	for _, profile := range supportedProfiles {
		profileIDs = append(profileIDs, profile.ID)
	}
	sort.Strings(profileIDs)
	return ModelCredentialUsageView{ProviderInstanceID: instanceID, ProviderModelID: model.ID, CredentialID: credential.ID, CredentialLabel: credential.Label, CredentialStatus: credential.Status, CredentialExpiresAt: cloneTime(credential.ExpiresAt), PlanCode: currentPlanCodes(snapshot.Plans, evaluatedAt)[credential.ID], SupportedContextProfileIDs: profileIDs, Allowances: allowances, CatalogRevision: snapshot.Revision, ObservedAt: snapshot.ObservedAt}, nil
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
		parameters := make([]EndpointParameterValueView, 0, len(endpoint.Parameters))
		for _, parameter := range endpoint.Parameters {
			parameters = append(parameters, EndpointParameterValueView{ID: parameter.ID, Value: parameter.Value})
		}
		views = append(views, EndpointView{
			ID:                 endpoint.ID,
			ProviderInstanceID: endpoint.ProviderInstanceID,
			BaseURL:            endpoint.BaseURL,
			Region:             endpoint.Region,
			Parameters:         parameters,
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
			Priority:           credential.Priority,
			DeclaredPlan:       cloneDeclaredPlan(credential.DeclaredPlan),
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
			AllowedServiceIDs:  append([]string(nil), binding.AllowedServiceIDs...),
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
		ID:              instance.ID,
		DefinitionID:    instance.DefinitionID,
		Handle:          instance.Handle,
		DisplayName:     instance.DisplayName,
		Status:          instance.Status,
		RoutingStrategy: instance.RoutingStrategy,
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
		planAcquisition := authMethod.PlanAcquisition
		if planAcquisition == "" {
			planAcquisition = providerconfig.PlanAcquisitionUnavailable
		}
		authMethods = append(authMethods, AuthMethodView{
			ID:                  authMethod.ID,
			Type:                authMethod.Type,
			Refreshable:         authMethod.Refreshable,
			MultipleCredentials: authMethod.MultipleCredentials,
			PlanAcquisition:     planAcquisition,
		})
	}
	planOptions := make([]PlanOptionView, 0, len(definition.PlanOptions))
	for _, planOption := range definition.PlanOptions {
		planOptions = append(planOptions, PlanOptionView{ID: planOption.ID, DisplayName: planOption.DisplayName, DisplayNameKey: planOption.DisplayNameKey, AuthMethodIDs: append([]string{}, planOption.AuthMethodIDs...), ManuallySelectable: planOption.ManuallySelectable, SortOrder: planOption.SortOrder, Revision: planOption.Revision})
	}
	endpointPresets := make([]EndpointPresetView, 0, len(definition.EndpointPresets))
	for _, preset := range definition.EndpointPresets {
		parameters := make([]EndpointParameterDefinitionView, 0, len(preset.Parameters))
		for _, parameter := range preset.Parameters {
			parameters = append(parameters, EndpointParameterDefinitionView{ID: parameter.ID, Kind: parameter.Kind, Required: parameter.Required})
		}
		endpointPresets = append(endpointPresets, EndpointPresetView{
			ID:             preset.ID,
			BaseURL:        preset.BaseURL,
			Region:         preset.Region,
			UserEditable:   preset.UserEditable,
			RegionEditable: preset.RegionalBaseURLTemplate != "",
			Parameters:     parameters,
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
		PlanOptions:           planOptions,
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
func catalogView(snapshot catalog.Snapshot, disabledModelIDs []string, disabledServiceIDs []string, credentialIDs []string, credentialLabels map[string]string, evaluationTime time.Time) CatalogView {
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
					ID:              profile.ID,
					DisplayName:     profile.DisplayName,
					Default:         profile.Default,
					Operation:       profile.Operation,
					ActionBindingID: profile.ActionBindingID,
					Capabilities:    capabilityView(profile.Capabilities),
					SwitchPolicy:    profile.SwitchPolicy,
					PoolPolicy:      profile.PoolPolicy,
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
			offeringViews = append(offeringViews, OfferingView{ID: offering.ID, UpstreamModelID: offering.UpstreamModelID, RequestProjection: catalog.CloneRequestProjection(offering.RequestProjection), Profiles: profileViews})
		}
		sort.Slice(offeringViews, func(left int, right int) bool {
			return offeringViews[left].ID < offeringViews[right].ID
		})
		authorizationStatus := modelAuthorizationStatus(model, snapshot.Entitlements, credentialIDs, evaluationTime)
		models = append(models, ModelView{ID: model.ID, UpstreamModelID: model.UpstreamModelID, DisplayName: model.DisplayName, EntitlementMode: model.EntitlementMode, Enabled: !modelDisabled(disabledModelIDs, model.ID), AuthorizationStatus: authorizationStatus, Offerings: offeringViews})
	}
	sort.Slice(models, func(left int, right int) bool {
		return models[left].ID < models[right].ID
	})
	serviceOfferingsByService := make(map[string][]catalog.ServiceOffering)
	for _, offering := range snapshot.ServiceOfferings {
		serviceOfferingsByService[offering.ProviderServiceID] = append(serviceOfferingsByService[offering.ProviderServiceID], offering)
	}
	serviceProfilesByOffering := make(map[string][]catalog.ExecutionProfile)
	for _, profile := range snapshot.Profiles {
		if profile.ServiceOfferingID != "" {
			serviceProfilesByOffering[profile.ServiceOfferingID] = append(serviceProfilesByOffering[profile.ServiceOfferingID], profile)
		}
	}
	services := make([]ServiceView, 0, len(snapshot.Services))
	for _, service := range snapshot.Services {
		offeringViews := make([]ServiceOfferingView, 0, len(serviceOfferingsByService[service.ID]))
		for _, offering := range serviceOfferingsByService[service.ID] {
			profileViews := make([]ServiceExecutionProfileView, 0, len(serviceProfilesByOffering[offering.ID]))
			for _, profile := range serviceProfilesByOffering[offering.ID] {
				capabilities := offering.Capabilities
				if profile.ServiceCapabilities != nil {
					capabilities = *profile.ServiceCapabilities
				}
				profileView := ServiceExecutionProfileView{ID: profile.ID, DisplayName: profile.DisplayName, Default: profile.Default, Operation: profile.Operation, ActionBindingID: profile.ActionBindingID, Capabilities: capabilities}
				if pool, exists := poolsByProfile[profile.ID]; exists {
					poolValue := poolView(pool)
					profileView.Pool = &poolValue
				}
				profileViews = append(profileViews, profileView)
			}
			sort.Slice(profileViews, func(left int, right int) bool { return profileViews[left].ID < profileViews[right].ID })
			offeringViews = append(offeringViews, ServiceOfferingView{ID: offering.ID, UpstreamServiceID: offering.UpstreamServiceID, Capabilities: offering.Capabilities, Profiles: profileViews})
		}
		sort.Slice(offeringViews, func(left int, right int) bool { return offeringViews[left].ID < offeringViews[right].ID })
		authorizationStatus := serviceAuthorizationStatus(service, snapshot.ServiceEntitlements, credentialIDs, evaluationTime)
		services = append(services, ServiceView{ID: service.ID, DisplayName: service.DisplayName, Operation: service.Operation, EntitlementMode: service.EntitlementMode, Enabled: !serviceDisabled(disabledServiceIDs, service.ID), AuthorizationStatus: authorizationStatus, Offerings: offeringViews})
	}
	sort.Slice(services, func(left int, right int) bool { return services[left].ID < services[right].ID })
	allowances := make([]AllowanceView, 0, len(snapshot.Allowances))
	for _, allowance := range snapshot.Allowances {
		allowances = append(allowances, allowanceViewFrom(allowance, credentialLabels))
	}
	plansByKey := make(map[string]*PlanView)
	for _, plan := range snapshot.Plans {
		planKey := plan.PlanCode + "\x00" + plan.PlanName + "\x00" + plan.Status + "\x00" + string(plan.EvidenceSource)
		if existing, exists := plansByKey[planKey]; exists {
			existing.CredentialCount++
			if plan.ObservedAt.After(existing.ObservedAt) {
				existing.ObservedAt = plan.ObservedAt
			}
			if !plan.ExpiresAt.IsZero() && (existing.ExpiresAt.IsZero() || plan.ExpiresAt.Before(existing.ExpiresAt)) {
				existing.ExpiresAt = plan.ExpiresAt
			}
			continue
		}
		plansByKey[planKey] = &PlanView{PlanCode: plan.PlanCode, PlanName: plan.PlanName, Status: plan.Status, CredentialCount: 1, EvidenceSource: plan.EvidenceSource, ObservedAt: plan.ObservedAt, ExpiresAt: plan.ExpiresAt}
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
		if plans[left].Status != plans[right].Status {
			return plans[left].Status < plans[right].Status
		}
		return plans[left].EvidenceSource < plans[right].EvidenceSource
	})
	return CatalogView{ProviderInstanceID: snapshot.ProviderInstanceID, DefaultAdditionalParameters: catalog.CloneAdditionalPayloadProjection(snapshot.DefaultAdditionalParameters), Models: models, Services: services, Allowances: allowances, Plans: plans, Revision: snapshot.Revision, ObservedAt: snapshot.ObservedAt}
}

// modelAuthorizationStatus derives three-state access without treating absent or expired evidence as denial.
// modelAuthorizationStatus 派生三态访问结果且不会把缺失或过期证据视为拒绝。
func modelAuthorizationStatus(model catalog.ProviderModel, entitlements []catalog.ModelEntitlement, credentialIDs []string, evaluationTime time.Time) catalog.AuthorizationStatus {
	if model.EntitlementMode == catalog.EntitlementAllBoundCredentials {
		if len(credentialIDs) == 0 {
			return catalog.AuthorizationUnknown
		}
		return catalog.AuthorizationAuthorized
	}
	credentialSet := make(map[string]struct{}, len(credentialIDs))
	for _, credentialID := range credentialIDs {
		credentialSet[credentialID] = struct{}{}
	}
	deniedCredentials := make(map[string]struct{})
	for _, entitlement := range entitlements {
		if entitlement.ProviderModelID != model.ID || !metadataEvidenceCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, evaluationTime) {
			continue
		}
		if _, configured := credentialSet[entitlement.CredentialID]; !configured {
			continue
		}
		if entitlement.Availability == catalog.AvailabilityAllowed {
			return catalog.AuthorizationAuthorized
		}
		if entitlement.Availability == catalog.AvailabilityDenied {
			deniedCredentials[entitlement.CredentialID] = struct{}{}
		}
	}
	if len(credentialIDs) > 0 && len(deniedCredentials) == len(credentialSet) {
		return catalog.AuthorizationDenied
	}
	return catalog.AuthorizationUnknown
}

// queryModelByID resolves one exact provider model from an atomic catalog.
// queryModelByID 从一个原子目录解析一个精确供应商模型。
func queryModelByID(models []catalog.ProviderModel, modelID string) (catalog.ProviderModel, bool) {
	for _, model := range models {
		if model.ID == modelID {
			return model, true
		}
	}
	return catalog.ProviderModel{}, false
}

// queryCredentialByID resolves one exact non-secret credential record.
// queryCredentialByID 解析一条精确的非秘密凭据记录。
func queryCredentialByID(credentials []providerconfig.Credential, credentialID string) (providerconfig.Credential, bool) {
	for _, credential := range credentials {
		if credential.ID == credentialID {
			return credential, true
		}
	}
	return providerconfig.Credential{}, false
}

// currentPlanCodes indexes only current commercial plan evidence by credential.
// currentPlanCodes 仅按凭据索引当前商业套餐证据。
func currentPlanCodes(plans []catalog.PlanSnapshot, evaluationTime time.Time) map[string]string {
	indexed := make(map[string]string)
	for _, plan := range plans {
		if metadataEvidenceCurrent(plan.ObservedAt, plan.ExpiresAt, evaluationTime) {
			indexed[plan.CredentialID] = plan.PlanCode
		}
	}
	return indexed
}

// applicableAllowanceProfiles returns exact supported profiles affected by at least one current usage observation.
// applicableAllowanceProfiles 返回至少受一条当前用量观测影响的精确受支持规格。
func applicableAllowanceProfiles(allowances []catalog.AllowanceSnapshot, credential providerconfig.Credential, modelID string, profiles []catalog.ExecutionProfile, evaluationTime time.Time) []string {
	profileIDs := make(map[string]struct{})
	for _, allowance := range allowances {
		if !metadataEvidenceCurrent(allowance.ObservedAt, allowance.ExpiresAt, evaluationTime) {
			continue
		}
		for _, profile := range profiles {
			requiredCapabilities := []string(nil)
			if allowance.Scope == catalog.ScopeCapability {
				requiredCapabilities = []string{allowance.ScopeID}
				if !resolve.CapabilitiesSatisfy(profile.Capabilities, requiredCapabilities) {
					continue
				}
			}
			if resolve.AllowanceAppliesToModelContext(allowance, credential, modelID, profile.ID, requiredCapabilities) {
				profileIDs[profile.ID] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(profileIDs))
	for profileID := range profileIDs {
		result = append(result, profileID)
	}
	sort.Strings(result)
	return result
}

// allowanceViewFrom converts one raw usage observation without exposing shared-scope identifiers.
// allowanceViewFrom 转换一条原始用量观测且不暴露共享作用域标识。
func allowanceViewFrom(allowance catalog.AllowanceSnapshot, credentialLabels map[string]string) AllowanceView {
	view := AllowanceView{Kind: allowance.Kind, Scope: allowance.Scope, Metric: allowance.Metric, Unit: allowance.Unit, Currency: allowance.Currency, Limit: cloneString(allowance.Limit), Used: cloneString(allowance.Used), Remaining: cloneString(allowance.Remaining), RemainingRatio: cloneFloat(allowance.RemainingRatio), Status: allowance.Status, Mandatory: allowance.Mandatory, ObservedAt: allowance.ObservedAt, ExpiresAt: allowance.ExpiresAt}
	if allowance.Scope == catalog.ScopeCredential {
		view.CredentialID = allowance.ScopeID
		view.CredentialLabel = credentialLabels[allowance.ScopeID]
	}
	if allowance.Window != nil {
		view.Window = &AllowanceWindowView{Kind: allowance.Window.Kind, Duration: strconv.FormatInt(int64(allowance.Window.Duration), 10), CalendarUnit: allowance.Window.CalendarUnit, TimeZone: allowance.Window.TimeZone, ResetAt: cloneTime(allowance.Window.ResetAt)}
	}
	return view
}

// serviceAuthorizationStatus derives three-state special-service access from current configured-account evidence.
// serviceAuthorizationStatus 根据当前已配置账号证据派生特殊服务三态访问结果。
func serviceAuthorizationStatus(service catalog.ProviderService, entitlements []catalog.ServiceEntitlement, credentialIDs []string, evaluationTime time.Time) catalog.AuthorizationStatus {
	if service.EntitlementMode == catalog.EntitlementAllBoundCredentials {
		if len(credentialIDs) == 0 {
			return catalog.AuthorizationUnknown
		}
		return catalog.AuthorizationAuthorized
	}
	credentialSet := make(map[string]struct{}, len(credentialIDs))
	for _, credentialID := range credentialIDs {
		credentialSet[credentialID] = struct{}{}
	}
	deniedCredentials := make(map[string]struct{})
	for _, entitlement := range entitlements {
		if entitlement.ProviderServiceID != service.ID || !metadataEvidenceCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, evaluationTime) {
			continue
		}
		if _, configured := credentialSet[entitlement.CredentialID]; !configured {
			continue
		}
		if entitlement.Availability == catalog.AvailabilityAllowed {
			return catalog.AuthorizationAuthorized
		}
		if entitlement.Availability == catalog.AvailabilityDenied {
			deniedCredentials[entitlement.CredentialID] = struct{}{}
		}
	}
	if len(credentialIDs) > 0 && len(deniedCredentials) == len(credentialSet) {
		return catalog.AuthorizationDenied
	}
	return catalog.AuthorizationUnknown
}

// metadataEvidenceCurrent reports whether commercial metadata is currently trustworthy.
// metadataEvidenceCurrent 报告商业元数据当前是否可信。
func metadataEvidenceCurrent(observedAt time.Time, expiresAt time.Time, evaluationTime time.Time) bool {
	return !observedAt.IsZero() && !observedAt.After(evaluationTime) && (expiresAt.IsZero() || expiresAt.After(evaluationTime))
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

// serviceDisabled reports whether local management policy explicitly disables one service identifier.
// serviceDisabled 返回本地管理策略是否显式停用一个服务标识。
func serviceDisabled(disabledServiceIDs []string, serviceID string) bool {
	for _, disabledServiceID := range disabledServiceIDs {
		if disabledServiceID == serviceID {
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
		ReasoningEfforts:           append([]string(nil), capabilities.ReasoningEfforts...),
		ReasoningSummaryModes:      append([]string(nil), capabilities.ReasoningSummaryModes...),
		InputModalities:            append([]string(nil), capabilities.InputModalities...),
		OutputModalities:           append([]string(nil), capabilities.OutputModalities...),
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

// cloneDeclaredPlan returns mutation-safe operator plan metadata.
// cloneDeclaredPlan 返回防止外部修改的操作员套餐元数据。
func cloneDeclaredPlan(value *providerconfig.DeclaredPlanSelection) *providerconfig.DeclaredPlanSelection {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
