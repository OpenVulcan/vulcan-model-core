package catalog

import (
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// SearchInvocationMode identifies the exact mechanism used to request model web access.
// SearchInvocationMode 标识请求模型联网的精确机制。
type SearchInvocationMode string

const (
	// SearchInvocationDirectRequest calls a dedicated search endpoint.
	// SearchInvocationDirectRequest 调用专用搜索端点。
	SearchInvocationDirectRequest SearchInvocationMode = "direct_request"
	// SearchInvocationAlwaysOn uses a model whose search is always enabled.
	// SearchInvocationAlwaysOn 使用始终启用搜索的模型。
	SearchInvocationAlwaysOn SearchInvocationMode = "model_always_on"
	// SearchInvocationNativeTool enables one provider-native search tool.
	// SearchInvocationNativeTool 启用一个供应商原生搜索工具。
	SearchInvocationNativeTool SearchInvocationMode = "native_tool"
	// SearchInvocationPrompt requests search through a versioned instruction template.
	// SearchInvocationPrompt 通过版本化指令模板请求搜索。
	SearchInvocationPrompt SearchInvocationMode = "prompt_required"
	// SearchInvocationNativeToolAndPrompt enables both documented mechanisms.
	// SearchInvocationNativeToolAndPrompt 同时启用两个有文档依据的机制。
	SearchInvocationNativeToolAndPrompt SearchInvocationMode = "native_tool_and_prompt"
)

// OptionalCountLimit represents a known positive count limit or an explicit unknown value.
// OptionalCountLimit 表示一个已知正数数量限制或显式未知值。
type OptionalCountLimit struct {
	// Known reports whether Value is authoritative.
	// Known 表示 Value 是否具有权威性。
	Known bool `json:"known"`
	// Value is the positive count limit when Known is true.
	// Value 是 Known 为真时的正数数量限制。
	Value int `json:"value"`
}

// SearchFilterCapabilities describes individually evidenced search filters.
// SearchFilterCapabilities 描述逐项有证据支持的搜索过滤器。
type SearchFilterCapabilities struct {
	// DomainAllow describes allowed-domain filtering.
	// DomainAllow 描述允许域名过滤。
	DomainAllow CapabilityLevel `json:"domain_allow"`
	// DomainBlock describes blocked-domain filtering.
	// DomainBlock 描述阻止域名过滤。
	DomainBlock CapabilityLevel `json:"domain_block"`
	// PublicationTime describes publication-time filtering.
	// PublicationTime 描述发布时间过滤。
	PublicationTime CapabilityLevel `json:"publication_time"`
	// Language describes language filtering.
	// Language 描述语言过滤。
	Language CapabilityLevel `json:"language"`
	// Region describes country or region filtering.
	// Region 描述国家或地区过滤。
	Region CapabilityLevel `json:"region"`
	// Location describes coarse user-location context.
	// Location 描述粗粒度用户位置上下文。
	Location CapabilityLevel `json:"location"`
	// SafeSearch describes provider safety filtering.
	// SafeSearch 描述供应商安全过滤。
	SafeSearch CapabilityLevel `json:"safe_search"`
}

// WebSearchCapabilities describes one exact unified-search execution shape.
// WebSearchCapabilities 描述一个精确统一搜索执行形态。
type WebSearchCapabilities struct {
	// BackendKind identifies the immutable internal implementation.
	// BackendKind 标识不可变内部实现。
	BackendKind vcp.SearchBackendKind `json:"backend_kind"`
	// InvocationMode identifies the exact upstream search trigger.
	// InvocationMode 标识精确上游搜索触发方式。
	InvocationMode SearchInvocationMode `json:"invocation_mode"`
	// BackingModelOfferingID fixes the model for model-grounded search.
	// BackingModelOfferingID 固定模型型搜索使用的模型。
	BackingModelOfferingID string `json:"backing_model_offering_id,omitempty"`
	// PromptTemplateID identifies the code-owned prompt template when required.
	// PromptTemplateID 标识需要时由代码拥有的提示模板。
	PromptTemplateID string `json:"prompt_template_id,omitempty"`
	// PromptTemplateRevision freezes the prompt template revision.
	// PromptTemplateRevision 冻结提示模板修订号。
	PromptTemplateRevision uint64 `json:"prompt_template_revision,omitempty"`
	// OutputModes lists supported unified response shapes.
	// OutputModes 列出支持的统一响应形态。
	OutputModes []vcp.WebSearchOutputMode `json:"output_modes"`
	// EvidenceKinds lists observable provider evidence shapes.
	// EvidenceKinds 列出可观察供应商证据形态。
	EvidenceKinds []vcp.SearchEvidenceKind `json:"evidence_kinds"`
	// EvidenceRequirements lists accepted caller verification policies.
	// EvidenceRequirements 列出接受的调用方验证策略。
	EvidenceRequirements []vcp.SearchEvidenceRequirement `json:"evidence_requirements"`
	// Filters describes individually evidenced search policies.
	// Filters 描述逐项有证据支持的搜索策略。
	Filters SearchFilterCapabilities `json:"filters"`
	// MaxResults is the provider-supported result ceiling when known.
	// MaxResults 是已知时供应商支持的结果上限。
	MaxResults OptionalCountLimit `json:"max_results"`
}

// ServiceCapabilities contains one closed special-service capability variant.
// ServiceCapabilities 包含一个封闭特殊服务能力变体。
type ServiceCapabilities struct {
	// WebSearch contains unified web-search capabilities.
	// WebSearch 包含统一网页搜索能力。
	WebSearch *WebSearchCapabilities `json:"web_search,omitempty"`
}

// ProviderService describes one logical special service within a provider instance.
// ProviderService 描述一个供应商实例内的逻辑特殊服务。
type ProviderService struct {
	// ID is the immutable provider-scoped service identifier.
	// ID 是不可变供应商作用域服务标识。
	ID string
	// ProviderInstanceID owns the service.
	// ProviderInstanceID 是拥有该服务的供应商实例。
	ProviderInstanceID string
	// DisplayName is the client-visible service name.
	// DisplayName 是客户端可见服务名称。
	DisplayName string
	// Operation identifies the sole VCP operation exposed by the service.
	// Operation 标识服务暴露的唯一 VCP 操作。
	Operation vcp.OperationKind
	// Source records the service evidence source.
	// Source 记录服务证据来源。
	Source ModelSource
	// EntitlementMode determines whether explicit credential authorization is required.
	// EntitlementMode 决定是否要求显式凭据授权。
	EntitlementMode EntitlementMode
	// Revision is the immutable service catalog revision.
	// Revision 是不可变服务目录修订号。
	Revision uint64
}

// ServiceOffering binds one provider service to a channel and exact implementation.
// ServiceOffering 将一个供应商服务绑定到通道和精确实现。
type ServiceOffering struct {
	// ID is the immutable service offering identifier.
	// ID 是不可变服务产品标识。
	ID string
	// ProviderInstanceID owns the offering.
	// ProviderInstanceID 是拥有该产品的供应商实例。
	ProviderInstanceID string
	// ProviderServiceID references one service in the same provider instance.
	// ProviderServiceID 引用同一供应商实例中的一个服务。
	ProviderServiceID string
	// ChannelID identifies the upstream provider channel.
	// ChannelID 标识上游供应商通道。
	ChannelID string
	// UpstreamServiceID identifies the exact endpoint, engine, or safe model handle.
	// UpstreamServiceID 标识精确端点、引擎或安全模型句柄。
	UpstreamServiceID string
	// Capabilities contains the channel-specific service baseline.
	// Capabilities 包含通道特定服务能力基线。
	Capabilities ServiceCapabilities
	// CapabilityRevision identifies the capability evidence revision.
	// CapabilityRevision 标识能力证据修订号。
	CapabilityRevision uint64
	// Revision is the immutable service offering revision.
	// Revision 是不可变服务产品修订号。
	Revision uint64
}

// ServiceEntitlement describes one credential's special-service authorization.
// ServiceEntitlement 描述一个凭据的特殊服务授权。
type ServiceEntitlement struct {
	// ID is the immutable service entitlement identifier.
	// ID 是不可变服务授权标识。
	ID string
	// ProviderInstanceID owns the entitlement.
	// ProviderInstanceID 是拥有该授权的供应商实例。
	ProviderInstanceID string
	// CredentialID identifies the authorized account or key.
	// CredentialID 标识获得授权的账号或 Key。
	CredentialID string
	// ProviderServiceID identifies the authorized service.
	// ProviderServiceID 标识获得授权的服务。
	ProviderServiceID string
	// Availability is the current authorization state.
	// Availability 是当前授权状态。
	Availability AvailabilityStatus
	// AllowedProfileIDs optionally restricts execution to explicit profiles.
	// AllowedProfileIDs 可选地将执行限制到显式规格。
	AllowedProfileIDs []string
	// Source records the authorization evidence source.
	// Source 记录授权证据来源。
	Source ModelSource
	// ObservedAt records when authorization evidence was obtained.
	// ObservedAt 记录获得授权证据的时间。
	ObservedAt time.Time
	// ExpiresAt records when authorization evidence becomes stale.
	// ExpiresAt 记录授权证据失效时间。
	ExpiresAt time.Time
	// Revision is the immutable entitlement snapshot revision.
	// Revision 是不可变授权快照修订号。
	Revision uint64
}
