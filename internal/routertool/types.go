// Package routertool owns explicit Router-managed model-tool bindings.
// Package routertool 管理显式的 Router 模型工具绑定。
package routertool

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidBinding reports a malformed Router model-tool binding.
	// ErrInvalidBinding 表示 Router 模型工具绑定格式无效。
	ErrInvalidBinding = errors.New("invalid router tool binding")
	// ErrBindingNotFound reports an absent Router model-tool binding.
	// ErrBindingNotFound 表示 Router 模型工具绑定不存在。
	ErrBindingNotFound = errors.New("router tool binding not found")
	// ErrBindingUnavailable reports that no enabled and executable binding satisfies the parent model scope.
	// ErrBindingUnavailable 表示没有已启用且可执行的绑定满足父模型范围。
	ErrBindingUnavailable = errors.New("router tool binding unavailable")
)

// SafetyPolicy identifies the closed outbound-content policy applied by a Router tool backend.
// SafetyPolicy 标识 Router 工具后端使用的封闭出站内容策略。
type SafetyPolicy string

const (
	// SafetyPublicHTTPSOnly permits only public HTTPS resources and blocks private-network destinations.
	// SafetyPublicHTTPSOnly 仅允许公网 HTTPS 资源并阻止内网目标。
	SafetyPublicHTTPSOnly SafetyPolicy = "public_https_only"
	// MaximumTimeoutMilliseconds caps one Router child execution at five minutes.
	// MaximumTimeoutMilliseconds 将单次 Router 子执行限制为五分钟。
	MaximumTimeoutMilliseconds int64 = 5 * 60 * 1000
	// MaximumCallsPerParent caps one binding's child calls in one parent execution.
	// MaximumCallsPerParent 限制一个绑定在单个父执行中的子调用次数。
	MaximumCallsPerParent = 32
	// MaximumSearchResults caps normalized search results exposed to one parent call.
	// MaximumSearchResults 限制单次父调用可见的规范化搜索结果数。
	MaximumSearchResults = 100
	// MaximumExtractURLs caps URLs accepted by one extraction tool call.
	// MaximumExtractURLs 限制单次提取工具调用接受的 URL 数。
	MaximumExtractURLs = 20
	// MaximumSerializedResultBytes caps one model-visible Router tool result at one MiB.
	// MaximumSerializedResultBytes 将单个模型可见 Router 工具结果限制为一 MiB。
	MaximumSerializedResultBytes int64 = 1024 * 1024
	// MaximumScopeIdentifiers caps each administrator-authored exact allowlist.
	// MaximumScopeIdentifiers 限制每个管理员编写的精确允许列表。
	MaximumScopeIdentifiers = 128
)

// AvailabilityReason identifies one stable non-sensitive Router binding readiness reason.
// AvailabilityReason 标识一个稳定且不敏感的 Router 绑定就绪原因。
type AvailabilityReason string

const (
	// AvailabilityReasonBindingMissing means no binding applies to the selected parent model profile.
	// AvailabilityReasonBindingMissing 表示没有绑定适用于所选父模型规格。
	AvailabilityReasonBindingMissing AvailabilityReason = "router_binding_missing"
	// AvailabilityReasonBindingDisabled means applicable bindings exist but all are administratively disabled.
	// AvailabilityReasonBindingDisabled 表示存在适用绑定但全部被管理员关闭。
	AvailabilityReasonBindingDisabled AvailabilityReason = "router_binding_disabled"
	// AvailabilityReasonBindingUnavailable means an enabled binding exists but no backend target is currently executable.
	// AvailabilityReasonBindingUnavailable 表示存在已启用绑定但当前没有可执行后端 Target。
	AvailabilityReasonBindingUnavailable AvailabilityReason = "router_binding_unavailable"
)

// Availability separates configured support from current backend readiness for one parent model profile.
// Availability 将一个父模型规格的已配置支持与当前后端就绪状态分离。
type Availability struct {
	// Supported reports whether at least one in-scope binding is configured.
	// Supported 报告是否至少配置了一个范围匹配的绑定。
	Supported bool `json:"supported"`
	// Ready reports whether an enabled binding resolves to an executable backend now.
	// Ready 报告当前是否有已启用绑定解析到可执行后端。
	Ready bool `json:"ready"`
	// UnavailableReason is empty only when Ready is true.
	// UnavailableReason 仅在 Ready 为真时为空。
	UnavailableReason AvailabilityReason `json:"unavailable_reason,omitempty"`
}

// BindingProbe reports whether one exact persisted binding can currently resolve its frozen backend.
// BindingProbe 报告一个精确持久化绑定当前能否解析其冻结后端。
type BindingProbe struct {
	// BindingID identifies the tested administrator policy.
	// BindingID 标识被测试的管理员策略。
	BindingID string `json:"binding_id"`
	// Revision identifies the tested immutable policy revision.
	// Revision 标识被测试的不可变策略修订号。
	Revision uint64 `json:"revision"`
	// ToolID identifies the standard tool or Router extension.
	// ToolID 标识标准工具或 Router 增强能力。
	ToolID string `json:"tool_id"`
	// Operation identifies the exact child VCP operation.
	// Operation 标识精确的子 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// Ready reports whether normal target resolution found an executable backend.
	// Ready 报告常规 Target 解析是否找到可执行后端。
	Ready bool `json:"ready"`
	// UnavailableReason provides one stable non-secret reason when the binding is not ready.
	// UnavailableReason 在绑定未就绪时提供一个稳定且不泄密的原因。
	UnavailableReason AvailabilityReason `json:"unavailable_reason,omitempty"`
}

// Binding maps one standard model tool or closed Router extension to one exact provider service.
// Binding 将一个标准模型工具或封闭 Router 增强能力映射到一个精确供应商服务。
type Binding struct {
	// ID is the Router-owned stable binding identifier.
	// ID 是 Router 所有的稳定绑定标识。
	ID string `json:"id"`
	// Kind is the closed standard model tool supplied by this binding.
	// Kind 是此绑定提供的封闭标准模型工具。
	Kind vcp.StandardModelToolKind `json:"kind,omitempty"`
	// Extension identifies one closed operation-backed Router enhancement.
	// Extension 标识一个封闭且由操作支持的 Router 增强能力。
	Extension vcp.RouterExtensionKind `json:"extension,omitempty"`
	// ProviderInstanceID fixes the backend provider instance.
	// ProviderInstanceID 固定后端供应商实例。
	ProviderInstanceID string `json:"provider_instance_id"`
	// ProviderServiceID fixes the backend logical service.
	// ProviderServiceID 固定后端逻辑服务。
	ProviderServiceID string `json:"provider_service_id,omitempty"`
	// ServiceOfferingID fixes the backend service offering.
	// ServiceOfferingID 固定后端服务产品。
	ServiceOfferingID string `json:"service_offering_id,omitempty"`
	// ProviderModelID fixes the backend logical model for operation-backed enhancements.
	// ProviderModelID 为操作支持的增强能力固定后端逻辑模型。
	ProviderModelID string `json:"provider_model_id,omitempty"`
	// OfferingID fixes the backend model offering.
	// OfferingID 固定后端模型产品。
	OfferingID string `json:"offering_id,omitempty"`
	// ExecutionProfileID fixes the backend execution profile.
	// ExecutionProfileID 固定后端执行规格。
	ExecutionProfileID string `json:"execution_profile_id"`
	// Priority is ordered ascending; smaller values are selected first.
	// Priority 按升序排序；较小值优先选择。
	Priority int `json:"priority"`
	// Enabled controls whether the binding can be selected.
	// Enabled 控制此绑定能否被选择。
	Enabled bool `json:"enabled"`
	// AllowedProviderInstanceIDs optionally restricts parent model owners.
	// AllowedProviderInstanceIDs 可选地限制父模型供应商实例。
	AllowedProviderInstanceIDs []string `json:"allowed_provider_instance_ids,omitempty"`
	// AllowedProviderModelIDs optionally restricts parent logical models.
	// AllowedProviderModelIDs 可选地限制父逻辑模型。
	AllowedProviderModelIDs []string `json:"allowed_provider_model_ids,omitempty"`
	// AllowedExecutionProfileIDs optionally restricts parent model profiles.
	// AllowedExecutionProfileIDs 可选地限制父模型规格。
	AllowedExecutionProfileIDs []string `json:"allowed_execution_profile_ids,omitempty"`
	// TimeoutMilliseconds is the hard ceiling for one child execution.
	// TimeoutMilliseconds 是一次子执行的硬超时上限。
	TimeoutMilliseconds int64 `json:"timeout_milliseconds"`
	// MaximumCalls is the per-parent maximum for this binding.
	// MaximumCalls 是此绑定在单个父执行中的最大调用次数。
	MaximumCalls int `json:"maximum_calls"`
	// MaximumResults is the maximum normalized search result count.
	// MaximumResults 是规范化搜索结果的最大数量。
	MaximumResults int `json:"maximum_results"`
	// MaximumURLs is the maximum normalized extraction URL count.
	// MaximumURLs 是规范化抓取 URL 的最大数量。
	MaximumURLs int `json:"maximum_urls"`
	// MaximumResultBytes is the maximum serialized tool-result size returned to the parent model.
	// MaximumResultBytes 是回填父模型的序列化工具结果最大字节数。
	MaximumResultBytes int64 `json:"maximum_result_bytes"`
	// SafetyPolicy fixes the outbound resource policy.
	// SafetyPolicy 固定出站资源策略。
	SafetyPolicy SafetyPolicy `json:"safety_policy"`
	// Revision is the optimistic-lock revision.
	// Revision 是乐观锁修订号。
	Revision uint64 `json:"revision"`
	// CreatedAt records creation time.
	// CreatedAt 记录创建时间。
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt records the latest mutation time.
	// UpdatedAt 记录最近修改时间。
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate verifies a binding without inferring missing service identifiers or limits.
// Validate 在不推断缺失服务标识或限制的情况下校验绑定。
func (b Binding) Validate() error {
	standard := b.Kind.Valid()
	extension := b.Extension.Valid()
	serviceTarget := strings.TrimSpace(b.ProviderServiceID) != "" && strings.TrimSpace(b.ServiceOfferingID) != "" && strings.TrimSpace(b.ProviderModelID) == "" && strings.TrimSpace(b.OfferingID) == ""
	modelTarget := strings.TrimSpace(b.ProviderModelID) != "" && strings.TrimSpace(b.OfferingID) != "" && strings.TrimSpace(b.ProviderServiceID) == "" && strings.TrimSpace(b.ServiceOfferingID) == ""
	if !normalizedBindingIdentifier(b.ID, true) ||
		!normalizedBindingIdentifier(b.ProviderInstanceID, true) ||
		!normalizedBindingIdentifier(b.ProviderServiceID, standard) ||
		!normalizedBindingIdentifier(b.ServiceOfferingID, standard) ||
		!normalizedBindingIdentifier(b.ProviderModelID, extension) ||
		!normalizedBindingIdentifier(b.OfferingID, extension) ||
		!normalizedBindingIdentifier(b.ExecutionProfileID, true) ||
		standard == extension || serviceTarget == modelTarget || standard && !serviceTarget || extension && !modelTarget {
		return fmt.Errorf("%w: identity fields are required", ErrInvalidBinding)
	}
	if b.Priority < 0 || b.TimeoutMilliseconds <= 0 || b.MaximumCalls <= 0 || b.MaximumResults < 0 || b.MaximumURLs < 0 || b.MaximumResultBytes <= 0 || b.Revision == 0 || b.CreatedAt.IsZero() || b.UpdatedAt.IsZero() || b.CreatedAt.After(b.UpdatedAt) {
		return fmt.Errorf("%w: required limits, revision, and timestamps are invalid", ErrInvalidBinding)
	}
	if b.TimeoutMilliseconds > MaximumTimeoutMilliseconds || b.MaximumCalls > MaximumCallsPerParent || b.MaximumResults > MaximumSearchResults || b.MaximumURLs > MaximumExtractURLs || b.MaximumResultBytes > MaximumSerializedResultBytes {
		return fmt.Errorf("%w: binding safety limit exceeds the supported maximum", ErrInvalidBinding)
	}
	if b.Kind == vcp.StandardModelToolWebSearch && b.MaximumResults <= 0 {
		return fmt.Errorf("%w: web_search requires maximum_results", ErrInvalidBinding)
	}
	if b.Kind == vcp.StandardModelToolWebExtractor && b.MaximumURLs <= 0 {
		return fmt.Errorf("%w: web_extractor requires maximum_urls", ErrInvalidBinding)
	}
	if b.SafetyPolicy != SafetyPublicHTTPSOnly {
		return fmt.Errorf("%w: unsupported safety policy", ErrInvalidBinding)
	}
	if errScopes := validateScopes(b.AllowedProviderInstanceIDs, b.AllowedProviderModelIDs, b.AllowedExecutionProfileIDs); errScopes != nil {
		return errScopes
	}
	return nil
}

// ValidateReplacement verifies immutable creation facts, monotonic time, and one-step optimistic revision.
// ValidateReplacement 校验不可变创建事实、单调时间与单步乐观修订。
// Parameters: current is the exact previously stored binding with the same stable identifier.
// 参数：current 是具有相同稳定标识的精确既有绑定。
// Returns: nil only when the receiver is a valid direct replacement.
// 返回：仅当接收者是有效直接替换值时返回 nil。
func (b Binding) ValidateReplacement(current Binding) error {
	if errCurrent := current.Validate(); errCurrent != nil {
		return errCurrent
	}
	if errNext := b.Validate(); errNext != nil {
		return errNext
	}
	if b.ID != current.ID || b.Revision != current.Revision+1 || !b.CreatedAt.Equal(current.CreatedAt) || b.UpdatedAt.Before(current.UpdatedAt) {
		return fmt.Errorf("%w: replacement revision or audit timeline is invalid", ErrInvalidBinding)
	}
	return nil
}

// normalizedBindingIdentifier verifies one optional or required identity without silently trimming operator input.
// normalizedBindingIdentifier 校验一个可选或必填身份且绝不静默裁剪操作员输入。
func normalizedBindingIdentifier(value string, required bool) bool {
	trimmed := strings.TrimSpace(value)
	if value != trimmed {
		return false
	}
	return !required || trimmed != ""
}

// ToolID returns the exact standard or Router-extension identifier owned by this binding.
// ToolID 返回此绑定拥有的精确标准工具或 Router 增强能力标识。
func (b Binding) ToolID() string {
	if b.Kind.Valid() {
		return string(b.Kind)
	}
	return string(b.Extension)
}

// Operation returns the exact child VCP operation selected by this binding.
// Operation 返回此绑定选择的精确子 VCP 操作。
func (b Binding) Operation() vcp.OperationKind {
	if b.Kind == vcp.StandardModelToolWebSearch {
		return vcp.OperationSearchWeb
	}
	if b.Kind == vcp.StandardModelToolWebExtractor {
		return vcp.OperationWebExtract
	}
	return b.Extension.Operation()
}

// validateScopes rejects duplicate or blank exact scope identifiers.
// validateScopes 拒绝重复或空白的精确范围标识。
func validateScopes(groups ...[]string) error {
	for _, values := range groups {
		if len(values) > MaximumScopeIdentifiers {
			return fmt.Errorf("%w: scope allowlist exceeds the supported maximum", ErrInvalidBinding)
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
				return fmt.Errorf("%w: scope identifiers must be non-empty and trimmed", ErrInvalidBinding)
			}
			if _, exists := seen[value]; exists {
				return fmt.Errorf("%w: duplicate scope identifier %q", ErrInvalidBinding, value)
			}
			seen[value] = struct{}{}
		}
	}
	return nil
}
