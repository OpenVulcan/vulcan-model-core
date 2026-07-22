package vcp

import (
	"fmt"
	"strings"
)

// PreflightAccuracy identifies whether a usage fact is provider-exact, Router-estimated, or unavailable.
// PreflightAccuracy 标识用量事实是供应商精确值、Router 估算值还是不可用。
type PreflightAccuracy string

const (
	// PreflightExact is returned only for provider-reported or arithmetically exact facts.
	// PreflightExact 仅用于供应商报告或可精确算术计算的事实。
	PreflightExact PreflightAccuracy = "exact"
	// PreflightEstimated marks a Router estimate whose accounting method is disclosed.
	// PreflightEstimated 标记公开计量方法的 Router 估算值。
	PreflightEstimated PreflightAccuracy = "estimated"
	// PreflightUnknown preserves an unsupported or unknowable value without inventing a number.
	// PreflightUnknown 在不虚构数值的情况下保留不支持或不可知状态。
	PreflightUnknown PreflightAccuracy = "unknown"
)

// UsagePreflightRequest asks for side-effect-free accounting against one exact execution target.
// UsagePreflightRequest 请求针对一个精确执行 Target 进行无副作用计量。
type UsagePreflightRequest struct {
	// ProtocolVersion fixes the request contract version.
	// ProtocolVersion 固定请求合同版本。
	ProtocolVersion string `json:"protocol_version"`
	// RequestID is a caller-owned safe correlation identifier.
	// RequestID 是调用方拥有的安全关联标识。
	RequestID string `json:"request_id"`
	// Execution contains the same validated operation and exact target that would be executed.
	// Execution 包含将被执行的同一已验证操作与精确 Target。
	Execution ExecutionRequest `json:"execution"`
}

// Validate verifies that preflight cannot carry a mismatched version or an executable dispatch policy.
// Validate 校验预检不能携带不匹配版本或可执行分派策略。
func (r UsagePreflightRequest) Validate() error {
	if r.ProtocolVersion != ProtocolVersion || strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("%w: preflight protocol_version and request_id are required", ErrInvalidRequest)
	}
	if errExecution := r.Execution.Validate(); errExecution != nil {
		return errExecution
	}
	if r.Execution.DispatchMode == DispatchDeferred || r.Execution.RetryPolicy != nil {
		return fmt.Errorf("%w: preflight cannot request deferred dispatch or retries", ErrInvalidRequest)
	}
	return nil
}

// PreflightMetric contains one typed input accounting dimension.
// PreflightMetric 包含一个类型化输入计量维度。
type PreflightMetric struct {
	// Unit identifies tokens, bytes, pixels, items, or a provider-defined unit.
	// Unit 标识 Token、字节、像素、项目数或供应商定义单位。
	Unit string `json:"unit"`
	// Value is absent when accuracy is unknown.
	// Value 在精度为 unknown 时不存在。
	Value *float64 `json:"value,omitempty"`
	// Accuracy states whether Value is exact, estimated, or unavailable.
	// Accuracy 声明 Value 是精确、估算还是不可用。
	Accuracy PreflightAccuracy `json:"accuracy"`
	// AccountingBasis safely identifies the counting rule without exposing request contents.
	// AccountingBasis 安全标识计量规则且不暴露请求内容。
	AccountingBasis string `json:"accounting_basis"`
}

// UsagePreflightResponse returns safe side-effect-free accounting for one immutable target.
// UsagePreflightResponse 返回一个不可变 Target 的安全无副作用计量。
type UsagePreflightResponse struct {
	// ProtocolVersion is the exact response contract version.
	// ProtocolVersion 是响应的精确合同版本。
	ProtocolVersion string `json:"protocol_version"`
	// RequestID echoes the caller-owned correlation identifier.
	// RequestID 回显调用方拥有的关联标识。
	RequestID string `json:"request_id"`
	// Target echoes the exact target that was counted and never contains candidates.
	// Target 回显被计量的精确 Target 且绝不包含候选列表。
	Target TargetSelection `json:"target"`
	// Usage contains provider-compatible token accounting when available.
	// Usage 在可用时包含供应商兼容 Token 计量。
	Usage UsageObservation `json:"usage"`
	// Metrics contains all independently known operation units.
	// Metrics 包含全部独立已知的操作单位。
	Metrics []PreflightMetric `json:"metrics"`
}
