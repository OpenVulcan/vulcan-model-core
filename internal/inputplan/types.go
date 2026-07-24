// Package inputplan freezes conditional media acquisition and upstream materialization before execution.
// Package inputplan 在执行前冻结条件媒体获取与上游物化方案。
package inputplan

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidPlan reports a malformed plan request or persisted plan.
	// ErrInvalidPlan 表示方案请求或持久化方案格式错误。
	ErrInvalidPlan = errors.New("invalid input plan")
	// ErrPlanNotFound reports an unknown or inaccessible plan identifier.
	// ErrPlanNotFound 表示未知或不可访问方案标识。
	ErrPlanNotFound = errors.New("input plan not found")
	// ErrCapabilityChanged reports target, catalog, capability, or resource drift after planning.
	// ErrCapabilityChanged 表示规划后 Target、目录、能力或资源发生漂移。
	ErrCapabilityChanged = errors.New("input plan capability changed")
	// ErrInputRejected reports an explicit capability or media limit conflict.
	// ErrInputRejected 表示明确能力或媒体限制冲突。
	ErrInputRejected = errors.New("input rejected")
)

// ClientStepKind identifies one exact action Vulcan must complete before execution.
// ClientStepKind 标识 Vulcan 在执行前必须完成的一项精确动作。
type ClientStepKind string

const (
	// ClientStepReferenceExisting references an already ready Router resource.
	// ClientStepReferenceExisting 引用一个已经就绪的 Router 资源。
	ClientStepReferenceExisting ClientStepKind = "reference_existing"
	// ClientStepUploadMultipart uploads bytes to Router.
	// ClientStepUploadMultipart 将字节上传到 Router。
	ClientStepUploadMultipart ClientStepKind = "upload_multipart"
	// ClientStepImportURL asks Router to import one URL.
	// ClientStepImportURL 请求 Router 导入一个 URL。
	ClientStepImportURL ClientStepKind = "import_url"
	// ClientStepImportBase64 asks Router to import Base64 bytes.
	// ClientStepImportBase64 请求 Router 导入 Base64 字节。
	ClientStepImportBase64 ClientStepKind = "import_base64"
)

// PendingResource describes authoritative metadata for bytes not yet stored by Router.
// PendingResource 描述尚未由 Router 存储字节的权威元数据。
type PendingResource struct {
	// Kind is the expected closed media family.
	// Kind 是预期封闭媒体类别。
	Kind vcp.MediaKind `json:"kind"`
	// MIMEType is the expected normalized MIME type.
	// MIMEType 是预期规范 MIME 类型。
	MIMEType string `json:"mime_type"`
	// SizeBytes is the exact known byte count.
	// SizeBytes 是精确已知字节数。
	SizeBytes int64 `json:"size_bytes"`
	// Metadata contains authoritative media measurements already known by the caller.
	// Metadata 包含调用方已知的权威媒体测量值。
	Metadata resource.Metadata `json:"metadata"`
	// Workflow is the caller-selected acquisition mechanism.
	// Workflow 是调用方选择的获取机制。
	Workflow catalog.ClientResourceWorkflow `json:"workflow"`
}

// Input describes exactly one existing or pending media resource.
// Input 描述精确一个现有或待创建媒体资源。
type Input struct {
	// InputID is stable within the request and preserved in execution mapping.
	// InputID 在请求内稳定并保留到执行映射。
	InputID string `json:"input_id"`
	// ResourceID selects an existing Router resource.
	// ResourceID 选择一个现有 Router 资源。
	ResourceID string `json:"resource_id,omitempty"`
	// Pending describes not-yet-ingested bytes.
	// Pending 描述尚未接收的字节。
	Pending *PendingResource `json:"pending,omitempty"`
	// Role declares why the resource participates in the operation.
	// Role 声明资源参与操作的原因。
	Role vcp.MediaInputRole `json:"role"`
}

// Request describes one exact model-scoped conditional input planning request.
// Request 描述一个精确模型作用域条件输入规划请求。
type Request struct {
	// OwnerAPIKeyID is installed from authenticated call-plane context.
	// OwnerAPIKeyID 由已认证调用面 Context 写入。
	OwnerAPIKeyID string `json:"-"`
	// Model selects one exact provider-scoped model and profile.
	// Model 选择一个精确供应商作用域模型与规格。
	Model vcp.ModelSelection `json:"model"`
	// Operation identifies the exact VCP operation.
	// Operation 标识精确 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// Inputs preserves caller input order.
	// Inputs 保留调用方输入顺序。
	Inputs []Input `json:"inputs"`
	// RequiredFeatures lists exact operation intersections that must remain supported.
	// RequiredFeatures 列出必须保持支持的精确操作交集。
	RequiredFeatures []vcp.CapabilityFeature `json:"required_features,omitempty"`
	// AllowProjection explicitly authorizes documented emulated frame or audio projection.
	// AllowProjection 显式授权已记录的模拟抽帧或音轨投影。
	AllowProjection bool `json:"allow_projection,omitempty"`
}

// PlannedInput freezes one input identity, content facts, and exact transfer decision.
// PlannedInput 冻结一个输入身份、内容事实及精确传输决策。
type PlannedInput struct {
	// InputID preserves the request identity.
	// InputID 保留请求身份。
	InputID string `json:"input_id"`
	// ResourceID is populated for an existing Router resource.
	// ResourceID 为现有 Router 资源时填充。
	ResourceID string `json:"resource_id,omitempty"`
	// SHA256 freezes existing resource content.
	// SHA256 冻结现有资源内容。
	SHA256 string `json:"sha256,omitempty"`
	// Kind is the exact media family.
	// Kind 是精确媒体类别。
	Kind vcp.MediaKind `json:"kind"`
	// MIMEType is the exact authoritative or expected MIME type.
	// MIMEType 是精确权威或预期 MIME 类型。
	MIMEType string `json:"mime_type"`
	// SizeBytes is the exact byte count.
	// SizeBytes 是精确字节数。
	SizeBytes int64 `json:"size_bytes"`
	// Role is the exact operation role.
	// Role 是精确操作角色。
	Role vcp.MediaInputRole `json:"role"`
	// ImageWidth freezes the authoritative image width when Kind is image.
	// ImageWidth 在 Kind 为图片时冻结权威图片宽度。
	ImageWidth int `json:"image_width,omitempty"`
	// ImageHeight freezes the authoritative image height when Kind is image.
	// ImageHeight 在 Kind 为图片时冻结权威图片高度。
	ImageHeight int `json:"image_height,omitempty"`
	// ImageHasAlpha freezes structural alpha-channel evidence for masks and transparent inputs.
	// ImageHasAlpha 为遮罩和透明输入冻结结构化 Alpha 通道证据。
	ImageHasAlpha bool `json:"image_has_alpha,omitempty"`
	// ClientStep tells Vulcan how to obtain the Router resource.
	// ClientStep 告知 Vulcan 如何获得 Router 资源。
	ClientStep ClientStepKind `json:"client_step"`
	// Materialization is the sole selected Router-to-provider representation.
	// Materialization 是唯一选定 Router 到供应商表示。
	Materialization catalog.UpstreamMaterializationMode `json:"materialization"`
	// GeneratedBy freezes safe generation provenance when required by the target capability.
	// GeneratedBy 在目标能力要求时冻结安全生成来源。
	GeneratedBy *resource.GenerationProvenance `json:"generated_by,omitempty"`
}

// Plan is an expiring immutable conditional-input decision.
// Plan 是一个会过期且不可变的条件输入决策。
type Plan struct {
	// ID is the opaque plan identifier.
	// ID 是不透明方案标识。
	ID string `json:"input_plan_id"`
	// OwnerAPIKeyID is the non-public authorization owner.
	// OwnerAPIKeyID 是不公开授权所有者。
	OwnerAPIKeyID string `json:"-"`
	// Accepted reports whether every input has one legal path.
	// Accepted 表示每项输入是否都有一条合法路径。
	Accepted bool `json:"accepted"`
	// Operation is the frozen VCP operation.
	// Operation 是冻结的 VCP 操作。
	Operation vcp.OperationKind `json:"operation"`
	// Model is the safe exact model selection visible to the caller.
	// Model 是调用方可见的安全精确模型选择。
	Model vcp.ModelSelection `json:"model"`
	// Target is the exact immutable same-provider destination.
	// Target 是精确不可变同供应商目标。
	Target resolve.Target `json:"-"`
	// CapabilityRevision freezes interpreted capability evidence.
	// CapabilityRevision 冻结解释后的能力证据。
	CapabilityRevision uint64 `json:"capability_revision"`
	// CatalogRevision freezes the atomic catalog snapshot.
	// CatalogRevision 冻结原子目录快照。
	CatalogRevision uint64 `json:"catalog_revision"`
	// Inputs preserves planned input order.
	// Inputs 保留规划输入顺序。
	Inputs []PlannedInput `json:"inputs"`
	// RequiresProviderPreparation reports a Router-managed upload or asset creation stage.
	// RequiresProviderPreparation 表示需要 Router 管理上传或资产创建阶段。
	RequiresProviderPreparation bool `json:"requires_provider_preparation"`
	// AsynchronousPreparation reports that preparation may outlive one HTTP request.
	// AsynchronousPreparation 表示准备过程可能超过一次 HTTP 请求。
	AsynchronousPreparation bool `json:"asynchronous_preparation"`
	// ErrorCode is a stable rejection code and never contains resource content.
	// ErrorCode 是稳定拒绝码且绝不包含资源内容。
	ErrorCode string `json:"error_code,omitempty"`
	// CreatedAt records decision time.
	// CreatedAt 记录决策时间。
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt limits reuse.
	// ExpiresAt 限制复用时间。
	ExpiresAt time.Time `json:"expires_at"`
	// Revision is the immutable persistence revision.
	// Revision 是不可变持久化修订号。
	Revision uint64 `json:"revision"`
}

// Validate verifies the persisted plan envelope and exact accepted/rejected shape.
// Validate 校验持久方案信封及精确接受/拒绝形态。
func (p Plan) Validate() error {
	if !validPlanID(p.ID) || strings.TrimSpace(p.OwnerAPIKeyID) == "" || !p.Operation.Valid() || p.Model.Target != vcp.ModelTargetExact || p.Model.ProviderInstanceID == "" || p.Model.ProviderModelID == "" || p.Model.ExecutionProfileID == "" || p.CreatedAt.IsZero() || !p.ExpiresAt.After(p.CreatedAt) || p.Revision == 0 {
		return fmt.Errorf("%w: identity, owner, operation, timestamps, and revision are required", ErrInvalidPlan)
	}
	if p.Accepted {
		if p.ErrorCode != "" || p.CapabilityRevision == 0 || p.CatalogRevision == 0 || len(p.Inputs) == 0 || p.Target.ProviderInstanceID == "" {
			return fmt.Errorf("%w: accepted plan requires target, revisions, and inputs", ErrInvalidPlan)
		}
	} else if strings.TrimSpace(p.ErrorCode) == "" {
		return fmt.Errorf("%w: rejected plan requires an error code", ErrInvalidPlan)
	}
	return nil
}

// FrozenMaterializationPlan projects only private realization facts for the resource materializer.
// FrozenMaterializationPlan 仅为资源物化器投影私有实现事实。
func (p Plan) FrozenMaterializationPlan() resource.FrozenMaterializationPlan {
	inputs := make([]resource.FrozenMaterializationInput, len(p.Inputs))
	for index, input := range p.Inputs {
		inputs[index] = resource.FrozenMaterializationInput{InputID: input.InputID, ResourceID: input.ResourceID, SHA256: input.SHA256, Kind: input.Kind, MIMEType: input.MIMEType, SizeBytes: input.SizeBytes, Role: input.Role, ImageWidth: input.ImageWidth, ImageHeight: input.ImageHeight, ImageHasAlpha: input.ImageHasAlpha, Materialization: input.Materialization}
	}
	return resource.FrozenMaterializationPlan{OwnerAPIKeyID: p.OwnerAPIKeyID, Accepted: p.Accepted, ExpiresAt: p.ExpiresAt, Target: p.Target, Inputs: inputs}
}

// validPlanID verifies the cryptographic plan identifier shape.
// validPlanID 校验加密方案标识形态。
func validPlanID(identifier string) bool {
	if len(identifier) != 36 || !strings.HasPrefix(identifier, "ipl_") {
		return false
	}
	decoded, errDecode := hex.DecodeString(identifier[4:])
	return errDecode == nil && len(decoded) == 16
}
