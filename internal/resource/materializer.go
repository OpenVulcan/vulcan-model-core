package resource

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrMaterializationFailed reports an exact planned representation that could not be produced.
	// ErrMaterializationFailed 表示无法生成精确规划表示。
	ErrMaterializationFailed = errors.New("resource materialization failed")
	// ErrMaterializationChanged reports resource facts that no longer match a frozen plan.
	// ErrMaterializationChanged 表示资源事实不再匹配冻结方案。
	ErrMaterializationChanged = errors.New("resource materialization input changed")
)

// FrozenMaterializationPlan contains only the accepted private plan facts required for realization.
// FrozenMaterializationPlan 仅包含实现所需的已接受私有方案事实。
type FrozenMaterializationPlan struct {
	// OwnerAPIKeyID fixes resource authorization.
	// OwnerAPIKeyID 固定资源授权。
	OwnerAPIKeyID string
	// Accepted confirms capability planning succeeded.
	// Accepted 确认能力规划成功。
	Accepted bool
	// ExpiresAt limits decision reuse.
	// ExpiresAt 限制决策复用。
	ExpiresAt time.Time
	// Target fixes complete provider ownership.
	// Target 固定完整供应商归属。
	Target resolve.Target
	// Inputs preserves frozen input order.
	// Inputs 保留冻结输入顺序。
	Inputs []FrozenMaterializationInput
}

// FrozenMaterializationInput contains one planned resource representation.
// FrozenMaterializationInput 包含一个规划资源表示。
type FrozenMaterializationInput struct {
	// InputID preserves canonical identity.
	// InputID 保留规范身份。
	InputID string
	// ResourceID is present for an already stored resource.
	// ResourceID 为已存储资源时存在。
	ResourceID string
	// SHA256 freezes existing bytes when known at planning time.
	// SHA256 在规划时已知的情况下冻结现有字节。
	SHA256 string
	// Kind is the exact media family.
	// Kind 是精确媒体类别。
	Kind vcp.MediaKind
	// MIMEType is authoritative or expected.
	// MIMEType 具有权威性或为预期值。
	MIMEType string
	// SizeBytes is exact.
	// SizeBytes 是精确值。
	SizeBytes int64
	// Role is the operation semantic role.
	// Role 是操作语义角色。
	Role vcp.MediaInputRole
	// ImageWidth freezes authoritative image width when Kind is image.
	// ImageWidth 在 Kind 为图片时冻结权威图片宽度。
	ImageWidth int
	// ImageHeight freezes authoritative image height when Kind is image.
	// ImageHeight 在 Kind 为图片时冻结权威图片高度。
	ImageHeight int
	// ImageHasAlpha freezes structural alpha-channel evidence.
	// ImageHasAlpha 冻结结构化 Alpha 通道证据。
	ImageHasAlpha bool
	// Materialization is the sole selected representation.
	// Materialization 是唯一选定表示。
	Materialization catalog.UpstreamMaterializationMode
}

// ResourceAssignment binds one pending planned input to its completed Router resource.
// ResourceAssignment 将一个待创建规划输入绑定到已完成 Router 资源。
type ResourceAssignment struct {
	// InputID identifies the exact planned input.
	// InputID 标识精确规划输入。
	InputID string
	// ResourceID identifies the completed Router resource.
	// ResourceID 标识已完成 Router 资源。
	ResourceID string
}

// MaterializedInput is an exact-one-of internal provider representation.
// MaterializedInput 是精确单选内部供应商表示。
type MaterializedInput struct {
	// InputID preserves canonical input order and identity.
	// InputID 保留规范输入顺序与身份。
	InputID string
	// ResourceID identifies the verified Router source.
	// ResourceID 标识已验证 Router 来源。
	ResourceID string
	// Kind identifies the media family.
	// Kind 标识媒体类别。
	Kind vcp.MediaKind
	// Role identifies operation semantics.
	// Role 标识操作语义。
	Role vcp.MediaInputRole
	// MIMEType is authoritative.
	// MIMEType 具有权威性。
	MIMEType string
	// Mode is the frozen catalog-selected representation.
	// Mode 是冻结目录选定表示。
	Mode catalog.UpstreamMaterializationMode
	// InlineBase64 contains bytes only for inline mode.
	// InlineBase64 仅在内联方式下包含字节。
	InlineBase64 string
	// RemoteURL contains the validated origin only for direct URL mode.
	// RemoteURL 仅在直连 URL 方式下包含已验证来源。
	RemoteURL string
	// ProviderHandle contains a protected-at-rest handle only during provider dispatch.
	// ProviderHandle 仅在供应商分派期间包含静态受保护句柄。
	ProviderHandle string
	// ProviderAssetKind identifies the handle family.
	// ProviderAssetKind 标识句柄类别。
	ProviderAssetKind ProviderAssetKind
	// GeneratedBy preserves safe generation provenance for provider constraints.
	// GeneratedBy 为供应商约束保留安全生成来源。
	GeneratedBy *GenerationProvenance
}

// AssetUploadRequest supplies one exact target and verified byte stream to a provider action.
// AssetUploadRequest 向供应商动作提供一个精确 Target 与已验证字节流。
type AssetUploadRequest struct {
	// Target freezes complete upstream ownership.
	// Target 冻结完整上游归属。
	Target AssetBindingTarget
	// ResourceID identifies the Router source.
	// ResourceID 标识 Router 来源。
	ResourceID string
	// SHA256 identifies exact bytes.
	// SHA256 标识精确字节。
	SHA256 string
	// Kind identifies media family.
	// Kind 标识媒体类别。
	Kind vcp.MediaKind
	// MIMEType is authoritative.
	// MIMEType 具有权威性。
	MIMEType string
	// SizeBytes is exact stream length.
	// SizeBytes 是精确流长度。
	SizeBytes int64
	// Mode is the exact provider upload or asset action result shape.
	// Mode 是精确供应商上传或资产动作结果形态。
	Mode catalog.UpstreamMaterializationMode
	// Content streams verified bytes and remains caller-owned.
	// Content 流式提供已验证字节且仍由调用方拥有。
	Content io.Reader
}

// AssetUploadResult contains one sensitive provider handle before protected storage.
// AssetUploadResult 包含进入受保护存储前的敏感供应商句柄。
type AssetUploadResult struct {
	// Handle is the exact sensitive upstream identifier or URI.
	// Handle 是精确敏感上游标识或 URI。
	Handle string
	// Kind identifies the returned handle family.
	// Kind 标识返回句柄类别。
	Kind ProviderAssetKind
	// ExpiresAt records authoritative provider expiry.
	// ExpiresAt 记录权威供应商过期时间。
	ExpiresAt *time.Time
}

// AssetUploader owns provider-specific upload, object, or asset actions.
// AssetUploader 拥有供应商特定上传、对象或资产动作。
type AssetUploader interface {
	// Upload creates one provider-owned asset for the exact target.
	// Upload 为精确 Target 创建一个供应商拥有资产。
	Upload(context.Context, AssetUploadRequest) (AssetUploadResult, error)
	// Delete removes a just-created provider asset during compensation.
	// Delete 在补偿期间移除一个刚创建供应商资产。
	Delete(context.Context, AssetBindingTarget, ProviderAssetKind, string) error
}

// MaterializerOptions configures deterministic time and binding identity.
// MaterializerOptions 配置确定性时间与绑定身份。
type MaterializerOptions struct {
	// Now returns current time.
	// Now 返回当前时间。
	Now func() time.Time
	// NewBindingID returns one unpredictable binding identifier.
	// NewBindingID 返回一个不可预测绑定标识。
	NewBindingID func() (string, error)
}

// Materializer realizes only the path frozen by an accepted input plan.
// Materializer 仅实现已接受输入方案冻结的路径。
type Materializer struct {
	// resources owns verified bytes and internal source facts.
	// resources 拥有已验证字节与内部来源事实。
	resources *Service
	// bindings owns exact-target reusable handles.
	// bindings 拥有精确 Target 可复用句柄。
	bindings AssetBindingStore
	// secrets protects provider handles at rest.
	// secrets 静态保护供应商句柄。
	secrets secret.Store
	// uploader dispatches exact provider-owned asset actions.
	// uploader 分派精确供应商拥有资产动作。
	uploader AssetUploader
	// options contains deterministic dependencies.
	// options 包含确定性依赖。
	options MaterializerOptions
}

// NewMaterializer creates one exact-path provider resource materializer.
// NewMaterializer 创建一个精确路径供应商资源物化器。
func NewMaterializer(resources *Service, bindings AssetBindingStore, secrets secret.Store, uploader AssetUploader, options MaterializerOptions) (*Materializer, error) {
	if resources == nil || dependency.IsNil(bindings) || dependency.IsNil(secrets) {
		return nil, ErrMaterializationFailed
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewBindingID == nil {
		options.NewBindingID = randomAssetBindingID
	}
	return &Materializer{resources: resources, bindings: bindings, secrets: secrets, uploader: uploader, options: options}, nil
}

// Materialize produces ordered internal representations without alternative-path probing.
// Materialize 在不探测替代路径的情况下生成有序内部表示。
func (m *Materializer) Materialize(ctx context.Context, ownerAPIKeyID string, plan FrozenMaterializationPlan, assignments []ResourceAssignment) ([]MaterializedInput, error) {
	if m == nil || ctx == nil || ownerAPIKeyID == "" || !plan.Accepted || plan.OwnerAPIKeyID != ownerAPIKeyID || !plan.ExpiresAt.After(m.options.Now().UTC()) {
		return nil, ErrMaterializationFailed
	}
	assignmentByInput := make(map[string]string, len(assignments))
	for _, assignment := range assignments {
		if assignment.InputID == "" || assignment.ResourceID == "" {
			return nil, ErrMaterializationFailed
		}
		if _, exists := assignmentByInput[assignment.InputID]; exists {
			return nil, ErrMaterializationFailed
		}
		assignmentByInput[assignment.InputID] = assignment.ResourceID
	}
	results := make([]MaterializedInput, 0, len(plan.Inputs))
	usedAssignments := 0
	for _, planned := range plan.Inputs {
		resourceID := planned.ResourceID
		assignedResourceID, assigned := assignmentByInput[planned.InputID]
		if resourceID != "" && assigned {
			return nil, ErrMaterializationFailed
		}
		if resourceID == "" {
			if !assigned {
				return nil, ErrMaterializationFailed
			}
			resourceID = assignedResourceID
			usedAssignments++
		}
		value, errGet := m.resources.Get(ctx, ownerAPIKeyID, resourceID)
		if errGet != nil || value.Kind != planned.Kind || value.MIMEType != planned.MIMEType || value.SizeBytes != planned.SizeBytes || (planned.SHA256 != "" && value.SHA256 != planned.SHA256) || !materializedImageMetadataMatches(planned, value.Metadata) {
			return nil, ErrMaterializationChanged
		}
		materialized, errMaterialize := m.materializeOne(ctx, plan.Target, planned, value)
		if errMaterialize != nil {
			return nil, errMaterialize
		}
		results = append(results, materialized)
	}
	if usedAssignments != len(assignments) {
		return nil, ErrMaterializationFailed
	}
	return results, nil
}

// materializedImageMetadataMatches verifies image facts frozen by the accepted input plan.
// materializedImageMetadataMatches 验证已接受输入方案冻结的图片事实。
func materializedImageMetadataMatches(planned FrozenMaterializationInput, metadata Metadata) bool {
	if planned.Kind != vcp.MediaImage {
		return true
	}
	return metadata.Image != nil && metadata.Image.Width == planned.ImageWidth && metadata.Image.Height == planned.ImageHeight && metadata.Image.HasAlpha == planned.ImageHasAlpha
}

// materializeOne realizes one frozen representation.
// materializeOne 实现一个冻结表示。
func (m *Materializer) materializeOne(ctx context.Context, target resolve.Target, planned FrozenMaterializationInput, value Resource) (MaterializedInput, error) {
	result := MaterializedInput{InputID: planned.InputID, ResourceID: value.ID, Kind: value.Kind, Role: planned.Role, MIMEType: value.MIMEType, Mode: planned.Materialization, GeneratedBy: value.GeneratedBy}
	switch planned.Materialization {
	case catalog.MaterializationInlineBase64:
		_, content, errOpen := m.resources.OpenContent(ctx, value.OwnerAPIKeyID, value.ID)
		if errOpen != nil {
			return MaterializedInput{}, errOpen
		}
		defer content.Close()
		bytes, errRead := io.ReadAll(io.LimitReader(content, value.SizeBytes+1))
		if errRead != nil || int64(len(bytes)) != value.SizeBytes {
			return MaterializedInput{}, ErrMaterializationFailed
		}
		result.InlineBase64 = base64.StdEncoding.EncodeToString(bytes)
	case catalog.MaterializationDirectRemoteURL:
		if value.Source != SourceURLImport || strings.TrimSpace(value.SourceURL) == "" {
			return MaterializedInput{}, ErrMaterializationFailed
		}
		result.RemoteURL = value.SourceURL
	case catalog.MaterializationProviderFileID, catalog.MaterializationProviderAssetID, catalog.MaterializationProviderObjectURI:
		handle, kind, errHandle := m.providerHandle(ctx, target, planned.Materialization, value)
		if errHandle != nil {
			return MaterializedInput{}, errHandle
		}
		result.ProviderHandle, result.ProviderAssetKind = handle, kind
	default:
		return MaterializedInput{}, ErrMaterializationFailed
	}
	return result, nil
}

// providerHandle reuses one exact live binding or creates and compensates one new provider asset.
// providerHandle 复用一个精确有效绑定或创建并补偿一个新供应商资产。
func (m *Materializer) providerHandle(ctx context.Context, target resolve.Target, mode catalog.UpstreamMaterializationMode, value Resource) (string, ProviderAssetKind, error) {
	bindingTarget := assetTarget(target)
	binding, errBinding := m.bindings.FindExact(ctx, value.ID, value.SHA256, bindingTarget, mode, m.options.Now().UTC())
	if errBinding == nil {
		handle, errSecret := m.secrets.Get(ctx, binding.ProtectedHandleRef)
		if errSecret != nil {
			return "", "", ErrMaterializationFailed
		}
		return string(handle), binding.Kind, nil
	}
	if !errors.Is(errBinding, ErrAssetBindingNotFound) {
		return "", "", errBinding
	}
	if dependency.IsNil(m.uploader) {
		return "", "", ErrMaterializationFailed
	}
	_, content, errOpen := m.resources.OpenContent(ctx, value.OwnerAPIKeyID, value.ID)
	if errOpen != nil {
		return "", "", errOpen
	}
	defer content.Close()
	uploaded, errUpload := m.uploader.Upload(ctx, AssetUploadRequest{Target: bindingTarget, ResourceID: value.ID, SHA256: value.SHA256, Kind: value.Kind, MIMEType: value.MIMEType, SizeBytes: value.SizeBytes, Mode: mode, Content: content})
	if errUpload != nil || strings.TrimSpace(uploaded.Handle) == "" || !handleMatchesMode(uploaded.Kind, mode) {
		return "", "", ErrMaterializationFailed
	}
	secretReference, errSecret := m.secrets.Put(ctx, []byte(uploaded.Handle))
	if errSecret != nil {
		_ = m.uploader.Delete(context.WithoutCancel(ctx), bindingTarget, uploaded.Kind, uploaded.Handle)
		return "", "", ErrMaterializationFailed
	}
	bindingID, errID := m.options.NewBindingID()
	if errID != nil || !validAssetBindingID(bindingID) {
		_ = m.secrets.Delete(context.WithoutCancel(ctx), secretReference)
		_ = m.uploader.Delete(context.WithoutCancel(ctx), bindingTarget, uploaded.Kind, uploaded.Handle)
		return "", "", ErrMaterializationFailed
	}
	createdAt := m.options.Now().UTC()
	created := ProviderAssetBinding{ID: bindingID, ResourceID: value.ID, ResourceSHA256: value.SHA256, Target: bindingTarget, Materialization: mode, Kind: uploaded.Kind, ProtectedHandleRef: secretReference, CreatedAt: createdAt, ExpiresAt: uploaded.ExpiresAt, Revision: 1}
	if errSave := m.bindings.Save(ctx, created); errSave != nil {
		_ = m.secrets.Delete(context.WithoutCancel(ctx), secretReference)
		_ = m.uploader.Delete(context.WithoutCancel(ctx), bindingTarget, uploaded.Kind, uploaded.Handle)
		return "", "", errSave
	}
	return uploaded.Handle, uploaded.Kind, nil
}

// assetTarget projects the complete target identity that governs provider asset reuse.
// assetTarget 投影管理供应商资产复用的完整 Target 身份。
func assetTarget(target resolve.Target) AssetBindingTarget {
	return AssetBindingTarget{ProviderDefinitionID: target.ProviderDefinitionID, ProviderInstanceID: target.ProviderInstanceID, EndpointID: target.EndpointID, Region: target.EndpointRegion, CredentialID: target.CredentialID, ActionBindingID: target.ActionBindingID, ProviderModelID: target.ProviderModelID, UpstreamModelID: target.UpstreamModelID}
}

// handleMatchesMode verifies one exact provider handle family.
// handleMatchesMode 校验一个精确供应商句柄类别。
func handleMatchesMode(kind ProviderAssetKind, mode catalog.UpstreamMaterializationMode) bool {
	return (kind == ProviderAssetFile && mode == catalog.MaterializationProviderFileID) || (kind == ProviderAssetObject && mode == catalog.MaterializationProviderObjectURI) || (kind == ProviderAssetOpaque && mode == catalog.MaterializationProviderAssetID)
}

// randomAssetBindingID returns a 128-bit opaque binding identifier.
// randomAssetBindingID 返回一个 128 位不透明绑定标识。
func randomAssetBindingID() (string, error) {
	bytes := make([]byte, 16)
	if _, errRead := rand.Read(bytes); errRead != nil {
		return "", errRead
	}
	return "pab_" + hex.EncodeToString(bytes), nil
}
