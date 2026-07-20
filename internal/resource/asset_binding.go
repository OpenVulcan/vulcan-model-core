package resource

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

var (
	// ErrAssetBindingNotFound reports no live binding for one exact target.
	// ErrAssetBindingNotFound 表示一个精确 Target 没有有效绑定。
	ErrAssetBindingNotFound = errors.New("provider asset binding not found")
	// ErrInvalidAssetBinding reports malformed provider-owned asset metadata.
	// ErrInvalidAssetBinding 表示供应商拥有资产元数据格式错误。
	ErrInvalidAssetBinding = errors.New("invalid provider asset binding")
)

// ProviderAssetKind identifies one closed provider-owned handle family.
// ProviderAssetKind 标识一种封闭供应商拥有句柄类别。
type ProviderAssetKind string

const (
	// ProviderAssetFile identifies a provider file identifier.
	// ProviderAssetFile 标识供应商文件标识。
	ProviderAssetFile ProviderAssetKind = "file_id"
	// ProviderAssetObject identifies an authorized object URI.
	// ProviderAssetObject 标识授权对象 URI。
	ProviderAssetObject ProviderAssetKind = "object_uri"
	// ProviderAssetOpaque identifies a provider asset identifier.
	// ProviderAssetOpaque 标识供应商资产标识。
	ProviderAssetOpaque ProviderAssetKind = "asset_id"
)

// AssetBindingTarget freezes every identity that constrains upstream asset validity.
// AssetBindingTarget 冻结约束上游资产有效性的每项身份。
type AssetBindingTarget struct {
	// ProviderDefinitionID identifies the code-owned provider definition.
	// ProviderDefinitionID 标识代码拥有供应商定义。
	ProviderDefinitionID string `json:"provider_definition_id"`
	// ProviderInstanceID fixes the user-visible integration.
	// ProviderInstanceID 固定用户可见集成。
	ProviderInstanceID string `json:"provider_instance_id"`
	// EndpointID fixes the endpoint identity.
	// EndpointID 固定端点身份。
	EndpointID string `json:"endpoint_id"`
	// Region preserves endpoint-local validity.
	// Region 保留端点本地区域有效性。
	Region string `json:"region"`
	// CredentialID fixes the upstream principal.
	// CredentialID 固定上游主体。
	CredentialID string `json:"credential_id"`
	// ActionBindingID fixes the code-owned upload or asset action.
	// ActionBindingID 固定代码拥有上传或资产动作。
	ActionBindingID string `json:"action_binding_id"`
	// ProviderModelID fixes the logical model.
	// ProviderModelID 固定逻辑模型。
	ProviderModelID string `json:"provider_model_id"`
	// UpstreamModelID fixes the exact upstream model handle.
	// UpstreamModelID 固定精确上游模型句柄。
	UpstreamModelID string `json:"upstream_model_id"`
}

// ProviderAssetBinding stores a protected-reference-backed upstream materialization.
// ProviderAssetBinding 存储一个由受保护引用支持的上游物化结果。
type ProviderAssetBinding struct {
	// ID is the opaque binding identifier.
	// ID 是不透明绑定标识。
	ID string `json:"id"`
	// ResourceID identifies the Router resource.
	// ResourceID 标识 Router 资源。
	ResourceID string `json:"resource_id"`
	// ResourceSHA256 freezes the exact bytes.
	// ResourceSHA256 冻结精确字节。
	ResourceSHA256 string `json:"resource_sha256"`
	// Target freezes complete provider ownership scope.
	// Target 冻结完整供应商归属作用域。
	Target AssetBindingTarget `json:"target"`
	// Materialization records the exact selected transfer mode.
	// Materialization 记录精确选定传输方式。
	Materialization catalog.UpstreamMaterializationMode `json:"materialization"`
	// Kind identifies the protected upstream handle family.
	// Kind 标识受保护上游句柄类别。
	Kind ProviderAssetKind `json:"kind"`
	// ProtectedHandleRef points to an OS-protected secret and never contains the handle itself.
	// ProtectedHandleRef 指向操作系统保护 Secret 且绝不包含句柄本身。
	ProtectedHandleRef string `json:"protected_handle_ref"`
	// CreatedAt records provider asset creation time.
	// CreatedAt 记录供应商资产创建时间。
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt limits reuse when the provider handle is temporary.
	// ExpiresAt 在供应商句柄临时时限制复用。
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Revision is the immutable binding revision.
	// Revision 是不可变绑定修订号。
	Revision uint64 `json:"revision"`
}

// Validate verifies exact target completeness, hash, handle reference, and materialization agreement.
// Validate 校验精确 Target 完整性、Hash、句柄引用与物化方式一致性。
func (b ProviderAssetBinding) Validate() error {
	if !validAssetBindingID(b.ID) || !validResourceID(b.ResourceID) || len(b.ResourceSHA256) != 64 || strings.TrimSpace(b.ProtectedHandleRef) == "" || b.CreatedAt.IsZero() || b.Revision == 0 || (b.ExpiresAt != nil && !b.ExpiresAt.After(b.CreatedAt)) {
		return ErrInvalidAssetBinding
	}
	target := b.Target
	if target.ProviderDefinitionID == "" || target.ProviderInstanceID == "" || target.EndpointID == "" || target.CredentialID == "" || target.ActionBindingID == "" || target.ProviderModelID == "" || target.UpstreamModelID == "" {
		return fmt.Errorf("%w: complete target identity is required", ErrInvalidAssetBinding)
	}
	validPair := (b.Kind == ProviderAssetFile && b.Materialization == catalog.MaterializationProviderFileID) || (b.Kind == ProviderAssetObject && b.Materialization == catalog.MaterializationProviderObjectURI) || (b.Kind == ProviderAssetOpaque && b.Materialization == catalog.MaterializationProviderAssetID)
	if !validPair {
		return fmt.Errorf("%w: handle kind and materialization disagree", ErrInvalidAssetBinding)
	}
	return nil
}

// AssetBindingStore persists exact-target provider asset bindings.
// AssetBindingStore 持久化精确 Target 供应商资产绑定。
type AssetBindingStore interface {
	// Save creates one binding and rejects identity reuse.
	// Save 创建一个绑定并拒绝身份复用。
	Save(context.Context, ProviderAssetBinding) error
	// FindExact returns one live binding for exact resource bytes, target, and mode.
	// FindExact 为精确资源字节、Target 与方式返回一个有效绑定。
	FindExact(context.Context, string, string, AssetBindingTarget, catalog.UpstreamMaterializationMode, time.Time) (ProviderAssetBinding, error)
	// DeleteByResource removes every binding owned by one Router resource.
	// DeleteByResource 移除一个 Router 资源拥有的每个绑定。
	DeleteByResource(context.Context, string) error
}

// MemoryAssetBindingStore is an atomic in-memory binding repository.
// MemoryAssetBindingStore 是原子内存绑定仓库。
type MemoryAssetBindingStore struct {
	// mu protects binding snapshots.
	// mu 保护绑定快照。
	mu sync.RWMutex
	// bindings owns values by identifier.
	// bindings 按标识拥有值。
	bindings map[string]ProviderAssetBinding
}

// NewMemoryAssetBindingStore creates an empty binding repository.
// NewMemoryAssetBindingStore 创建一个空绑定仓库。
func NewMemoryAssetBindingStore() *MemoryAssetBindingStore {
	return &MemoryAssetBindingStore{bindings: make(map[string]ProviderAssetBinding)}
}

// Save creates one validated immutable binding.
// Save 创建一个已校验不可变绑定。
func (s *MemoryAssetBindingStore) Save(ctx context.Context, binding ProviderAssetBinding) error {
	if ctx == nil || s == nil {
		return ErrInvalidAssetBinding
	}
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	if errValidate := binding.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bindings[binding.ID]; exists {
		return ErrInvalidAssetBinding
	}
	s.bindings[binding.ID] = binding
	return nil
}

// FindExact returns one unexpired exact-target binding.
// FindExact 返回一个未过期精确 Target 绑定。
func (s *MemoryAssetBindingStore) FindExact(ctx context.Context, resourceID string, resourceHash string, target AssetBindingTarget, mode catalog.UpstreamMaterializationMode, now time.Time) (ProviderAssetBinding, error) {
	if ctx == nil || s == nil || now.IsZero() {
		return ProviderAssetBinding{}, ErrInvalidAssetBinding
	}
	if errContext := ctx.Err(); errContext != nil {
		return ProviderAssetBinding{}, errContext
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, binding := range s.bindings {
		if binding.ResourceID == resourceID && binding.ResourceSHA256 == resourceHash && binding.Target == target && binding.Materialization == mode && (binding.ExpiresAt == nil || binding.ExpiresAt.After(now)) {
			return binding, nil
		}
	}
	return ProviderAssetBinding{}, ErrAssetBindingNotFound
}

// DeleteByResource removes every binding for one Router resource.
// DeleteByResource 移除一个 Router 资源的每个绑定。
func (s *MemoryAssetBindingStore) DeleteByResource(ctx context.Context, resourceID string) error {
	if ctx == nil || s == nil || !validResourceID(resourceID) {
		return ErrInvalidAssetBinding
	}
	if errContext := ctx.Err(); errContext != nil {
		return errContext
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for identifier, binding := range s.bindings {
		if binding.ResourceID == resourceID {
			delete(s.bindings, identifier)
		}
	}
	return nil
}

// CleanupResourceBindings satisfies resource deletion with exact binding removal.
// CleanupResourceBindings 通过精确绑定移除满足资源删除。
func (s *MemoryAssetBindingStore) CleanupResourceBindings(ctx context.Context, resourceID string) error {
	return s.DeleteByResource(ctx, resourceID)
}

// validAssetBindingID verifies the 128-bit binding identifier shape.
// validAssetBindingID 校验 128 位绑定标识形态。
func validAssetBindingID(identifier string) bool {
	if len(identifier) != 36 || !strings.HasPrefix(identifier, "pab_") {
		return false
	}
	decoded, errDecode := hex.DecodeString(identifier[4:])
	return errDecode == nil && len(decoded) == 16
}
