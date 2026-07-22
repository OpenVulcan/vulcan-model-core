package resource

import (
	"context"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// AssetBindingCleaner removes provider-owned handles before releasing their protected local references.
// AssetBindingCleaner 在释放受保护本地引用前删除供应商拥有句柄。
type AssetBindingCleaner struct {
	// bindings owns durable exact-target cleanup work.
	// bindings 拥有持久化精确 Target 清理任务。
	bindings AssetBindingStore
	// secrets resolves protected upstream handles only at the deletion boundary.
	// secrets 仅在删除边界解析受保护上游句柄。
	secrets secret.Store
	// uploader dispatches idempotent provider-scoped deletion.
	// uploader 分派幂等的供应商作用域删除。
	uploader AssetUploader
}

// NewAssetBindingCleaner creates a provider-aware Router resource cleanup boundary.
// NewAssetBindingCleaner 创建一个感知供应商的 Router 资源清理边界。
func NewAssetBindingCleaner(bindings AssetBindingStore, secrets secret.Store, uploader AssetUploader) (*AssetBindingCleaner, error) {
	if dependency.IsNil(bindings) || dependency.IsNil(secrets) || dependency.IsNil(uploader) {
		return nil, ErrInvalidAssetBinding
	}
	return &AssetBindingCleaner{bindings: bindings, secrets: secrets, uploader: uploader}, nil
}

// CleanupResourceBindings deletes every upstream handle in stable order and retains failed work for retry.
// CleanupResourceBindings 按稳定顺序删除每个上游句柄，并保留失败任务以供重试。
func (c *AssetBindingCleaner) CleanupResourceBindings(ctx context.Context, resourceID string) error {
	if c == nil || ctx == nil {
		return ErrInvalidAssetBinding
	}
	bindings, errList := c.bindings.ListByResource(ctx, resourceID)
	if errList != nil {
		return errList
	}
	for _, binding := range bindings {
		handle, errSecret := c.secrets.Get(ctx, binding.ProtectedHandleRef)
		if errSecret != nil || len(handle) == 0 {
			clear(handle)
			return fmt.Errorf("%w: protected provider handle is unavailable", ErrInvalidAssetBinding)
		}
		errDelete := c.uploader.Delete(ctx, binding.Target, binding.Kind, string(handle))
		clear(handle)
		if errDelete != nil {
			return fmt.Errorf("delete provider asset binding %s: %w", binding.ID, errDelete)
		}
		if errBinding := c.bindings.Delete(ctx, binding.ID); errBinding != nil {
			return errBinding
		}
		if errSecret := c.secrets.Delete(ctx, binding.ProtectedHandleRef); errSecret != nil {
			return fmt.Errorf("delete protected provider handle: %w", errSecret)
		}
	}
	return nil
}
