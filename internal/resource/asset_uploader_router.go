package resource

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
)

var (
	// ErrAssetUploaderRouteNotFound reports an exact provider definition without a registered asset owner.
	// ErrAssetUploaderRouteNotFound 表示精确供应商定义没有已注册资产管理器。
	ErrAssetUploaderRouteNotFound = errors.New("provider asset uploader route not found")
	// ErrInvalidAssetUploaderRoute reports duplicate or incomplete routing configuration.
	// ErrInvalidAssetUploaderRoute 表示重复或不完整的路由配置。
	ErrInvalidAssetUploaderRoute = errors.New("invalid provider asset uploader route")
)

// AssetUploaderRoute binds explicit provider definition IDs to one provider-owned uploader.
// AssetUploaderRoute 将明确供应商定义 ID 绑定到一个供应商拥有的上传器。
type AssetUploaderRoute struct {
	// ProviderDefinitionIDs contains the complete closed ownership set for this uploader.
	// ProviderDefinitionIDs 包含此上传器完整封闭的归属集合。
	ProviderDefinitionIDs []string
	// Uploader owns upload and cleanup behavior for the declared definitions.
	// Uploader 管理已声明定义的上传与清理行为。
	Uploader AssetUploader
}

// AssetUploaderRouter dispatches exact provider-scoped asset operations without probing alternatives.
// AssetUploaderRouter 在不探测替代路径的情况下分派精确供应商作用域资产操作。
type AssetUploaderRouter struct {
	// uploaders indexes one and only one uploader for each provider definition.
	// uploaders 为每个供应商定义索引唯一上传器。
	uploaders map[string]AssetUploader
}

// NewAssetUploaderRouter creates one immutable exact-definition dispatch table.
// NewAssetUploaderRouter 创建一个不可变的精确定义分派表。
func NewAssetUploaderRouter(routes ...AssetUploaderRoute) (*AssetUploaderRouter, error) {
	if len(routes) == 0 {
		return nil, ErrInvalidAssetUploaderRoute
	}
	uploaders := make(map[string]AssetUploader)
	for _, route := range routes {
		if dependency.IsNil(route.Uploader) || len(route.ProviderDefinitionIDs) == 0 {
			return nil, ErrInvalidAssetUploaderRoute
		}
		for _, definitionID := range route.ProviderDefinitionIDs {
			definitionID = strings.TrimSpace(definitionID)
			if definitionID == "" {
				return nil, ErrInvalidAssetUploaderRoute
			}
			if _, exists := uploaders[definitionID]; exists {
				return nil, fmt.Errorf("%w: duplicate provider definition %q", ErrInvalidAssetUploaderRoute, definitionID)
			}
			uploaders[definitionID] = route.Uploader
		}
	}
	return &AssetUploaderRouter{uploaders: uploaders}, nil
}

// Upload dispatches one upload to the uploader that owns the exact frozen definition.
// Upload 将一次上传分派给拥有精确冻结定义的上传器。
func (r *AssetUploaderRouter) Upload(ctx context.Context, request AssetUploadRequest) (AssetUploadResult, error) {
	uploader, errLookup := r.lookup(request.Target.ProviderDefinitionID)
	if errLookup != nil {
		return AssetUploadResult{}, errLookup
	}
	return uploader.Upload(ctx, request)
}

// Delete dispatches one cleanup to the same exact provider owner used at materialization time.
// Delete 将一次清理分派给物化时使用的同一精确供应商管理器。
func (r *AssetUploaderRouter) Delete(ctx context.Context, target AssetBindingTarget, kind ProviderAssetKind, handle string) error {
	uploader, errLookup := r.lookup(target.ProviderDefinitionID)
	if errLookup != nil {
		return errLookup
	}
	return uploader.Delete(ctx, target, kind, handle)
}

// lookup resolves exactly one configured uploader and never falls back across providers.
// lookup 解析唯一已配置上传器且绝不跨供应商回退。
func (r *AssetUploaderRouter) lookup(definitionID string) (AssetUploader, error) {
	if r == nil || strings.TrimSpace(definitionID) == "" {
		return nil, ErrAssetUploaderRouteNotFound
	}
	uploader, exists := r.uploaders[definitionID]
	if !exists || dependency.IsNil(uploader) {
		return nil, fmt.Errorf("%w: %s", ErrAssetUploaderRouteNotFound, definitionID)
	}
	return uploader, nil
}
