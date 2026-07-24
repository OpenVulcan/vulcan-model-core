package resource

import (
	"context"
	"errors"
	"testing"
)

// routingAssetUploader records exact dispatch without performing external work.
// routingAssetUploader 记录精确分派且不执行外部工作。
type routingAssetUploader struct {
	// uploads counts routed upload calls.
	// uploads 统计路由上传调用。
	uploads int
	// deletes counts routed delete calls.
	// deletes 统计路由删除调用。
	deletes int
}

// Upload records one routed upload.
// Upload 记录一次路由上传。
func (u *routingAssetUploader) Upload(_ context.Context, _ AssetUploadRequest) (AssetUploadResult, error) {
	u.uploads++
	return AssetUploadResult{Handle: "provider-handle", Kind: ProviderAssetObject}, nil
}

// Delete records one routed cleanup.
// Delete 记录一次路由清理。
func (u *routingAssetUploader) Delete(_ context.Context, _ AssetBindingTarget, _ ProviderAssetKind, _ string) error {
	u.deletes++
	return nil
}

// TestAssetUploaderRouterDispatchesExactDefinition verifies uploads and cleanup never cross provider ownership.
// TestAssetUploaderRouterDispatchesExactDefinition 验证上传与清理绝不会跨越供应商归属。
func TestAssetUploaderRouterDispatchesExactDefinition(t *testing.T) {
	first := &routingAssetUploader{}
	second := &routingAssetUploader{}
	router, errRouter := NewAssetUploaderRouter(
		AssetUploaderRoute{ProviderDefinitionIDs: []string{"definition-first"}, Uploader: first},
		AssetUploaderRoute{ProviderDefinitionIDs: []string{"definition-second"}, Uploader: second},
	)
	if errRouter != nil {
		t.Fatalf("NewAssetUploaderRouter() error = %v", errRouter)
	}
	target := AssetBindingTarget{ProviderDefinitionID: "definition-second"}
	if _, errUpload := router.Upload(context.Background(), AssetUploadRequest{Target: target}); errUpload != nil {
		t.Fatalf("Upload() error = %v", errUpload)
	}
	if errDelete := router.Delete(context.Background(), target, ProviderAssetObject, "provider-handle"); errDelete != nil {
		t.Fatalf("Delete() error = %v", errDelete)
	}
	if first.uploads != 0 || first.deletes != 0 || second.uploads != 1 || second.deletes != 1 {
		t.Fatalf("first = %#v, second = %#v", first, second)
	}
}

// TestAssetUploaderRouterRejectsDuplicateAndUnknownDefinitions verifies ambiguous or absent routes fail explicitly.
// TestAssetUploaderRouterRejectsDuplicateAndUnknownDefinitions 验证歧义或缺失路由会显式失败。
func TestAssetUploaderRouterRejectsDuplicateAndUnknownDefinitions(t *testing.T) {
	uploader := &routingAssetUploader{}
	if _, errRouter := NewAssetUploaderRouter(AssetUploaderRoute{ProviderDefinitionIDs: []string{"duplicate", "duplicate"}, Uploader: uploader}); !errors.Is(errRouter, ErrInvalidAssetUploaderRoute) {
		t.Fatalf("duplicate route error = %v", errRouter)
	}
	router, errRouter := NewAssetUploaderRouter(AssetUploaderRoute{ProviderDefinitionIDs: []string{"known"}, Uploader: uploader})
	if errRouter != nil {
		t.Fatalf("NewAssetUploaderRouter() error = %v", errRouter)
	}
	if _, errUpload := router.Upload(context.Background(), AssetUploadRequest{Target: AssetBindingTarget{ProviderDefinitionID: "unknown"}}); !errors.Is(errUpload, ErrAssetUploaderRouteNotFound) {
		t.Fatalf("unknown route error = %v", errUpload)
	}
}
