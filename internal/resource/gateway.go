package resource

import (
	"context"
	"io"
)

// Gateway unifies authorized resource storage and import workflows for the call-plane boundary.
// Gateway 为调用面边界统一已授权资源存储与导入工作流。
type Gateway struct {
	// resources owns object storage and lifecycle operations.
	// resources 拥有对象存储与生命周期操作。
	resources *Service
	// importer owns secure URL and Base64 ingestion.
	// importer 拥有安全 URL 与 Base64 接收。
	importer *Importer
}

// NewGateway creates one complete resource call-plane gateway.
// NewGateway 创建一个完整资源调用面网关。
func NewGateway(resources *Service, importer *Importer) (*Gateway, error) {
	if resources == nil || importer == nil || importer.resources != resources {
		return nil, ErrInvalidResource
	}
	return &Gateway{resources: resources, importer: importer}, nil
}

// MaximumObjectBytes returns the immutable decoded object ceiling.
// MaximumObjectBytes 返回不可变解码对象上限。
func (g *Gateway) MaximumObjectBytes() int64 {
	if g == nil || g.resources == nil {
		return 0
	}
	return g.resources.options.MaxObjectBytes
}

// Create streams one multipart-provided resource into Router storage.
// Create 将一个 Multipart 提供的资源流式写入 Router 存储。
func (g *Gateway) Create(ctx context.Context, input CreateInput) (Resource, error) {
	return g.resources.Create(ctx, input)
}

// ImportURL securely imports one public URL.
// ImportURL 安全导入一个公网 URL。
func (g *Gateway) ImportURL(ctx context.Context, input URLImportInput) (Resource, error) {
	return g.importer.ImportURL(ctx, input)
}

// ImportGeneratedURL securely imports one provider-generated temporary public URL.
// ImportGeneratedURL 安全导入一个供应商生成的临时公网 URL。
func (g *Gateway) ImportGeneratedURL(ctx context.Context, input URLImportInput) (Resource, error) {
	return g.importer.ImportGeneratedURL(ctx, input)
}

// CreateGenerated publishes one already-acquired provider output through the common bounded resource service.
// CreateGenerated 通过统一受限资源服务发布一个已获取的供应商输出。
func (g *Gateway) CreateGenerated(ctx context.Context, input CreateInput) (Resource, error) {
	input.Source = SourceGenerated
	input.SourceURL = ""
	return g.resources.Create(ctx, input)
}

// ImportBase64 decodes one bounded Base64 object.
// ImportBase64 解码一个受限 Base64 对象。
func (g *Gateway) ImportBase64(ctx context.Context, input Base64ImportInput) (Resource, error) {
	return g.importer.ImportBase64(ctx, input)
}

// Get returns owner-scoped public metadata.
// Get 返回所有者作用域的公开元数据。
func (g *Gateway) Get(ctx context.Context, ownerAPIKeyID string, resourceID string) (Resource, error) {
	value, errGet := g.resources.Get(ctx, ownerAPIKeyID, resourceID)
	if errGet != nil {
		return Resource{}, errGet
	}
	if value.State != StateReady || (value.ExpiresAt != nil && !value.ExpiresAt.After(g.resources.options.Now().UTC())) {
		return Resource{}, ErrResourceNotFound
	}
	return value, nil
}

// OpenContent opens owner-scoped verified bytes.
// OpenContent 打开所有者作用域的已验证字节。
func (g *Gateway) OpenContent(ctx context.Context, ownerAPIKeyID string, resourceID string) (Resource, io.ReadCloser, error) {
	return g.resources.OpenContent(ctx, ownerAPIKeyID, resourceID)
}

// Delete removes owner-scoped bindings and object bytes before tombstoning metadata.
// Delete 在元数据变成墓碑前删除所有者作用域绑定与对象字节。
func (g *Gateway) Delete(ctx context.Context, ownerAPIKeyID string, resourceID string) error {
	return g.resources.Delete(ctx, ownerAPIKeyID, resourceID)
}
