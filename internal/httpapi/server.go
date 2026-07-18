// Package httpapi exposes only framework-level Vulcan Model Core endpoints.
// httpapi 包仅暴露 Vulcan Model Core 的框架级端点。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/OpenVulcan/vulcan-model-core/internal/management"
)

var (
	// ErrProviderCatalogRequired identifies a missing provider metadata source.
	// ErrProviderCatalogRequired 标识缺失的供应商元数据来源。
	ErrProviderCatalogRequired = errors.New("provider catalog is required")
)

// ProviderCatalog exposes the registered provider snapshot needed by HTTP metadata endpoints.
// ProviderCatalog 暴露 HTTP 元数据端点所需的已注册供应商快照。
type ProviderCatalog interface {
	// ProviderIDs returns stable provider identifiers without exposing adapters.
	// ProviderIDs 返回稳定的供应商标识且不暴露适配器。
	ProviderIDs() []string
}

// ManagementQuery exposes client-safe configuration, catalog, and management-detail views.
// ManagementQuery 暴露客户端安全的配置、目录和管理详情视图。
type ManagementQuery interface {
	// ListDefinitions returns visible system and custom provider definitions.
	// ListDefinitions 返回可见系统与自定义供应商定义。
	ListDefinitions(context.Context) ([]management.ProviderDefinitionView, error)
	// ListInstances returns safe aggregate provider instance views.
	// ListInstances 返回安全的供应商实例聚合视图。
	ListInstances(context.Context) ([]management.ProviderInstanceView, error)
	// GetInstance returns one safe provider instance aggregate.
	// GetInstance 返回一个安全供应商实例聚合。
	GetInstance(context.Context, string) (management.ProviderInstanceView, error)
	// GetCatalog returns one safe atomic provider model catalog.
	// GetCatalog 返回一个安全原子供应商模型目录。
	GetCatalog(context.Context, string) (management.CatalogView, error)
	// ListEndpoints returns management-safe endpoint records.
	// ListEndpoints 返回管理安全端点记录。
	ListEndpoints(context.Context, string) ([]management.EndpointView, error)
	// ListCredentials returns management-safe non-secret credential records.
	// ListCredentials 返回管理安全的非秘密凭据记录。
	ListCredentials(context.Context, string) ([]management.CredentialView, error)
	// ListBindings returns management-safe access binding records.
	// ListBindings 返回管理安全访问绑定记录。
	ListBindings(context.Context, string) ([]management.BindingView, error)
}

// Server owns the minimal Vulcan Model Core HTTP surface.
// Server 管理最小化的 Vulcan Model Core HTTP 接口面。
type Server struct {
	// catalog supplies provider readiness and metadata.
	// catalog 提供供应商就绪状态和元数据。
	catalog ProviderCatalog
	// control supplies the complete authenticated management and call-plane dependency graph.
	// control 提供完整认证的管理和调用面依赖图。
	control *ControlPlane
	// handler contains the immutable route table.
	// handler 包含不可变的路由表。
	handler http.Handler
}

// errorResponse carries one non-sensitive machine-readable HTTP error code.
// errorResponse 携带一个不敏感且机器可读的 HTTP 错误码。
type errorResponse struct {
	// Error is the stable public error category without internal persistence details.
	// Error 是不包含内部持久化详情的稳定公开错误类别。
	Error string `json:"error"`
}

// New creates the minimal HTTP API without legacy protocol routes.
// New 创建不含旧协议路由的最小 HTTP API。
func New(catalog ProviderCatalog) (*Server, error) {
	return newServer(catalog, nil)
}

// NewWithControlPlane creates the authenticated local management and call-plane HTTP surface.
// NewWithControlPlane 创建认证的本地管理和调用面 HTTP 接口面。
func NewWithControlPlane(catalog ProviderCatalog, control ControlPlane) (*Server, error) {
	if errControl := control.validate(); errControl != nil {
		return nil, errControl
	}
	return newServer(catalog, &control)
}

// newServer creates one immutable route table with an optional fully authenticated control plane.
// newServer 创建一个带可选完整认证控制面的不可变路由表。
func newServer(catalog ProviderCatalog, control *ControlPlane) (*Server, error) {
	if catalog == nil {
		return nil, ErrProviderCatalogRequired
	}
	// server owns the catalog before routes capture it.
	// server 在路由捕获目录前持有该目录。
	server := &Server{catalog: catalog, control: control}
	// mux registers framework routes plus optional route-scoped authenticated Vulcan surfaces.
	// mux 注册框架路由以及可选的按路由作用域认证 Vulcan 接口面。
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.handleHealth)
	mux.HandleFunc("HEAD /healthz", server.handleHealth)
	mux.HandleFunc("GET /readyz", server.handleReady)
	mux.HandleFunc("HEAD /readyz", server.handleReady)
	mux.HandleFunc("GET /vulcan/meta/providers", server.handleProviders)
	if control != nil {
		// management routes are protected exclusively by the management credential namespace.
		// management 路由仅受管理凭据命名空间保护。
		mux.Handle("GET /vulcan/manage/protocol-profiles", server.requireManagement(http.HandlerFunc(server.handleProtocolProfiles)))
		mux.Handle("GET /vulcan/manage/provider-definitions", server.requireManagement(http.HandlerFunc(server.handleProviderDefinitions)))
		mux.Handle("POST /vulcan/manage/provider-definitions", server.requireManagement(http.HandlerFunc(server.handleCreateCustomDefinition)))
		mux.Handle("PUT /vulcan/manage/provider-definitions/{provider_definition_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateCustomDefinition)))
		mux.Handle("GET /vulcan/manage/provider-instances", server.requireManagement(http.HandlerFunc(server.handleProviderInstances)))
		mux.Handle("POST /vulcan/manage/provider-instances", server.requireManagement(http.HandlerFunc(server.handleCreateInstance)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}", server.requireManagement(http.HandlerFunc(server.handleProviderInstance)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateInstance)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/enabled", server.requireManagement(http.HandlerFunc(server.handleSetInstanceEnabled)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}/catalog", server.requireManagement(http.HandlerFunc(server.handleProviderCatalog)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}/custom-catalog", server.requireManagement(http.HandlerFunc(server.handleCustomCatalog)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/custom-catalog", server.requireManagement(http.HandlerFunc(server.handleSaveCustomCatalog)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/models/{provider_model_id}/enabled", server.requireManagement(http.HandlerFunc(server.handleSetModelEnabled)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}/endpoints", server.requireManagement(http.HandlerFunc(server.handleEndpoints)))
		mux.Handle("POST /vulcan/manage/provider-instances/{provider_instance_id}/endpoints", server.requireManagement(http.HandlerFunc(server.handleCreateEndpoint)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/endpoints/{endpoint_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateEndpoint)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}/credentials", server.requireManagement(http.HandlerFunc(server.handleCredentials)))
		mux.Handle("POST /vulcan/manage/provider-instances/{provider_instance_id}/credentials", server.requireManagement(http.HandlerFunc(server.handleCreateCredential)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/credentials/{credential_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateCredential)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/credentials/{credential_id}/secret", server.requireManagement(http.HandlerFunc(server.handleRotateCredentialSecret)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/credentials/{credential_id}/status", server.requireManagement(http.HandlerFunc(server.handleSetCredentialStatus)))
		mux.Handle("GET /vulcan/manage/provider-instances/{provider_instance_id}/bindings", server.requireManagement(http.HandlerFunc(server.handleBindings)))
		mux.Handle("POST /vulcan/manage/provider-instances/{provider_instance_id}/bindings", server.requireManagement(http.HandlerFunc(server.handleCreateBinding)))
		mux.Handle("PUT /vulcan/manage/provider-instances/{provider_instance_id}/bindings/{binding_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateBinding)))
		mux.Handle("GET /vulcan/manage/api-keys", server.requireManagement(http.HandlerFunc(server.handleAPIKeys)))
		mux.Handle("POST /vulcan/manage/api-keys", server.requireManagement(http.HandlerFunc(server.handleCreateAPIKey)))
		mux.Handle("PUT /vulcan/manage/api-keys/{api_key_id}", server.requireManagement(http.HandlerFunc(server.handleUpdateAPIKey)))
		mux.Handle("DELETE /vulcan/manage/api-keys/{api_key_id}", server.requireManagement(http.HandlerFunc(server.handleDeleteAPIKey)))
		// call routes are protected exclusively by enabled call-plane API keys.
		// call 路由仅受启用的调用面 API 密钥保护。
		mux.Handle("GET /vulcan/v1/models", server.requireAPIKey(http.HandlerFunc(server.handleCallModels)))
	}
	server.handler = mux
	return server, nil
}

// Handler returns the immutable HTTP handler.
// Handler 返回不可变的 HTTP 处理器。
func (s *Server) Handler() http.Handler {
	return s.handler
}

// handleHealth reports process liveness independently of provider readiness.
// handleHealth 独立于供应商就绪状态报告进程存活情况。
func (s *Server) handleHealth(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleReady reports whether at least one provider adapter is registered.
// handleReady 报告是否至少注册了一个供应商适配器。
func (s *Server) handleReady(w http.ResponseWriter, request *http.Request) {
	// providerCount reflects the current executable provider set.
	// providerCount 反映当前可执行供应商集合。
	providerCount := len(s.catalog.ProviderIDs())
	// statusCode is unavailable until one provider can execute requests.
	// statusCode 在至少一个供应商可执行请求前保持不可用。
	statusCode := http.StatusOK
	// status describes the machine-readable readiness state.
	// status 描述机器可读的就绪状态。
	status := "ready"
	if providerCount == 0 {
		statusCode = http.StatusServiceUnavailable
		status = "not_ready"
	}
	if request.Method == http.MethodHead {
		w.WriteHeader(statusCode)
		return
	}
	writeJSON(w, statusCode, map[string]any{"status": status, "providers": providerCount})
}

// handleProviders returns provider identifiers without protocol fusion metadata.
// handleProviders 返回供应商标识且不包含协议融合元数据。
func (s *Server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.catalog.ProviderIDs()})
}

// writeJSON writes one compact JSON response.
// writeJSON 写入一个紧凑的 JSON 响应。
func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
