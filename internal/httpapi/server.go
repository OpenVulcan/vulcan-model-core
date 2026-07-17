// Package httpapi exposes only framework-level Vulcan Model Core endpoints.
// httpapi 包仅暴露 Vulcan Model Core 的框架级端点。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
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

// ManagementQuery exposes client-safe VulcanCode configuration and model discovery views.
// ManagementQuery 暴露客户端安全的 VulcanCode 配置与模型发现视图。
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
}

// Server owns the minimal Vulcan Model Core HTTP surface.
// Server 管理最小化的 Vulcan Model Core HTTP 接口面。
type Server struct {
	// catalog supplies provider readiness and metadata.
	// catalog 提供供应商就绪状态和元数据。
	catalog ProviderCatalog
	// management optionally supplies VulcanCode management and discovery views.
	// management 可选地提供 VulcanCode 管理与发现视图。
	management ManagementQuery
	// handler contains the immutable route table.
	// handler 包含不可变的路由表。
	handler http.Handler
}

// New creates the minimal HTTP API without legacy protocol routes.
// New 创建不含旧协议路由的最小 HTTP API。
func New(catalog ProviderCatalog) (*Server, error) {
	return newServer(catalog, nil)
}

// NewWithManagement creates the HTTP API with client-safe VulcanCode discovery routes.
// NewWithManagement 创建带客户端安全 VulcanCode 发现路由的 HTTP API。
func NewWithManagement(catalog ProviderCatalog, managementQuery ManagementQuery) (*Server, error) {
	if managementQuery == nil {
		return nil, errors.New("management query service is required")
	}
	return newServer(catalog, managementQuery)
}

// newServer creates one immutable route table with optional management discovery.
// newServer 创建一个带可选管理发现能力的不可变路由表。
func newServer(catalog ProviderCatalog, managementQuery ManagementQuery) (*Server, error) {
	if catalog == nil {
		return nil, ErrProviderCatalogRequired
	}
	// server owns the catalog before routes capture it.
	// server 在路由捕获目录前持有该目录。
	server := &Server{catalog: catalog, management: managementQuery}
	// mux registers only framework and Vulcan metadata endpoints.
	// mux 仅注册框架端点和 Vulcan 元数据端点。
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.handleHealth)
	mux.HandleFunc("HEAD /healthz", server.handleHealth)
	mux.HandleFunc("GET /readyz", server.handleReady)
	mux.HandleFunc("HEAD /readyz", server.handleReady)
	mux.HandleFunc("GET /vulcan/meta/providers", server.handleProviders)
	if managementQuery != nil {
		mux.HandleFunc("GET /vulcan/management/provider-definitions", server.handleProviderDefinitions)
		mux.HandleFunc("GET /vulcan/management/provider-instances", server.handleProviderInstances)
		mux.HandleFunc("GET /vulcan/management/provider-instances/{provider_instance_id}", server.handleProviderInstance)
		mux.HandleFunc("GET /vulcan/catalog/provider-instances/{provider_instance_id}", server.handleProviderCatalog)
	}
	server.handler = mux
	return server, nil
}

// handleProviderDefinitions returns safe system and custom provider metadata.
// handleProviderDefinitions 返回安全的系统与自定义供应商元数据。
func (s *Server) handleProviderDefinitions(w http.ResponseWriter, request *http.Request) {
	definitions, errDefinitions := s.management.ListDefinitions(request.Context())
	if errDefinitions != nil {
		writeManagementError(w, errDefinitions)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider_definitions": definitions})
}

// handleProviderInstances returns safe aggregate provider configuration views.
// handleProviderInstances 返回安全的供应商配置聚合视图。
func (s *Server) handleProviderInstances(w http.ResponseWriter, request *http.Request) {
	instances, errInstances := s.management.ListInstances(request.Context())
	if errInstances != nil {
		writeManagementError(w, errInstances)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider_instances": instances})
}

// handleProviderInstance returns one safe aggregate provider configuration view.
// handleProviderInstance 返回一个安全供应商配置聚合视图。
func (s *Server) handleProviderInstance(w http.ResponseWriter, request *http.Request) {
	instance, errInstance := s.management.GetInstance(request.Context(), request.PathValue("provider_instance_id"))
	if errInstance != nil {
		writeManagementError(w, errInstance)
		return
	}
	writeJSON(w, http.StatusOK, instance)
}

// handleProviderCatalog returns one safe atomic model and resource catalog.
// handleProviderCatalog 返回一个安全原子模型与资源目录。
func (s *Server) handleProviderCatalog(w http.ResponseWriter, request *http.Request) {
	providerCatalog, errCatalog := s.management.GetCatalog(request.Context(), request.PathValue("provider_instance_id"))
	if errCatalog != nil {
		writeManagementError(w, errCatalog)
		return
	}
	writeJSON(w, http.StatusOK, providerCatalog)
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

// writeManagementError maps domain absence to 404 without leaking persistence details.
// writeManagementError 将领域缺失映射为 404 且不泄露持久化细节。
func writeManagementError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	errorCode := "internal_error"
	if errors.Is(err, providerconfig.ErrNotFound) || errors.Is(err, catalog.ErrSnapshotNotFound) {
		statusCode = http.StatusNotFound
		errorCode = "not_found"
	}
	writeJSON(w, statusCode, map[string]any{"error": errorCode})
}
