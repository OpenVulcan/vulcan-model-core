package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/access"
	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// resourceDiagnosticView is the deliberately minimal resource lifecycle contract for management diagnostics.
// resourceDiagnosticView 是管理诊断专用的最小资源生命周期合同。
type resourceDiagnosticView struct {
	// ID is the Router-owned resource identifier.
	// ID 是 Router 所有的资源标识。
	ID string `json:"id"`
	// Kind identifies the closed media kind.
	// Kind 标识封闭媒体类型。
	Kind vcp.MediaKind `json:"kind"`
	// MIMEType is the inspected media type when available.
	// MIMEType 是可用时经过检查的媒体类型。
	MIMEType string `json:"mime_type"`
	// SizeBytes is the exact stored object size without its content digest.
	// SizeBytes 是不含内容摘要的精确存储对象大小。
	SizeBytes int64 `json:"size_bytes"`
	// Source records how Router obtained the resource without exposing its origin URL.
	// Source 记录 Router 获取资源的方式且不暴露来源 URL。
	Source resource.Source `json:"source"`
	// State is the current resource lifecycle state.
	// State 是当前资源生命周期状态。
	State resource.State `json:"state"`
	// ErrorCode is the stable non-secret ingestion failure code.
	// ErrorCode 是稳定且非秘密的接收失败码。
	ErrorCode string `json:"error_code,omitempty"`
	// CreatedAt is the initial reservation time.
	// CreatedAt 是初始保留时间。
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the latest lifecycle transition time.
	// UpdatedAt 是最近生命周期转换时间。
	UpdatedAt time.Time `json:"updated_at"`
	// ExpiresAt is the resource retention expiry when present.
	// ExpiresAt 是存在时的资源保留到期时间。
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Revision is the persisted optimistic concurrency revision.
	// Revision 是持久化的乐观并发修订号。
	Revision uint64 `json:"revision"`
}

// executionDiagnosticView is the content-free execution lifecycle contract for management diagnostics.
// executionDiagnosticView 是管理诊断专用且不含内容的执行生命周期合同。
type executionDiagnosticView struct {
	// ID is the Router-owned execution identifier.
	// ID 是 Router 所有的执行标识。
	ID string `json:"id"`
	// Status is the current durable lifecycle state.
	// Status 是当前持久化生命周期状态。
	Status execution.Status `json:"status"`
	// Operation is the safe closed operation identifier.
	// Operation 是安全的封闭操作标识。
	Operation vcp.OperationKind `json:"operation"`
	// Failure contains only the stable safe failure classification.
	// Failure 仅包含稳定且安全的失败分类。
	Failure *execution.Failure `json:"failure,omitempty"`
	// CreatedAt is the durable admission time.
	// CreatedAt 是持久化接收时间。
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the latest committed transition time.
	// UpdatedAt 是最近提交的状态转换时间。
	UpdatedAt time.Time `json:"updated_at"`
	// ExpiresAt is the execution retention expiry.
	// ExpiresAt 是执行保留到期时间。
	ExpiresAt time.Time `json:"expires_at"`
	// Revision is the persisted optimistic concurrency revision.
	// Revision 是持久化的乐观并发修订号。
	Revision uint64 `json:"revision"`
}

const (
	// managementDiagnosticLimit bounds one page without exposing an unbounded local activity history.
	// managementDiagnosticLimit 限制单页大小，避免暴露无界的本地活动历史。
	managementDiagnosticLimit = 100
)

// ResourceDiagnostics lists management-safe metadata without resource content or private ownership fields.
// ResourceDiagnostics 列出不含资源正文或私有所有权字段的管理安全元数据。
type ResourceDiagnostics interface {
	// ListDiagnostics returns newest resource metadata in stable order.
	// ListDiagnostics 以稳定顺序返回最新资源元数据。
	ListDiagnostics(context.Context, int) ([]resource.Resource, error)
}

// ExecutionDiagnostics lists management-safe lifecycle snapshots without private provider affinity.
// ExecutionDiagnostics 列出不含私有供应商亲和性的管理安全生命周期快照。
type ExecutionDiagnostics interface {
	// ListDiagnostics returns newest execution snapshots in stable order.
	// ListDiagnostics 以稳定顺序返回最新执行快照。
	ListDiagnostics(context.Context, int) ([]execution.Record, error)
}

// AccessDiagnostics exposes only bounded redacted audit entries and aggregate request metrics.
// AccessDiagnostics 仅暴露有界脱敏审计条目与聚合请求指标。
type AccessDiagnostics interface {
	// Audit returns a bounded isolated audit snapshot.
	// Audit 返回有界且隔离的审计快照。
	Audit() []access.AuditEvent
	// Metrics returns aggregate content-free request metrics.
	// Metrics 返回不含内容的聚合请求指标。
	Metrics() access.Snapshot
}

// resourceDiagnosticListResponse is the bounded management resource envelope.
// resourceDiagnosticListResponse 是有界的管理资源信封。
type resourceDiagnosticListResponse struct {
	// Resources contains metadata only; content and internal paths remain absent by JSON contract.
	// Resources 仅包含元数据；正文与内部路径按 JSON 合同保持缺省。
	Resources []resourceDiagnosticView `json:"resources"`
}

// executionDiagnosticListResponse is the bounded management execution envelope.
// executionDiagnosticListResponse 是有界的管理执行信封。
type executionDiagnosticListResponse struct {
	// Executions contains lifecycle and safe terminal results only.
	// Executions 仅包含生命周期与安全终态结果。
	Executions []executionDiagnosticView `json:"executions"`
}

// providerFileDiagnosticListResponse is a credential-scoped protected provider-file envelope.
// providerFileDiagnosticListResponse 是凭据作用域且受保护的供应商文件信封。
type providerFileDiagnosticListResponse struct {
	// Files contains provider metadata only and never downloads file content.
	// Files 仅包含供应商元数据且绝不下载文件正文。
	Files []provider.ProviderFileDiagnostic `json:"files"`
}

// providerFileDiagnosticResponse is one credential-scoped protected provider-file envelope.
// providerFileDiagnosticResponse 是一个凭据作用域且受保护的供应商文件信封。
type providerFileDiagnosticResponse struct {
	// File contains metadata only and never includes the provider temporary download URL.
	// File 仅包含元数据且绝不包含供应商临时下载地址。
	File provider.ProviderFileDiagnostic `json:"file"`
}

// accessDiagnosticResponse is the protected redacted access observability envelope.
// accessDiagnosticResponse 是受保护且脱敏的访问可观测性信封。
type accessDiagnosticResponse struct {
	// Audit contains bounded route metadata and validated non-secret principal identifiers.
	// Audit 包含有界路由元数据与经过验证的非秘密主体标识。
	Audit []access.AuditEvent `json:"audit"`
	// Metrics contains aggregate request counts and duration.
	// Metrics 包含聚合请求数与耗时。
	Metrics access.Snapshot `json:"metrics"`
}

// projectResourceDiagnostics removes content-derived and owner-private fields before serialization.
// projectResourceDiagnostics 在序列化前删除内容派生字段与所有者私有字段。
func projectResourceDiagnostics(resources []resource.Resource) []resourceDiagnosticView {
	// views is the exact safe response slice and never aliases the durable records.
	// views 是精确的安全响应切片且绝不与持久化记录共享别名。
	views := make([]resourceDiagnosticView, len(resources))
	for index, value := range resources {
		views[index] = resourceDiagnosticView{ID: value.ID, Kind: value.Kind, MIMEType: value.MIMEType, SizeBytes: value.SizeBytes, Source: value.Source, State: value.State, ErrorCode: value.ErrorCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ExpiresAt: value.ExpiresAt, Revision: value.Revision}
	}
	return views
}

// projectExecutionDiagnostics removes request, result content, and provider-private recovery state before serialization.
// projectExecutionDiagnostics 在序列化前删除请求、结果正文与供应商私有恢复状态。
func projectExecutionDiagnostics(executions []execution.Record) []executionDiagnosticView {
	// views is the exact content-free response slice and never aliases the durable records.
	// views 是精确且不含内容的响应切片，绝不与持久化记录共享别名。
	views := make([]executionDiagnosticView, len(executions))
	for index, value := range executions {
		views[index] = executionDiagnosticView{ID: value.ID, Status: value.Status, Operation: value.Operation, Failure: value.Failure, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ExpiresAt: value.ExpiresAt, Revision: value.Revision}
	}
	return views
}

// handleResourceDiagnostics returns newest resource metadata under management authentication.
// handleResourceDiagnostics 在管理认证下返回最新资源元数据。
func (s *Server) handleResourceDiagnostics(writer http.ResponseWriter, request *http.Request) {
	resources, errList := s.control.ResourceDiagnostics.ListDiagnostics(request.Context(), managementDiagnosticLimit)
	if errList != nil {
		writeControlError(writer, errList)
		return
	}
	writeJSON(writer, http.StatusOK, resourceDiagnosticListResponse{Resources: projectResourceDiagnostics(resources)})
}

// handleExecutionDiagnostics returns newest execution lifecycle snapshots under management authentication.
// handleExecutionDiagnostics 在管理认证下返回最新执行生命周期快照。
func (s *Server) handleExecutionDiagnostics(writer http.ResponseWriter, request *http.Request) {
	executions, errList := s.control.ExecutionDiagnostics.ListDiagnostics(request.Context(), managementDiagnosticLimit)
	if errList != nil {
		writeControlError(writer, errList)
		return
	}
	writeJSON(writer, http.StatusOK, executionDiagnosticListResponse{Executions: projectExecutionDiagnostics(executions)})
}

// handleAccessDiagnostics returns bounded redacted authorization audit and metrics under management authentication.
// handleAccessDiagnostics 在管理认证下返回有界脱敏授权审计与指标。
func (s *Server) handleAccessDiagnostics(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, accessDiagnosticResponse{Audit: s.control.AccessDiagnostics.Audit(), Metrics: s.control.AccessDiagnostics.Metrics()})
}

// handleProviderFileDiagnostics lists files for one explicit instance, endpoint, and credential.
// handleProviderFileDiagnostics 为一个显式实例、入口与凭据列出文件。
func (s *Server) handleProviderFileDiagnostics(writer http.ResponseWriter, request *http.Request) {
	instanceID := request.PathValue("provider_instance_id")
	credentialID := request.PathValue("credential_id")
	endpointID := request.URL.Query().Get("endpoint_id")
	if instanceID == "" || credentialID == "" || endpointID == "" {
		writeControlError(writer, vcp.ErrInvalidRequest)
		return
	}
	files, errList := s.control.ProviderFileDiagnostics.ListProviderFiles(request.Context(), instanceID, endpointID, credentialID)
	if errList != nil {
		writeControlError(writer, errList)
		return
	}
	writeJSON(writer, http.StatusOK, providerFileDiagnosticListResponse{Files: files})
}

// handleProviderFileDiagnostic retrieves one exact protected provider-file metadata record.
// handleProviderFileDiagnostic 获取一条精确且受保护的供应商文件元数据记录。
func (s *Server) handleProviderFileDiagnostic(writer http.ResponseWriter, request *http.Request) {
	instanceID := request.PathValue("provider_instance_id")
	credentialID := request.PathValue("credential_id")
	fileID := request.PathValue("file_id")
	endpointID := request.URL.Query().Get("endpoint_id")
	if instanceID == "" || credentialID == "" || fileID == "" || endpointID == "" {
		writeControlError(writer, vcp.ErrInvalidRequest)
		return
	}
	file, errGet := s.control.ProviderFileDiagnostics.GetProviderFile(request.Context(), instanceID, endpointID, credentialID, fileID)
	if errGet != nil {
		writeControlError(writer, errGet)
		return
	}
	writeJSON(writer, http.StatusOK, providerFileDiagnosticResponse{File: file})
}
