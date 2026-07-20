package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// resourceEnvelopeOverhead reserves bounded space for JSON and multipart metadata around object bytes.
	// resourceEnvelopeOverhead 为对象字节周围的 JSON 与 Multipart 元数据保留受限空间。
	resourceEnvelopeOverhead int64 = 64 << 10
)

// ResourceGateway is the complete authenticated resource boundary required by the HTTP server.
// ResourceGateway 是 HTTP 服务所需的完整已认证资源边界。
type ResourceGateway interface {
	// MaximumObjectBytes returns the decoded object ceiling used to bound request bodies.
	// MaximumObjectBytes 返回用于限制请求正文的解码对象上限。
	MaximumObjectBytes() int64
	// Create ingests one already-authorized byte stream.
	// Create 接收一个已授权字节流。
	Create(context.Context, resource.CreateInput) (resource.Resource, error)
	// ImportURL imports one validated public URL.
	// ImportURL 导入一个已校验公网 URL。
	ImportURL(context.Context, resource.URLImportInput) (resource.Resource, error)
	// ImportBase64 imports one bounded typed Base64 payload.
	// ImportBase64 导入一个受限类型化 Base64 Payload。
	ImportBase64(context.Context, resource.Base64ImportInput) (resource.Resource, error)
	// Get returns owner-scoped resource metadata.
	// Get 返回所有者作用域资源元数据。
	Get(context.Context, string, string) (resource.Resource, error)
	// OpenContent opens owner-scoped resource content.
	// OpenContent 打开所有者作用域资源内容。
	OpenContent(context.Context, string, string) (resource.Resource, io.ReadCloser, error)
	// Delete deletes one owner-scoped resource.
	// Delete 删除一个所有者作用域资源。
	Delete(context.Context, string, string) error
}

// resourceImportRequest is an exact-one-of URL/Base64 resource import envelope.
// resourceImportRequest 是 URL/Base64 精确二选一资源导入信封。
type resourceImportRequest struct {
	// Kind is checked against authoritative magic.
	// Kind 将与权威魔数核对。
	Kind vcp.MediaKind `json:"kind"`
	// DeclaredMIME is an optional strict caller assertion.
	// DeclaredMIME 是可选严格调用方断言。
	DeclaredMIME string `json:"declared_mime,omitempty"`
	// Retention selects one closed lifecycle policy.
	// Retention 选择一种封闭生命周期策略。
	Retention resource.RetentionPolicy `json:"retention"`
	// ExpiresAt is valid only for explicit expiry.
	// ExpiresAt 仅对明确过期有效。
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// URL is present only for URL import.
	// URL 仅在 URL 导入时存在。
	URL *resourceURLImport `json:"url,omitempty"`
	// Base64 is present only for Base64 import.
	// Base64 仅在 Base64 导入时存在。
	Base64 *resourceBase64Import `json:"base64,omitempty"`
}

// resourceURLImport contains one exact URL source.
// resourceURLImport 包含一个精确 URL 来源。
type resourceURLImport struct {
	// Location is the caller-authorized public HTTP(S) URL.
	// Location 是调用方授权的公网 HTTP(S) URL。
	Location string `json:"location"`
}

// resourceBase64Import contains one exact encoded byte source.
// resourceBase64Import 包含一个精确编码字节来源。
type resourceBase64Import struct {
	// Encoding selects the standard or URL-safe padded alphabet.
	// Encoding 选择标准或 URL 安全带填充字母表。
	Encoding resource.Base64Encoding `json:"encoding"`
	// Data contains the encoded bytes.
	// Data 包含编码字节。
	Data string `json:"data"`
}

// handleCreateResource accepts one bounded multipart upload.
// handleCreateResource 接收一个受限 Multipart 上传。
func (s *Server) handleCreateResource(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	mediaType, _, errMediaType := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if errMediaType != nil || mediaType != "multipart/form-data" {
		writeJSON(writer, http.StatusUnsupportedMediaType, errorResponse{Error: "multipart/form-data is required"})
		return
	}
	maximumBytes := s.control.Resources.MaximumObjectBytes()
	if maximumBytes <= 0 {
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "resource service unavailable"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumBytes+resourceEnvelopeOverhead)
	if errParse := request.ParseMultipartForm(1 << 20); errParse != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid multipart resource"})
		return
	}
	defer request.MultipartForm.RemoveAll()
	if errShape := validateMultipartShape(request); errShape != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: errShape.Error()})
		return
	}
	file, header, errFile := request.FormFile("file")
	if errFile != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "exactly one file is required"})
		return
	}
	defer file.Close()
	expiresAt, errExpiry := parseOptionalTime(request.FormValue("expires_at"))
	if errExpiry != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "expires_at must be RFC3339"})
		return
	}
	value, errCreate := s.control.Resources.Create(request.Context(), resource.CreateInput{OwnerAPIKeyID: ownerAPIKeyID, Kind: vcp.MediaKind(request.FormValue("kind")), DeclaredMIME: firstNonEmpty(request.FormValue("declared_mime"), header.Header.Get("Content-Type")), Source: resource.SourceMultipart, Retention: resource.RetentionPolicy(request.FormValue("retention")), ExpiresAt: expiresAt, Reader: file})
	if errCreate != nil {
		writeResourceError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, value)
}

// handleImportResource accepts one strict bounded URL or Base64 request.
// handleImportResource 接收一个严格受限 URL 或 Base64 请求。
func (s *Server) handleImportResource(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	maximumBytes := s.control.Resources.MaximumObjectBytes()
	maximumEncoded := ((maximumBytes + 2) / 3) * 4
	request.Body = http.MaxBytesReader(writer, request.Body, maximumEncoded+resourceEnvelopeOverhead)
	defer request.Body.Close()
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload resourceImportRequest
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid resource import request"})
		return
	}
	if errTrailing := ensureJSONEOF(decoder); errTrailing != nil || (payload.URL == nil) == (payload.Base64 == nil) {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "exactly one URL or Base64 source is required"})
		return
	}
	var value resource.Resource
	var errImport error
	if payload.URL != nil {
		value, errImport = s.control.Resources.ImportURL(request.Context(), resource.URLImportInput{OwnerAPIKeyID: ownerAPIKeyID, URL: payload.URL.Location, Kind: payload.Kind, DeclaredMIME: payload.DeclaredMIME, Retention: payload.Retention, ExpiresAt: payload.ExpiresAt})
	} else {
		value, errImport = s.control.Resources.ImportBase64(request.Context(), resource.Base64ImportInput{OwnerAPIKeyID: ownerAPIKeyID, Data: payload.Base64.Data, Encoding: payload.Base64.Encoding, Kind: payload.Kind, DeclaredMIME: payload.DeclaredMIME, Retention: payload.Retention, ExpiresAt: payload.ExpiresAt})
	}
	if errImport != nil {
		writeResourceError(writer, errImport)
		return
	}
	writeJSON(writer, http.StatusCreated, value)
}

// handleGetResource returns owner-scoped public metadata.
// handleGetResource 返回所有者作用域公开元数据。
func (s *Server) handleGetResource(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	value, errGet := s.control.Resources.Get(request.Context(), ownerAPIKeyID, request.PathValue("resource_id"))
	if errGet != nil {
		writeResourceError(writer, errGet)
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

// handleGetResourceContent streams verified bytes without content sniffing.
// handleGetResourceContent 在不进行内容嗅探的情况下流式返回已验证字节。
func (s *Server) handleGetResourceContent(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	value, content, errOpen := s.control.Resources.OpenContent(request.Context(), ownerAPIKeyID, request.PathValue("resource_id"))
	if errOpen != nil {
		writeResourceError(writer, errOpen)
		return
	}
	defer content.Close()
	writer.Header().Set("Content-Type", value.MIMEType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", value.SizeBytes))
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.Copy(writer, content)
}

// handleDeleteResource deletes one owner-scoped resource and returns no body.
// handleDeleteResource 删除一个所有者作用域资源且不返回正文。
func (s *Server) handleDeleteResource(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	if errDelete := s.control.Resources.Delete(request.Context(), ownerAPIKeyID, request.PathValue("resource_id")); errDelete != nil {
		writeResourceError(writer, errDelete)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// validateMultipartShape rejects duplicate, unknown, or missing form nodes.
// validateMultipartShape 拒绝重复、未知或缺失表单节点。
func validateMultipartShape(request *http.Request) error {
	allowedValues := map[string]bool{"kind": true, "declared_mime": true, "retention": true, "expires_at": true}
	for name, values := range request.MultipartForm.Value {
		if !allowedValues[name] || len(values) != 1 {
			return errors.New("multipart fields must be unique and recognized")
		}
	}
	if len(request.MultipartForm.File) != 1 || len(request.MultipartForm.File["file"]) != 1 || len(request.MultipartForm.Value["kind"]) != 1 || len(request.MultipartForm.Value["retention"]) != 1 {
		return errors.New("kind, retention, and exactly one file are required")
	}
	return nil
}

// parseOptionalTime parses one optional RFC3339 timestamp.
// parseOptionalTime 解析一个可选 RFC3339 时间戳。
func parseOptionalTime(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, errParse := time.Parse(time.RFC3339Nano, value)
	if errParse != nil {
		return nil, errParse
	}
	return &parsed, nil
}

// firstNonEmpty returns the first non-empty exact value.
// firstNonEmpty 返回第一个非空精确值。
func firstNonEmpty(first string, second string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	return second
}

// ensureJSONEOF rejects trailing JSON values.
// ensureJSONEOF 拒绝尾随 JSON 值。
func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if errDecode := decoder.Decode(&trailing); !errors.Is(errDecode, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

// writeResourceError maps safe resource-domain failures without exposing origin URLs or internal paths.
// writeResourceError 映射安全资源领域失败且不暴露来源 URL 或内部路径。
func writeResourceError(writer http.ResponseWriter, errValue error) {
	switch {
	case errors.Is(errValue, resource.ErrResourceNotFound), errors.Is(errValue, resource.ErrResourceAccessDenied):
		writeJSON(writer, http.StatusNotFound, errorResponse{Error: "resource not found"})
	case errors.Is(errValue, resource.ErrResourceQuotaExceeded):
		writeJSON(writer, http.StatusRequestEntityTooLarge, errorResponse{Error: "resource limit exceeded"})
	case errors.Is(errValue, resource.ErrUnsafeImportURL), errors.Is(errValue, resource.ErrInvalidResource), errors.Is(errValue, resource.ErrMIMEConflict):
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid resource request"})
	case errors.Is(errValue, resource.ErrImportResponse):
		writeJSON(writer, http.StatusBadGateway, errorResponse{Error: "resource import failed"})
	case errors.Is(errValue, resource.ErrResourceConflict):
		writeJSON(writer, http.StatusConflict, errorResponse{Error: "resource conflict"})
	default:
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "resource operation failed"})
	}
}
