package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// managementExtractTestOwnerID isolates durable extraction diagnostics from real call-plane owners.
	// managementExtractTestOwnerID 将持久化内容提取诊断与真实调用面所有者隔离。
	managementExtractTestOwnerID = "api_management_extract_test"
)

// managementExtractTestRequest selects one exact extraction profile and one bounded typed request.
// managementExtractTestRequest 选择一个精确提取规格及一个有界类型化请求。
type managementExtractTestRequest struct {
	// ServiceOfferingID fixes one provider channel implementation.
	// ServiceOfferingID 固定一个供应商通道实现。
	ServiceOfferingID string `json:"service_offering_id"`
	// ExecutionProfileID fixes one executable extraction capability shape.
	// ExecutionProfileID 固定一个可执行内容提取能力形态。
	ExecutionProfileID string `json:"execution_profile_id"`
	// URLs contains explicit HTTPS resources entered by the operator.
	// URLs 包含操作员输入的明确 HTTPS 资源。
	URLs []string `json:"urls"`
	// Query optionally enables relevance-ranked chunks.
	// Query 可选地启用按相关性排序的片段。
	Query string `json:"query,omitempty"`
	// ChunksPerSource limits relevance chunks and requires Query.
	// ChunksPerSource 限制相关片段数量且要求同时提供 Query。
	ChunksPerSource *int `json:"chunks_per_source,omitempty"`
	// Depth selects one profile-authored extraction depth.
	// Depth 选择一个规格声明的提取深度。
	Depth vcp.WebExtractDepth `json:"depth"`
	// Format selects one profile-authored content format.
	// Format 选择一个规格声明的内容格式。
	Format vcp.WebExtractFormat `json:"format"`
	// IncludeImages requests extracted image URLs.
	// IncludeImages 请求提取图片 URL。
	IncludeImages bool `json:"include_images"`
	// IncludeFavicon requests the page favicon URL.
	// IncludeFavicon 请求页面站点图标 URL。
	IncludeFavicon bool `json:"include_favicon"`
	// TimeoutSeconds optionally bounds provider extraction time.
	// TimeoutSeconds 可选地限制供应商提取时间。
	TimeoutSeconds *float64 `json:"timeout_seconds,omitempty"`
}

// managementExtractTestResponse returns the real provider result and its durable diagnostic execution identifier.
// managementExtractTestResponse 返回真实供应商结果及其持久化诊断执行标识。
type managementExtractTestResponse struct {
	// ExecutionID identifies the diagnostic execution without exposing a credential.
	// ExecutionID 标识诊断执行且不暴露凭据。
	ExecutionID string `json:"execution_id"`
	// Extract contains the unified provider extraction response.
	// Extract 包含统一的供应商内容提取响应。
	Extract vcp.WebExtractResponse `json:"extract"`
}

// handleExtractServiceTest executes one management-authorized request against an exact extraction profile.
// handleExtractServiceTest 针对精确内容提取规格执行一个经管理授权的请求。
func (s *Server) handleExtractServiceTest(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[managementExtractTestRequest](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid extraction test request"})
		return
	}
	providerInstanceID := request.PathValue("provider_instance_id")
	providerServiceID := request.PathValue("provider_service_id")
	providerCatalog, errCatalog := s.control.Query.GetCatalog(request.Context(), providerInstanceID)
	if errCatalog != nil {
		writeControlError(writer, errCatalog)
		return
	}
	capabilities, errProfile := extractTestCapabilities(providerCatalog, providerServiceID, payload.ServiceOfferingID, payload.ExecutionProfileID)
	if errProfile != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: errProfile.Error()})
		return
	}
	operation := vcp.WebExtractOperation{URLs: append([]string(nil), payload.URLs...), Query: payload.Query, ChunksPerSource: payload.ChunksPerSource, Depth: payload.Depth, Format: payload.Format, IncludeImages: payload.IncludeImages, IncludeFavicon: payload.IncludeFavicon, TimeoutSeconds: payload.TimeoutSeconds}
	if errOperation := operation.Validate(); errOperation != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: errOperation.Error()})
		return
	}
	if errCapability := validateExtractTestPolicy(operation, capabilities); errCapability != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: errCapability.Error()})
		return
	}
	executionRequest := vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       fmt.Sprintf("management-extract-test-%d", time.Now().UTC().UnixNano()),
		Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{
			ProviderInstanceID: providerInstanceID,
			ProviderServiceID:  providerServiceID,
			ServiceOfferingID:  payload.ServiceOfferingID,
			ExecutionProfileID: payload.ExecutionProfileID,
		}},
		Operation: vcp.OperationWebExtract,
		Payload:   vcp.OperationPayload{WebExtract: &operation},
	}
	record, _, errExecute := s.control.Executions.Create(request.Context(), managementExtractTestOwnerID, executionRequest)
	if errExecute != nil {
		writeExecutionError(writer, errExecute)
		return
	}
	if record.Status != execution.StatusSucceeded || record.Result == nil || record.Result.Extract == nil {
		failureCode := "extract_test_incomplete"
		if record.Failure != nil && strings.TrimSpace(record.Failure.Code) != "" {
			failureCode = record.Failure.Code
		}
		writeJSON(writer, http.StatusBadGateway, errorResponse{Error: failureCode})
		return
	}
	writeJSON(writer, http.StatusOK, managementExtractTestResponse{ExecutionID: record.ID, Extract: *record.Result.Extract})
}

// extractTestCapabilities returns the sole typed contract for an exact enabled extraction profile.
// extractTestCapabilities 返回一个精确已启用内容提取规格的唯一类型化合同。
func extractTestCapabilities(providerCatalog management.CatalogView, providerServiceID string, offeringID string, profileID string) (catalog.WebExtractCapabilities, error) {
	for _, service := range providerCatalog.Services {
		if service.ID != providerServiceID {
			continue
		}
		if !service.Enabled || service.Operation != vcp.OperationWebExtract {
			return catalog.WebExtractCapabilities{}, fmt.Errorf("selected service is not an enabled web-extraction service")
		}
		for _, offering := range service.Offerings {
			if offering.ID != offeringID {
				continue
			}
			for _, profile := range offering.Profiles {
				if profile.ID != profileID {
					continue
				}
				if profile.Operation != vcp.OperationWebExtract || profile.Capabilities.WebExtract == nil {
					return catalog.WebExtractCapabilities{}, fmt.Errorf("selected profile has no typed web-extraction contract")
				}
				if profile.Pool == nil || profile.Pool.ReadyCredentials == 0 {
					return catalog.WebExtractCapabilities{}, fmt.Errorf("selected extraction profile has no ready credential")
				}
				return *profile.Capabilities.WebExtract, nil
			}
			return catalog.WebExtractCapabilities{}, fmt.Errorf("extraction execution profile was not found")
		}
		return catalog.WebExtractCapabilities{}, fmt.Errorf("extraction service offering was not found")
	}
	return catalog.WebExtractCapabilities{}, fmt.Errorf("extraction service was not found")
}

// validateExtractTestPolicy enforces only capabilities declared by the exact selected profile.
// validateExtractTestPolicy 仅允许精确所选规格声明的能力。
func validateExtractTestPolicy(operation vcp.WebExtractOperation, capabilities catalog.WebExtractCapabilities) error {
	if len(operation.URLs) > capabilities.MaxURLs || !containsExtractDepth(capabilities.Depths, operation.Depth) || !containsExtractFormat(capabilities.Formats, operation.Format) {
		return fmt.Errorf("selected extraction profile does not support the requested URL count, depth, or format")
	}
	if operation.Query != "" && !capabilities.QueryRelevance {
		return fmt.Errorf("selected extraction profile does not support query relevance")
	}
	if operation.ChunksPerSource != nil && (*operation.ChunksPerSource < capabilities.MinimumChunksPerSource || *operation.ChunksPerSource > capabilities.MaximumChunksPerSource) {
		return fmt.Errorf("selected extraction profile does not support the requested chunk count")
	}
	if operation.IncludeImages && !capabilities.IncludeImages || operation.IncludeFavicon && !capabilities.IncludeFavicon {
		return fmt.Errorf("selected extraction profile does not support requested media metadata")
	}
	if operation.TimeoutSeconds != nil && (*operation.TimeoutSeconds < capabilities.MinimumTimeoutSeconds || *operation.TimeoutSeconds > capabilities.MaximumTimeoutSeconds) {
		return fmt.Errorf("selected extraction profile does not support the requested timeout")
	}
	return nil
}

// containsExtractDepth reports exact membership in one code-owned profile list.
// containsExtractDepth 报告一个代码拥有规格列表中的精确提取深度成员关系。
func containsExtractDepth(depths []vcp.WebExtractDepth, selected vcp.WebExtractDepth) bool {
	for _, depth := range depths {
		if depth == selected {
			return true
		}
	}
	return false
}

// containsExtractFormat reports exact membership in one code-owned profile list.
// containsExtractFormat 报告一个代码拥有规格列表中的精确内容格式成员关系。
func containsExtractFormat(formats []vcp.WebExtractFormat, selected vcp.WebExtractFormat) bool {
	for _, format := range formats {
		if format == selected {
			return true
		}
	}
	return false
}
