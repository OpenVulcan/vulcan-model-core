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
	// managementSearchTestOwnerID isolates durable management tests from real call-plane API-key owners.
	// managementSearchTestOwnerID 将持久化管理测试与真实调用面 API Key 所有者隔离。
	managementSearchTestOwnerID = "api_management_search_test"
	// maximumManagementSearchQueryRunes bounds an operator-authored diagnostic query before provider execution.
	// maximumManagementSearchQueryRunes 在供应商执行前限制操作员编写的诊断查询。
	maximumManagementSearchQueryRunes = 8192
)

// managementSearchTestRequest selects one exact service profile and one declared search response contract.
// managementSearchTestRequest 选择一个精确服务规格及一个已声明搜索响应合同。
type managementSearchTestRequest struct {
	// Query is the exact operator-entered search text.
	// Query 是操作员输入的精确搜索文本。
	Query string `json:"query"`
	// ServiceOfferingID fixes one provider channel implementation.
	// ServiceOfferingID 固定一个供应商通道实现。
	ServiceOfferingID string `json:"service_offering_id"`
	// ExecutionProfileID fixes one executable search capability shape.
	// ExecutionProfileID 固定一个可执行搜索能力形态。
	ExecutionProfileID string `json:"execution_profile_id"`
	// OutputMode must be declared by the selected profile.
	// OutputMode 必须由所选规格声明。
	OutputMode vcp.WebSearchOutputMode `json:"output_mode"`
	// EvidenceRequirement must be declared by the selected profile.
	// EvidenceRequirement 必须由所选规格声明。
	EvidenceRequirement vcp.SearchEvidenceRequirement `json:"evidence_requirement"`
}

// managementSearchTestResponse returns the real provider result and its durable diagnostic execution identifier.
// managementSearchTestResponse 返回真实供应商结果及其持久化诊断执行标识。
type managementSearchTestResponse struct {
	// ExecutionID identifies the diagnostic execution without exposing a credential.
	// ExecutionID 标识诊断执行且不暴露凭据。
	ExecutionID string `json:"execution_id"`
	// Search contains the unified provider-confirmed search response.
	// Search 包含统一的供应商确认搜索响应。
	Search vcp.WebSearchResponse `json:"search"`
}

// handleSearchServiceTest executes one management-authorized query against an exact configured search profile.
// handleSearchServiceTest 针对精确的已配置搜索规格执行一个经管理授权的查询。
func (s *Server) handleSearchServiceTest(writer http.ResponseWriter, request *http.Request) {
	payload, errDecode := decodeControlJSON[managementSearchTestRequest](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid search test request"})
		return
	}
	payload.Query = strings.TrimSpace(payload.Query)
	if payload.Query == "" || len([]rune(payload.Query)) > maximumManagementSearchQueryRunes {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "search query is empty or too long"})
		return
	}
	providerInstanceID := request.PathValue("provider_instance_id")
	providerServiceID := request.PathValue("provider_service_id")
	providerCatalog, errCatalog := s.control.Query.GetCatalog(request.Context(), providerInstanceID)
	if errCatalog != nil {
		writeControlError(writer, errCatalog)
		return
	}
	capabilities, errProfile := searchTestCapabilities(providerCatalog, providerServiceID, payload.ServiceOfferingID, payload.ExecutionProfileID)
	if errProfile != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: errProfile.Error()})
		return
	}
	if !containsSearchOutputMode(capabilities.OutputModes, payload.OutputMode) || !containsSearchEvidenceRequirement(capabilities.EvidenceRequirements, payload.EvidenceRequirement) {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "search test policy is not supported by the selected profile"})
		return
	}
	executionRequest := vcp.ExecutionRequest{
		ProtocolVersion: vcp.ProtocolVersion,
		RequestID:       fmt.Sprintf("management-search-test-%d", time.Now().UTC().UnixNano()),
		Target: vcp.TargetSelection{Service: &vcp.ServiceSelection{
			ProviderInstanceID: providerInstanceID,
			ProviderServiceID:  providerServiceID,
			ServiceOfferingID:  payload.ServiceOfferingID,
			ExecutionProfileID: payload.ExecutionProfileID,
		}},
		Operation: vcp.OperationSearchWeb,
		Payload: vcp.OperationPayload{SearchWeb: &vcp.WebSearchOperation{
			Query:               payload.Query,
			OutputMode:          payload.OutputMode,
			EvidenceRequirement: payload.EvidenceRequirement,
		}},
	}
	record, _, errExecute := s.control.Executions.Create(request.Context(), managementSearchTestOwnerID, executionRequest)
	if errExecute != nil {
		writeExecutionError(writer, errExecute)
		return
	}
	if record.Status != execution.StatusSucceeded || record.Result == nil || record.Result.Search == nil {
		failureCode := "search_test_incomplete"
		if record.Failure != nil && strings.TrimSpace(record.Failure.Code) != "" {
			failureCode = record.Failure.Code
		}
		writeJSON(writer, http.StatusBadGateway, errorResponse{Error: failureCode})
		return
	}
	writeJSON(writer, http.StatusOK, managementSearchTestResponse{ExecutionID: record.ID, Search: *record.Result.Search})
}

// searchTestCapabilities returns the sole typed contract for an exact enabled search profile.
// searchTestCapabilities 返回一个精确已启用搜索规格的唯一类型化合同。
func searchTestCapabilities(providerCatalog management.CatalogView, providerServiceID string, offeringID string, profileID string) (catalog.WebSearchCapabilities, error) {
	for _, service := range providerCatalog.Services {
		if service.ID != providerServiceID {
			continue
		}
		if !service.Enabled || service.Operation != vcp.OperationSearchWeb {
			return catalog.WebSearchCapabilities{}, fmt.Errorf("selected service is not an enabled web-search service")
		}
		for _, offering := range service.Offerings {
			if offering.ID != offeringID {
				continue
			}
			for _, profile := range offering.Profiles {
				if profile.ID != profileID {
					continue
				}
				if profile.Operation != vcp.OperationSearchWeb || profile.Capabilities.WebSearch == nil {
					return catalog.WebSearchCapabilities{}, fmt.Errorf("selected profile has no typed web-search contract")
				}
				if profile.Pool == nil || profile.Pool.ReadyCredentials == 0 {
					return catalog.WebSearchCapabilities{}, fmt.Errorf("selected search profile has no ready credential")
				}
				return *profile.Capabilities.WebSearch, nil
			}
			return catalog.WebSearchCapabilities{}, fmt.Errorf("search execution profile was not found")
		}
		return catalog.WebSearchCapabilities{}, fmt.Errorf("search service offering was not found")
	}
	return catalog.WebSearchCapabilities{}, fmt.Errorf("search service was not found")
}

// containsSearchOutputMode reports exact membership in one code-owned profile list.
// containsSearchOutputMode 报告一个代码拥有规格列表中的精确成员关系。
func containsSearchOutputMode(modes []vcp.WebSearchOutputMode, selected vcp.WebSearchOutputMode) bool {
	for _, mode := range modes {
		if mode == selected {
			return true
		}
	}
	return false
}

// containsSearchEvidenceRequirement reports exact membership in one code-owned profile list.
// containsSearchEvidenceRequirement 报告一个代码拥有规格列表中的精确成员关系。
func containsSearchEvidenceRequirement(requirements []vcp.SearchEvidenceRequirement, selected vcp.SearchEvidenceRequirement) bool {
	for _, requirement := range requirements {
		if requirement == selected {
			return true
		}
	}
	return false
}
