package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// InputPlanService creates immutable owner-scoped conditional media plans.
// InputPlanService 创建不可变所有者作用域条件媒体方案。
type InputPlanService interface {
	// Create resolves and persists one exact input plan.
	// Create 解析并持久化一个精确输入方案。
	CreateInputPlan(context.Context, inputplan.Request) (inputplan.Plan, error)
}

// handleCreateInputPlan creates one bounded strict conditional-input plan.
// handleCreateInputPlan 创建一个受限严格条件输入方案。
func (s *Server) handleCreateInputPlan(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	payload, errDecode := decodeControlJSON[inputplan.Request](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid input plan request"})
		return
	}
	payload.OwnerAPIKeyID = ownerAPIKeyID
	plan, errCreate := s.control.InputPlans.CreateInputPlan(request.Context(), payload)
	if errCreate != nil {
		writeInputPlanError(writer, errCreate)
		return
	}
	writeJSON(writer, http.StatusCreated, plan)
}

// writeInputPlanError maps planning failures without exposing provider candidates or resource ownership.
// writeInputPlanError 映射规划失败且不暴露供应商候选或资源归属。
func writeInputPlanError(writer http.ResponseWriter, errValue error) {
	switch {
	case errors.Is(errValue, inputplan.ErrInvalidPlan):
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid input plan request"})
	case errors.Is(errValue, inputplan.ErrInputRejected):
		writeJSON(writer, http.StatusUnprocessableEntity, errorResponse{Error: "input rejected"})
	case errors.Is(errValue, resource.ErrResourceNotFound), errors.Is(errValue, resource.ErrResourceAccessDenied):
		writeJSON(writer, http.StatusNotFound, errorResponse{Error: "resource not found"})
	case errors.Is(errValue, resolve.ErrNoEligibleTarget), errors.Is(errValue, resolve.ErrModelNotFound), errors.Is(errValue, resolve.ErrProfileNotFound):
		writeJSON(writer, http.StatusUnprocessableEntity, errorResponse{Error: "no eligible input target"})
	default:
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "input planning failed"})
	}
}
