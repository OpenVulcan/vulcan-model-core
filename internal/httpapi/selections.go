package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ExecutionSelector chooses one safe exact model target inside a caller-fixed provider instance.
// ExecutionSelector 在调用方固定的供应商实例内选择一个安全精确模型 Target。
type ExecutionSelector interface {
	// Select returns an exact model selection without exposing credential or endpoint identity.
	// Select 返回一个不暴露凭据或入口身份的精确模型选择。
	Select(context.Context, vcp.ExecutionSelectionRequest, time.Time) (vcp.ExecutionSelection, error)
}

// handleCreateExecutionSelection resolves one capability-driven target before immutable execution admission.
// handleCreateExecutionSelection 在不可变执行接收前解析一个能力驱动 Target。
func (s *Server) handleCreateExecutionSelection(writer http.ResponseWriter, request *http.Request) {
	if _, ok := authenticatedAPIKeyID(request.Context()); !ok {
		writeUnauthorized(writer)
		return
	}
	selector, ok := s.control.Targets.(ExecutionSelector)
	if !ok {
		writeJSON(writer, http.StatusNotImplemented, errorResponse{Error: "execution selection unavailable"})
		return
	}
	payload, errDecode := decodeControlJSON[vcp.ExecutionSelectionRequest](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid execution selection request"})
		return
	}
	selection, errSelect := selector.Select(request.Context(), payload, time.Now().UTC())
	if errSelect != nil {
		writeExecutionSelectionError(writer, errSelect)
		return
	}
	writeJSON(writer, http.StatusOK, selection)
}

// writeExecutionSelectionError maps selection failure without disclosing rejected candidates.
// writeExecutionSelectionError 映射选择失败且不披露被拒绝候选项。
func writeExecutionSelectionError(writer http.ResponseWriter, errValue error) {
	switch {
	case errors.Is(errValue, vcp.ErrInvalidRequest):
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid execution selection request"})
	case errors.Is(errValue, resolve.ErrNoEligibleTarget), errors.Is(errValue, resolve.ErrModelNotFound), errors.Is(errValue, resolve.ErrProfileNotFound):
		writeJSON(writer, http.StatusUnprocessableEntity, errorResponse{Error: "no eligible execution target"})
	default:
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "execution selection failed"})
	}
}
