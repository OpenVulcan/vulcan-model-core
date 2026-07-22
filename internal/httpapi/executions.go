package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ExecutionService owns durable owner-scoped execution lifecycle operations.
// ExecutionService 拥有持久化所有者作用域执行生命周期操作。
type ExecutionService interface {
	// Create admits and executes one VCP request or returns an idempotent replay.
	// Create 接收并执行一个 VCP 请求或返回幂等重放。
	Create(context.Context, string, vcp.ExecutionRequest) (execution.Record, bool, error)
	// Get returns one owner-scoped execution.
	// Get 返回一个所有者作用域执行。
	Get(context.Context, string, string) (execution.Record, error)
	// Events returns durable events after one sequence.
	// Events 返回指定序号之后的持久化事件。
	Events(context.Context, string, string, uint64) ([]execution.Event, error)
	// Cancel requests one deterministic cancellation.
	// Cancel 请求一次确定性取消。
	Cancel(context.Context, string, string) (execution.Record, error)
}

// executionEventWaiter is the optional shared-store event distribution extension implemented by the production service.
// executionEventWaiter 是生产服务实现的可选共享存储事件分发扩展。
type executionEventWaiter interface {
	// WaitEvents waits for one durable event batch without making notification delivery authoritative.
	// WaitEvents 等待一批持久事件，且不将通知传递作为权威事实。
	WaitEvents(context.Context, string, string, uint64, time.Duration) ([]execution.Event, error)
}

// UsagePreflightService owns side-effect-free accounting for one exact call-plane target.
// UsagePreflightService 拥有一个精确调用面 Target 的无副作用计量。
type UsagePreflightService interface {
	// Preflight returns provider-exact, Router-estimated, or explicitly unknown usage facts.
	// Preflight 返回供应商精确、Router 估算或明确未知的用量事实。
	Preflight(context.Context, string, vcp.UsagePreflightRequest) (vcp.UsagePreflightResponse, error)
}

// executionCreateResponse reports whether this response is an exact idempotent replay.
// executionCreateResponse 报告此响应是否为精确幂等重放。
type executionCreateResponse struct {
	// Execution contains the safe durable record projection.
	// Execution 包含安全持久化记录投影。
	Execution execution.Record `json:"execution"`
	// IdempotentReplay reports an existing exact request.
	// IdempotentReplay 表示返回了已有精确请求。
	IdempotentReplay bool `json:"idempotent_replay"`
}

// handleCreateExecution creates and possibly completes one durable execution.
// handleCreateExecution 创建并可能完成一个持久化执行。
func (s *Server) handleCreateExecution(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	payload, errDecode := decodeControlJSON[vcp.ExecutionRequest](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid execution request"})
		return
	}
	record, replayed, errCreate := s.control.Executions.Create(request.Context(), ownerAPIKeyID, payload)
	if errCreate != nil {
		writeExecutionError(writer, errCreate)
		return
	}
	statusCode := http.StatusCreated
	if replayed {
		statusCode = http.StatusOK
	} else if !record.Status.IsTerminal() {
		statusCode = http.StatusAccepted
	}
	writeJSON(writer, statusCode, executionCreateResponse{Execution: record, IdempotentReplay: replayed})
}

// handleUsagePreflight returns side-effect-free usage facts without creating an execution record.
// handleUsagePreflight 返回无副作用用量事实且不创建执行记录。
func (s *Server) handleUsagePreflight(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	payload, errDecode := decodeControlJSON[vcp.UsagePreflightRequest](writer, request)
	if errDecode != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid usage preflight request"})
		return
	}
	response, errPreflight := s.control.Preflight.Preflight(request.Context(), ownerAPIKeyID, payload)
	if errPreflight != nil {
		writeExecutionError(writer, errPreflight)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

// handleGetExecution returns one owner-scoped safe execution view.
// handleGetExecution 返回一个所有者作用域安全执行视图。
func (s *Server) handleGetExecution(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	record, errGet := s.control.Executions.Get(request.Context(), ownerAPIKeyID, request.PathValue("execution_id"))
	if errGet != nil {
		writeExecutionError(writer, errGet)
		return
	}
	writeJSON(writer, http.StatusOK, record)
}

// handleCancelExecution applies one deterministic owner-scoped cancellation.
// handleCancelExecution 应用一次确定性所有者作用域取消。
func (s *Server) handleCancelExecution(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	record, errCancel := s.control.Executions.Cancel(request.Context(), ownerAPIKeyID, request.PathValue("execution_id"))
	if errCancel != nil {
		writeExecutionError(writer, errCancel)
		return
	}
	writeJSON(writer, http.StatusOK, record)
}

// handleExecutionEvents replays ordered events and follows non-terminal executions through SSE.
// handleExecutionEvents 通过 SSE 回放有序事件并跟随非终态执行。
func (s *Server) handleExecutionEvents(writer http.ResponseWriter, request *http.Request) {
	ownerAPIKeyID, ok := authenticatedAPIKeyID(request.Context())
	if !ok {
		writeUnauthorized(writer)
		return
	}
	executionID := request.PathValue("execution_id")
	afterSequence, errSequence := parseLastEventID(executionID, request.Header.Get("Last-Event-ID"))
	if errSequence != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid last event id"})
		return
	}
	record, errGet := s.control.Executions.Get(request.Context(), ownerAPIKeyID, executionID)
	if errGet != nil {
		writeExecutionError(writer, errGet)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "event streaming unavailable"})
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache, no-transform")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	// heartbeat limits intermediary idle time without inventing semantic progress.
	// heartbeat 在不虚构语义进度的情况下限制中间层空闲时间。
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	// poll observes only the durable local event log and never polls an upstream candidate.
	// poll 仅观察持久化本地事件日志且绝不轮询上游候选。
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	for {
		events, errEvents := s.control.Executions.Events(request.Context(), ownerAPIKeyID, executionID, afterSequence)
		if errEvents != nil {
			return
		}
		for _, event := range events {
			if errWrite := writeSSEExecutionEvent(writer, event); errWrite != nil {
				return
			}
			afterSequence = event.Sequence
		}
		if len(events) > 0 {
			flusher.Flush()
		}
		record, errGet = s.control.Executions.Get(request.Context(), ownerAPIKeyID, executionID)
		if errGet != nil || record.Status.IsTerminal() {
			return
		}
		if waiter, distributed := s.control.Executions.(executionEventWaiter); distributed {
			waitedEvents, errWait := waiter.WaitEvents(request.Context(), ownerAPIKeyID, executionID, afterSequence, 15*time.Second)
			if errWait != nil {
				return
			}
			for _, event := range waitedEvents {
				if errWrite := writeSSEExecutionEvent(writer, event); errWrite != nil {
					return
				}
				afterSequence = event.Sequence
			}
			if len(waitedEvents) > 0 {
				flusher.Flush()
			} else {
				if _, errWrite := writer.Write([]byte(": keep-alive\n\n")); errWrite != nil {
					return
				}
				flusher.Flush()
			}
			continue
		}
		select {
		case <-request.Context().Done():
			return
		case <-poll.C:
		case <-heartbeat.C:
			if _, errWrite := writer.Write([]byte(": keep-alive\n\n")); errWrite != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSEExecutionEvent writes one JSON event with stable id and semantic event name.
// writeSSEExecutionEvent 写入一个具有稳定 ID 与语义事件名的 JSON 事件。
func writeSSEExecutionEvent(writer http.ResponseWriter, event execution.Event) error {
	payload, errEncode := json.Marshal(event)
	if errEncode != nil {
		return errEncode
	}
	_, errWrite := fmt.Fprintf(writer, "id: %s\nevent: %s\ndata: %s\n\n", event.EventID, event.Type, payload)
	return errWrite
}

// parseLastEventID validates that replay cannot cross execution identities.
// parseLastEventID 校验回放不能跨越执行身份。
func parseLastEventID(executionID string, eventID string) (uint64, error) {
	if eventID == "" {
		return 0, nil
	}
	if len(executionID) <= 4 {
		return 0, execution.ErrInvalidExecution
	}
	prefix := "evt_" + executionID[4:] + "_"
	if !strings.HasPrefix(eventID, prefix) {
		return 0, execution.ErrInvalidExecution
	}
	sequence, errParse := strconv.ParseUint(strings.TrimPrefix(eventID, prefix), 10, 64)
	if errParse != nil || sequence == 0 {
		return 0, execution.ErrInvalidExecution
	}
	return sequence, nil
}

// writeExecutionError maps failures without exposing target candidates, prompts, or upstream identifiers.
// writeExecutionError 映射错误且不暴露 Target 候选、提示词或上游标识。
func writeExecutionError(writer http.ResponseWriter, errValue error) {
	switch {
	case errors.Is(errValue, execution.ErrExecutionNotFound):
		writeJSON(writer, http.StatusNotFound, errorResponse{Error: "execution not found"})
	case errors.Is(errValue, execution.ErrIdempotencyConflict):
		writeJSON(writer, http.StatusConflict, errorResponse{Error: "idempotency conflict"})
	case errors.Is(errValue, execution.ErrRevisionConflict):
		writeJSON(writer, http.StatusConflict, errorResponse{Error: "execution changed"})
	case errors.Is(errValue, inputplan.ErrCapabilityChanged):
		writeJSON(writer, http.StatusConflict, errorResponse{Error: "capability changed"})
	case errors.Is(errValue, resolve.ErrNoEligibleTarget), errors.Is(errValue, resolve.ErrModelNotFound), errors.Is(errValue, resolve.ErrServiceNotFound), errors.Is(errValue, resolve.ErrProfileNotFound):
		writeJSON(writer, http.StatusUnprocessableEntity, errorResponse{Error: "no eligible execution target"})
	case errors.Is(errValue, vcp.ErrInvalidRequest), errors.Is(errValue, execution.ErrInvalidExecution):
		writeJSON(writer, http.StatusBadRequest, errorResponse{Error: "invalid execution request"})
	default:
		writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "execution service failed"})
	}
}
