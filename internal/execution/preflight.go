package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ProviderUsagePreflighter exposes an optional exact provider-native accounting path.
// ProviderUsagePreflighter 暴露一个可选的供应商原生精确计量路径。
type ProviderUsagePreflighter interface {
	// PreflightUsage counts one request without producing model output.
	// PreflightUsage 在不产生模型输出的情况下计量一条请求。
	PreflightUsage(context.Context, provider.ExecutionRequest) (provider.UsagePreflightResult, error)
}

// Preflight performs side-effect-free accounting against the same exact target resolution used by execution.
// Preflight 针对执行使用的同一精确 Target 解析执行无副作用计量。
func (s *Service) Preflight(ctx context.Context, ownerAPIKeyID string, request vcp.UsagePreflightRequest) (vcp.UsagePreflightResponse, error) {
	if strings.TrimSpace(ownerAPIKeyID) == "" {
		return vcp.UsagePreflightResponse{}, fmt.Errorf("%w: owner API key is required", ErrInvalidExecution)
	}
	if errValidate := request.Validate(); errValidate != nil {
		return vcp.UsagePreflightResponse{}, errValidate
	}
	now := s.options.Now().UTC()
	target, errTarget := s.resolveTarget(ctx, request.Execution, now, nil)
	if errTarget != nil {
		return vcp.UsagePreflightResponse{}, errTarget
	}
	binding, definition, errBinding := s.loadBinding(ctx, target)
	if errBinding != nil {
		return vcp.UsagePreflightResponse{}, errBinding
	}
	providerRequest := provider.ExecutionRequest{Binding: binding, Definition: definition, Execution: &request.Execution, LineageID: request.RequestID, Now: now}
	usage, tokenMetric, errUsage := s.preflightTokenUsage(ctx, providerRequest, request.Execution)
	if errUsage != nil {
		return vcp.UsagePreflightResponse{}, errUsage
	}
	metrics := append([]vcp.PreflightMetric{tokenMetric}, exactOperationMetrics(request.Execution)...)
	return vcp.UsagePreflightResponse{ProtocolVersion: vcp.ProtocolVersion, RequestID: request.RequestID, Target: request.Execution.Target, Usage: usage, Metrics: metrics}, nil
}

// preflightTokenUsage uses a native counter for text-only conversation requests and otherwise returns an explicit estimate or unknown value.
// preflightTokenUsage 对纯文本会话使用原生计量器，其他情况返回明确的估算值或未知值。
func (s *Service) preflightTokenUsage(ctx context.Context, request provider.ExecutionRequest, executionRequest vcp.ExecutionRequest) (vcp.UsageObservation, vcp.PreflightMetric, error) {
	if executionRequest.Operation == vcp.OperationConversationRespond && !conversationContainsMedia(*executionRequest.Payload.Conversation) {
		if preflighter, supported := s.providers.(ProviderUsagePreflighter); supported {
			result, errPreflight := preflighter.PreflightUsage(ctx, request)
			if errPreflight == nil {
				value := usageInputValue(result.Usage)
				return result.Usage, vcp.PreflightMetric{Unit: "tokens", Value: value, Accuracy: result.Accuracy, AccountingBasis: result.Usage.AccountingBasis}, nil
			}
			if !errors.Is(errPreflight, provider.ErrExecutionDriverNotFound) {
				return vcp.UsageObservation{}, vcp.PreflightMetric{}, errPreflight
			}
		}
		return estimatedConversationUsage(executionRequest)
	}
	usage := vcp.UsageObservation{Source: "unknown", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "provider_counter_unavailable", Final: true}
	metric := vcp.PreflightMetric{Unit: "tokens", Accuracy: vcp.PreflightUnknown, AccountingBasis: "provider_counter_unavailable"}
	return usage, metric, nil
}

// conversationContainsMedia reports whether native token counting would require resource materialization.
// conversationContainsMedia 报告原生 Token 计量是否需要资源物化。
func conversationContainsMedia(operation vcp.ConversationOperation) bool {
	for _, item := range operation.Context {
		for _, block := range item.Content {
			if block.Type == vcp.ContentImage || block.Type == vcp.ContentAudio || block.Type == vcp.ContentVideo || block.Type == vcp.ContentFile {
				return true
			}
		}
	}
	return false
}

// estimatedConversationUsage returns a disclosed conservative estimate from the canonical request JSON size.
// estimatedConversationUsage 根据规范请求 JSON 大小返回公开规则的保守估算。
func estimatedConversationUsage(request vcp.ExecutionRequest) (vcp.UsageObservation, vcp.PreflightMetric, error) {
	conversation, errConversation := request.ConversationRequest()
	if errConversation != nil {
		return vcp.UsageObservation{}, vcp.PreflightMetric{}, errConversation
	}
	encoded, errEncode := json.Marshal(conversation)
	if errEncode != nil {
		return vcp.UsageObservation{}, vcp.PreflightMetric{}, errEncode
	}
	estimatedTokens := int64(math.Ceil(float64(len(encoded)) / 4))
	if estimatedTokens == 0 {
		estimatedTokens = 1
	}
	usage := vcp.UsageObservation{InputTokens: &estimatedTokens, TotalTokens: &estimatedTokens, Source: "estimated", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "canonical_json_utf8_bytes_div_4", Final: true}
	value := float64(estimatedTokens)
	metric := vcp.PreflightMetric{Unit: "tokens", Value: &value, Accuracy: vcp.PreflightEstimated, AccountingBasis: usage.AccountingBasis}
	return usage, metric, nil
}

// usageInputValue returns the provider input count, falling back only to the provider total count when input is absent.
// usageInputValue 返回供应商输入计数，仅在输入缺失时退回供应商总计数。
func usageInputValue(usage vcp.UsageObservation) *float64 {
	if usage.InputTokens != nil {
		value := float64(*usage.InputTokens)
		return &value
	}
	if usage.TotalTokens != nil {
		value := float64(*usage.TotalTokens)
		return &value
	}
	return nil
}

// exactOperationMetrics derives only arithmetically exact requested units from the typed operation.
// exactOperationMetrics 仅从类型化操作推导算术上精确的请求单位。
func exactOperationMetrics(request vcp.ExecutionRequest) []vcp.PreflightMetric {
	metric := func(unit string, value float64, basis string) vcp.PreflightMetric {
		return vcp.PreflightMetric{Unit: unit, Value: &value, Accuracy: vcp.PreflightExact, AccountingBasis: basis}
	}
	switch request.Operation {
	case vcp.OperationMediaAnalyze:
		return []vcp.PreflightMetric{metric("media_items", float64(len(request.Payload.MediaAnalyze.Inputs)), "typed_input_count")}
	case vcp.OperationImageGenerate:
		operation := request.Payload.ImageGenerate
		count := operation.Count
		if count == 0 {
			count = 1
		}
		metrics := []vcp.PreflightMetric{metric("images", float64(count), "requested_output_count")}
		if operation.Width > 0 && operation.Height > 0 {
			metrics = append(metrics, metric("pixels", float64(operation.Width)*float64(operation.Height)*float64(count), "requested_width_height_count"))
		}
		return metrics
	case vcp.OperationImageEdit:
		count := request.Payload.ImageEdit.Count
		if count == 0 {
			count = 1
		}
		return []vcp.PreflightMetric{metric("images", float64(count), "requested_output_count")}
	case vcp.OperationVideoGenerate:
		operation := request.Payload.VideoGenerate
		metrics := []vcp.PreflightMetric{metric("videos", math.Max(1, float64(operation.Count)), "requested_output_count")}
		if operation.DurationSeconds > 0 {
			metrics = append(metrics, metric("video_milliseconds", operation.DurationSeconds*1000, "requested_duration"))
		}
		return metrics
	case vcp.OperationVideoExtend:
		return []vcp.PreflightMetric{metric("video_milliseconds", request.Payload.VideoExtend.AdditionalDurationSeconds*1000, "requested_extension_duration")}
	case vcp.OperationSpeechSynthesize:
		characterCount := len([]rune(request.Payload.SpeechSynthesize.Text))
		for _, segment := range request.Payload.SpeechSynthesize.Segments {
			characterCount += len([]rune(segment.Text))
		}
		return []vcp.PreflightMetric{metric("characters", float64(characterCount), "typed_text_rune_count")}
	case vcp.OperationEmbeddingCreate:
		return []vcp.PreflightMetric{metric("embedding_inputs", float64(len(request.Payload.EmbeddingCreate.Inputs)), "typed_input_count")}
	case vcp.OperationRerankDocuments:
		return []vcp.PreflightMetric{metric("rerank_documents", float64(len(request.Payload.RerankDocuments.Candidates)), "typed_candidate_count")}
	case vcp.OperationSearchWeb:
		return []vcp.PreflightMetric{metric("search_queries", 1, "single_typed_query")}
	case vcp.OperationMusicGenerate:
		if request.Payload.MusicGenerate.DurationSeconds > 0 {
			return []vcp.PreflightMetric{metric("audio_milliseconds", request.Payload.MusicGenerate.DurationSeconds*1000, "requested_duration")}
		}
	}
	return nil
}
