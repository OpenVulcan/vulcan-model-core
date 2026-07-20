package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	aistudio "github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidMediaAnalyzeDriver reports an incomplete Google media-analysis driver.
	// ErrInvalidMediaAnalyzeDriver 表示不完整的 Google 媒体分析 Driver。
	ErrInvalidMediaAnalyzeDriver = errors.New("invalid Google media analysis driver")
	// ErrUnsupportedMediaAnalyzeInput reports a task or materialization outside the evidence-closed Profile.
	// ErrUnsupportedMediaAnalyzeInput 表示任务或物化结果超出证据封闭的 Profile。
	ErrUnsupportedMediaAnalyzeInput = errors.New("unsupported Google media analysis input")
)

const (
	// MediaAnalyzeActionBindingID identifies the dedicated Google media-analysis action.
	// MediaAnalyzeActionBindingID 标识专用 Google 媒体分析动作。
	MediaAnalyzeActionBindingID = "action_google_aistudio_media_analyze"
	// MediaAnalyzeProtocolProfileID identifies the Router-versioned Gemini media-analysis projection.
	// MediaAnalyzeProtocolProfileID 标识由 Router 版本化的 Gemini 媒体分析投影。
	MediaAnalyzeProtocolProfileID = "google.aistudio.media_analyze.v1beta"
	// MediaAnalyzePromptRevision freezes the Router-owned task instructions used by this action.
	// MediaAnalyzePromptRevision 固定此动作使用的 Router 所有任务指令。
	MediaAnalyzePromptRevision uint64 = 1
)

// MediaAnalyzeActionDriver executes one synchronous Gemini media-analysis request.
// MediaAnalyzeActionDriver 执行一条同步 Gemini 媒体分析请求。
type MediaAnalyzeActionDriver struct {
	// definitionID is the sole owning provider definition.
	// definitionID 是唯一拥有的供应商 Definition。
	definitionID string
	// client owns API-key-authenticated target transport.
	// client 负责使用 API Key 认证的 Target 传输。
	client *transport.Client
}

// NewMediaAnalyzeDriver creates an immutable Google AI Studio media-analysis driver.
// NewMediaAnalyzeDriver 创建不可变的 Google AI Studio 媒体分析 Driver。
func NewMediaAnalyzeDriver(definitionID string, client *transport.Client) (*MediaAnalyzeActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidMediaAnalyzeDriver
	}
	return &MediaAnalyzeActionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的 Definition。
func (d *MediaAnalyzeActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact Google media-analysis action.
// ActionBindingID 返回精确的 Google 媒体分析动作。
func (d *MediaAnalyzeActionDriver) ActionBindingID() string {
	return MediaAnalyzeActionBindingID
}

// Execute projects an explicit media task and exact accepted materializations into Gemini generateContent.
// Execute 将明确媒体任务和精确已接受物化结果投影到 Gemini generateContent。
func (d *MediaAnalyzeActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidMediaAnalyzeDriver
	}
	action, errAction := execution.ValidateForAction(MediaAnalyzeActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationMediaAnalyze || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Google media analysis is synchronous only", ErrUnsupportedMediaAnalyzeInput)
	}
	operation := *execution.Execution.Payload.MediaAnalyze
	instruction, errInstruction := googleMediaAnalyzeInstruction(operation)
	if errInstruction != nil {
		return provider.ExecutionResult{}, errInstruction
	}
	parts, errParts := googleMediaAnalyzeParts(instruction, operation.Inputs, execution.MaterializedInputs)
	if errParts != nil {
		return provider.ExecutionResult{}, errParts
	}
	// upstream contains only the versioned task instruction and accepted media carriers.
	// upstream 仅包含版本化任务指令和已接受媒体载体。
	upstream := aistudio.GenerateContentRequest{Contents: []aistudio.Content{{Role: "user", Parts: parts}}}
	encoded, errMarshal := json.Marshal(upstream)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidMediaAnalyzeDriver, errMarshal)
	}
	path, errPath := aiStudioEndpointPath(execution.Binding.Target.UpstreamModelID, "generateContent", false)
	if errPath != nil {
		return provider.ExecutionResult{}, errPath
	}
	// projectionID binds the analysis report to the immutable target and execution lineage.
	// projectionID 将分析报告绑定到不可变 Target 与执行谱系。
	projectionID := vcp.DeriveID("prj", execution.Execution.RequestID, execution.LineageID, execution.Binding.Target.ProviderInstanceID, execution.Binding.Target.ChannelID, execution.Binding.Target.EndpointID, execution.Binding.Target.CredentialID, execution.Binding.Target.UpstreamModelID)
	// projected preserves client-safe route and prompt-revision facts for response reduction.
	// projected 保留供响应归并使用的客户端安全路由和提示词修订事实。
	projected := aistudio.ProjectedRequest{Upstream: upstream, Report: vcp.ExecutionReport{
		ResponseID:        vcp.DeriveID("resp", execution.Execution.RequestID),
		ExecutionID:       vcp.DeriveID("exec", projectionID),
		CatalogRevision:   execution.Binding.Target.CatalogRevision,
		Route:             vcp.RouteSummary{ProviderDefinition: execution.Binding.Target.ProviderDefinitionID, Model: execution.Binding.Target.ProviderModelID, ExecutionProfile: execution.Binding.Target.ExecutionProfileID},
		ConversionSummary: []string{fmt.Sprintf("google_aistudio.media_analyze.prompt.v%d", MediaAnalyzePromptRevision)},
	}}
	return executeAIStudioResponse(ctx, d.client, transport.Request{
		Binding: execution.Binding, Method: http.MethodPost, Path: path, Body: encoded,
		Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationHeader, HeaderName: "X-Goog-Api-Key"},
		IdempotencyKey: execution.Execution.IdempotencyKey,
	}, projected, execution.Now)
}

// googleMediaAnalyzeInstruction returns the frozen Router-owned task instruction without guessing unsupported moderation semantics.
// googleMediaAnalyzeInstruction 返回固定的 Router 所有任务指令，且不猜测不受支持的审核语义。
func googleMediaAnalyzeInstruction(operation vcp.MediaAnalyzeOperation) (string, error) {
	switch operation.Task {
	case vcp.MediaAnalyzeDescribe:
		return "Describe the supplied media faithfully. Distinguish direct observations from uncertainty.", nil
	case vcp.MediaAnalyzeSummarize:
		return "Summarize the supplied media faithfully. Preserve the important sequence, entities, and events.", nil
	case vcp.MediaAnalyzeQuestionAnswer:
		return "Answer this question using only evidence from the supplied media:\n" + strings.TrimSpace(operation.Instruction), nil
	case vcp.MediaAnalyzeExtract:
		if strings.TrimSpace(operation.Instruction) == "" {
			return "", fmt.Errorf("%w: extract requires an explicit instruction", ErrUnsupportedMediaAnalyzeInput)
		}
		return "Extract the requested information from the supplied media:\n" + strings.TrimSpace(operation.Instruction), nil
	case vcp.MediaAnalyzeModerate:
		return "", fmt.Errorf("%w: moderate has no verified Gemini media-analysis contract", ErrUnsupportedMediaAnalyzeInput)
	default:
		return "", fmt.Errorf("%w: unknown task %q", ErrUnsupportedMediaAnalyzeInput, operation.Task)
	}
}

// googleMediaAnalyzeParts preserves declared input order and requires one exact materialization per input identity.
// googleMediaAnalyzeParts 保留声明的输入顺序，并要求每个输入身份恰好对应一个物化结果。
func googleMediaAnalyzeParts(instruction string, inputs []vcp.MediaInput, materialized []resource.MaterializedInput) ([]aistudio.Part, error) {
	// byInputID prevents repeated Router resources from collapsing distinct ordered operation inputs.
	// byInputID 防止重复 Router 资源折叠不同的有序操作输入。
	byInputID := make(map[string]resource.MaterializedInput, len(materialized))
	for _, input := range materialized {
		if _, exists := byInputID[input.InputID]; exists {
			return nil, fmt.Errorf("%w: duplicate materialized input %q", ErrUnsupportedMediaAnalyzeInput, input.InputID)
		}
		byInputID[input.InputID] = input
	}
	if len(byInputID) != len(inputs) {
		return nil, fmt.Errorf("%w: materialized input count differs from operation input count", ErrUnsupportedMediaAnalyzeInput)
	}
	parts := make([]aistudio.Part, 0, len(inputs)+1)
	parts = append(parts, aistudio.Part{Text: instruction})
	for _, declared := range inputs {
		input, exists := byInputID[declared.ID]
		if !exists || input.ResourceID != declared.Resource.ResourceID || input.Kind != declared.Kind || input.Role != declared.Role {
			return nil, fmt.Errorf("%w: materialized input %q differs from the declared input", ErrUnsupportedMediaAnalyzeInput, declared.ID)
		}
		part, errPart := googleMaterializedPart(input)
		if errPart != nil {
			return nil, errPart
		}
		parts = append(parts, part)
	}
	return parts, nil
}

// googleMaterializedPart maps one frozen representation to its sole documented Gemini carrier.
// googleMaterializedPart 将一个冻结表示映射到其唯一已记录的 Gemini 载体。
func googleMaterializedPart(input resource.MaterializedInput) (aistudio.Part, error) {
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if input.InlineBase64 == "" {
			return aistudio.Part{}, fmt.Errorf("%w: inline materialization is empty", ErrUnsupportedMediaAnalyzeInput)
		}
		return aistudio.Part{InlineData: &aistudio.InlineData{MIMEType: input.MIMEType, Data: input.InlineBase64}}, nil
	case catalog.MaterializationProviderFileID:
		if input.ProviderHandle == "" {
			return aistudio.Part{}, fmt.Errorf("%w: provider file handle is empty", ErrUnsupportedMediaAnalyzeInput)
		}
		return aistudio.Part{FileData: &aistudio.FileData{MIMEType: input.MIMEType, FileURI: input.ProviderHandle}}, nil
	default:
		return aistudio.Part{}, fmt.Errorf("%w: materialization mode %q has no Gemini media carrier", ErrUnsupportedMediaAnalyzeInput, input.Mode)
	}
}
