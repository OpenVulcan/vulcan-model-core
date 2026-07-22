package minimax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidVisionDriver reports an incomplete MiniMax VLM driver or malformed response.
	// ErrInvalidVisionDriver 表示不完整的 MiniMax VLM 驱动或格式错误的响应。
	ErrInvalidVisionDriver = errors.New("invalid MiniMax vision driver")
	// ErrUnsupportedVisionInput reports a media task outside the copied minimax-cli contract.
	// ErrUnsupportedVisionInput 表示媒体任务超出复制的 minimax-cli 合同。
	ErrUnsupportedVisionInput = errors.New("unsupported MiniMax vision input")
)

const (
	// MediaAnalyzeActionBindingID identifies MiniMax Coding Plan VLM analysis.
	// MediaAnalyzeActionBindingID 标识 MiniMax Coding Plan VLM 分析。
	MediaAnalyzeActionBindingID = "action_minimax_media_analyze"
	// MediaAnalyzeProtocolProfileID identifies the versioned MiniMax VLM wire contract.
	// MediaAnalyzeProtocolProfileID 标识版本化 MiniMax VLM wire 合同。
	MediaAnalyzeProtocolProfileID = "minimax.coding_plan.vlm.v1"
	// mediaAnalyzePath is copied from minimax-cli's VLM endpoint definition.
	// mediaAnalyzePath 从 minimax-cli 的 VLM 端点定义复制而来。
	mediaAnalyzePath = "/v1/coding_plan/vlm"
)

// VisionDriver executes one synchronous image-analysis request.
// VisionDriver 执行一条同步图片分析请求。
type VisionDriver struct {
	// definitionID fixes one regional provider definition.
	// definitionID 固定一个区域供应商 Definition。
	definitionID string
	// client owns exact-target authenticated transport.
	// client 管理精确 Target 的认证传输。
	client *transport.Client
}

// visionRequest is the exact VLM request shape copied from minimax-cli.
// visionRequest 是从 minimax-cli 复制的精确 VLM 请求形态。
type visionRequest struct {
	// Prompt contains the explicit Router task instruction.
	// Prompt 包含明确的 Router 任务指令。
	Prompt string `json:"prompt"`
	// ImageURL contains an image data URI for inline materialization.
	// ImageURL 为内联物化包含图片 Data URI。
	ImageURL string `json:"image_url,omitempty"`
}

// visionResponse is the exact successful VLM response shape copied from minimax-cli.
// visionResponse 是从 minimax-cli 复制的精确 VLM 成功响应形态。
type visionResponse struct {
	// Content is the provider-generated analysis text.
	// Content 是供应商生成的分析文本。
	Content string `json:"content"`
}

// NewVisionDriver creates one region-fixed MiniMax VLM driver.
// NewVisionDriver 创建一个区域固定的 MiniMax VLM 驱动。
func NewVisionDriver(definitionID string, client *transport.Client) (*VisionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || client == nil {
		return nil, ErrInvalidVisionDriver
	}
	return &VisionDriver{definitionID: definitionID, client: client}, nil
}

// ProviderDefinitionID returns the sole owning definition.
// ProviderDefinitionID 返回唯一归属 Definition。
func (d *VisionDriver) ProviderDefinitionID() string { return d.definitionID }

// ActionBindingID returns the exact VLM action identifier.
// ActionBindingID 返回精确 VLM 动作标识。
func (d *VisionDriver) ActionBindingID() string { return MediaAnalyzeActionBindingID }

// Execute projects one VCP image task to the MiniMax VLM endpoint.
// Execute 将一条 VCP 图片任务投影到 MiniMax VLM 端点。
func (d *VisionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.client == nil {
		return provider.ExecutionResult{}, ErrInvalidVisionDriver
	}
	action, errAction := execution.ValidateForAction(MediaAnalyzeActionBindingID, providerconfig.AuthMethodAPIKey, providerconfig.AuthMethodDeviceFlow)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationMediaAnalyze || execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: MiniMax VLM is synchronous only", ErrUnsupportedVisionInput)
	}
	projected, errProject := projectVisionRequest(*execution.Execution.Payload.MediaAnalyze, execution.MaterializedInputs)
	if errProject != nil {
		return provider.ExecutionResult{}, errProject
	}
	body, errMarshal := json.Marshal(projected)
	if errMarshal != nil {
		return provider.ExecutionResult{}, fmt.Errorf("%w: encode request: %v", ErrInvalidVisionDriver, errMarshal)
	}
	response, errRequest := d.client.Do(ctx, transport.Request{Binding: execution.Binding, Method: http.MethodPost, Path: mediaAnalyzePath, Body: body, Headers: []transport.Header{{Name: "Content-Type", Value: "application/json"}}, Authentication: transport.Authentication{Mode: transport.AuthenticationBearer}, IdempotencyKey: execution.Execution.IdempotencyKey})
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	defer func() { _ = transport.DrainAndClose(response) }()
	reader, errBound := transport.NewBoundedResponseReader(response.Body, transport.MaximumNonStreamingResponseBytes)
	if errBound != nil {
		return provider.ExecutionResult{}, errBound
	}
	var upstream visionResponse
	decoder := json.NewDecoder(reader)
	if errDecode := decoder.Decode(&upstream); errDecode != nil || strings.TrimSpace(upstream.Content) == "" {
		return provider.ExecutionResult{}, fmt.Errorf("%w: decode response", ErrInvalidVisionDriver)
	}
	if errTrailing := rejectTrailingJSON(decoder, ErrInvalidVisionDriver); errTrailing != nil {
		return provider.ExecutionResult{}, errTrailing
	}
	responseID := vcp.DeriveID("resp", execution.Execution.RequestID)
	canonical, events, report, errResult := textResult(responseID, upstream.Content, execution.Now, "minimax.coding_plan.vlm.v1")
	if errResult != nil {
		return provider.ExecutionResult{}, errResult
	}
	return provider.ExecutionResult{Response: canonical, Events: events, Report: report}, nil
}

// projectVisionRequest maps one exact image input and explicit task to the copied MiniMax fields.
// projectVisionRequest 将一个精确图片输入和明确任务映射到复制的 MiniMax 字段。
func projectVisionRequest(operation vcp.MediaAnalyzeOperation, materialized []resource.MaterializedInput) (visionRequest, error) {
	if len(operation.Inputs) != 1 || len(materialized) != 1 || operation.Inputs[0].Kind != vcp.MediaImage || operation.Inputs[0].Role != vcp.MediaRoleUnderstanding {
		return visionRequest{}, fmt.Errorf("%w: exactly one understanding image is required", ErrUnsupportedVisionInput)
	}
	declared, input := operation.Inputs[0], materialized[0]
	if input.InputID != declared.ID || input.ResourceID != declared.Resource.ResourceID || input.Kind != declared.Kind || input.Role != declared.Role {
		return visionRequest{}, fmt.Errorf("%w: materialized input differs from declared input", ErrUnsupportedVisionInput)
	}
	prompt, errPrompt := miniMaxVisionPrompt(operation)
	if errPrompt != nil {
		return visionRequest{}, errPrompt
	}
	request := visionRequest{Prompt: prompt}
	switch input.Mode {
	case catalog.MaterializationInlineBase64:
		if input.InlineBase64 == "" || !supportedVisionMIMEType(input.MIMEType) {
			return visionRequest{}, fmt.Errorf("%w: inline image is empty or has an unsupported MIME type", ErrUnsupportedVisionInput)
		}
		request.ImageURL = "data:" + input.MIMEType + ";base64," + input.InlineBase64
	default:
		return visionRequest{}, fmt.Errorf("%w: materialization mode %q has no MiniMax VLM carrier", ErrUnsupportedVisionInput, input.Mode)
	}
	return request, nil
}

// miniMaxVisionPrompt maps only task semantics proved safe for MiniMax's free-form prompt field.
// miniMaxVisionPrompt 仅将已证明可安全承载于 MiniMax 自由提示字段的任务语义进行映射。
func miniMaxVisionPrompt(operation vcp.MediaAnalyzeOperation) (string, error) {
	switch operation.Task {
	case vcp.MediaAnalyzeDescribe:
		if strings.TrimSpace(operation.Instruction) != "" {
			return strings.TrimSpace(operation.Instruction), nil
		}
		return "Describe the image.", nil
	case vcp.MediaAnalyzeSummarize:
		return "Summarize the image faithfully.", nil
	case vcp.MediaAnalyzeQuestionAnswer, vcp.MediaAnalyzeExtract:
		if strings.TrimSpace(operation.Instruction) == "" {
			return "", fmt.Errorf("%w: the selected task requires an instruction", ErrUnsupportedVisionInput)
		}
		return strings.TrimSpace(operation.Instruction), nil
	case vcp.MediaAnalyzeModerate:
		return "", fmt.Errorf("%w: moderation has no verified MiniMax VLM contract", ErrUnsupportedVisionInput)
	default:
		return "", fmt.Errorf("%w: unknown task %q", ErrUnsupportedVisionInput, operation.Task)
	}
}

// supportedVisionMIMEType reports the exact image formats accepted by minimax-cli's VLM conversion.
// supportedVisionMIMEType 报告 minimax-cli 的 VLM 转换接受的精确图片格式。
func supportedVisionMIMEType(mimeType string) bool {
	switch mimeType {
	case "image/jpeg", "image/png", "image/webp":
		return true
	default:
		return false
	}
}
