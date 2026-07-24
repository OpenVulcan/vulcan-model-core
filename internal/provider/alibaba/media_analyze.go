package alibaba

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

var (
	// ErrInvalidMediaAnalyzeDriver reports an incomplete Alibaba Omni analysis driver.
	// ErrInvalidMediaAnalyzeDriver 表示不完整的 Alibaba Omni 分析 Driver。
	ErrInvalidMediaAnalyzeDriver = errors.New("invalid Alibaba media analysis driver")
	// ErrUnsupportedMediaAnalyzeInput reports a task or input outside the evidence-closed Omni contract.
	// ErrUnsupportedMediaAnalyzeInput 表示任务或输入超出证据封闭的 Omni 合同。
	ErrUnsupportedMediaAnalyzeInput = errors.New("unsupported Alibaba media analysis input")
)

const (
	// MediaAnalyzeActionBindingID identifies the dedicated non-realtime Qwen Omni analysis action.
	// MediaAnalyzeActionBindingID 标识专用非实时 Qwen Omni 分析动作。
	MediaAnalyzeActionBindingID = "action_alibaba_qwen_omni_media_analyze"
	// MediaAnalyzeProtocolProfileID identifies the Router-versioned analysis projection layered on Alibaba Chat.
	// MediaAnalyzeProtocolProfileID 标识叠加在 Alibaba Chat 上且由 Router 版本化的分析投影。
	MediaAnalyzeProtocolProfileID = "alibaba.qwen_omni.media_analyze.v1"
	// MediaAnalyzePromptRevision freezes the Router-owned task instruction semantics.
	// MediaAnalyzePromptRevision 冻结 Router 所有任务指令语义。
	MediaAnalyzePromptRevision uint64 = 1
)

// MediaAnalyzeActionDriver executes one streaming Qwen Omni analysis through the already verified Alibaba Chat transport.
// MediaAnalyzeActionDriver 通过已验证的 Alibaba Chat 传输执行一条流式 Qwen Omni 分析。
type MediaAnalyzeActionDriver struct {
	// definitionID fixes the regional Model Studio boundary.
	// definitionID 固定区域 Model Studio 边界。
	definitionID string
	// chatDriver owns the exact compatible wire projection and stream decoder.
	// chatDriver 拥有精确兼容 Wire 投影与流解码器。
	chatDriver *provideropenai.ChatDriver
}

// NewMediaAnalyzeActionDriver creates one definition-bound Qwen Omni analysis driver.
// NewMediaAnalyzeActionDriver 创建一个绑定 Definition 的 Qwen Omni 分析 Driver。
func NewMediaAnalyzeActionDriver(definitionID string, chatDriver *provideropenai.ChatDriver) (*MediaAnalyzeActionDriver, error) {
	if strings.TrimSpace(definitionID) == "" || chatDriver == nil || chatDriver.ProviderDefinitionID() != definitionID {
		return nil, ErrInvalidMediaAnalyzeDriver
	}
	return &MediaAnalyzeActionDriver{definitionID: definitionID, chatDriver: chatDriver}, nil
}

// ProviderDefinitionID returns the sole provider definition owned by this driver.
// ProviderDefinitionID 返回此 Driver 唯一拥有的供应商 Definition。
func (d *MediaAnalyzeActionDriver) ProviderDefinitionID() string {
	if d == nil {
		return ""
	}
	return d.definitionID
}

// ActionBindingID returns the exact Alibaba Omni media-analysis action.
// ActionBindingID 返回精确的 Alibaba Omni 媒体分析动作。
func (d *MediaAnalyzeActionDriver) ActionBindingID() string {
	return MediaAnalyzeActionBindingID
}

// Execute converts a closed media task into one frozen user instruction plus ordered media blocks and delegates only transport mechanics to Chat.
// Execute 将封闭媒体任务转换为一条固定用户指令与有序媒体块，并仅把传输机制委托给 Chat。
func (d *MediaAnalyzeActionDriver) Execute(ctx context.Context, execution provider.ExecutionRequest) (provider.ExecutionResult, error) {
	if d == nil || d.chatDriver == nil {
		return provider.ExecutionResult{}, ErrInvalidMediaAnalyzeDriver
	}
	action, errAction := execution.ValidateForAction(MediaAnalyzeActionBindingID, providerconfig.AuthMethodAPIKey)
	if errAction != nil {
		return provider.ExecutionResult{}, errAction
	}
	if action.Operation != vcp.OperationMediaAnalyze || !execution.Execution.Stream {
		return provider.ExecutionResult{}, fmt.Errorf("%w: Qwen Omni media analysis requires streaming", ErrUnsupportedMediaAnalyzeInput)
	}
	operation := *execution.Execution.Payload.MediaAnalyze
	request, errRequest := alibabaMediaAnalyzeRequest(*execution.Execution, execution.Binding.Target.ProviderInstanceID, execution.Binding.Target.ProviderModelID, execution.Binding.Target.ExecutionProfileID, operation, execution.MaterializedInputs)
	if errRequest != nil {
		return provider.ExecutionResult{}, errRequest
	}
	// delegated removes the action envelope only after exact action and input validation, so Chat cannot reinterpret the original operation.
	// delegated 仅在精确动作与输入校验后移除动作信封，因此 Chat 无法重新解释原始操作。
	delegated := execution
	delegated.Execution = nil
	delegated.Request = request
	result, errExecute := d.chatDriver.Execute(ctx, delegated)
	if errExecute != nil {
		return provider.ExecutionResult{}, errExecute
	}
	result.Report.ConversionSummary = append(result.Report.ConversionSummary, fmt.Sprintf("alibaba.qwen_omni.media_analyze.prompt.v%d", MediaAnalyzePromptRevision))
	return result, nil
}

// alibabaMediaAnalyzeRequest builds one canonical Chat request only after proving exact declared-to-materialized input identity.
// alibabaMediaAnalyzeRequest 仅在证明声明输入与物化输入精确一致后构建一条规范 Chat 请求。
func alibabaMediaAnalyzeRequest(envelope vcp.ExecutionRequest, providerInstanceID string, providerModelID string, executionProfileID string, operation vcp.MediaAnalyzeOperation, materialized []resource.MaterializedInput) (vcp.VulcanRequest, error) {
	instruction, errInstruction := alibabaMediaAnalyzeInstruction(operation)
	if errInstruction != nil {
		return vcp.VulcanRequest{}, errInstruction
	}
	if errInputs := validateAlibabaMediaAnalyzeInputs(operation.Inputs, materialized); errInputs != nil {
		return vcp.VulcanRequest{}, errInputs
	}
	// content preserves the declared media ordering after the frozen Router-owned instruction.
	// content 在固定 Router 所有指令之后保留声明的媒体顺序。
	content := make([]vcp.ContentBlock, 0, len(operation.Inputs)+1)
	content = append(content, vcp.ContentBlock{Type: vcp.ContentText, Text: instruction})
	for _, input := range operation.Inputs {
		contentType, errType := alibabaMediaContentType(input.Kind)
		if errType != nil {
			return vcp.VulcanRequest{}, errType
		}
		content = append(content, vcp.ContentBlock{Type: contentType, ResourceRef: input.Resource.ResourceID, MediaRole: input.Role})
	}
	request := vcp.VulcanRequest{
		ProtocolVersion: envelope.ProtocolVersion, RequestID: envelope.RequestID, IdempotencyKey: envelope.IdempotencyKey,
		ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: providerInstanceID, ProviderModelID: providerModelID, ExecutionProfileID: executionProfileID},
		Context: []vcp.ContextItem{{
			ItemID: vcp.DeriveID("item", envelope.RequestID, "alibaba_qwen_omni_media_analyze"), Sequence: 1, Kind: vcp.ContextMessage,
			Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser, Placement: vcp.PlacementTranscript,
			Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel, Content: content, Message: &vcp.MessageItem{},
		}},
		CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
		ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
		CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityNativeOnly, OptionalOnUnsupported: vcp.OptionalFail},
		Stream:                  true, Budget: envelope.Budget,
	}
	if errValidate := request.Validate(); errValidate != nil {
		return vcp.VulcanRequest{}, fmt.Errorf("%w: synthesized conversation request: %v", ErrUnsupportedMediaAnalyzeInput, errValidate)
	}
	return request, nil
}

// alibabaMediaAnalyzeInstruction returns a frozen task-specific instruction and rejects unverified moderation semantics.
// alibabaMediaAnalyzeInstruction 返回固定的任务专属指令，并拒绝未经验证的审核语义。
func alibabaMediaAnalyzeInstruction(operation vcp.MediaAnalyzeOperation) (string, error) {
	switch operation.Task {
	case vcp.MediaAnalyzeDescribe:
		return "Describe the supplied media faithfully. Distinguish direct observations from uncertainty.", nil
	case vcp.MediaAnalyzeSummarize:
		return "Summarize the supplied media faithfully. Preserve important sequence, entities, speech, and events.", nil
	case vcp.MediaAnalyzeQuestionAnswer:
		return "Answer this question using only evidence from the supplied media:\n" + strings.TrimSpace(operation.Instruction), nil
	case vcp.MediaAnalyzeExtract:
		if strings.TrimSpace(operation.Instruction) == "" {
			return "", fmt.Errorf("%w: extract requires an explicit instruction", ErrUnsupportedMediaAnalyzeInput)
		}
		return "Extract the requested information from the supplied media:\n" + strings.TrimSpace(operation.Instruction), nil
	case vcp.MediaAnalyzeModerate:
		return "", fmt.Errorf("%w: moderate has no verified Qwen Omni media-analysis contract", ErrUnsupportedMediaAnalyzeInput)
	default:
		return "", fmt.Errorf("%w: unknown task %q", ErrUnsupportedMediaAnalyzeInput, operation.Task)
	}
}

// validateAlibabaMediaAnalyzeInputs requires one exact materialization per declared input without candidate-path fallback.
// validateAlibabaMediaAnalyzeInputs 要求每个声明输入恰好对应一个物化结果，且不采用候选路径兜底。
func validateAlibabaMediaAnalyzeInputs(inputs []vcp.MediaInput, materialized []resource.MaterializedInput) error {
	if len(inputs) != len(materialized) {
		return fmt.Errorf("%w: materialized input count differs from operation input count", ErrUnsupportedMediaAnalyzeInput)
	}
	// byInputID keeps repeated Router resources distinct when callers assign different ordered input identities.
	// byInputID 在调用方分配不同有序输入身份时保持重复 Router 资源彼此独立。
	byInputID := make(map[string]resource.MaterializedInput, len(materialized))
	for _, input := range materialized {
		if _, exists := byInputID[input.InputID]; exists {
			return fmt.Errorf("%w: duplicate materialized input %q", ErrUnsupportedMediaAnalyzeInput, input.InputID)
		}
		byInputID[input.InputID] = input
	}
	for _, declared := range inputs {
		input, exists := byInputID[declared.ID]
		if !exists || input.ResourceID != declared.Resource.ResourceID || input.Kind != declared.Kind || input.Role != declared.Role {
			return fmt.Errorf("%w: materialized input %q differs from the declared input", ErrUnsupportedMediaAnalyzeInput, declared.ID)
		}
	}
	return nil
}

// alibabaMediaContentType maps one closed media kind to its canonical conversation block.
// alibabaMediaContentType 将一种封闭媒体类型映射到其规范会话内容块。
func alibabaMediaContentType(kind vcp.MediaKind) (vcp.ContentType, error) {
	switch kind {
	case vcp.MediaImage:
		return vcp.ContentImage, nil
	case vcp.MediaAudio:
		return vcp.ContentAudio, nil
	case vcp.MediaVideo:
		return vcp.ContentVideo, nil
	default:
		return "", fmt.Errorf("%w: media kind %q has no Qwen Omni carrier", ErrUnsupportedMediaAnalyzeInput, kind)
	}
}
