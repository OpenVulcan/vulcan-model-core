package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaReasoningContract contains only B-level predictConfig facts paired with the reviewed Chat wire mapping.
// alibabaReasoningContract 仅包含与已审核 Chat Wire 映射配对的 B 级 predictConfig 事实。
type alibabaReasoningContract struct {
	// switchDefault is present only when enable_thinking is an evidenced model parameter.
	// switchDefault 仅在 enable_thinking 是已证实模型参数时存在。
	switchDefault *bool
	// budgetMinimum is the inclusive thinking_budget minimum when the complete range is known.
	// budgetMinimum 是完整范围已知时包含端点的 thinking_budget 最小值。
	budgetMinimum int64
	// budgetMaximum is the inclusive thinking_budget maximum when the complete range is known.
	// budgetMaximum 是完整范围已知时包含端点的 thinking_budget 最大值。
	budgetMaximum int64
	// budgetDefault is the provider-authored thinking_budget default when known.
	// budgetDefault 是已知时由供应商编写的 thinking_budget 默认值。
	budgetDefault int64
}

// alibabaModelStudioCNConversationModels returns the curated standard-API conversation models verified for the China endpoint.
// alibabaModelStudioCNConversationModels 返回已为中国站标准 API 入口验证的精选会话模型。
func alibabaModelStudioCNConversationModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.5-flash", "Qwen3.5 Flash", 1_000_000, 65_536, false, true), 991_808, 81_920), 256)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.5-plus", "Qwen3.5 Plus", 1_000_000, 65_536, true, true), 991_808, 81_920), 256)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 65_536, true, true), 991_808, 81_920), 256)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 65_536, true, true), 2_048)),
		alibabaModelStudioNativeSearchModel(alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 65_536, true, false)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModel("qwen3.7-max-2026-06-08", "Qwen3.7 Max 2026-06-08", 1_000_000, 65_536, true, false), 2_048)),
		alibabaModel("glm-5.1", "GLM-5.1", 202_752, 131_072, true, true),
		alibabaModelTokenLimits(alibabaModel("glm-5.2-fast-preview", "GLM-5.2 Fast Preview", 1_048_576, 131_072, true, false), 1_048_576, 131_072),
		alibabaModelTokenLimits(alibabaModel("ZHIPU/GLM-5.2", "ZHIPU GLM-5.2", 1_048_576, 131_072, true, false), 1_048_576, 131_072),
		alibabaModelTokenLimits(alibabaMultimodalConversationModel(alibabaModel("kimi/kimi-k3", "Kimi K3", 1_048_576, 1_048_576, false, false), true), 1_048_576, 1_048_576),
		alibabaMiniMaxM3Model(),
		alibabaStepFun37FlashModel(),
		alibabaModelTokenLimits(alibabaModel("xiaomi/mimo-v2.5-pro", "Xiaomi MiMo V2.5 Pro", 1_048_576, 131_072, false, false), 1_048_576, 131_072),
		alibabaModelStudioNativeSearchModel(alibabaModelTokenLimits(alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 393_216, false, true), 1_000_000, 0)),
		alibabaModelStudioNativeSearchModel(alibabaModelTokenLimits(alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 393_216, false, true), 1_000_000, 0)),
	}
}

// alibabaModelStudioSGConversationModels returns the curated standard-API conversation models verified for the Singapore endpoint.
// alibabaModelStudioSGConversationModels 返回已为新加坡标准 API 入口验证的精选会话模型。
func alibabaModelStudioSGConversationModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.5-flash", "Qwen3.5 Flash", 1_000_000, 65_536, false, true), 991_808, 81_920), 256)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.5-plus", "Qwen3.5 Plus", 1_000_000, 65_536, true, true), 991_808, 81_920), 256)),
		alibabaModelStudioNativeSearchModel(alibabaModelStudioQwenMultimodalModel(alibabaModelTokenLimits(alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 65_536, true, true), 991_808, 81_920), 256)),
		alibabaModelTokenLimits(alibabaModel("glm-5.2-fast-preview", "GLM-5.2 Fast Preview", 1_048_576, 131_072, true, false), 1_048_576, 131_072),
		alibabaModelStudioNativeSearchModel(alibabaModelTokenLimits(alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 393_216, false, true), 1_000_000, 0)),
	}
}

// alibabaModelTokenLimits applies independently verified input and reasoning ceilings without deriving missing values.
// alibabaModelTokenLimits 应用独立验证的输入与推理上限，且不会推导缺失值。
func alibabaModelTokenLimits(template systemModelTemplate, maximumInput int64, maximumReasoning int64) systemModelTemplate {
	template.maxInputTokens = maximumInput
	template.maxReasoningTokens = maximumReasoning
	return template
}

// alibabaModelStudioNativeSearchModel marks one standard-API model whose hosted web search is implemented by the Alibaba Chat adapter.
// alibabaModelStudioNativeSearchModel 标记一个由阿里云 Chat 适配器实现托管联网搜索的标准 API 模型。
func alibabaModelStudioNativeSearchModel(template systemModelTemplate) systemModelTemplate {
	template.standardTools = []catalog.StandardModelToolCapability{{Kind: vcp.StandardModelToolWebSearch, Native: true}}
	return template
}

// alibabaModelStudioQwenMultimodalModel applies the official two-hour video and model-specific image-count limits to one regional Qwen model.
// alibabaModelStudioQwenMultimodalModel 为一个区域 Qwen 模型应用官方两小时视频与模型专属图片数量限制。
func alibabaModelStudioQwenMultimodalModel(template systemModelTemplate, maximumImages int64) systemModelTemplate {
	template = alibabaMultimodalConversationModel(template, true)
	for inputIndex := range template.mediaInputs {
		input := &template.mediaInputs[inputIndex]
		input.Evidence = []catalog.CapabilityEvidence{{
			Source:     catalog.ModelSourceProviderAPI,
			Reference:  "https://help.aliyun.com/zh/model-studio/vision-model/",
			ObservedAt: mediaEvidenceObservedAt(),
			Revision:   1,
		}}
		input.EvidenceRevision = 1
		switch input.Kind {
		case vcp.MediaImage:
			input.Common.MaxItems = catalog.OptionalLimit{Known: true, Value: maximumImages}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 20 << 20}
			input.Image = &catalog.ImageMediaLimits{MaxPixels: catalog.OptionalLimit{Known: true, Value: 16_000_000}}
		case vcp.MediaVideo:
			input.Common.MaxItems = catalog.OptionalLimit{Known: true, Value: 64}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 2 << 30}
			input.Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 2 * 60 * 60 * 1_000}}
		}
	}
	return template
}

// alibabaMiniMaxM3Model returns the China-only MiniMax M3 conversation contract with provider-published media limits.
// alibabaMiniMaxM3Model 返回带有供应商公布媒体限制的中国站专属 MiniMax M3 会话合同。
func alibabaMiniMaxM3Model() systemModelTemplate {
	template := alibabaModelTokenLimits(alibabaMultimodalConversationModel(alibabaModel("MiniMax/MiniMax-M3", "MiniMax M3", 1_048_576, 32_768, false, false), true), 1_048_576, 0)
	for inputIndex := range template.mediaInputs {
		input := &template.mediaInputs[inputIndex]
		input.Evidence = []catalog.CapabilityEvidence{{
			Source:     catalog.ModelSourceProviderAPI,
			Reference:  "https://help.aliyun.com/en/model-studio/minimax-api-by-minimax",
			ObservedAt: mediaEvidenceObservedAt(),
			Revision:   1,
		}}
		input.EvidenceRevision = 1
		switch input.Kind {
		case vcp.MediaImage:
			input.Common.MIMETypes = []string{"image/jpeg", "image/png", "image/webp", "image/gif"}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 10 << 20}
		case vcp.MediaVideo:
			input.Common.MIMETypes = []string{"video/mp4", "video/x-msvideo", "video/quicktime", "video/x-matroska"}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 50 << 20}
			input.Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 30 * 60 * 1_000}}
		}
	}
	return template
}

// alibabaStepFun37FlashModel returns the China-only Step 3.7 Flash conversation contract with provider-published media limits.
// alibabaStepFun37FlashModel 返回带有供应商公布媒体限制的中国站专属 Step 3.7 Flash 会话合同。
func alibabaStepFun37FlashModel() systemModelTemplate {
	template := alibabaModelTokenLimits(alibabaMultimodalConversationModel(alibabaModel("stepfun/step-3.7-flash", "Step 3.7 Flash", 262_144, 262_144, false, false), true), 262_144, 262_144)
	for inputIndex := range template.mediaInputs {
		input := &template.mediaInputs[inputIndex]
		input.Evidence = []catalog.CapabilityEvidence{{
			Source:     catalog.ModelSourceProviderAPI,
			Reference:  "https://help.aliyun.com/zh/model-studio/stepfun",
			ObservedAt: mediaEvidenceObservedAt(),
			Revision:   1,
		}}
		input.EvidenceRevision = 1
		switch input.Kind {
		case vcp.MediaImage:
			input.Common.MIMETypes = []string{"image/jpeg", "image/png", "image/webp", "image/gif"}
			input.Common.MaxItems = catalog.OptionalLimit{Known: true, Value: 50}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 10 << 20}
			input.Common.MaxTotalBytes = catalog.OptionalLimit{Known: true, Value: 20 << 20}
		case vcp.MediaVideo:
			input.Common.MIMETypes = []string{"video/mp4"}
			input.Common.MaxItemBytes = catalog.OptionalLimit{Known: true, Value: 128 << 20}
			input.Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 5 * 60 * 1_000}}
		}
	}
	return template
}

// alibabaCodingPlanModels returns the exact current Coding Plan text-only model allowlist.
// alibabaCodingPlanModels 返回当前 Coding Plan 精确的纯文本模型白名单。
func alibabaCodingPlanModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, true, false),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.5-plus", "Qwen3.5 Plus", 1_000_000, 0, true, false), true),
		alibabaModel("qwen3-max-2026-01-23", "Qwen3 Max 0123", 262_144, 0, false, false),
		alibabaModel("qwen3-coder-next", "Qwen3 Coder Next", 262_144, 0, false, false),
		alibabaModel("qwen3-coder-plus", "Qwen3 Coder Plus", 1_000_000, 0, false, false),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 196_608, 0, false, false),
		alibabaModel("glm-5", "GLM-5", 202_752, 0, true, true),
		alibabaModel("glm-4.7", "GLM-4.7", 202_752, 0, true, true),
		alibabaMultimodalConversationModel(alibabaModel("kimi-k2.5", "Kimi K2.5", 262_144, 0, false, false), true),
	}
}

// alibabaTokenPlanPersonalCNModels returns the exact current China Personal Token Plan allowlist.
// alibabaTokenPlanPersonalCNModels 返回当前中国站个人 Token Plan 精确白名单。
func alibabaTokenPlanPersonalCNModels() []systemModelTemplate {
	models := []systemModelTemplate{
		alibabaMultimodalConversationModel(alibabaModel("qwen3.8-max-preview", "Qwen3.8 Max Preview", 1_000_000, 131_072, false, false), true),
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, true, false),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, true, false), false),
		alibabaModel("glm-5.2", "GLM-5.2", 1_000_000, 0, true, true),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, false, true),
	}
	return appendAlibabaTokenPlanHarnessModels(models)
}

// alibabaTokenPlanTeamCNModels returns the exact current China Team Token Plan allowlist.
// alibabaTokenPlanTeamCNModels 返回当前中国站团队 Token Plan 精确白名单。
func alibabaTokenPlanTeamCNModels() []systemModelTemplate {
	models := []systemModelTemplate{
		alibabaMultimodalConversationModel(alibabaModel("qwen3.8-max-preview", "Qwen3.8 Max Preview", 1_000_000, 131_072, false, false), true),
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, true, false),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, true, false), false),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, false, true),
		alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 0, false, true),
		alibabaModel("deepseek-v3.2", "DeepSeek V3.2", 131_072, 0, false, true),
		alibabaMultimodalConversationModel(alibabaModel("kimi-k2.7-code", "Kimi K2.7 Code", 262_144, 0, false, false), true),
		alibabaModel("kimi-k2.6", "Kimi K2.6", 262_144, 0, false, false),
		alibabaMultimodalConversationModel(alibabaModel("kimi-k2.5", "Kimi K2.5", 262_144, 0, false, false), true),
		alibabaModel("glm-5.2", "GLM-5.2", 1_000_000, 0, true, true),
		alibabaModel("glm-5.1", "GLM-5.1", 198_000, 0, true, true),
		alibabaModel("glm-5", "GLM-5", 198_000, 0, true, true),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 196_608, 0, false, false),
	}
	return appendAlibabaTokenPlanHarnessModels(models)
}

// alibabaTokenPlanTeamGlobalModels returns the exact current Global Team Token Plan allowlist.
// alibabaTokenPlanTeamGlobalModels 返回当前国际站团队 Token Plan 精确白名单。
func alibabaTokenPlanTeamGlobalModels() []systemModelTemplate {
	models := []systemModelTemplate{
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, true, false),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, true, false), true),
		alibabaMultimodalConversationModel(alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, true, false), false),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, false, true),
		alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 0, false, true),
		alibabaModel("deepseek-v3.2", "DeepSeek V3.2", 128_000, 0, false, true),
		alibabaMultimodalConversationModel(alibabaModel("kimi-k2.7-code", "Kimi K2.7 Code", 256_000, 0, false, false), true),
		alibabaModel("kimi-k2.6", "Kimi K2.6", 256_000, 0, false, false),
		alibabaMultimodalConversationModel(alibabaModel("kimi-k2.5", "Kimi K2.5", 256_000, 0, false, false), true),
		alibabaModel("glm-5.2", "GLM-5.2", 198_000, 0, true, true),
		alibabaModel("glm-5.1", "GLM-5.1", 198_000, 0, true, true),
		alibabaModel("glm-5", "GLM-5", 198_000, 0, true, true),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 192_000, 0, false, false),
	}
	return appendAlibabaTokenPlanHarnessModels(models)
}

// appendAlibabaTokenPlanHarnessModels adds exact Responses offerings without changing the ordinary Chat offerings.
// appendAlibabaTokenPlanHarnessModels 增加精确 Responses 产品形态且不改变普通 Chat 产品形态。
func appendAlibabaTokenPlanHarnessModels(models []systemModelTemplate) []systemModelTemplate {
	expanded := append([]systemModelTemplate(nil), models...)
	for _, model := range models {
		switch model.upstreamID {
		case "qwen3.8-max-preview", "qwen3.7-max", "qwen3.7-plus":
			expanded = append(expanded, alibabaTokenPlanHarnessModel(model))
		}
	}
	return expanded
}

// alibabaTokenPlanHarnessModel builds the separate text-only Responses offering proven by Qwen Code's side request.
// alibabaTokenPlanHarnessModel 构建由 Qwen Code 旁路请求证实的独立纯文本 Responses 产品形态。
func alibabaTokenPlanHarnessModel(source systemModelTemplate) systemModelTemplate {
	return systemModelTemplate{
		upstreamID: source.upstreamID, displayName: source.displayName + " Harness", contextWindow: source.contextWindow, maxOutputTokens: source.maxOutputTokens,
		inputModalities: []string{"text"}, outputModalities: []string{"text"},
		reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported,
		streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported, entitlementMode: source.entitlementMode,
		operation: vcp.OperationConversationRespond, actionBindingID: provideralibaba.TokenPlanHarnessConversationActionBindingID,
		standardTools: alibabaTokenPlanHarnessStandardTools(),
	}
}

// alibabaTokenPlanHarnessStandardTools returns the two closed Vulcan semantics implemented automatically by Token Plan Harness.
// alibabaTokenPlanHarnessStandardTools 返回由 Token Plan Harness 自动实现的两个封闭 Vulcan 语义。
func alibabaTokenPlanHarnessStandardTools() []catalog.StandardModelToolCapability {
	return []catalog.StandardModelToolCapability{
		{Kind: vcp.StandardModelToolWebSearch, Native: true},
		{Kind: vcp.StandardModelToolWebExtractor, Native: true},
	}
}

// alibabaModel builds one conservative text-only model template from explicit regional plan evidence.
// alibabaModel 根据明确的区域套餐证据构建一个保守的纯文本模型模板。
func alibabaModel(upstreamID string, displayName string, contextWindow int64, maxOutputTokens int64, streamingTools bool, strictSchema bool) systemModelTemplate {
	// streamingToolCapability remains unknown unless Alibaba documents tool_stream for the model.
	// streamingToolCapability 仅在阿里云记录模型支持 tool_stream 时才可用。
	streamingToolCapability := catalog.CapabilityUnknown
	if streamingTools {
		streamingToolCapability = catalog.CapabilityNative
	}
	// strictSchemaCapability rejects ordinary JSON-mode fallback as strict schema support.
	// strictSchemaCapability 不把普通 JSON Mode 降级视为严格 Schema 支持。
	strictSchemaCapability := catalog.CapabilityUnsupported
	if strictSchema {
		strictSchemaCapability = catalog.CapabilityNative
	}
	reasoningContract := alibabaReasoningContractForModel(upstreamID)
	template := systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, contextWindow: contextWindow, maxOutputTokens: maxOutputTokens, recommendedReasoningTokens: reasoningContract.budgetDefault,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityUnknown,
		streamingTools: streamingToolCapability, strictSchema: strictSchemaCapability, entitlementMode: catalog.EntitlementAllBoundCredentials,
	}
	if reasoningContract.switchDefault != nil {
		switchDefault := *reasoningContract.switchDefault
		template.parameters = append(template.parameters, catalog.ParameterDescriptor{ID: provideralibaba.ReasoningEnabledParameterID, Kind: catalog.ParameterBoolean, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Boolean: &switchDefault}})
		unsupportedReasoning := catalog.CapabilityUnsupported
		nativeReasoning := catalog.CapabilityNative
		template.profiles = []systemProfileTemplate{
			{suffix: "ordinary", displayName: displayName + " Ordinary", contextWindow: contextWindow, defaultProfile: true, reasoningOverride: &unsupportedReasoning, removeParameterIDs: []string{provideralibaba.ReasoningBudgetParameterID}},
			{suffix: "reasoning", displayName: displayName + " Reasoning", contextWindow: contextWindow, reasoningOverride: &nativeReasoning},
		}
	}
	if reasoningContract.budgetMinimum > 0 && reasoningContract.budgetMaximum >= reasoningContract.budgetMinimum && reasoningContract.budgetDefault >= reasoningContract.budgetMinimum && reasoningContract.budgetDefault <= reasoningContract.budgetMaximum {
		minimum := reasoningContract.budgetMinimum
		maximum := reasoningContract.budgetMaximum
		defaultBudget := reasoningContract.budgetDefault
		template.parameters = append(template.parameters, catalog.ParameterDescriptor{ID: provideralibaba.ReasoningBudgetParameterID, Kind: catalog.ParameterInteger, IntegerRange: &catalog.IntegerRange{Minimum: &minimum, Maximum: &maximum}, Default: &catalog.ParameterDefault{Source: catalog.ParameterDefaultProvider, Integer: &defaultBudget}})
	}
	return template
}

// alibabaMultimodalConversationModel adds only the image and optionally video carriers proven for one exact plan model.
// alibabaMultimodalConversationModel 仅为一个精确套餐模型增加已证实的图片以及可选视频载体。
func alibabaMultimodalConversationModel(template systemModelTemplate, includeVideo bool) systemModelTemplate {
	template.inputModalities = []string{"text", "image"}
	template.mediaInputs = []catalog.MediaInputCapability{alibabaConversationMediaInput(vcp.MediaImage)}
	if includeVideo {
		template.inputModalities = append(template.inputModalities, "video")
		template.mediaInputs = append(template.mediaInputs, alibabaConversationMediaInput(vcp.MediaVideo))
	}
	return template
}

// alibabaConversationMediaInput returns the conservative Chat carrier contract proven by Qwen Code's OpenAI-compatible media projection.
// alibabaConversationMediaInput 返回由 Qwen Code OpenAI 兼容媒体投影证实的保守 Chat 载体合同。
func alibabaConversationMediaInput(kind vcp.MediaKind) catalog.MediaInputCapability {
	mimeTypes := []string{"image/jpeg", "image/png", "image/webp"}
	if kind == vcp.MediaVideo {
		mimeTypes = []string{"video/mp4", "video/webm", "video/quicktime"}
	}
	capability := catalog.MediaInputCapability{
		Kind: kind, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative,
		InteractionModes: []catalog.MediaInteractionMode{catalog.MediaInteractionMixedConversation}, MediaOnlyPolicy: catalog.MediaOnlyUnsupported,
		AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript},
		ClientWorkflows:      []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan},
		MaterializationModes: []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL},
		Common:               catalog.CommonMediaLimits{MIMETypes: mimeTypes, AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}},
		Compatibility:        catalog.MediaCompatibility{ToolCalling: catalog.CapabilityNative, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityNative, StructuredOutput: catalog.CapabilityUnknown, RequiresText: true},
		Evidence: []catalog.CapabilityEvidence{{
			Source:     catalog.ModelSourceSystem,
			Reference:  "https://github.com/QwenLM/qwen-code/blob/819cd4ab4a335f04228c161cf89616c2cc88ef28/packages/core/src/core/modalityDefaults.ts",
			ObservedAt: mediaEvidenceObservedAt(),
			Revision:   1,
		}},
		EvidenceRevision: 1,
	}
	if kind == vcp.MediaImage {
		capability.Image = &catalog.ImageMediaLimits{}
	} else {
		capability.Video = &catalog.VideoMediaLimits{}
	}
	return capability
}

// alibabaReasoningContractForModel returns exact model-identity predictConfig facts observed on 2026-07-23 and paired with Bailian CLI's profile-independent Chat carrier.
// alibabaReasoningContractForModel 返回 2026-07-23 观测到的精确模型身份 predictConfig 事实，并与百炼 CLI 不区分配置 Profile 的 Chat 载体配对。
func alibabaReasoningContractForModel(upstreamID string) alibabaReasoningContract {
	trueValue := true
	falseValue := false
	switch upstreamID {
	case "qwen3.7-plus", "qwen3.6-plus", "qwen3.5-plus", "qwen3.5-flash", "qwen3.7-max", "qwen3.7-max-2026-06-08", "qwen3.6-flash", "glm-5.2", "glm-5.1", "glm-5", "glm-4.7":
		return alibabaReasoningContract{switchDefault: &trueValue, budgetMinimum: 1, budgetMaximum: 32768, budgetDefault: 4000}
	case "glm-5.2-fast-preview", "ZHIPU/GLM-5.2", "xiaomi/mimo-v2.5-pro":
		return alibabaReasoningContract{switchDefault: &trueValue}
	case "stepfun/step-3.7-flash":
		return alibabaReasoningContract{switchDefault: &falseValue}
	case "deepseek-v4-pro", "deepseek-v4-flash":
		return alibabaReasoningContract{switchDefault: &falseValue, budgetMinimum: 4000, budgetMaximum: 32768, budgetDefault: 4000}
	case "deepseek-v3.2":
		return alibabaReasoningContract{switchDefault: &falseValue, budgetMinimum: 1, budgetMaximum: 32768, budgetDefault: 4000}
	case "kimi-k2.5", "kimi-k2.6":
		return alibabaReasoningContract{switchDefault: &falseValue}
	case "kimi-k2.7-code":
		return alibabaReasoningContract{budgetMinimum: 1, budgetMaximum: 32768, budgetDefault: 4000}
	default:
		return alibabaReasoningContract{}
	}
}
