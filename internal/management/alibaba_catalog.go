package management

import "github.com/OpenVulcan/vulcan-model-core/internal/catalog"

// alibabaCodingPlanModels returns the exact current Coding Plan text-only model allowlist.
// alibabaCodingPlanModels 返回当前 Coding Plan 精确的纯文本模型白名单。
func alibabaCodingPlanModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, 1_024, true, false),
		alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, 1_024, true, false),
		alibabaModel("qwen3.5-plus", "Qwen3.5 Plus", 1_000_000, 0, 1_024, true, false),
		alibabaModel("qwen3-max-2026-01-23", "Qwen3 Max 0123", 262_144, 0, 0, false, false),
		alibabaModel("qwen3-coder-next", "Qwen3 Coder Next", 262_144, 0, 0, false, false),
		alibabaModel("qwen3-coder-plus", "Qwen3 Coder Plus", 1_000_000, 0, 0, false, false),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 196_608, 0, 0, false, false),
		alibabaModel("glm-5", "GLM-5", 202_752, 0, 1_024, true, true),
		alibabaModel("glm-4.7", "GLM-4.7", 202_752, 0, 0, true, true),
		alibabaModel("kimi-k2.5", "Kimi K2.5", 262_144, 0, 1_024, false, false),
	}
}

// alibabaTokenPlanPersonalCNModels returns the exact current China Personal Token Plan allowlist.
// alibabaTokenPlanPersonalCNModels 返回当前中国站个人 Token Plan 精确白名单。
func alibabaTokenPlanPersonalCNModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModel("qwen3.8-max-preview", "Qwen3.8 Max Preview", 0, 131_072, 0, false, false),
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, 8_192, true, false),
		alibabaModel("glm-5.2", "GLM-5.2", 1_000_000, 0, 8_192, true, true),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, 0, false, true),
	}
}

// alibabaTokenPlanTeamCNModels returns the exact current China Team Token Plan allowlist.
// alibabaTokenPlanTeamCNModels 返回当前中国站团队 Token Plan 精确白名单。
func alibabaTokenPlanTeamCNModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModel("qwen3.8-max-preview", "Qwen3.8 Max Preview", 0, 131_072, 0, false, false),
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, 8_192, true, false),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, 0, false, true),
		alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 0, 0, false, true),
		alibabaModel("deepseek-v3.2", "DeepSeek V3.2", 128_000, 0, 0, false, true),
		alibabaModel("kimi-k2.7-code", "Kimi K2.7 Code", 256_000, 0, 8_192, false, false),
		alibabaModel("kimi-k2.6", "Kimi K2.6", 256_000, 0, 8_192, false, false),
		alibabaModel("kimi-k2.5", "Kimi K2.5", 256_000, 0, 8_192, false, false),
		alibabaModel("glm-5.2", "GLM-5.2", 1_000_000, 0, 8_192, true, true),
		alibabaModel("glm-5.1", "GLM-5.1", 198_000, 0, 8_192, true, true),
		alibabaModel("glm-5", "GLM-5", 198_000, 0, 8_192, true, true),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 192_000, 0, 0, false, false),
	}
}

// alibabaTokenPlanTeamGlobalModels returns the exact current Global Team Token Plan allowlist.
// alibabaTokenPlanTeamGlobalModels 返回当前国际站团队 Token Plan 精确白名单。
func alibabaTokenPlanTeamGlobalModels() []systemModelTemplate {
	return []systemModelTemplate{
		alibabaModel("qwen3.7-max", "Qwen3.7 Max", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.7-plus", "Qwen3.7 Plus", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.6-plus", "Qwen3.6 Plus", 1_000_000, 0, 8_192, true, false),
		alibabaModel("qwen3.6-flash", "Qwen3.6 Flash", 1_000_000, 0, 8_192, true, false),
		alibabaModel("deepseek-v4-pro", "DeepSeek V4 Pro", 1_000_000, 0, 0, false, true),
		alibabaModel("deepseek-v4-flash", "DeepSeek V4 Flash", 1_000_000, 0, 0, false, true),
		alibabaModel("deepseek-v3.2", "DeepSeek V3.2", 128_000, 0, 0, false, true),
		alibabaModel("kimi-k2.7-code", "Kimi K2.7 Code", 256_000, 0, 8_192, false, false),
		alibabaModel("kimi-k2.6", "Kimi K2.6", 256_000, 0, 8_192, false, false),
		alibabaModel("kimi-k2.5", "Kimi K2.5", 256_000, 0, 8_192, false, false),
		alibabaModel("glm-5.2", "GLM-5.2", 198_000, 0, 8_192, true, true),
		alibabaModel("glm-5.1", "GLM-5.1", 198_000, 0, 8_192, true, true),
		alibabaModel("glm-5", "GLM-5", 198_000, 0, 8_192, true, true),
		alibabaModel("MiniMax-M2.5", "MiniMax M2.5", 192_000, 0, 0, false, false),
	}
}

// alibabaModel builds one conservative text-only model template from explicit regional plan evidence.
// alibabaModel 根据明确的区域套餐证据构建一个保守的纯文本模型模板。
func alibabaModel(upstreamID string, displayName string, contextWindow int64, maxOutputTokens int64, recommendedReasoningTokens int64, streamingTools bool, strictSchema bool) systemModelTemplate {
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
	return systemModelTemplate{
		upstreamID: upstreamID, displayName: displayName, contextWindow: contextWindow, maxOutputTokens: maxOutputTokens, recommendedReasoningTokens: recommendedReasoningTokens,
		inputModalities: []string{"text"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityUnknown,
		streamingTools: streamingToolCapability, strictSchema: strictSchemaCapability, entitlementMode: catalog.EntitlementAllBoundCredentials,
	}
}
