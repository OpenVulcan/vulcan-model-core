package management

import "github.com/OpenVulcan/vulcan-model-core/internal/catalog"

const (
	// deepSeekContextWindow conservatively materializes the official 1M shared context as decimal tokens.
	// deepSeekContextWindow 将官方 1M 共享上下文保守落实为十进制 Token。
	deepSeekContextWindow int64 = 1000000
	// deepSeekRecommendedMaxInputTokens is the official agent-integration prompt recommendation.
	// deepSeekRecommendedMaxInputTokens 是官方智能体集成提示词建议上限。
	deepSeekRecommendedMaxInputTokens int64 = 840000
	// deepSeekMaximumOutputTokens is the official 384 Ki-token completion ceiling.
	// deepSeekMaximumOutputTokens 是官方 384 Ki Token 补全上限。
	deepSeekMaximumOutputTokens int64 = 393216
	// deepSeekRecommendedOutputTokens is the official agent-integration output recommendation.
	// deepSeekRecommendedOutputTokens 是官方智能体集成输出建议值。
	deepSeekRecommendedOutputTokens int64 = 128000
)

// deepSeekModels returns the exact current official DeepSeek public API model catalog.
// deepSeekModels 返回当前精确的 DeepSeek 官方公共 API 模型目录。
func deepSeekModels() []systemModelTemplate {
	return []systemModelTemplate{
		deepSeekModel("deepseek-v4-flash", "DeepSeek V4 Flash"),
		deepSeekModel("deepseek-v4-pro", "DeepSeek V4 Pro"),
	}
}

// deepSeekModel constructs one dual-mode DeepSeek text model from shared official limits.
// deepSeekModel 使用共享官方限制构造一个双模式 DeepSeek 文本模型。
func deepSeekModel(upstreamID string, displayName string) systemModelTemplate {
	return systemModelTemplate{
		upstreamID:              upstreamID,
		displayName:             displayName,
		contextWindow:           deepSeekContextWindow,
		maxInputTokens:          deepSeekRecommendedMaxInputTokens,
		maxOutputTokens:         deepSeekMaximumOutputTokens,
		recommendedOutputTokens: deepSeekRecommendedOutputTokens,
		inputModalities:         []string{"text"},
		reasoning:               catalog.CapabilityNative,
		reasoningEfforts:        []string{"high", "max"},
		toolCalling:             catalog.CapabilityNative,
		parallelTools:           catalog.CapabilityUnknown,
		streamingTools:          catalog.CapabilityUnknown,
		strictSchema:            catalog.CapabilityUnknown,
		entitlementMode:         catalog.EntitlementAllBoundCredentials,
	}
}
