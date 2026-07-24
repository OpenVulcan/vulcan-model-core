package management

import "github.com/OpenVulcan/vulcan-model-core/internal/catalog"

// copiedModelEvidence contains structured capability facts copied from one CLIProxyAPI models.json record.
// copiedModelEvidence 包含从一条 CLIProxyAPI models.json 记录复制的结构化能力事实。
type copiedModelEvidence struct {
	// maxOutputTokens is max_completion_tokens when the source declares a positive value.
	// maxOutputTokens 是源码声明正值时的 max_completion_tokens。
	maxOutputTokens int64
	// maxReasoningTokens is thinking.max when the source declares a positive value.
	// maxReasoningTokens 是源码声明正值时的 thinking.max。
	maxReasoningTokens int64
	// reasoning records whether a structured thinking object proves native reasoning support.
	// reasoning 记录结构化 thinking 对象是否证明原生推理支持。
	reasoning catalog.CapabilityLevel
	// toolCalling records whether supported_parameters explicitly includes tools.
	// toolCalling 记录 supported_parameters 是否明确包含 tools。
	toolCalling catalog.CapabilityLevel
}

var (
	// copiedModelEvidenceByKey pins source-catalog and model facts from CLIProxyAPI commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
	// copiedModelEvidenceByKey 固定 CLIProxyAPI 提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 的源码目录与模型事实。
	copiedModelEvidenceByKey = map[string]copiedModelEvidence{
		"claude/claude-haiku-4-5-20251001":  {maxOutputTokens: 64000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-sonnet-4-5-20250929": {maxOutputTokens: 64000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-sonnet-4-6":          {maxOutputTokens: 64000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-6":            {maxOutputTokens: 128000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-7":            {maxOutputTokens: 128000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-8":            {maxOutputTokens: 128000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-sonnet-5":            {maxOutputTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-fable-5":             {maxOutputTokens: 128000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-5-20251101":   {maxOutputTokens: 64000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-1-20250805":   {maxOutputTokens: 32000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-opus-4-20250514":     {maxOutputTokens: 32000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-sonnet-4-20250514":   {maxOutputTokens: 64000, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-3-7-sonnet-20250219": {maxOutputTokens: 8192, maxReasoningTokens: 128000, reasoning: catalog.CapabilityNative},
		"claude/claude-3-5-haiku-20241022":  {maxOutputTokens: 8192},

		"aistudio/gemini-2.5-pro":           {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-2.5-flash":         {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-2.5-flash-lite":    {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-3.1-pro-preview":   {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-3-flash-preview":   {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-pro-latest":        {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-flash-latest":      {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-flash-lite-latest": {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"aistudio/gemini-3.5-flash":         {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"gemini/gemini-2.5-pro":             {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"gemini/gemini-2.5-flash":           {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"gemini/gemini-2.5-flash-lite":      {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"gemini/gemini-3.1-pro-preview":     {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"gemini/gemini-3-flash-preview":     {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"gemini/gemini-3.5-flash":           {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"vertex/gemini-2.5-pro":             {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"vertex/gemini-2.5-flash":           {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"vertex/gemini-2.5-flash-lite":      {maxReasoningTokens: 24576, reasoning: catalog.CapabilityNative},
		"vertex/gemini-3-flash-preview":     {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"vertex/gemini-3.1-pro-preview":     {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"vertex/gemini-3.1-flash-lite":      {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"vertex/gemini-3.5-flash":           {maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},

		"antigravity/claude-opus-4-6-thinking":   {maxOutputTokens: 64000, maxReasoningTokens: 64000, reasoning: catalog.CapabilityNative},
		"antigravity/claude-sonnet-4-6":          {maxOutputTokens: 64000, maxReasoningTokens: 64000, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-3-flash":             {maxOutputTokens: 65536, maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-3-flash-agent":       {maxOutputTokens: 65536, maxReasoningTokens: 32768, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-pro-agent":           {maxOutputTokens: 65535, maxReasoningTokens: 65535, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-3.1-pro-low":         {maxOutputTokens: 65535, maxReasoningTokens: 65535, reasoning: catalog.CapabilityNative},
		"antigravity/gpt-oss-120b-medium":        {maxOutputTokens: 32768},
		"antigravity/gemini-3.1-flash-lite":      {maxOutputTokens: 65535, maxReasoningTokens: 65535, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-3.5-flash-low":       {maxOutputTokens: 65535, maxReasoningTokens: 65535, reasoning: catalog.CapabilityNative},
		"antigravity/gemini-3.5-flash-extra-low": {maxOutputTokens: 65535, maxReasoningTokens: 65535, reasoning: catalog.CapabilityNative},

		"xai/grok-build-0.1":               {maxOutputTokens: 256000},
		"xai/grok-4.5":                     {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"xai/grok-4.3":                     {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"xai/grok-4.20-0309-reasoning":     {maxOutputTokens: 65536},
		"xai/grok-4.20-0309-non-reasoning": {maxOutputTokens: 65536, reasoning: catalog.CapabilityUnsupported},
		"xai/grok-4.20-multi-agent-0309":   {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"xai/grok-3-mini":                  {maxOutputTokens: 32768, reasoning: catalog.CapabilityNative},
		"xai/grok-3-mini-fast":             {maxOutputTokens: 32768, reasoning: catalog.CapabilityNative},
		"xai/grok-composer-2.5-fast":       {maxOutputTokens: 32768},

		"kimi/kimi-k2":                  {maxOutputTokens: 32768},
		"kimi/kimi-k2-thinking":         {maxOutputTokens: 32768, reasoning: catalog.CapabilityNative},
		"kimi/kimi-k2.5":                {maxOutputTokens: 32768, reasoning: catalog.CapabilityNative},
		"kimi/kimi-k2.6":                {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"kimi/kimi-k2.7-code":           {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"kimi/kimi-k2.7-code-highspeed": {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
		"kimi/kimi-k3":                  {maxOutputTokens: 65536, reasoning: catalog.CapabilityNative},
	}
)

// copiedModelEvidenceFor returns normalized evidence while preserving unknown capabilities explicitly.
// copiedModelEvidenceFor 返回规范化证据，并显式保留未知能力。
func copiedModelEvidenceFor(sourceCatalogID string, upstreamModelID string) copiedModelEvidence {
	evidence := copiedModelEvidenceByKey[sourceCatalogID+"/"+upstreamModelID]
	if evidence.reasoning == "" {
		evidence.reasoning = catalog.CapabilityUnknown
	}
	if evidence.toolCalling == "" {
		evidence.toolCalling = catalog.CapabilityUnknown
	}
	return evidence
}
