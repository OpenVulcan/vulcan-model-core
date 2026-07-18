package management

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// systemModelTemplate contains code-owned facts shared across instance-isolated catalog records.
// systemModelTemplate 包含在实例隔离目录记录之间共享的代码拥有事实。
type systemModelTemplate struct {
	upstreamID      string
	displayName     string
	contextWindow   int64
	inputModalities []string
	reasoning       catalog.CapabilityLevel
	toolCalling     catalog.CapabilityLevel
	parallelTools   catalog.CapabilityLevel
	streamingTools  catalog.CapabilityLevel
	strictSchema    catalog.CapabilityLevel
	entitlementMode catalog.EntitlementMode
}

// buildSystemCatalog materializes one immutable template into records owned only by the new instance.
// buildSystemCatalog 将一个不可变模板实例化为仅由新实例拥有的记录。
func buildSystemCatalog(onboarding providerconfig.SystemOnboarding, definition providerconfig.ProviderDefinition, observedAt time.Time) (catalog.Snapshot, error) {
	templates, errTemplates := systemModelTemplates(definition.ModelCatalogID)
	if errTemplates != nil {
		return catalog.Snapshot{}, errTemplates
	}
	snapshot := catalog.Snapshot{ProviderInstanceID: onboarding.Instance.ID, Revision: 1, ObservedAt: observedAt}
	for _, template := range templates {
		modelSuffix := catalogIdentifier(template.upstreamID)
		modelID := "model_" + modelSuffix
		snapshot.Models = append(snapshot.Models, catalog.ProviderModel{ID: modelID, ProviderInstanceID: onboarding.Instance.ID, UpstreamModelID: template.upstreamID, DisplayName: template.displayName, Source: catalog.ModelSourceSystem, EntitlementMode: template.entitlementMode, Revision: 1})
		for _, channel := range definition.Channels {
			offeringID := "offer_" + modelSuffix + "_" + channel.ID
			capabilities := systemModelCapabilities(template)
			snapshot.Offerings = append(snapshot.Offerings, catalog.ModelOffering{ID: offeringID, ProviderInstanceID: onboarding.Instance.ID, ProviderModelID: modelID, ChannelID: channel.ID, UpstreamModelID: template.upstreamID, Capabilities: capabilities, CapabilityRevision: 1, Revision: 1})
			snapshot.Profiles = append(snapshot.Profiles, catalog.ExecutionProfile{ID: "profile_" + modelSuffix + "_" + channel.ID, ProviderInstanceID: onboarding.Instance.ID, OfferingID: offeringID, DisplayName: template.displayName, Default: true, Capabilities: capabilities, SwitchPolicy: catalog.ProfileSwitchReplayRequired, PoolPolicy: catalog.PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1})
		}
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate system provider catalog: %w", errValidate)
	}
	return snapshot, nil
}

// systemModelTemplates returns the exact current code-owned model set for one registered catalog identifier.
// systemModelTemplates 返回一个已注册目录标识的精确当前代码拥有模型集合。
func systemModelTemplates(catalogID string) ([]systemModelTemplate, error) {
	switch catalogID {
	case "kimi_open_platform":
		return kimiOpenPlatformModels(), nil
	case "kimi_coding":
		return kimiCodingModels(), nil
	default:
		return nil, fmt.Errorf("system provider model catalog %q is not registered", catalogID)
	}
}

// kimiOpenPlatformModels returns current non-retired models documented by the Kimi API Open Platform.
// kimiOpenPlatformModels 返回 Kimi API 开放平台当前记录且未退役的模型。
func kimiOpenPlatformModels() []systemModelTemplate {
	allBound := catalog.EntitlementAllBoundCredentials
	return []systemModelTemplate{
		{upstreamID: "kimi-k3", displayName: "Kimi K3", contextWindow: 1048576, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityNative, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code", displayName: "Kimi K2.7 Code", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.7-code-highspeed", displayName: "Kimi K2.7 Code HighSpeed", contextWindow: 262144, inputModalities: []string{"text", "image", "video"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.6", displayName: "Kimi K2.6", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: allBound},
		{upstreamID: "kimi-k2.5", displayName: "Kimi K2.5", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k", displayName: "Moonshot V1 8K", contextWindow: 8192, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k", displayName: "Moonshot V1 32K", contextWindow: 32768, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k", displayName: "Moonshot V1 128K", contextWindow: 131072, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-8k-vision-preview", displayName: "Moonshot V1 8K Vision", contextWindow: 8192, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-32k-vision-preview", displayName: "Moonshot V1 32K Vision", contextWindow: 32768, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "moonshot-v1-128k-vision-preview", displayName: "Moonshot V1 128K Vision", contextWindow: 131072, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnknown, parallelTools: catalog.CapabilityUnknown, streamingTools: catalog.CapabilityUnknown, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
	}
}

// kimiCodingModels returns the three current model identifiers documented for Coding Plan integrations.
// kimiCodingModels 返回 Coding Plan 集成文档记录的三个当前模型标识。
func kimiCodingModels() []systemModelTemplate {
	return []systemModelTemplate{
		{upstreamID: "k3", displayName: "Kimi K3", contextWindow: 262144, inputModalities: []string{"text", "image"}, reasoning: catalog.CapabilityNative, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityNative, entitlementMode: catalog.EntitlementExplicit},
		{upstreamID: "kimi-for-coding", displayName: "Kimi K2.7 Code", contextWindow: 262144, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementAllBoundCredentials},
		{upstreamID: "kimi-for-coding-highspeed", displayName: "Kimi K2.7 Code HighSpeed", contextWindow: 262144, inputModalities: []string{"text"}, reasoning: catalog.CapabilityUnknown, toolCalling: catalog.CapabilityNative, parallelTools: catalog.CapabilityNative, streamingTools: catalog.CapabilityNative, strictSchema: catalog.CapabilityUnknown, entitlementMode: catalog.EntitlementExplicit},
	}
}

// systemModelCapabilities constructs one closed capability set without inferring undocumented output limits.
// systemModelCapabilities 构建一组封闭能力且不推断未记录输出限制。
func systemModelCapabilities(template systemModelTemplate) catalog.ModelCapabilities {
	return catalog.ModelCapabilities{Tokens: catalog.TokenLimits{ContextWindow: catalog.OptionalTokenLimit{Known: true, Value: template.contextWindow}}, ToolCalling: template.toolCalling, ParallelToolCalls: template.parallelTools, StreamingToolArguments: template.streamingTools, StrictJSONSchema: template.strictSchema, Reasoning: template.reasoning, InputModalities: append([]string(nil), template.inputModalities...), OutputModalities: []string{"text"}}
}

// catalogIdentifier converts one trusted upstream model identifier to the portable catalog identifier alphabet.
// catalogIdentifier 将一个受信任上游模型标识转换为可移植目录标识字母表。
func catalogIdentifier(value string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}
