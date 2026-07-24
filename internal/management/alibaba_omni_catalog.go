package management

import (
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// alibabaOmniModels returns the non-realtime Qwen3.5 Omni conversation and dedicated media-analysis profiles verified for regional Model Studio endpoints.
// alibabaOmniModels 返回已为区域 Model Studio 入口验证的非实时 Qwen3.5 Omni 会话与专用媒体分析规格。
func alibabaOmniModels() []systemModelTemplate {
	// variants freezes model-specific function-calling support without broad family inference.
	// variants 冻结模型专属函数调用支持且不进行宽泛家族推断。
	variants := []struct {
		// upstreamID is the exact Model Studio identifier.
		// upstreamID 是精确的 Model Studio 标识。
		upstreamID string
		// displayName is the operator-facing model name.
		// displayName 是面向操作员的模型名称。
		displayName string
		// toolCalling is the exact catalog-evidenced function-calling level.
		// toolCalling 是目录证据确认的精确函数调用等级。
		toolCalling catalog.CapabilityLevel
	}{
		{upstreamID: "qwen3.5-omni-plus", displayName: "Qwen3.5 Omni Plus", toolCalling: catalog.CapabilityNative},
		{upstreamID: "qwen3.5-omni-flash", displayName: "Qwen3.5 Omni Flash", toolCalling: catalog.CapabilityUnsupported},
	}
	models := make([]systemModelTemplate, 0, len(variants)*2)
	for _, variant := range variants {
		// conversation publishes only behavior preserved by the OpenAI Chat projector and the Alibaba adapter.
		// conversation 仅发布 OpenAI Chat 投影器与 Alibaba 适配器可完整保留的行为。
		conversation := systemModelTemplate{
			upstreamID: variant.upstreamID, displayName: variant.displayName,
			contextWindow: 262144, maxInputTokens: 196608, maxOutputTokens: 65536,
			inputModalities: []string{"text", "image", "audio", "video"}, outputModalities: []string{"text", "audio"},
			reasoning: catalog.CapabilityUnsupported, toolCalling: variant.toolCalling, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnknown,
			entitlementMode: catalog.EntitlementAllBoundCredentials, streamingOnly: true,
			standardTools: []catalog.StandardModelToolCapability{{Kind: vcp.StandardModelToolWebSearch, Native: true}}, mediaInputs: alibabaOmniMediaInputs(catalog.MediaInteractionMixedConversation, variant.toolCalling),
			mediaOutputs: []catalog.MediaOutputCapability{alibabaOmniAudioOutputCapability()},
		}
		// analysis exposes media-only task semantics through a frozen Router instruction rather than pretending that an omitted prompt is native.
		// analysis 通过固定 Router 指令公开媒体单独任务语义，而不伪装省略提示词是原生行为。
		analysis := systemModelTemplate{
			upstreamID: variant.upstreamID, displayName: variant.displayName + " Media Analysis",
			contextWindow: 262144, maxInputTokens: 196608, maxOutputTokens: 65536,
			inputModalities: []string{"image", "audio", "video"}, outputModalities: []string{"text"},
			reasoning: catalog.CapabilityUnsupported, toolCalling: catalog.CapabilityUnsupported, parallelTools: catalog.CapabilityUnsupported, streamingTools: catalog.CapabilityUnsupported, strictSchema: catalog.CapabilityUnsupported,
			entitlementMode: catalog.EntitlementAllBoundCredentials, operation: vcp.OperationMediaAnalyze, actionBindingID: provideralibaba.MediaAnalyzeActionBindingID, streamingOnly: true,
			mediaInputs: alibabaOmniMediaInputs(catalog.MediaInteractionAnalysis, catalog.CapabilityUnsupported),
		}
		models = append(models, conversation, analysis)
	}
	return models
}

// alibabaOmniMediaInputs returns the exact image, audio, and video carriers implemented by the Chat projection for one interaction shape.
// alibabaOmniMediaInputs 返回 Chat 投影为一种交互形态实现的精确图片、音频与视频载体。
func alibabaOmniMediaInputs(interaction catalog.MediaInteractionMode, toolCalling catalog.CapabilityLevel) []catalog.MediaInputCapability {
	// evidence points to the official non-realtime Omni contract verified together with the copied Bailian CLI carrier implementation.
	// evidence 指向与复制的 Bailian CLI 载体实现共同核验的官方非实时 Omni 合同。
	evidence := []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-omni", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}
	// common owns only facts shared by every accepted media family.
	// common 仅拥有每种已接受媒体类别共享的事实。
	common := func(kind vcp.MediaKind, mimeTypes []string, workflows []catalog.ClientResourceWorkflow, materializations []catalog.UpstreamMaterializationMode) catalog.MediaInputCapability {
		// mediaOnlyPolicy records the dedicated analysis driver's versioned implicit instruction without changing mixed-conversation semantics.
		// mediaOnlyPolicy 记录专用分析驱动的版本化隐式指令，且不改变混合会话语义。
		mediaOnlyPolicy := catalog.MediaOnlyUnsupported
		if interaction == catalog.MediaInteractionAnalysis {
			mediaOnlyPolicy = catalog.MediaOnlyRouterInstruction
		}
		return catalog.MediaInputCapability{
			Kind: kind, Roles: []vcp.MediaInputRole{vcp.MediaRoleUnderstanding}, Level: catalog.CapabilityNative,
			InteractionModes: []catalog.MediaInteractionMode{interaction}, MediaOnlyPolicy: mediaOnlyPolicy,
			AllowedAuthorities: []vcp.Authority{vcp.AuthorityUser}, AllowedPlacements: []vcp.Placement{vcp.PlacementTranscript},
			ClientWorkflows: append([]catalog.ClientResourceWorkflow(nil), workflows...), MaterializationModes: append([]catalog.UpstreamMaterializationMode(nil), materializations...),
			Common:        catalog.CommonMediaLimits{MIMETypes: append([]string(nil), mimeTypes...), AllowsRemoteURL: catalog.OptionalBool{Known: true, Value: true}},
			Compatibility: catalog.MediaCompatibility{ToolCalling: toolCalling, Streaming: catalog.CapabilityNative, Reasoning: catalog.CapabilityUnsupported, StructuredOutput: catalog.CapabilityUnsupported},
			Evidence:      append([]catalog.CapabilityEvidence(nil), evidence...), EvidenceRevision: 1,
		}
	}
	// inlineWorkflows describe Router-owned byte ingestion before bounded inline projection.
	// inlineWorkflows 描述在受限内联投影前由 Router 管理的字节摄取流程。
	inlineWorkflows := []catalog.ClientResourceWorkflow{catalog.ClientWorkflowUploadThenReference, catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowImportBase64ThenReference, catalog.ClientWorkflowResolveInputPlan}
	// inlineAndURL are the two carriers implemented for image and audio on every verified region.
	// inlineAndURL 是每个已验证区域为图片与音频实现的两种载体。
	inlineAndURL := []catalog.UpstreamMaterializationMode{catalog.MaterializationInlineBase64, catalog.MaterializationDirectRemoteURL}
	image := common(vcp.MediaImage, []string{"image/jpeg", "image/png", "image/webp"}, inlineWorkflows, inlineAndURL)
	image.Image = &catalog.ImageMediaLimits{}
	audio := common(vcp.MediaAudio, []string{"audio/wav", "audio/x-wav", "audio/mpeg", "audio/mp3", "audio/amr", "audio/aac", "audio/mp4", "audio/x-m4a", "audio/ogg", "audio/3gpp"}, inlineWorkflows, inlineAndURL)
	audio.Audio = &catalog.AudioMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 10800000}, Encodings: []string{"wav", "mp3", "amr", "aac", "ogg", "3gpp"}}
	video := common(vcp.MediaVideo, []string{"video/mp4", "video/x-msvideo", "video/x-matroska", "video/quicktime", "video/x-flv", "video/x-ms-wmv"}, []catalog.ClientResourceWorkflow{catalog.ClientWorkflowImportURLThenReference, catalog.ClientWorkflowResolveInputPlan}, []catalog.UpstreamMaterializationMode{catalog.MaterializationDirectRemoteURL})
	video.Video = &catalog.VideoMediaLimits{MaxDurationMilliseconds: catalog.OptionalLimit{Known: true, Value: 3600000}, Containers: []string{"mp4", "avi", "mkv", "mov", "flv", "wmv"}, EmbeddedAudio: catalog.OptionalBool{Known: true, Value: true}}
	return []catalog.MediaInputCapability{image, audio, video}
}

// alibabaOmniAudioOutputCapability returns the verified streaming PCM-to-WAV conversation output contract.
// alibabaOmniAudioOutputCapability 返回已验证的流式 PCM 到 WAV 会话输出合同。
func alibabaOmniAudioOutputCapability() catalog.MediaOutputCapability {
	return catalog.MediaOutputCapability{
		Kind: vcp.MediaAudio, Level: catalog.CapabilityNative, Formats: []string{"wav"}, MaxOutputs: catalog.OptionalLimit{Known: true, Value: 1},
		Audio:    &catalog.AudioMediaLimits{MaxSampleRateHz: catalog.OptionalLimit{Known: true, Value: 24000}, MaxChannels: catalog.OptionalLimit{Known: true, Value: 1}, Encodings: []string{"pcm_s16le"}},
		Delivery: catalog.DeliveryCapabilities{Streaming: true},
		Evidence: []catalog.CapabilityEvidence{{Source: catalog.ModelSourceProviderAPI, Reference: "https://www.alibabacloud.com/help/en/model-studio/qwen-omni", ObservedAt: mediaEvidenceObservedAt(), Revision: 1}}, EvidenceRevision: 1,
	}
}
