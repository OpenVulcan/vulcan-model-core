package management

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAlibabaFunASRCatalogPublishesURLOnlyAudioAndVideoContract verifies the executable task and client workflow remain aligned.
// TestAlibabaFunASRCatalogPublishesURLOnlyAudioAndVideoContract 验证可执行任务与客户端工作流保持一致。
func TestAlibabaFunASRCatalogPublishesURLOnlyAudioAndVideoContract(t *testing.T) {
	// template is the exact stable Fun-ASR catalog record.
	// template 是精确的稳定版 Fun-ASR 目录记录。
	template := alibabaFunASRModel()
	if template.upstreamID != "fun-asr" || template.operation != vcp.OperationSpeechTranscribe || template.actionBindingID != provideralibaba.SpeechTranscribeAsyncActionBindingID || len(template.mediaInputs) != 2 || len(template.parameters) != 6 || len(template.parameterRules) != 1 {
		t.Fatalf("Fun-ASR template = %#v", template)
	}
	for _, input := range template.mediaInputs {
		if input.Roles[0] != vcp.MediaRoleTranscriptionSource || len(input.ClientWorkflows) != 2 || input.ClientWorkflows[0] != catalog.ClientWorkflowImportURLThenReference || len(input.MaterializationModes) != 1 || input.MaterializationModes[0] != catalog.MaterializationDirectRemoteURL || !input.Common.AllowsRemoteURL.Known || !input.Common.AllowsRemoteURL.Value || input.Common.MaxItemBytes.Value != 2<<30 || input.Common.MaxItems.Value != 100 {
			t.Fatalf("Fun-ASR input = %#v", input)
		}
		switch input.Kind {
		case vcp.MediaAudio:
			if input.Audio == nil || input.Audio.MaxDurationMilliseconds.Value != 12*60*60*1000 || len(input.Common.MIMETypes) != 9 {
				t.Fatalf("Fun-ASR audio input = %#v", input)
			}
		case vcp.MediaVideo:
			if input.Video == nil || input.Video.MaxDurationMilliseconds.Value != 12*60*60*1000 || !input.Video.EmbeddedAudio.Value || len(input.Common.MIMETypes) != 8 {
				t.Fatalf("Fun-ASR video input = %#v", input)
			}
		default:
			t.Fatalf("unexpected Fun-ASR input kind = %q", input.Kind)
		}
	}
}

// TestAlibabaCosyVoiceCatalogPreservesRegionalModelsAndCompleteControls verifies regional publication and copied CLI parameters.
// TestAlibabaCosyVoiceCatalogPreservesRegionalModelsAndCompleteControls 验证区域发布及复制的 CLI 完整参数。
func TestAlibabaCosyVoiceCatalogPreservesRegionalModelsAndCompleteControls(t *testing.T) {
	cnModels := alibabaCosyVoiceModels(true)
	singaporeModels := alibabaCosyVoiceModels(false)
	if len(cnModels) != 5 || len(singaporeModels) != 2 || cnModels[0].upstreamID != "cosyvoice-v2" || singaporeModels[0].upstreamID != "cosyvoice-v3-flash" {
		t.Fatalf("CosyVoice regional models = CN:%#v Singapore:%#v", cnModels, singaporeModels)
	}
	for _, model := range append(cnModels, singaporeModels...) {
		if model.operation != vcp.OperationSpeechSynthesize || model.actionBindingID != provideralibaba.CosyVoiceSynthesizeActionBindingID || len(model.parameters) != 11 || len(model.mediaOutputs) != 1 || !model.mediaOutputs[0].Delivery.Synchronous || !model.mediaOutputs[0].Delivery.Streaming {
			t.Fatalf("CosyVoice model = %#v", model)
		}
	}
}
