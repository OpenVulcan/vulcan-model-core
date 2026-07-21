// Package bootstrap registers process-wide immutable protocol metadata.
// Package bootstrap 注册进程范围内不可变的协议元数据。
package bootstrap

import (
	"errors"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/anthropic/messages"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/antigravity"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/interactions"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/codex"
	openairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	xairesponses "github.com/OpenVulcan/vulcan-model-core/internal/protocol/xai/responses"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	provideropenrouter "github.com/OpenVulcan/vulcan-model-core/internal/provider/openrouter"
	providertavily "github.com/OpenVulcan/vulcan-model-core/internal/provider/tavily"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// RegisterProtocolProfiles registers the versioned first-phase upstream protocols implemented in this process.
// RegisterProtocolProfiles 注册此进程实现的第一阶段版本化上游协议。
func RegisterProtocolProfiles(registry *providerconfig.ProtocolRegistry) error {
	if registry == nil {
		return errors.New("protocol registry is required")
	}
	// profiles intentionally publish no profile-global advanced capability claims because those facts are target-specific.
	// profiles 有意不发布 Profile 全局高级能力声明，因为这些事实取决于精确 Target。
	profiles := []providerconfig.ProtocolProfile{
		{
			ID:                         chat.ProfileID,
			Version:                    "1",
			DisplayName:                "OpenAI Chat Completions",
			UserConfigurable:           true,
			CustomDefinitionCompatible: true,
			RuntimeReady:               true,
			ModelDiscovery:             providerconfig.SupportUnsupported,
			AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
		},
		{
			ID:                         openairesponses.ProfileID,
			Version:                    "1",
			DisplayName:                "OpenAI Responses",
			UserConfigurable:           true,
			CustomDefinitionCompatible: true,
			RuntimeReady:               true,
			ModelDiscovery:             providerconfig.SupportUnsupported,
			AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
		},
		{
			ID:                 xairesponses.ProfileID,
			Version:            "1",
			DisplayName:        "xAI Responses",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                         aistudio.ProfileID,
			Version:                    "1",
			DisplayName:                "Gemini GenerateContent (AI Studio / Vertex-compatible)",
			UserConfigurable:           false,
			CustomDefinitionCompatible: true,
			RuntimeReady:               true,
			ModelDiscovery:             providerconfig.SupportUnsupported,
			AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodHeaderKey},
		},
		{
			ID:                         messages.ProfileID,
			Version:                    "1",
			DisplayName:                "Anthropic Messages",
			UserConfigurable:           true,
			CustomDefinitionCompatible: true,
			RuntimeReady:               true,
			ModelDiscovery:             providerconfig.SupportUnsupported,
			AllowedAuthMethods:         []providerconfig.AuthMethodType{providerconfig.AuthMethodHeaderKey},
		},
		{
			ID:                 codex.ProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Codex",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 interactions.ProfileID,
			Version:            "1",
			DisplayName:        "Google Interactions",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 antigravity.ProfileID,
			Version:            "1",
			DisplayName:        "Google Antigravity",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.EmbeddingProtocolProfileID,
			Version:            "1",
			DisplayName:        "Alibaba Model Studio Embeddings",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideranthropic.SearchProtocolProfileID,
			Version:            "2025-03-05",
			DisplayName:        "Anthropic Messages Web Search 2025-03-05",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providertavily.ProtocolProfileID,
			Version:            "1",
			DisplayName:        "Tavily Search API",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.EmbeddingProtocolProfileID,
			Version:            "1",
			DisplayName:        "Google AI Studio Embeddings",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.MediaAnalyzeProtocolProfileID,
			Version:            "1",
			DisplayName:        "Google AI Studio Media Analysis",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID: providergoogle.VideoGenerateProtocolProfileID, Version: "3.1", DisplayName: "Google Veo Video Generation", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: providergoogle.VideoExtendProtocolProfileID, Version: "3.1", DisplayName: "Google Veo Video Extension", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.SearchProtocolProfileID,
			Version:            "v1beta",
			DisplayName:        "Google Interactions Search Grounding",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.ImageGenerateProtocolProfileID,
			Version:            "v1beta",
			DisplayName:        "Google Interactions Image Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.ImageEditProtocolProfileID,
			Version:            "v1beta",
			DisplayName:        "Google Interactions Image Editing",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providergoogle.SpeechSynthesizeProtocolProfileID,
			Version:            "v1beta",
			DisplayName:        "Google Interactions Speech Synthesis",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.ImageGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "Alibaba Qwen Image Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.ImageEditProtocolProfileID,
			Version:            "1",
			DisplayName:        "Alibaba Qwen Image Editing",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.WanImageGenerateProtocolProfileID,
			Version:            "2.7",
			DisplayName:        "Alibaba Wan 2.7 Image Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.WanImageEditProtocolProfileID,
			Version:            "2.7",
			DisplayName:        "Alibaba Wan 2.7 Image Editing",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideralibaba.WanVideoGenerateProtocolProfileID,
			Version:            "2.7",
			DisplayName:        "Alibaba Wan 2.7 Video Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID: provideralibaba.SpeechSynthesizeProtocolProfileID, Version: "1", DisplayName: "Alibaba Qwen3-TTS Non-Realtime Speech", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: provideralibaba.SpeechTranscribeProtocolProfileID, Version: "1", DisplayName: "Alibaba Qwen3-ASR Synchronous Transcription", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: provideralibaba.SpeechTranscribeAsyncProtocolProfileID, Version: "1", DisplayName: "Alibaba Fun-ASR Asynchronous Transcription", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID:                 providerminimax.ImageGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "MiniMax Image Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerminimax.VideoGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "MiniMax Video Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerminimax.SpeechSynthesizeProtocolProfileID,
			Version:            "1",
			DisplayName:        "MiniMax Speech Synthesis",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerminimax.SpeechSynthesizeAsyncProtocolProfileID,
			Version:            "1",
			DisplayName:        "MiniMax Long-Text Speech Synthesis",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID: providerminimax.MusicGenerateProtocolProfileID, Version: "1", DisplayName: "MiniMax Music Generation", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: providerminimax.MusicCoverPrepareProtocolProfileID, Version: "1", DisplayName: "MiniMax Music Cover Preparation", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: providerminimax.MusicCoverProtocolProfileID, Version: "1", DisplayName: "MiniMax Prepared Music Cover", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenai.EmbeddingProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Embeddings",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenai.SearchProtocolProfileID,
			Version:            "2025-08-26",
			DisplayName:        "OpenAI Responses Web Search 2025-08-26",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID: provideropenai.SpeechSynthesizeProtocolProfileID, Version: "1", DisplayName: "OpenAI Audio Speech", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: provideropenai.SpeechTranscribeProtocolProfileID, Version: "1", DisplayName: "OpenAI Audio Transcriptions", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenai.ImageGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Image Generation API",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenai.ImageEditProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Image Edit API",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenrouter.EmbeddingProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenRouter Embeddings",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenrouter.RerankProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenRouter Rerank",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenrouter.ImageGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenRouter Image API",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 provideropenrouter.VideoGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "OpenRouter Video API",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID: provideropenrouter.SpeechSynthesizeProtocolProfileID, Version: "1", DisplayName: "OpenRouter Audio Speech", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID: provideropenrouter.SpeechTranscribeProtocolProfileID, Version: "1", DisplayName: "OpenRouter Audio Transcriptions", UserConfigurable: false, RuntimeReady: true, ModelDiscovery: providerconfig.SupportUnsupported, AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.SearchProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Responses Web Search",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.ImageGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Imagine Image Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.ImageEditProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Imagine Image Editing",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.VideoGenerateProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Imagine Video Generation",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.VideoEditProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Imagine Video Editing",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
		{
			ID:                 providerxai.VideoExtendProtocolProfileID,
			Version:            "1",
			DisplayName:        "xAI Imagine Video Extension",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
		},
	}
	for _, profile := range profiles {
		if errRegister := registry.Register(profile); errRegister != nil {
			return fmt.Errorf("register protocol profile %s: %w", profile.ID, errRegister)
		}
	}
	return nil
}
