package bootstrap

import (
	"errors"
	"testing"

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

// TestRegisterProtocolProfilesRegistersOnlySupportedCustomProfiles verifies management receives the exact first-phase protocol vocabulary.
// TestRegisterProtocolProfilesRegistersOnlySupportedCustomProfiles 验证管理面获得精确的第一阶段协议词汇。
func TestRegisterProtocolProfilesRegistersOnlySupportedCustomProfiles(t *testing.T) {
	// registry receives immutable process-owned protocol metadata.
	// registry 接收不可变的进程拥有协议元数据。
	registry := providerconfig.NewProtocolRegistry()
	if errRegister := RegisterProtocolProfiles(registry); errRegister != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errRegister)
	}
	// profiles records the stable sorted registration snapshot.
	// profiles 记录稳定排序后的注册快照。
	profiles := registry.List()
	if len(profiles) != 54 {
		t.Fatalf("registered profile count = %d, want 54", len(profiles))
	}
	// expectedIDs preserves the public management identifiers without exposing upstream compatibility endpoints.
	// expectedIDs 保留公开管理标识而不暴露上游兼容端点。
	expectedIDs := []string{provideralibaba.SpeechTranscribeAsyncProtocolProfileID, provideralibaba.EmbeddingProtocolProfileID, provideralibaba.ImageEditProtocolProfileID, provideralibaba.ImageGenerateProtocolProfileID, provideralibaba.SpeechTranscribeProtocolProfileID, provideralibaba.SpeechSynthesizeProtocolProfileID, provideralibaba.WanImageEditProtocolProfileID, provideralibaba.WanImageGenerateProtocolProfileID, provideralibaba.WanVideoGenerateProtocolProfileID, messages.ProfileID, provideranthropic.SearchProtocolProfileID, aistudio.ProfileID, providergoogle.EmbeddingProtocolProfileID, providergoogle.MediaAnalyzeProtocolProfileID, antigravity.ProfileID, interactions.ProfileID, providergoogle.SearchProtocolProfileID, providergoogle.ImageEditProtocolProfileID, providergoogle.ImageGenerateProtocolProfileID, providergoogle.SpeechSynthesizeProtocolProfileID, providergoogle.VideoExtendProtocolProfileID, providergoogle.VideoGenerateProtocolProfileID, providerminimax.SearchWebProtocolProfileID, providerminimax.MediaAnalyzeProtocolProfileID, providerminimax.ImageGenerateProtocolProfileID, providerminimax.MusicCoverPrepareProtocolProfileID, providerminimax.MusicCoverProtocolProfileID, providerminimax.MusicGenerateProtocolProfileID, providerminimax.SpeechSynthesizeProtocolProfileID, providerminimax.SpeechSynthesizeAsyncProtocolProfileID, providerminimax.VideoGenerateProtocolProfileID, provideropenai.SpeechSynthesizeProtocolProfileID, provideropenai.SpeechTranscribeProtocolProfileID, chat.ProfileID, codex.ProfileID, provideropenai.EmbeddingProtocolProfileID, provideropenai.ImageEditProtocolProfileID, provideropenai.ImageGenerateProtocolProfileID, openairesponses.ProfileID, provideropenai.SearchProtocolProfileID, provideropenrouter.SpeechSynthesizeProtocolProfileID, provideropenrouter.SpeechTranscribeProtocolProfileID, provideropenrouter.EmbeddingProtocolProfileID, provideropenrouter.ImageGenerateProtocolProfileID, provideropenrouter.RerankProtocolProfileID, provideropenrouter.VideoGenerateProtocolProfileID, providertavily.ProtocolProfileID, providerxai.ImageEditProtocolProfileID, providerxai.ImageGenerateProtocolProfileID, xairesponses.ProfileID, providerxai.SearchProtocolProfileID, providerxai.VideoEditProtocolProfileID, providerxai.VideoExtendProtocolProfileID, providerxai.VideoGenerateProtocolProfileID}
	for index, expectedID := range expectedIDs {
		if profiles[index].ID != expectedID {
			t.Fatalf("profile[%d].ID = %q, want %q", index, profiles[index].ID, expectedID)
		}
		if !profiles[index].RuntimeReady {
			t.Fatalf("profile[%d] must be runtime ready: %#v", index, profiles[index])
		}
		if profiles[index].ModelDiscovery != providerconfig.SupportUnsupported {
			t.Fatalf("profile[%d].ModelDiscovery = %q, want unsupported", index, profiles[index].ModelDiscovery)
		}
	}
	// customProfiles is the exact new-provider selection set exposed by management.
	// customProfiles 是管理面公开的精确新增供应商选择集合。
	customProfiles := map[string]providerconfig.AuthMethodType{
		chat.ProfileID:            providerconfig.AuthMethodBearer,
		openairesponses.ProfileID: providerconfig.AuthMethodBearer,
		messages.ProfileID:        providerconfig.AuthMethodHeaderKey,
	}
	// compatibleProfiles includes the hidden legacy Vertex custom shape that must remain loadable but cannot be newly selected.
	// compatibleProfiles 包含必须保持可加载但不可新增选择的旧版 Vertex 自定义形态。
	compatibleProfiles := map[string]struct{}{chat.ProfileID: {}, openairesponses.ProfileID: {}, messages.ProfileID: {}, aistudio.ProfileID: {}}
	for _, profile := range profiles {
		expectedAuth, custom := customProfiles[profile.ID]
		if profile.UserConfigurable != custom {
			t.Fatalf("profile %q UserConfigurable = %v, want %v", profile.ID, profile.UserConfigurable, custom)
		}
		if custom {
			if len(profile.AllowedAuthMethods) != 1 || profile.AllowedAuthMethods[0] != expectedAuth {
				t.Fatalf("profile %q AllowedAuthMethods = %#v, want only %q", profile.ID, profile.AllowedAuthMethods, expectedAuth)
			}
		} else if profile.ID != aistudio.ProfileID && len(profile.AllowedAuthMethods) != 0 {
			t.Fatalf("non-custom profile %q exposes auth methods %#v", profile.ID, profile.AllowedAuthMethods)
		}
		_, compatible := compatibleProfiles[profile.ID]
		if profile.CustomDefinitionCompatible != compatible {
			t.Fatalf("profile %q CustomDefinitionCompatible = %v, want %v", profile.ID, profile.CustomDefinitionCompatible, compatible)
		}
	}
}

// TestRegisterProtocolProfilesRejectsDuplicateOwnership verifies startup cannot silently replace process-owned protocol semantics.
// TestRegisterProtocolProfilesRejectsDuplicateOwnership 验证启动过程不能静默替换进程拥有的协议语义。
func TestRegisterProtocolProfilesRejectsDuplicateOwnership(t *testing.T) {
	// registry receives the first immutable protocol registration set.
	// registry 接收第一组不可变协议注册。
	registry := providerconfig.NewProtocolRegistry()
	if errRegister := RegisterProtocolProfiles(registry); errRegister != nil {
		t.Fatalf("first RegisterProtocolProfiles() error = %v", errRegister)
	}
	// errRegister records duplicate ownership reported by the protocol registry.
	// errRegister 记录协议注册表报告的重复归属。
	errRegister := RegisterProtocolProfiles(registry)
	if !errors.Is(errRegister, providerconfig.ErrAlreadyRegistered) {
		t.Fatalf("second RegisterProtocolProfiles() error = %v, want ErrAlreadyRegistered", errRegister)
	}
}
