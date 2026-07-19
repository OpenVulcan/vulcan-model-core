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
			ID:                 chat.ProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Chat Completions",
			UserConfigurable:   true,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodBearer},
		},
		{
			ID:                 openairesponses.ProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Responses",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
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
			ID:                 aistudio.ProfileID,
			Version:            "1",
			DisplayName:        "Gemini GenerateContent (AI Studio / Vertex-compatible)",
			UserConfigurable:   true,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: []providerconfig.AuthMethodType{providerconfig.AuthMethodHeaderKey},
		},
		{
			ID:                 messages.ProfileID,
			Version:            "1",
			DisplayName:        "Anthropic Messages",
			UserConfigurable:   false,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: nil,
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
	}
	for _, profile := range profiles {
		if errRegister := registry.Register(profile); errRegister != nil {
			return fmt.Errorf("register protocol profile %s: %w", profile.ID, errRegister)
		}
	}
	return nil
}
