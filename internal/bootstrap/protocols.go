// Package bootstrap registers process-wide immutable protocol metadata.
// Package bootstrap 注册进程范围内不可变的协议元数据。
package bootstrap

import (
	"errors"
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/google/aistudio"
	"github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/chat"
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
			AllowedAuthMethods: genericCustomAuthMethods(),
		},
		{
			ID:                 openairesponses.ProfileID,
			Version:            "1",
			DisplayName:        "OpenAI Responses",
			UserConfigurable:   true,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: genericCustomAuthMethods(),
		},
		{
			ID:                 xairesponses.ProfileID,
			Version:            "1",
			DisplayName:        "xAI Responses",
			UserConfigurable:   true,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: genericCustomAuthMethods(),
		},
		{
			ID:                 aistudio.ProfileID,
			Version:            "1",
			DisplayName:        "Google AI Studio GenerateContent",
			UserConfigurable:   true,
			RuntimeReady:       true,
			ModelDiscovery:     providerconfig.SupportUnsupported,
			AllowedAuthMethods: genericCustomAuthMethods(),
		},
	}
	for _, profile := range profiles {
		if errRegister := registry.Register(profile); errRegister != nil {
			return fmt.Errorf("register protocol profile %s: %w", profile.ID, errRegister)
		}
	}
	return nil
}

// genericCustomAuthMethods returns exactly the generic credential mechanisms accepted by custom-definition validation.
// genericCustomAuthMethods 返回自定义定义校验接受的精确通用凭据机制。
func genericCustomAuthMethods() []providerconfig.AuthMethodType {
	return []providerconfig.AuthMethodType{
		providerconfig.AuthMethodBearer,
		providerconfig.AuthMethodHeaderKey,
		providerconfig.AuthMethodQueryKey,
		providerconfig.AuthMethodNone,
	}
}
