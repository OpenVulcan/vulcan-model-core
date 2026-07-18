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
	if len(profiles) != 8 {
		t.Fatalf("registered profile count = %d, want 8", len(profiles))
	}
	// expectedIDs preserves the public management identifiers without exposing upstream compatibility endpoints.
	// expectedIDs 保留公开管理标识而不暴露上游兼容端点。
	expectedIDs := []string{messages.ProfileID, aistudio.ProfileID, antigravity.ProfileID, interactions.ProfileID, chat.ProfileID, codex.ProfileID, openairesponses.ProfileID, xairesponses.ProfileID}
	for index, expectedID := range expectedIDs {
		if profiles[index].ID != expectedID {
			t.Fatalf("profile[%d].ID = %q, want %q", index, profiles[index].ID, expectedID)
		}
		if !profiles[index].UserConfigurable || !profiles[index].RuntimeReady {
			t.Fatalf("profile[%d] must be user configurable and runtime ready: %#v", index, profiles[index])
		}
		if profiles[index].ModelDiscovery != providerconfig.SupportUnsupported {
			t.Fatalf("profile[%d].ModelDiscovery = %q, want unsupported", index, profiles[index].ModelDiscovery)
		}
		if len(profiles[index].AllowedAuthMethods) != 4 || profiles[index].AllowedAuthMethods[0] != providerconfig.AuthMethodBearer || profiles[index].AllowedAuthMethods[1] != providerconfig.AuthMethodHeaderKey || profiles[index].AllowedAuthMethods[2] != providerconfig.AuthMethodQueryKey || profiles[index].AllowedAuthMethods[3] != providerconfig.AuthMethodNone {
			t.Fatalf("profile[%d].AllowedAuthMethods = %#v, want generic custom authentication methods", index, profiles[index].AllowedAuthMethods)
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
