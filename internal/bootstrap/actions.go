package bootstrap

import (
	"fmt"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

const (
	// ConversationActionBindingID identifies the established conversation action in every current system definition.
	// ConversationActionBindingID 标识每个当前系统 Definition 中的既有会话动作。
	ConversationActionBindingID = "action_conversation_respond"
)

// withConversationAction attaches one explicit action from the definition's already proven single protocol boundary.
// withConversationAction 根据 Definition 已验证的单协议边界附加一个显式动作。
func withConversationAction(definition providerconfig.ProviderDefinition) (providerconfig.ProviderDefinition, error) {
	for _, action := range definition.ActionBindings {
		if action.ID == ConversationActionBindingID || action.Operation == vcp.OperationConversationRespond {
			return providerconfig.ProviderDefinition{}, fmt.Errorf("provider definition %s already declares conversation action", definition.ID)
		}
	}
	if !definition.RuntimeReady {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("provider definition %s is not executable", definition.ID)
	}
	definition.ActionBindings = append(definition.ActionBindings, providerconfig.ProviderActionBinding{
		ID: ConversationActionBindingID, Operation: vcp.OperationConversationRespond,
		DriverID: definition.DriverID, DriverVersion: definition.DriverVersion, ProtocolProfileID: definition.ProtocolProfileID, EndpointProfileID: definition.EndpointProfileID,
		AuthMethodIDs: append([]string(nil), definition.AuthMethodIDs...), Delivery: providerconfig.ActionDeliveryModes{Synchronous: true, Streaming: true}, Revision: definition.Revision,
	})
	return definition, nil
}

// registerConversationDriver registers both the existing profile boundary and its exact action-bound migration path.
// registerConversationDriver 同时注册既有 Profile 边界及其精确动作绑定迁移路径。
func registerConversationDriver(registry *provider.ExecutionRegistry, driver provider.ExecutionDriver) error {
	if errRegister := registry.Register(driver); errRegister != nil {
		return errRegister
	}
	actionDriver, errAction := provider.NewConversationActionDriver(ConversationActionBindingID, driver)
	if errAction != nil {
		return errAction
	}
	return registry.RegisterAction(actionDriver)
}
