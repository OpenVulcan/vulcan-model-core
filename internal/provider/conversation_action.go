package provider

import (
	"context"
	"fmt"
	"strings"
)

// ConversationActionDriver adapts one proven conversation profile Driver to one immutable ActionBinding.
// ConversationActionDriver 将一个已验证会话 Profile Driver 适配到一个不可变 ActionBinding。
type ConversationActionDriver struct {
	// actionBindingID is the sole action owned by this adapter.
	// actionBindingID 是此适配器唯一拥有的动作。
	actionBindingID string
	// profileDriver is the exact proven upstream conversation implementation.
	// profileDriver 是精确且已验证的上游会话实现。
	profileDriver ExecutionDriver
}

// NewConversationActionDriver creates an action adapter without changing provider wire behavior.
// NewConversationActionDriver 创建一个不改变供应商 wire 行为的动作适配器。
func NewConversationActionDriver(actionBindingID string, profileDriver ExecutionDriver) (*ConversationActionDriver, error) {
	if strings.TrimSpace(actionBindingID) == "" || isNilExecutionDependency(profileDriver) {
		return nil, fmt.Errorf("%w: action binding and profile driver are required", ErrActionExecutionDriverRequired)
	}
	return &ConversationActionDriver{actionBindingID: actionBindingID, profileDriver: profileDriver}, nil
}

// ProviderDefinitionID returns the exact definition owned by the proven Driver.
// ProviderDefinitionID 返回已验证 Driver 拥有的精确 Definition。
func (d *ConversationActionDriver) ProviderDefinitionID() string {
	return d.profileDriver.ProviderDefinitionID()
}

// ActionBindingID returns the sole conversation action binding.
// ActionBindingID 返回唯一会话动作绑定。
func (d *ConversationActionDriver) ActionBindingID() string {
	return d.actionBindingID
}

// Execute converts the validated action envelope and delegates to the unchanged profile Driver.
// Execute 转换已校验动作信封并委派给未改变的 Profile Driver。
func (d *ConversationActionDriver) Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	if request.Execution == nil {
		return ExecutionResult{}, fmt.Errorf("%w: conversation action execution request is required", ErrExecutionBinding)
	}
	conversation, errConversation := request.Execution.ConversationRequest()
	if errConversation != nil {
		return ExecutionResult{}, errConversation
	}
	request.Request = conversation
	request.Execution = nil
	return d.profileDriver.Execute(ctx, request)
}
