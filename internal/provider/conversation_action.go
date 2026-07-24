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
	projected, errProject := d.projectActionRequest(request)
	if errProject != nil {
		return ExecutionResult{}, errProject
	}
	return d.profileDriver.Execute(ctx, projected)
}

// PreflightUsage converts the action envelope and delegates only when the proven profile owns a native counter.
// PreflightUsage 转换动作信封，并且仅在已验证 Profile 拥有原生计量器时委派。
func (d *ConversationActionDriver) PreflightUsage(ctx context.Context, request ExecutionRequest) (UsagePreflightResult, error) {
	counter, supported := d.profileDriver.(UsagePreflightDriver)
	if !supported {
		return UsagePreflightResult{}, fmt.Errorf("%w: conversation profile has no native usage preflight", ErrExecutionDriverNotFound)
	}
	projected, errProject := d.projectActionRequest(request)
	if errProject != nil {
		return UsagePreflightResult{}, errProject
	}
	return counter.PreflightUsage(ctx, projected)
}

// projectActionRequest validates the immutable action before projecting its conversation onto the proven legacy profile boundary.
// projectActionRequest 在把会话投影到已验证旧版 Profile 边界前校验不可变动作。
func (d *ConversationActionDriver) projectActionRequest(request ExecutionRequest) (ExecutionRequest, error) {
	if request.Execution == nil {
		return ExecutionRequest{}, fmt.Errorf("%w: conversation action execution request is required", ErrExecutionBinding)
	}
	action, errAction := request.ValidateForAction(d.actionBindingID)
	if errAction != nil {
		return ExecutionRequest{}, errAction
	}
	if action.ProtocolProfileID != d.profileDriver.ProtocolProfileID() {
		return ExecutionRequest{}, fmt.Errorf("%w: conversation action protocol does not match the proven profile driver", ErrExecutionBinding)
	}
	conversation, errConversation := request.Execution.ConversationRequest()
	if errConversation != nil {
		return ExecutionRequest{}, errConversation
	}
	request.Request = conversation
	request.Execution = nil
	request.Definition.ProtocolProfileID = action.ProtocolProfileID
	request.Definition.EndpointProfileID = action.EndpointProfileID
	request.Definition.AuthMethodIDs = append([]string(nil), action.AuthMethodIDs...)
	return request, nil
}
