package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestExecutionRegistryDispatchesExactDefinitionAndProfile verifies target-owned Driver selection.
// TestExecutionRegistryDispatchesExactDefinitionAndProfile 验证由 Target 所有的精确 Driver 选择。
func TestExecutionRegistryDispatchesExactDefinitionAndProfile(t *testing.T) {
	registry := NewExecutionRegistry()
	driver := &recordingExecutionDriver{definitionID: "definition-1", profileID: "openai.responses"}
	if errRegister := registry.Register(driver); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	result, errExecute := registry.Execute(context.Background(), validExecutionRequest())
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !driver.executed || result.UpstreamResponseID != "res-upstream" {
		t.Fatalf("driver execution = %v, result = %#v", driver.executed, result)
	}
}

// TestExecutionRequestRejectsChannelProfileMismatch verifies a Driver cannot execute another channel profile.
// TestExecutionRequestRejectsChannelProfileMismatch 验证 Driver 不能执行其他 Channel Profile。
func TestExecutionRequestRejectsChannelProfileMismatch(t *testing.T) {
	request := validExecutionRequest()
	_, errValidate := request.ValidateForProfile("google.aistudio")
	if !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestRejectsForeignContinuation verifies continuation affinity is checked before network execution.
// TestExecutionRequestRejectsForeignContinuation 验证会在网络执行前检查续接亲和性。
func TestExecutionRequestRejectsForeignContinuation(t *testing.T) {
	request := validExecutionRequest()
	request.Request.Context = nil
	request.Request.ReasoningPolicy.ContinuationID = "continuation-1"
	request.Continuation = &ContinuationBinding{
		ContinuationID: "continuation-1", ProviderDefinitionID: "definition-foreign", ProviderInstanceID: "instance-1",
		ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
	}
	_, errValidate := request.ValidateForProfile("openai.responses")
	if !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestAcceptsRemoteCompactionContinuation verifies explicit remote compaction resolves through the same immutable provider binding.
// TestExecutionRequestAcceptsRemoteCompactionContinuation 验证显式远程压缩通过相同不可变 Provider 绑定解析。
func TestExecutionRequestAcceptsRemoteCompactionContinuation(t *testing.T) {
	request := validExecutionRequest()
	request.Request.RemoteCompaction = &vcp.RemoteCompactionRequest{PreviousResponseID: "continuation-1"}
	request.Continuation = &ContinuationBinding{
		ContinuationID: "continuation-1", ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1",
		ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
	}
	if _, errValidate := request.ValidateForProfile("openai.responses"); errValidate != nil {
		t.Fatalf("ValidateForProfile() error = %v", errValidate)
	}
}

// TestExecutionRequestRejectsTargetScopedContinuationDrift verifies a sealed response identifier cannot cross an immutable target's network, credential, or wire-model boundary.
// TestExecutionRequestRejectsTargetScopedContinuationDrift 验证密封响应标识不能跨越不可变 Target 的网络、Credential 或 wire 模型边界。
func TestExecutionRequestRejectsTargetScopedContinuationDrift(t *testing.T) {
	for _, testCase := range []struct {
		// name identifies the exact target-bound continuation field under test.
		// name 标识待测的精确 Target 绑定续接字段。
		name string
		// mutate changes one continuation field away from the resolved target value.
		// mutate 将一条续接字段更改为不同于已解析 Target 的值。
		mutate func(*ContinuationBinding)
	}{
		{name: "endpoint", mutate: func(binding *ContinuationBinding) { binding.EndpointID = "endpoint-foreign" }},
		{name: "credential", mutate: func(binding *ContinuationBinding) { binding.CredentialID = "credential-foreign" }},
		{name: "upstream_model", mutate: func(binding *ContinuationBinding) { binding.UpstreamModelID = "upstream-model-foreign" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := validExecutionRequest()
			request.Request.Context = nil
			request.Request.ReasoningPolicy.ContinuationID = "continuation-1"
			continuation := &ContinuationBinding{
				ContinuationID: "continuation-1", ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1",
				EndpointID: "endpoint-1", CredentialID: "credential-1", ProviderModelID: "model-1", UpstreamModelID: "upstream-model", ExecutionProfileID: "profile-1", UpstreamResponseID: "res-upstream",
			}
			testCase.mutate(continuation)
			request.Continuation = continuation
			if _, errValidate := request.ValidateForProfile("openai.responses"); !errors.Is(errValidate, ErrExecutionBinding) {
				t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
			}
		})
	}
}

// TestExecutionRequestRejectsUndeclaredCredentialAuthMethod verifies a credential cannot select an identifier absent from the immutable definition.
// TestExecutionRequestRejectsUndeclaredCredentialAuthMethod 验证凭据不能选择不可变 Definition 中不存在的认证标识。
func TestExecutionRequestRejectsUndeclaredCredentialAuthMethod(t *testing.T) {
	request := validExecutionRequest()
	request.Definition.AuthMethods = nil
	if _, errValidate := request.ValidateForProfile("openai.responses"); !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// TestExecutionRequestRejectsUnsupportedCredentialAuthType verifies a Driver can reject a declared credential type that its concrete wire carrier cannot encode.
// TestExecutionRequestRejectsUnsupportedCredentialAuthType 验证 Driver 可以拒绝其具体 wire 载体无法编码的已声明凭据类型。
func TestExecutionRequestRejectsUnsupportedCredentialAuthType(t *testing.T) {
	request := validExecutionRequest()
	request.Definition.AuthMethods[0].Type = providerconfig.AuthMethodBearer
	if _, errValidate := request.ValidateForProfile("openai.responses", providerconfig.AuthMethodAPIKey); !errors.Is(errValidate, ErrExecutionBinding) {
		t.Fatalf("ValidateForProfile() error = %v, want ErrExecutionBinding", errValidate)
	}
}

// recordingExecutionDriver records dispatches without performing a network operation.
// recordingExecutionDriver 在不执行网络操作的前提下记录分派。
type recordingExecutionDriver struct {
	// definitionID is the exact provider definition accepted by this test Driver.
	// definitionID 是此测试 Driver 接受的精确供应商 Definition。
	definitionID string
	// profileID is the exact protocol profile accepted by this test Driver.
	// profileID 是此测试 Driver 接受的精确协议 Profile。
	profileID string
	// executed reports whether Execute received a validated request.
	// executed 表示 Execute 是否收到已校验请求。
	executed bool
}

// ProviderDefinitionID returns the test Driver definition ownership.
// ProviderDefinitionID 返回测试 Driver 的 Definition 归属。
func (d *recordingExecutionDriver) ProviderDefinitionID() string {
	return d.definitionID
}

// ProtocolProfileID returns the test Driver protocol ownership.
// ProtocolProfileID 返回测试 Driver 的协议归属。
func (d *recordingExecutionDriver) ProtocolProfileID() string {
	return d.profileID
}

// Execute records a validated request and returns safe mock continuation data.
// Execute 记录已校验请求并返回安全的模拟续接数据。
func (d *recordingExecutionDriver) Execute(_ context.Context, _ ExecutionRequest) (ExecutionResult, error) {
	d.executed = true
	return ExecutionResult{UpstreamResponseID: "res-upstream"}, nil
}

// validExecutionRequest creates a complete executable fixture with exact channel and credential ownership.
// validExecutionRequest 创建具有精确 Channel、Credential 归属的完整可执行夹具。
func validExecutionRequest() ExecutionRequest {
	now := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	return ExecutionRequest{
		Binding: transport.Binding{
			Target: resolve.Target{
				ProviderDefinitionID: "definition-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", EndpointID: "endpoint-1", CredentialID: "credential-1",
				ProviderModelID: "model-1", OfferingID: "offering-1", ExecutionProfileID: "profile-1", UpstreamModelID: "upstream-model",
			},
			Endpoint:   providerconfig.Endpoint{ID: "endpoint-1", ProviderInstanceID: "instance-1", ChannelID: "channel-1", BaseURL: "https://provider.example", Status: providerconfig.EndpointReady},
			Credential: providerconfig.Credential{ID: "credential-1", ProviderInstanceID: "instance-1", AuthMethodID: "api-key", SecretRef: "secret-1", Status: providerconfig.CredentialActive},
		},
		Definition: providerconfig.ProviderDefinition{
			ID: "definition-1", Kind: providerconfig.DefinitionKindSystem,
			ProtocolProfileID: "openai.responses", AuthMethodIDs: []string{"api-key"}, RuntimeReady: true,
			AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "api-key", Type: providerconfig.AuthMethodAPIKey}},
		},
		Request: vcp.VulcanRequest{
			ProtocolVersion: vcp.ProtocolVersion, RequestID: "request-1",
			ModelSelection: vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: "instance-1", ProviderModelID: "model-1", ExecutionProfileID: "profile-1"},
			Context: []vcp.ContextItem{{
				ItemID: "item-user", Sequence: 1, Kind: vcp.ContextMessage, Authority: vcp.AuthorityUser, Actor: vcp.ActorEndUser,
				Placement: vcp.PlacementTranscript, Activation: vcp.Activation{Mode: vcp.ActivationRequestStart}, Visibility: vcp.VisibilityModel,
				Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "Hello"}}, Message: &vcp.MessageItem{},
			}},
			CachePolicy:             vcp.CachePolicy{Strategy: vcp.CacheRegular, OnUnsupported: vcp.CacheUnsupportedReject},
			ContextManagementPolicy: vcp.ContextManagementPolicy{Mode: vcp.ContextManagementRegular},
			CapabilityPolicy:        vcp.CapabilityPolicy{ExecutionMode: vcp.CapabilityMaximize, OptionalOnUnsupported: vcp.OptionalOmit},
		},
		LineageID: "lineage-1", Now: now,
	}
}
