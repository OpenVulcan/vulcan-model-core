package execution

import (
	"context"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// exactPreflightExecutor records native preflight calls and never executes model output.
// exactPreflightExecutor 记录原生预检调用且绝不执行模型输出。
type exactPreflightExecutor struct {
	// preflightCalls counts side-effect-free provider accounting calls.
	// preflightCalls 统计无副作用供应商计量调用。
	preflightCalls int
}

// Execute fails the test contract if a preflight accidentally creates model output.
// Execute 在预检意外创建模型输出时使测试合同失败。
func (e *exactPreflightExecutor) Execute(context.Context, provider.ExecutionRequest) (provider.ExecutionResult, error) {
	return provider.ExecutionResult{}, nil
}

// PreflightUsage returns one exact provider-reported count.
// PreflightUsage 返回一个供应商报告的精确计数。
func (e *exactPreflightExecutor) PreflightUsage(_ context.Context, _ provider.ExecutionRequest) (provider.UsagePreflightResult, error) {
	e.preflightCalls++
	inputTokens := int64(37)
	usage := vcp.UsageObservation{InputTokens: &inputTokens, TotalTokens: &inputTokens, Source: "provider_reported", Aggregation: "snapshot", Phase: "preflight", AccountingBasis: "test_native_counter", Final: true}
	return provider.UsagePreflightResult{Usage: usage, Accuracy: vcp.PreflightExact}, nil
}

// TestServicePreflightUsesExactProviderCounterWithoutExecution verifies accounting resolves one target but creates no execution record.
// TestServicePreflightUsesExactProviderCounterWithoutExecution 验证计量解析一个 Target 但不创建执行记录。
func TestServicePreflightUsesExactProviderCounterWithoutExecution(t *testing.T) {
	now := time.Date(2026, time.July, 21, 18, 0, 0, 0, time.UTC)
	target := failoverTestTarget("credential_preflight", "endpoint_preflight")
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{
		definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID},
		endpoint:   providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
	}
	executor := &exactPreflightExecutor{}
	store := NewMemoryStore()
	service, errService := NewService(store, resolver, configurations, nil, nil, executor, ServiceOptions{Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	executionRequest := failoverTestRequest(target)
	executionRequest.RequestID = "execution_preflight"
	request := vcp.UsagePreflightRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "preflight_test", Execution: executionRequest}
	response, errPreflight := service.Preflight(context.Background(), "api_owner", request)
	if errPreflight != nil {
		t.Fatalf("Preflight() error = %v", errPreflight)
	}
	if executor.preflightCalls != 1 || response.Usage.InputTokens == nil || *response.Usage.InputTokens != 37 || len(response.Metrics) == 0 || response.Metrics[0].Accuracy != vcp.PreflightExact {
		t.Fatalf("preflight response = %#v, calls = %d", response, executor.preflightCalls)
	}
	if records, errDiagnostics := store.ListDiagnostics(context.Background(), 10); errDiagnostics != nil || len(records) != 0 {
		t.Fatalf("preflight created durable executions: records=%#v error=%v", records, errDiagnostics)
	}
}

// TestServicePreflightFallsBackToDisclosedEstimate verifies unsupported native counting never masquerades as exact.
// TestServicePreflightFallsBackToDisclosedEstimate 验证不支持原生计量时绝不会伪装为精确值。
func TestServicePreflightFallsBackToDisclosedEstimate(t *testing.T) {
	now := time.Date(2026, time.July, 21, 18, 30, 0, 0, time.UTC)
	target := failoverTestTarget("credential_estimate", "endpoint_estimate")
	resolver := &staticResolver{target: target}
	configurations := staticConfigurations{definition: providerconfig.ProviderDefinition{ID: target.ProviderDefinitionID}, endpoint: providerconfig.Endpoint{ID: target.EndpointID, ProviderInstanceID: target.ProviderInstanceID, ChannelID: target.ChannelID, BaseURL: "https://provider.example", Region: target.EndpointRegion, Status: providerconfig.EndpointReady}, credential: providerconfig.Credential{ID: target.CredentialID, ProviderInstanceID: target.ProviderInstanceID, Status: providerconfig.CredentialActive}}
	executor := &recordingProviderExecutor{}
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{Now: func() time.Time { return now }, Retention: time.Hour})
	if errService != nil {
		t.Fatalf("NewService() error = %v", errService)
	}
	executionRequest := failoverTestRequest(target)
	executionRequest.RequestID = "execution_estimate"
	response, errPreflight := service.Preflight(context.Background(), "api_owner", vcp.UsagePreflightRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "preflight_estimate", Execution: executionRequest})
	if errPreflight != nil {
		t.Fatalf("Preflight() error = %v", errPreflight)
	}
	if response.Usage.InputTokens == nil || response.Metrics[0].Accuracy != vcp.PreflightEstimated || response.Metrics[0].AccountingBasis != "canonical_json_utf8_bytes_div_4" || executor.calls != 0 {
		t.Fatalf("estimated response = %#v, execute calls = %d", response, executor.calls)
	}
}
