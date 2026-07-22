package tavily

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestMetadataDriverMapsDocumentedUsageWithoutInventingWindows verifies plan and seven supported credit observations.
// TestMetadataDriverMapsDocumentedUsageWithoutInventingWindows 校验套餐与七项受支持积分观测且不虚构周期。
func TestMetadataDriverMapsDocumentedUsageWithoutInventingWindows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/usage" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"key":{"usage":30,"limit":100,"search_usage":11,"extract_usage":19,"crawl_usage":7},"account":{"current_plan":"Project Plus","plan_usage":40,"plan_limit":200,"paygo_usage":5,"paygo_limit":50,"search_usage":15,"extract_usage":25,"crawl_usage":8}}`)
	}))
	defer server.Close()

	secrets := secret.NewMemoryStore()
	secretReference, errPut := secrets.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_tavily_search_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "search_api", BaseURL: "https://api.tavily.com"}}}
	driver, errDriver := NewMetadataDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewMetadataDriver() error = %v", errDriver)
	}
	driver.baseURL = server.URL
	driver.now = func() time.Time { return time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC) }
	instance := providerconfig.ProviderInstance{ID: "pvi_tavily", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_tavily", ProviderInstanceID: instance.ID, AuthMethodID: "api_key", SecretRef: secretReference}
	metadata, errMetadata := driver.ReadCredentialMetadata(context.Background(), instance, credential)
	if errMetadata != nil {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
	if metadata.Plan == nil || metadata.Plan.PlanCode != "project_plus" || metadata.Plan.PlanName != "Project Plus" || len(metadata.Allowances) != 7 {
		t.Fatalf("metadata = %#v", metadata)
	}
	expectedMetrics := []string{"tavily.key.total", "tavily.account.plan", "tavily.account.paygo", "tavily.key.search", "tavily.key.extract", "tavily.account.search", "tavily.account.extract"}
	for index, allowance := range metadata.Allowances {
		if allowance.Metric != expectedMetrics[index] || allowance.Window != nil || allowance.Scope != catalog.ScopeCredential || allowance.ScopeID != credential.ID {
			t.Fatalf("allowance[%d] = %#v", index, allowance)
		}
	}
	if metadata.Allowances[0].Remaining == nil || *metadata.Allowances[0].Remaining != "70" || metadata.Allowances[3].Used == nil || *metadata.Allowances[3].Used != "11" || metadata.Allowances[3].Limit != nil {
		t.Fatalf("allowances = %#v", metadata.Allowances)
	}
}

// TestMetadataDriverAcceptsNullableIndependentLimits verifies Tavily null key and pay-as-you-go limits remain unbounded observations instead of becoming zero limits.
// TestMetadataDriverAcceptsNullableIndependentLimits 验证 Tavily 的 null Key 与按量付费上限保持为无边界观测，而不会被转换为零上限。
func TestMetadataDriverAcceptsNullableIndependentLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/usage" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"key":{"usage":2,"limit":null,"search_usage":2,"extract_usage":0},"account":{"current_plan":"Researcher","plan_usage":2,"plan_limit":1000,"paygo_usage":0,"paygo_limit":null,"search_usage":2,"extract_usage":0}}`)
	}))
	defer server.Close()

	secrets := secret.NewMemoryStore()
	secretReference, errPut := secrets.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_tavily_search_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "search_api", BaseURL: "https://api.tavily.com"}}}
	driver, errDriver := NewMetadataDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewMetadataDriver() error = %v", errDriver)
	}
	driver.baseURL = server.URL
	driver.now = func() time.Time { return time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC) }
	metadata, errMetadata := driver.ReadCredentialMetadata(context.Background(), providerconfig.ProviderInstance{ID: "pvi_tavily", DefinitionID: definition.ID}, providerconfig.Credential{ID: "cred_tavily", ProviderInstanceID: "pvi_tavily", AuthMethodID: "api_key", SecretRef: secretReference})
	if errMetadata != nil {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
	if metadata.Plan == nil || metadata.Plan.PlanCode != "researcher" || len(metadata.Allowances) != 7 {
		t.Fatalf("metadata = %#v", metadata)
	}
	if metadata.Allowances[0].Limit != nil || metadata.Allowances[0].Remaining != nil || metadata.Allowances[0].Kind != catalog.AllowanceProviderDefined {
		t.Fatalf("key total allowance = %#v", metadata.Allowances[0])
	}
	if metadata.Allowances[1].Limit == nil || *metadata.Allowances[1].Limit != "1000" || metadata.Allowances[1].Remaining == nil || *metadata.Allowances[1].Remaining != "998" {
		t.Fatalf("account plan allowance = %#v", metadata.Allowances[1])
	}
	if metadata.Allowances[2].Limit != nil || metadata.Allowances[2].Remaining != nil || metadata.Allowances[2].Kind != catalog.AllowanceProviderDefined || metadata.Allowances[2].Status != catalog.AllowanceUnlimited {
		t.Fatalf("pay-as-you-go allowance = %#v", metadata.Allowances[2])
	}
}

// TestMetadataDriverClassifiesCredentialRejection verifies authentication failures remain distinguishable from network failures.
// TestMetadataDriverClassifiesCredentialRejection 校验认证失败与网络失败保持可区分。
func TestMetadataDriverClassifiesCredentialRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	secrets := secret.NewMemoryStore()
	secretReference, errPut := secrets.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_tavily_search_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "search_api", BaseURL: "https://api.tavily.com"}}}
	driver, errDriver := NewMetadataDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewMetadataDriver() error = %v", errDriver)
	}
	driver.baseURL = server.URL
	_, errMetadata := driver.ReadCredentialMetadata(context.Background(), providerconfig.ProviderInstance{ID: "pvi_tavily", DefinitionID: definition.ID}, providerconfig.Credential{ID: "cred_tavily", ProviderInstanceID: "pvi_tavily", AuthMethodID: "api_key", SecretRef: secretReference})
	if !errors.Is(errMetadata, provider.ErrMetadataAuthentication) {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
}
