package google

import (
	"context"
	"encoding/json"
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

// TestAntigravityCatalogDriverDefinitionIsMutationSafe verifies the immutable driver contract across constructor and accessor boundaries.
// TestAntigravityCatalogDriverDefinitionIsMutationSafe 验证构造器与访问器边界上的不可变 Driver 合同。
func TestAntigravityCatalogDriverDefinitionIsMutationSafe(t *testing.T) {
	definition := providerconfig.ProviderDefinition{
		ID:              "system_google_antigravity",
		AuthMethodIDs:   []string{"oauth"},
		AuthMethods:     []providerconfig.AuthMethodDefinition{{ID: "oauth"}},
		EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: "https://cloudcode-pa.googleapis.com"}},
	}
	driver, errDriver := NewAntigravityCatalogDriver(definition, secret.NewMemoryStore(), &http.Client{})
	if errDriver != nil {
		t.Fatalf("NewAntigravityCatalogDriver() error = %v", errDriver)
	}
	definition.AuthMethodIDs[0] = "mutated"
	definition.AuthMethods[0].ID = "mutated"
	definition.EndpointPresets[0].BaseURL = "https://mutated.example"
	first := driver.Definition()
	if first.AuthMethodIDs[0] != "oauth" || first.AuthMethods[0].ID != "oauth" || first.EndpointPresets[0].BaseURL != "https://cloudcode-pa.googleapis.com" {
		t.Fatalf("driver definition changed through constructor input: %+v", first)
	}
	first.AuthMethodIDs[0] = "mutated-again"
	if second := driver.Definition(); second.AuthMethodIDs[0] != "oauth" {
		t.Fatalf("driver definition changed through accessor result: %+v", second)
	}
}

// TestAntigravityCatalogDriverRefusesRedirectsWithoutMutatingCaller verifies catalog bearer tokens cannot cross redirect boundaries.
// TestAntigravityCatalogDriverRefusesRedirectsWithoutMutatingCaller 验证目录 Bearer Token 不能跨越重定向边界。
func TestAntigravityCatalogDriverRefusesRedirectsWithoutMutatingCaller(t *testing.T) {
	callerRedirectError := errors.New("caller redirect policy")
	caller := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return callerRedirectError }}
	definition := providerconfig.ProviderDefinition{ID: "system_google_antigravity", EndpointPresets: []providerconfig.EndpointPreset{{BaseURL: "https://cloudcode-pa.googleapis.com"}}}
	driver, errDriver := NewAntigravityCatalogDriver(definition, secret.NewMemoryStore(), caller)
	if errDriver != nil {
		t.Fatalf("NewAntigravityCatalogDriver() error = %v", errDriver)
	}
	if driver.client == caller {
		t.Fatal("Antigravity catalog driver retained the caller-owned HTTP client")
	}
	if errRedirect := driver.client.CheckRedirect(nil, nil); !errors.Is(errRedirect, http.ErrUseLastResponse) {
		t.Fatalf("Antigravity catalog redirect error = %v, want http.ErrUseLastResponse", errRedirect)
	}
	if errRedirect := caller.CheckRedirect(nil, nil); !errors.Is(errRedirect, callerRedirectError) {
		t.Fatalf("caller redirect error = %v, want original policy", errRedirect)
	}
}

// TestAntigravityCatalogDriverReadsTierAndCredits verifies the copied loadCodeAssist request and typed response mapping.
// TestAntigravityCatalogDriverReadsTierAndCredits 验证复制的 loadCodeAssist 请求与强类型响应映射。
func TestAntigravityCatalogDriverReadsTierAndCredits(t *testing.T) {
	loadRequestCount := 0
	quotaRequestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1internal:retrieveUserQuotaSummary" {
			quotaRequestCount++
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"groups":[{"displayName":"Gemini models","buckets":[{"bucketId":"weekly","displayName":"Weekly limit","remainingFraction":0.75,"resetTime":"2026-08-01T00:00:00Z"}]}]}`)
			return
		}
		loadRequestCount++
		if request.URL.Path != antigravityLoadCodeAssistPath || request.Header.Get("Authorization") != "Bearer access-token" || request.Header.Get("User-Agent") != AntigravityLoadCodeAssistUserAgent("") {
			t.Errorf("request = %s headers=%v", request.URL.Path, request.Header)
		}
		body, errBody := io.ReadAll(request.Body)
		if errBody != nil || string(body) != `{"metadata":{"ideType":"ANTIGRAVITY"}}` {
			t.Errorf("body = %s error=%v", body, errBody)
		}
		writer.Header().Set("Content-Type", "application/json")
		remaining := "42.5"
		if loadRequestCount > 1 {
			remaining = "17.25"
		}
		_, _ = io.WriteString(writer, `{"paidTier":{"id":"google-one-ai-premium","availableCredits":[{"creditType":"GOOGLE_ONE_AI","creditAmount":"`+remaining+`","minimumCreditAmountForUsage":"1"}]}}`)
	}))
	defer server.Close()
	secrets := secret.NewMemoryStore()
	protectedToken, errToken := MarshalAntigravityToken(AntigravityToken{AccessToken: "access-token", RefreshToken: "refresh-token", Email: "user@example.com", ProjectID: "project-one", Type: "antigravity"})
	if errToken != nil {
		t.Fatalf("MarshalAntigravityToken() error = %v", errToken)
	}
	secretReference, errSecret := secrets.Put(context.Background(), protectedToken)
	if errSecret != nil {
		t.Fatalf("Put() error = %v", errSecret)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_google_antigravity", Kind: providerconfig.DefinitionKindSystem, DisplayName: "Google Antigravity", DriverID: "antigravity", DriverVersion: "1", ConfigSchemaVersion: "1", ProtocolProfileID: "google.antigravity", EndpointProfileID: "google_antigravity", AuthMethodIDs: []string{"oauth"}, RuntimeReady: true, EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL, Region: "Global"}}, AuthMethods: []providerconfig.AuthMethodDefinition{{ID: "oauth", Type: providerconfig.AuthMethodOAuth}}, Features: providerconfig.ProviderFeatureSet{PlanReader: providerconfig.SupportSupported, EntitlementReader: providerconfig.SupportUnsupported, AllowanceReader: providerconfig.SupportSupported}, Revision: 1}
	driver, errDriver := NewAntigravityCatalogDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAntigravityCatalogDriver() error = %v", errDriver)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_antigravity_catalog", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_antigravity_catalog", ProviderInstanceID: instance.ID, SecretRef: secretReference}
	metadata, errMetadata := driver.ReadCredentialMetadata(context.Background(), instance, credential)
	if errMetadata != nil || metadata.Plan == nil || metadata.Plan.PlanCode != "google-one-ai-premium" || metadata.Plan.CredentialID != credential.ID {
		t.Fatalf("ReadCredentialMetadata() plan = %#v error=%v", metadata.Plan, errMetadata)
	}
	if len(metadata.Allowances) != 2 || metadata.Allowances[0].Metric != antigravityGoogleOneCreditType || metadata.Allowances[0].Remaining == nil || *metadata.Allowances[0].Remaining != "42.5" || metadata.Allowances[0].Status != catalog.AllowanceAvailable || metadata.Allowances[0].Mandatory || metadata.Allowances[1].RemainingRatio == nil || *metadata.Allowances[1].RemainingRatio != 0.75 {
		t.Fatalf("ReadCredentialMetadata() allowances = %#v", metadata.Allowances)
	}
	if errPlanValidation := metadata.Plan.Validate(); errPlanValidation != nil {
		t.Fatalf("ReadCredentialMetadata() plan validation error = %v", errPlanValidation)
	}
	if errAllowanceValidation := metadata.Allowances[0].Validate(); errAllowanceValidation != nil {
		t.Fatalf("ReadCredentialMetadata() allowance validation error = %v", errAllowanceValidation)
	}
	// metadataSnapshot proves the provider records survive the exact atomic catalog boundary used by refresh.
	// metadataSnapshot 证明供应商记录可以通过刷新流程使用的精确原子目录边界。
	metadataSnapshot := catalog.Snapshot{ProviderInstanceID: instance.ID, Plans: []catalog.PlanSnapshot{*metadata.Plan}, Allowances: metadata.Allowances, Revision: 1, ObservedAt: metadata.Plan.ObservedAt}
	if errSnapshotValidation := metadataSnapshot.Validate(); errSnapshotValidation != nil {
		t.Fatalf("ReadCredentialMetadata() snapshot validation error = %v", errSnapshotValidation)
	}
	if loadRequestCount != 1 || quotaRequestCount != 1 {
		t.Fatalf("request counts load=%d quota=%d, want 1 each", loadRequestCount, quotaRequestCount)
	}
	refreshedMetadata, errRefreshedMetadata := driver.ReadCredentialMetadata(context.Background(), instance, credential)
	if errRefreshedMetadata != nil || refreshedMetadata.Plan == nil || refreshedMetadata.Plan.PlanCode != "google-one-ai-premium" {
		t.Fatalf("refreshed ReadCredentialMetadata() plan = %#v error=%v", refreshedMetadata.Plan, errRefreshedMetadata)
	}
	if len(refreshedMetadata.Allowances) != 2 || refreshedMetadata.Allowances[0].Remaining == nil || *refreshedMetadata.Allowances[0].Remaining != "17.25" {
		t.Fatalf("refreshed ReadCredentialMetadata() allowances = %#v", refreshedMetadata.Allowances)
	}
	if loadRequestCount != 2 || quotaRequestCount != 2 {
		t.Fatalf("request counts after refresh load=%d quota=%d, want 2 each", loadRequestCount, quotaRequestCount)
	}
}

// TestAntigravityAllowanceComparisonPreservesExactIntegers verifies status decisions do not round values beyond IEEE-754 integer precision.
// TestAntigravityAllowanceComparisonPreservesExactIntegers 验证状态判定不会舍入超出 IEEE-754 整数精度的数值。
func TestAntigravityAllowanceComparisonPreservesExactIntegers(t *testing.T) {
	// availableCredits contains the exact provider credit values used by the typed response fixture.
	// availableCredits 包含强类型响应夹具使用的精确供应商积分值。
	availableCredits := []antigravityCredit{{
		CreditType:                  antigravityGoogleOneCreditType,
		CreditAmount:                json.Number("9007199254740992"),
		MinimumCreditAmountForUsage: json.Number("9007199254740993"),
	}}
	// response places the remaining amount exactly one unit below the minimum at the float64 precision boundary.
	// response 将剩余量放在 float64 精度边界处，且精确地比最低要求少一个单位。
	response := antigravityLoadCodeAssistResponse{PaidTier: antigravityPaidTier{
		ID:               "pro",
		AvailableCredits: &availableCredits,
	}}
	// observedAt fixes the resulting allowance snapshot timestamps.
	// observedAt 固定生成的额度快照时间戳。
	observedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	allowances, errAllowances := antigravityAllowancesFromResponse(
		response,
		providerconfig.ProviderInstance{ID: "pvi_antigravity_exact"},
		providerconfig.Credential{ID: "cred_antigravity_exact"},
		observedAt,
	)
	if errAllowances != nil {
		t.Fatalf("antigravityAllowancesFromResponse() error = %v", errAllowances)
	}
	if len(allowances) != 1 || allowances[0].Status != catalog.AllowanceExhausted {
		t.Fatalf("exact allowance comparison = %#v", allowances)
	}
}

// TestAntigravityAllowanceRejectsUnboundedNumericExponents verifies exact comparison cannot expand provider-controlled exponents without limit.
// TestAntigravityAllowanceRejectsUnboundedNumericExponents 验证精确比较不会无限展开供应商控制的指数。
func TestAntigravityAllowanceRejectsUnboundedNumericExponents(t *testing.T) {
	availableCredits := []antigravityCredit{{
		CreditType:                  antigravityGoogleOneCreditType,
		CreditAmount:                json.Number("1e999999999"),
		MinimumCreditAmountForUsage: json.Number("1"),
	}}
	_, errAllowances := antigravityAllowancesFromResponse(
		antigravityLoadCodeAssistResponse{PaidTier: antigravityPaidTier{ID: "pro", AvailableCredits: &availableCredits}},
		providerconfig.ProviderInstance{ID: "pvi_antigravity_unbounded"},
		providerconfig.Credential{ID: "cred_antigravity_unbounded"},
		time.Date(2026, 7, 19, 12, 30, 0, 0, time.UTC),
	)
	if !errors.Is(errAllowances, provider.ErrMetadataResponseInvalid) {
		t.Fatalf("antigravityAllowancesFromResponse() error = %v, want ErrMetadataResponseInvalid", errAllowances)
	}
}

// TestAntigravityAllowancePreservesKnownMissingCredits verifies the copied non-array branch becomes a non-blocking exhausted observation.
// TestAntigravityAllowancePreservesKnownMissingCredits 验证复制的非数组分支会转为不阻塞的已耗尽观测。
func TestAntigravityAllowancePreservesKnownMissingCredits(t *testing.T) {
	// observedAt fixes the known no-credits observation lifetime.
	// observedAt 固定已知无积分观测的生命周期。
	observedAt := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	allowances, errAllowances := antigravityAllowancesFromResponse(
		antigravityLoadCodeAssistResponse{PaidTier: antigravityPaidTier{ID: "pro"}},
		providerconfig.ProviderInstance{ID: "pvi_antigravity_missing_credits"},
		providerconfig.Credential{ID: "cred_antigravity_missing_credits"},
		observedAt,
	)
	if errAllowances != nil {
		t.Fatalf("antigravityAllowancesFromResponse() error = %v", errAllowances)
	}
	if len(allowances) != 1 || allowances[0].Status != catalog.AllowanceExhausted || allowances[0].Mandatory || allowances[0].Remaining != nil {
		t.Fatalf("missing credits allowance = %#v", allowances)
	}
	if errValidation := allowances[0].Validate(); errValidation != nil {
		t.Fatalf("missing credits allowance validation error = %v", errValidation)
	}
}

// TestAntigravityCatalogDriverClassifiesControlPlaneFailures verifies stable authentication, availability, and response error categories.
// TestAntigravityCatalogDriverClassifiesControlPlaneFailures 验证稳定的认证、可用性与响应错误分类。
func TestAntigravityCatalogDriverClassifiesControlPlaneFailures(t *testing.T) {
	testCases := []struct {
		// name labels the isolated provider failure class.
		// name 标记隔离的供应商失败分类。
		name string
		// statusCode is the simulated provider HTTP status.
		// statusCode 是模拟的供应商 HTTP 状态。
		statusCode int
		// response is the exact simulated provider body.
		// response 是精确的模拟供应商响应体。
		response string
		// want is the expected safe metadata error category.
		// want 是预期的安全元数据错误类别。
		want error
	}{
		{name: "authentication", statusCode: http.StatusUnauthorized, response: `{}`, want: provider.ErrMetadataAuthentication},
		{name: "request timeout", statusCode: http.StatusRequestTimeout, response: `{}`, want: provider.ErrMetadataUnavailable},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, response: `{}`, want: provider.ErrMetadataUnavailable},
		{name: "invalid status", statusCode: http.StatusTeapot, response: `{}`, want: provider.ErrMetadataResponseInvalid},
		{name: "invalid response", statusCode: http.StatusOK, response: `{`, want: provider.ErrMetadataResponseInvalid},
		{name: "trailing response", statusCode: http.StatusOK, response: `{"paidTier":{"id":"pro"}} {}`, want: provider.ErrMetadataResponseInvalid},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(testCase.statusCode)
				_, _ = io.WriteString(writer, testCase.response)
			}))
			defer server.Close()
			secrets := secret.NewMemoryStore()
			protectedToken, errToken := MarshalAntigravityToken(AntigravityToken{AccessToken: "access-token", RefreshToken: "refresh-token", Email: "user@example.com", ProjectID: "project-one", Type: "antigravity"})
			if errToken != nil {
				t.Fatalf("MarshalAntigravityToken() error = %v", errToken)
			}
			secretReference, errSecret := secrets.Put(context.Background(), protectedToken)
			if errSecret != nil {
				t.Fatalf("Put() error = %v", errSecret)
			}
			definition := providerconfig.ProviderDefinition{ID: "system_google_antigravity", Kind: providerconfig.DefinitionKindSystem, EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL}}}
			driver, errDriver := NewAntigravityCatalogDriver(definition, secrets, server.Client())
			if errDriver != nil {
				t.Fatalf("NewAntigravityCatalogDriver() error = %v", errDriver)
			}
			_, errPlan := driver.ReadPlan(context.Background(), providerconfig.ProviderInstance{ID: "instance-1"}, providerconfig.Credential{ID: "credential-1", SecretRef: secretReference})
			if !errors.Is(errPlan, testCase.want) {
				t.Fatalf("ReadPlan() error = %v, want category %v", errPlan, testCase.want)
			}
		})
	}
}
