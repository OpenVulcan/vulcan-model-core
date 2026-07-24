package deepseek

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestAllowanceDriverMapsOfficialBalanceBreakdown verifies exact currency conversion, status, scope, and request authentication.
// TestAllowanceDriverMapsOfficialBalanceBreakdown 验证精确货币换算、状态、作用域与请求认证。
func TestAllowanceDriverMapsOfficialBalanceBreakdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/user/balance" || request.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("request = %s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"is_available":true,"balance_infos":[{"currency":"CNY","total_balance":"110.00","granted_balance":"10.00","topped_up_balance":"100.00"},{"currency":"USD","total_balance":"1.23","granted_balance":"0.23","topped_up_balance":"1.00"}]}`)
	}))
	defer server.Close()
	driver, instance, credential := newTestAllowanceDriver(t, server)
	allowances, errAllowances := driver.ReadAllowances(context.Background(), instance, credential)
	if errAllowances != nil {
		t.Fatalf("ReadAllowances() error = %v", errAllowances)
	}
	if len(allowances) != 6 {
		t.Fatalf("allowance count = %d, want 6", len(allowances))
	}
	expected := []struct {
		// metric is the exact normalized balance component.
		// metric 是精确的规范化余额组成部分。
		metric string
		// currency is the provider-reported ISO currency.
		// currency 是供应商报告的 ISO 货币。
		currency string
		// remaining is the exact integer minor-unit balance.
		// remaining 是精确的整数最小货币单位余额。
		remaining string
	}{
		{metric: "deepseek.balance.total", currency: "CNY", remaining: "11000"},
		{metric: "deepseek.balance.granted", currency: "CNY", remaining: "1000"},
		{metric: "deepseek.balance.topped_up", currency: "CNY", remaining: "10000"},
		{metric: "deepseek.balance.total", currency: "USD", remaining: "123"},
		{metric: "deepseek.balance.granted", currency: "USD", remaining: "23"},
		{metric: "deepseek.balance.topped_up", currency: "USD", remaining: "100"},
	}
	for index, allowance := range allowances {
		if allowance.Metric != expected[index].metric || allowance.Currency != expected[index].currency || allowance.Remaining == nil || *allowance.Remaining != expected[index].remaining {
			t.Fatalf("allowance[%d] = %#v", index, allowance)
		}
		if allowance.Scope != catalog.ScopeCredential || allowance.ScopeID != credential.ID || allowance.Unit != catalog.UnitMinorCurrency {
			t.Fatalf("allowance[%d] scope/unit = %#v", index, allowance)
		}
		if strings.Contains(allowance.ID, credential.ID) {
			t.Fatalf("allowance ID exposes credential identity: %q", allowance.ID)
		}
	}
	if allowances[0].Status != catalog.AllowanceAvailable || !allowances[0].Mandatory || allowances[1].Mandatory {
		t.Fatalf("CNY allowance statuses = %#v", allowances[:3])
	}
}

// TestAllowanceDriverUsesProviderAvailabilityAsTheBlockingState verifies an unavailable account produces an exhausted mandatory aggregate.
// TestAllowanceDriverUsesProviderAvailabilityAsTheBlockingState 验证不可用账号生成已耗尽的强制聚合余额。
func TestAllowanceDriverUsesProviderAvailabilityAsTheBlockingState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"is_available":false,"balance_infos":[{"currency":"CNY","total_balance":"0","granted_balance":"0","topped_up_balance":"0"}]}`)
	}))
	defer server.Close()
	driver, instance, credential := newTestAllowanceDriver(t, server)
	allowances, errAllowances := driver.ReadAllowances(context.Background(), instance, credential)
	if errAllowances != nil {
		t.Fatalf("ReadAllowances() error = %v", errAllowances)
	}
	if len(allowances) != 3 || allowances[0].Status != catalog.AllowanceExhausted || !allowances[0].Mandatory {
		t.Fatalf("allowances = %#v", allowances)
	}
}

// TestAllowanceDriverRejectsCredentialFailure verifies authentication failures remain distinguishable from provider outages.
// TestAllowanceDriverRejectsCredentialFailure 验证认证失败与供应商故障保持可区分。
func TestAllowanceDriverRejectsCredentialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	driver, instance, credential := newTestAllowanceDriver(t, server)
	_, errAllowances := driver.ReadAllowances(context.Background(), instance, credential)
	if !errors.Is(errAllowances, provider.ErrMetadataAuthentication) {
		t.Fatalf("ReadAllowances() error = %v", errAllowances)
	}
}

// TestDecimalToMinorUnitsRejectsUnrepresentablePrecision verifies monetary values are never silently rounded.
// TestDecimalToMinorUnitsRejectsUnrepresentablePrecision 验证货币值绝不会被静默舍入。
func TestDecimalToMinorUnitsRejectsUnrepresentablePrecision(t *testing.T) {
	var payload balanceResponse
	if errDecode := json.Unmarshal([]byte(`{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"1.001","granted_balance":"0","topped_up_balance":"0"}]}`), &payload); errDecode != nil {
		t.Fatalf("decode fixture: %v", errDecode)
	}
	if _, errNormalize := normalizeBalanceResponse("pvi_deepseek", "cred_deepseek", payload, time.Now().UTC()); !errors.Is(errNormalize, provider.ErrMetadataResponseInvalid) {
		t.Fatalf("normalizeBalanceResponse() error = %v", errNormalize)
	}
}

// TestNormalizeBalanceResponseRejectsInconsistentBreakdown verifies provider corruption cannot create contradictory balance rows.
// TestNormalizeBalanceResponseRejectsInconsistentBreakdown 验证供应商损坏数据不能生成互相矛盾的余额行。
func TestNormalizeBalanceResponseRejectsInconsistentBreakdown(t *testing.T) {
	var payload balanceResponse
	if errDecode := json.Unmarshal([]byte(`{"is_available":true,"balance_infos":[{"currency":"CNY","total_balance":"10.00","granted_balance":"4.00","topped_up_balance":"5.00"}]}`), &payload); errDecode != nil {
		t.Fatalf("decode fixture: %v", errDecode)
	}
	if _, errNormalize := normalizeBalanceResponse("pvi_deepseek", "cred_deepseek", payload, time.Now().UTC()); !errors.Is(errNormalize, provider.ErrMetadataResponseInvalid) {
		t.Fatalf("normalizeBalanceResponse() error = %v", errNormalize)
	}
}

// newTestAllowanceDriver creates one official-definition driver redirected only inside the local test boundary.
// newTestAllowanceDriver 创建一个仅在本地测试边界内重定向的官方 Definition Driver。
func newTestAllowanceDriver(t *testing.T, server *httptest.Server) (*AllowanceDriver, providerconfig.ProviderInstance, providerconfig.Credential) {
	t.Helper()
	secrets := secret.NewMemoryStore()
	secretReference, errPut := secrets.Put(context.Background(), []byte("test-secret"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_deepseek_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: "https://api.deepseek.com"}}}
	driver, errDriver := NewAllowanceDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	driver.baseURL = server.URL
	driver.now = func() time.Time { return time.Date(2026, time.July, 24, 1, 2, 3, 0, time.UTC) }
	instance := providerconfig.ProviderInstance{ID: "pvi_deepseek", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_deepseek", ProviderInstanceID: instance.ID, AuthMethodID: "api_key", SecretRef: secretReference}
	return driver, instance, credential
}
