package minimax

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestAllowanceDriverUsesOnlySelectedRegionAndNormalizesSpecialStatuses verifies fixed-region auth and quota semantics copied from minimax-cli.
// TestAllowanceDriverUsesOnlySelectedRegionAndNormalizesSpecialStatuses 验证从 minimax-cli 复制的固定区域认证与额度语义。
func TestAllowanceDriverUsesOnlySelectedRegionAndNormalizesSpecialStatuses(t *testing.T) {
	observedAt := time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC)
	intervalEnd := observedAt.Add(5 * time.Hour).UnixMilli()
	weeklyEnd := observedAt.Add(4 * 24 * time.Hour).UnixMilli()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != tokenPlanRemainsPath || request.Header.Get("Authorization") != "Bearer minimax-key" || request.Header.Get("x-api-key") != "" {
			t.Errorf("request path=%q authorization=%q x-api-key=%q", request.URL.Path, request.Header.Get("Authorization"), request.Header.Get("x-api-key"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"model_remains":[{"model_name":"general","start_time":1,"end_time":` + formatTestInt(intervalEnd) + `,"remains_time":18000000,"current_interval_total_count":100,"current_interval_usage_count":25,"current_interval_remaining_percent":75,"current_interval_status":1,"current_weekly_total_count":1000,"current_weekly_usage_count":600,"current_weekly_remaining_percent":40,"current_weekly_status":1,"weekly_start_time":1,"weekly_end_time":` + formatTestInt(weeklyEnd) + `,"weekly_remains_time":345600000,"weekly_boost_permille":1500},{"model_name":"video","start_time":1,"end_time":` + formatTestInt(intervalEnd) + `,"remains_time":18000000,"current_interval_total_count":0,"current_interval_usage_count":0,"current_interval_status":3,"current_weekly_total_count":0,"current_weekly_usage_count":0,"current_weekly_status":3,"weekly_start_time":1,"weekly_end_time":` + formatTestInt(weeklyEnd) + `,"weekly_remains_time":345600000}]}`))
	}))
	defer server.Close()
	secrets := secret.NewMemoryStore()
	secretRef, errSecret := secrets.Put(context.Background(), []byte("minimax-key"))
	if errSecret != nil {
		t.Fatalf("put secret: %v", errSecret)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_minimax_test", EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL, Region: "Global"}}}
	driver, errDriver := NewAllowanceDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	driver.now = func() time.Time { return observedAt }
	instance := providerconfig.ProviderInstance{ID: "pvi_minimax_test", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_minimax_test", ProviderInstanceID: instance.ID, AuthMethodID: "api_key", SecretRef: secretRef}
	allowances, errAllowances := driver.ReadAllowances(context.Background(), instance, credential)
	if errAllowances != nil {
		t.Fatalf("ReadAllowances() error = %v", errAllowances)
	}
	if len(allowances) != 4 {
		t.Fatalf("allowance count = %d, want 4", len(allowances))
	}
	current, weekly, unavailable, unavailableWeekly := allowances[0], allowances[1], allowances[2], allowances[3]
	if current.Scope != catalog.ScopeCredential || current.Metric != "minimax.general.current_interval" || current.Remaining == nil || *current.Remaining != "25" || current.Used == nil || *current.Used != "75" || current.Window == nil || current.Window.ResetAt == nil || !current.Window.ResetAt.Equal(time.UnixMilli(intervalEnd).UTC()) {
		t.Fatalf("current allowance = %#v", current)
	}
	if weekly.DisplayMultiplierPermille == nil || *weekly.DisplayMultiplierPermille != 1500 || weekly.RemainingRatio == nil || *weekly.RemainingRatio != 0.4 || weekly.Window == nil || weekly.Window.CalendarUnit != "week" || weekly.Window.StartAt == nil || !weekly.Window.StartAt.Equal(time.UnixMilli(1).UTC()) {
		t.Fatalf("weekly allowance = %#v", weekly)
	}
	if unavailable.Status != catalog.AllowanceNotIncluded || unavailableWeekly.Status != catalog.AllowanceNotIncluded || unavailable.Limit != nil || unavailable.Used != nil || unavailable.Remaining != nil {
		t.Fatalf("not-in-plan allowance = %#v", unavailable)
	}
}

// TestQuotaAllowancePreservesUnlimitedStatus verifies one explicitly unlimited window is not collapsed into ordinary availability.
// TestQuotaAllowancePreservesUnlimitedStatus 验证一个明确无限的窗口不会被折叠为普通可用状态。
func TestQuotaAllowancePreservesUnlimitedStatus(t *testing.T) {
	// observedAt fixes the evidence timestamps for deterministic validation.
	// observedAt 固定证据时间戳以进行确定性校验。
	observedAt := time.Date(2026, time.July, 22, 8, 0, 0, 0, time.UTC)
	// resetAt supplies the provider-defined window boundary required by the catalog contract.
	// resetAt 提供目录合同要求的供应商定义窗口边界。
	resetAt := observedAt.Add(5 * time.Hour)
	allowance, errAllowance := quotaAllowance("pvi_minimax_test", "cred_minimax_test", "general", "weekly", 0, 0, nil, 3, false, &catalog.AllowanceWindow{Kind: catalog.WindowCalendar, CalendarUnit: "week", ResetAt: &resetAt}, nil, observedAt)
	if errAllowance != nil {
		t.Fatalf("quotaAllowance() error = %v", errAllowance)
	}
	if allowance.Status != catalog.AllowanceUnlimited || allowance.Limit != nil || allowance.Remaining != nil || allowance.RemainingRatio != nil {
		t.Fatalf("unlimited allowance = %#v", allowance)
	}
}

// TestAllowanceDriverDoesNotProbeAnotherRegion verifies a rejection remains scoped to the selected Definition.
// TestAllowanceDriverDoesNotProbeAnotherRegion 验证拒绝结果始终限定在所选 Definition 内。
func TestAllowanceDriverDoesNotProbeAnotherRegion(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	secrets := secret.NewMemoryStore()
	secretRef, errSecret := secrets.Put(context.Background(), []byte("wrong-region-or-key"))
	if errSecret != nil {
		t.Fatalf("put secret: %v", errSecret)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_minimax_cn", EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL, Region: "CN"}}}
	driver, errDriver := NewAllowanceDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	_, errAllowances := driver.ReadAllowances(context.Background(), providerconfig.ProviderInstance{ID: "pvi_minimax_cn", DefinitionID: definition.ID}, providerconfig.Credential{ID: "cred_minimax_cn", ProviderInstanceID: "pvi_minimax_cn", AuthMethodID: "api_key", SecretRef: secretRef})
	if errAllowances == nil || !strings.Contains(errAllowances.Error(), "selected regional endpoint") || calls != 1 {
		t.Fatalf("error=%v calls=%d", errAllowances, calls)
	}
}

// TestAllowanceDriverProjectsDeviceFlowAccessToken verifies quota lookup never sends the protected OAuth document.
// TestAllowanceDriverProjectsDeviceFlowAccessToken 验证额度查询绝不会发送受保护的 OAuth 文档。
func TestAllowanceDriverProjectsDeviceFlowAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer oauth-access-token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		_, _ = writer.Write([]byte(`{"model_remains":[]}`))
	}))
	defer server.Close()
	protected := secret.NewMemoryStore()
	encoded, errMarshal := MarshalToken(Token{AccessToken: "oauth-access-token", RefreshToken: "oauth-refresh-token", ExpiresAt: time.Now().UTC().Add(time.Hour), Region: "global", ResourceURL: "https://api.minimax.io", Type: "minimax"})
	if errMarshal != nil {
		t.Fatalf("MarshalToken() error = %v", errMarshal)
	}
	secretRef, errSecret := protected.Put(context.Background(), encoded)
	clear(encoded)
	if errSecret != nil {
		t.Fatalf("put token: %v", errSecret)
	}
	accessTokens, errAccessTokens := NewAccessTokenStore(protected)
	if errAccessTokens != nil {
		t.Fatalf("NewAccessTokenStore() error = %v", errAccessTokens)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_minimax_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL, Region: "Global"}}}
	driver, errDriver := NewAllowanceDriver(definition, accessTokens, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_minimax_global", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_minimax_oauth", ProviderInstanceID: instance.ID, AuthMethodID: "device_flow", SecretRef: secretRef}
	allowances, errAllowances := driver.ReadAllowances(context.Background(), instance, credential)
	if errAllowances != nil || len(allowances) != 0 {
		t.Fatalf("ReadAllowances() = %#v, %v", allowances, errAllowances)
	}
}

// formatTestInt formats one deterministic integer for a JSON fixture without adding a production dependency.
// formatTestInt 为 JSON 夹具格式化确定性整数且不增加生产依赖。
func formatTestInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
