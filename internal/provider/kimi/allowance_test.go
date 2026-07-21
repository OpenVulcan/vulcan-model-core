package kimi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// roundTripFunc adapts one test function to an HTTP transport.
// roundTripFunc 将一个测试函数适配为 HTTP 传输层。
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip executes the configured deterministic test transport.
// RoundTrip 执行已配置的确定性测试传输。
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// TestKimiAllowancePreservesNestedLegacyWindow verifies copied nested counters and item-level durations.
// TestKimiAllowancePreservesNestedLegacyWindow 验证复制的嵌套计数与条目级时长。
func TestKimiAllowancePreservesNestedLegacyWindow(t *testing.T) {
	var payload kimiUsageResponse
	if errDecode := json.Unmarshal([]byte(`{"limits":[{"name":"Weekly pool","duration":7,"timeUnit":"DAYS","detail":{"used":25,"limit":100,"reset_in":3600}}]}`), &payload); errDecode != nil {
		t.Fatalf("decode Kimi usage fixture: %v", errDecode)
	}
	item := payload.Limits[0]
	window := &kimiLimitWindow{Duration: item.Duration, TimeUnit: item.TimeUnit}
	observedAt := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	allowance, present, errAllowance := kimiAllowanceFromDetail(*item.Detail, window, "weekly_pool", providerconfig.ProviderInstance{ID: "pvi_kimi"}, providerconfig.Credential{ID: "cred_kimi"}, observedAt)
	if errAllowance != nil || !present {
		t.Fatalf("Kimi allowance present=%v error=%v", present, errAllowance)
	}
	if allowance.Remaining == nil || *allowance.Remaining != "75" || allowance.RemainingRatio == nil || *allowance.RemainingRatio != 0.75 || allowance.Window == nil || allowance.Window.Kind != catalog.WindowRolling || allowance.Window.Duration != 7*24*time.Hour || allowance.Window.ResetAt == nil || !allowance.Window.ResetAt.Equal(observedAt.Add(time.Hour)) {
		t.Fatalf("Kimi allowance = %#v", allowance)
	}
	if errValidate := allowance.Validate(); errValidate != nil {
		t.Fatalf("Kimi allowance validation error = %v", errValidate)
	}
}

// TestKimiAllowanceAcceptsObservedMinuteEnum verifies Kimi's current protobuf-style usage-window unit.
// TestKimiAllowanceAcceptsObservedMinuteEnum 验证 Kimi 当前 Protobuf 风格的用量窗口单位。
func TestKimiAllowanceAcceptsObservedMinuteEnum(t *testing.T) {
	observedAt := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	var detail kimiUsageDetail
	if errDecode := json.Unmarshal([]byte(`{"used":1,"limit":10}`), &detail); errDecode != nil {
		t.Fatalf("decode Kimi detail fixture: %v", errDecode)
	}
	var window kimiLimitWindow
	if errDecode := json.Unmarshal([]byte(`{"duration":5,"timeUnit":"TIME_UNIT_MINUTE"}`), &window); errDecode != nil {
		t.Fatalf("decode Kimi window fixture: %v", errDecode)
	}
	allowance, present, errAllowance := kimiAllowanceFromDetail(detail, &window, "minute_window", providerconfig.ProviderInstance{ID: "pvi_kimi"}, providerconfig.Credential{ID: "cred_kimi"}, observedAt)
	if errAllowance != nil || !present {
		t.Fatalf("Kimi allowance present=%t error=%v", present, errAllowance)
	}
	if allowance.Window == nil || allowance.Window.Duration != 5*time.Minute {
		t.Fatalf("Kimi allowance window = %#v", allowance.Window)
	}
}

// TestReadCredentialMetadataDetectsAllegrettoAndSendsProvenHeaders verifies one response updates plan, entitlements, and usage atomically.
// TestReadCredentialMetadataDetectsAllegrettoAndSendsProvenHeaders 验证一份响应会原子更新套餐、授权与用量，并发送已验证请求头。
func TestReadCredentialMetadataDetectsAllegrettoAndSendsProvenHeaders(t *testing.T) {
	ctx := context.Background()
	secrets := secret.NewMemoryStore()
	encodedToken, errToken := MarshalToken(Token{AccessToken: "access-secret", RefreshToken: "refresh-secret", DeviceID: "device-one", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	secretReference, errPut := secrets.Put(ctx, encodedToken)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != kimiUsageURL || request.Header.Get("Authorization") != "Bearer access-secret" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("User-Agent") != kimiUsageUserAgent || request.Header.Get("X-Msh-Platform") != kimiUsagePlatform || request.Header.Get("X-Msh-Version") != kimiUsageVersion || request.Header.Get("X-Msh-Device-Id") != "device-one" || request.Header.Get("X-Msh-Device-Name") == "" || request.Header.Get("X-Msh-Device-Model") == "" {
			t.Errorf("Kimi usage request URL=%q headers=%#v", request.URL.String(), request.Header)
		}
		body := `{"user":{"membership":{"level":"LEVEL_INTERMEDIATE"}},"usage":{"used":25,"limit":100,"remaining":75}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(stringsReader(body))}, nil
	})}
	driver, errDriver := NewAllowanceDriver(providerconfig.ProviderDefinition{ID: "provider_kimi_coding"}, secrets, client)
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	instance := providerconfig.ProviderInstance{ID: "pvi_kimi"}
	credential := providerconfig.Credential{ID: "cred_kimi", ProviderInstanceID: instance.ID, AuthMethodID: "device_flow", SecretRef: secretReference}
	metadata, errMetadata := driver.ReadCredentialMetadata(ctx, instance, credential)
	if errMetadata != nil {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
	if metadata.Plan == nil || metadata.Plan.PlanCode != PlanOptionAllegretto || metadata.Plan.PlanName != "Allegretto" || metadata.Plan.EvidenceSource != catalog.MetadataEvidenceProviderAPI {
		t.Fatalf("Kimi plan = %#v", metadata.Plan)
	}
	assertKimiEntitlement(t, metadata.Entitlements, ModelK27ID, catalog.AvailabilityAllowed, []string{ProfileK27ID})
	assertKimiEntitlement(t, metadata.Entitlements, ModelK3ID, catalog.AvailabilityAllowed, []string{ProfileK3256KID, ProfileK31MID})
	assertKimiEntitlement(t, metadata.Entitlements, ModelK27HighSpeedID, catalog.AvailabilityAllowed, []string{ProfileK27HighSpeedID})
	if len(metadata.Allowances) != 1 || metadata.Allowances[0].Remaining == nil || *metadata.Allowances[0].Remaining != "75" {
		t.Fatalf("Kimi allowances = %#v", metadata.Allowances)
	}
}

// TestMembershipMetadataFromProviderCoversConfirmedTierMatrix verifies all four confirmed provider values without inference.
// TestMembershipMetadataFromProviderCoversConfirmedTierMatrix 验证全部四个已确认供应商值且不进行推测。
func TestMembershipMetadataFromProviderCoversConfirmedTierMatrix(t *testing.T) {
	observedAt := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		providerLevel string
		planCode      string
		k3Profiles    []string
		highSpeed     catalog.AvailabilityStatus
	}{
		{name: "Andante", providerLevel: ProviderMembershipAndante, planCode: PlanOptionAndante, highSpeed: catalog.AvailabilityDenied},
		{name: "Moderato", providerLevel: ProviderMembershipModerato, planCode: PlanOptionModerato, k3Profiles: []string{ProfileK3256KID}, highSpeed: catalog.AvailabilityDenied},
		{name: "Allegretto", providerLevel: ProviderMembershipAllegretto, planCode: PlanOptionAllegretto, k3Profiles: []string{ProfileK3256KID, ProfileK31MID}, highSpeed: catalog.AvailabilityAllowed},
		{name: "Allegro", providerLevel: ProviderMembershipAllegro, planCode: PlanOptionAllegro, k3Profiles: []string{ProfileK3256KID, ProfileK31MID}, highSpeed: catalog.AvailabilityAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, entitlements, errMetadata := MembershipMetadataFromProvider("pvi_kimi", "cred_kimi", test.providerLevel, observedAt)
			if errMetadata != nil {
				t.Fatalf("MembershipMetadataFromProvider() error = %v", errMetadata)
			}
			if plan.PlanCode != test.planCode || !plan.ExpiresAt.Equal(observedAt.Add(5*time.Minute)) {
				t.Fatalf("plan = %#v", plan)
			}
			k3Availability := catalog.AvailabilityDenied
			if len(test.k3Profiles) > 0 {
				k3Availability = catalog.AvailabilityAllowed
			}
			assertKimiEntitlement(t, entitlements, ModelK3ID, k3Availability, test.k3Profiles)
			assertKimiEntitlement(t, entitlements, ModelK27HighSpeedID, test.highSpeed, profilesWhen(test.highSpeed == catalog.AvailabilityAllowed, ProfileK27HighSpeedID))
		})
	}
}

// TestReadCredentialMetadataRejectsUnknownProviderMembership verifies new provider values remain explicit errors instead of guessed access.
// TestReadCredentialMetadataRejectsUnknownProviderMembership 验证新的供应商值会保持显式错误而不会猜测权限。
func TestReadCredentialMetadataRejectsUnknownProviderMembership(t *testing.T) {
	ctx := context.Background()
	secrets := secret.NewMemoryStore()
	encodedToken, errToken := MarshalToken(Token{AccessToken: "access-secret", RefreshToken: "refresh-secret", DeviceID: "device-one", Type: "kimi"})
	if errToken != nil {
		t.Fatalf("MarshalToken() error = %v", errToken)
	}
	secretReference, errPut := secrets.Put(ctx, encodedToken)
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"user":{"membership":{"level":"LEVEL_FUTURE"}}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(stringsReader(body))}, nil
	})}
	driver, errDriver := NewAllowanceDriver(providerconfig.ProviderDefinition{ID: "provider_kimi_coding"}, secrets, client)
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	_, errMetadata := driver.ReadCredentialMetadata(ctx, providerconfig.ProviderInstance{ID: "pvi_kimi"}, providerconfig.Credential{ID: "cred_kimi", AuthMethodID: "device_flow", SecretRef: secretReference})
	if !errors.Is(errMetadata, provider.ErrMetadataResponseInvalid) {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
}

// TestReadCredentialMetadataKeepsAPIKeyDeclaredMembership verifies static keys never infer a tier from account response data.
// TestReadCredentialMetadataKeepsAPIKeyDeclaredMembership 验证静态密钥绝不会从账号响应数据推断档位。
func TestReadCredentialMetadataKeepsAPIKeyDeclaredMembership(t *testing.T) {
	ctx := context.Background()
	secrets := secret.NewMemoryStore()
	secretReference, errPut := secrets.Put(ctx, []byte("static-api-key"))
	if errPut != nil {
		t.Fatalf("Put() error = %v", errPut)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Msh-Device-Id") == "" {
			t.Error("Kimi API-key usage request omitted its persisted device identity")
		}
		body := `{"user":{"membership":{"level":"LEVEL_ADVANCED"}},"usage":{"used":1,"limit":10,"remaining":9}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(stringsReader(body))}, nil
	})}
	driver, errDriver := NewAllowanceDriver(providerconfig.ProviderDefinition{ID: "provider_kimi_coding"}, secrets, client)
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	declaredAt := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	credential := providerconfig.Credential{ID: "cred_kimi", ProviderInstanceID: "pvi_kimi", AuthMethodID: "api_key", SecretRef: secretReference, DeclaredPlan: &providerconfig.DeclaredPlanSelection{PlanOptionID: PlanOptionAndante, DeclaredAt: declaredAt, Revision: 1}}
	metadata, errMetadata := driver.ReadCredentialMetadata(ctx, providerconfig.ProviderInstance{ID: "pvi_kimi"}, credential)
	if errMetadata != nil {
		t.Fatalf("ReadCredentialMetadata() error = %v", errMetadata)
	}
	if metadata.Plan == nil || metadata.Plan.PlanCode != PlanOptionAndante || metadata.Plan.EvidenceSource != catalog.MetadataEvidenceOperatorDeclared || !metadata.Plan.ExpiresAt.IsZero() {
		t.Fatalf("Kimi API-key plan = %#v", metadata.Plan)
	}
	assertKimiEntitlement(t, metadata.Entitlements, ModelK3ID, catalog.AvailabilityDenied, nil)
	assertKimiEntitlement(t, metadata.Entitlements, ModelK27HighSpeedID, catalog.AvailabilityDenied, nil)
}

// stringsReader returns a fresh reader for one immutable response fixture.
// stringsReader 为一个不可变响应样本返回新的读取器。
func stringsReader(value string) io.Reader {
	return strings.NewReader(value)
}

// assertKimiEntitlement verifies one exact model authorization record.
// assertKimiEntitlement 验证一条精确模型授权记录。
func assertKimiEntitlement(t *testing.T, entitlements []catalog.ModelEntitlement, modelID string, availability catalog.AvailabilityStatus, profiles []string) {
	t.Helper()
	for _, entitlement := range entitlements {
		if entitlement.ProviderModelID != modelID {
			continue
		}
		if entitlement.Availability != availability || !slices.Equal(entitlement.AllowedProfileIDs, profiles) {
			t.Fatalf("entitlement for %s = %#v, want availability=%s profiles=%v", modelID, entitlement, availability, profiles)
		}
		return
	}
	t.Fatalf("entitlement for %s is missing", modelID)
}
