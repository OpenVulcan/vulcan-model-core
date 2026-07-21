package xai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providermetadata "github.com/OpenVulcan/vulcan-model-core/internal/provider/metadata"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// billingURL is the Grok CLI billing endpoint copied from the source router.
	// billingURL 是从来源路由项目复制的 Grok CLI 计费入口。
	billingURL = "https://cli-chat-proxy.grok.com/v1/billing"
	// billingResponseLimit bounds one account billing response.
	// billingResponseLimit 限制一份账号计费响应的大小。
	billingResponseLimit = 1 << 20
)

// AllowanceDriver reads xAI account billing data behind the protected token boundary.
// AllowanceDriver 在受保护 Token 边界后读取 xAI 账号计费数据。
type AllowanceDriver struct {
	// definition is the immutable xAI account definition.
	// definition 是不可变的 xAI 账号定义。
	definition providerconfig.ProviderDefinition
	// secrets resolves the token document only during metadata reads.
	// secrets 仅在元数据读取期间解析 Token 文档。
	secrets secret.Store
	// client executes bounded provider requests without redirects.
	// client 执行有界且不跟随重定向的供应商请求。
	client *http.Client
}

// billingCent accepts both direct numeric values and the provider's val wrapper.
// billingCent 同时接受直接数值与供应商的 val 包装形式。
type billingCent struct {
	// value is the exact optional cent amount.
	// value 是精确的可选分金额。
	value providermetadata.Decimal
}

// UnmarshalJSON decodes only the two response shapes proven by the source router.
// UnmarshalJSON 仅解码来源路由项目已证实的两种响应形态。
func (c *billingCent) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*c = billingCent{}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var wrapper struct {
			// Value is the wrapped cent amount.
			// Value 是包装后的分金额。
			Value providermetadata.Decimal `json:"val"`
		}
		if errDecode := json.Unmarshal(trimmed, &wrapper); errDecode != nil || !wrapper.Value.Set() {
			return errors.New("xAI billing cent wrapper is invalid")
		}
		c.value = wrapper.Value
		return nil
	}
	return json.Unmarshal(trimmed, &c.value)
}

// xaiBillingConfig is the exact billing configuration subset consumed by Vulcan.
// xaiBillingConfig 是 Vulcan 消费的精确计费配置字段子集。
type xaiBillingConfig struct {
	// MonthlyLimit is the monthly budget in USD cents.
	// MonthlyLimit 是以美元分计量的月度预算。
	MonthlyLimit billingCent `json:"monthlyLimit"`
	// MonthlyLimitSnake is the snake-case monthly budget variant.
	// MonthlyLimitSnake 是下划线形式的月度预算变体。
	MonthlyLimitSnake billingCent `json:"monthly_limit"`
	// Used is the consumed amount in USD cents.
	// Used 是以美元分计量的已消费金额。
	Used billingCent `json:"used"`
	// OnDemandCap is the optional pay-as-you-go cap in USD cents.
	// OnDemandCap 是以美元分计量的可选按量上限。
	OnDemandCap billingCent `json:"onDemandCap"`
	// OnDemandCapSnake is the snake-case pay-as-you-go cap variant.
	// OnDemandCapSnake 是下划线形式的按量上限变体。
	OnDemandCapSnake billingCent `json:"on_demand_cap"`
	// BillingPeriodStart is the account period start.
	// BillingPeriodStart 是账号计费周期开始时间。
	BillingPeriodStart string `json:"billingPeriodStart"`
	// BillingPeriodStartSnake is the snake-case period start variant.
	// BillingPeriodStartSnake 是下划线形式的周期开始时间变体。
	BillingPeriodStartSnake string `json:"billing_period_start"`
	// BillingPeriodEnd is the account period end.
	// BillingPeriodEnd 是账号计费周期结束时间。
	BillingPeriodEnd string `json:"billingPeriodEnd"`
	// BillingPeriodEndSnake is the snake-case period end variant.
	// BillingPeriodEndSnake 是下划线形式的周期结束时间变体。
	BillingPeriodEndSnake string `json:"billing_period_end"`
}

// xaiBillingResponse is the exact account billing envelope.
// xaiBillingResponse 是精确的账号计费信封。
type xaiBillingResponse struct {
	// Config contains the optional current billing configuration.
	// Config 包含可选的当前计费配置。
	Config *xaiBillingConfig `json:"config"`
}

// NewAllowanceDriver creates one strict xAI billing reader.
// NewAllowanceDriver 创建一个严格的 xAI 计费读取器。
func NewAllowanceDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AllowanceDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil {
		return nil, errors.New("xAI definition, secret store, and HTTP client are required")
	}
	return &AllowanceDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client)}, nil
}

// Definition returns the immutable xAI account definition.
// Definition 返回不可变的 xAI 账号定义。
func (d *AllowanceDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves execution error classification to the execution driver.
// ClassifyError 将执行错误分类留给执行 Driver。
func (d *AllowanceDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadAllowances returns the monthly budget and optional pay-as-you-go cap.
// ReadAllowances 返回月度预算与可选按量上限。
func (d *AllowanceDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	protectedValue, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: resolve xAI credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	token, errToken := UnmarshalToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return nil, fmt.Errorf("%w: decode xAI credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, billingURL, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create xAI billing request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request xAI billing: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, billingResponseLimit+1))
	if errBody != nil || len(body) > billingResponseLimit {
		return nil, fmt.Errorf("%w: read xAI billing response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, xaiBillingStatusError(response.StatusCode)
	}
	var payload xaiBillingResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil || payload.Config == nil {
		return nil, fmt.Errorf("%w: decode xAI billing response", provider.ErrMetadataResponseInvalid)
	}
	return xaiBillingAllowances(*payload.Config, instance, credential, time.Now().UTC())
}

// xaiBillingAllowances converts the exact billing fields to monetary resource modes.
// xaiBillingAllowances 将精确计费字段转换为货币资源模式。
func xaiBillingAllowances(config xaiBillingConfig, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	monthlyLimit := firstBillingCent(config.MonthlyLimit, config.MonthlyLimitSnake)
	onDemandCap := firstBillingCent(config.OnDemandCap, config.OnDemandCapSnake)
	if !monthlyLimit.value.Set() || !config.Used.value.Set() || config.Used.value.Float64() > monthlyLimit.value.Float64() {
		return nil, fmt.Errorf("%w: xAI monthly billing values are invalid", provider.ErrMetadataResponseInvalid)
	}
	limit := monthlyLimit.value.String()
	used := config.Used.value.String()
	remainingValue := monthlyLimit.value.Float64() - config.Used.value.Float64()
	remaining := strconv.FormatFloat(remainingValue, 'f', -1, 64)
	var ratio *float64
	if monthlyLimit.value.Float64() > 0 {
		value := remainingValue / monthlyLimit.value.Float64()
		ratio = &value
	}
	window := &catalog.AllowanceWindow{Kind: catalog.WindowCalendar, CalendarUnit: "month"}
	billingPeriodEnd := config.BillingPeriodEnd
	if billingPeriodEnd == "" {
		billingPeriodEnd = config.BillingPeriodEndSnake
	}
	if billingPeriodEnd != "" {
		reset, errReset := time.Parse(time.RFC3339, billingPeriodEnd)
		if errReset != nil {
			return nil, fmt.Errorf("%w: xAI billing period end is invalid", provider.ErrMetadataResponseInvalid)
		}
		window.ResetAt = &reset
	}
	status := catalog.AllowanceUnknownSufficiency
	if ratio != nil {
		status = xaiRemainingStatus(*ratio)
	}
	allowances := []catalog.AllowanceSnapshot{{ID: xaiAllowanceID(credential.ID, "monthly_budget"), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: "monthly_budget", Unit: catalog.UnitMinorCurrency, Currency: "USD", Limit: &limit, Used: &used, Remaining: &remaining, RemainingRatio: ratio, Status: status, Mandatory: false, Window: window, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}}
	if onDemandCap.value.Set() {
		capValue := onDemandCap.value.String()
		allowances = append(allowances, catalog.AllowanceSnapshot{ID: xaiAllowanceID(credential.ID, "on_demand_cap"), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceProviderDefined, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: "on_demand_cap", Unit: catalog.UnitMinorCurrency, Currency: "USD", Limit: &capValue, Status: catalog.AllowanceUnknownSufficiency, Mandatory: false, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1})
	}
	return allowances, nil
}

// firstBillingCent returns the first explicitly reported provider amount.
// firstBillingCent 返回第一个供应商显式报告的金额。
func firstBillingCent(values ...billingCent) billingCent {
	for _, value := range values {
		if value.value.Set() {
			return value
		}
	}
	return billingCent{}
}

// xaiRemainingStatus derives a display state from a normalized remaining ratio.
// xaiRemainingStatus 从规范化剩余比例派生显示状态。
func xaiRemainingStatus(ratio float64) catalog.AllowanceStatus {
	if ratio <= 0 {
		return catalog.AllowanceExhausted
	}
	if ratio <= 0.1 {
		return catalog.AllowanceLow
	}
	return catalog.AllowanceAvailable
}

// xaiAllowanceID derives a bounded stable allowance identifier.
// xaiAllowanceID 派生一个有界且稳定的额度标识。
func xaiAllowanceID(credentialID string, metric string) string {
	digest := sha256.Sum256([]byte(credentialID + "\x00" + metric))
	return fmt.Sprintf("allow_%x", digest)
}

// xaiBillingStatusError classifies one upstream status without retaining response content.
// xaiBillingStatusError 在不保留响应内容的情况下分类一个上游状态。
func xaiBillingStatusError(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: xAI billing request returned status %d", provider.ErrMetadataAuthentication, status)
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return fmt.Errorf("%w: xAI billing request returned status %d", provider.ErrMetadataUnavailable, status)
	}
	return fmt.Errorf("%w: xAI billing request returned status %d", provider.ErrMetadataResponseInvalid, status)
}
