package anthropic

import (
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
	// claudeUsageURL is the Claude account usage endpoint copied from the source router.
	// claudeUsageURL 是从来源路由项目复制的 Claude 账号用量入口。
	claudeUsageURL = "https://api.anthropic.com/api/oauth/usage"
	// claudeUsageResponseLimit bounds one account usage response.
	// claudeUsageResponseLimit 限制一份账号用量响应的大小。
	claudeUsageResponseLimit = 1 << 20
)

// AllowanceDriver reads Claude account quotas behind the protected OAuth boundary.
// AllowanceDriver 在受保护 OAuth 边界后读取 Claude 账号额度。
type AllowanceDriver struct {
	// definition is the immutable Claude Code product definition.
	// definition 是不可变的 Claude Code 产品定义。
	definition providerconfig.ProviderDefinition
	// secrets resolves the complete token only during the usage request.
	// secrets 仅在用量请求期间解析完整 Token。
	secrets secret.Store
	// client performs bounded provider requests without redirects.
	// client 执行有界且不跟随重定向的供应商请求。
	client *http.Client
}

// claudeUsageWindow is one percentage window returned by Anthropic.
// claudeUsageWindow 是 Anthropic 返回的一个百分比窗口。
type claudeUsageWindow struct {
	// Utilization is the consumed percentage.
	// Utilization 是已消费百分比。
	Utilization providermetadata.Decimal `json:"utilization"`
	// ResetsAt is the absolute provider reset time.
	// ResetsAt 是供应商绝对重置时间。
	ResetsAt string `json:"resets_at"`
}

// claudeExtraUsage is the optional monthly monetary allowance.
// claudeExtraUsage 是可选的月度货币额度。
type claudeExtraUsage struct {
	// IsEnabled reports whether additional paid usage is active.
	// IsEnabled 报告额外付费用量是否启用。
	IsEnabled bool `json:"is_enabled"`
	// MonthlyLimit is the provider amount in USD cents.
	// MonthlyLimit 是以美元分计量的供应商月度上限。
	MonthlyLimit providermetadata.Decimal `json:"monthly_limit"`
	// UsedCredits is the provider amount consumed in USD cents.
	// UsedCredits 是以美元分计量的已消费金额。
	UsedCredits providermetadata.Decimal `json:"used_credits"`
	// Utilization is the optional consumed percentage.
	// Utilization 是可选已消费百分比。
	Utilization providermetadata.Decimal `json:"utilization"`
}

// claudeUsageResponse is the exact usage response subset consumed by Vulcan.
// claudeUsageResponse 是 Vulcan 消费的精确用量响应字段子集。
type claudeUsageResponse struct {
	// FiveHour is the short account window.
	// FiveHour 是账号短周期窗口。
	FiveHour *claudeUsageWindow `json:"five_hour"`
	// SevenDay is the general weekly account window.
	// SevenDay 是常规周账号窗口。
	SevenDay *claudeUsageWindow `json:"seven_day"`
	// SevenDayOAuthApps is the OAuth application weekly window.
	// SevenDayOAuthApps 是 OAuth 应用周窗口。
	SevenDayOAuthApps *claudeUsageWindow `json:"seven_day_oauth_apps"`
	// SevenDayOpus is the Opus weekly window.
	// SevenDayOpus 是 Opus 周窗口。
	SevenDayOpus *claudeUsageWindow `json:"seven_day_opus"`
	// SevenDaySonnet is the Sonnet weekly window.
	// SevenDaySonnet 是 Sonnet 周窗口。
	SevenDaySonnet *claudeUsageWindow `json:"seven_day_sonnet"`
	// SevenDayCowork is the Cowork weekly window.
	// SevenDayCowork 是 Cowork 周窗口。
	SevenDayCowork *claudeUsageWindow `json:"seven_day_cowork"`
	// IguanaNecktie is a provider-named quota window preserved exactly.
	// IguanaNecktie 是精确保留的供应商命名额度窗口。
	IguanaNecktie *claudeUsageWindow `json:"iguana_necktie"`
	// ExtraUsage contains optional paid overage data.
	// ExtraUsage 包含可选付费超额用量数据。
	ExtraUsage *claudeExtraUsage `json:"extra_usage"`
}

// NewAllowanceDriver creates one strict Claude usage reader.
// NewAllowanceDriver 创建一个严格的 Claude 用量读取器。
func NewAllowanceDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AllowanceDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil {
		return nil, errors.New("Claude definition, secret store, and HTTP client are required")
	}
	return &AllowanceDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client)}, nil
}

// Definition returns the immutable Claude Code definition.
// Definition 返回不可变的 Claude Code 定义。
func (d *AllowanceDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves execution error classification to the execution driver.
// ClassifyError 将执行错误分类留给执行 Driver。
func (d *AllowanceDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadAllowances returns every Claude time window and enabled extra-usage balance.
// ReadAllowances 返回 Claude 的全部时间窗口与已启用额外用量余额。
func (d *AllowanceDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	protectedValue, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: resolve Claude credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	token, errToken := UnmarshalClaudeToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return nil, fmt.Errorf("%w: decode Claude credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, claudeUsageURL, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create Claude usage request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("anthropic-beta", "oauth-2025-04-20")
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request Claude usage: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, claudeUsageResponseLimit+1))
	if errBody != nil || len(body) > claudeUsageResponseLimit {
		return nil, fmt.Errorf("%w: read Claude usage response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, claudeUsageStatusError(response.StatusCode)
	}
	var payload claudeUsageResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return nil, fmt.Errorf("%w: decode Claude usage response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	observedAt := time.Now().UTC()
	windows := []struct {
		// metric is the stable upstream window name.
		// metric 是稳定的上游窗口名称。
		metric string
		// value is the optional window observation.
		// value 是可选窗口观测。
		value *claudeUsageWindow
	}{{"five_hour", payload.FiveHour}, {"seven_day", payload.SevenDay}, {"seven_day_oauth_apps", payload.SevenDayOAuthApps}, {"seven_day_opus", payload.SevenDayOpus}, {"seven_day_sonnet", payload.SevenDaySonnet}, {"seven_day_cowork", payload.SevenDayCowork}, {"iguana_necktie", payload.IguanaNecktie}}
	allowances := make([]catalog.AllowanceSnapshot, 0, len(windows)+1)
	for _, item := range windows {
		if item.value == nil {
			continue
		}
		allowance, errAllowance := claudeWindowAllowance(item.metric, *item.value, instance, credential, observedAt)
		if errAllowance != nil {
			return nil, errAllowance
		}
		allowances = append(allowances, allowance)
	}
	if payload.ExtraUsage != nil && payload.ExtraUsage.IsEnabled {
		allowance, present, errAllowance := claudeExtraUsageAllowance(*payload.ExtraUsage, instance, credential, observedAt)
		if errAllowance != nil {
			return nil, errAllowance
		}
		if present {
			allowances = append(allowances, allowance)
		}
	}
	return allowances, nil
}

// claudeWindowAllowance converts one percentage window to the canonical quota model.
// claudeWindowAllowance 将一个百分比窗口转换为规范额度模型。
func claudeWindowAllowance(metric string, window claudeUsageWindow, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (catalog.AllowanceSnapshot, error) {
	if !window.Utilization.Set() || window.Utilization.Float64() > 100 {
		return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: Claude usage percentage is invalid", provider.ErrMetadataResponseInvalid)
	}
	usedValue := window.Utilization.Float64()
	remainingValue := 100 - usedValue
	limit := "100"
	used := window.Utilization.String()
	remaining := strconv.FormatFloat(remainingValue, 'f', -1, 64)
	ratio := remainingValue / 100
	windowView := &catalog.AllowanceWindow{Kind: catalog.WindowProviderDefined}
	if window.ResetsAt != "" {
		reset, errReset := time.Parse(time.RFC3339, window.ResetsAt)
		if errReset != nil {
			return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: Claude reset time is invalid", provider.ErrMetadataResponseInvalid)
		}
		windowView.ResetAt = &reset
	}
	return catalog.AllowanceSnapshot{ID: claudeAllowanceID(credential.ID, metric), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: metric, Unit: catalog.UnitPercentage, Limit: &limit, Used: &used, Remaining: &remaining, RemainingRatio: &ratio, Status: claudeRemainingStatus(ratio), Mandatory: false, Window: windowView, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}, nil
}

// claudeExtraUsageAllowance converts the enabled USD-cent budget to a monetary balance.
// claudeExtraUsageAllowance 将已启用的美元分预算转换为货币余额。
func claudeExtraUsageAllowance(extra claudeExtraUsage, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (catalog.AllowanceSnapshot, bool, error) {
	if !extra.MonthlyLimit.Set() && !extra.UsedCredits.Set() {
		return catalog.AllowanceSnapshot{}, false, nil
	}
	if !extra.MonthlyLimit.Set() || !extra.UsedCredits.Set() || extra.UsedCredits.Float64() > extra.MonthlyLimit.Float64() {
		return catalog.AllowanceSnapshot{}, false, fmt.Errorf("%w: Claude extra usage balance is invalid", provider.ErrMetadataResponseInvalid)
	}
	limit := extra.MonthlyLimit.String()
	used := extra.UsedCredits.String()
	remainingValue := extra.MonthlyLimit.Float64() - extra.UsedCredits.Float64()
	remaining := strconv.FormatFloat(remainingValue, 'f', -1, 64)
	var ratio *float64
	if extra.MonthlyLimit.Float64() > 0 {
		value := remainingValue / extra.MonthlyLimit.Float64()
		ratio = &value
	}
	status := catalog.AllowanceUnknownSufficiency
	if ratio != nil {
		status = claudeRemainingStatus(*ratio)
	}
	return catalog.AllowanceSnapshot{ID: claudeAllowanceID(credential.ID, "extra_usage"), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceBalance, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: "extra_usage", Unit: catalog.UnitMinorCurrency, Currency: "USD", Limit: &limit, Used: &used, Remaining: &remaining, RemainingRatio: ratio, Status: status, Mandatory: false, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}, true, nil
}

// claudeRemainingStatus derives the display state from a normalized remaining ratio.
// claudeRemainingStatus 从规范化剩余比例派生显示状态。
func claudeRemainingStatus(ratio float64) catalog.AllowanceStatus {
	if ratio <= 0 {
		return catalog.AllowanceExhausted
	}
	if ratio <= 0.1 {
		return catalog.AllowanceLow
	}
	return catalog.AllowanceAvailable
}

// claudeAllowanceID derives a bounded stable allowance identifier.
// claudeAllowanceID 派生一个有界且稳定的额度标识。
func claudeAllowanceID(credentialID string, metric string) string {
	digest := sha256.Sum256([]byte(credentialID + "\x00" + metric))
	return fmt.Sprintf("allow_%x", digest)
}

// claudeUsageStatusError classifies one upstream status without retaining response content.
// claudeUsageStatusError 在不保留响应内容的情况下分类一个上游状态。
func claudeUsageStatusError(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: Claude usage request returned status %d", provider.ErrMetadataAuthentication, status)
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return fmt.Errorf("%w: Claude usage request returned status %d", provider.ErrMetadataUnavailable, status)
	}
	return fmt.Errorf("%w: Claude usage request returned status %d", provider.ErrMetadataResponseInvalid, status)
}
