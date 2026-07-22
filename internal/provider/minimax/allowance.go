package minimax

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// tokenPlanRemainsPath is the exact MiniMax Token Plan quota path copied from minimax-cli.
	// tokenPlanRemainsPath 是从 minimax-cli 复制的精确 MiniMax Token Plan 额度路径。
	tokenPlanRemainsPath = "/v1/token_plan/remains"
	// maximumQuotaResponseBytes bounds one MiniMax quota response before decoding.
	// maximumQuotaResponseBytes 在解码前限制单个 MiniMax 额度响应大小。
	maximumQuotaResponseBytes = 1 << 20
)

// AllowanceDriver reads region-fixed MiniMax Token Plan windows without probing another regional endpoint.
// AllowanceDriver 读取区域固定的 MiniMax Token Plan 窗口且不探测其他区域入口。
type AllowanceDriver struct {
	// definition is the immutable region-specific provider definition.
	// definition 是不可变的区域特定供应商定义。
	definition providerconfig.ProviderDefinition
	// secrets resolves the exact protected API key selected by the caller.
	// secrets 解析调用方选中的精确受保护 API Key。
	secrets secret.Store
	// client performs bounded requests without following redirects.
	// client 执行有界且不跟随重定向的请求。
	client *http.Client
	// baseURL is the sole region-specific API Origin accepted by this driver.
	// baseURL 是此 Driver 接受的唯一区域特定 API Origin。
	baseURL string
	// now supplies deterministic observation timestamps.
	// now 提供确定性观测时间戳。
	now func() time.Time
}

// quotaResponse contains the exact MiniMax quota collection used by minimax-cli.
// quotaResponse 包含 minimax-cli 使用的精确 MiniMax 额度集合。
type quotaResponse struct {
	// ModelRemains contains independently reported model or service quota buckets.
	// ModelRemains 包含独立报告的模型或服务额度桶。
	ModelRemains []quotaModelRemain `json:"model_remains"`
}

// quotaModelRemain mirrors the MiniMax Token Plan counter fields copied from minimax-cli.
// quotaModelRemain 镜像从 minimax-cli 复制的 MiniMax Token Plan 计数字段。
type quotaModelRemain struct {
	// ModelName is the provider-owned quota bucket name.
	// ModelName 是供应商拥有的额度桶名称。
	ModelName string `json:"model_name"`
	// StartTime is the current interval start in Unix milliseconds.
	// StartTime 是当前周期开始时间的 Unix 毫秒值。
	StartTime int64 `json:"start_time"`
	// EndTime is the current interval end in Unix milliseconds.
	// EndTime 是当前周期结束时间的 Unix 毫秒值。
	EndTime int64 `json:"end_time"`
	// RemainsTime is the provider-reported current interval remaining milliseconds.
	// RemainsTime 是供应商报告的当前周期剩余毫秒数。
	RemainsTime int64 `json:"remains_time"`
	// CurrentIntervalTotalCount is the current interval limit.
	// CurrentIntervalTotalCount 是当前周期上限。
	CurrentIntervalTotalCount int64 `json:"current_interval_total_count"`
	// CurrentIntervalUsageCount is the provider-misnamed remaining count copied from minimax-cli's rendering contract.
	// CurrentIntervalUsageCount 是按 minimax-cli 展示合同复制的供应商误命名剩余次数。
	CurrentIntervalUsageCount int64 `json:"current_interval_usage_count"`
	// CurrentIntervalRemainingPercent is the optional provider-calculated remaining percentage.
	// CurrentIntervalRemainingPercent 是可选的供应商计算剩余百分比。
	CurrentIntervalRemainingPercent *float64 `json:"current_interval_remaining_percent"`
	// CurrentIntervalStatus is 1 normal, 2 exhausted, or 3 unlimited.
	// CurrentIntervalStatus 为 1 正常、2 耗尽或 3 无限。
	CurrentIntervalStatus *int `json:"current_interval_status"`
	// CurrentWeeklyTotalCount is the weekly limit.
	// CurrentWeeklyTotalCount 是周额度上限。
	CurrentWeeklyTotalCount int64 `json:"current_weekly_total_count"`
	// CurrentWeeklyUsageCount is the provider-misnamed weekly remaining count copied from minimax-cli's rendering contract.
	// CurrentWeeklyUsageCount 是按 minimax-cli 展示合同复制的供应商误命名周剩余次数。
	CurrentWeeklyUsageCount int64 `json:"current_weekly_usage_count"`
	// CurrentWeeklyRemainingPercent is the optional base weekly remaining percentage.
	// CurrentWeeklyRemainingPercent 是可选的周基础剩余百分比。
	CurrentWeeklyRemainingPercent *float64 `json:"current_weekly_remaining_percent"`
	// CurrentWeeklyStatus is 1 normal, 2 exhausted, or 3 unlimited.
	// CurrentWeeklyStatus 为 1 正常、2 耗尽或 3 无限。
	CurrentWeeklyStatus *int `json:"current_weekly_status"`
	// WeeklyStartTime is the weekly start in Unix milliseconds.
	// WeeklyStartTime 是周周期开始时间的 Unix 毫秒值。
	WeeklyStartTime int64 `json:"weekly_start_time"`
	// WeeklyEndTime is the weekly end in Unix milliseconds.
	// WeeklyEndTime 是周周期结束时间的 Unix 毫秒值。
	WeeklyEndTime int64 `json:"weekly_end_time"`
	// WeeklyRemainsTime is the provider-reported weekly remaining milliseconds.
	// WeeklyRemainsTime 是供应商报告的周周期剩余毫秒数。
	WeeklyRemainsTime int64 `json:"weekly_remains_time"`
	// WeeklyBoostPermille is the provider presentation multiplier in thousandths.
	// WeeklyBoostPermille 是供应商以千分比报告的展示倍率。
	WeeklyBoostPermille *int64 `json:"weekly_boost_permille"`
}

// NewAllowanceDriver creates one strict MiniMax quota reader for a single regional Definition.
// NewAllowanceDriver 为单个区域 Definition 创建严格的 MiniMax 额度读取器。
func NewAllowanceDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AllowanceDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil || len(definition.EndpointPresets) != 1 {
		return nil, errors.New("MiniMax definition, one endpoint preset, secret store, and HTTP client are required")
	}
	baseURL := strings.TrimRight(definition.EndpointPresets[0].BaseURL, "/")
	if baseURL == "" {
		return nil, errors.New("MiniMax quota base URL is required")
	}
	return &AllowanceDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client), baseURL: baseURL, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Definition returns the immutable region-specific MiniMax definition.
// Definition 返回不可变的区域特定 MiniMax Definition。
func (d *AllowanceDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves runtime execution errors to the action Driver.
// ClassifyError 将运行时执行错误交给动作 Driver。
func (d *AllowanceDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadAllowances requests and normalizes current interval and weekly quota windows.
// ReadAllowances 请求并规范化当前周期与周额度窗口。
func (d *AllowanceDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	if instance.DefinitionID != d.definition.ID || credential.ProviderInstanceID != instance.ID || (credential.AuthMethodID != "api_key" && credential.AuthMethodID != "device_flow") {
		return nil, fmt.Errorf("%w: MiniMax quota scope or authentication method is invalid", provider.ErrMetadataAuthentication)
	}
	apiKey, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: resolve MiniMax credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	defer clear(apiKey)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+tokenPlanRemainsPath, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create MiniMax quota request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+string(apiKey))
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request MiniMax quota: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: MiniMax selected regional endpoint rejected the credential", provider.ErrMetadataAuthentication)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: MiniMax quota HTTP status %d", provider.ErrMetadataUnavailable, response.StatusCode)
	}
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumQuotaResponseBytes+1))
	if errBody != nil || len(body) > maximumQuotaResponseBytes {
		return nil, fmt.Errorf("%w: read MiniMax quota response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	var payload quotaResponse
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return nil, fmt.Errorf("%w: decode MiniMax quota response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	if errTrailing := rejectTrailingQuotaJSON(decoder); errTrailing != nil {
		return nil, errTrailing
	}
	observedAt := d.now().UTC()
	allowances := make([]catalog.AllowanceSnapshot, 0, len(payload.ModelRemains)*2)
	for index, model := range payload.ModelRemains {
		modelAllowances, errNormalize := normalizeQuotaModel(instance.ID, credential.ID, index, model, observedAt)
		if errNormalize != nil {
			return nil, errNormalize
		}
		allowances = append(allowances, modelAllowances...)
	}
	return allowances, nil
}

// rejectTrailingQuotaJSON rejects ambiguous data after the single quota object.
// rejectTrailingQuotaJSON 拒绝单个额度对象之后的含糊数据。
func rejectTrailingQuotaJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		return fmt.Errorf("%w: MiniMax quota response contains trailing JSON", provider.ErrMetadataResponseInvalid)
	}
	return nil
}

// normalizeQuotaModel creates two independent typed windows from one provider bucket.
// normalizeQuotaModel 从一个供应商额度桶创建两个独立类型化窗口。
func normalizeQuotaModel(instanceID string, credentialID string, index int, model quotaModelRemain, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	name := strings.TrimSpace(model.ModelName)
	if name == "" || model.CurrentIntervalTotalCount < 0 || model.CurrentIntervalUsageCount < 0 || model.CurrentWeeklyTotalCount < 0 || model.CurrentWeeklyUsageCount < 0 || model.RemainsTime < 0 || model.WeeklyRemainsTime < 0 {
		return nil, fmt.Errorf("%w: MiniMax quota row %d contains invalid identity or negative counters", provider.ErrMetadataResponseInvalid, index)
	}
	notIncluded := model.CurrentIntervalTotalCount == 0 && model.CurrentWeeklyTotalCount == 0 && quotaStatus(model.CurrentIntervalStatus) == 3 && quotaStatus(model.CurrentWeeklyStatus) == 3
	currentStart, errCurrentStart := quotaResetTime(model.StartTime)
	if errCurrentStart != nil {
		return nil, fmt.Errorf("%w: MiniMax quota row %d current interval start: %v", provider.ErrMetadataResponseInvalid, index, errCurrentStart)
	}
	currentReset, errCurrentTime := quotaResetTime(model.EndTime)
	if errCurrentTime != nil {
		return nil, fmt.Errorf("%w: MiniMax quota row %d current interval: %v", provider.ErrMetadataResponseInvalid, index, errCurrentTime)
	}
	weeklyReset, errWeeklyTime := quotaResetTime(model.WeeklyEndTime)
	if errWeeklyTime != nil {
		return nil, fmt.Errorf("%w: MiniMax quota row %d weekly interval: %v", provider.ErrMetadataResponseInvalid, index, errWeeklyTime)
	}
	weeklyStart, errWeeklyStart := quotaResetTime(model.WeeklyStartTime)
	if errWeeklyStart != nil {
		return nil, fmt.Errorf("%w: MiniMax quota row %d weekly interval start: %v", provider.ErrMetadataResponseInvalid, index, errWeeklyStart)
	}
	current, errCurrent := quotaAllowance(instanceID, credentialID, name, "current_interval", model.CurrentIntervalTotalCount, model.CurrentIntervalUsageCount, model.CurrentIntervalRemainingPercent, quotaStatus(model.CurrentIntervalStatus), notIncluded, &catalog.AllowanceWindow{Kind: catalog.WindowProviderDefined, StartAt: currentStart, ResetAt: currentReset}, nil, observedAt)
	if errCurrent != nil {
		return nil, errCurrent
	}
	weekly, errWeekly := quotaAllowance(instanceID, credentialID, name, "weekly", model.CurrentWeeklyTotalCount, model.CurrentWeeklyUsageCount, model.CurrentWeeklyRemainingPercent, quotaStatus(model.CurrentWeeklyStatus), notIncluded, &catalog.AllowanceWindow{Kind: catalog.WindowCalendar, CalendarUnit: "week", StartAt: weeklyStart, ResetAt: weeklyReset}, model.WeeklyBoostPermille, observedAt)
	if errWeekly != nil {
		return nil, errWeekly
	}
	return []catalog.AllowanceSnapshot{current, weekly}, nil
}

// quotaAllowance builds one validated quota snapshot without guessing model entitlement mappings.
// quotaAllowance 构建一个经过校验的额度快照且不猜测模型权益映射。
func quotaAllowance(instanceID string, credentialID string, modelName string, windowName string, limitValue int64, remainingValue int64, percent *float64, providerStatus int, notIncluded bool, window *catalog.AllowanceWindow, multiplier *int64, observedAt time.Time) (catalog.AllowanceSnapshot, error) {
	if providerStatus < 0 || providerStatus > 3 || remainingValue > limitValue && providerStatus != 3 {
		return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: MiniMax quota counters or status are invalid", provider.ErrMetadataResponseInvalid)
	}
	status := catalog.AllowanceAvailable
	limit, used, remaining := quotaCounts(limitValue, remainingValue, providerStatus)
	ratio, errRatio := quotaRatio(percent, limitValue, remainingValue, providerStatus)
	if errRatio != nil {
		return catalog.AllowanceSnapshot{}, errRatio
	}
	switch {
	case notIncluded:
		status = catalog.AllowanceNotIncluded
	case providerStatus == 3:
		status = catalog.AllowanceUnlimited
	case providerStatus == 2:
		status = catalog.AllowanceExhausted
	case ratio != nil && *ratio < 0.2:
		status = catalog.AllowanceLow
	}
	metricName := "minimax." + modelName + "." + windowName
	allowance := catalog.AllowanceSnapshot{ID: miniMaxAllowanceID(credentialID, modelName, windowName), ProviderInstanceID: instanceID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: credentialID, Metric: metricName, Unit: catalog.UnitRequests, Limit: limit, Used: used, Remaining: remaining, RemainingRatio: ratio, Status: status, Mandatory: false, Window: window, DisplayMultiplierPermille: multiplier, Source: catalog.ModelSourceProviderAPI, EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}
	if errValidate := allowance.Validate(); errValidate != nil {
		return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: MiniMax normalized quota is invalid: %v", provider.ErrMetadataResponseInvalid, errValidate)
	}
	return allowance, nil
}

// quotaCounts returns exact decimal pointers and omits invented amounts for unlimited buckets.
// quotaCounts 返回精确十进制指针，并为无限额度桶省略虚构数值。
func quotaCounts(limitValue int64, remainingValue int64, providerStatus int) (*string, *string, *string) {
	if providerStatus == 3 {
		return nil, nil, nil
	}
	usedValue := limitValue - remainingValue
	limit := strconv.FormatInt(limitValue, 10)
	used := strconv.FormatInt(usedValue, 10)
	remaining := strconv.FormatInt(remainingValue, 10)
	return &limit, &used, &remaining
}

// quotaRatio normalizes an optional provider percentage or derives it only from exact counts.
// quotaRatio 规范化可选供应商百分比，或仅从精确计数派生比例。
func quotaRatio(percent *float64, limitValue int64, remainingValue int64, providerStatus int) (*float64, error) {
	if providerStatus == 3 {
		return nil, nil
	}
	if percent != nil {
		if *percent < 0 || *percent > 100 {
			return nil, fmt.Errorf("%w: MiniMax remaining percentage is outside zero to one hundred", provider.ErrMetadataResponseInvalid)
		}
		value := *percent / 100
		return &value, nil
	}
	if limitValue == 0 {
		return nil, nil
	}
	value := float64(remainingValue) / float64(limitValue)
	return &value, nil
}

// quotaResetTime validates one absolute Unix-millisecond reset boundary.
// quotaResetTime 校验一个绝对 Unix 毫秒重置边界。
func quotaResetTime(epochMilliseconds int64) (*time.Time, error) {
	if epochMilliseconds <= 0 {
		return nil, nil
	}
	resetAt := time.UnixMilli(epochMilliseconds).UTC()
	return &resetAt, nil
}

// quotaStatus returns zero only when the optional status is absent.
// quotaStatus 仅在可选状态缺失时返回零。
func quotaStatus(status *int) int {
	if status == nil {
		return 0
	}
	return *status
}

// miniMaxAllowanceID creates a stable credential-scoped identifier from provider-owned names.
// miniMaxAllowanceID 从供应商拥有的名称创建稳定的凭据作用域标识。
func miniMaxAllowanceID(credentialID string, modelName string, windowName string) string {
	digest := sha256.Sum256([]byte(modelName))
	return "allow_minimax_" + strings.TrimPrefix(credentialID, "cred_") + "_" + hex.EncodeToString(digest[:6]) + "_" + windowName
}
