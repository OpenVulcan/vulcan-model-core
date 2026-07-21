package kimi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	// kimiUsageURL is the Coding Plan usage endpoint copied from the source router.
	// kimiUsageURL 是从来源路由项目复制的 Coding Plan 用量入口。
	kimiUsageURL = "https://api.kimi.com/coding/v1/usages"
	// kimiUsageResponseLimit bounds one account usage response.
	// kimiUsageResponseLimit 限制一份账号用量响应的大小。
	kimiUsageResponseLimit = 1 << 20
	// kimiUsageUserAgent is the exact Kimi CLI identity proven by the source router's usage implementation.
	// kimiUsageUserAgent 是来源路由用量实现验证过的精确 Kimi CLI 身份。
	kimiUsageUserAgent = "KimiCLI/1.10.6"
	// kimiUsagePlatform is the exact platform value accepted by the Kimi account API.
	// kimiUsagePlatform 是 Kimi 账号接口接受的精确平台值。
	kimiUsagePlatform = "kimi_cli"
	// kimiUsageVersion is the exact client version paired with the proven usage headers.
	// kimiUsageVersion 是与已验证用量请求头配套的精确客户端版本。
	kimiUsageVersion = "1.10.6"
)

// AllowanceDriver reads Kimi Coding Plan usage without exposing bearer credentials.
// AllowanceDriver 读取 Kimi Coding Plan 用量且不暴露 Bearer 凭据。
type AllowanceDriver struct {
	// definition is the immutable Coding Plan definition.
	// definition 是不可变的 Coding Plan 定义。
	definition providerconfig.ProviderDefinition
	// tokens projects API keys and device-flow documents to bearer values.
	// tokens 将 API Key 与设备授权文档投影为 Bearer 值。
	tokens *AccessTokenStore
	// client performs bounded usage requests without redirects.
	// client 执行有界且不跟随重定向的用量请求。
	client *http.Client
}

// kimiUsageDetail is one exact Kimi usage counter subset.
// kimiUsageDetail 是一组精确的 Kimi 用量计数字段子集。
type kimiUsageDetail struct {
	// Used is the consumed provider quantity.
	// Used 是已消费的供应商数量。
	Used providermetadata.Decimal `json:"used"`
	// Limit is the maximum provider quantity.
	// Limit 是供应商数量上限。
	Limit providermetadata.Decimal `json:"limit"`
	// Remaining is the provider-reported available quantity.
	// Remaining 是供应商报告的可用数量。
	Remaining providermetadata.Decimal `json:"remaining"`
	// Name is the optional provider metric name.
	// Name 是可选供应商指标名称。
	Name string `json:"name"`
	// Title is the optional provider display title.
	// Title 是可选供应商显示标题。
	Title string `json:"title"`
	// ResetAt is the camel-case absolute reset time.
	// ResetAt 是驼峰形式的绝对重置时间。
	ResetAt string `json:"resetAt"`
	// ResetAtSnake is the snake-case absolute reset time.
	// ResetAtSnake 是下划线形式的绝对重置时间。
	ResetAtSnake string `json:"reset_at"`
	// ResetTime is the alternate camel-case reset time.
	// ResetTime 是备用驼峰形式重置时间。
	ResetTime string `json:"resetTime"`
	// ResetTimeSnake is the alternate snake-case reset time.
	// ResetTimeSnake 是备用下划线形式重置时间。
	ResetTimeSnake string `json:"reset_time"`
	// ResetIn is the camel-case relative reset delay.
	// ResetIn 是驼峰形式相对重置延迟。
	ResetIn providermetadata.Decimal `json:"resetIn"`
	// ResetInSnake is the snake-case relative reset delay.
	// ResetInSnake 是下划线形式相对重置延迟。
	ResetInSnake providermetadata.Decimal `json:"reset_in"`
	// TTL is the alternate relative reset delay.
	// TTL 是备用相对重置延迟。
	TTL providermetadata.Decimal `json:"ttl"`
	// Duration is an alternate inline window magnitude.
	// Duration 是备用的内联窗口数值。
	Duration providermetadata.Decimal `json:"duration"`
	// TimeUnit is the alternate inline window unit.
	// TimeUnit 是备用的内联窗口单位。
	TimeUnit string `json:"timeUnit"`
}

// kimiLimitWindow describes a provider-reported rolling duration.
// kimiLimitWindow 描述供应商报告的滚动时长。
type kimiLimitWindow struct {
	// Duration is the positive duration magnitude.
	// Duration 是正数时长数值。
	Duration providermetadata.Decimal `json:"duration"`
	// TimeUnit identifies seconds, minutes, hours, or days.
	// TimeUnit 标识秒、分钟、小时或天。
	TimeUnit string `json:"timeUnit"`
}

// kimiLimitItem contains one named Kimi usage window.
// kimiLimitItem 包含一个具名 Kimi 用量窗口。
type kimiLimitItem struct {
	kimiUsageDetail
	// Scope is the fallback provider metric name.
	// Scope 是备用供应商指标名称。
	Scope string `json:"scope"`
	// Detail contains the actual counter when Kimi nests it.
	// Detail 在 Kimi 嵌套计数时包含实际计数。
	Detail *kimiUsageDetail `json:"detail"`
	// Window contains explicit duration metadata.
	// Window 包含显式时长元数据。
	Window *kimiLimitWindow `json:"window"`
	// Duration is the item-level window magnitude used by legacy responses.
	// Duration 是旧版响应使用的条目级窗口数值。
	Duration providermetadata.Decimal `json:"duration"`
	// TimeUnit is the item-level window unit used by legacy responses.
	// TimeUnit 是旧版响应使用的条目级窗口单位。
	TimeUnit string `json:"timeUnit"`
}

// kimiUsageResponse is the exact Kimi account usage envelope.
// kimiUsageResponse 是精确的 Kimi 账号用量信封。
type kimiUsageResponse struct {
	// Usage is the account summary counter.
	// Usage 是账号汇总计数。
	Usage *kimiUsageDetail `json:"usage"`
	// Limits contains detailed usage windows.
	// Limits 包含详细用量窗口。
	Limits []kimiLimitItem `json:"limits"`
	// User contains the account membership facts returned by the same observation.
	// User 包含同一次观测返回的账号会员事实。
	User kimiUsageUser `json:"user"`
}

// kimiUsageUser contains the exact account subset required for authorization.
// kimiUsageUser 包含授权所需的精确账号字段子集。
type kimiUsageUser struct {
	// Membership contains the current provider-owned commercial level.
	// Membership 包含当前由供应商拥有的商业等级。
	Membership kimiUsageMembership `json:"membership"`
}

// kimiUsageMembership contains Kimi's exact membership-level code.
// kimiUsageMembership 包含 Kimi 的精确会员等级代码。
type kimiUsageMembership struct {
	// Level is the exact enum returned by user.membership.level.
	// Level 是 user.membership.level 返回的精确枚举值。
	Level string `json:"level"`
}

// NewAllowanceDriver creates one strict Kimi Coding Plan usage reader.
// NewAllowanceDriver 创建一个严格的 Kimi Coding Plan 用量读取器。
func NewAllowanceDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AllowanceDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil {
		return nil, errors.New("Kimi definition, secret store, and HTTP client are required")
	}
	tokens, errTokens := NewAccessTokenStore(secrets)
	if errTokens != nil {
		return nil, errTokens
	}
	return &AllowanceDriver{definition: providerconfig.CloneProviderDefinition(definition), tokens: tokens, client: providertransport.CloneHTTPClientWithoutRedirects(client)}, nil
}

// Definition returns the immutable Kimi Coding Plan definition.
// Definition 返回不可变的 Kimi Coding Plan 定义。
func (d *AllowanceDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves execution error classification to the execution driver.
// ClassifyError 将执行错误分类留给执行 Driver。
func (d *AllowanceDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadAllowances queries and normalizes every Kimi Coding Plan usage row.
// ReadAllowances 查询并规范化每条 Kimi Coding Plan 用量记录。
func (d *AllowanceDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	payload, observedAt, errUsage := d.readUsage(ctx, credential)
	if errUsage != nil {
		return nil, errUsage
	}
	return kimiAllowances(payload, instance, credential, observedAt)
}

// ReadCredentialMetadata reads Kimi's account plan, exact model entitlements, and usage from one consistent response.
// ReadCredentialMetadata 从一份一致响应读取 Kimi 账号套餐、精确模型授权与用量。
func (d *AllowanceDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	payload, observedAt, errUsage := d.readUsage(ctx, credential)
	if errUsage != nil {
		return provider.CredentialMetadataResult{}, errUsage
	}
	allowances, errAllowances := kimiAllowances(payload, instance, credential, observedAt)
	if errAllowances != nil {
		return provider.CredentialMetadataResult{}, errAllowances
	}
	var plan catalog.PlanSnapshot
	var entitlements []catalog.ModelEntitlement
	var errMembership error
	switch credential.AuthMethodID {
	case "device_flow":
		plan, entitlements, errMembership = MembershipMetadataFromProvider(instance.ID, credential.ID, payload.User.Membership.Level, observedAt)
	case "api_key":
		if credential.DeclaredPlan == nil {
			return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Kimi API key has no declared membership", provider.ErrMetadataResponseInvalid)
		}
		tier, _, errTier := membershipFromPlanOption(credential.DeclaredPlan.PlanOptionID)
		if errTier != nil {
			return provider.CredentialMetadataResult{}, fmt.Errorf("%w: %v", provider.ErrMetadataResponseInvalid, errTier)
		}
		plan, entitlements, errMembership = membershipMetadata(instance.ID, credential.ID, tier, catalog.MetadataEvidenceOperatorDeclared, credential.DeclaredPlan.DeclaredAt, time.Time{}, credential.DeclaredPlan.Revision)
	default:
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: unsupported Kimi authentication method %q", provider.ErrMetadataAuthentication, credential.AuthMethodID)
	}
	if errMembership != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: %v", provider.ErrMetadataResponseInvalid, errMembership)
	}
	return provider.CredentialMetadataResult{Plan: &plan, Entitlements: entitlements, Allowances: allowances}, nil
}

// readUsage performs the source-proven Kimi account request and decodes its bounded response.
// readUsage 执行来源验证过的 Kimi 账号请求并解码其有界响应。
func (d *AllowanceDriver) readUsage(ctx context.Context, credential providerconfig.Credential) (kimiUsageResponse, time.Time, error) {
	accessToken, deviceID, deviceDocument, errToken := d.tokens.resolve(ctx, credential.SecretRef)
	if errToken != nil {
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: resolve Kimi credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	defer clear(accessToken)
	switch credential.AuthMethodID {
	case "device_flow":
		if !deviceDocument || strings.TrimSpace(deviceID) == "" {
			return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: Kimi device-flow credential document is invalid", provider.ErrMetadataAuthentication)
		}
	case "api_key":
		if deviceDocument {
			return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: Kimi API key credential contains a device-flow document", provider.ErrMetadataAuthentication)
		}
		deviceID = persistedKimiDeviceID()
	default:
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: unsupported Kimi authentication method %q", provider.ErrMetadataAuthentication, credential.AuthMethodID)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, kimiUsageURL, nil)
	if errRequest != nil {
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("create Kimi usage request: %w", errRequest)
	}
	applyKimiUsageHeaders(request, string(accessToken), deviceID)
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: request Kimi usage: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, kimiUsageResponseLimit+1))
	if errBody != nil || len(body) > kimiUsageResponseLimit {
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: read Kimi usage response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return kimiUsageResponse{}, time.Time{}, kimiUsageStatusError(response.StatusCode)
	}
	var payload kimiUsageResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return kimiUsageResponse{}, time.Time{}, fmt.Errorf("%w: decode Kimi usage response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	return payload, time.Now().UTC(), nil
}

// applyKimiUsageHeaders copies the source router's complete accepted account-usage request identity.
// applyKimiUsageHeaders 复制来源路由完整且已被接受的账号用量请求身份。
func applyKimiUsageHeaders(request *http.Request, accessToken string, deviceID string) {
	hostname, errHostname := os.Hostname()
	if errHostname != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown"
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", kimiUsageUserAgent)
	request.Header.Set("X-Msh-Platform", kimiUsagePlatform)
	request.Header.Set("X-Msh-Version", kimiUsageVersion)
	request.Header.Set("X-Msh-Device-Name", hostname)
	request.Header.Set("X-Msh-Device-Model", runtime.GOOS+" "+runtime.GOARCH)
	request.Header.Set("X-Msh-Device-Id", deviceID)
}

// kimiAllowances normalizes every counter in one already authenticated Kimi response.
// kimiAllowances 规范化一份已认证 Kimi 响应中的每个计数器。
func kimiAllowances(payload kimiUsageResponse, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	allowances := make([]catalog.AllowanceSnapshot, 0, len(payload.Limits)+1)
	if payload.Usage != nil {
		allowance, present, errAllowance := kimiAllowanceFromDetail(*payload.Usage, nil, "weekly_usage", instance, credential, observedAt)
		if errAllowance != nil {
			return nil, errAllowance
		}
		if present {
			allowances = append(allowances, allowance)
		}
	}
	for index, item := range payload.Limits {
		detail := item.kimiUsageDetail
		if item.Detail != nil {
			detail = *item.Detail
		}
		window := item.Window
		if window == nil {
			duration := firstKimiDecimal(item.Duration, detail.Duration)
			timeUnit := firstKimiMetric(item.TimeUnit, detail.TimeUnit)
			if duration.Set() {
				window = &kimiLimitWindow{Duration: duration, TimeUnit: timeUnit}
			}
		}
		name := firstKimiMetric(item.Name, item.Title, item.Scope, detail.Name, detail.Title)
		metric := kimiMetric(name)
		if name == "" {
			metric = kimiUnnamedLimitMetric(window, index)
		}
		allowance, present, errAllowance := kimiAllowanceFromDetail(detail, window, metric, instance, credential, observedAt)
		if errAllowance != nil {
			return nil, errAllowance
		}
		if present {
			allowances = append(allowances, allowance)
		}
	}
	return allowances, nil
}

// kimiUnnamedLimitMetric derives a canonical metric only from an explicit provider-reported window duration.
// kimiUnnamedLimitMetric 仅根据供应商显式报告的窗口时长派生规范指标。
func kimiUnnamedLimitMetric(window *kimiLimitWindow, index int) string {
	if window == nil || !window.Duration.Set() {
		return "limit_" + strconv.Itoa(index+1)
	}
	multiplier := time.Second
	switch strings.ToUpper(strings.TrimSpace(window.TimeUnit)) {
	case "", "SECONDS":
	case "MINUTES", "TIME_UNIT_MINUTE":
		multiplier = time.Minute
	case "HOURS":
		multiplier = time.Hour
	case "DAYS":
		multiplier = 24 * time.Hour
	default:
		return "limit_" + strconv.Itoa(index+1)
	}
	duration := time.Duration(window.Duration.Float64() * float64(multiplier))
	if duration == 5*time.Hour {
		return "five_hour_usage"
	}
	return "limit_" + strconv.Itoa(index+1)
}

// firstKimiDecimal returns the first explicitly reported numeric variant.
// firstKimiDecimal 返回第一个显式报告的数值变体。
func firstKimiDecimal(values ...providermetadata.Decimal) providermetadata.Decimal {
	for _, value := range values {
		if value.Set() {
			return value
		}
	}
	return providermetadata.Decimal{}
}

// kimiAllowanceFromDetail converts one provider counter without inventing a missing accounting unit.
// kimiAllowanceFromDetail 转换一个供应商计数且不臆造缺失的计量单位。
func kimiAllowanceFromDetail(detail kimiUsageDetail, window *kimiLimitWindow, metric string, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (catalog.AllowanceSnapshot, bool, error) {
	if !detail.Used.Set() && !detail.Limit.Set() && !detail.Remaining.Set() {
		return catalog.AllowanceSnapshot{}, false, nil
	}
	var limit, used, remaining *string
	if detail.Limit.Set() {
		value := detail.Limit.String()
		limit = &value
	}
	if detail.Used.Set() {
		value := detail.Used.String()
		used = &value
	}
	if detail.Remaining.Set() {
		value := detail.Remaining.String()
		remaining = &value
	} else if detail.Limit.Set() && detail.Used.Set() {
		value := detail.Limit.Float64() - detail.Used.Float64()
		if value < 0 {
			return catalog.AllowanceSnapshot{}, false, fmt.Errorf("%w: Kimi usage exceeds its limit", provider.ErrMetadataResponseInvalid)
		}
		text := strconv.FormatFloat(value, 'f', -1, 64)
		remaining = &text
	}
	var remainingRatio *float64
	if detail.Limit.Set() && detail.Limit.Float64() > 0 && remaining != nil {
		value, _ := strconv.ParseFloat(*remaining, 64)
		ratio := value / detail.Limit.Float64()
		if ratio > 1 {
			return catalog.AllowanceSnapshot{}, false, fmt.Errorf("%w: Kimi remaining usage exceeds its limit", provider.ErrMetadataResponseInvalid)
		}
		remainingRatio = &ratio
	}
	windowView, errWindow := kimiAllowanceWindow(detail, window, observedAt)
	if errWindow != nil {
		return catalog.AllowanceSnapshot{}, false, errWindow
	}
	status := catalog.AllowanceUnknownSufficiency
	if remainingRatio != nil {
		status = catalog.AllowanceAvailable
		if *remainingRatio <= 0 {
			status = catalog.AllowanceExhausted
		} else if *remainingRatio <= 0.1 {
			status = catalog.AllowanceLow
		}
	}
	return catalog.AllowanceSnapshot{ID: kimiAllowanceID(credential.ID, metric), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: metric, Unit: catalog.UnitProviderDefined, Limit: limit, Used: used, Remaining: remaining, RemainingRatio: remainingRatio, Status: status, Mandatory: false, Window: windowView, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}, true, nil
}

// kimiAllowanceWindow resolves only explicitly reported duration and reset facts.
// kimiAllowanceWindow 仅解析供应商显式报告的时长与重置事实。
func kimiAllowanceWindow(detail kimiUsageDetail, window *kimiLimitWindow, observedAt time.Time) (*catalog.AllowanceWindow, error) {
	result := &catalog.AllowanceWindow{Kind: catalog.WindowProviderDefined}
	if window != nil && window.Duration.Set() {
		multiplier := time.Second
		switch strings.ToUpper(strings.TrimSpace(window.TimeUnit)) {
		case "", "SECONDS":
		case "MINUTES", "TIME_UNIT_MINUTE":
			multiplier = time.Minute
		case "HOURS":
			multiplier = time.Hour
		case "DAYS":
			multiplier = 24 * time.Hour
		default:
			return nil, fmt.Errorf("%w: Kimi usage window unit %q is invalid", provider.ErrMetadataResponseInvalid, window.TimeUnit)
		}
		result.Kind = catalog.WindowRolling
		result.Duration = time.Duration(window.Duration.Float64() * float64(multiplier))
		if result.Duration <= 0 {
			return nil, fmt.Errorf("%w: Kimi usage window duration is invalid", provider.ErrMetadataResponseInvalid)
		}
	}
	for _, raw := range []string{detail.ResetAt, detail.ResetAtSnake, detail.ResetTime, detail.ResetTimeSnake} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		reset, errReset := time.Parse(time.RFC3339, raw)
		if errReset != nil {
			return nil, fmt.Errorf("%w: Kimi reset time is invalid", provider.ErrMetadataResponseInvalid)
		}
		result.ResetAt = &reset
		return result, nil
	}
	for _, delay := range []providermetadata.Decimal{detail.ResetIn, detail.ResetInSnake, detail.TTL} {
		if delay.Set() {
			reset := observedAt.Add(time.Duration(delay.Float64() * float64(time.Second)))
			result.ResetAt = &reset
			break
		}
	}
	return result, nil
}

// firstKimiMetric returns the first exact non-empty provider metric label.
// firstKimiMetric 返回第一个精确的非空供应商指标标签。
func firstKimiMetric(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// kimiMetric normalizes a provider label into a stable readable metric identifier.
// kimiMetric 将供应商标签规范化为稳定且可读的指标标识。
func kimiMetric(value string) string {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(value)), func(character rune) bool {
		return (character < 'a' || character > 'z') && (character < '0' || character > '9')
	})
	if len(parts) == 0 {
		return "provider_limit"
	}
	return strings.Join(parts, "_")
}

// kimiAllowanceID derives a bounded stable allowance identifier.
// kimiAllowanceID 派生一个有界且稳定的额度标识。
func kimiAllowanceID(credentialID string, metric string) string {
	digest := sha256.Sum256([]byte(credentialID + "\x00" + metric))
	return fmt.Sprintf("allow_%x", digest)
}

// kimiUsageStatusError classifies one upstream status without retaining response content.
// kimiUsageStatusError 在不保留响应内容的情况下分类一个上游状态。
func kimiUsageStatusError(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: Kimi usage request returned status %d", provider.ErrMetadataAuthentication, status)
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return fmt.Errorf("%w: Kimi usage request returned status %d", provider.ErrMetadataUnavailable, status)
	}
	return fmt.Errorf("%w: Kimi usage request returned status %d", provider.ErrMetadataResponseInvalid, status)
}
