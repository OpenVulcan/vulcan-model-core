package openai

import (
	"context"
	"crypto/sha256"
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
	providermetadata "github.com/OpenVulcan/vulcan-model-core/internal/provider/metadata"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// CodexCatalogModel contains one exact model identity copied from CLIProxyAPI's pinned models.json catalog.
// CodexCatalogModel 包含从 CLIProxyAPI 固定版本 models.json 目录复制的一条精确模型身份。
type CodexCatalogModel struct {
	// UpstreamID is the exact Codex model identifier sent to the provider.
	// UpstreamID 是发送给供应商的精确 Codex 模型标识。
	UpstreamID string
	// DisplayName is the copied operator-facing model name.
	// DisplayName 是复制的面向操作员模型名称。
	DisplayName string
	// ContextWindow is the copied total context limit.
	// ContextWindow 是复制的总上下文限制。
	ContextWindow int64
	// MaxOutputTokens is the copied maximum completion size.
	// MaxOutputTokens 是复制的最大补全大小。
	MaxOutputTokens int64
	// Reasoning records the structured thinking capability declared by the source catalog.
	// Reasoning 记录源码目录声明的结构化 Thinking 能力。
	Reasoning catalog.CapabilityLevel
	// ToolCalling records the source catalog's explicit tools parameter support.
	// ToolCalling 记录源码目录明确声明的 tools 参数支持。
	ToolCalling catalog.CapabilityLevel
}

// CodexCatalogDriver reads plan and model-authorization metadata from the protected Codex OAuth document.
// CodexCatalogDriver 从受保护的 Codex OAuth 文档读取套餐与模型授权元数据。
type CodexCatalogDriver struct {
	// definition is the exact immutable Codex product definition.
	// definition 是精确且不可变的 Codex 产品定义。
	definition providerconfig.ProviderDefinition
	// secrets resolves protected OAuth documents only for local claim inspection.
	// secrets 仅为本地声明检查解析受保护 OAuth 文档。
	secrets secret.Store
	// client executes bounded Codex account-control requests without following redirects.
	// client 执行有界的 Codex 账号控制请求且不跟随重定向。
	client *http.Client
	// usageURL is the exact account-control endpoint and remains replaceable only by package tests.
	// usageURL 是精确账号控制入口且仅允许包内测试替换。
	usageURL string
}

const (
	// codexUsageURL is the account usage endpoint copied from the source router.
	// codexUsageURL 是从来源路由项目复制的账号用量入口。
	codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"
	// codexUsageResponseLimit bounds one protected account metadata response.
	// codexUsageResponseLimit 限制一份受保护账号元数据响应的大小。
	codexUsageResponseLimit = 1 << 20
)

// codexUsageWindow is the exact percentage-window subset returned by the Codex usage API.
// codexUsageWindow 是 Codex 用量 API 返回的精确百分比窗口字段子集。
type codexUsageWindow struct {
	// UsedPercent is the consumed percentage.
	// UsedPercent 是已消费百分比。
	UsedPercent providermetadata.Decimal `json:"used_percent"`
	// UsedPercentCamel is the camel-case consumed percentage variant.
	// UsedPercentCamel 是驼峰形式已消费百分比变体。
	UsedPercentCamel providermetadata.Decimal `json:"usedPercent"`
	// LimitWindowSeconds is the provider-reported window duration.
	// LimitWindowSeconds 是供应商报告的窗口时长。
	LimitWindowSeconds providermetadata.Decimal `json:"limit_window_seconds"`
	// LimitWindowSecondsCamel is the camel-case duration variant.
	// LimitWindowSecondsCamel 是驼峰形式时长变体。
	LimitWindowSecondsCamel providermetadata.Decimal `json:"limitWindowSeconds"`
	// ResetAfterSeconds is the relative reset delay.
	// ResetAfterSeconds 是相对重置延迟。
	ResetAfterSeconds providermetadata.Decimal `json:"reset_after_seconds"`
	// ResetAfterSecondsCamel is the camel-case relative reset variant.
	// ResetAfterSecondsCamel 是驼峰形式相对重置变体。
	ResetAfterSecondsCamel providermetadata.Decimal `json:"resetAfterSeconds"`
	// ResetAt is the absolute Unix reset timestamp.
	// ResetAt 是绝对 Unix 重置时间戳。
	ResetAt providermetadata.Decimal `json:"reset_at"`
	// ResetAtCamel is the camel-case absolute reset variant.
	// ResetAtCamel 是驼峰形式绝对重置变体。
	ResetAtCamel providermetadata.Decimal `json:"resetAt"`
}

// codexRateLimit is one primary-secondary usage window pair.
// codexRateLimit 是一对主次用量窗口。
type codexRateLimit struct {
	// Allowed reports current provider permission.
	// Allowed 报告当前供应商许可状态。
	Allowed *bool `json:"allowed"`
	// LimitReached reports explicit exhaustion.
	// LimitReached 报告显式耗尽状态。
	LimitReached bool `json:"limit_reached"`
	// LimitReachedCamel is the camel-case exhaustion variant.
	// LimitReachedCamel 是驼峰形式耗尽状态变体。
	LimitReachedCamel bool `json:"limitReached"`
	// PrimaryWindow is the short provider window.
	// PrimaryWindow 是供应商短周期窗口。
	PrimaryWindow *codexUsageWindow `json:"primary_window"`
	// PrimaryWindowCamel is the camel-case primary window variant.
	// PrimaryWindowCamel 是驼峰形式主窗口变体。
	PrimaryWindowCamel *codexUsageWindow `json:"primaryWindow"`
	// SecondaryWindow is the long provider window.
	// SecondaryWindow 是供应商长周期窗口。
	SecondaryWindow *codexUsageWindow `json:"secondary_window"`
	// SecondaryWindowCamel is the camel-case secondary window variant.
	// SecondaryWindowCamel 是驼峰形式次窗口变体。
	SecondaryWindowCamel *codexUsageWindow `json:"secondaryWindow"`
}

// codexAdditionalRateLimit is one named metered feature returned by Codex.
// codexAdditionalRateLimit 是 Codex 返回的一项具名计量功能。
type codexAdditionalRateLimit struct {
	// LimitName is the provider display identifier.
	// LimitName 是供应商显示标识。
	LimitName string `json:"limit_name"`
	// LimitNameCamel is the camel-case display identifier variant.
	// LimitNameCamel 是驼峰形式显示标识变体。
	LimitNameCamel string `json:"limitName"`
	// MeteredFeature is the fallback stable feature identifier.
	// MeteredFeature 是备用的稳定功能标识。
	MeteredFeature string `json:"metered_feature"`
	// MeteredFeatureCamel is the camel-case feature identifier variant.
	// MeteredFeatureCamel 是驼峰形式功能标识变体。
	MeteredFeatureCamel string `json:"meteredFeature"`
	// RateLimit contains this feature's windows.
	// RateLimit 包含该功能的窗口。
	RateLimit *codexRateLimit `json:"rate_limit"`
	// RateLimitCamel is the camel-case rate-limit variant.
	// RateLimitCamel 是驼峰形式限额变体。
	RateLimitCamel *codexRateLimit `json:"rateLimit"`
}

// codexUsageResponse is the exact account-usage subset consumed by Vulcan.
// codexUsageResponse 是 Vulcan 消费的精确账号用量字段子集。
type codexUsageResponse struct {
	// RateLimit contains normal coding limits.
	// RateLimit 包含常规编码限额。
	RateLimit *codexRateLimit `json:"rate_limit"`
	// RateLimitCamel is the camel-case normal coding limits variant.
	// RateLimitCamel 是驼峰形式常规编码限额变体。
	RateLimitCamel *codexRateLimit `json:"rateLimit"`
	// CodeReviewRateLimit contains code-review limits.
	// CodeReviewRateLimit 包含代码审查限额。
	CodeReviewRateLimit *codexRateLimit `json:"code_review_rate_limit"`
	// CodeReviewRateLimitCamel is the camel-case code-review limits variant.
	// CodeReviewRateLimitCamel 是驼峰形式代码审查限额变体。
	CodeReviewRateLimitCamel *codexRateLimit `json:"codeReviewRateLimit"`
	// AdditionalRateLimits contains provider-named feature limits.
	// AdditionalRateLimits 包含供应商命名的功能限额。
	AdditionalRateLimits []codexAdditionalRateLimit `json:"additional_rate_limits"`
	// AdditionalRateLimitsCamel is the camel-case feature limits variant.
	// AdditionalRateLimitsCamel 是驼峰形式功能限额变体。
	AdditionalRateLimitsCamel []codexAdditionalRateLimit `json:"additionalRateLimits"`
	// RateLimitResetCredits contains remaining manual reset grants.
	// RateLimitResetCredits 包含剩余的手动重置次数。
	RateLimitResetCredits *struct {
		// AvailableCount is the remaining reset count.
		// AvailableCount 是剩余重置次数。
		AvailableCount providermetadata.Decimal `json:"available_count"`
		// AvailableCountCamel is the camel-case remaining reset count variant.
		// AvailableCountCamel 是驼峰形式剩余重置次数变体。
		AvailableCountCamel providermetadata.Decimal `json:"availableCount"`
	} `json:"rate_limit_reset_credits"`
	// RateLimitResetCreditsCamel is the camel-case reset grant variant.
	// RateLimitResetCreditsCamel 是驼峰形式重置次数变体。
	RateLimitResetCreditsCamel *struct {
		// AvailableCount is the remaining reset count.
		// AvailableCount 是剩余重置次数。
		AvailableCount providermetadata.Decimal `json:"available_count"`
		// AvailableCountCamel is the camel-case remaining reset count.
		// AvailableCountCamel 是驼峰形式剩余重置次数。
		AvailableCountCamel providermetadata.Decimal `json:"availableCount"`
	} `json:"rateLimitResetCredits"`
}

// NewCodexCatalogDriver creates a plan and entitlement reader backed by protected Codex token documents.
// NewCodexCatalogDriver 创建由受保护 Codex Token 文档支持的套餐与授权读取器。
func NewCodexCatalogDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, clients ...*http.Client) (*CodexCatalogDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) {
		return nil, errors.New("Codex definition and secret store are required")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if len(clients) > 0 && clients[0] != nil {
		client = clients[0]
	}
	return &CodexCatalogDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client), usageURL: codexUsageURL}, nil
}

// Definition returns the immutable Codex system definition.
// Definition 返回不可变的 Codex 系统定义。
func (d *CodexCatalogDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves execution error classification to the execution driver.
// ClassifyError 将执行错误分类留给执行 Driver。
func (d *CodexCatalogDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadPlan returns the ChatGPT plan claim embedded in the protected OAuth document's identity token.
// ReadPlan 返回受保护 OAuth 文档身份令牌中嵌入的 ChatGPT 套餐声明。
func (d *CodexCatalogDriver) ReadPlan(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (catalog.PlanSnapshot, error) {
	metadata, _, errMetadata := d.readProtectedMetadata(ctx, instance, credential, time.Now().UTC())
	if errMetadata != nil {
		return catalog.PlanSnapshot{}, errMetadata
	}
	if metadata.Plan == nil {
		return catalog.PlanSnapshot{}, fmt.Errorf("%w: Codex metadata omitted its plan", provider.ErrMetadataResponseInvalid)
	}
	return *metadata.Plan, nil
}

// ReadEntitlements returns the exact Codex model set selected by CLIProxyAPI for the token's plan claim.
// ReadEntitlements 返回 CLIProxyAPI 根据 Token 套餐声明选择的精确 Codex 模型集合。
func (d *CodexCatalogDriver) ReadEntitlements(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.ModelEntitlement, error) {
	metadata, _, errMetadata := d.readProtectedMetadata(ctx, instance, credential, time.Now().UTC())
	if errMetadata != nil {
		return nil, errMetadata
	}
	return append([]catalog.ModelEntitlement(nil), metadata.Entitlements...), nil
}

// ReadAllowances returns every Codex account window and reset-credit balance.
// ReadAllowances 返回 Codex 账号的全部窗口与重置次数余额。
func (d *CodexCatalogDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	value, errValue := d.secrets.Get(ctx, credential.SecretRef)
	if errValue != nil {
		return nil, fmt.Errorf("%w: resolve Codex credential: %v", provider.ErrMetadataAuthentication, errValue)
	}
	defer clear(value)
	token, errToken := UnmarshalCodexToken(value)
	if errToken != nil {
		return nil, fmt.Errorf("%w: decode Codex credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	return d.readUsage(ctx, instance, credential, token, time.Now().UTC())
}

// ReadCredentialMetadata decodes one internally consistent plan and entitlement observation from the protected OAuth document.
// ReadCredentialMetadata 从受保护 OAuth 文档解码一份内部一致的套餐与授权观测。
func (d *CodexCatalogDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	observedAt := time.Now().UTC()
	metadata, token, errMetadata := d.readProtectedMetadata(ctx, instance, credential, observedAt)
	if errMetadata != nil {
		return provider.CredentialMetadataResult{}, errMetadata
	}
	allowances, errAllowances := d.readUsage(ctx, instance, credential, token, observedAt)
	if errAllowances != nil {
		return provider.CredentialMetadataResult{}, errAllowances
	}
	metadata.Allowances = allowances
	return metadata, nil
}

// readProtectedMetadata derives local token claims and returns the validated transport token in one secret read.
// readProtectedMetadata 在一次 Secret 读取中派生本地 Token 声明并返回已校验的传输 Token。
func (d *CodexCatalogDriver) readProtectedMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (provider.CredentialMetadataResult, CodexToken, error) {
	value, errValue := d.secrets.Get(ctx, credential.SecretRef)
	if errValue != nil {
		return provider.CredentialMetadataResult{}, CodexToken{}, fmt.Errorf("%w: resolve Codex credential: %v", provider.ErrMetadataAuthentication, errValue)
	}
	defer clear(value)
	metadata, errMetadata := CodexCredentialMetadataFromToken(value, instance, credential, observedAt)
	if errMetadata != nil {
		return provider.CredentialMetadataResult{}, CodexToken{}, errMetadata
	}
	token, errToken := UnmarshalCodexToken(value)
	if errToken != nil {
		return provider.CredentialMetadataResult{}, CodexToken{}, fmt.Errorf("%w: decode Codex credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	return metadata, token, nil
}

// readUsage performs one bounded Codex usage request and normalizes every returned resource.
// readUsage 执行一次有界 Codex 用量请求并规范化全部返回资源。
func (d *CodexCatalogDriver) readUsage(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential, token CodexToken, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, d.usageURL, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create Codex usage request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal")
	if accountID := strings.TrimSpace(token.AccountID); accountID != "" {
		request.Header.Set("Chatgpt-Account-Id", accountID)
	}
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request Codex usage: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	body, errBody := io.ReadAll(io.LimitReader(response.Body, codexUsageResponseLimit+1))
	if errBody != nil || len(body) > codexUsageResponseLimit {
		return nil, fmt.Errorf("%w: read Codex usage response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, codexUsageStatusError(response.StatusCode)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	var payload codexUsageResponse
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return nil, fmt.Errorf("%w: decode Codex usage response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	allowances := make([]catalog.AllowanceSnapshot, 0, 8)
	var errAppend error
	allowances, errAppend = appendCodexRateLimit(allowances, firstCodexRateLimit(payload.RateLimit, payload.RateLimitCamel), "codex", instance, credential, observedAt)
	if errAppend != nil {
		return nil, errAppend
	}
	allowances, errAppend = appendCodexRateLimit(allowances, firstCodexRateLimit(payload.CodeReviewRateLimit, payload.CodeReviewRateLimitCamel), "code_review", instance, credential, observedAt)
	if errAppend != nil {
		return nil, errAppend
	}
	additionalRateLimits := payload.AdditionalRateLimits
	if additionalRateLimits == nil {
		additionalRateLimits = payload.AdditionalRateLimitsCamel
	}
	for index, additional := range additionalRateLimits {
		name := strings.TrimSpace(additional.LimitName)
		if name == "" {
			name = strings.TrimSpace(additional.LimitNameCamel)
		}
		if name == "" {
			name = strings.TrimSpace(additional.MeteredFeature)
		}
		if name == "" {
			name = strings.TrimSpace(additional.MeteredFeatureCamel)
		}
		if name == "" {
			name = "additional_" + strconv.Itoa(index+1)
		}
		allowances, errAppend = appendCodexRateLimit(allowances, firstCodexRateLimit(additional.RateLimit, additional.RateLimitCamel), "additional_"+codexCatalogIdentifier(name), instance, credential, observedAt)
		if errAppend != nil {
			return nil, errAppend
		}
	}
	resetCredits := payload.RateLimitResetCredits
	if resetCredits == nil {
		resetCredits = payload.RateLimitResetCreditsCamel
	}
	if resetCredits != nil {
		availableCount := firstCodexDecimal(resetCredits.AvailableCount, resetCredits.AvailableCountCamel)
		if availableCount.Set() {
			remaining := availableCount.String()
			allowances = append(allowances, catalog.AllowanceSnapshot{ID: codexHashedCatalogID("allow_", credential.ID+"\x00rate_limit_reset_credits"), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceCreditGrant, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: "rate_limit_reset_credits", Unit: catalog.UnitRequests, Remaining: &remaining, Status: allowanceStatusFromRemaining(availableCount.Float64()), Mandatory: false, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1})
		}
	}
	return allowances, nil
}

// appendCodexRateLimit appends the exact primary and secondary windows of one Codex feature.
// appendCodexRateLimit 追加一项 Codex 功能的精确主窗口与次窗口。
func appendCodexRateLimit(target []catalog.AllowanceSnapshot, limit *codexRateLimit, metricPrefix string, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	if limit == nil {
		return target, nil
	}
	windows := []struct {
		// suffix distinguishes the two provider window positions.
		// suffix 区分两个供应商窗口位置。
		suffix string
		// value contains the optional provider window.
		// value 包含可选供应商窗口。
		value *codexUsageWindow
	}{{suffix: "primary", value: firstCodexWindow(limit.PrimaryWindow, limit.PrimaryWindowCamel)}, {suffix: "secondary", value: firstCodexWindow(limit.SecondaryWindow, limit.SecondaryWindowCamel)}}
	for _, item := range windows {
		if item.value == nil {
			continue
		}
		metric := metricPrefix + "_" + item.suffix
		allowance, errAllowance := codexWindowAllowance(*item.value, limit, metric, instance, credential, observedAt)
		if errAllowance != nil {
			return nil, errAllowance
		}
		target = append(target, allowance)
	}
	return target, nil
}

// codexWindowAllowance converts one strict percentage window to the canonical resource model.
// codexWindowAllowance 将一个严格百分比窗口转换为规范资源模型。
func codexWindowAllowance(window codexUsageWindow, limit *codexRateLimit, metric string, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (catalog.AllowanceSnapshot, error) {
	usedValue := 0.0
	usedPercent := firstCodexDecimal(window.UsedPercent, window.UsedPercentCamel)
	if usedPercent.Set() {
		usedValue = usedPercent.Float64()
	} else if limit.LimitReached || limit.LimitReachedCamel || (limit.Allowed != nil && !*limit.Allowed) {
		usedValue = 100
	}
	if usedValue > 100 {
		return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: Codex usage percentage exceeds 100", provider.ErrMetadataResponseInvalid)
	}
	used := strconv.FormatFloat(usedValue, 'f', -1, 64)
	remainingValue := 100 - usedValue
	remaining := strconv.FormatFloat(remainingValue, 'f', -1, 64)
	limitText := "100"
	remainingRatio := remainingValue / 100
	windowView := &catalog.AllowanceWindow{Kind: catalog.WindowProviderDefined}
	windowSeconds := firstCodexDecimal(window.LimitWindowSeconds, window.LimitWindowSecondsCamel)
	if windowSeconds.Set() {
		seconds := windowSeconds.Float64()
		if seconds <= 0 || seconds > float64((365*24*time.Hour)/time.Second) {
			return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: Codex usage window duration is invalid", provider.ErrMetadataResponseInvalid)
		}
		windowView.Kind = catalog.WindowRolling
		windowView.Duration = time.Duration(seconds * float64(time.Second))
	}
	resetAt := firstCodexDecimal(window.ResetAt, window.ResetAtCamel)
	resetAfter := firstCodexDecimal(window.ResetAfterSeconds, window.ResetAfterSecondsCamel)
	if resetAt.Set() {
		reset := time.Unix(int64(resetAt.Float64()), 0).UTC()
		windowView.ResetAt = &reset
	} else if resetAfter.Set() {
		reset := observedAt.Add(time.Duration(resetAfter.Float64() * float64(time.Second)))
		windowView.ResetAt = &reset
	}
	return catalog.AllowanceSnapshot{ID: codexHashedCatalogID("allow_", credential.ID+"\x00"+metric), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceWindowQuota, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: metric, Unit: catalog.UnitPercentage, Limit: &limitText, Used: &used, Remaining: &remaining, RemainingRatio: &remainingRatio, Status: allowanceStatusFromRemaining(remainingValue), Mandatory: false, Window: windowView, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}, nil
}

// firstCodexDecimal returns the first explicitly reported numeric variant.
// firstCodexDecimal 返回第一个显式报告的数值变体。
func firstCodexDecimal(values ...providermetadata.Decimal) providermetadata.Decimal {
	for _, value := range values {
		if value.Set() {
			return value
		}
	}
	return providermetadata.Decimal{}
}

// firstCodexRateLimit returns the first present naming variant.
// firstCodexRateLimit 返回第一个存在的命名变体。
func firstCodexRateLimit(values ...*codexRateLimit) *codexRateLimit {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// firstCodexWindow returns the first present window naming variant.
// firstCodexWindow 返回第一个存在的窗口命名变体。
func firstCodexWindow(values ...*codexUsageWindow) *codexUsageWindow {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// allowanceStatusFromRemaining derives a display-only state from a non-negative remaining value.
// allowanceStatusFromRemaining 从非负剩余值派生仅用于显示的状态。
func allowanceStatusFromRemaining(remaining float64) catalog.AllowanceStatus {
	if remaining <= 0 {
		return catalog.AllowanceExhausted
	}
	if remaining <= 10 {
		return catalog.AllowanceLow
	}
	return catalog.AllowanceAvailable
}

// codexUsageStatusError classifies one upstream status without retaining response content.
// codexUsageStatusError 在不保留响应内容的情况下分类一个上游状态。
func codexUsageStatusError(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: Codex usage request returned status %d", provider.ErrMetadataAuthentication, status)
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
		return fmt.Errorf("%w: Codex usage request returned status %d", provider.ErrMetadataUnavailable, status)
	}
	return fmt.Errorf("%w: Codex usage request returned status %d", provider.ErrMetadataResponseInvalid, status)
}

// CodexCredentialMetadataFromToken derives one plan and its model entitlements from a protected OAuth document.
// CodexCredentialMetadataFromToken 从一份受保护 OAuth 文档派生一个套餐及其模型授权。
//
// Parameters:
//   - value: serialized protected Codex OAuth document.
//   - instance: exact provider instance that owns the observation.
//   - credential: exact account credential represented by value.
//   - observedAt: fixed observation time used by every returned snapshot.
//
// 参数：
//   - value：序列化后的受保护 Codex OAuth 文档。
//   - instance：拥有该观测的精确供应商实例。
//   - credential：value 所代表的精确账号凭据。
//   - observedAt：所有返回快照共用的固定观测时间。
//
// Returns:
//   - provider.CredentialMetadataResult: plan and allowed-model observations from one identity token.
//   - error: malformed, mismatched, expired, or incomplete OAuth evidence.
//
// 返回值：
//   - provider.CredentialMetadataResult：来自同一身份令牌的套餐与允许模型观测。
//   - error：OAuth 事实格式错误、不匹配、已过期或不完整时的错误。
func CodexCredentialMetadataFromToken(value []byte, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (provider.CredentialMetadataResult, error) {
	if strings.TrimSpace(instance.ID) == "" || strings.TrimSpace(credential.ID) == "" || observedAt.IsZero() {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Codex metadata ownership and observation time are required", provider.ErrMetadataResponseInvalid)
	}
	token, errToken := UnmarshalCodexToken(value)
	if errToken != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: decode Codex credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	claims, errClaims := parseCodexJWT(token.IDToken)
	if errClaims != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: decode Codex identity token: %v", provider.ErrMetadataAuthentication, errClaims)
	}
	accountID := strings.TrimSpace(claims.Auth.AccountID)
	if accountID == "" || accountID != strings.TrimSpace(token.AccountID) {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Codex identity token account does not match the protected credential", provider.ErrMetadataAuthentication)
	}
	planCode := strings.TrimSpace(claims.Auth.PlanType)
	if planCode == "" {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Codex identity token does not contain chatgpt_plan_type", provider.ErrMetadataResponseInvalid)
	}
	// CLIProxyAPI treats the ID token as preserved plan metadata and does not expire its decoded plan_type claim.
	// CLIProxyAPI 将 ID Token 视为保留的套餐元数据，且不会按其 exp 使已解码的 plan_type 声明失效。
	expiresAt := token.ExpiresAt.UTC()
	if !expiresAt.After(observedAt) {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Codex OAuth credential has expired", provider.ErrMetadataAuthentication)
	}
	plan := catalog.PlanSnapshot{ID: codexPlanCatalogID(credential.ID), ProviderInstanceID: instance.ID, CredentialID: credential.ID, PlanCode: planCode, PlanName: planCode, Status: "active", EvidenceSource: catalog.MetadataEvidenceProtectedTokenClaim, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 1}
	entitlementClass, upstreamModelIDs := codexPlanModels(planCode)
	entitlements := make([]catalog.ModelEntitlement, 0, len(upstreamModelIDs))
	for _, upstreamModelID := range upstreamModelIDs {
		modelSuffix := codexCatalogIdentifier(upstreamModelID)
		entitlements = append(entitlements, catalog.ModelEntitlement{
			ID:                 codexEntitlementCatalogID(credential.ID, upstreamModelID),
			ProviderInstanceID: instance.ID,
			CredentialID:       credential.ID,
			ProviderModelID:    "model_" + modelSuffix,
			Availability:       catalog.AvailabilityAllowed,
			EntitlementClass:   entitlementClass,
			Source:             catalog.ModelSourceProviderAPI,
			EvidenceSource:     catalog.MetadataEvidenceProtectedTokenClaim,
			ObservedAt:         observedAt,
			ExpiresAt:          expiresAt,
			Revision:           1,
		})
	}
	return provider.CredentialMetadataResult{Plan: &plan, Entitlements: entitlements}, nil
}

// codexPlanCatalogID derives one stable bounded plan identifier from the complete credential identity.
// codexPlanCatalogID 从完整凭据身份派生一个稳定且有界的套餐标识。
func codexPlanCatalogID(credentialID string) string {
	return codexHashedCatalogID("plan_", credentialID)
}

// codexEntitlementCatalogID derives one stable bounded authorization identifier for an exact credential-model pair.
// codexEntitlementCatalogID 为一个精确凭据与模型组合派生稳定且有界的授权标识。
func codexEntitlementCatalogID(credentialID string, upstreamModelID string) string {
	return codexHashedCatalogID("ent_", credentialID+"\x00"+upstreamModelID)
}

// codexHashedCatalogID preserves complete subject identity without inheriting source identifier length or punctuation.
// codexHashedCatalogID 保留完整主体身份，且不继承源标识长度或标点。
func codexHashedCatalogID(prefix string, subjectIdentity string) string {
	// subjectHash is a full SHA-256 digest so distinct maximum-length credential identities remain collision-resistant.
	// subjectHash 是完整 SHA-256 摘要，使不同的最大长度凭据身份仍保持抗碰撞。
	subjectHash := sha256.Sum256([]byte(subjectIdentity))
	return fmt.Sprintf("%s%x", prefix, subjectHash)
}

// CodexCatalogModels returns the exact union of CLIProxyAPI's pinned Codex plan catalogs in stable provider order.
// CodexCatalogModels 按稳定供应商顺序返回 CLIProxyAPI 固定 Codex 套餐目录的精确并集。
func CodexCatalogModels() []CodexCatalogModel {
	return []CodexCatalogModel{
		{UpstreamID: "gpt-5.3-codex-spark", DisplayName: "GPT 5.3 Codex Spark", ContextWindow: 128000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.4", DisplayName: "GPT 5.4", ContextWindow: 1050000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.4-mini", DisplayName: "GPT 5.4 Mini", ContextWindow: 400000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.5", DisplayName: "GPT 5.5", ContextWindow: 272000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.6-sol", DisplayName: "GPT 5.6 Sol", ContextWindow: 372000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.6-terra", DisplayName: "GPT 5.6 Terra", ContextWindow: 372000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "gpt-5.6-luna", DisplayName: "GPT 5.6 Luna", ContextWindow: 372000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
		{UpstreamID: "codex-auto-review", DisplayName: "Codex Auto Review", ContextWindow: 272000, MaxOutputTokens: 128000, Reasoning: catalog.CapabilityNative, ToolCalling: catalog.CapabilityNative},
	}
}

// codexPlanModels copies CLIProxyAPI's known plan branches while safely withholding unknown-plan entitlements.
// codexPlanModels 复制 CLIProxyAPI 的已知套餐分支，同时安全地不授予未知套餐权限。
func codexPlanModels(planCode string) (string, []string) {
	switch strings.ToLower(strings.TrimSpace(planCode)) {
	case "free":
		return "codex_free", []string{"gpt-5.4-mini", "gpt-5.5", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	case "team", "business", "go":
		return "codex_team", []string{"gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	case "plus":
		return "codex_plus", []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	case "pro":
		return "codex_pro", []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	default:
		return "codex_unknown", nil
	}
}

// CodexPlanKnown reports whether one provider claim belongs to the pinned safe entitlement branches.
// CodexPlanKnown 表示一个供应商声明是否属于固定的安全权益分支。
func CodexPlanKnown(planCode string) bool {
	entitlementClass, _ := codexPlanModels(planCode)
	return entitlementClass != "codex_unknown"
}

// codexCatalogIdentifier converts one fixed upstream model identifier to Vulcan's portable catalog alphabet.
// codexCatalogIdentifier 将一个固定上游模型标识转换为 Vulcan 可移植目录字母表。
func codexCatalogIdentifier(value string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}
