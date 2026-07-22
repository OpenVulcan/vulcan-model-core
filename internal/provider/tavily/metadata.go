package tavily

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
	"unicode"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	providertransport "github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

const (
	// usageEndpointPath is the documented Tavily account usage path.
	// usageEndpointPath 是文档记录的 Tavily 账号用量路径。
	usageEndpointPath = "/usage"
	// maximumUsageResponseBytes bounds one Tavily usage document before decoding.
	// maximumUsageResponseBytes 在解码前限制单个 Tavily 用量文档大小。
	maximumUsageResponseBytes = 1 << 20
)

// MetadataDriver reads one internally consistent Tavily plan and credit observation.
// MetadataDriver 读取一份内部一致的 Tavily 套餐与 Credit 观测。
type MetadataDriver struct {
	// definition is the immutable Tavily provider definition.
	// definition 是不可变的 Tavily 供应商 Definition。
	definition providerconfig.ProviderDefinition
	// secrets resolves the exact protected API key selected by the caller.
	// secrets 解析调用方选中的精确受保护 API Key。
	secrets secret.Store
	// client performs bounded requests without following redirects.
	// client 执行有界且不跟随重定向的请求。
	client *http.Client
	// baseURL is the sole documented Tavily API Origin.
	// baseURL 是唯一记录在案的 Tavily API Origin。
	baseURL string
	// now supplies deterministic observation timestamps.
	// now 提供确定性观测时间戳。
	now func() time.Time
}

// usageResponse mirrors the documented Tavily key and account usage objects.
// usageResponse 镜像文档记录的 Tavily Key 与账号用量对象。
type usageResponse struct {
	// Key contains the selected API key's exact credit counters.
	// Key 包含所选 API Key 的精确 Credit 计数。
	Key usageKey `json:"key"`
	// Account contains the enclosing account's plan and aggregate counters.
	// Account 包含所属账号的套餐与聚合计数。
	Account usageAccount `json:"account"`
}

// usageKey contains the documented API-key usage fields consumed by the Router.
// usageKey 包含 Router 消费的文档化 API Key 用量字段。
type usageKey struct {
	// Usage is total credits consumed by this key.
	// Usage 是此 Key 消耗的 Credit 总量。
	Usage int64 `json:"usage"`
	// Limit is the optional total credit limit for this key; Tavily returns null when the key has no independent cap.
	// Limit 是此 Key 的可选 Credit 总上限；当 Key 没有独立上限时 Tavily 返回 null。
	Limit *int64 `json:"limit"`
	// SearchUsage is search credit consumption.
	// SearchUsage 是搜索 Credit 消耗。
	SearchUsage int64 `json:"search_usage"`
	// ExtractUsage is extraction credit consumption.
	// ExtractUsage 是内容提取 Credit 消耗。
	ExtractUsage int64 `json:"extract_usage"`
}

// usageAccount contains the documented account-level fields consumed by the Router.
// usageAccount 包含 Router 消费的文档化账号级字段。
type usageAccount struct {
	// CurrentPlan is the provider-authored commercial plan name.
	// CurrentPlan 是供应商编写的商业套餐名称。
	CurrentPlan string `json:"current_plan"`
	// PlanUsage is account plan credit consumption.
	// PlanUsage 是账号套餐 Credit 消耗。
	PlanUsage int64 `json:"plan_usage"`
	// PlanLimit is the optional account plan credit limit.
	// PlanLimit 是可选的账号套餐 Credit 上限。
	PlanLimit *int64 `json:"plan_limit"`
	// PaygoUsage is pay-as-you-go credit consumption.
	// PaygoUsage 是按量付费 Credit 消耗。
	PaygoUsage int64 `json:"paygo_usage"`
	// PaygoLimit is the optional pay-as-you-go credit limit; Tavily returns null when no independent cap exists.
	// PaygoLimit 是可选的按量付费 Credit 上限；当不存在独立上限时 Tavily 返回 null。
	PaygoLimit *int64 `json:"paygo_limit"`
	// SearchUsage is account-wide search credit consumption.
	// SearchUsage 是账号范围搜索 Credit 消耗。
	SearchUsage int64 `json:"search_usage"`
	// ExtractUsage is account-wide extraction credit consumption.
	// ExtractUsage 是账号范围内容提取 Credit 消耗。
	ExtractUsage int64 `json:"extract_usage"`
}

// NewMetadataDriver creates one strict Tavily usage reader.
// NewMetadataDriver 创建一个严格的 Tavily 用量读取器。
func NewMetadataDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*MetadataDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil || len(definition.EndpointPresets) != 1 {
		return nil, errors.New("Tavily definition, one endpoint preset, secret store, and HTTP client are required")
	}
	baseURL := strings.TrimRight(definition.EndpointPresets[0].BaseURL, "/")
	if baseURL != "https://api.tavily.com" {
		return nil, errors.New("Tavily usage reader requires the fixed official API Origin")
	}
	return &MetadataDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client), baseURL: baseURL, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Definition returns the immutable Tavily provider definition.
// Definition 返回不可变的 Tavily 供应商 Definition。
func (d *MetadataDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves runtime execution errors to action Drivers.
// ClassifyError 将运行时执行错误交给动作 Driver。
func (d *MetadataDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadCredentialMetadata requests and normalizes plan and credit facts from one usage response.
// ReadCredentialMetadata 从一次用量响应请求并规范化套餐与 Credit 事实。
func (d *MetadataDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	if instance.DefinitionID != d.definition.ID || credential.ProviderInstanceID != instance.ID || credential.AuthMethodID != "api_key" {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Tavily usage scope or authentication method is invalid", provider.ErrMetadataAuthentication)
	}
	apiKey, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: resolve Tavily credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	defer clear(apiKey)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+usageEndpointPath, nil)
	if errRequest != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("create Tavily usage request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+string(apiKey))
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: request Tavily usage: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Tavily rejected the credential", provider.ErrMetadataAuthentication)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: Tavily usage HTTP status %d", provider.ErrMetadataUnavailable, response.StatusCode)
	}
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumUsageResponseBytes+1))
	if errBody != nil || len(body) > maximumUsageResponseBytes {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: read Tavily usage response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	var payload usageResponse
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: decode Tavily usage response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	if errTrailing := rejectTrailingUsageJSON(decoder); errTrailing != nil {
		return provider.CredentialMetadataResult{}, errTrailing
	}
	observedAt := d.now().UTC()
	plan, allowances, errNormalize := normalizeUsageResponse(instance.ID, credential.ID, payload, observedAt)
	if errNormalize != nil {
		return provider.CredentialMetadataResult{}, errNormalize
	}
	return provider.CredentialMetadataResult{Plan: &plan, Allowances: allowances}, nil
}

// rejectTrailingUsageJSON rejects ambiguous data after the single usage object.
// rejectTrailingUsageJSON 拒绝单个用量对象之后的含糊数据。
func rejectTrailingUsageJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		return fmt.Errorf("%w: Tavily usage response contains trailing JSON", provider.ErrMetadataResponseInvalid)
	}
	return nil
}

// normalizeUsageResponse creates credential-observed plan and allowance facts without inventing account identity or reset time.
// normalizeUsageResponse 创建凭据观测的套餐与额度事实，且不虚构账号身份或重置时间。
func normalizeUsageResponse(instanceID string, credentialID string, payload usageResponse, observedAt time.Time) (catalog.PlanSnapshot, []catalog.AllowanceSnapshot, error) {
	planName := strings.TrimSpace(payload.Account.CurrentPlan)
	if planName == "" || !nonNegativeUsage(payload) {
		return catalog.PlanSnapshot{}, nil, fmt.Errorf("%w: Tavily usage contains an empty plan or negative counters", provider.ErrMetadataResponseInvalid)
	}
	planCode := normalizePlanCode(planName)
	if planCode == "" {
		return catalog.PlanSnapshot{}, nil, fmt.Errorf("%w: Tavily plan name cannot produce a stable code", provider.ErrMetadataResponseInvalid)
	}
	expiresAt := observedAt.Add(5 * time.Minute)
	plan := catalog.PlanSnapshot{ID: "plan_tavily_" + strings.TrimPrefix(credentialID, "cred_"), ProviderInstanceID: instanceID, CredentialID: credentialID, PlanCode: planCode, PlanName: planName, Status: "active", EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 1}
	if errPlan := plan.Validate(); errPlan != nil {
		return catalog.PlanSnapshot{}, nil, fmt.Errorf("%w: normalized Tavily plan is invalid: %v", provider.ErrMetadataResponseInvalid, errPlan)
	}
	allowanceInputs := []struct {
		// metric identifies the exact provider counter represented by this row.
		// metric 标识此行表示的精确供应商计数器。
		metric string
		// limit is present only for provider-reported bounded totals.
		// limit 仅在供应商报告有界总额时存在。
		limit *int64
		// used is the exact provider-reported consumed credit count.
		// used 是供应商报告的精确已消耗 Credit 数量。
		used int64
	}{
		{metric: "tavily.key.total", limit: payload.Key.Limit, used: payload.Key.Usage},
		{metric: "tavily.account.plan", limit: payload.Account.PlanLimit, used: payload.Account.PlanUsage},
		{metric: "tavily.account.paygo", limit: payload.Account.PaygoLimit, used: payload.Account.PaygoUsage},
		{metric: "tavily.key.search", used: payload.Key.SearchUsage},
		{metric: "tavily.key.extract", used: payload.Key.ExtractUsage},
		{metric: "tavily.account.search", used: payload.Account.SearchUsage},
		{metric: "tavily.account.extract", used: payload.Account.ExtractUsage},
	}
	allowances := make([]catalog.AllowanceSnapshot, 0, len(allowanceInputs))
	for _, input := range allowanceInputs {
		allowance, errAllowance := tavilyAllowance(instanceID, credentialID, input.metric, input.limit, input.used, observedAt, expiresAt)
		if errAllowance != nil {
			return catalog.PlanSnapshot{}, nil, errAllowance
		}
		allowances = append(allowances, allowance)
	}
	return plan, allowances, nil
}

// nonNegativeUsage reports whether every documented Tavily counter is non-negative.
// nonNegativeUsage 报告每个文档化 Tavily 计数器是否非负。
func nonNegativeUsage(payload usageResponse) bool {
	values := []int64{payload.Key.Usage, payload.Key.SearchUsage, payload.Key.ExtractUsage, payload.Account.PlanUsage, payload.Account.PaygoUsage, payload.Account.SearchUsage, payload.Account.ExtractUsage}
	for _, value := range values {
		if value < 0 {
			return false
		}
	}
	// Optional limits are validated only when Tavily actually supplied them; null means no independent bound.
	// 可选上限仅在 Tavily 实际返回时校验；null 表示没有独立边界。
	for _, limit := range []*int64{payload.Key.Limit, payload.Account.PlanLimit, payload.Account.PaygoLimit} {
		if limit != nil && *limit < 0 {
			return false
		}
	}
	return true
}

// tavilyAllowance creates one validated credential-observed credit snapshot.
// tavilyAllowance 创建一个经过校验的凭据观测 Credit 快照。
func tavilyAllowance(instanceID string, credentialID string, metric string, limitValue *int64, usedValue int64, observedAt time.Time, expiresAt time.Time) (catalog.AllowanceSnapshot, error) {
	used := strconv.FormatInt(usedValue, 10)
	status := catalog.AllowanceUnknownSufficiency
	var limit *string
	var remaining *string
	var ratio *float64
	kind := catalog.AllowanceProviderDefined
	if limitValue != nil {
		if usedValue > *limitValue {
			return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: Tavily usage exceeds limit for %s", provider.ErrMetadataResponseInvalid, metric)
		}
		limitText := strconv.FormatInt(*limitValue, 10)
		remainingText := strconv.FormatInt(*limitValue-usedValue, 10)
		limit = &limitText
		remaining = &remainingText
		kind = catalog.AllowanceBalance
		switch {
		case *limitValue == 0:
			status = catalog.AllowanceNotIncluded
		case usedValue == *limitValue:
			status = catalog.AllowanceExhausted
		default:
			status = catalog.AllowanceAvailable
			remainingRatio := float64(*limitValue-usedValue) / float64(*limitValue)
			ratio = &remainingRatio
			if remainingRatio < 0.2 {
				status = catalog.AllowanceLow
			}
		}
	}
	// A null Tavily PAYGO limit means no finite cap was reported; it does not describe whether billing is enabled.
	// Tavily 的 PAYGO 上限为 null 表示未报告有限上限；它不描述按量付费是否启用。
	if metric == "tavily.account.paygo" && limitValue == nil {
		status = catalog.AllowanceUnlimited
	}
	allowance := catalog.AllowanceSnapshot{ID: tavilyAllowanceID(credentialID, metric), ProviderInstanceID: instanceID, Kind: kind, Scope: catalog.ScopeCredential, ScopeID: credentialID, Metric: metric, Unit: catalog.UnitProviderCredits, Limit: limit, Used: &used, Remaining: remaining, RemainingRatio: ratio, Status: status, Mandatory: false, Source: catalog.ModelSourceProviderAPI, EvidenceSource: catalog.MetadataEvidenceProviderAPI, ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 1}
	if errValidate := allowance.Validate(); errValidate != nil {
		return catalog.AllowanceSnapshot{}, fmt.Errorf("%w: normalized Tavily allowance is invalid: %v", provider.ErrMetadataResponseInvalid, errValidate)
	}
	return allowance, nil
}

// normalizePlanCode converts a provider plan label into a stable lowercase identifier.
// normalizePlanCode 将供应商套餐标签转换为稳定的小写标识。
func normalizePlanCode(planName string) string {
	var builder strings.Builder
	separatorPending := false
	for _, value := range strings.ToLower(planName) {
		if unicode.IsLetter(value) || unicode.IsDigit(value) {
			if separatorPending && builder.Len() > 0 {
				builder.WriteByte('_')
			}
			builder.WriteRune(value)
			separatorPending = false
			continue
		}
		separatorPending = builder.Len() > 0
	}
	return builder.String()
}

// tavilyAllowanceID creates a stable credential-scoped identifier without exposing provider values.
// tavilyAllowanceID 创建稳定的凭据作用域标识且不暴露供应商值。
func tavilyAllowanceID(credentialID string, metric string) string {
	digest := sha256.Sum256([]byte(metric))
	return "allow_tavily_" + strings.TrimPrefix(credentialID, "cred_") + "_" + hex.EncodeToString(digest[:6])
}
