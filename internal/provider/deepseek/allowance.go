package deepseek

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
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
	// balanceEndpointPath is the official DeepSeek user-balance path.
	// balanceEndpointPath 是 DeepSeek 官方用户余额路径。
	balanceEndpointPath = "/user/balance"
	// maximumBalanceResponseBytes bounds one DeepSeek balance document before decoding.
	// maximumBalanceResponseBytes 在解码前限制单个 DeepSeek 余额文档大小。
	maximumBalanceResponseBytes = 1 << 20
)

// AllowanceDriver reads official DeepSeek account balances through one protected API key.
// AllowanceDriver 通过一个受保护 API Key 读取 DeepSeek 官方账号余额。
type AllowanceDriver struct {
	// definition is the immutable DeepSeek provider definition.
	// definition 是不可变的 DeepSeek 供应商 Definition。
	definition providerconfig.ProviderDefinition
	// secrets resolves the exact protected API key selected by the caller.
	// secrets 解析调用方选择的精确受保护 API Key。
	secrets secret.Store
	// client performs bounded requests without following redirects.
	// client 执行有界且不跟随重定向的请求。
	client *http.Client
	// baseURL is the sole documented DeepSeek public API Origin.
	// baseURL 是唯一记录在案的 DeepSeek 公共 API Origin。
	baseURL string
	// now supplies deterministic observation timestamps.
	// now 提供确定性观测时间戳。
	now func() time.Time
}

// balanceResponse mirrors the official DeepSeek account-balance response.
// balanceResponse 镜像 DeepSeek 官方账号余额响应。
type balanceResponse struct {
	// IsAvailable reports whether the account has sufficient balance for API calls.
	// IsAvailable 表示账号是否有足够余额执行 API 调用。
	IsAvailable bool `json:"is_available"`
	// BalanceInfos contains each provider-reported currency balance.
	// BalanceInfos 包含供应商报告的每种货币余额。
	BalanceInfos []balanceInfo `json:"balance_infos"`
}

// balanceInfo contains one exact provider-reported currency balance breakdown.
// balanceInfo 包含一份精确的供应商货币余额明细。
type balanceInfo struct {
	// Currency is the official CNY or USD currency code.
	// Currency 是官方 CNY 或 USD 货币代码。
	Currency string `json:"currency"`
	// TotalBalance is the complete available account balance.
	// TotalBalance 是账号完整可用余额。
	TotalBalance providermetadata.Decimal `json:"total_balance"`
	// GrantedBalance is the provider-granted balance component.
	// GrantedBalance 是供应商赠送余额部分。
	GrantedBalance providermetadata.Decimal `json:"granted_balance"`
	// ToppedUpBalance is the customer-funded balance component.
	// ToppedUpBalance 是客户充值余额部分。
	ToppedUpBalance providermetadata.Decimal `json:"topped_up_balance"`
}

// NewAllowanceDriver creates one strict DeepSeek balance reader.
// NewAllowanceDriver 创建一个严格的 DeepSeek 余额读取器。
func NewAllowanceDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AllowanceDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) || client == nil || len(definition.EndpointPresets) != 1 {
		return nil, errors.New("DeepSeek definition, one endpoint preset, secret store, and HTTP client are required")
	}
	baseURL := strings.TrimRight(definition.EndpointPresets[0].BaseURL, "/")
	if baseURL != "https://api.deepseek.com" {
		return nil, errors.New("DeepSeek balance reader requires the fixed official API Origin")
	}
	return &AllowanceDriver{
		definition: providerconfig.CloneProviderDefinition(definition),
		secrets:    secrets,
		client:     providertransport.CloneHTTPClientWithoutRedirects(client),
		baseURL:    baseURL,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

// Definition returns the immutable DeepSeek provider definition.
// Definition 返回不可变的 DeepSeek 供应商 Definition。
func (d *AllowanceDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves runtime execution errors to the Chat execution driver.
// ClassifyError 将运行时执行错误交给 Chat 执行 Driver。
func (d *AllowanceDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadAllowances requests and normalizes every official DeepSeek currency balance for one credential.
// ReadAllowances 为一个凭据请求并规范化全部 DeepSeek 官方货币余额。
func (d *AllowanceDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	if d == nil || instance.DefinitionID != d.definition.ID || credential.ProviderInstanceID != instance.ID || credential.AuthMethodID != "api_key" {
		return nil, fmt.Errorf("%w: DeepSeek balance scope or authentication method is invalid", provider.ErrMetadataAuthentication)
	}
	apiKey, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return nil, fmt.Errorf("%w: resolve DeepSeek credential: %v", provider.ErrMetadataAuthentication, errSecret)
	}
	defer clear(apiKey)
	if len(apiKey) == 0 {
		return nil, fmt.Errorf("%w: DeepSeek credential is empty", provider.ErrMetadataAuthentication)
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+balanceEndpointPath, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create DeepSeek balance request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+string(apiKey))
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return nil, fmt.Errorf("%w: request DeepSeek balance: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: DeepSeek rejected the credential", provider.ErrMetadataAuthentication)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: DeepSeek balance HTTP status %d", provider.ErrMetadataUnavailable, response.StatusCode)
	}
	body, errBody := io.ReadAll(io.LimitReader(response.Body, maximumBalanceResponseBytes+1))
	if errBody != nil || len(body) > maximumBalanceResponseBytes {
		return nil, fmt.Errorf("%w: read DeepSeek balance response", provider.ErrMetadataResponseInvalid)
	}
	defer clear(body)
	var payload balanceResponse
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if errDecode := decoder.Decode(&payload); errDecode != nil {
		return nil, fmt.Errorf("%w: decode DeepSeek balance response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	if errTrailing := rejectTrailingBalanceJSON(decoder); errTrailing != nil {
		return nil, errTrailing
	}
	return normalizeBalanceResponse(instance.ID, credential.ID, payload, d.now().UTC())
}

// rejectTrailingBalanceJSON rejects ambiguous data after the single balance object.
// rejectTrailingBalanceJSON 拒绝单个余额对象之后的含糊数据。
func rejectTrailingBalanceJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if errTrailing := decoder.Decode(&trailing); !errors.Is(errTrailing, io.EOF) {
		return fmt.Errorf("%w: DeepSeek balance response contains trailing JSON", provider.ErrMetadataResponseInvalid)
	}
	return nil
}

// normalizeBalanceResponse converts exact provider currency strings into validated minor-unit snapshots.
// normalizeBalanceResponse 将精确的供应商货币字符串转换为经过校验的最小货币单位快照。
func normalizeBalanceResponse(instanceID string, credentialID string, payload balanceResponse, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	if len(payload.BalanceInfos) == 0 {
		return nil, fmt.Errorf("%w: DeepSeek balance response contains no currency balances", provider.ErrMetadataResponseInvalid)
	}
	// currencies rejects duplicated rows because each official currency is a unique balance identity.
	// currencies 拒绝重复行，因为每种官方货币都是唯一的余额身份。
	currencies := make(map[string]struct{}, len(payload.BalanceInfos))
	allowances := make([]catalog.AllowanceSnapshot, 0, len(payload.BalanceInfos)*3)
	expiresAt := observedAt.Add(5 * time.Minute)
	for _, info := range payload.BalanceInfos {
		currency := strings.ToUpper(strings.TrimSpace(info.Currency))
		if currency != "CNY" && currency != "USD" {
			return nil, fmt.Errorf("%w: DeepSeek returned unsupported currency %q", provider.ErrMetadataResponseInvalid, info.Currency)
		}
		if _, exists := currencies[currency]; exists {
			return nil, fmt.Errorf("%w: DeepSeek returned duplicate currency %s", provider.ErrMetadataResponseInvalid, currency)
		}
		currencies[currency] = struct{}{}
		total, errTotal := decimalToMinorUnits(info.TotalBalance)
		if errTotal != nil {
			return nil, fmt.Errorf("%w: DeepSeek total balance for %s: %v", provider.ErrMetadataResponseInvalid, currency, errTotal)
		}
		granted, errGranted := decimalToMinorUnits(info.GrantedBalance)
		if errGranted != nil {
			return nil, fmt.Errorf("%w: DeepSeek granted balance for %s: %v", provider.ErrMetadataResponseInvalid, currency, errGranted)
		}
		toppedUp, errToppedUp := decimalToMinorUnits(info.ToppedUpBalance)
		if errToppedUp != nil {
			return nil, fmt.Errorf("%w: DeepSeek topped-up balance for %s: %v", provider.ErrMetadataResponseInvalid, currency, errToppedUp)
		}
		if !balanceComponentsMatchTotal(total, granted, toppedUp) {
			return nil, fmt.Errorf("%w: DeepSeek balance components do not equal the total for %s", provider.ErrMetadataResponseInvalid, currency)
		}
		totalStatus := catalog.AllowanceExhausted
		if payload.IsAvailable {
			totalStatus = catalog.AllowanceAvailable
		}
		// components records the official aggregate plus its granted and customer-funded breakdown.
		// components 记录官方总额及其赠送与客户充值明细。
		components := []struct {
			// metric is the stable normalized provider metric.
			// metric 是稳定的规范化供应商指标。
			metric string
			// kind preserves whether the row is an aggregate balance or a granted credit component.
			// kind 保留该行是聚合余额还是赠送 Credit 部分。
			kind catalog.AllowanceKind
			// remaining is the exact integer minor-unit amount.
			// remaining 是精确的整数最小货币单位金额。
			remaining string
			// status is the independently normalized component state.
			// status 是独立规范化的组成部分状态。
			status catalog.AllowanceStatus
			// mandatory reports whether provider unavailability blocks execution.
			// mandatory 表示供应商不可用是否阻止执行。
			mandatory bool
		}{
			{metric: "deepseek.balance.total", kind: catalog.AllowanceBalance, remaining: total, status: totalStatus, mandatory: true},
			{metric: "deepseek.balance.granted", kind: catalog.AllowanceCreditGrant, remaining: granted, status: balanceComponentStatus(granted)},
			{metric: "deepseek.balance.topped_up", kind: catalog.AllowanceBalance, remaining: toppedUp, status: balanceComponentStatus(toppedUp)},
		}
		for _, component := range components {
			allowance := catalog.AllowanceSnapshot{
				ID:                 deepSeekAllowanceID(credentialID, currency, component.metric),
				ProviderInstanceID: instanceID,
				Kind:               component.kind,
				Scope:              catalog.ScopeCredential,
				ScopeID:            credentialID,
				Metric:             component.metric,
				Unit:               catalog.UnitMinorCurrency,
				Currency:           currency,
				Remaining:          &component.remaining,
				Status:             component.status,
				Mandatory:          component.mandatory,
				Source:             catalog.ModelSourceProviderAPI,
				EvidenceSource:     catalog.MetadataEvidenceProviderAPI,
				ObservedAt:         observedAt,
				ExpiresAt:          expiresAt,
				Revision:           1,
			}
			if errValidate := allowance.Validate(); errValidate != nil {
				return nil, fmt.Errorf("%w: normalized DeepSeek allowance is invalid: %v", provider.ErrMetadataResponseInvalid, errValidate)
			}
			allowances = append(allowances, allowance)
		}
	}
	return allowances, nil
}

// decimalToMinorUnits converts an exact non-negative amount to integer hundredths without floating-point rounding.
// decimalToMinorUnits 将精确非负金额转换为整数百分位且不使用浮点舍入。
func decimalToMinorUnits(value providermetadata.Decimal) (string, error) {
	if !value.Set() {
		return "", errors.New("balance amount is missing")
	}
	majorText, fractionalText, hasFraction := strings.Cut(value.String(), ".")
	if !hasFraction {
		fractionalText = ""
	}
	if len(fractionalText) > 2 {
		if strings.Trim(fractionalText[2:], "0") != "" {
			return "", errors.New("balance amount has precision below the supported minor currency unit")
		}
		fractionalText = fractionalText[:2]
	}
	fractionalText += strings.Repeat("0", 2-len(fractionalText))
	major, validMajor := new(big.Int).SetString(majorText, 10)
	fractional, validFractional := new(big.Int).SetString(fractionalText, 10)
	if !validMajor || !validFractional {
		return "", errors.New("balance amount is invalid")
	}
	major.Mul(major, big.NewInt(100))
	major.Add(major, fractional)
	return major.String(), nil
}

// balanceComponentStatus returns whether one non-mandatory balance component contains funds.
// balanceComponentStatus 返回一个非强制余额组成部分是否包含资金。
func balanceComponentStatus(remaining string) catalog.AllowanceStatus {
	if remaining == "0" {
		return catalog.AllowanceExhausted
	}
	return catalog.AllowanceAvailable
}

// balanceComponentsMatchTotal reports whether the official granted and topped-up components exactly reproduce the total.
// balanceComponentsMatchTotal 报告官方赠送与充值组成部分之和是否精确等于总额。
func balanceComponentsMatchTotal(total string, granted string, toppedUp string) bool {
	totalValue, validTotal := new(big.Int).SetString(total, 10)
	grantedValue, validGranted := new(big.Int).SetString(granted, 10)
	toppedUpValue, validToppedUp := new(big.Int).SetString(toppedUp, 10)
	if !validTotal || !validGranted || !validToppedUp {
		return false
	}
	return totalValue.Cmp(grantedValue.Add(grantedValue, toppedUpValue)) == 0
}

// deepSeekAllowanceID derives one credential-local immutable identifier without exposing the credential identifier.
// deepSeekAllowanceID 派生一个凭据本地不可变标识且不暴露凭据标识。
func deepSeekAllowanceID(credentialID string, currency string, metric string) string {
	sum := sha256.Sum256([]byte(credentialID + "\x00" + currency + "\x00" + metric))
	return "allow_deepseek_" + hex.EncodeToString(sum[:12])
}
