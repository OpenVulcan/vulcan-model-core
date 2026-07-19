package google

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
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
	// antigravityLoadCodeAssistPath is the control-plane endpoint copied from CLIProxyAPI.
	// antigravityLoadCodeAssistPath 是从 CLIProxyAPI 复制的控制面入口。
	antigravityLoadCodeAssistPath = "/v1internal:loadCodeAssist"
	// antigravityGoogleOneCreditType identifies the account credit consumed by CLIProxyAPI's credits path.
	// antigravityGoogleOneCreditType 标识 CLIProxyAPI 积分路径消费的账号积分。
	antigravityGoogleOneCreditType = "GOOGLE_ONE_AI"
)

// AntigravityCatalogDriver reads plan and credit metadata from loadCodeAssist without exposing credentials.
// AntigravityCatalogDriver 从 loadCodeAssist 读取套餐与积分元数据且不暴露凭据。
type AntigravityCatalogDriver struct {
	// definition is the exact immutable Antigravity product definition.
	// definition 是精确且不可变的 Antigravity 产品定义。
	definition providerconfig.ProviderDefinition
	// secrets resolves the credential only for the outbound control-plane request.
	// secrets 仅为出站控制面请求解析凭据。
	secrets secret.Store
	// client executes bounded provider control-plane requests.
	// client 执行有界的供应商控制面请求。
	client *http.Client
}

// antigravityLoadCodeAssistResponse is the exact subset consumed from CLIProxyAPI's proven response path.
// antigravityLoadCodeAssistResponse 是从 CLIProxyAPI 已验证响应路径消费的精确字段子集。
type antigravityLoadCodeAssistResponse struct {
	// PaidTier contains account plan and optional paid credits.
	// PaidTier 包含账号套餐与可选付费积分。
	PaidTier antigravityPaidTier `json:"paidTier"`
}

// antigravityPaidTier contains the plan identifier and provider credit grants.
// antigravityPaidTier 包含套餐标识与供应商积分 Grant。
type antigravityPaidTier struct {
	// ID is the provider plan code.
	// ID 是供应商套餐代码。
	ID string `json:"id"`
	// AvailableCredits distinguishes a provider-reported array from the known no-credits shape copied from CLIProxyAPI.
	// AvailableCredits 区分供应商报告的数组与从 CLIProxyAPI 复制的已知无积分形态。
	AvailableCredits *[]antigravityCredit `json:"availableCredits"`
}

// antigravityCredit describes one provider credit balance.
// antigravityCredit 描述一个供应商积分余额。
type antigravityCredit struct {
	// CreditType identifies the credit product.
	// CreditType 标识积分产品。
	CreditType string `json:"creditType"`
	// CreditAmount is the remaining provider credit amount.
	// CreditAmount 是剩余供应商积分数量。
	CreditAmount json.Number `json:"creditAmount"`
	// MinimumCreditAmountForUsage is the minimum balance required to execute.
	// MinimumCreditAmountForUsage 是执行所需的最低积分余额。
	MinimumCreditAmountForUsage json.Number `json:"minimumCreditAmountForUsage"`
}

// NewAntigravityCatalogDriver creates a strongly typed plan and allowance reader.
// NewAntigravityCatalogDriver 创建强类型套餐与额度读取器。
func NewAntigravityCatalogDriver(definition providerconfig.ProviderDefinition, secrets secret.Store, client *http.Client) (*AntigravityCatalogDriver, error) {
	if definition.ID == "" || len(definition.EndpointPresets) != 1 || strings.TrimSpace(definition.EndpointPresets[0].BaseURL) == "" || dependency.IsNil(secrets) || client == nil {
		return nil, errors.New("Antigravity definition, secret store, and HTTP client are required")
	}
	return &AntigravityCatalogDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets, client: providertransport.CloneHTTPClientWithoutRedirects(client)}, nil
}

// Definition returns the immutable Antigravity system definition.
// Definition 返回不可变的 Antigravity 系统定义。
func (d *AntigravityCatalogDriver) Definition() providerconfig.ProviderDefinition {
	return providerconfig.CloneProviderDefinition(d.definition)
}

// ClassifyError leaves execution error classification to the execution driver.
// ClassifyError 将执行错误分类留给执行 Driver。
func (d *AntigravityCatalogDriver) ClassifyError(provider.ErrorObservation) (provider.ClassifiedError, bool) {
	return provider.ClassifiedError{}, false
}

// ReadPlan returns the paidTier identifier reported by loadCodeAssist.
// ReadPlan 返回 loadCodeAssist 报告的 paidTier 标识。
func (d *AntigravityCatalogDriver) ReadPlan(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (catalog.PlanSnapshot, error) {
	response, observedAt, errRead := d.readCatalog(ctx, instance, credential)
	if errRead != nil {
		return catalog.PlanSnapshot{}, errRead
	}
	return antigravityPlanFromResponse(response, instance, credential, observedAt)
}

// ReadCredentialMetadata decodes plan and credit facts from one internally consistent loadCodeAssist response.
// ReadCredentialMetadata 从一份内部一致的 loadCodeAssist 响应中解码套餐与积分事实。
func (d *AntigravityCatalogDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	response, observedAt, errRead := d.readCatalog(ctx, instance, credential)
	if errRead != nil {
		return provider.CredentialMetadataResult{}, errRead
	}
	plan, errPlan := antigravityPlanFromResponse(response, instance, credential, observedAt)
	if errPlan != nil {
		return provider.CredentialMetadataResult{}, errPlan
	}
	allowances, errAllowances := antigravityAllowancesFromResponse(response, instance, credential, observedAt)
	if errAllowances != nil {
		return provider.CredentialMetadataResult{}, errAllowances
	}
	return provider.CredentialMetadataResult{Plan: &plan, Allowances: allowances}, nil
}

// antigravityPlanFromResponse maps one validated paid-tier observation to the catalog domain.
// antigravityPlanFromResponse 将一份已校验付费层级观测映射到目录领域。
func antigravityPlanFromResponse(response antigravityLoadCodeAssistResponse, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) (catalog.PlanSnapshot, error) {
	planCode := strings.TrimSpace(response.PaidTier.ID)
	if planCode == "" {
		return catalog.PlanSnapshot{}, fmt.Errorf("%w: Antigravity loadCodeAssist response does not contain paidTier.id", provider.ErrMetadataResponseInvalid)
	}
	return catalog.PlanSnapshot{ID: antigravityCredentialCatalogID("plan_", credential.ID), ProviderInstanceID: instance.ID, CredentialID: credential.ID, PlanCode: planCode, PlanName: planCode, Status: "active", ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}, nil
}

// ReadAllowances returns the GOOGLE_ONE_AI credit balance reported by loadCodeAssist.
// ReadAllowances 返回 loadCodeAssist 报告的 GOOGLE_ONE_AI 积分余额。
func (d *AntigravityCatalogDriver) ReadAllowances(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) ([]catalog.AllowanceSnapshot, error) {
	response, observedAt, errRead := d.readCatalog(ctx, instance, credential)
	if errRead != nil {
		return nil, errRead
	}
	return antigravityAllowancesFromResponse(response, instance, credential, observedAt)
}

// antigravityAllowancesFromResponse maps the exact GOOGLE_ONE_AI credit from one typed response.
// antigravityAllowancesFromResponse 从一份类型化响应中映射精确的 GOOGLE_ONE_AI 积分。
func antigravityAllowancesFromResponse(response antigravityLoadCodeAssistResponse, instance providerconfig.ProviderInstance, credential providerconfig.Credential, observedAt time.Time) ([]catalog.AllowanceSnapshot, error) {
	if response.PaidTier.AvailableCredits == nil {
		// CLIProxyAPI records a known unavailable credits hint when availableCredits is not an array.
		// availableCredits 不是数组时，CLIProxyAPI 会记录已知无可用积分提示。
		return []catalog.AllowanceSnapshot{{ID: antigravityCredentialCatalogID("allow_", credential.ID), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceCreditGrant, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: antigravityGoogleOneCreditType, Unit: catalog.UnitProviderCredits, Status: catalog.AllowanceExhausted, Mandatory: false, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}}, nil
	}
	for _, credit := range *response.PaidTier.AvailableCredits {
		if !strings.EqualFold(strings.TrimSpace(credit.CreditType), antigravityGoogleOneCreditType) {
			continue
		}
		remaining := strings.TrimSpace(credit.CreditAmount.String())
		minimum := strings.TrimSpace(credit.MinimumCreditAmountForUsage.String())
		// Exact rationals prevent availability decisions from rounding large integers or high-precision decimals through float64.
		// 精确有理数可防止可用性判定通过 float64 舍入大整数或高精度小数。
		remainingValue, validRemaining := parseAntigravityCreditNumber(remaining)
		minimumValue, validMinimum := parseAntigravityCreditNumber(minimum)
		if !validRemaining || !validMinimum {
			return nil, fmt.Errorf("%w: Antigravity credit response contains invalid numeric values", provider.ErrMetadataResponseInvalid)
		}
		status := catalog.AllowanceExhausted
		if remainingValue.Cmp(minimumValue) >= 0 {
			status = catalog.AllowanceAvailable
		}
		// GOOGLE_ONE_AI credits are model-selective in CLIProxyAPI and must not block every model owned by this credential.
		// GOOGLE_ONE_AI 积分在 CLIProxyAPI 中仅针对特定模型，不能阻塞该凭据拥有的全部模型。
		return []catalog.AllowanceSnapshot{{ID: antigravityCredentialCatalogID("allow_", credential.ID), ProviderInstanceID: instance.ID, Kind: catalog.AllowanceCreditGrant, Scope: catalog.ScopeCredential, ScopeID: credential.ID, Metric: antigravityGoogleOneCreditType, Unit: catalog.UnitProviderCredits, Remaining: &remaining, Status: status, Mandatory: false, Source: catalog.ModelSourceProviderAPI, ObservedAt: observedAt, ExpiresAt: observedAt.Add(5 * time.Minute), Revision: 1}}, nil
	}
	return nil, nil
}

// parseAntigravityCreditNumber applies CLIProxyAPI's finite float range gate before preserving the value as an exact rational.
// parseAntigravityCreditNumber 先应用 CLIProxyAPI 的有限浮点范围门控，再将数值保留为精确有理数。
func parseAntigravityCreditNumber(raw string) (*big.Rat, bool) {
	normalized := strings.TrimSpace(raw)
	boundedValue, errParse := strconv.ParseFloat(normalized, 64)
	if normalized == "" || errParse != nil || math.IsNaN(boundedValue) || math.IsInf(boundedValue, 0) || boundedValue < 0 {
		return nil, false
	}
	exactValue, validExact := new(big.Rat).SetString(normalized)
	if !validExact || exactValue.Sign() < 0 {
		return nil, false
	}
	return exactValue, true
}

// antigravityCredentialCatalogID derives one stable portable catalog identifier without inheriting credential identifier length.
// antigravityCredentialCatalogID 派生一个稳定的可移植目录标识，且不继承凭据标识长度。
func antigravityCredentialCatalogID(prefix string, credentialID string) string {
	// credentialHash keeps the complete credential identity collision-resistant while satisfying the catalog's bounded identifier grammar.
	// credentialHash 在满足目录有界标识语法的同时，以抗碰撞方式保留完整凭据身份。
	credentialHash := sha256.Sum256([]byte(credentialID))
	return fmt.Sprintf("%s%x", prefix, credentialHash)
}

// readCatalog fetches and decodes one fresh loadCodeAssist response without caching across explicit refreshes.
// readCatalog 获取并解码一个最新的 loadCodeAssist 响应，不在显式刷新之间缓存。
func (d *AntigravityCatalogDriver) readCatalog(ctx context.Context, _ providerconfig.ProviderInstance, credential providerconfig.Credential) (antigravityLoadCodeAssistResponse, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, err
	}
	protectedValue, errSecret := d.secrets.Get(ctx, credential.SecretRef)
	if errSecret != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("resolve Antigravity credential: %w", errSecret)
	}
	token, errToken := UnmarshalAntigravityToken(protectedValue)
	clear(protectedValue)
	if errToken != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: decode Antigravity credential: %v", provider.ErrMetadataAuthentication, errToken)
	}
	// requestBody exactly preserves CLIProxyAPI's loadCodeAssist IDE metadata.
	// requestBody 精确保留 CLIProxyAPI 的 loadCodeAssist IDE 元数据。
	requestBody := struct {
		// Metadata identifies the official Antigravity control-plane client shape.
		// Metadata 标识官方 Antigravity 控制面客户端形态。
		Metadata map[string]string `json:"metadata"`
	}{Metadata: map[string]string{"ideType": "ANTIGRAVITY"}}
	body, errMarshal := json.Marshal(requestBody)
	if errMarshal != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("marshal Antigravity catalog request: %w", errMarshal)
	}
	endpoint := strings.TrimSuffix(d.definition.EndpointPresets[0].BaseURL, "/") + antigravityLoadCodeAssistPath
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if errRequest != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("create Antigravity catalog request: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", AntigravityLoadCodeAssistUserAgent(""))
	response, errResponse := d.client.Do(request)
	if errResponse != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: request Antigravity catalog: %v", provider.ErrMetadataUnavailable, errResponse)
	}
	defer response.Body.Close()
	responseBody, errBody := io.ReadAll(io.LimitReader(response.Body, antigravityControlResponseLimit+1))
	if errBody != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: read Antigravity catalog response: %v", provider.ErrMetadataUnavailable, errBody)
	}
	defer clear(responseBody)
	if len(responseBody) > antigravityControlResponseLimit {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: Antigravity catalog response exceeds the response limit", provider.ErrMetadataResponseInvalid)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: Antigravity catalog request returned status %d", provider.ErrMetadataAuthentication, response.StatusCode)
		}
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: Antigravity catalog request returned status %d", provider.ErrMetadataUnavailable, response.StatusCode)
		}
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: Antigravity catalog request returned status %d", provider.ErrMetadataResponseInvalid, response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	var decoded antigravityLoadCodeAssistResponse
	if errDecode := decoder.Decode(&decoded); errDecode != nil {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: decode Antigravity catalog response: %v", provider.ErrMetadataResponseInvalid, errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); !errors.Is(errTrailing, io.EOF) {
		return antigravityLoadCodeAssistResponse{}, time.Time{}, fmt.Errorf("%w: Antigravity catalog response contains trailing JSON data", provider.ErrMetadataResponseInvalid)
	}
	observedAt := time.Now().UTC()
	return decoded, observedAt, nil
}
