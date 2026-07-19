package openai

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
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
}

// NewCodexCatalogDriver creates a plan and entitlement reader backed by protected Codex token documents.
// NewCodexCatalogDriver 创建由受保护 Codex Token 文档支持的套餐与授权读取器。
func NewCodexCatalogDriver(definition providerconfig.ProviderDefinition, secrets secret.Store) (*CodexCatalogDriver, error) {
	if definition.ID == "" || dependency.IsNil(secrets) {
		return nil, errors.New("Codex definition and secret store are required")
	}
	return &CodexCatalogDriver{definition: providerconfig.CloneProviderDefinition(definition), secrets: secrets}, nil
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
	metadata, errMetadata := d.ReadCredentialMetadata(ctx, instance, credential)
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
	metadata, errMetadata := d.ReadCredentialMetadata(ctx, instance, credential)
	if errMetadata != nil {
		return nil, errMetadata
	}
	return append([]catalog.ModelEntitlement(nil), metadata.Entitlements...), nil
}

// ReadCredentialMetadata decodes one internally consistent plan and entitlement observation from the protected OAuth document.
// ReadCredentialMetadata 从受保护 OAuth 文档解码一份内部一致的套餐与授权观测。
func (d *CodexCatalogDriver) ReadCredentialMetadata(ctx context.Context, instance providerconfig.ProviderInstance, credential providerconfig.Credential) (provider.CredentialMetadataResult, error) {
	value, errValue := d.secrets.Get(ctx, credential.SecretRef)
	if errValue != nil {
		return provider.CredentialMetadataResult{}, fmt.Errorf("%w: resolve Codex credential: %v", provider.ErrMetadataAuthentication, errValue)
	}
	defer clear(value)
	return CodexCredentialMetadataFromToken(value, instance, credential, time.Now().UTC())
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
	plan := catalog.PlanSnapshot{ID: codexPlanCatalogID(credential.ID), ProviderInstanceID: instance.ID, CredentialID: credential.ID, PlanCode: planCode, PlanName: planCode, Status: "active", ObservedAt: observedAt, ExpiresAt: expiresAt, Revision: 1}
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

// codexPlanModels reproduces CLIProxyAPI's exact plan switch, including its Pro fallback for unknown plan codes.
// codexPlanModels 复现 CLIProxyAPI 的精确套餐分支，包括未知套餐代码回退到 Pro 集合的行为。
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
		return "codex_pro", []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "codex-auto-review"}
	}
}

// codexCatalogIdentifier converts one fixed upstream model identifier to Vulcan's portable catalog alphabet.
// codexCatalogIdentifier 将一个固定上游模型标识转换为 Vulcan 可移植目录字母表。
func codexCatalogIdentifier(value string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(value)
}
