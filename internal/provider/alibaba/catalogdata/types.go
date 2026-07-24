// Package catalogdata owns versioned, credential-free Alibaba catalog facts.
// Package catalogdata 管理由版本控制且不含凭据的 Alibaba 目录事实。
package catalogdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SchemaVersion is the current embedded Alibaba catalog schema revision.
// SchemaVersion 是当前内嵌 Alibaba 目录 Schema 修订号。
const SchemaVersion = 1

// ManifestSchemaVersion is the current Alibaba catalog manifest schema revision.
// ManifestSchemaVersion 是当前 Alibaba 目录清单 Schema 修订号。
const ManifestSchemaVersion = 2

// Product identifies one immutable Alibaba commercial product boundary.
// Product 标识一个不可变的 Alibaba 商业产品边界。
type Product string

const (
	// ProductCodingPlan identifies Alibaba Coding Plan.
	// ProductCodingPlan 标识 Alibaba Coding Plan。
	ProductCodingPlan Product = "coding_plan"
	// ProductTokenPlanPersonal identifies Alibaba Personal Token Plan.
	// ProductTokenPlanPersonal 标识 Alibaba 个人 Token Plan。
	ProductTokenPlanPersonal Product = "token_plan_personal"
	// ProductTokenPlanTeam identifies Alibaba Team Token Plan.
	// ProductTokenPlanTeam 标识 Alibaba 团队 Token Plan。
	ProductTokenPlanTeam Product = "token_plan_team"
	// ProductModelStudioAPI identifies the ordinary Model Studio data-plane API.
	// ProductModelStudioAPI 标识普通 Model Studio 数据面 API。
	ProductModelStudioAPI Product = "model_studio_api"
)

// ConsoleSite identifies the exact Alibaba console account site.
// ConsoleSite 标识精确的 Alibaba 控制台账号站点。
type ConsoleSite string

const (
	// ConsoleSiteDomestic identifies the China domestic console.
	// ConsoleSiteDomestic 标识中国国内控制台。
	ConsoleSiteDomestic ConsoleSite = "domestic"
	// ConsoleSiteInternational identifies the international console.
	// ConsoleSiteInternational 标识国际控制台。
	ConsoleSiteInternational ConsoleSite = "international"
	// ConsoleSiteNotApplicable marks products without a console-catalog site dimension.
	// ConsoleSiteNotApplicable 标记不具有控制台目录站点维度的产品。
	ConsoleSiteNotApplicable ConsoleSite = "not_applicable"
)

// Region identifies the exact Alibaba inference and catalog region.
// Region 标识精确的 Alibaba 推理与目录区域。
type Region string

const (
	// RegionCN identifies the China Beijing service boundary.
	// RegionCN 标识中国北京服务边界。
	RegionCN Region = "cn_beijing"
	// RegionSingapore identifies the Singapore service boundary.
	// RegionSingapore 标识新加坡服务边界。
	RegionSingapore Region = "ap_southeast_1"
	// RegionHongKong identifies the Hong Kong service boundary.
	// RegionHongKong 标识香港服务边界。
	RegionHongKong Region = "cn_hongkong"
	// RegionTokyo identifies the Tokyo service boundary.
	// RegionTokyo 标识东京服务边界。
	RegionTokyo Region = "ap_northeast_1"
	// RegionFrankfurt identifies the Frankfurt service boundary.
	// RegionFrankfurt 标识法兰克福服务边界。
	RegionFrankfurt Region = "eu_central_1"
	// RegionVirginia identifies the Virginia service boundary.
	// RegionVirginia 标识弗吉尼亚服务边界。
	RegionVirginia Region = "us_east_1"
	// RegionGlobal identifies a provider-defined global subscription boundary.
	// RegionGlobal 标识供应商定义的国际订阅边界。
	RegionGlobal Region = "global"
)

// Channel identifies one exact upstream protocol or native operation family.
// Channel 标识一个精确的上游协议或原生操作系列。
type Channel string

const (
	// ChannelOpenAIChat identifies Alibaba's OpenAI Chat compatible channel.
	// ChannelOpenAIChat 标识 Alibaba 的 OpenAI Chat 兼容通道。
	ChannelOpenAIChat Channel = "openai_chat"
	// ChannelConsoleCatalog identifies non-executable Model Studio catalog facts.
	// ChannelConsoleCatalog 标识不可执行的 Model Studio 目录事实。
	ChannelConsoleCatalog Channel = "console_catalog"
)

// VerificationStatus records whether one product boundary has reproducible source evidence.
// VerificationStatus 记录一个产品边界是否具有可复现的来源证据。
type VerificationStatus string

const (
	// VerificationVerified means a complete committed snapshot exists.
	// VerificationVerified 表示存在完整且已提交的快照。
	VerificationVerified VerificationStatus = "verified"
	// VerificationUnverified means no other product or region may fill the missing facts.
	// VerificationUnverified 表示不得使用其他产品或区域填补缺失事实。
	VerificationUnverified VerificationStatus = "unverified"
)

// ModelFactSourceStatus records whether one retained provider fact remains present in the latest source observation.
// ModelFactSourceStatus 记录一个保留的供应商事实是否仍存在于最新来源观测。
type ModelFactSourceStatus string

const (
	// ModelFactSourceActive marks a model present in the latest provider response.
	// ModelFactSourceActive 标记最新供应商响应中仍存在的模型。
	ModelFactSourceActive ModelFactSourceStatus = "active"
	// ModelFactSourceRemoved retains a model omitted by the latest provider response for audit and migration.
	// ModelFactSourceRemoved 保留最新供应商响应中缺失的模型以供审核与迁移。
	ModelFactSourceRemoved ModelFactSourceStatus = "source_removed"
)

// Manifest describes every verified and intentionally unverified Alibaba catalog boundary.
// Manifest 描述全部已验证及明确未验证的 Alibaba 目录边界。
type Manifest struct {
	// SchemaVersion identifies the manifest schema.
	// SchemaVersion 标识 Manifest Schema。
	SchemaVersion int `json:"schema_version"`
	// Entries contains the closed product and region matrix.
	// Entries 包含封闭的产品与区域矩阵。
	Entries []ManifestEntry `json:"entries"`
}

// ManifestEntry maps one system catalog identifier to one exact evidence boundary.
// ManifestEntry 将一个系统目录标识映射到一个精确证据边界。
type ManifestEntry struct {
	// CatalogID is the code-owned system catalog identifier.
	// CatalogID 是代码拥有的系统目录标识。
	CatalogID string `json:"catalog_id"`
	// Product is the immutable commercial product.
	// Product 是不可变的商业产品。
	Product Product `json:"product"`
	// ConsoleSite is the exact account-site boundary.
	// ConsoleSite 是精确的账号站点边界。
	ConsoleSite ConsoleSite `json:"console_site"`
	// Region is the exact catalog or inference region.
	// Region 是精确的目录或推理区域。
	Region Region `json:"region"`
	// Channel is the exact observed upstream channel.
	// Channel 是精确观测到的上游通道。
	Channel Channel `json:"channel"`
	// Status reports whether a committed snapshot exists.
	// Status 表示是否存在已提交快照。
	Status VerificationStatus `json:"status"`
	// Filename is present only for a verified embedded snapshot.
	// Filename 仅为已验证的内嵌快照提供。
	Filename string `json:"filename,omitempty"`
	// Evidence records the non-secret source boundary or the missing evidence.
	// Evidence 记录非秘密来源边界或缺失证据。
	Evidence string `json:"evidence"`
	// EvidenceSourceType identifies the exact non-secret evidence class used for this boundary.
	// EvidenceSourceType 标识该边界使用的精确非秘密证据类型。
	EvidenceSourceType string `json:"evidence_source_type"`
	// EvidenceObservedAt records when this boundary was last reviewed against its source.
	// EvidenceObservedAt 记录该边界最后一次依据来源完成审核的时间。
	EvidenceObservedAt time.Time `json:"evidence_observed_at"`
	// ContentRevision binds a verified manifest entry to the exact normalized snapshot revision.
	// ContentRevision 将已验证 Manifest 条目绑定到精确的规范化快照修订。
	ContentRevision string `json:"content_revision,omitempty"`
}

// manifestBoundary defines one required immutable product, site, region, and channel identity.
// manifestBoundary 定义一个必需且不可变的产品、站点、区域与通道身份。
type manifestBoundary struct {
	// CatalogID is the unique system catalog identity.
	// CatalogID 是唯一系统目录身份。
	CatalogID string
	// Product is the exact commercial product.
	// Product 是精确商业产品。
	Product Product
	// ConsoleSite is the exact account-site boundary.
	// ConsoleSite 是精确账号站点边界。
	ConsoleSite ConsoleSite
	// Region is the exact catalog or inference region.
	// Region 是精确目录或推理区域。
	Region Region
	// Channel is the sole observed protocol or catalog surface.
	// Channel 是唯一观测协议或目录能力面。
	Channel Channel
}

// requiredManifestBoundaries is the closed Alibaba product matrix that must remain explicit even without credentials.
// requiredManifestBoundaries 是即使缺少凭据也必须保持显式声明的封闭 Alibaba 产品矩阵。
var requiredManifestBoundaries = []manifestBoundary{
	{CatalogID: "alibaba_model_studio_cn", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteDomestic, Region: RegionCN, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_sg_domestic", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteDomestic, Region: RegionSingapore, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_hong_kong", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteDomestic, Region: RegionHongKong, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_tokyo", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteInternational, Region: RegionTokyo, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_frankfurt", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteInternational, Region: RegionFrankfurt, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_us", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteInternational, Region: RegionVirginia, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_model_studio_workspace_sg", Product: ProductModelStudioAPI, ConsoleSite: ConsoleSiteNotApplicable, Region: RegionSingapore, Channel: ChannelConsoleCatalog},
	{CatalogID: "alibaba_coding_plan_cn", Product: ProductCodingPlan, ConsoleSite: ConsoleSiteDomestic, Region: RegionCN, Channel: ChannelOpenAIChat},
	{CatalogID: "alibaba_coding_plan_global", Product: ProductCodingPlan, ConsoleSite: ConsoleSiteInternational, Region: RegionGlobal, Channel: ChannelOpenAIChat},
	{CatalogID: "alibaba_token_plan_personal_cn", Product: ProductTokenPlanPersonal, ConsoleSite: ConsoleSiteDomestic, Region: RegionCN, Channel: ChannelOpenAIChat},
	{CatalogID: "alibaba_token_plan_personal_global", Product: ProductTokenPlanPersonal, ConsoleSite: ConsoleSiteInternational, Region: RegionSingapore, Channel: ChannelOpenAIChat},
	{CatalogID: "alibaba_token_plan_team_cn", Product: ProductTokenPlanTeam, ConsoleSite: ConsoleSiteDomestic, Region: RegionCN, Channel: ChannelOpenAIChat},
	{CatalogID: "alibaba_token_plan_team_global", Product: ProductTokenPlanTeam, ConsoleSite: ConsoleSiteInternational, Region: RegionSingapore, Channel: ChannelOpenAIChat},
}

// Snapshot contains one complete normalized provider catalog observation.
// Snapshot 包含一份完整且规范化的供应商目录观测。
type Snapshot struct {
	// SchemaVersion identifies the snapshot schema.
	// SchemaVersion 标识快照 Schema。
	SchemaVersion int `json:"schema_version"`
	// Product is the immutable commercial product boundary.
	// Product 是不可变的商业产品边界。
	Product Product `json:"product"`
	// ConsoleSite is the exact source account site.
	// ConsoleSite 是精确的来源账号站点。
	ConsoleSite ConsoleSite `json:"console_site"`
	// Region is the exact source catalog region.
	// Region 是精确的来源目录区域。
	Region Region `json:"region"`
	// Channel identifies the observed catalog channel.
	// Channel 标识观测目录通道。
	Channel Channel `json:"channel"`
	// SourceAPI is the exact read-only source operation.
	// SourceAPI 是精确的只读来源操作。
	SourceAPI string `json:"source_api"`
	// SourceRevision is the SHA-256 of normalized credential-free content.
	// SourceRevision 是规范化且不含凭据内容的 SHA-256。
	SourceRevision string `json:"source_revision"`
	// ObservedAt records the first observation time for this exact revision.
	// ObservedAt 记录该精确修订首次观测时间。
	ObservedAt time.Time `json:"observed_at"`
	// FamilyTotal is the exact provider-reported grouped result count.
	// FamilyTotal 是供应商报告的精确分组结果数量。
	FamilyTotal int `json:"family_total"`
	// RecordTotal is the flattened unique concrete model count.
	// RecordTotal 是展平后的唯一具体模型数量。
	RecordTotal int `json:"record_total"`
	// ActiveRecordTotal is present when historical removed facts make the retained total exceed the latest source count, including an exact zero.
	// ActiveRecordTotal 在历史删除事实使保留总数超过最新来源数量时存在，并可精确表达零条活跃记录。
	ActiveRecordTotal *int `json:"active_record_total,omitempty"`
	// Models contains every concrete model record without publication filtering.
	// Models 包含全部未经过发布过滤的具体模型记录。
	Models []ModelFact `json:"models"`
}

// ModelFact contains evidence-safe fields from one concrete Alibaba model item.
// ModelFact 包含一个具体 Alibaba 模型条目的证据安全字段。
type ModelFact struct {
	// ModelID is the exact upstream request model identifier.
	// ModelID 是精确的上游请求模型标识。
	ModelID string `json:"model_id"`
	// SourceStatus is empty or active for current facts and source_removed for retained historical facts.
	// SourceStatus 对当前事实为空或 active，对保留历史事实为 source_removed。
	SourceStatus ModelFactSourceStatus `json:"source_status,omitempty"`
	// ModelAlias is the provider's stable or dated alias when present.
	// ModelAlias 是存在时供应商提供的稳定或日期别名。
	ModelAlias string `json:"model_alias,omitempty"`
	// EquivalentSnapshot links a stable alias to its provider snapshot.
	// EquivalentSnapshot 将稳定别名关联到供应商快照。
	EquivalentSnapshot string `json:"equivalent_snapshot,omitempty"`
	// DisplayName is the provider-facing model name.
	// DisplayName 是供应商显示的模型名称。
	DisplayName string `json:"display_name"`
	// Provider identifies the model publisher.
	// Provider 标识模型发布方。
	Provider string `json:"provider,omitempty"`
	// SourceFamilyID identifies the grouped catalog record that owned this item.
	// SourceFamilyID 标识拥有该条目的分组目录记录。
	SourceFamilyID string `json:"source_family_id"`
	// VersionTag distinguishes stable aliases from dated snapshots.
	// VersionTag 区分稳定别名与日期快照。
	VersionTag string `json:"version_tag,omitempty"`
	// CollectionTag identifies the provider model family.
	// CollectionTag 标识供应商模型系列。
	CollectionTag string `json:"collection_tag,omitempty"`
	// Category is the provider's normalized model category.
	// Category 是供应商规范化的模型分类。
	Category string `json:"category,omitempty"`
	// ServiceSites lists exact provider service-site markers.
	// ServiceSites 列出精确的供应商服务站点标记。
	ServiceSites []string `json:"service_sites,omitempty"`
	// Capabilities contains provider capability codes without interpretation.
	// Capabilities 包含未经解释的供应商能力代码。
	Capabilities []string `json:"capabilities,omitempty"`
	// Features contains provider feature flags without protocol-path inference.
	// Features 包含不推断协议路径的供应商功能标记。
	Features []string `json:"features,omitempty"`
	// RequestModalities lists provider-declared input modalities.
	// RequestModalities 列出供应商声明的输入模态。
	RequestModalities []string `json:"request_modalities,omitempty"`
	// ResponseModalities lists provider-declared output modalities.
	// ResponseModalities 列出供应商声明的输出模态。
	ResponseModalities []string `json:"response_modalities,omitempty"`
	// ContextWindow is present only when the provider reports a total context limit.
	// ContextWindow 仅在供应商报告总上下文上限时存在。
	ContextWindow *int64 `json:"context_window,omitempty"`
	// MaxInputTokens is present only when independently reported.
	// MaxInputTokens 仅在独立报告时存在。
	MaxInputTokens *int64 `json:"max_input_tokens,omitempty"`
	// MaxOutputTokens is present only when independently reported.
	// MaxOutputTokens 仅在独立报告时存在。
	MaxOutputTokens *int64 `json:"max_output_tokens,omitempty"`
	// MaxReasoningTokens is the provider reasoning budget ceiling when reported.
	// MaxReasoningTokens 是供应商报告的推理预算上限。
	MaxReasoningTokens *int64 `json:"max_reasoning_tokens,omitempty"`
	// ReasoningMaxInputTokens is the thinking-profile input ceiling when reported.
	// ReasoningMaxInputTokens 是供应商报告的思考规格输入上限。
	ReasoningMaxInputTokens *int64 `json:"reasoning_max_input_tokens,omitempty"`
	// ReasoningMaxOutputTokens is the thinking-profile output ceiling when reported.
	// ReasoningMaxOutputTokens 是供应商报告的思考规格输出上限。
	ReasoningMaxOutputTokens *int64 `json:"reasoning_max_output_tokens,omitempty"`
	// PermissionInference distinguishes an explicit permission result from omission.
	// PermissionInference 区分显式推理权限结果与字段缺失。
	PermissionInference *bool `json:"permission_inference,omitempty"`
	// SupportsInference distinguishes an explicit product-support result from omission.
	// SupportsInference 区分显式产品支持结果与字段缺失。
	SupportsInference *bool `json:"supports_inference,omitempty"`
	// ActivationStatus preserves the provider activation state without guessing its labels.
	// ActivationStatus 保留供应商激活状态且不猜测其标签。
	ActivationStatus *int `json:"activation_status,omitempty"`
	// RateLimits contains every provider tier exactly as reported.
	// RateLimits 包含供应商精确报告的每个限制层级。
	RateLimits []RateLimitFact `json:"rate_limits,omitempty"`
}

// RateLimitFact contains one strong qpmInfo tier without interpreting tier precedence.
// RateLimitFact 包含一个强类型 qpmInfo 层级且不解释层级优先关系。
type RateLimitFact struct {
	// TierID is the exact qpmInfo map key.
	// TierID 是精确的 qpmInfo Map Key。
	TierID string `json:"tier_id"`
	// TierType is the provider-reported tier type.
	// TierType 是供应商报告的层级类型。
	TierType string `json:"tier_type,omitempty"`
	// CountLimit is the request-count ceiling when reported.
	// CountLimit 是存在时的请求计数上限。
	CountLimit *int64 `json:"count_limit,omitempty"`
	// CountPeriodSeconds preserves the provider period in seconds.
	// CountPeriodSeconds 以秒保留供应商周期。
	CountPeriodSeconds *int64 `json:"count_period_seconds,omitempty"`
	// UsageLimit is the usage-field ceiling when reported.
	// UsageLimit 是存在时的用量字段上限。
	UsageLimit *int64 `json:"usage_limit,omitempty"`
	// UsagePeriodSeconds preserves the provider usage period in seconds.
	// UsagePeriodSeconds 以秒保留供应商用量周期。
	UsagePeriodSeconds *int64 `json:"usage_period_seconds,omitempty"`
	// UsageField is the exact provider metric identifier.
	// UsageField 是精确的供应商指标标识。
	UsageField string `json:"usage_field,omitempty"`
}

// Validate verifies one manifest is complete, unique, and honest about missing evidence.
// Validate 校验一份 Manifest 完整、唯一且如实记录缺失证据。
func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion || len(m.Entries) != len(requiredManifestBoundaries) {
		return errors.New("Alibaba catalog manifest schema or entries are invalid")
	}
	seenCatalogIDs := make(map[string]struct{}, len(m.Entries))
	for _, entry := range m.Entries {
		if errEntry := entry.Validate(); errEntry != nil {
			return errEntry
		}
		if _, exists := seenCatalogIDs[entry.CatalogID]; exists {
			return fmt.Errorf("duplicate Alibaba catalog ID %q", entry.CatalogID)
		}
		seenCatalogIDs[entry.CatalogID] = struct{}{}
	}
	for _, boundary := range requiredManifestBoundaries {
		matched := false
		for _, entry := range m.Entries {
			if entry.CatalogID != boundary.CatalogID {
				continue
			}
			if entry.Product != boundary.Product || entry.ConsoleSite != boundary.ConsoleSite || entry.Region != boundary.Region || entry.Channel != boundary.Channel {
				return fmt.Errorf("Alibaba catalog %q crosses its required product boundary", boundary.CatalogID)
			}
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("Alibaba catalog manifest omits required boundary %q", boundary.CatalogID)
		}
	}
	return nil
}

// Validate verifies one manifest entry has one exact evidence state.
// Validate 校验一个 Manifest 条目具有唯一精确的证据状态。
func (e ManifestEntry) Validate() error {
	if !canonicalNonEmptyString(e.CatalogID) || !canonicalNonEmptyString(e.Evidence) || !canonicalNonEmptyString(e.EvidenceSourceType) || e.EvidenceObservedAt.IsZero() || !validProduct(e.Product) || !validConsoleSite(e.ConsoleSite) || !validRegion(e.Region) || !validChannel(e.Channel) {
		return fmt.Errorf("Alibaba catalog manifest entry %q is invalid", e.CatalogID)
	}
	switch e.Status {
	case VerificationVerified:
		_, errRevision := hex.DecodeString(e.ContentRevision)
		if !canonicalNonEmptyString(e.Filename) || len(e.ContentRevision) != 64 || errRevision != nil {
			return fmt.Errorf("verified Alibaba catalog %q requires a filename", e.CatalogID)
		}
	case VerificationUnverified:
		if e.Filename != "" || e.ContentRevision != "" {
			return fmt.Errorf("unverified Alibaba catalog %q cannot name a snapshot", e.CatalogID)
		}
	default:
		return fmt.Errorf("Alibaba catalog %q has invalid verification status %q", e.CatalogID, e.Status)
	}
	return nil
}

// Validate verifies one normalized snapshot is complete and reproducible.
// Validate 校验一份规范化快照完整且可复现。
func (s Snapshot) Validate() error {
	if s.SchemaVersion != SchemaVersion || !validProduct(s.Product) || !validConsoleSite(s.ConsoleSite) || !validRegion(s.Region) || !validChannel(s.Channel) {
		return errors.New("Alibaba catalog snapshot identity is invalid")
	}
	if !validSnapshotBoundary(s.Product, s.ConsoleSite, s.Region, s.Channel) {
		return errors.New("Alibaba catalog snapshot crosses the closed product boundary matrix")
	}
	if !canonicalNonEmptyString(s.SourceAPI) || s.ObservedAt.IsZero() || s.FamilyTotal < 0 || s.RecordTotal < 0 || s.RecordTotal != len(s.Models) {
		return errors.New("Alibaba catalog snapshot provenance or totals are invalid")
	}
	if s.RecordTotal == 0 {
		return errors.New("verified Alibaba static catalog snapshot cannot be empty")
	}
	seenModels := make(map[string]struct{}, len(s.Models))
	activeRecordTotal := 0
	previousModelID := ""
	for _, model := range s.Models {
		if errModel := model.Validate(); errModel != nil {
			return errModel
		}
		if _, exists := seenModels[model.ModelID]; exists {
			return fmt.Errorf("duplicate Alibaba model %q", model.ModelID)
		}
		if previousModelID != "" && model.ModelID <= previousModelID {
			return errors.New("Alibaba model facts must be sorted by model ID")
		}
		seenModels[model.ModelID] = struct{}{}
		if model.SourceStatus != ModelFactSourceRemoved {
			activeRecordTotal++
		}
		previousModelID = model.ModelID
	}
	if s.ActiveRecordTotal == nil {
		if activeRecordTotal != s.RecordTotal {
			return errors.New("Alibaba catalog with retained removed facts requires an active record total")
		}
	} else if *s.ActiveRecordTotal != activeRecordTotal || *s.ActiveRecordTotal < 0 || *s.ActiveRecordTotal >= s.RecordTotal {
		return errors.New("Alibaba catalog active record total does not match retained model states")
	}
	if activeRecordTotal > 0 && s.FamilyTotal == 0 {
		return errors.New("Alibaba catalog with active models requires a positive family total")
	}
	revision, errRevision := s.ContentRevision()
	if errRevision != nil {
		return errRevision
	}
	if s.SourceRevision != revision {
		return errors.New("Alibaba catalog source revision does not match normalized content")
	}
	return nil
}

// validSnapshotBoundary reports whether one snapshot identity belongs to the closed manifest matrix.
// validSnapshotBoundary 报告一个快照身份是否属于封闭的 Manifest 矩阵。
func validSnapshotBoundary(product Product, consoleSite ConsoleSite, region Region, channel Channel) bool {
	for _, boundary := range requiredManifestBoundaries {
		if boundary.Product == product && boundary.ConsoleSite == consoleSite && boundary.Region == region && boundary.Channel == channel {
			return true
		}
	}
	return false
}

// ContentRevision returns the deterministic SHA-256 for non-temporal snapshot content.
// ContentRevision 返回非时间性快照内容的确定性 SHA-256。
func (s Snapshot) ContentRevision() (string, error) {
	content := s
	content.SourceRevision = ""
	content.ObservedAt = time.Time{}
	encoded, errMarshal := json.Marshal(content)
	if errMarshal != nil {
		return "", fmt.Errorf("marshal Alibaba catalog revision content: %w", errMarshal)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Validate verifies one concrete model fact and every exact rate-limit tier.
// Validate 校验一个具体模型事实及其每个精确速率限制层级。
func (m ModelFact) Validate() error {
	if !canonicalNonEmptyString(m.ModelID) || !canonicalNonEmptyString(m.DisplayName) || !canonicalNonEmptyString(m.SourceFamilyID) {
		return errors.New("Alibaba model identity is incomplete")
	}
	optionalIdentities := []struct {
		// name identifies one exact persisted evidence field.
		// name 标识一个精确持久化证据字段。
		name string
		// value contains the provider fact when present.
		// value 包含存在时的供应商事实。
		value string
	}{
		{name: "model_alias", value: m.ModelAlias}, {name: "equivalent_snapshot", value: m.EquivalentSnapshot}, {name: "provider", value: m.Provider},
		{name: "version_tag", value: m.VersionTag}, {name: "collection_tag", value: m.CollectionTag}, {name: "category", value: m.Category},
	}
	for _, identity := range optionalIdentities {
		if identity.value != "" && identity.value != strings.TrimSpace(identity.value) {
			return fmt.Errorf("Alibaba model %q contains a non-canonical %s", m.ModelID, identity.name)
		}
	}
	if m.SourceStatus != "" && m.SourceStatus != ModelFactSourceActive && m.SourceStatus != ModelFactSourceRemoved {
		return fmt.Errorf("Alibaba model %q has invalid source status %q", m.ModelID, m.SourceStatus)
	}
	for _, value := range []*int64{m.ContextWindow, m.MaxInputTokens, m.MaxOutputTokens, m.MaxReasoningTokens, m.ReasoningMaxInputTokens, m.ReasoningMaxOutputTokens} {
		if value != nil && *value < 0 {
			return fmt.Errorf("Alibaba model %q contains a negative token limit", m.ModelID)
		}
	}
	if !sortedUniqueStrings(m.ServiceSites) || !sortedUniqueStrings(m.Capabilities) || !sortedUniqueStrings(m.Features) || !sortedUniqueStrings(m.RequestModalities) || !sortedUniqueStrings(m.ResponseModalities) {
		return fmt.Errorf("Alibaba model %q contains unsorted or duplicate string facts", m.ModelID)
	}
	previousTierID := ""
	for _, limit := range m.RateLimits {
		if errLimit := limit.Validate(); errLimit != nil {
			return fmt.Errorf("Alibaba model %q: %w", m.ModelID, errLimit)
		}
		if previousTierID != "" && limit.TierID <= previousTierID {
			return fmt.Errorf("Alibaba model %q rate-limit tiers must be sorted", m.ModelID)
		}
		previousTierID = limit.TierID
	}
	return nil
}

// Validate verifies a qpmInfo tier preserves only complete count and usage tuples.
// Validate 校验一个 qpmInfo 层级仅保留完整的计数与用量元组。
func (r RateLimitFact) Validate() error {
	if !canonicalNonEmptyString(r.TierID) || r.TierType != strings.TrimSpace(r.TierType) || r.UsageField != "" && !canonicalNonEmptyString(r.UsageField) {
		return errors.New("Alibaba rate-limit tier or usage-field identity is invalid")
	}
	if (r.CountLimit == nil) != (r.CountPeriodSeconds == nil) || (r.UsageLimit == nil) != (r.UsagePeriodSeconds == nil) || (r.UsageLimit == nil) != (r.UsageField == "") {
		return fmt.Errorf("Alibaba rate-limit tier %q contains a partial limit tuple", r.TierID)
	}
	for _, value := range []*int64{r.CountLimit, r.CountPeriodSeconds, r.UsageLimit, r.UsagePeriodSeconds} {
		if value != nil && *value <= 0 {
			return fmt.Errorf("Alibaba rate-limit tier %q contains a non-positive limit", r.TierID)
		}
	}
	return nil
}

// sortedUniqueStrings reports whether values are already canonicalized.
// sortedUniqueStrings 报告字符串是否已经规范化。
func sortedUniqueStrings(values []string) bool {
	if !slices.IsSorted(values) || len(slices.Compact(append([]string(nil), values...))) != len(values) {
		return false
	}
	for _, value := range values {
		if !canonicalNonEmptyString(value) {
			return false
		}
	}
	return true
}

// canonicalNonEmptyString reports whether one evidence identity is already trimmed and non-empty.
// canonicalNonEmptyString 报告一个证据身份是否已去除首尾空白且非空。
func canonicalNonEmptyString(value string) bool {
	return value != "" && value == strings.TrimSpace(value)
}

// validProduct reports whether a product belongs to the closed Alibaba matrix.
// validProduct 报告产品是否属于封闭的 Alibaba 矩阵。
func validProduct(product Product) bool {
	return product == ProductCodingPlan || product == ProductTokenPlanPersonal || product == ProductTokenPlanTeam || product == ProductModelStudioAPI
}

// validConsoleSite reports whether a console site belongs to the closed Alibaba matrix.
// validConsoleSite 报告控制台站点是否属于封闭的 Alibaba 矩阵。
func validConsoleSite(site ConsoleSite) bool {
	return site == ConsoleSiteDomestic || site == ConsoleSiteInternational || site == ConsoleSiteNotApplicable
}

// validRegion reports whether a region belongs to the closed Alibaba matrix.
// validRegion 报告区域是否属于封闭的 Alibaba 矩阵。
func validRegion(region Region) bool {
	return region == RegionCN || region == RegionSingapore || region == RegionHongKong || region == RegionTokyo || region == RegionFrankfurt || region == RegionVirginia || region == RegionGlobal
}

// validChannel reports whether a channel belongs to the closed Alibaba evidence surface.
// validChannel 报告通道是否属于封闭的 Alibaba 证据面。
func validChannel(channel Channel) bool {
	return channel == ChannelOpenAIChat || channel == ChannelConsoleCatalog
}
