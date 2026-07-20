package vcp

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SearchBackendKind identifies one immutable internal web-search implementation.
// SearchBackendKind 标识一种不可变内部网页搜索实现。
type SearchBackendKind string

const (
	// SearchBackendDirectAPI calls a dedicated search API.
	// SearchBackendDirectAPI 调用专用搜索 API。
	SearchBackendDirectAPI SearchBackendKind = "direct_search_api"
	// SearchBackendGroundedModel calls one fixed web-enabled model.
	// SearchBackendGroundedModel 调用一个固定联网模型。
	SearchBackendGroundedModel SearchBackendKind = "model_grounded_search"
)

// WebSearchOutputMode identifies one requested response shape.
// WebSearchOutputMode 标识一种请求响应形态。
type WebSearchOutputMode string

const (
	// WebSearchOutputResults requests structured search results.
	// WebSearchOutputResults 请求结构化搜索结果。
	WebSearchOutputResults WebSearchOutputMode = "results"
	// WebSearchOutputAnswerWithCitations requests an answer with citations.
	// WebSearchOutputAnswerWithCitations 请求带引用的答案。
	WebSearchOutputAnswerWithCitations WebSearchOutputMode = "answer_with_citations"
	// WebSearchOutputResultsAndAnswer requests both real results and an answer.
	// WebSearchOutputResultsAndAnswer 同时请求真实结果和答案。
	WebSearchOutputResultsAndAnswer WebSearchOutputMode = "results_and_answer"
)

// SearchEvidenceRequirement identifies caller-required search observability.
// SearchEvidenceRequirement 标识调用方要求的搜索可观察性。
type SearchEvidenceRequirement string

const (
	// SearchEvidenceBestEffort permits a transparent unverified model request.
	// SearchEvidenceBestEffort 允许透明的未验证模型搜索请求。
	SearchEvidenceBestEffort SearchEvidenceRequirement = "best_effort"
	// SearchEvidenceVerified requires observable provider search evidence.
	// SearchEvidenceVerified 要求可观察的供应商搜索证据。
	SearchEvidenceVerified SearchEvidenceRequirement = "verified"
)

// SearchExecutionStatus identifies whether web access was observed.
// SearchExecutionStatus 标识是否观察到联网行为。
type SearchExecutionStatus string

const (
	// SearchExecutionConfirmed records observable search evidence.
	// SearchExecutionConfirmed 记录可观察搜索证据。
	SearchExecutionConfirmed SearchExecutionStatus = "confirmed"
	// SearchExecutionRequestedUnverified records a prompted request without observable evidence.
	// SearchExecutionRequestedUnverified 记录已提示但没有可观察证据的请求。
	SearchExecutionRequestedUnverified SearchExecutionStatus = "requested_unverified"
	// SearchExecutionNotPerformed records explicit provider non-execution.
	// SearchExecutionNotPerformed 记录供应商明确未执行搜索。
	SearchExecutionNotPerformed SearchExecutionStatus = "not_performed"
)

// SearchEvidenceKind identifies one provider-backed proof shape.
// SearchEvidenceKind 标识一种供应商支持的证明形态。
type SearchEvidenceKind string

const (
	// SearchEvidenceProviderEvent uses a provider search event.
	// SearchEvidenceProviderEvent 使用供应商搜索事件。
	SearchEvidenceProviderEvent SearchEvidenceKind = "provider_event"
	// SearchEvidenceStructuredResult uses provider-returned structured results.
	// SearchEvidenceStructuredResult 使用供应商返回的结构化结果。
	SearchEvidenceStructuredResult SearchEvidenceKind = "structured_result"
	// SearchEvidenceCitation uses provider-returned citations.
	// SearchEvidenceCitation 使用供应商返回的引用。
	SearchEvidenceCitation SearchEvidenceKind = "citation"
	// SearchEvidenceProviderContract uses only an official provider guarantee.
	// SearchEvidenceProviderContract 仅使用供应商官方保证。
	SearchEvidenceProviderContract SearchEvidenceKind = "provider_contract_only"
)

// DomainFilter contains explicit allowed and blocked domains.
// DomainFilter 包含显式允许和阻止域名。
type DomainFilter struct {
	// Allow contains exact allowed domain names.
	// Allow 包含精确允许域名。
	Allow []string `json:"allow,omitempty"`
	// Block contains exact blocked domain names.
	// Block 包含精确阻止域名。
	Block []string `json:"block,omitempty"`
}

// SearchTimeFilter contains explicit publication-time boundaries.
// SearchTimeFilter 包含显式发布时间边界。
type SearchTimeFilter struct {
	// PublishedAfter is an inclusive lower publication boundary.
	// PublishedAfter 是包含端点的最早发布时间。
	PublishedAfter *time.Time `json:"published_after,omitempty"`
	// PublishedBefore is an inclusive upper publication boundary.
	// PublishedBefore 是包含端点的最晚发布时间。
	PublishedBefore *time.Time `json:"published_before,omitempty"`
}

// SearchLocale contains explicit language and region preferences.
// SearchLocale 包含显式语言和地区偏好。
type SearchLocale struct {
	// Language is a provider-supported language tag.
	// Language 是供应商支持的语言标签。
	Language string `json:"language,omitempty"`
	// Region is a provider-supported country or region code.
	// Region 是供应商支持的国家或地区代码。
	Region string `json:"region,omitempty"`
}

// SearchLocation contains coarse caller-authorized location context.
// SearchLocation 包含调用方授权的粗粒度位置上下文。
type SearchLocation struct {
	// Country is an optional country code.
	// Country 是可选国家代码。
	Country string `json:"country,omitempty"`
	// Region is an optional administrative region.
	// Region 是可选行政区域。
	Region string `json:"region,omitempty"`
	// City is an optional city name.
	// City 是可选城市名称。
	City string `json:"city,omitempty"`
	// Timezone is an optional IANA timezone name.
	// Timezone 是可选 IANA 时区名称。
	Timezone string `json:"timezone,omitempty"`
}

// SafeSearchMode identifies one provider-supported safety preference.
// SafeSearchMode 标识一种供应商支持的安全搜索偏好。
type SafeSearchMode string

const (
	// SafeSearchOff disables filtering when supported.
	// SafeSearchOff 在支持时禁用过滤。
	SafeSearchOff SafeSearchMode = "off"
	// SafeSearchModerate requests moderate filtering.
	// SafeSearchModerate 请求中等过滤。
	SafeSearchModerate SafeSearchMode = "moderate"
	// SafeSearchStrict requests strict filtering.
	// SafeSearchStrict 请求严格过滤。
	SafeSearchStrict SafeSearchMode = "strict"
)

// WebSearchOperation is the sole public web-search payload.
// WebSearchOperation 是唯一公开网页搜索载荷。
type WebSearchOperation struct {
	// Query is the exact caller search query.
	// Query 是调用方精确搜索查询。
	Query string `json:"query"`
	// Domains contains explicit domain filters.
	// Domains 包含显式域名过滤器。
	Domains DomainFilter `json:"domains"`
	// Time contains explicit publication-time filters.
	// Time 包含显式发布时间过滤器。
	Time SearchTimeFilter `json:"time"`
	// Locale contains language and region preferences.
	// Locale 包含语言和地区偏好。
	Locale SearchLocale `json:"locale"`
	// Location contains coarse user-authorized location context.
	// Location 包含粗粒度用户授权位置上下文。
	Location SearchLocation `json:"location"`
	// SafeSearch requests one declared safety policy.
	// SafeSearch 请求一个已声明安全策略。
	SafeSearch SafeSearchMode `json:"safe_search"`
	// MaxResults requests a positive provider-supported result limit.
	// MaxResults 请求一个正数且供应商支持的结果限制。
	MaxResults *int `json:"max_results,omitempty"`
	// OutputMode requests one declared response shape.
	// OutputMode 请求一个已声明响应形态。
	OutputMode WebSearchOutputMode `json:"output_mode"`
	// EvidenceRequirement controls acceptance of unverified model search.
	// EvidenceRequirement 控制是否接受未验证模型搜索。
	EvidenceRequirement SearchEvidenceRequirement `json:"evidence_requirement"`
}

// WebSearchResult contains one provider-returned result.
// WebSearchResult 包含一个供应商返回结果。
type WebSearchResult struct {
	// ID is stable within the response.
	// ID 在响应内保持稳定。
	ID string `json:"id"`
	// Rank preserves provider result order starting at one.
	// Rank 保留从一开始的供应商结果顺序。
	Rank int `json:"rank"`
	// Title is the provider-returned title.
	// Title 是供应商返回标题。
	Title string `json:"title,omitempty"`
	// URL is the provider-returned canonical URL.
	// URL 是供应商返回规范 URL。
	URL string `json:"url"`
	// SourceDomain is the parsed or provider-returned source domain.
	// SourceDomain 是解析或供应商返回来源域名。
	SourceDomain string `json:"source_domain,omitempty"`
	// Snippet is the provider-returned excerpt.
	// Snippet 是供应商返回摘要片段。
	Snippet string `json:"snippet,omitempty"`
	// PublishedAt is the provider-returned publication time.
	// PublishedAt 是供应商返回发布时间。
	PublishedAt *time.Time `json:"published_at,omitempty"`
	// UpdatedAt is the provider-returned update time.
	// UpdatedAt 是供应商返回更新时间。
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Author is the provider-returned author.
	// Author 是供应商返回作者。
	Author string `json:"author,omitempty"`
	// ProviderScore preserves the provider-returned relevance score without normalization.
	// ProviderScore 保留供应商返回且未经归一化的相关性分数。
	ProviderScore *float64 `json:"provider_score,omitempty"`
}

// CitationLocation identifies one answer span or output item.
// CitationLocation 标识一个答案片段或输出项目。
type CitationLocation struct {
	// OutputItemID optionally identifies the cited output item.
	// OutputItemID 可选地标识被引用输出项目。
	OutputItemID string `json:"output_item_id,omitempty"`
	// Start is an optional inclusive UTF-8 character offset.
	// Start 是可选包含端点的 UTF-8 字符偏移。
	Start *int `json:"start,omitempty"`
	// End is an optional exclusive UTF-8 character offset.
	// End 是可选不包含端点的 UTF-8 字符偏移。
	End *int `json:"end,omitempty"`
}

// Citation contains one provider-returned source relation.
// Citation 包含一个供应商返回来源关系。
type Citation struct {
	// ID is stable within the response.
	// ID 在响应内保持稳定。
	ID string `json:"id"`
	// ResultID optionally links one structured search result.
	// ResultID 可选地链接一个结构化搜索结果。
	ResultID string `json:"result_id,omitempty"`
	// URL is the provider-returned source URL.
	// URL 是供应商返回来源 URL。
	URL string `json:"url"`
	// Title is the provider-returned source title.
	// Title 是供应商返回来源标题。
	Title string `json:"title,omitempty"`
	// Location identifies the cited answer span.
	// Location 标识被引用答案片段。
	Location CitationLocation `json:"location"`
}

// SearchSource contains one provider-reported consulted source that is not necessarily a ranked result or citation.
// SearchSource 包含一个供应商报告的已咨询来源，它不一定是排序结果或引用。
type SearchSource struct {
	// Type identifies the provider source kind.
	// Type 标识供应商来源类型。
	Type string `json:"type"`
	// URL is the provider-returned source URL.
	// URL 是供应商返回的来源 URL。
	URL string `json:"url"`
}

// SearchCall contains one provider-observed native search action in an ordinary model response.
// SearchCall 包含普通模型响应中一次供应商观测到的原生搜索动作。
type SearchCall struct {
	// ID is the stable provider or Router-derived search-call identifier.
	// ID 是稳定的供应商或 Router 派生搜索调用标识。
	ID string `json:"id"`
	// Status is the provider lifecycle state.
	// Status 是供应商生命周期状态。
	Status string `json:"status"`
	// ActionType identifies search, open_page, or find_in_page.
	// ActionType 标识 search、open_page 或 find_in_page。
	ActionType string `json:"action_type,omitempty"`
	// Query is the actual provider query for search actions.
	// Query 是搜索动作的真实供应商查询。
	Query string `json:"query,omitempty"`
	// URL is the provider target for open_page or find_in_page actions.
	// URL 是 open_page 或 find_in_page 动作的供应商目标。
	URL string `json:"url,omitempty"`
	// Pattern is the provider search pattern for find_in_page actions.
	// Pattern 是 find_in_page 动作的供应商搜索模式。
	Pattern string `json:"pattern,omitempty"`
	// Sources preserves every provider-reported consulted source.
	// Sources 保留每个供应商报告的已咨询来源。
	Sources []SearchSource `json:"sources,omitempty"`
}

// SearchExecutionEvidence describes how actual web access was observed.
// SearchExecutionEvidence 描述如何观察到实际联网行为。
type SearchExecutionEvidence struct {
	// Status records confirmed, requested-unverified, or not-performed state.
	// Status 记录已确认、请求未验证或未执行状态。
	Status SearchExecutionStatus `json:"status"`
	// Kinds contains stable unique evidence kinds.
	// Kinds 包含稳定唯一证据类型。
	Kinds []SearchEvidenceKind `json:"kinds,omitempty"`
}

// WebSearchResponse is the unified response for both search backends.
// WebSearchResponse 是两种搜索后端的统一响应。
type WebSearchResponse struct {
	// Query is the actual provider search query when exposed.
	// Query 是供应商暴露时的实际搜索查询。
	Query string `json:"query"`
	// Queries preserves every actual provider search query in execution order when exposed.
	// Queries 按执行顺序保留供应商暴露的每个真实搜索查询。
	Queries []string `json:"queries,omitempty"`
	// Evidence describes observed search execution.
	// Evidence 描述观察到的搜索执行。
	Evidence SearchExecutionEvidence `json:"evidence"`
	// Results contains real ordered provider results.
	// Results 包含真实有序供应商结果。
	Results []WebSearchResult `json:"results,omitempty"`
	// Answer contains an optional provider-generated answer.
	// Answer 包含可选供应商生成答案。
	Answer string `json:"answer,omitempty"`
	// Citations contains real provider-returned citations.
	// Citations 包含真实供应商返回引用。
	Citations []Citation `json:"citations,omitempty"`
	// Sources preserves provider-reported consulted sources without falsely ranking or citing them.
	// Sources 保留供应商报告的已咨询来源，而不虚假地对其排序或建立引用。
	Sources []SearchSource `json:"sources,omitempty"`
	// Usage contains provider-reported usage facts.
	// Usage 包含供应商报告用量事实。
	Usage *UsageObservation `json:"usage,omitempty"`
}

// Validate verifies the unified search query and closed policy fields.
// Validate 校验统一搜索查询和封闭策略字段。
func (o WebSearchOperation) Validate() error {
	if strings.TrimSpace(o.Query) == "" {
		return fmt.Errorf("%w: web search query is required", ErrInvalidRequest)
	}
	if o.OutputMode != WebSearchOutputResults && o.OutputMode != WebSearchOutputAnswerWithCitations && o.OutputMode != WebSearchOutputResultsAndAnswer {
		return fmt.Errorf("%w: invalid web search output_mode %q", ErrInvalidRequest, o.OutputMode)
	}
	if o.EvidenceRequirement != SearchEvidenceBestEffort && o.EvidenceRequirement != SearchEvidenceVerified {
		return fmt.Errorf("%w: invalid search evidence_requirement %q", ErrInvalidRequest, o.EvidenceRequirement)
	}
	if o.SafeSearch != "" && o.SafeSearch != SafeSearchOff && o.SafeSearch != SafeSearchModerate && o.SafeSearch != SafeSearchStrict {
		return fmt.Errorf("%w: invalid safe_search %q", ErrInvalidRequest, o.SafeSearch)
	}
	if o.MaxResults != nil && *o.MaxResults <= 0 {
		return fmt.Errorf("%w: max_results must be positive", ErrInvalidRequest)
	}
	if o.Time.PublishedAfter != nil && o.Time.PublishedBefore != nil && o.Time.PublishedAfter.After(*o.Time.PublishedBefore) {
		return fmt.Errorf("%w: published_after cannot be later than published_before", ErrInvalidRequest)
	}
	return validateDomainFilter(o.Domains)
}

// validateDomainFilter verifies normalized unique domain names without URL paths.
// validateDomainFilter 校验不含 URL 路径的规范唯一域名。
func validateDomainFilter(filter DomainFilter) error {
	seen := make(map[string]string, len(filter.Allow)+len(filter.Block))
	for _, entry := range append(append([]string{}, filter.Allow...), filter.Block...) {
		domain := strings.ToLower(strings.TrimSpace(entry))
		if domain == "" || strings.ContainsAny(domain, "/?#") {
			return fmt.Errorf("%w: invalid search domain %q", ErrInvalidRequest, entry)
		}
		parsed, errParse := url.Parse("https://" + domain)
		if errParse != nil || parsed.Hostname() == "" || parsed.Hostname() != domain {
			return fmt.Errorf("%w: invalid search domain %q", ErrInvalidRequest, entry)
		}
		if previous, exists := seen[domain]; exists {
			return fmt.Errorf("%w: duplicate search domain %q in %s", ErrInvalidRequest, domain, previous)
		}
		seen[domain] = "domain filters"
	}
	return nil
}
