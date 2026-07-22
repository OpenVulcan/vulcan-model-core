package vcp

import (
	"fmt"
	"math"
	"net/url"
	"strings"
)

const (
	// MaximumWebExtractURLs is the public per-request URL ceiling.
	// MaximumWebExtractURLs 是公开单次请求 URL 数量上限。
	MaximumWebExtractURLs = 20
	// MinimumWebExtractChunks is the smallest supported relevance chunk count.
	// MinimumWebExtractChunks 是支持的最小相关片段数量。
	MinimumWebExtractChunks = 1
	// MaximumWebExtractChunks is the largest supported relevance chunk count.
	// MaximumWebExtractChunks 是支持的最大相关片段数量。
	MaximumWebExtractChunks = 5
)

// WebExtractDepth identifies one extraction fidelity and cost tier.
// WebExtractDepth 标识一种内容提取精度与成本档位。
type WebExtractDepth string

const (
	// WebExtractDepthBasic requests ordinary page-content extraction.
	// WebExtractDepthBasic 请求普通网页内容提取。
	WebExtractDepthBasic WebExtractDepth = "basic"
	// WebExtractDepthAdvanced requests richer tables and embedded content.
	// WebExtractDepthAdvanced 请求更丰富的表格与嵌入内容。
	WebExtractDepthAdvanced WebExtractDepth = "advanced"
)

// WebExtractFormat identifies the requested extracted-content representation.
// WebExtractFormat 标识请求的提取内容表示形式。
type WebExtractFormat string

const (
	// WebExtractFormatMarkdown requests Markdown content.
	// WebExtractFormatMarkdown 请求 Markdown 内容。
	WebExtractFormatMarkdown WebExtractFormat = "markdown"
	// WebExtractFormatText requests plain text content.
	// WebExtractFormatText 请求纯文本内容。
	WebExtractFormatText WebExtractFormat = "text"
)

// WebExtractOperation contains one bounded direct web-content extraction request.
// WebExtractOperation 包含一个有界的直接网页内容提取请求。
type WebExtractOperation struct {
	// URLs contains one to twenty exact HTTPS resources.
	// URLs 包含一到二十个精确 HTTPS 资源。
	URLs []string `json:"urls"`
	// Query optionally asks the provider to retain relevance-ranked chunks.
	// Query 可选地要求供应商保留按相关性排序的片段。
	Query string `json:"query,omitempty"`
	// ChunksPerSource limits relevance chunks and requires Query.
	// ChunksPerSource 限制相关片段数量且要求同时提供 Query。
	ChunksPerSource *int `json:"chunks_per_source,omitempty"`
	// Depth selects basic or advanced extraction and defaults to basic.
	// Depth 选择 basic 或 advanced 提取，省略时默认为 basic。
	Depth WebExtractDepth `json:"depth,omitempty"`
	// Format selects Markdown or plain text and defaults to Markdown.
	// Format 选择 Markdown 或纯文本，省略时默认为 Markdown。
	Format WebExtractFormat `json:"format,omitempty"`
	// IncludeImages requests extracted image URLs.
	// IncludeImages 请求返回提取到的图片 URL。
	IncludeImages bool `json:"include_images,omitempty"`
	// IncludeFavicon requests the page favicon URL.
	// IncludeFavicon 请求返回页面站点图标 URL。
	IncludeFavicon bool `json:"include_favicon,omitempty"`
	// TimeoutSeconds optionally bounds provider extraction time from one to sixty seconds.
	// TimeoutSeconds 可选地将供应商提取时间限制在一到六十秒。
	TimeoutSeconds *float64 `json:"timeout_seconds,omitempty"`
}

// WebExtractResult contains one successfully extracted page.
// WebExtractResult 包含一个成功提取的网页。
type WebExtractResult struct {
	// URL is the exact extracted resource URL.
	// URL 是被提取资源的精确 URL。
	URL string `json:"url"`
	// RawContent contains provider-returned Markdown or plain text.
	// RawContent 包含供应商返回的 Markdown 或纯文本。
	RawContent string `json:"raw_content"`
	// Images contains provider-returned HTTPS image URLs when requested.
	// Images 包含请求图片时供应商返回的 HTTPS 图片 URL。
	Images []string `json:"images,omitempty"`
	// Favicon contains the provider-returned HTTPS favicon URL when requested.
	// Favicon 包含请求站点图标时供应商返回的 HTTPS 图标 URL。
	Favicon string `json:"favicon,omitempty"`
}

// WebExtractFailure contains one provider-reported per-URL failure.
// WebExtractFailure 包含一个供应商报告的单 URL 失败。
type WebExtractFailure struct {
	// URL identifies the resource that could not be extracted.
	// URL 标识无法提取的资源。
	URL string `json:"url"`
	// Error is the provider-returned safe failure description.
	// Error 是供应商返回的安全失败说明。
	Error string `json:"error"`
}

// WebExtractResponse is the unified typed result for direct content extraction.
// WebExtractResponse 是直接内容提取的统一类型化结果。
type WebExtractResponse struct {
	// Results preserves successful provider result order.
	// Results 保留成功结果的供应商顺序。
	Results []WebExtractResult `json:"results"`
	// FailedResults preserves structured per-URL provider failures.
	// FailedResults 保留结构化的逐 URL 供应商失败。
	FailedResults []WebExtractFailure `json:"failed_results,omitempty"`
	// ProviderRequestID is the provider support identifier.
	// ProviderRequestID 是供应商支持标识。
	ProviderRequestID string `json:"provider_request_id,omitempty"`
	// ResponseTimeSeconds is the provider-reported execution duration when present.
	// ResponseTimeSeconds 是存在时供应商报告的执行耗时。
	ResponseTimeSeconds *float64 `json:"response_time_seconds,omitempty"`
	// Usage contains provider-reported service-unit consumption.
	// Usage 包含供应商报告的服务计量消耗。
	Usage *UsageObservation `json:"usage,omitempty"`
}

// Validate verifies the closed extraction request without normalizing caller identity.
// Validate 校验封闭提取请求且不规范化调用方身份。
func (o WebExtractOperation) Validate() error {
	if len(o.URLs) == 0 || len(o.URLs) > MaximumWebExtractURLs {
		return fmt.Errorf("%w: web extraction requires 1..%d URLs", ErrInvalidRequest, MaximumWebExtractURLs)
	}
	seenURLs := make(map[string]struct{}, len(o.URLs))
	for _, rawURL := range o.URLs {
		if errURL := validateWebExtractHTTPSURL(rawURL); errURL != nil {
			return errURL
		}
		if _, exists := seenURLs[rawURL]; exists {
			return fmt.Errorf("%w: duplicate web extraction URL %q", ErrInvalidRequest, rawURL)
		}
		seenURLs[rawURL] = struct{}{}
	}
	if o.Query != strings.TrimSpace(o.Query) {
		return fmt.Errorf("%w: web extraction query cannot contain surrounding whitespace", ErrInvalidRequest)
	}
	if o.ChunksPerSource != nil {
		if o.Query == "" {
			return fmt.Errorf("%w: chunks_per_source requires query", ErrInvalidRequest)
		}
		if *o.ChunksPerSource < MinimumWebExtractChunks || *o.ChunksPerSource > MaximumWebExtractChunks {
			return fmt.Errorf("%w: chunks_per_source must be within %d..%d", ErrInvalidRequest, MinimumWebExtractChunks, MaximumWebExtractChunks)
		}
	}
	if o.Depth != "" && o.Depth != WebExtractDepthBasic && o.Depth != WebExtractDepthAdvanced {
		return fmt.Errorf("%w: unsupported web extraction depth %q", ErrInvalidRequest, o.Depth)
	}
	if o.Format != "" && o.Format != WebExtractFormatMarkdown && o.Format != WebExtractFormatText {
		return fmt.Errorf("%w: unsupported web extraction format %q", ErrInvalidRequest, o.Format)
	}
	if o.TimeoutSeconds != nil && (math.IsNaN(*o.TimeoutSeconds) || math.IsInf(*o.TimeoutSeconds, 0) || *o.TimeoutSeconds < 1 || *o.TimeoutSeconds > 60) {
		return fmt.Errorf("%w: web extraction timeout_seconds must be within 1..60", ErrInvalidRequest)
	}
	return nil
}

// validateWebExtractHTTPSURL requires an absolute credential-free HTTPS URL.
// validateWebExtractHTTPSURL 要求绝对、无凭据的 HTTPS URL。
func validateWebExtractHTTPSURL(rawURL string) error {
	if rawURL == "" || rawURL != strings.TrimSpace(rawURL) {
		return fmt.Errorf("%w: web extraction URLs must be normalized", ErrInvalidRequest)
	}
	parsed, errParse := url.ParseRequestURI(rawURL)
	if errParse != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%w: web extraction URL must be an absolute credential-free HTTPS URL", ErrInvalidRequest)
	}
	return nil
}
