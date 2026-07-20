package vcp

import (
	"fmt"
	"math"
	"strings"
)

// RerankContent contains exactly one text or resource value.
// RerankContent 只包含一个文本或资源值。
type RerankContent struct {
	// Text contains UTF-8 query or candidate text.
	// Text 包含 UTF-8 查询或候选文本。
	Text *string `json:"text,omitempty"`
	// Resource contains one Router-owned multimodal value.
	// Resource 包含一个 Router 拥有的多模态值。
	Resource *ResourceReference `json:"resource,omitempty"`
}

// RerankQuery identifies the sole query.
// RerankQuery 标识唯一查询。
type RerankQuery struct {
	// ID is stable within the request.
	// ID 在请求内保持稳定。
	ID string `json:"id"`
	// Content contains the exact query value.
	// Content 包含精确查询值。
	Content RerankContent `json:"content"`
}

// RerankCandidate identifies one ordered candidate.
// RerankCandidate 标识一个有序候选项。
type RerankCandidate struct {
	// ID is stable within the request and response.
	// ID 在请求和响应中保持稳定。
	ID string `json:"id"`
	// Content contains the candidate value.
	// Content 包含候选值。
	Content RerankContent `json:"content"`
}

// RerankTruncation identifies an explicitly requested provider-supported policy.
// RerankTruncation 标识显式请求且供应商支持的截断策略。
type RerankTruncation string

const (
	// RerankTruncationNone forbids truncation.
	// RerankTruncationNone 禁止截断。
	RerankTruncationNone RerankTruncation = "none"
	// RerankTruncationProvider permits the selected profile's documented native truncation.
	// RerankTruncationProvider 允许所选规格记录的原生截断。
	RerankTruncationProvider RerankTruncation = "provider"
)

// RerankOperation contains one query and an ordered candidate list.
// RerankOperation 包含一个查询和有序候选列表。
type RerankOperation struct {
	// Query contains the sole query.
	// Query 包含唯一查询。
	Query RerankQuery `json:"query"`
	// Candidates contains stable ordered candidates.
	// Candidates 包含稳定有序候选项。
	Candidates []RerankCandidate `json:"candidates"`
	// TopN optionally limits the returned result count.
	// TopN 可选地限制返回结果数量。
	TopN *int `json:"top_n,omitempty"`
	// ReturnContent requests candidate content in results.
	// ReturnContent 请求在结果中返回候选内容。
	ReturnContent bool `json:"return_content,omitempty"`
	// Truncation requests one declared profile policy.
	// Truncation 请求一个已声明规格策略。
	Truncation RerankTruncation `json:"truncation"`
}

// RerankResult contains one provider-ranked candidate without score rewriting.
// RerankResult 包含一个未经分数改写的供应商重排候选项。
type RerankResult struct {
	// CandidateID identifies the original candidate.
	// CandidateID 标识原始候选项。
	CandidateID string `json:"candidate_id"`
	// OriginalIndex preserves the request position.
	// OriginalIndex 保留请求位置。
	OriginalIndex int `json:"original_index"`
	// Rank is the provider result order starting at one.
	// Rank 是从一开始的供应商结果顺序。
	Rank int `json:"rank"`
	// ProviderScore is the unmodified provider-reported score.
	// ProviderScore 是未经修改的供应商报告分数。
	ProviderScore float64 `json:"provider_score"`
	// ScoreSemantics records the provider-defined score meaning.
	// ScoreSemantics 记录供应商定义的分数含义。
	ScoreSemantics string `json:"score_semantics"`
	// Content optionally returns the original candidate content.
	// Content 可选地返回原始候选内容。
	Content *RerankContent `json:"content,omitempty"`
}

// Validate verifies exact query content, stable candidates, and result limits.
// Validate 校验精确查询内容、稳定候选项和结果限制。
func (o RerankOperation) Validate() error {
	if strings.TrimSpace(o.Query.ID) == "" {
		return fmt.Errorf("%w: rerank query id is required", ErrInvalidRequest)
	}
	if errContent := validateRerankContent(o.Query.Content); errContent != nil {
		return fmt.Errorf("%w: rerank query: %v", ErrInvalidRequest, errContent)
	}
	if len(o.Candidates) == 0 {
		return fmt.Errorf("%w: rerank candidates are required", ErrInvalidRequest)
	}
	if o.TopN != nil && (*o.TopN <= 0 || *o.TopN > len(o.Candidates)) {
		return fmt.Errorf("%w: rerank top_n must be positive and cannot exceed candidate count", ErrInvalidRequest)
	}
	if o.Truncation != RerankTruncationNone && o.Truncation != RerankTruncationProvider {
		return fmt.Errorf("%w: invalid rerank truncation %q", ErrInvalidRequest, o.Truncation)
	}
	seen := make(map[string]struct{}, len(o.Candidates))
	for index := range o.Candidates {
		candidate := o.Candidates[index]
		if strings.TrimSpace(candidate.ID) == "" {
			return fmt.Errorf("%w: rerank candidate %d requires id", ErrInvalidRequest, index)
		}
		if _, exists := seen[candidate.ID]; exists {
			return fmt.Errorf("%w: duplicate rerank candidate id %q", ErrInvalidRequest, candidate.ID)
		}
		seen[candidate.ID] = struct{}{}
		if errContent := validateRerankContent(candidate.Content); errContent != nil {
			return fmt.Errorf("%w: rerank candidate %q: %v", ErrInvalidRequest, candidate.ID, errContent)
		}
	}
	return nil
}

// ValidateResults verifies stable provider order, original indexes, raw finite scores, and optional content policy.
// ValidateResults 校验稳定供应商顺序、原始索引、原始有限分数以及可选内容策略。
func (o RerankOperation) ValidateResults(results []RerankResult) error {
	if len(results) == 0 || len(results) > len(o.Candidates) || o.TopN != nil && len(results) > *o.TopN {
		return fmt.Errorf("%w: rerank result count is invalid", ErrInvalidRequest)
	}
	seen := make(map[int]struct{}, len(results))
	for index, result := range results {
		if result.Rank != index+1 || result.OriginalIndex < 0 || result.OriginalIndex >= len(o.Candidates) {
			return fmt.Errorf("%w: rerank results require stable rank and original index", ErrInvalidRequest)
		}
		if _, exists := seen[result.OriginalIndex]; exists {
			return fmt.Errorf("%w: rerank result repeats original index %d", ErrInvalidRequest, result.OriginalIndex)
		}
		seen[result.OriginalIndex] = struct{}{}
		candidate := o.Candidates[result.OriginalIndex]
		if result.CandidateID != candidate.ID || strings.TrimSpace(result.ScoreSemantics) == "" || math.IsNaN(result.ProviderScore) || math.IsInf(result.ProviderScore, 0) {
			return fmt.Errorf("%w: rerank result identity, score, or semantics is invalid", ErrInvalidRequest)
		}
		if o.ReturnContent {
			if result.Content == nil || !rerankContentEqual(*result.Content, candidate.Content) {
				return fmt.Errorf("%w: rerank result content does not match its candidate", ErrInvalidRequest)
			}
		} else if result.Content != nil {
			return fmt.Errorf("%w: rerank result content was not requested", ErrInvalidRequest)
		}
	}
	return nil
}

// rerankContentEqual compares the closed text-or-resource shape without guessing aliases.
// rerankContentEqual 比较封闭的文本或资源形态且不猜测别名。
func rerankContentEqual(left RerankContent, right RerankContent) bool {
	if left.Text != nil && right.Text != nil {
		return *left.Text == *right.Text
	}
	if left.Resource != nil && right.Resource != nil {
		return *left.Resource == *right.Resource
	}
	return false
}

// validateRerankContent verifies exact-one text or resource content.
// validateRerankContent 校验唯一文本或资源内容。
func validateRerankContent(content RerankContent) error {
	if (content.Text == nil) == (content.Resource == nil) {
		return fmt.Errorf("content requires exactly one text or resource")
	}
	if content.Text != nil && strings.TrimSpace(*content.Text) == "" {
		return fmt.Errorf("text is empty")
	}
	if content.Resource != nil && strings.TrimSpace(content.Resource.ResourceID) == "" {
		return fmt.Errorf("resource_id is required")
	}
	return nil
}
