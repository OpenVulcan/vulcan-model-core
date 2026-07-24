package alibaba

import (
	"context"
	"errors"
	"fmt"

	responsesprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
)

const (
	// TokenPlanHarnessConversationActionBindingID identifies the exact Responses side-request action proven by Qwen Code.
	// TokenPlanHarnessConversationActionBindingID 标识由 Qwen Code 证实的精确 Responses 旁路请求动作。
	TokenPlanHarnessConversationActionBindingID = "action_alibaba_token_plan_harness_respond"
)

var (
	// ErrInvalidTokenPlanHarnessRequest reports a request outside the exact Qwen Code Responses tool contract.
	// ErrInvalidTokenPlanHarnessRequest 表示请求超出 Qwen Code 的精确 Responses 工具合同。
	ErrInvalidTokenPlanHarnessRequest = errors.New("invalid Alibaba Token Plan Harness request")
)

// TokenPlanHarnessResponsesAdapter applies the retention and closed-tool contract proven by the official Qwen Code client.
// TokenPlanHarnessResponsesAdapter 应用官方 Qwen Code 客户端证实的留存与封闭工具合同。
type TokenPlanHarnessResponsesAdapter struct{}

// NewTokenPlanHarnessResponsesAdapter creates one stateless Token Plan Responses adapter.
// NewTokenPlanHarnessResponsesAdapter 创建一个无状态 Token Plan Responses 适配器。
func NewTokenPlanHarnessResponsesAdapter() *TokenPlanHarnessResponsesAdapter {
	return &TokenPlanHarnessResponsesAdapter{}
}

// Adapt disables provider retention and rejects every unverified Responses tool shape.
// Adapt 禁用供应商留存并拒绝所有未经验证的 Responses 工具形态。
func (a *TokenPlanHarnessResponsesAdapter) Adapt(_ context.Context, _ provider.ExecutionRequest, request *responsesprofile.Request) ([]transport.Header, error) {
	if a == nil || request == nil {
		return nil, ErrInvalidTokenPlanHarnessRequest
	}
	for _, tool := range request.Tools {
		if tool.Type != "web_search" && tool.Type != "web_extractor" {
			return nil, fmt.Errorf("%w: tool type %q is not proven", ErrInvalidTokenPlanHarnessRequest, tool.Type)
		}
	}
	// store is false because the official side request explicitly disables provider retention.
	// store 为假，因为官方旁路请求显式禁用供应商留存。
	store := false
	request.Store = &store
	return nil, nil
}
