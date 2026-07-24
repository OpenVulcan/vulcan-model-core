package alibaba

import (
	"context"
	"errors"
	"testing"

	responsesprofile "github.com/OpenVulcan/vulcan-model-core/internal/protocol/openai/responses"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
)

// TestTokenPlanHarnessResponsesAdapterAppliesExactClosedWire verifies retention and tool restrictions match Qwen Code evidence.
// TestTokenPlanHarnessResponsesAdapterAppliesExactClosedWire 验证留存与工具限制符合 Qwen Code 证据。
func TestTokenPlanHarnessResponsesAdapterAppliesExactClosedWire(t *testing.T) {
	request := responsesprofile.Request{Tools: []responsesprofile.Tool{{Type: "web_search"}, {Type: "web_extractor"}}}
	headers, errAdapt := NewTokenPlanHarnessResponsesAdapter().Adapt(context.Background(), provider.ExecutionRequest{}, &request)
	if errAdapt != nil {
		t.Fatalf("Adapt() error = %v", errAdapt)
	}
	if len(headers) != 0 || request.Store == nil || *request.Store {
		t.Fatalf("adapted request = %#v, headers = %#v", request, headers)
	}

	request.Tools = append(request.Tools, responsesprofile.Tool{Type: "function", Name: "unproven"})
	if _, errAdapt = NewTokenPlanHarnessResponsesAdapter().Adapt(context.Background(), provider.ExecutionRequest{}, &request); !errors.Is(errAdapt, ErrInvalidTokenPlanHarnessRequest) {
		t.Fatalf("unproven tool Adapt() error = %v, want ErrInvalidTokenPlanHarnessRequest", errAdapt)
	}
}
