package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// operationTargetResolver returns exact model and service targets by requested operation.
// operationTargetResolver 按请求操作返回精确模型与服务 Target。
type operationTargetResolver struct {
	// model is the immutable parent model target.
	// model 是不可变父模型 Target。
	model resolve.Target
	// service is the immutable Router child service target.
	// service 是不可变 Router 子服务 Target。
	service resolve.Target
}

// Resolve returns the service target only for search and otherwise returns the parent model.
// Resolve 仅为搜索返回服务 Target，其他情况返回父模型。
func (r *operationTargetResolver) Resolve(_ context.Context, request resolve.Request) (resolve.Target, resolve.Diagnostics, error) {
	if request.Operation == vcp.OperationSearchWeb {
		return r.service, resolve.Diagnostics{ReadyCandidates: 1}, nil
	}
	return r.model, resolve.Diagnostics{ReadyCandidates: 1}, nil
}

// staticModelToolResolver returns one frozen Router binding.
// staticModelToolResolver 返回一个冻结的 Router 绑定。
type staticModelToolResolver struct {
	// resolved contains the exact administrator binding and child target.
	// resolved 包含精确管理员绑定与子 Target。
	resolved routertool.ResolvedBinding
}

// recordingInputPlanCreator captures one Router child media plan request and returns a fixed accepted plan.
// recordingInputPlanCreator 捕获一个 Router 子媒体方案请求并返回固定的已接受方案。
type recordingInputPlanCreator struct {
	// request is the exact input planning request received from the Router extension.
	// request 是从 Router 增强能力收到的精确输入规划请求。
	request inputplan.Request
	// plan is the immutable accepted plan returned to the child execution.
	// plan 是返回给子执行的不可变已接受方案。
	plan inputplan.Plan
}

// CreateInputPlan records and returns the configured immutable plan.
// CreateInputPlan 记录并返回配置的不可变方案。
func (c *recordingInputPlanCreator) CreateInputPlan(_ context.Context, request inputplan.Request) (inputplan.Plan, error) {
	c.request = request
	return c.plan, nil
}

// Revalidate returns the configured immutable plan for the InputPlanReader contract.
// Revalidate 为 InputPlanReader 合同返回配置的不可变方案。
func (c *recordingInputPlanCreator) Revalidate(_ context.Context, _ string, _ string) (inputplan.Plan, error) {
	return c.plan, nil
}

// Resolve verifies the requested standard kind and returns the frozen binding.
// Resolve 校验请求的标准类型并返回冻结绑定。
func (r staticModelToolResolver) Resolve(_ context.Context, _ resolve.Target, kind vcp.StandardModelToolKind, _ time.Time) (routertool.ResolvedBinding, error) {
	if kind != r.resolved.Binding.Kind {
		return routertool.ResolvedBinding{}, fmt.Errorf("unexpected tool kind %s", kind)
	}
	return r.resolved, nil
}

// ResolveExtension verifies the requested enhancement and returns its frozen model target.
// ResolveExtension 校验请求的增强能力并返回其冻结模型 Target。
func (r staticModelToolResolver) ResolveExtension(_ context.Context, _ resolve.Target, extension vcp.RouterExtensionKind, _ time.Time) (routertool.ResolvedBinding, error) {
	if extension == r.resolved.Binding.Extension {
		return r.resolved, nil
	}
	return routertool.ResolvedBinding{}, fmt.Errorf("unexpected Router extension %s", extension)
}

// TestWithholdRouterManagedMediaProhibitsParentByteDispatch verifies delegated media is represented only by an opaque reference.
// TestWithholdRouterManagedMediaProhibitsParentByteDispatch 校验已委托媒体仅以不透明引用表示。
func TestWithholdRouterManagedMediaProhibitsParentByteDispatch(t *testing.T) {
	request := vcp.ExecutionRequest{
		Operation: vcp.OperationConversationRespond,
		Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{Context: []vcp.ContextItem{{
			ItemID:    "message_media",
			Sequence:  1,
			Kind:      vcp.ContextMessage,
			Authority: vcp.AuthorityUser,
			Actor:     vcp.ActorEndUser,
			Placement: vcp.PlacementTranscript,
			Activation: vcp.Activation{
				Mode: vcp.ActivationRequestStart,
			},
			Visibility: vcp.VisibilityModel,
			Content: []vcp.ContentBlock{
				{Type: vcp.ContentImage, ResourceRef: "res_image", MediaRole: vcp.MediaRoleUnderstanding},
				{Type: vcp.ContentAudio, ResourceRef: "res_audio", MediaRole: vcp.MediaRoleUnderstanding},
			},
			Message: &vcp.MessageItem{},
		}}}},
	}
	plan := ModelToolPlan{RouterExtensions: []RouterExtensionPlanEntry{{ID: vcp.RouterExtensionImageUnderstanding}}}
	inputs := []resource.MaterializedInput{
		{InputID: "image", ResourceID: "res_image", Kind: vcp.MediaImage},
		{InputID: "audio", ResourceID: "res_audio", Kind: vcp.MediaAudio},
	}
	filtered := withholdRouterManagedMedia(&request, plan, inputs)
	blocks := request.Payload.Conversation.Context[0].Content
	if len(filtered) != 1 || filtered[0].ResourceID != "res_audio" || blocks[0].Type != vcp.ContentText || blocks[0].ResourceRef != "" || blocks[1].Type != vcp.ContentAudio {
		t.Fatalf("filtered=%+v blocks=%+v", filtered, blocks)
	}
	if !strings.Contains(blocks[0].Text, "resource_ref=res_image") {
		t.Fatalf("opaque Router reference missing from provider prompt: %q", blocks[0].Text)
	}
}

// TestAuthorizedRouterMediaInputAllowsImmutableResourceReuse verifies repeated references do not create ambiguous authorization.
// TestAuthorizedRouterMediaInputAllowsImmutableResourceReuse 校验重复引用不会产生含糊授权。
func TestAuthorizedRouterMediaInputAllowsImmutableResourceReuse(t *testing.T) {
	parent := Record{Request: vcp.ExecutionRequest{Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{Context: []vcp.ContextItem{
		{Content: []vcp.ContentBlock{{Type: vcp.ContentImage, ResourceRef: "res_image"}}},
		{Content: []vcp.ContentBlock{{Type: vcp.ContentImage, ResourceRef: "res_image"}}},
	}}}}}
	media, errMedia := authorizedRouterMediaInput(parent, vcp.RouterExtensionImageUnderstanding, "res_image")
	if errMedia != nil || media.Kind != vcp.MediaImage || media.Role != vcp.MediaRoleUnderstanding || media.Resource.ResourceID != "res_image" {
		t.Fatalf("authorized media = %+v, error = %v", media, errMedia)
	}
	parent.Request.Payload.Conversation.Context[1].Content[0].Type = vcp.ContentAudio
	if _, errConflict := authorizedRouterMediaInput(parent, vcp.RouterExtensionImageUnderstanding, "res_image"); errConflict == nil {
		t.Fatal("conflicting media kinds unexpectedly authorized")
	}
}

// TestRouterExtensionChildRequestCreatesFrozenMediaInputPlan verifies delegated media is planned against the already frozen child target.
// TestRouterExtensionChildRequestCreatesFrozenMediaInputPlan 校验委托媒体按照已冻结的子 Target 创建输入方案。
func TestRouterExtensionChildRequestCreatesFrozenMediaInputPlan(t *testing.T) {
	now := time.Now().UTC()
	target := resolve.Target{
		ProviderDefinitionID: "definition_media",
		ProviderInstanceID:   "pvi_media",
		ProviderModelID:      "model_media",
		OfferingID:           "offering_media",
		ExecutionProfileID:   "profile_media",
		Operation:            vcp.OperationMediaAnalyze,
		EndpointID:           "endpoint_media",
		CredentialID:         "credential_media",
		ActionBindingID:      "action_media",
		CapabilityRevision:   3,
		CatalogRevision:      4,
	}
	binding := routertool.Binding{
		ID:                  "rtb_media",
		Extension:           vcp.RouterExtensionImageUnderstanding,
		ProviderInstanceID:  target.ProviderInstanceID,
		ProviderModelID:     target.ProviderModelID,
		OfferingID:          target.OfferingID,
		ExecutionProfileID:  target.ExecutionProfileID,
		Enabled:             true,
		TimeoutMilliseconds: 5000,
		MaximumCalls:        1,
		MaximumResultBytes:  65536,
		SafetyPolicy:        routertool.SafetyPublicHTTPSOnly,
		Revision:            1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	creator := &recordingInputPlanCreator{plan: inputplan.Plan{
		ID:                 "ipl_11111111111111111111111111111111",
		Accepted:           true,
		Operation:          target.Operation,
		Model:              vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: target.ProviderInstanceID, ProviderModelID: target.ProviderModelID, ExecutionProfileID: target.ExecutionProfileID},
		Target:             target,
		CapabilityRevision: target.CapabilityRevision,
		CatalogRevision:    target.CatalogRevision,
		Inputs:             []inputplan.PlannedInput{{InputID: "router_media", ResourceID: "res_image", Kind: vcp.MediaImage, Role: vcp.MediaRoleUnderstanding}},
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Hour),
		Revision:           1,
	}}
	service := &Service{plans: creator}
	parent := Record{
		ID:            "exe_parent",
		OwnerAPIKeyID: "api_owner",
		Request: vcp.ExecutionRequest{Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{Context: []vcp.ContextItem{{
			Content: []vcp.ContentBlock{{Type: vcp.ContentImage, ResourceRef: "res_image"}},
		}}}}},
	}
	call := routerToolCall{
		Output: vcp.OutputItem{ToolCall: &vcp.ToolCallItem{ToolCallID: "call_media", Arguments: `{"resource_ref":"res_image","task":"describe"}`, Status: vcp.ToolCallCompleted}},
		Plan: routerToolCallPlan{
			Extension:     vcp.RouterExtensionImageUnderstanding,
			RouterBinding: &routertool.ResolvedBinding{Binding: binding, Target: target},
		},
	}
	request, errRequest := service.routerToolChildRequest(context.Background(), parent, call, 1)
	if errRequest != nil {
		t.Fatalf("build media child request: %v", errRequest)
	}
	if request.InputPlanID != creator.plan.ID || request.Operation != vcp.OperationMediaAnalyze || request.Payload.MediaAnalyze == nil || len(request.Payload.MediaAnalyze.Inputs) != 1 {
		t.Fatalf("media child request = %+v", request)
	}
	if creator.request.OwnerAPIKeyID != parent.OwnerAPIKeyID || creator.request.Operation != target.Operation || creator.request.Model.ProviderInstanceID != target.ProviderInstanceID || len(creator.request.Inputs) != 1 || creator.request.Inputs[0].ResourceID != "res_image" || creator.request.Inputs[0].Role != vcp.MediaRoleUnderstanding {
		t.Fatalf("input planning request = %+v", creator.request)
	}
}

// TestRouterExtensionChildRequestBuildsExactImageGeneration verifies one extension call cannot change its frozen model target.
// TestRouterExtensionChildRequestBuildsExactImageGeneration 校验一个增强调用无法改变其冻结模型 Target。
func TestRouterExtensionChildRequestBuildsExactImageGeneration(t *testing.T) {
	now := time.Now().UTC()
	target := resolve.Target{
		ProviderDefinitionID: "definition_image",
		ProviderInstanceID:   "pvi_image",
		ProviderModelID:      "model_image",
		OfferingID:           "offering_image",
		ExecutionProfileID:   "profile_image",
		Operation:            vcp.OperationImageGenerate,
		EndpointID:           "endpoint_image",
		CredentialID:         "credential_image",
		ActionBindingID:      "action_image",
		CapabilityRevision:   3,
		CatalogRevision:      4,
	}
	binding := routertool.Binding{
		ID:                  "rtb_image",
		Extension:           vcp.RouterExtensionImageGeneration,
		ProviderInstanceID:  target.ProviderInstanceID,
		ProviderModelID:     target.ProviderModelID,
		OfferingID:          target.OfferingID,
		ExecutionProfileID:  target.ExecutionProfileID,
		Enabled:             true,
		TimeoutMilliseconds: 5000,
		MaximumCalls:        1,
		MaximumResultBytes:  65536,
		SafetyPolicy:        routertool.SafetyPublicHTTPSOnly,
		Revision:            1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	call := routerToolCall{
		Output: vcp.OutputItem{ToolCall: &vcp.ToolCallItem{ToolCallID: "call_image", Arguments: `{"prompt":"a blue volcano","count":2}`, Status: vcp.ToolCallCompleted}},
		Plan: routerToolCallPlan{
			Extension:     vcp.RouterExtensionImageGeneration,
			RouterBinding: &routertool.ResolvedBinding{Binding: binding, Target: target},
		},
	}
	request, errRequest := (&Service{}).routerToolChildRequest(context.Background(), Record{ID: "exe_parent"}, call, 1)
	if errRequest != nil {
		t.Fatalf("build image child request: %v", errRequest)
	}
	if request.Operation != vcp.OperationImageGenerate || request.Target.Model == nil || request.Target.Model.ProviderInstanceID != target.ProviderInstanceID || request.Target.Model.ProviderModelID != target.ProviderModelID || request.Target.Model.ExecutionProfileID != target.ExecutionProfileID || request.Payload.ImageGenerate == nil || request.Payload.ImageGenerate.Prompt != "a blue volcano" || request.Payload.ImageGenerate.Count != 2 {
		t.Fatalf("image child request = %+v", request)
	}
}

// TestModelToolPlanPublicAuditsExtensionBindingWithoutBackendSecrets verifies public records retain policy identity only.
// TestModelToolPlanPublicAuditsExtensionBindingWithoutBackendSecrets 校验公开记录只保留策略身份而不含后端秘密。
func TestModelToolPlanPublicAuditsExtensionBindingWithoutBackendSecrets(t *testing.T) {
	plan := ModelToolPlan{
		CatalogRevision: 9,
		RouterExtensions: []RouterExtensionPlanEntry{{
			ID:                    vcp.RouterExtensionImageGeneration,
			RouterBindingID:       "rtb_image",
			RouterBindingRevision: 3,
			RouterBinding: &routertool.ResolvedBinding{
				Binding: routertool.Binding{ID: "rtb_image", Revision: 3},
				Target:  resolve.Target{CredentialID: "credential_private", EndpointID: "endpoint_private"},
			},
		}},
	}
	public := plan.Public()
	if len(public.RouterExtensions) != 1 || public.RouterExtensions[0].ID != vcp.RouterExtensionImageGeneration || public.RouterExtensions[0].RouterBindingID != "rtb_image" || public.RouterExtensions[0].RouterBindingRevision != 3 {
		t.Fatalf("public Router extension plan = %+v", public.RouterExtensions)
	}
	encoded, errEncode := json.Marshal(public)
	if errEncode != nil {
		t.Fatalf("encode public model tool plan: %v", errEncode)
	}
	if strings.Contains(string(encoded), "credential_private") || strings.Contains(string(encoded), "endpoint_private") {
		t.Fatalf("public model tool plan leaked private target: %s", encoded)
	}
}

// TestApplyNativeModelToolDefinitionsMakesNewSelectionAuthoritative verifies native, Router, and disabled modes replace legacy search intent deterministically.
// TestApplyNativeModelToolDefinitionsMakesNewSelectionAuthoritative 校验原生、Router 与关闭模式会确定性替换旧搜索意图。
func TestApplyNativeModelToolDefinitionsMakesNewSelectionAuthoritative(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		mode       vcp.ModelToolMode
		wantSearch bool
	}{
		{name: "native", mode: vcp.ModelToolNative, wantSearch: true},
		{name: "router", mode: vcp.ModelToolRouter, wantSearch: false},
		{name: "disabled", mode: vcp.ModelToolDisabled, wantSearch: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := vcp.ExecutionRequest{
				Operation: vcp.OperationConversationRespond,
				Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{
					Tools:      []vcp.ToolDefinition{{Kind: vcp.ToolNativeWebSearch, Name: "legacy_search"}, {Kind: vcp.ToolFunction, Name: "caller_tool"}},
					ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: testCase.mode}}},
				}},
			}
			applyNativeModelToolDefinitions(&request)
			searchCount := 0
			for _, tool := range request.Payload.Conversation.Tools {
				if tool.Kind == vcp.ToolNativeWebSearch {
					searchCount++
					if tool.Name != "web_search" {
						t.Fatalf("normalized native search tool = %+v", tool)
					}
				}
			}
			if (searchCount == 1) != testCase.wantSearch || len(request.Payload.Conversation.Tools) != 1+searchCount {
				t.Fatalf("mode=%s tools=%+v", testCase.mode, request.Payload.Conversation.Tools)
			}
		})
	}
}

// TestApplyRouterToolDefinitionsRemapsOnlyRouterNamedSelection verifies native names remain public while frozen Router names become provider functions.
// TestApplyRouterToolDefinitionsRemapsOnlyRouterNamedSelection 校验原生名称保持公开形式，而冻结 Router 名称会转换为供应商函数。
func TestApplyRouterToolDefinitionsRemapsOnlyRouterNamedSelection(t *testing.T) {
	newRequest := func() vcp.ExecutionRequest {
		return vcp.ExecutionRequest{
			Operation: vcp.OperationConversationRespond,
			Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{
				ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceNamed, NamedTool: string(vcp.StandardModelToolWebSearch)},
			}},
		}
	}

	nativeRequest := newRequest()
	applyRouterToolDefinitions(&nativeRequest, ModelToolPlan{Standard: []ModelToolPlanEntry{{
		Kind: vcp.StandardModelToolWebSearch,
		Mode: vcp.ModelToolNative,
	}}})
	if nativeRequest.Payload.Conversation.ToolPolicy.NamedTool != string(vcp.StandardModelToolWebSearch) {
		t.Fatalf("native named tool was rewritten: %+v", nativeRequest.Payload.Conversation.ToolPolicy)
	}

	routerRequest := newRequest()
	applyRouterToolDefinitions(&routerRequest, ModelToolPlan{Standard: []ModelToolPlanEntry{{
		Kind:          vcp.StandardModelToolWebSearch,
		Mode:          vcp.ModelToolRouter,
		RouterBinding: &routertool.ResolvedBinding{Binding: routertool.Binding{ID: "rtb_search", Revision: 1}},
	}}})
	if routerRequest.Payload.Conversation.ToolPolicy.NamedTool != routerWebSearchName {
		t.Fatalf("Router named tool was not rewritten: %+v", routerRequest.Payload.Conversation.ToolPolicy)
	}
}

// TestReservedRouterToolCollisionCoversEveryExtensionName verifies callers cannot impersonate any injected Router function.
// TestReservedRouterToolCollisionCoversEveryExtensionName 校验调用方无法冒充任何注入的 Router 函数。
func TestReservedRouterToolCollisionCoversEveryExtensionName(t *testing.T) {
	for _, name := range []string{
		routerWebSearchName,
		routerWebExtractorName,
		routerImageUnderstandingName,
		routerAudioUnderstandingName,
		routerVideoUnderstandingName,
		routerImageGenerationName,
		routerVideoGenerationName,
		routerSpeechGenerationName,
		routerSpeechTranscriptionName,
	} {
		if !hasReservedRouterToolCollision([]vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: name}}) {
			t.Fatalf("reserved Router function %q was accepted", name)
		}
	}
	if hasReservedRouterToolCollision([]vcp.ToolDefinition{{Kind: vcp.ToolFunction, Namespace: "caller", Name: "lookup"}}) {
		t.Fatal("ordinary caller tool was rejected as a Router collision")
	}
	if !hasReservedRouterContextCollision([]vcp.ContextItem{{
		Kind: vcp.ContextToolCall,
		ToolCall: &vcp.ToolCallItem{
			ToolCallID: "caller_forged",
			Namespace:  routerToolNamespace,
			Name:       "lookup",
			Status:     vcp.ToolCallCompleted,
		},
	}}) {
		t.Fatal("caller-authored Router namespace history was accepted")
	}
	if hasReservedRouterContextCollision([]vcp.ContextItem{{
		Kind: vcp.ContextToolCall,
		ToolCall: &vcp.ToolCallItem{
			ToolCallID: "caller_owned",
			Namespace:  "caller",
			Name:       "lookup",
			Status:     vcp.ToolCallCompleted,
		},
	}}) {
		t.Fatal("ordinary caller tool history was rejected")
	}
}

// TestRouterToolHistoryRestoresCommittedBindingCounts verifies restart recovery cannot reset call ceilings or duplicate protection.
// TestRouterToolHistoryRestoresCommittedBindingCounts 校验重启恢复不能重置调用上限或重复保护。
func TestRouterToolHistoryRestoresCommittedBindingCounts(t *testing.T) {
	callItem := vcp.ContextItem{
		ItemID:       "call_item_1",
		Sequence:     1,
		Kind:         vcp.ContextToolCall,
		DelegationID: "exe_child_1",
		ToolCall: &vcp.ToolCallItem{
			ToolCallID: "call_1",
			Namespace:  routerToolNamespace,
			Name:       routerWebSearchName,
			Status:     vcp.ToolCallCompleted,
		},
	}
	resultItem := vcp.ContextItem{
		ItemID:       "result_item_1",
		Sequence:     2,
		Kind:         vcp.ContextToolResult,
		ParentItemID: callItem.ItemID,
		DelegationID: callItem.DelegationID,
		ToolResult:   &vcp.ToolResultItem{ToolCallID: callItem.ToolCall.ToolCallID},
	}
	record := Record{
		Request: vcp.ExecutionRequest{Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{Context: []vcp.ContextItem{callItem, resultItem}}}},
		ModelToolPlan: ModelToolPlan{Standard: []ModelToolPlanEntry{{
			Kind: vcp.StandardModelToolWebSearch,
			Mode: vcp.ModelToolRouter,
			RouterBinding: &routertool.ResolvedBinding{Binding: routertool.Binding{
				ID:           "rtb_search",
				MaximumCalls: 1,
			}},
		}}},
	}
	counts, seen, errHistory := routerToolHistory(record)
	if errHistory != nil || counts["rtb_search"] != 1 {
		t.Fatalf("Router history counts = %#v, error = %v", counts, errHistory)
	}
	if _, exists := seen["call_1"]; !exists {
		t.Fatalf("Router history did not restore call identity: %#v", seen)
	}
	record.Request.Payload.Conversation.Context = append(record.Request.Payload.Conversation.Context, callItem, resultItem)
	if _, _, errDuplicate := routerToolHistory(record); errDuplicate == nil {
		t.Fatal("Router history accepted a duplicate committed call")
	}
}

// TestMaximumAttemptBudgetsRemainGlobalAcrossRecovery verifies process restarts cannot replenish provider dispatch limits.
// TestMaximumAttemptBudgetsRemainGlobalAcrossRecovery 校验进程重启不能补充供应商分派上限。
func TestMaximumAttemptBudgetsRemainGlobalAcrossRecovery(t *testing.T) {
	record := Record{Attempts: make([]Attempt, 3)}
	if remaining := maximumCycleAttempts(record); remaining != maxSameProviderExecutionAttempts-3 {
		t.Fatalf("remaining ordinary attempts = %d", remaining)
	}
	record.ModelToolPlan = ModelToolPlan{Standard: []ModelToolPlanEntry{{
		Kind: vcp.StandardModelToolWebSearch,
		Mode: vcp.ModelToolRouter,
		RouterBinding: &routertool.ResolvedBinding{Binding: routertool.Binding{
			MaximumCalls: 4,
		}},
	}}}
	if remaining := maximumSynchronousCycleAttempts(record); remaining != maxSameProviderExecutionAttempts+4-3 {
		t.Fatalf("remaining Router parent dispatches = %d", remaining)
	}
	record.Attempts = make([]Attempt, maxSameProviderExecutionAttempts+4)
	if remaining := maximumSynchronousCycleAttempts(record); remaining != 0 {
		t.Fatalf("exhausted Router parent dispatches = %d", remaining)
	}
}

// TestRouterToolCallsRejectsUnplannedReservedFunction verifies a provider cannot synthesize private Router authority.
// TestRouterToolCallsRejectsUnplannedReservedFunction 校验供应商不能伪造私有 Router 权限。
func TestRouterToolCallsRejectsUnplannedReservedFunction(t *testing.T) {
	result := provider.ExecutionResult{Response: vcp.Response{Items: []vcp.OutputItem{{
		Kind: vcp.ContextToolCall,
		ToolCall: &vcp.ToolCallItem{
			ToolCallID: "call_unplanned",
			Name:       routerImageGenerationName,
			Status:     vcp.ToolCallCompleted,
		},
	}}}}
	if _, errCalls := routerToolCalls(result, ModelToolPlan{}); stableFailureCode(errCalls) != string(vcp.RouterToolResultInvalid) {
		t.Fatalf("unplanned reserved tool error = %v", errCalls)
	}
}

// TestModelToolAdmissionEventsPublishEnabledAndFrozenModes verifies the parent audit stream distinguishes disabled selections from enabled tools.
// TestModelToolAdmissionEventsPublishEnabledAndFrozenModes 校验父执行审计流会区分禁用选择和已启用工具。
func TestModelToolAdmissionEventsPublishEnabledAndFrozenModes(t *testing.T) {
	events := modelToolAdmissionEvents(ModelToolPlan{
		Standard: []ModelToolPlanEntry{
			{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolDisabled},
			{Kind: vcp.StandardModelToolWebExtractor, Mode: vcp.ModelToolRouter},
		},
		Extra: []string{"code_interpreter"},
		RouterExtensions: []RouterExtensionPlanEntry{{
			ID: vcp.RouterExtensionImageUnderstanding,
		}},
	})
	if len(events) != 7 {
		t.Fatalf("admission event count = %d, want 7: %#v", len(events), events)
	}
	if events[0].Stage != ModelToolStageModeFrozen || events[0].Mode != vcp.ModelToolDisabled {
		t.Fatalf("disabled selection event = %#v", events[0])
	}
	for _, event := range events {
		durable := Event{ExecutionID: "exe_0123456789abcdef0123456789abcdef", EventID: "evt_0123456789abcdef0123456789abcdef_1", Sequence: 1, Time: time.Unix(1, 0).UTC(), Type: EventModelToolLifecycle, ModelTool: &event}
		if errValidate := durable.Validate(); errValidate != nil {
			t.Fatalf("admission event %#v is invalid: %v", event, errValidate)
		}
	}
}

// TestModelToolLifecycleEventRejectsLeakedCallState verifies admission events cannot carry call or child identifiers.
// TestModelToolLifecycleEventRejectsLeakedCallState 校验接收事件不能携带调用或子执行标识。
func TestModelToolLifecycleEventRejectsLeakedCallState(t *testing.T) {
	payload := ModelToolEvent{ToolID: string(vcp.StandardModelToolWebSearch), Stage: ModelToolStageEnabled, Mode: vcp.ModelToolNative, ToolCallID: "call_private"}
	event := Event{ExecutionID: "exe_0123456789abcdef0123456789abcdef", EventID: "evt_0123456789abcdef0123456789abcdef_1", Sequence: 1, Time: time.Unix(1, 0).UTC(), Type: EventModelToolLifecycle, ModelTool: &payload}
	if errValidate := event.Validate(); errValidate == nil {
		t.Fatal("admission event with call state unexpectedly validated")
	}
}

// routerLoopProviderExecutor emits one Router tool call, one child result, and one final parent response.
// routerLoopProviderExecutor 依次发出一个 Router 工具调用、一个子结果与一个最终父响应。
type routerLoopProviderExecutor struct {
	// requests records all provider-bound parent and child requests.
	// requests 记录全部供应商绑定的父请求与子请求。
	requests []provider.ExecutionRequest
}

// Execute returns deterministic typed results for the three expected dispatches.
// Execute 为三个预期分派返回确定性类型化结果。
func (e *routerLoopProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.requests = append(e.requests, request)
	switch len(e.requests) {
	case 1:
		if request.Execution == nil || request.Execution.Operation != vcp.OperationConversationRespond || len(request.Execution.Payload.Conversation.Tools) != 1 || request.Execution.Payload.Conversation.Tools[0].Name != routerWebSearchName || request.Execution.Payload.Conversation.Tools[0].Strict {
			return provider.ExecutionResult{}, fmt.Errorf("Router search function was not injected")
		}
		return canonicalConversationResult(vcp.Response{ResponseID: "response_tool", Status: vcp.ResponseCompleted, Items: []vcp.OutputItem{{ItemID: "tool_item", Kind: vcp.ContextToolCall, Status: vcp.OutputItemCompleted, ToolCall: &vcp.ToolCallItem{ToolCallID: "call_search", UpstreamID: "upstream_search", Name: routerWebSearchName, Arguments: `{"query":"OpenVulcan","max_results":2}`, Status: vcp.ToolCallCompleted}}}}, request.Now), nil
	case 2:
		if request.Execution == nil || request.Execution.Operation != vcp.OperationSearchWeb || request.Execution.Payload.SearchWeb == nil || request.Execution.Payload.SearchWeb.Query != "OpenVulcan" || *request.Execution.Payload.SearchWeb.MaxResults != 2 {
			return provider.ExecutionResult{}, fmt.Errorf("Router search child request differs from tool arguments")
		}
		return provider.ExecutionResult{Search: &vcp.WebSearchResponse{Query: "OpenVulcan", Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}}, Results: []vcp.WebSearchResult{{ID: "result_1", Rank: 1, Title: "OpenVulcan", URL: "https://openvulcan.example"}}}}, nil
	case 3:
		conversation := request.Execution.Payload.Conversation
		if request.Execution.Operation != vcp.OperationConversationRespond || len(conversation.Context) != 2 || conversation.Context[0].ToolCall == nil || conversation.Context[1].ToolResult == nil || conversation.Context[1].DelegationID == "" {
			return provider.ExecutionResult{}, fmt.Errorf("Router tool result was not reinjected into canonical context")
		}
		if request.Execution.IdempotencyKey == e.requests[0].Execution.IdempotencyKey {
			return provider.ExecutionResult{}, fmt.Errorf("semantic parent rounds reused one upstream idempotency key")
		}
		return canonicalConversationResult(vcp.Response{ResponseID: "response_final", Status: vcp.ResponseCompleted}, request.Now), nil
	default:
		return provider.ExecutionResult{}, fmt.Errorf("unexpected provider dispatch %d", len(e.requests))
	}
}

// partialFailureRouterLoopProviderExecutor returns two Router calls, succeeds the first child, and fails the second child.
// partialFailureRouterLoopProviderExecutor 返回两个 Router 调用，使第一个子执行成功并使第二个子执行失败。
type partialFailureRouterLoopProviderExecutor struct {
	// requests records every parent and child provider dispatch.
	// requests 记录每次父级及子级供应商分派。
	requests []provider.ExecutionRequest
}

// Execute returns deterministic parent calls and query-specific child outcomes.
// Execute 返回确定性的父级调用以及按查询区分的子执行结果。
func (e *partialFailureRouterLoopProviderExecutor) Execute(_ context.Context, request provider.ExecutionRequest) (provider.ExecutionResult, error) {
	e.requests = append(e.requests, request)
	if request.Execution == nil {
		return provider.ExecutionResult{}, fmt.Errorf("execution request is required")
	}
	if request.Execution.Operation == vcp.OperationConversationRespond {
		return canonicalConversationResult(vcp.Response{ResponseID: "response_partial_failure", Status: vcp.ResponseCompleted, Items: []vcp.OutputItem{
			{ItemID: "tool_success", Kind: vcp.ContextToolCall, Status: vcp.OutputItemCompleted, ToolCall: &vcp.ToolCallItem{ToolCallID: "call_success", UpstreamID: "upstream_success", Name: routerWebSearchName, Arguments: `{"query":"success","max_results":1}`, Status: vcp.ToolCallCompleted}},
			{ItemID: "tool_failure", Kind: vcp.ContextToolCall, Status: vcp.OutputItemCompleted, ToolCall: &vcp.ToolCallItem{ToolCallID: "call_failure", UpstreamID: "upstream_failure", Name: routerWebSearchName, Arguments: `{"query":"failure","max_results":1}`, Status: vcp.ToolCallCompleted}},
		}}, request.Now), nil
	}
	if request.Execution.Operation != vcp.OperationSearchWeb || request.Execution.Payload.SearchWeb == nil {
		return provider.ExecutionResult{}, fmt.Errorf("unexpected Router child operation")
	}
	if request.Execution.Payload.SearchWeb.Query == "success" {
		return provider.ExecutionResult{Search: &vcp.WebSearchResponse{Query: "success", Evidence: vcp.SearchExecutionEvidence{Status: vcp.SearchExecutionConfirmed, Kinds: []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult}}, Results: []vcp.WebSearchResult{{ID: "result_1", Rank: 1, Title: "success", URL: "https://example.com/success"}}}}, nil
	}
	return provider.ExecutionResult{}, fmt.Errorf("intentional Router child failure")
}

// TestValidatePublicHTTPSURLRejectsPrivateDestinations verifies the Router never forwards obvious local extraction targets.
// TestValidatePublicHTTPSURLRejectsPrivateDestinations 验证 Router 绝不转发明显的本地抓取目标。
func TestValidatePublicHTTPSURLRejectsPrivateDestinations(t *testing.T) {
	for _, rawURL := range []string{
		"http://example.com",
		"https://localhost/admin",
		"https://127.0.0.1/private",
		"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.1/internal",
	} {
		if errValidate := validatePublicHTTPSURL(context.Background(), rawURL); errValidate == nil {
			t.Fatalf("validatePublicHTTPSURL(%q) unexpectedly succeeded", rawURL)
		}
	}
	if errValidate := validatePublicHTTPSURL(context.Background(), "https://8.8.8.8/public"); errValidate != nil {
		t.Fatalf("validate public address: %v", errValidate)
	}
}

// TestSerializeRouterExtractResultUsesLeastPrivilegeEnvelope verifies provider diagnostics and usage never cross into another model.
// TestSerializeRouterExtractResultUsesLeastPrivilegeEnvelope 验证供应商诊断与用量绝不会跨越到另一个模型。
func TestSerializeRouterExtractResultUsesLeastPrivilegeEnvelope(t *testing.T) {
	credits := 2.0
	result := Result{Extract: &vcp.WebExtractResponse{
		Results:           []vcp.WebExtractResult{{URL: "https://example.com", RawContent: "external page"}},
		ProviderRequestID: "provider-secret-support-id",
		Usage:             &vcp.UsageObservation{ServiceUnits: &credits, ServiceUnit: "credits", Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "provider_private", Final: true},
	}}
	serialized, errSerialize := serializeRouterToolResult(routerToolCallPlan{Standard: vcp.StandardModelToolWebExtractor}, result, 65536)
	if errSerialize != nil {
		t.Fatalf("serializeRouterToolResult() error = %v", errSerialize)
	}
	if !strings.Contains(serialized, `"external_content_untrusted":true`) || !strings.Contains(serialized, "external page") || strings.Contains(serialized, "provider-secret-support-id") || strings.Contains(serialized, "provider_private") {
		t.Fatalf("least-privilege extract result = %s", serialized)
	}
}

// TestSerializeRouterExtensionResultsExposeOnlyModelRequiredFields verifies extension children cannot leak response, usage, hash, or lifecycle metadata into the parent model.
// TestSerializeRouterExtensionResultsExposeOnlyModelRequiredFields 校验增强能力子执行无法向父模型泄露响应、用量、哈希或生命周期元数据。
func TestSerializeRouterExtensionResultsExposeOnlyModelRequiredFields(t *testing.T) {
	credits := 3.0
	analysis := Result{Analysis: &vcp.Response{
		ResponseID: "child-response-private",
		Status:     vcp.ResponseCompleted,
		Items:      []vcp.OutputItem{{Content: []vcp.ContentBlock{{Type: vcp.ContentText, Text: "observed media text"}}}},
		Usage:      &vcp.UsageObservation{ServiceUnits: &credits, ServiceUnit: "credits", Source: "provider_reported", Aggregation: "snapshot", Phase: "terminal", AccountingBasis: "provider_private", Final: true},
	}}
	serializedAnalysis, errAnalysis := serializeRouterToolResult(routerToolCallPlan{Extension: vcp.RouterExtensionImageUnderstanding}, analysis, 65536)
	if errAnalysis != nil {
		t.Fatalf("serialize analysis result: %v", errAnalysis)
	}
	if !strings.Contains(serializedAnalysis, `"external_content_untrusted":true`) || !strings.Contains(serializedAnalysis, "observed media text") || strings.Contains(serializedAnalysis, "child-response-private") || strings.Contains(serializedAnalysis, "provider_private") {
		t.Fatalf("least-privilege analysis result = %s", serializedAnalysis)
	}

	generated := Result{Resources: []resource.Resource{{
		ID: "res_public", Kind: vcp.MediaImage, MIMEType: "image/png", SizeBytes: 128,
		SHA256: "private-content-digest", ObjectKey: "private/object/path",
	}}}
	serializedGenerated, errGenerated := serializeRouterToolResult(routerToolCallPlan{Extension: vcp.RouterExtensionImageGeneration}, generated, 65536)
	if errGenerated != nil {
		t.Fatalf("serialize generated result: %v", errGenerated)
	}
	if !strings.Contains(serializedGenerated, `"resource_ref":"res_public"`) || !strings.Contains(serializedGenerated, `"mime_type":"image/png"`) || strings.Contains(serializedGenerated, "private-content-digest") || strings.Contains(serializedGenerated, "private/object/path") {
		t.Fatalf("least-privilege generated result = %s", serializedGenerated)
	}

	transcript := Result{Transcript: &vcp.Transcript{Candidates: []vcp.TranscriptCandidate{{CandidateID: "candidate-1", Text: "spoken external text"}}}}
	serializedTranscript, errTranscript := serializeRouterToolResult(routerToolCallPlan{Extension: vcp.RouterExtensionSpeechTranscription}, transcript, 65536)
	if errTranscript != nil {
		t.Fatalf("serialize transcript result: %v", errTranscript)
	}
	if !strings.Contains(serializedTranscript, `"external_content_untrusted":true`) || !strings.Contains(serializedTranscript, "spoken external text") {
		t.Fatalf("least-privilege transcript result = %s", serializedTranscript)
	}
}

// TestServiceExecutesRouterToolThroughDurableChild verifies the complete frozen child-execution loop.
// TestServiceExecutesRouterToolThroughDurableChild 验证完整的冻结子执行循环。
func TestServiceExecutesRouterToolThroughDurableChild(t *testing.T) {
	now := time.Now().UTC()
	modelCapabilities := conversationTestCapabilities(true, false)
	modelCapabilities.ToolCalling = catalog.CapabilityNative
	modelCapabilities.StrictJSONSchema = catalog.CapabilityNative
	parentTarget := resolve.Target{ProviderDefinitionID: "definition_model", ProviderInstanceID: "pvi_model", ChannelID: "channel_model", EndpointID: "endpoint_model", EndpointRegion: "region_model", CredentialID: "credential_model", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_parent", OfferingID: "offering_model", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_model", ExecutionProfileID: "profile_model", UpstreamModelID: "upstream_model", ModelCapabilities: modelCapabilities, CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 7}
	serviceCapabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{}}
	childTarget := resolve.Target{ProviderDefinitionID: "definition_search", ProviderInstanceID: "pvi_search", ChannelID: "channel_search", EndpointID: "endpoint_search", EndpointRegion: "region_search", CredentialID: "credential_search", SubjectKind: resolve.ExecutionSubjectService, ProviderServiceID: "search.web", ServiceOfferingID: "offering_search", Operation: vcp.OperationSearchWeb, ActionBindingID: "action_search", ExecutionProfileID: "profile_search", UpstreamServiceID: "search", ServiceCapabilities: &serviceCapabilities, CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 3}
	binding := routertool.Binding{ID: "rtb_search", Kind: vcp.StandardModelToolWebSearch, ProviderInstanceID: childTarget.ProviderInstanceID, ProviderServiceID: childTarget.ProviderServiceID, ServiceOfferingID: childTarget.ServiceOfferingID, ExecutionProfileID: childTarget.ExecutionProfileID, Priority: 0, Enabled: true, TimeoutMilliseconds: 5000, MaximumCalls: 2, MaximumResults: 5, MaximumURLs: 1, MaximumResultBytes: 65536, SafetyPolicy: routertool.SafetyPublicHTTPSOnly, Revision: 1, CreatedAt: now, UpdatedAt: now}
	// alternateChildTarget proves the Router child does not re-resolve onto another endpoint or credential.
	// alternateChildTarget 证明 Router 子执行不会重新解析到其他端点或凭据。
	alternateChildTarget := childTarget
	alternateChildTarget.EndpointID = "endpoint_search_alternate"
	alternateChildTarget.CredentialID = "credential_search_alternate"
	resolver := &operationTargetResolver{model: parentTarget, service: alternateChildTarget}
	configurations := multiConfigurations{
		definition: providerconfig.ProviderDefinition{ID: parentTarget.ProviderDefinitionID},
		endpoints: []providerconfig.Endpoint{
			{ID: parentTarget.EndpointID, ProviderInstanceID: parentTarget.ProviderInstanceID, ChannelID: parentTarget.ChannelID, BaseURL: "https://model.example", Region: parentTarget.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
			{ID: childTarget.EndpointID, ProviderInstanceID: childTarget.ProviderInstanceID, ChannelID: childTarget.ChannelID, BaseURL: "https://search.example", Region: childTarget.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		},
		credentials: []providerconfig.Credential{
			{ID: parentTarget.CredentialID, ProviderInstanceID: parentTarget.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
			{ID: childTarget.CredentialID, ProviderInstanceID: childTarget.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
		},
	}
	executor := &routerLoopProviderExecutor{}
	identifiers := []string{"exe_11111111111111111111111111111111", "exe_22222222222222222222222222222222"}
	identifierIndex := 0
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) {
		identifier := identifiers[identifierIndex]
		identifierIndex++
		return identifier, nil
	}, Now: func() time.Time { return now }, Retention: time.Hour, ModelTools: staticModelToolResolver{resolved: routertool.ResolvedBinding{Binding: binding, Target: childTarget}}})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_router_tool", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: parentTarget.ProviderInstanceID, ProviderModelID: parentTarget.ProviderModelID, ExecutionProfileID: parentTarget.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolRouter}}}, ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceAuto}}}}
	record, replayed, errCreate := service.Create(context.Background(), "api_router", request)
	if errCreate != nil || replayed || record.Status != StatusSucceeded || record.CompletedRouterToolRounds != 1 || record.Result == nil || record.Result.Conversation == nil || len(executor.requests) != 3 {
		t.Fatalf("status=%s failure=%+v replayed=%t requests=%d error=%v", record.Status, record.Failure, replayed, len(executor.requests), errCreate)
	}
	child, errChild := service.Get(context.Background(), "api_router", identifiers[1])
	if errChild != nil || child.Status != StatusSucceeded || child.RouterToolLineage == nil || child.RouterToolLineage.ParentExecutionID != record.ID || child.Result == nil || child.Result.Search == nil {
		t.Fatalf("child=%+v error=%v", child, errChild)
	}
	parentEvents, errEvents := service.Events(context.Background(), "api_router", record.ID, 0)
	if errEvents != nil {
		t.Fatalf("parent events: %v", errEvents)
	}
	stages := make([]ModelToolEventStage, 0, 7)
	for _, event := range parentEvents {
		if event.ModelTool != nil {
			stages = append(stages, event.ModelTool.Stage)
		}
	}
	wantStages := []ModelToolEventStage{ModelToolStageEnabled, ModelToolStageModeFrozen, ModelToolStageRouterCallStarted, ModelToolStageChildCreated, ModelToolStageChildCompleted, ModelToolStageResultInjected, ModelToolStageParentResumed}
	if !reflect.DeepEqual(stages, wantStages) {
		t.Fatalf("parent model tool stages = %#v, want %#v", stages, wantStages)
	}
}

// TestRouterToolBatchFailureDoesNotPublishUncommittedInjection verifies a later child failure cannot publish an earlier uncommitted parent resume.
// TestRouterToolBatchFailureDoesNotPublishUncommittedInjection 验证后续子执行失败不能发布先前尚未提交的父级恢复事件。
func TestRouterToolBatchFailureDoesNotPublishUncommittedInjection(t *testing.T) {
	now := time.Now().UTC()
	modelCapabilities := conversationTestCapabilities(true, false)
	modelCapabilities.ToolCalling = catalog.CapabilityNative
	modelCapabilities.StrictJSONSchema = catalog.CapabilityNative
	parentTarget := resolve.Target{ProviderDefinitionID: "definition_batch_model", ProviderInstanceID: "pvi_batch_model", ChannelID: "channel_batch_model", EndpointID: "endpoint_batch_model", EndpointRegion: "region_batch_model", CredentialID: "credential_batch_model", SubjectKind: resolve.ExecutionSubjectModel, ProviderModelID: "model_batch_parent", OfferingID: "offering_batch_model", Operation: vcp.OperationConversationRespond, ActionBindingID: "action_batch_model", ExecutionProfileID: "profile_batch_model", UpstreamModelID: "upstream_batch_model", ModelCapabilities: modelCapabilities, CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 7}
	serviceCapabilities := catalog.ServiceCapabilities{WebSearch: &catalog.WebSearchCapabilities{}}
	childTarget := resolve.Target{ProviderDefinitionID: "definition_batch_search", ProviderInstanceID: "pvi_batch_search", ChannelID: "channel_batch_search", EndpointID: "endpoint_batch_search", EndpointRegion: "region_batch_search", CredentialID: "credential_batch_search", SubjectKind: resolve.ExecutionSubjectService, ProviderServiceID: "search.web", ServiceOfferingID: "offering_batch_search", Operation: vcp.OperationSearchWeb, ActionBindingID: "action_batch_search", ExecutionProfileID: "profile_batch_search", UpstreamServiceID: "search", ServiceCapabilities: &serviceCapabilities, CapabilityRevision: 1, ProviderConfigRevision: 1, CatalogRevision: 3}
	binding := routertool.Binding{ID: "rtb_batch_search", Kind: vcp.StandardModelToolWebSearch, ProviderInstanceID: childTarget.ProviderInstanceID, ProviderServiceID: childTarget.ProviderServiceID, ServiceOfferingID: childTarget.ServiceOfferingID, ExecutionProfileID: childTarget.ExecutionProfileID, Enabled: true, TimeoutMilliseconds: 5000, MaximumCalls: 2, MaximumResults: 5, MaximumURLs: 1, MaximumResultBytes: 65536, SafetyPolicy: routertool.SafetyPublicHTTPSOnly, Revision: 1, CreatedAt: now, UpdatedAt: now}
	resolver := &operationTargetResolver{model: parentTarget, service: childTarget}
	configurations := multiConfigurations{
		definition: providerconfig.ProviderDefinition{ID: parentTarget.ProviderDefinitionID},
		endpoints: []providerconfig.Endpoint{
			{ID: parentTarget.EndpointID, ProviderInstanceID: parentTarget.ProviderInstanceID, ChannelID: parentTarget.ChannelID, BaseURL: "https://model.example", Region: parentTarget.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
			{ID: childTarget.EndpointID, ProviderInstanceID: childTarget.ProviderInstanceID, ChannelID: childTarget.ChannelID, BaseURL: "https://search.example", Region: childTarget.EndpointRegion, Status: providerconfig.EndpointReady, Revision: 1},
		},
		credentials: []providerconfig.Credential{
			{ID: parentTarget.CredentialID, ProviderInstanceID: parentTarget.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
			{ID: childTarget.CredentialID, ProviderInstanceID: childTarget.ProviderInstanceID, Status: providerconfig.CredentialActive, Revision: 1},
		},
	}
	executor := &partialFailureRouterLoopProviderExecutor{}
	identifiers := []string{"exe_33333333333333333333333333333333", "exe_44444444444444444444444444444444", "exe_55555555555555555555555555555555"}
	identifierIndex := 0
	service, errService := NewService(NewMemoryStore(), resolver, configurations, nil, nil, executor, ServiceOptions{NewID: func() (string, error) {
		identifier := identifiers[identifierIndex]
		identifierIndex++
		return identifier, nil
	}, Now: func() time.Time { return now }, Retention: time.Hour, ModelTools: staticModelToolResolver{resolved: routertool.ResolvedBinding{Binding: binding, Target: childTarget}}})
	if errService != nil {
		t.Fatalf("create service: %v", errService)
	}
	request := vcp.ExecutionRequest{ProtocolVersion: vcp.ProtocolVersion, RequestID: "request_router_batch_failure", Target: vcp.TargetSelection{Model: &vcp.ModelSelection{Target: vcp.ModelTargetExact, ProviderInstanceID: parentTarget.ProviderInstanceID, ProviderModelID: parentTarget.ProviderModelID, ExecutionProfileID: parentTarget.ExecutionProfileID}}, Operation: vcp.OperationConversationRespond, Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{ModelTools: vcp.ModelToolSelection{Standard: []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolRouter}}}, ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceAuto}}}}
	record, replayed, errCreate := service.Create(context.Background(), "api_router_batch_failure", request)
	if errCreate != nil || replayed || record.Status != StatusFailed {
		t.Fatalf("status=%s replayed=%t error=%v", record.Status, replayed, errCreate)
	}
	parentEvents, errEvents := service.Events(context.Background(), "api_router_batch_failure", record.ID, 0)
	if errEvents != nil {
		t.Fatalf("parent events: %v", errEvents)
	}
	for _, event := range parentEvents {
		if event.ModelTool != nil && (event.ModelTool.Stage == ModelToolStageResultInjected || event.ModelTool.Stage == ModelToolStageParentResumed) {
			t.Fatalf("uncommitted model tool stage was published: %+v", event.ModelTool)
		}
	}
}

// TestApplyProviderToolChoiceRemovesAllTools verifies choice none is authoritative at the provider boundary.
// TestApplyProviderToolChoiceRemovesAllTools 验证 choice none 在供应商边界具有权威性。
func TestApplyProviderToolChoiceRemovesAllTools(t *testing.T) {
	request := vcp.ExecutionRequest{
		Operation: vcp.OperationConversationRespond,
		Payload: vcp.OperationPayload{Conversation: &vcp.ConversationOperation{
			Tools:      []vcp.ToolDefinition{{Kind: vcp.ToolFunction, Name: "lookup"}},
			ToolPolicy: vcp.ToolPolicy{Choice: vcp.ToolChoiceNone},
			ModelTools: vcp.ModelToolSelection{
				Standard:         []vcp.StandardModelToolSelection{{Kind: vcp.StandardModelToolWebSearch, Mode: vcp.ModelToolNative}},
				Extra:            []string{"code_interpreter"},
				RouterExtensions: []vcp.RouterExtensionKind{vcp.RouterExtensionImageGeneration},
			},
		}},
	}
	applyProviderToolChoice(&request)
	conversation := request.Payload.Conversation
	if len(conversation.Tools) != 0 || len(conversation.ModelTools.Standard) != 0 || len(conversation.ModelTools.Extra) != 0 || len(conversation.ModelTools.RouterExtensions) != 0 {
		t.Fatalf("provider-facing tools survived choice none: %+v", conversation)
	}
}

// TestRouterUnderstandingDefinitionExcludesUnsupportedModeration verifies Router never advertises a media task rejected by every implemented analysis adapter.
// TestRouterUnderstandingDefinitionExcludesUnsupportedModeration 校验 Router 绝不声明每个已实现分析适配器均拒绝的媒体任务。
func TestRouterUnderstandingDefinitionExcludesUnsupportedModeration(t *testing.T) {
	_, _, schema := routerExtensionDefinition(vcp.RouterExtensionImageUnderstanding)
	if strings.Contains(string(schema), `"moderate"`) {
		t.Fatalf("Router understanding schema advertises unsupported moderation: %s", schema)
	}
	for _, task := range []string{"describe", "summarize", "question_answer", "extract"} {
		if !strings.Contains(string(schema), `"`+task+`"`) {
			t.Fatalf("Router understanding schema omits supported task %q: %s", task, schema)
		}
	}
}

// TestExecuteRouterToolCallBatchBoundsParallelismAndPreservesOrder verifies one provider round cannot create unbounded children or reorder results.
// TestExecuteRouterToolCallBatchBoundsParallelismAndPreservesOrder 校验单个供应商轮次无法创建无界子执行或重排结果。
func TestExecuteRouterToolCallBatchBoundsParallelismAndPreservesOrder(t *testing.T) {
	calls := make([]routerToolCall, maximumParallelRouterToolChildren+3)
	entered := make(chan struct{}, len(calls))
	release := make(chan struct{})
	done := make(chan []routerToolCallResult, 1)
	go func() {
		done <- executeRouterToolCallBatch(calls, true, func(index int, _ routerToolCall) routerToolCallResult {
			entered <- struct{}{}
			<-release
			return routerToolCallResult{ModelResult: fmt.Sprintf("result-%d", index)}
		})
	}()
	for range maximumParallelRouterToolChildren {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("parallel Router tool worker did not start")
		}
	}
	select {
	case <-entered:
		t.Fatalf("more than %d Router tool children started concurrently", maximumParallelRouterToolChildren)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	var results []routerToolCallResult
	select {
	case results = <-done:
	case <-time.After(time.Second):
		t.Fatal("parallel Router tool batch did not finish")
	}
	for index, result := range results {
		if result.ModelResult != fmt.Sprintf("result-%d", index) {
			t.Fatalf("result[%d] = %q", index, result.ModelResult)
		}
	}
}

// TestProviderDispatchIdempotencyKeyChangesAfterDurableRouterRound verifies retries remain stable while semantic rounds differ.
// TestProviderDispatchIdempotencyKeyChangesAfterDurableRouterRound 验证重试保持稳定且不同语义轮次使用不同身份。
func TestProviderDispatchIdempotencyKeyChangesAfterDurableRouterRound(t *testing.T) {
	record := Record{ID: "exe_parent"}
	if got := providerDispatchIdempotencyKey(record); got != record.ID {
		t.Fatalf("initial key = %q, want %q", got, record.ID)
	}
	record.CompletedRouterToolRounds = 1
	firstCompletedRound := providerDispatchIdempotencyKey(record)
	if firstCompletedRound == record.ID || firstCompletedRound != providerDispatchIdempotencyKey(record) {
		t.Fatalf("completed round key is not distinct and stable: %q", firstCompletedRound)
	}
	record.CompletedRouterToolRounds = 2
	if next := providerDispatchIdempotencyKey(record); next == firstCompletedRound {
		t.Fatalf("different completed rounds reused key %q", next)
	}
}

// TestExecutionDeadlineAppliesHardRouterParentCeiling verifies callers cannot create an unbounded Router tool loop.
// TestExecutionDeadlineAppliesHardRouterParentCeiling 校验调用方不能创建无界 Router 工具循环。
func TestExecutionDeadlineAppliesHardRouterParentCeiling(t *testing.T) {
	createdAt := time.Now().UTC()
	binding := routertool.Binding{MaximumCalls: 1}
	routerRecord := Record{
		CreatedAt: createdAt,
		ModelToolPlan: ModelToolPlan{Standard: []ModelToolPlanEntry{{
			Kind:          vcp.StandardModelToolWebSearch,
			Mode:          vcp.ModelToolRouter,
			RouterBinding: &routertool.ResolvedBinding{Binding: binding},
		}}},
	}
	deadline, bounded := executionDeadline(routerRecord)
	if !bounded || !deadline.Equal(createdAt.Add(maximumRouterParentExecutionDuration)) {
		t.Fatalf("Router parent deadline = %v bounded=%t", deadline, bounded)
	}

	shorterMilliseconds := int64(1_000)
	routerRecord.Request.Budget.MaxExecutionMilliseconds = &shorterMilliseconds
	shorterDeadline, shorterBounded := executionDeadline(routerRecord)
	if !shorterBounded || !shorterDeadline.Equal(createdAt.Add(time.Second)) {
		t.Fatalf("short caller deadline = %v bounded=%t", shorterDeadline, shorterBounded)
	}

	unbounded := Record{CreatedAt: createdAt}
	if unboundedDeadline, isBounded := executionDeadline(unbounded); isBounded || !unboundedDeadline.IsZero() {
		t.Fatalf("ordinary execution unexpectedly bounded: %v bounded=%t", unboundedDeadline, isBounded)
	}
}
