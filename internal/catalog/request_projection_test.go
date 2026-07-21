package catalog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestRequestProjectionValidationRejectsProtectedPaths verifies configuration cannot replace protocol-owned request content.
// TestRequestProjectionValidationRejectsProtectedPaths 验证配置不能替换协议拥有的请求内容。
func TestRequestProjectionValidationRejectsProtectedPaths(t *testing.T) {
	projection := RequestProjection{Reasoning: ReasoningRequestProjection{Effort: []ReasoningParameterRule{{Value: "high", Set: []PayloadParameter{{Path: "model", Value: json.RawMessage(`"other"`)}}}}}}
	if errValidate := projection.Validate(); errValidate == nil {
		t.Fatal("RequestProjection.Validate() accepted a protected model path")
	}
}

// TestRequestProjectionValidationRejectsOverlappingReasoningPaths verifies effort and summary cannot overwrite each other.
// TestRequestProjectionValidationRejectsOverlappingReasoningPaths 验证强度与摘要不能相互覆盖。
func TestRequestProjectionValidationRejectsOverlappingReasoningPaths(t *testing.T) {
	projection := RequestProjection{Reasoning: ReasoningRequestProjection{
		Effort:  []ReasoningParameterRule{{Value: "high", Set: []PayloadParameter{{Path: "reasoning", Value: json.RawMessage(`{"effort":"high"}`)}}}},
		Summary: []ReasoningParameterRule{{Value: "auto", Set: []PayloadParameter{{Path: "reasoning.summary", Value: json.RawMessage(`"auto"`)}}}},
	}}
	if errValidate := projection.Validate(); errValidate == nil {
		t.Fatal("RequestProjection.Validate() accepted overlapping effort and summary paths")
	}
}

// TestCloneRequestProjectionDeepCopiesRawValues verifies catalog snapshots cannot share mutable JSON bytes.
// TestCloneRequestProjectionDeepCopiesRawValues 验证目录快照不会共享可变 JSON 字节。
func TestCloneRequestProjectionDeepCopiesRawValues(t *testing.T) {
	original := RequestProjection{Reasoning: ReasoningRequestProjection{Effort: []ReasoningParameterRule{{Value: "high", Set: []PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}}}}}
	cloned := CloneRequestProjection(original)
	cloned.Reasoning.Effort[0].Set[0].Value[1] = 'x'
	if string(original.Reasoning.Effort[0].Set[0].Value) != `"high"` {
		t.Fatalf("original raw value was mutated: %s", original.Reasoning.Effort[0].Set[0].Value)
	}
}

// TestSnapshotRejectsProviderAdditionalReasoningConflicts verifies separate configuration levels cannot own the same path.
// TestSnapshotRejectsProviderAdditionalReasoningConflicts 验证不同配置层级不能拥有同一路径。
func TestSnapshotRejectsProviderAdditionalReasoningConflicts(t *testing.T) {
	now := time.Now().UTC()
	snapshot := Snapshot{
		ProviderInstanceID:          "pvi_projection",
		DefaultAdditionalParameters: AdditionalPayloadProjection{Override: []PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}},
		Models:                      []ProviderModel{{ID: "model_projection", ProviderInstanceID: "pvi_projection", UpstreamModelID: "projection", DisplayName: "Projection", Source: ModelSourceUserDeclared, EntitlementMode: EntitlementAllBoundCredentials, Revision: 1}},
		Offerings:                   []ModelOffering{{ID: "offer_projection", ProviderInstanceID: "pvi_projection", ProviderModelID: "model_projection", ChannelID: "openai.chat", UpstreamModelID: "projection", Capabilities: ModelCapabilities{InputModalities: []string{"text"}, OutputModalities: []string{"text"}, ToolCalling: CapabilityNative, ParallelToolCalls: CapabilityUnknown, StreamingToolArguments: CapabilityUnknown, StrictJSONSchema: CapabilityUnknown, Reasoning: CapabilityNative, ReasoningEfforts: []string{"high"}}, RequestProjection: RequestProjection{Reasoning: ReasoningRequestProjection{Effort: []ReasoningParameterRule{{Value: "high", Set: []PayloadParameter{{Path: "reasoning_effort", Value: json.RawMessage(`"high"`)}}}}}}, CapabilityRevision: 1, Revision: 1}},
		Profiles:                    []ExecutionProfile{{ID: "profile_projection", ProviderInstanceID: "pvi_projection", OfferingID: "offer_projection", DisplayName: "Default", Default: true, Capabilities: ModelCapabilities{InputModalities: []string{"text"}, OutputModalities: []string{"text"}, ToolCalling: CapabilityNative, ParallelToolCalls: CapabilityUnknown, StreamingToolArguments: CapabilityUnknown, StrictJSONSchema: CapabilityUnknown, Reasoning: CapabilityNative, ReasoningEfforts: []string{"high"}}, SwitchPolicy: ProfileSwitchSeamless, PoolPolicy: PoolStrictProfile, CapabilityRevision: 1, Revision: 1}},
		Revision:                    1,
		ObservedAt:                  now,
	}
	if errValidate := snapshot.Validate(); errValidate == nil || !strings.Contains(errValidate.Error(), "conflicts with provider default additional parameters") {
		t.Fatalf("Snapshot.Validate() error = %v, want provider/model path conflict", errValidate)
	}
}
