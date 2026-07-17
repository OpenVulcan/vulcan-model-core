package vcp

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestVulcanRequestValidateRejectsUnknownClosedEnums verifies that unregistered request and context enum values are rejected.
// TestVulcanRequestValidateRejectsUnknownClosedEnums 校验未注册的请求与上下文枚举值会被拒绝。
func TestVulcanRequestValidateRejectsUnknownClosedEnums(t *testing.T) {
	// fields names every closed request or context enum boundary exercised by this test.
	// fields 列出本测试覆盖的每个封闭请求或上下文枚举边界。
	fields := []string{
		"model target",
		"authority",
		"actor",
		"placement",
		"activation",
		"visibility",
		"context kind",
		"content type",
		"tool kind",
		"tool choice",
		"cache strategy",
		"cache unsupported policy",
		"context management mode",
		"capability execution mode",
		"optional unsupported action",
	}
	for _, field := range fields {
		// field captures the current closed enum boundary for the subtest.
		// field 捕获当前子测试所校验的封闭枚举边界。
		field := field
		t.Run(field, func(t *testing.T) {
			// request starts valid so the mutated enum is the only rejection reason.
			// request 初始有效，以确保被修改的枚举是唯一拒绝原因。
			request := testTextRequest()
			setUnknownClosedEnum(t, &request, field)
			if errValidate := request.Validate(); !errors.Is(errValidate, ErrInvalidRequest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRequest", errValidate)
			}
		})
	}
}

// TestVulcanRequestValidateRemoteCompactionExclusiveInput verifies the required previous-response-or-context exclusive choice.
// TestVulcanRequestValidateRemoteCompactionExclusiveInput 校验远程压缩必须在先前响应与上下文之间二选一。
func TestVulcanRequestValidateRemoteCompactionExclusiveInput(t *testing.T) {
	// compactContext is a valid stateless compaction input independent from the request context.
	// compactContext 是独立于请求上下文的有效无状态压缩输入。
	compactContext := testTextRequest().Context
	// cases cover both valid branches and both invalid exclusivity states.
	// cases 覆盖两个有效分支和两个无效的互斥状态。
	cases := []struct {
		// name identifies the exclusive-input scenario.
		// name 标识互斥输入场景。
		name string
		// remote contains the explicit compaction input under validation.
		// remote 包含待校验的显式压缩输入。
		remote RemoteCompactionRequest
		// wantError reports whether validation must reject the scenario.
		// wantError 表示校验是否必须拒绝该场景。
		wantError bool
	}{
		{name: "previous response only", remote: RemoteCompactionRequest{PreviousResponseID: "rsp_previous"}},
		{name: "context only", remote: RemoteCompactionRequest{Context: compactContext}},
		{name: "neither input", remote: RemoteCompactionRequest{}, wantError: true},
		{name: "both inputs", remote: RemoteCompactionRequest{PreviousResponseID: "rsp_previous", Context: compactContext}, wantError: true},
	}
	for _, testCase := range cases {
		// testCase captures the current exclusivity scenario for the subtest.
		// testCase 捕获当前子测试的互斥场景。
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			// request starts valid before the explicit remote compaction input is attached.
			// request 在附加显式远程压缩输入前保持有效。
			request := testTextRequest()
			request.RemoteCompaction = &testCase.remote
			errValidate := request.Validate()
			if testCase.wantError && !errors.Is(errValidate, ErrInvalidRequest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRequest", errValidate)
			}
			if !testCase.wantError && errValidate != nil {
				t.Fatalf("Validate() error = %v, want nil", errValidate)
			}
		})
	}
}

// TestParseFrameRejectsNonCanonicalAttributeOrder verifies that a semantically valid reordered Frame is rejected.
// TestParseFrameRejectsNonCanonicalAttributeOrder 校验语义有效但属性重排的 Frame 会被拒绝。
func TestParseFrameRejectsNonCanonicalAttributeOrder(t *testing.T) {
	// item is a registered text-carriable developer instruction.
	// item 是已注册且可文本承载的开发者指令。
	item := testDeveloperFrameItem()
	encoded, _, errEncode := EncodeFrame(item, "frm_order")
	if errEncode != nil {
		t.Fatalf("EncodeFrame() error = %v", errEncode)
	}
	// nonCanonical swaps only the first two attributes while preserving every value.
	// nonCanonical 仅交换前两个属性并保留全部属性值。
	nonCanonical := strings.Replace(encoded, `<vulcan-frame version="1" frame-id="frm_order"`, `<vulcan-frame frame-id="frm_order" version="1"`, 1)
	if nonCanonical == encoded {
		t.Fatal("test setup did not reorder Frame attributes")
	}
	if _, errParse := ParseFrame(nonCanonical); !errors.Is(errParse, ErrInvalidFrame) {
		t.Fatalf("ParseFrame() error = %v, want ErrInvalidFrame", errParse)
	}
}

// TestFrameScannerCompleteOrTextReturnsExactInvalidFrame verifies validation failure preserves the original carrier bytes.
// TestFrameScannerCompleteOrTextReturnsExactInvalidFrame 校验验证失败会完整保留原始载体字节。
func TestFrameScannerCompleteOrTextReturnsExactInvalidFrame(t *testing.T) {
	// item is encoded first so the invalid input remains a complete canonical-shaped Frame.
	// item 先被编码，以确保无效输入仍是完整的规范形态 Frame。
	item := testDeveloperFrameItem()
	encoded, frame, errEncode := EncodeFrame(item, "frm_invalid_digest")
	if errEncode != nil {
		t.Fatalf("EncodeFrame() error = %v", errEncode)
	}
	// invalid replaces only the digest with a well-formed but incorrect value.
	// invalid 仅用格式正确但不匹配的值替换摘要。
	invalid := strings.Replace(encoded, frame.Digest, DigestText("different content"), 1)
	// scanner receives the invalid Frame across arbitrary chunk boundaries.
	// scanner 跨任意分片边界接收无效 Frame。
	scanner := &FrameScanner{}
	scanner.Feed(invalid[:23])
	scanner.Feed(invalid[23:71])
	scanner.Feed(invalid[71:])
	parsed, raw, restored := scanner.CompleteOrText()
	if restored || parsed != (Frame{}) || raw != invalid {
		t.Fatalf("CompleteOrText() = %#v, %q, %v, want zero Frame, exact input, false", parsed, raw, restored)
	}
}

// TestProjectionLedgerRestoreFrameRejectsEachTrustMismatch verifies every requested trust binding independently blocks restoration.
// TestProjectionLedgerRestoreFrameRejectsEachTrustMismatch 校验每个指定信任绑定单独不匹配时都会阻止恢复。
func TestProjectionLedgerRestoreFrameRejectsEachTrustMismatch(t *testing.T) {
	ledger, frame, item, now := testProjectionLedgerFixture(t)
	if restored, errRestore := ledger.RestoreFrame(frame, "lin", "user", 0, now); errRestore != nil || !reflect.DeepEqual(restored, item) {
		t.Fatalf("valid RestoreFrame() = %#v, %v, want %#v, nil", restored, errRestore, item)
	}
	// mismatchedDigest changes only the Frame digest for the digest mismatch case.
	// mismatchedDigest 仅为摘要不匹配场景修改 Frame 摘要。
	mismatchedDigest := frame
	mismatchedDigest.Digest = DigestText("forged content")
	// cases isolate each ledger trust binding required by ADR 0006.
	// cases 隔离 ADR 0006 要求的每个账本信任绑定。
	cases := []struct {
		// name identifies the mismatched trust binding.
		// name 标识不匹配的信任绑定。
		name string
		// frame is the candidate Frame supplied for restoration.
		// frame 是提供给恢复流程的候选 Frame。
		frame Frame
		// lineage identifies the current Router-owned lineage.
		// lineage 标识当前由 Router 拥有的谱系。
		lineage string
		// carrier identifies the observed upstream role or slot.
		// carrier 标识观测到的上游角色或槽位。
		carrier string
		// position identifies the observed zero-based upstream position.
		// position 标识观测到的上游零基位置。
		position int
	}{
		{name: "digest", frame: mismatchedDigest, lineage: "lin", carrier: "user", position: 0},
		{name: "position", frame: frame, lineage: "lin", carrier: "user", position: 1},
		{name: "carrier", frame: frame, lineage: "lin", carrier: "assistant", position: 0},
		{name: "lineage", frame: frame, lineage: "other", carrier: "user", position: 0},
	}
	for _, testCase := range cases {
		// testCase captures the current isolated trust mismatch for the subtest.
		// testCase 捕获当前子测试的独立信任不匹配。
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			if _, errRestore := ledger.RestoreFrame(testCase.frame, testCase.lineage, testCase.carrier, testCase.position, now); !errors.Is(errRestore, ErrProjectionMismatch) {
				t.Fatalf("RestoreFrame() error = %v, want ErrProjectionMismatch", errRestore)
			}
		})
	}
}

// setUnknownClosedEnum mutates exactly one named request or context enum to an unregistered value.
// setUnknownClosedEnum 将一个指定的请求或上下文枚举修改为未注册值。
func setUnknownClosedEnum(t *testing.T, request *VulcanRequest, field string) {
	t.Helper()
	switch field {
	case "model target":
		request.ModelSelection.Target = ModelTargetMode("unknown")
	case "authority":
		request.Context[0].Authority = Authority("unknown")
	case "actor":
		request.Context[0].Actor = Actor("unknown")
	case "placement":
		request.Context[0].Placement = Placement("unknown")
	case "activation":
		request.Context[0].Activation.Mode = ActivationMode("unknown")
	case "visibility":
		request.Context[0].Visibility = Visibility("unknown")
	case "context kind":
		request.Context[0].Kind = ContextKind("unknown")
	case "content type":
		request.Context[0].Content[0].Type = ContentType("unknown")
	case "tool kind":
		request.Tools = []ToolDefinition{{Kind: ToolKind("unknown"), Name: "lookup"}}
	case "tool choice":
		request.ToolPolicy.Choice = ToolChoiceMode("unknown")
	case "cache strategy":
		request.CachePolicy.Strategy = CacheStrategy("unknown")
	case "cache unsupported policy":
		request.CachePolicy.OnUnsupported = CacheUnsupportedPolicy("unknown")
	case "context management mode":
		request.ContextManagementPolicy.Mode = ContextManagementMode("unknown")
	case "capability execution mode":
		request.CapabilityPolicy.ExecutionMode = CapabilityExecutionMode("unknown")
	case "optional unsupported action":
		request.CapabilityPolicy.OptionalOnUnsupported = OptionalUnsupportedAction("unknown")
	default:
		t.Fatalf("unknown closed enum test field %q", field)
	}
}

// testDeveloperFrameItem creates a valid text-carriable developer instruction for Frame tests.
// testDeveloperFrameItem 为 Frame 测试创建一个有效且可文本承载的开发者指令。
func testDeveloperFrameItem() ContextItem {
	return ContextItem{
		ItemID:    "itm_dev",
		Sequence:  1,
		Kind:      ContextInstruction,
		Authority: AuthorityDeveloper,
		Actor:     ActorApplication,
		Placement: PlacementTranscript,
		Activation: Activation{
			Mode: ActivationRequestStart,
		},
		Visibility:  VisibilityModel,
		Content:     []ContentBlock{{Type: ContentText, Text: "Use evidence."}},
		Instruction: &InstructionItem{},
	}
}

// testProjectionLedgerFixture creates one valid registered Frame and its authoritative ledger entry.
// testProjectionLedgerFixture 创建一个有效已注册 Frame 及其权威账本条目。
func testProjectionLedgerFixture(t *testing.T) (ProjectionLedger, Frame, ContextItem, time.Time) {
	t.Helper()
	// item is the canonical truth preserved by the ledger.
	// item 是账本保存的规范真相。
	item := testDeveloperFrameItem()
	_, frame, errEncode := EncodeFrame(item, "frm_ledger")
	if errEncode != nil {
		t.Fatalf("EncodeFrame() error = %v", errEncode)
	}
	// now anchors deterministic ledger validity for restoration tests.
	// now 为恢复测试固定确定性的账本有效时间。
	now := time.Unix(100, 0)
	// ledger is the authoritative mapping for the registered Frame.
	// ledger 是已注册 Frame 的权威映射。
	ledger := ProjectionLedger{LedgerID: "ldg", ProjectionID: "prj", LineageID: "lin"}
	errAdd := ledger.Add(ProjectionEntry{
		ProjectionID:         "prj",
		LineageID:            "lin",
		CanonicalItemID:      item.ItemID,
		CanonicalSequence:    item.Sequence,
		CanonicalKind:        item.Kind,
		SourceAuthority:      item.Authority,
		CarrierProtocol:      "openai_chat",
		CarrierRoleOrSlot:    "user",
		UpstreamPosition:     0,
		ProjectionMode:       CapabilityProjected,
		ExecutionEquivalence: EquivalenceAdvisory,
		RuleID:               "openai_chat.developer.frame.v1",
		RuleVersion:          "1",
		FrameID:              frame.FrameID,
		ContentDigest:        frame.Digest,
		DecodePolicy:         "replay_only",
		OriginalItem:         item,
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Hour),
	})
	if errAdd != nil {
		t.Fatalf("Add() error = %v", errAdd)
	}
	return ledger, frame, item, now
}
