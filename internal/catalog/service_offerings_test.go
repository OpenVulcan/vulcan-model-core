package catalog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestSnapshotValidatesUnifiedDirectSearchService verifies service catalog ownership and profiles.
// TestSnapshotValidatesUnifiedDirectSearchService 校验服务目录所有权和规格。
func TestSnapshotValidatesUnifiedDirectSearchService(t *testing.T) {
	snapshot := validDirectSearchSnapshot()
	if errValidate := snapshot.Validate(); errValidate != nil {
		t.Fatalf("valid direct search snapshot failed validation: %v", errValidate)
	}

	store := NewMemoryStore()
	if errSave := store.Save(context.Background(), snapshot); errSave != nil {
		t.Fatalf("save direct search snapshot: %v", errSave)
	}
	snapshot.ServiceOfferings[0].Capabilities.WebSearch.OutputModes[0] = vcp.WebSearchOutputAnswerWithCitations
	stored, errGet := store.Get(context.Background(), snapshot.ProviderInstanceID)
	if errGet != nil {
		t.Fatalf("get direct search snapshot: %v", errGet)
	}
	if stored.ServiceOfferings[0].Capabilities.WebSearch.OutputModes[0] != vcp.WebSearchOutputResults {
		t.Fatalf("stored search output modes were mutated through caller-owned slices")
	}
}

// TestSnapshotRejectsUnknownSearchBackingModel verifies immutable model-backed service ownership.
// TestSnapshotRejectsUnknownSearchBackingModel 校验不可变模型型服务所有权。
func TestSnapshotRejectsUnknownSearchBackingModel(t *testing.T) {
	snapshot := validDirectSearchSnapshot()
	capabilities := snapshot.ServiceOfferings[0].Capabilities.WebSearch
	capabilities.BackendKind = vcp.SearchBackendGroundedModel
	capabilities.InvocationMode = SearchInvocationPrompt
	capabilities.BackingModelOfferingID = "offer_missing"
	capabilities.PromptTemplateID = "search_prompt"
	capabilities.PromptTemplateRevision = 1
	if errValidate := snapshot.Validate(); !errors.Is(errValidate, ErrInvalidCatalog) {
		t.Fatalf("missing backing model error = %v, want ErrInvalidCatalog", errValidate)
	}
}

// TestSnapshotValidatesAndClonesDirectExtractionService verifies the closed extraction contract and nested slice isolation.
// TestSnapshotValidatesAndClonesDirectExtractionService 校验封闭提取合同与嵌套切片隔离。
func TestSnapshotValidatesAndClonesDirectExtractionService(t *testing.T) {
	capabilities := ServiceCapabilities{WebExtract: &WebExtractCapabilities{MaxURLs: 20, Depths: []vcp.WebExtractDepth{vcp.WebExtractDepthBasic, vcp.WebExtractDepthAdvanced}, Formats: []vcp.WebExtractFormat{vcp.WebExtractFormatMarkdown, vcp.WebExtractFormatText}, QueryRelevance: true, MinimumChunksPerSource: 1, MaximumChunksPerSource: 5, IncludeImages: true, IncludeFavicon: true, MinimumTimeoutSeconds: 1, MaximumTimeoutSeconds: 60}}
	snapshot := Snapshot{ProviderInstanceID: "pvi_extract", Services: []ProviderService{{ID: "service_web_extract", ProviderInstanceID: "pvi_extract", DisplayName: "Web Extract", Operation: vcp.OperationWebExtract, Source: ModelSourceSystem, EntitlementMode: EntitlementAllBoundCredentials, Revision: 1}}, ServiceOfferings: []ServiceOffering{{ID: "service_offer_web_extract", ProviderInstanceID: "pvi_extract", ProviderServiceID: "service_web_extract", ChannelID: "tavily_extract", UpstreamServiceID: "direct_extract", Capabilities: capabilities, CapabilityRevision: 1, Revision: 1}}, Profiles: []ExecutionProfile{{ID: "profile_web_extract", ProviderInstanceID: "pvi_extract", ServiceOfferingID: "service_offer_web_extract", Operation: vcp.OperationWebExtract, ActionBindingID: "action_web_extract", DisplayName: "Web Extract", Default: true, ServiceCapabilities: &capabilities, SwitchPolicy: ProfileSwitchReplayRequired, PoolPolicy: PoolPreferSmallestSufficient, CapabilityRevision: 1, Revision: 1}}, Revision: 1, ObservedAt: time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)}
	if errValidate := snapshot.Validate(); errValidate != nil {
		t.Fatalf("valid extraction snapshot failed validation: %v", errValidate)
	}
	store := NewMemoryStore()
	if errSave := store.Save(context.Background(), snapshot); errSave != nil {
		t.Fatalf("save extraction snapshot: %v", errSave)
	}
	snapshot.ServiceOfferings[0].Capabilities.WebExtract.Depths[0] = vcp.WebExtractDepthAdvanced
	stored, errGet := store.Get(context.Background(), snapshot.ProviderInstanceID)
	if errGet != nil {
		t.Fatalf("get extraction snapshot: %v", errGet)
	}
	if stored.ServiceOfferings[0].Capabilities.WebExtract.Depths[0] != vcp.WebExtractDepthBasic {
		t.Fatal("stored extraction depths were mutated through caller-owned slices")
	}
}

// validDirectSearchSnapshot creates one fully linked direct search service catalog.
// validDirectSearchSnapshot 创建一个完整关联的直接搜索服务目录。
func validDirectSearchSnapshot() Snapshot {
	capabilities := ServiceCapabilities{WebSearch: &WebSearchCapabilities{
		BackendKind:    vcp.SearchBackendDirectAPI,
		InvocationMode: SearchInvocationDirectRequest,
		OutputModes:    []vcp.WebSearchOutputMode{vcp.WebSearchOutputResults},
		EvidenceKinds:  []vcp.SearchEvidenceKind{vcp.SearchEvidenceStructuredResult},
		EvidenceRequirements: []vcp.SearchEvidenceRequirement{
			vcp.SearchEvidenceBestEffort,
			vcp.SearchEvidenceVerified,
		},
		Filters: SearchFilterCapabilities{
			DomainAllow:     CapabilityNative,
			DomainBlock:     CapabilityUnsupported,
			PublicationTime: CapabilityNative,
			Language:        CapabilityNative,
			Region:          CapabilityNative,
			Location:        CapabilityUnsupported,
			SafeSearch:      CapabilityNative,
		},
		MaxResults: OptionalCountLimit{Known: true, Value: 20},
	}}
	return Snapshot{
		ProviderInstanceID: "pvi_search",
		Services: []ProviderService{{
			ID:                 "service_web_search",
			ProviderInstanceID: "pvi_search",
			DisplayName:        "Web Search",
			Operation:          vcp.OperationSearchWeb,
			Source:             ModelSourceSystem,
			EntitlementMode:    EntitlementAllBoundCredentials,
			Revision:           1,
		}},
		ServiceOfferings: []ServiceOffering{{
			ID:                 "service_offer_web_search",
			ProviderInstanceID: "pvi_search",
			ProviderServiceID:  "service_web_search",
			ChannelID:          "web_search",
			UpstreamServiceID:  "direct_search",
			Capabilities:       capabilities,
			CapabilityRevision: 1,
			Revision:           1,
		}},
		Profiles: []ExecutionProfile{{
			ID:                  "profile_web_search",
			ProviderInstanceID:  "pvi_search",
			ServiceOfferingID:   "service_offer_web_search",
			Operation:           vcp.OperationSearchWeb,
			ActionBindingID:     "action_web_search",
			DisplayName:         "Web Search",
			Default:             true,
			ServiceCapabilities: &capabilities,
			SwitchPolicy:        ProfileSwitchUnsupported,
			PoolPolicy:          PoolStrictProfile,
			CapabilityRevision:  1,
			Revision:            1,
		}},
		Revision:   1,
		ObservedAt: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	}
}
