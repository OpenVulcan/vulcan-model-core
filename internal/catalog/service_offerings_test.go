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
