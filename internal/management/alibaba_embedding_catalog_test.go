package management

import (
	"reflect"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba/catalogdata"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// TestAlibabaQwen37TextEmbeddingPreservesVerifiedCNContract verifies region, limits, dimensions, and executable policy stay aligned.
// TestAlibabaQwen37TextEmbeddingPreservesVerifiedCNContract 验证区域、限制、维度与可执行策略保持一致。
func TestAlibabaQwen37TextEmbeddingPreservesVerifiedCNContract(t *testing.T) {
	models := alibabaModelStudioCNEmbeddingModels()
	if len(models) != 1 {
		t.Fatalf("China-only embedding model count = %d, want 1", len(models))
	}
	model := models[0]
	if model.upstreamID != "qwen3.7-text-embedding" || model.operation != vcp.OperationEmbeddingCreate || model.contextWindow != 131_072 || model.maxInputTokens != 128_000 || model.embedding == nil {
		t.Fatalf("Qwen3.7 embedding template = %#v", model)
	}
	if !reflect.DeepEqual(model.embedding.InputTasks, []vcp.EmbeddingInputTask{vcp.EmbeddingTaskProviderDefault}) ||
		!reflect.DeepEqual(model.embedding.OutputKinds, []vcp.EmbeddingVectorKind{vcp.EmbeddingVectorDense}) ||
		!reflect.DeepEqual(model.embedding.Encodings, []vcp.EmbeddingEncoding{vcp.EmbeddingEncodingFloat}) ||
		!reflect.DeepEqual(model.embedding.Dimensions, []int{256, 512, 768, 1024, 1536, 2048, 2560}) ||
		model.embedding.DefaultDimensions != (catalog.OptionalLimit{Known: true, Value: 1024}) ||
		model.embedding.MaxBatchItems != (catalog.OptionalLimit{Known: true, Value: 20}) {
		t.Fatalf("Qwen3.7 embedding capabilities = %#v", model.embedding)
	}
	policies, errPolicies := catalogdata.LoadOperationPolicies()
	if errPolicies != nil {
		t.Fatalf("LoadOperationPolicies() error = %v", errPolicies)
	}
	policyByKey, errIndex := policies.EntryMap()
	if errIndex != nil {
		t.Fatalf("EntryMap() error = %v", errIndex)
	}
	key := catalogdata.OperationPolicyKey("alibaba_model_studio_cn", model.upstreamID, vcp.OperationEmbeddingCreate)
	policy, exists := policyByKey[key]
	if !exists || policy.Status != catalog.ModelOperationSupported || policy.Reason != catalog.SupportReasonProviderContractVerified {
		t.Fatalf("Qwen3.7 embedding policy = %#v, exists = %t", policy, exists)
	}
}

// TestAlibabaQwen37TextEmbeddingIsNotCopiedAcrossRegions verifies the CN-only model never enters Singapore or Workspace templates.
// TestAlibabaQwen37TextEmbeddingIsNotCopiedAcrossRegions 验证中国站专属模型绝不会进入新加坡或 Workspace 模板。
func TestAlibabaQwen37TextEmbeddingIsNotCopiedAcrossRegions(t *testing.T) {
	for _, catalogID := range []string{"alibaba_model_studio_sg_domestic", "alibaba_model_studio_workspace_sg"} {
		models, errModels := systemModelTemplates(catalogID)
		if errModels != nil {
			t.Fatalf("systemModelTemplates(%q) error = %v", catalogID, errModels)
		}
		for _, model := range models {
			if model.upstreamID == "qwen3.7-text-embedding" {
				t.Fatalf("catalog %q copied China-only embedding model", catalogID)
			}
		}
	}
}

// TestAlibabaQwen37TextEmbeddingReachesBuiltCatalog verifies provider evidence enrichment preserves the stricter per-input limit.
// TestAlibabaQwen37TextEmbeddingReachesBuiltCatalog 验证供应商证据增强后仍保留更严格的单输入限制。
func TestAlibabaQwen37TextEmbeddingReachesBuiltCatalog(t *testing.T) {
	protocols := providerconfig.NewProtocolRegistry()
	if errProtocols := bootstrap.RegisterProtocolProfiles(protocols); errProtocols != nil {
		t.Fatalf("RegisterProtocolProfiles() error = %v", errProtocols)
	}
	systems, errSystems := providerconfig.NewSystemRegistry(protocols)
	if errSystems != nil {
		t.Fatalf("NewSystemRegistry() error = %v", errSystems)
	}
	if errProviders := bootstrap.RegisterSystemProviders(systems); errProviders != nil {
		t.Fatalf("RegisterSystemProviders() error = %v", errProviders)
	}
	definition, exists := systems.Lookup(bootstrap.AlibabaModelStudioCNDefinitionID)
	if !exists {
		t.Fatal("Alibaba Model Studio CN definition is missing")
	}
	snapshot, errBuild := buildSystemCatalog(providerconfig.SystemOnboarding{Instance: providerconfig.ProviderInstance{ID: "pvi_qwen37_embedding"}}, definition, time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC))
	if errBuild != nil {
		t.Fatalf("buildSystemCatalog() error = %v", errBuild)
	}
	modelIDByOffering := make(map[string]string, len(snapshot.Offerings))
	for _, offering := range snapshot.Offerings {
		modelIDByOffering[offering.ID] = offering.ProviderModelID
	}
	for _, profile := range snapshot.Profiles {
		if profile.Operation != vcp.OperationEmbeddingCreate || profile.Capabilities.Embedding == nil {
			continue
		}
		for _, model := range snapshot.Models {
			if model.ID != modelIDByOffering[profile.OfferingID] || model.UpstreamModelID != "qwen3.7-text-embedding" {
				continue
			}
			if !profile.Capabilities.Tokens.ContextWindow.Known || profile.Capabilities.Tokens.ContextWindow.Value != 131_072 ||
				!profile.Capabilities.Tokens.MaxInputTokens.Known || profile.Capabilities.Tokens.MaxInputTokens.Value != 128_000 ||
				profile.ActionBindingID != "action_alibaba_embedding_create" {
				t.Fatalf("built Qwen3.7 embedding profile = %#v", profile)
			}
			return
		}
	}
	t.Fatal("built Alibaba Model Studio CN catalog omitted Qwen3.7 text embedding")
}
