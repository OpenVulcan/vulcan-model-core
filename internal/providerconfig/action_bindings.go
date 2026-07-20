package providerconfig

import (
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ResourceMaterializationMode identifies one trusted upstream resource representation.
// ResourceMaterializationMode 标识一种受信任上游资源表示。
type ResourceMaterializationMode string

const (
	// ResourceMaterializationInline sends bounded content inline.
	// ResourceMaterializationInline 内联发送受限内容。
	ResourceMaterializationInline ResourceMaterializationMode = "inline"
	// ResourceMaterializationDirectURL sends one previously validated remote URL directly.
	// ResourceMaterializationDirectURL 直接发送一个此前已校验的远程 URL。
	ResourceMaterializationDirectURL ResourceMaterializationMode = "direct_url"
	// ResourceMaterializationProviderFile uploads content to a provider file API.
	// ResourceMaterializationProviderFile 将内容上传到供应商文件 API。
	ResourceMaterializationProviderFile ResourceMaterializationMode = "provider_file"
	// ResourceMaterializationObjectURI sends one provider-authorized object URI.
	// ResourceMaterializationObjectURI 发送一个供应商授权对象 URI。
	ResourceMaterializationObjectURI ResourceMaterializationMode = "object_uri"
	// ResourceMaterializationAssetID sends one provider-owned asset identifier.
	// ResourceMaterializationAssetID 发送一个供应商拥有的资产标识。
	ResourceMaterializationAssetID ResourceMaterializationMode = "provider_asset_id"
)

// ActionDeliveryModes declares real upstream delivery behavior.
// ActionDeliveryModes 声明真实上游交付行为。
type ActionDeliveryModes struct {
	// Synchronous reports immediate response support.
	// Synchronous 表示支持立即响应。
	Synchronous bool
	// Streaming reports real semantic streaming support.
	// Streaming 表示支持真实语义流式输出。
	Streaming bool
	// Asynchronous reports provider task support.
	// Asynchronous 表示支持供应商任务。
	Asynchronous bool
	// Polling reports whether the asynchronous task can be observed through Router task polling.
	// Polling 表示异步任务是否可通过 Router 任务轮询进行观察。
	Polling bool
	// Cancellation reports whether the provider documents and implements task cancellation.
	// Cancellation 表示供应商是否记录并实现任务取消。
	Cancellation bool
}

// SearchActionBinding fixes one search implementation and model trigger.
// SearchActionBinding 固定一个搜索实现和模型触发方式。
type SearchActionBinding struct {
	// BackendKind identifies direct API or fixed web-enabled model execution.
	// BackendKind 标识直接 API 或固定联网模型执行。
	BackendKind vcp.SearchBackendKind
	// BackingModelOfferingID fixes the model for model-grounded search.
	// BackingModelOfferingID 固定模型型搜索使用的模型。
	BackingModelOfferingID string
	// EnableNativeSearch requires the documented provider flag or tool.
	// EnableNativeSearch 要求使用文档记录的供应商开关或工具。
	EnableNativeSearch bool
	// PromptTemplateID identifies a code-owned search instruction template.
	// PromptTemplateID 标识一个代码拥有的搜索指令模板。
	PromptTemplateID string
	// PromptTemplateRevision freezes the template behavior.
	// PromptTemplateRevision 冻结模板行为。
	PromptTemplateRevision uint64
}

// ProviderActionBinding binds one operation to one trusted driver and protocol path.
// ProviderActionBinding 将一个操作绑定到一个受信任驱动和协议路径。
type ProviderActionBinding struct {
	// ID is stable within one provider definition.
	// ID 在一个供应商定义内保持稳定。
	ID string
	// Operation identifies the sole VCP operation.
	// Operation 标识唯一 VCP 操作。
	Operation vcp.OperationKind
	// DriverID identifies the trusted execution driver.
	// DriverID 标识受信任执行驱动。
	DriverID string
	// DriverVersion freezes trusted driver behavior.
	// DriverVersion 冻结受信任驱动行为。
	DriverVersion string
	// ProtocolProfileID identifies the exact upstream protocol profile.
	// ProtocolProfileID 标识精确上游协议规格。
	ProtocolProfileID string
	// EndpointProfileID identifies the exact provider endpoint behavior.
	// EndpointProfileID 标识精确供应商端点行为。
	EndpointProfileID string
	// AuthMethodIDs lists allowed provider-owned authentication methods.
	// AuthMethodIDs 列出允许的供应商认证方式。
	AuthMethodIDs []string
	// Delivery declares real synchronous, streaming, and asynchronous behavior.
	// Delivery 声明真实同步、流式和异步行为。
	Delivery ActionDeliveryModes
	// ResourceMaterialization lists supported upstream resource representations.
	// ResourceMaterialization 列出支持的上游资源表示。
	ResourceMaterialization []ResourceMaterializationMode
	// Search contains fixed search behavior only for search.web.
	// Search 仅为 search.web 包含固定搜索行为。
	Search *SearchActionBinding
	// Revision is the immutable action binding revision.
	// Revision 是不可变动作绑定修订号。
	Revision uint64
}

// Validate verifies one code-owned operation binding without runtime candidates.
// Validate 校验一个不含运行时候选项的代码拥有操作绑定。
func (b ProviderActionBinding) Validate() error {
	if errID := validateIdentifier("provider action binding id", b.ID); errID != nil {
		return errID
	}
	if !validOperationKind(b.Operation) {
		return invalid("provider action binding operation %q is invalid", b.Operation)
	}
	if strings.TrimSpace(b.DriverID) == "" || strings.TrimSpace(b.DriverVersion) == "" || strings.TrimSpace(b.ProtocolProfileID) == "" || strings.TrimSpace(b.EndpointProfileID) == "" || b.Revision == 0 {
		return invalid("provider action binding driver, protocol, endpoint profile, and revision are required")
	}
	if !b.Delivery.Synchronous && !b.Delivery.Streaming && !b.Delivery.Asynchronous {
		return invalid("provider action binding requires at least one delivery mode")
	}
	if (b.Delivery.Polling || b.Delivery.Cancellation) && !b.Delivery.Asynchronous {
		return invalid("provider action binding polling and cancellation require asynchronous delivery")
	}
	seenAuth := make(map[string]struct{}, len(b.AuthMethodIDs))
	for _, authMethodID := range b.AuthMethodIDs {
		if errAuth := validateIdentifier("provider action binding auth method id", authMethodID); errAuth != nil {
			return errAuth
		}
		if _, exists := seenAuth[authMethodID]; exists {
			return invalid("provider action binding contains duplicate auth method %q", authMethodID)
		}
		seenAuth[authMethodID] = struct{}{}
	}
	seenMaterialization := make(map[ResourceMaterializationMode]struct{}, len(b.ResourceMaterialization))
	for _, mode := range b.ResourceMaterialization {
		if !validResourceMaterializationMode(mode) {
			return invalid("provider action binding resource materialization %q is invalid", mode)
		}
		if _, exists := seenMaterialization[mode]; exists {
			return invalid("provider action binding contains duplicate resource materialization %q", mode)
		}
		seenMaterialization[mode] = struct{}{}
	}
	if b.Operation == vcp.OperationSearchWeb {
		if b.Search == nil {
			return invalid("search.web action binding requires search configuration")
		}
		return b.Search.Validate()
	}
	if b.Search != nil {
		return invalid("non-search action binding cannot carry search configuration")
	}
	return nil
}

// Validate verifies one fixed direct or model-grounded search binding.
// Validate 校验一个固定直接或模型型搜索绑定。
func (b SearchActionBinding) Validate() error {
	if b.BackendKind == vcp.SearchBackendDirectAPI {
		if b.BackingModelOfferingID != "" || b.EnableNativeSearch || b.PromptTemplateID != "" || b.PromptTemplateRevision != 0 {
			return invalid("direct search action cannot carry model search configuration")
		}
		return nil
	}
	if b.BackendKind != vcp.SearchBackendGroundedModel {
		return invalid("search action backend kind %q is invalid", b.BackendKind)
	}
	if strings.TrimSpace(b.BackingModelOfferingID) == "" {
		return invalid("model-grounded search action requires backing model offering id")
	}
	promptConfigured := b.PromptTemplateID != "" || b.PromptTemplateRevision != 0
	if promptConfigured && (strings.TrimSpace(b.PromptTemplateID) == "" || b.PromptTemplateRevision == 0) {
		return invalid("model-grounded search prompt id and revision must be set together")
	}
	if !b.EnableNativeSearch && !promptConfigured {
		return invalid("model-grounded search requires native search enablement or a versioned prompt")
	}
	return nil
}

// validResourceMaterializationMode reports whether one representation is registered.
// validResourceMaterializationMode 报告一种资源表示是否已注册。
func validResourceMaterializationMode(mode ResourceMaterializationMode) bool {
	switch mode {
	case ResourceMaterializationInline, ResourceMaterializationDirectURL, ResourceMaterializationProviderFile, ResourceMaterializationObjectURI, ResourceMaterializationAssetID:
		return true
	default:
		return false
	}
}

// validOperationKind reports whether one VCP operation is registered.
// validOperationKind 报告一个 VCP 操作是否已注册。
func validOperationKind(operation vcp.OperationKind) bool {
	switch operation {
	case vcp.OperationConversationRespond, vcp.OperationMediaAnalyze, vcp.OperationImageGenerate, vcp.OperationImageEdit, vcp.OperationVideoGenerate, vcp.OperationVideoEdit, vcp.OperationVideoExtend, vcp.OperationSpeechSynthesize, vcp.OperationSpeechTranscribe, vcp.OperationEmbeddingCreate, vcp.OperationRerankDocuments, vcp.OperationSearchWeb, vcp.OperationMusicGenerate, vcp.OperationMusicCoverPrepare, vcp.OperationMusicCover:
		return true
	default:
		return false
	}
}

// actionBindingByID resolves one exact definition-owned action binding.
// actionBindingByID 解析一个精确定义拥有的动作绑定。
func actionBindingByID(bindings []ProviderActionBinding, bindingID string) (ProviderActionBinding, error) {
	for _, binding := range bindings {
		if binding.ID == bindingID {
			return binding, nil
		}
	}
	return ProviderActionBinding{}, fmt.Errorf("%w: action binding %q not found", ErrInvalidConfiguration, bindingID)
}
