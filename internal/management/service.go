// Package management coordinates provider configuration workflows and safe client queries.
// management 包协调供应商配置工作流与客户端安全查询。
package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

var (
	// ErrConfigurationIncomplete reports an instance that cannot enter ready state.
	// ErrConfigurationIncomplete 表示供应商实例无法进入 Ready 状态。
	ErrConfigurationIncomplete = errors.New("provider configuration is incomplete")
)

// Service coordinates configuration persistence, secret compensation, and lifecycle rules.
// Service 协调配置持久化、Secret 补偿和生命周期规则。
type Service struct {
	// configurations persists non-secret provider configuration.
	// configurations 持久化非秘密供应商配置。
	configurations providerconfig.Store
	// secrets persists opaque credential bytes outside business storage.
	// secrets 在业务存储之外持久化不透明凭据字节。
	secrets secret.Store
	// now returns the authoritative lifecycle timestamp.
	// now 返回权威生命周期时间戳。
	now func() time.Time
}

// NewService creates one provider configuration application service.
// NewService 创建一个供应商配置应用服务。
func NewService(configurations providerconfig.Store, secrets secret.Store) (*Service, error) {
	if configurations == nil || secrets == nil {
		return nil, errors.New("provider configuration and secret stores are required")
	}
	return &Service{configurations: configurations, secrets: secrets, now: time.Now}, nil
}

// CreateCustomDefinitionInput contains the editable portion of one generic custom provider.
// CreateCustomDefinitionInput 包含一个通用自定义供应商的可编辑部分。
type CreateCustomDefinitionInput struct {
	// ID optionally supplies an externally allocated custom_ identifier.
	// ID 可选地提供一个外部分配的 custom_ 标识。
	ID string
	// DisplayName is the management-facing provider name.
	// DisplayName 是管理界面显示的供应商名称。
	DisplayName string
	// ProtocolProfileID selects one user-configurable executable standard protocol.
	// ProtocolProfileID 选择一个用户可配置且可执行的标准协议。
	ProtocolProfileID string
	// AuthMethod selects one generic custom-provider authentication mechanism.
	// AuthMethod 选择一种通用自定义供应商认证机制。
	AuthMethod providerconfig.AuthMethodType
}

// CreateCustomDefinition builds and persists one constrained custom provider definition.
// CreateCustomDefinition 构建并持久化一个受约束的自定义供应商定义。
func (s *Service) CreateCustomDefinition(ctx context.Context, input CreateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	definitionID := input.ID
	if definitionID == "" {
		generatedID, errID := generateID("custom_")
		if errID != nil {
			return providerconfig.ProviderDefinition{}, errID
		}
		definitionID = generatedID
	}
	definition := providerconfig.ProviderDefinition{
		ID:                  definitionID,
		Kind:                providerconfig.DefinitionKindCustom,
		DisplayName:         input.DisplayName,
		ConfigSchemaVersion: "1",
		Channels: []providerconfig.ProviderChannel{{
			ID:                "default",
			ProtocolProfileID: input.ProtocolProfileID,
			EndpointProfileID: "custom",
			AuthMethodIDs:     []string{"default"},
			RuntimeReady:      true,
		}},
		AuthMethods: []providerconfig.AuthMethodDefinition{{
			ID:                  "default",
			Type:                input.AuthMethod,
			MultipleCredentials: true,
		}},
		Features: providerconfig.ProviderFeatureSet{
			ModelDiscovery:    providerconfig.SupportUnsupported,
			PlanReader:        providerconfig.SupportUnsupported,
			EntitlementReader: providerconfig.SupportUnsupported,
			AllowanceReader:   providerconfig.SupportUnsupported,
		},
		Revision: 1,
	}
	if errSave := s.configurations.SaveCustomDefinition(ctx, definition); errSave != nil {
		return providerconfig.ProviderDefinition{}, errSave
	}
	return definition, nil
}

// CreateInstanceInput contains initial provider instance configuration.
// CreateInstanceInput 包含供应商实例初始配置。
type CreateInstanceInput struct {
	// ID optionally supplies an externally allocated pvi_ identifier.
	// ID 可选地提供一个外部分配的 pvi_ 标识。
	ID string
	// DefinitionID selects one system or custom provider definition.
	// DefinitionID 选择一个系统或自定义供应商定义。
	DefinitionID string
	// Handle is the stable workspace routing alias.
	// Handle 是稳定的工作区路由别名。
	Handle string
	// DisplayName is the editable management-facing instance name.
	// DisplayName 是管理界面可编辑的实例名称。
	DisplayName string
}

// CreateInstance persists one provider instance in draft state.
// CreateInstance 以 Draft 状态持久化一个供应商实例。
func (s *Service) CreateInstance(ctx context.Context, input CreateInstanceInput) (providerconfig.ProviderInstance, error) {
	definition, errDefinition := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errDefinition != nil {
		return providerconfig.ProviderInstance{}, errDefinition
	}
	instanceID := input.ID
	if instanceID == "" {
		generatedID, errID := generateID("pvi_")
		if errID != nil {
			return providerconfig.ProviderInstance{}, errID
		}
		instanceID = generatedID
	}
	now := s.now().UTC()
	instance := providerconfig.ProviderInstance{
		ID:                 instanceID,
		DefinitionID:       definition.ID,
		Handle:             input.Handle,
		DisplayName:        input.DisplayName,
		Status:             providerconfig.LifecycleDraft,
		Revision:           1,
		DefinitionRevision: definition.Revision,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// AddEndpointInput contains one concrete upstream endpoint configuration.
// AddEndpointInput 包含一个具体上游端点配置。
type AddEndpointInput struct {
	// ID optionally supplies an externally allocated ep_ identifier.
	// ID 可选地提供一个外部分配的 ep_ 标识。
	ID string
	// ProviderInstanceID owns the endpoint.
	// ProviderInstanceID 是端点所属供应商实例。
	ProviderInstanceID string
	// ChannelID selects one channel declared by the provider definition.
	// ChannelID 选择供应商定义声明的一个通道。
	ChannelID string
	// BaseURL is the validated upstream base URL.
	// BaseURL 是经过校验的上游基础 URL。
	BaseURL string
	// Region is an optional provider-defined region.
	// Region 是可选的供应商定义区域。
	Region string
}

// AddEndpoint creates one ready local endpoint record without probing the network.
// AddEndpoint 创建一个本地 Ready 端点记录且不探测网络。
func (s *Service) AddEndpoint(ctx context.Context, input AddEndpointInput) (providerconfig.Endpoint, error) {
	endpointID := input.ID
	if endpointID == "" {
		generatedID, errID := generateID("ep_")
		if errID != nil {
			return providerconfig.Endpoint{}, errID
		}
		endpointID = generatedID
	}
	endpoint := providerconfig.Endpoint{
		ID:                 endpointID,
		ProviderInstanceID: input.ProviderInstanceID,
		ChannelID:          input.ChannelID,
		BaseURL:            input.BaseURL,
		Region:             input.Region,
		Status:             providerconfig.EndpointReady,
		Revision:           1,
	}
	if errSave := s.configurations.SaveEndpoint(ctx, endpoint); errSave != nil {
		return providerconfig.Endpoint{}, errSave
	}
	return endpoint, nil
}

// AddCredentialInput contains non-secret metadata and transient secret bytes.
// AddCredentialInput 包含非秘密元数据和临时 Secret 字节。
type AddCredentialInput struct {
	// ID optionally supplies an externally allocated cred_ identifier.
	// ID 可选地提供一个外部分配的 cred_ 标识。
	ID string
	// ProviderInstanceID owns the credential.
	// ProviderInstanceID 是凭据所属供应商实例。
	ProviderInstanceID string
	// AuthMethodID selects one definition-owned authentication method.
	// AuthMethodID 选择一个定义拥有的认证方式。
	AuthMethodID string
	// Label is the editable management-facing account name.
	// Label 是管理界面可编辑的账号名称。
	Label string
	// PrincipalKey is the stable upstream account identity when known.
	// PrincipalKey 是已知时稳定的上游账号身份。
	PrincipalKey string
	// Fingerprint is the irreversible duplicate-detection value.
	// Fingerprint 是不可逆的排重值。
	Fingerprint string
	// ScopeRefs lists shared commercial and organizational scopes.
	// ScopeRefs 列出共享商业与组织作用域。
	ScopeRefs []providerconfig.ScopeReference
	// Secret contains transient credential bytes and is never persisted in configuration storage.
	// Secret 包含临时凭据字节且绝不持久化到配置存储。
	Secret []byte
}

// AddCredential stores a secret first and compensates it if metadata persistence fails.
// AddCredential 先保存 Secret，并在元数据持久化失败时进行补偿删除。
func (s *Service) AddCredential(ctx context.Context, input AddCredentialInput) (providerconfig.Credential, error) {
	credentialID := input.ID
	if credentialID == "" {
		generatedID, errID := generateID("cred_")
		if errID != nil {
			return providerconfig.Credential{}, errID
		}
		credentialID = generatedID
	}
	secretReference, errSecret := s.secrets.Put(ctx, input.Secret)
	if errSecret != nil {
		return providerconfig.Credential{}, errSecret
	}
	credential := providerconfig.Credential{
		ID:                 credentialID,
		ProviderInstanceID: input.ProviderInstanceID,
		AuthMethodID:       input.AuthMethodID,
		Label:              input.Label,
		PrincipalKey:       input.PrincipalKey,
		SecretRef:          secretReference,
		Fingerprint:        input.Fingerprint,
		Status:             providerconfig.CredentialActive,
		ScopeRefs:          append([]providerconfig.ScopeReference(nil), input.ScopeRefs...),
		Revision:           1,
	}
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.Credential{}, fmt.Errorf("save credential metadata: %v; compensate secret: %w", errSave, errDelete)
		}
		return providerconfig.Credential{}, errSave
	}
	return credential, nil
}

// AddBindingInput contains one endpoint-to-credential access relationship.
// AddBindingInput 包含一个端点到凭据的访问关系。
type AddBindingInput struct {
	// ID optionally supplies an externally allocated bind_ identifier.
	// ID 可选地提供一个外部分配的 bind_ 标识。
	ID string
	// ProviderInstanceID owns every referenced record.
	// ProviderInstanceID 是全部被引用记录所属实例。
	ProviderInstanceID string
	// ChannelID is the exact provider channel.
	// ChannelID 是精确供应商通道。
	ChannelID string
	// EndpointID references one endpoint in the same instance.
	// EndpointID 引用同一实例中的一个端点。
	EndpointID string
	// CredentialID references one credential in the same instance.
	// CredentialID 引用同一实例中的一个凭据。
	CredentialID string
	// AllowedModelIDs optionally restricts the binding to explicit models.
	// AllowedModelIDs 可选地将绑定限制到明确模型。
	AllowedModelIDs []string
	// Priority is the deterministic same-pool order.
	// Priority 是同一账号池内的确定性顺序。
	Priority int
}

// AddBinding persists one enabled same-instance access binding.
// AddBinding 持久化一个启用的同实例访问绑定。
func (s *Service) AddBinding(ctx context.Context, input AddBindingInput) (providerconfig.AccessBinding, error) {
	bindingID := input.ID
	if bindingID == "" {
		generatedID, errID := generateID("bind_")
		if errID != nil {
			return providerconfig.AccessBinding{}, errID
		}
		bindingID = generatedID
	}
	binding := providerconfig.AccessBinding{
		ID:                 bindingID,
		ProviderInstanceID: input.ProviderInstanceID,
		ChannelID:          input.ChannelID,
		EndpointID:         input.EndpointID,
		CredentialID:       input.CredentialID,
		AllowedModelIDs:    append([]string(nil), input.AllowedModelIDs...),
		Priority:           input.Priority,
		Enabled:            true,
		Revision:           1,
	}
	if errSave := s.configurations.SaveBinding(ctx, binding); errSave != nil {
		return providerconfig.AccessBinding{}, errSave
	}
	return binding, nil
}

// ActivateInstance verifies a locally closed access path and transitions the instance to ready.
// ActivateInstance 校验本地闭合访问路径并将实例转换为 Ready。
func (s *Service) ActivateInstance(ctx context.Context, instanceID string) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return providerconfig.ProviderInstance{}, errEndpoints
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return providerconfig.ProviderInstance{}, errCredentials
	}
	bindings, errBindings := s.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return providerconfig.ProviderInstance{}, errBindings
	}
	readyEndpoints := make(map[string]struct{})
	for _, endpoint := range endpoints {
		if endpoint.Status == providerconfig.EndpointReady {
			readyEndpoints[endpoint.ID] = struct{}{}
		}
	}
	activeCredentials := make(map[string]struct{})
	for _, credential := range credentials {
		if credential.Status == providerconfig.CredentialActive {
			activeCredentials[credential.ID] = struct{}{}
		}
	}
	configurationClosed := false
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		_, endpointReady := readyEndpoints[binding.EndpointID]
		_, credentialActive := activeCredentials[binding.CredentialID]
		if endpointReady && credentialActive {
			configurationClosed = true
			break
		}
	}
	if !configurationClosed {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: ready endpoint, active credential, and enabled binding are required", ErrConfigurationIncomplete)
	}
	if instance.Status == providerconfig.LifecycleReady {
		return instance, nil
	}
	instance.Status = providerconfig.LifecycleReady
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// SetCredentialStatusInput contains one explicit credential lifecycle transition.
// SetCredentialStatusInput 包含一次显式凭据生命周期转换。
type SetCredentialStatusInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance lookup.
	// ProviderInstanceID 是凭据所属实例并阻止跨实例查询。
	ProviderInstanceID string
	// CredentialID identifies the exact credential to update.
	// CredentialID 标识需要更新的精确凭据。
	CredentialID string
	// Status is the new explicit credential state.
	// Status 是新的显式凭据状态。
	Status providerconfig.CredentialStatus
	// CoolingUntil is required only when Status is cooling.
	// CoolingUntil 仅在 Status 为 Cooling 时必填。
	CoolingUntil *time.Time
}

// SetCredentialStatus updates one credential without reading or rewriting its secret.
// SetCredentialStatus 更新一个凭据且不读取或重写其 Secret。
func (s *Service) SetCredentialStatus(ctx context.Context, input SetCredentialStatusInput) (providerconfig.Credential, error) {
	credentials, errCredentials := s.configurations.ListCredentials(ctx, input.ProviderInstanceID)
	if errCredentials != nil {
		return providerconfig.Credential{}, errCredentials
	}
	var selected providerconfig.Credential
	found := false
	for _, credential := range credentials {
		if credential.ID == input.CredentialID {
			selected = credential
			found = true
			break
		}
	}
	if !found {
		return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, input.CredentialID)
	}
	selected.Status = input.Status
	selected.CoolingUntil = nil
	if input.Status == providerconfig.CredentialCooling {
		selected.CoolingUntil = cloneTimePointer(input.CoolingUntil)
	}
	selected.Revision++
	if errSave := s.configurations.SaveCredential(ctx, selected); errSave != nil {
		return providerconfig.Credential{}, errSave
	}
	return selected, nil
}

// CustomCatalogService persists user-declared models without system-provider commercial metadata.
// CustomCatalogService 持久化用户声明模型且不包含系统供应商商业元数据。
type CustomCatalogService struct {
	// configurations verifies custom provider ownership and builds local pools.
	// configurations 校验自定义供应商所有权并构建本地账号池。
	configurations providerconfig.Store
	// catalogs atomically persists the user-declared model catalog.
	// catalogs 原子持久化用户声明模型目录。
	catalogs catalog.Store
	// resolver derives client-safe account pool summaries.
	// resolver 派生客户端安全账号池摘要。
	resolver *resolve.Resolver
}

// NewCustomCatalogService creates one user-declared model catalog manager.
// NewCustomCatalogService 创建一个用户声明模型目录管理器。
func NewCustomCatalogService(configurations providerconfig.Store, catalogs catalog.Store) (*CustomCatalogService, error) {
	if configurations == nil || catalogs == nil {
		return nil, errors.New("provider configuration and catalog stores are required")
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return nil, errResolver
	}
	return &CustomCatalogService{configurations: configurations, catalogs: catalogs, resolver: targetResolver}, nil
}

// SaveCustomCatalogInput contains one complete user-declared model catalog revision.
// SaveCustomCatalogInput 包含一份完整用户声明模型目录修订。
type SaveCustomCatalogInput struct {
	// ProviderInstanceID owns every supplied model record.
	// ProviderInstanceID 是全部传入模型记录的所有者。
	ProviderInstanceID string
	// Models contains logical user-declared models.
	// Models 包含逻辑用户声明模型。
	Models []catalog.ProviderModel
	// Offerings binds models to the configured custom provider channel.
	// Offerings 将模型绑定到已配置自定义供应商通道。
	Offerings []catalog.ModelOffering
	// Profiles contains client-selectable context and capability shapes.
	// Profiles 包含客户端可选上下文与能力形态。
	Profiles []catalog.ExecutionProfile
	// ObservedAt records when the user configuration was accepted.
	// ObservedAt 记录用户配置被接受的时间。
	ObservedAt time.Time
}

// SaveCustomCatalog validates custom ownership, derives pools, and atomically saves the catalog.
// SaveCustomCatalog 校验自定义所有权、派生账号池并原子保存目录。
func (s *CustomCatalogService) SaveCustomCatalog(ctx context.Context, input SaveCustomCatalogInput) (catalog.Snapshot, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return catalog.Snapshot{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom {
		return catalog.Snapshot{}, errors.New("user-declared catalogs are allowed only for custom providers")
	}
	for _, model := range input.Models {
		if model.Source != catalog.ModelSourceUserDeclared || model.EntitlementMode != catalog.EntitlementAllBoundCredentials {
			return catalog.Snapshot{}, errors.New("custom provider models must be user-declared and available to all bound credentials")
		}
	}
	revision := uint64(1)
	current, errCurrent := s.catalogs.Get(ctx, instance.ID)
	if errCurrent == nil {
		revision = current.Revision + 1
	} else if !errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
		return catalog.Snapshot{}, errCurrent
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models:             append([]catalog.ProviderModel(nil), input.Models...),
		Offerings:          append([]catalog.ModelOffering(nil), input.Offerings...),
		Profiles:           append([]catalog.ExecutionProfile(nil), input.Profiles...),
		Revision:           revision,
		ObservedAt:         input.ObservedAt,
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	pools, errPools := s.resolver.SummarizeSnapshot(ctx, snapshot, input.ObservedAt, revision)
	if errPools != nil {
		return catalog.Snapshot{}, errPools
	}
	snapshot.Pools = pools
	if errSave := s.catalogs.Save(ctx, snapshot); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return snapshot, nil
}

// cloneTimePointer copies one optional lifecycle timestamp.
// cloneTimePointer 复制一个可选生命周期时间戳。
func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// generateID creates one portable lowercase random domain identifier.
// generateID 创建一个可移植的小写随机领域标识。
func generateID(prefix string) (string, error) {
	randomBytes := make([]byte, 12)
	if _, errRandom := rand.Read(randomBytes); errRandom != nil {
		return "", fmt.Errorf("generate %s identifier: %w", prefix, errRandom)
	}
	return prefix + hex.EncodeToString(randomBytes), nil
}
