// Package management coordinates provider configuration workflows and safe client queries.
// management 包协调供应商配置工作流与客户端安全查询。
package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// OnboardSystemProviderInput contains the only operator-authored fields for one atomic system-provider onboarding.
// OnboardSystemProviderInput 包含一次原子系统供应商录入仅由操作员填写的字段。
type OnboardSystemProviderInput struct {
	// DefinitionID selects one exact code-owned provider variant.
	// DefinitionID 选择一个精确的代码拥有供应商变体。
	DefinitionID string
	// Handle is the stable workspace-visible routing alias.
	// Handle 是工作区可见的稳定路由别名。
	Handle string
	// DisplayName is the editable management-facing instance name.
	// DisplayName 是可编辑的管理端实例名称。
	DisplayName string
	// AuthMethodID selects one authentication method declared by the definition.
	// AuthMethodID 选择定义声明的一种认证方式。
	AuthMethodID string
	// CredentialLabel is the safe operator-visible account label.
	// CredentialLabel 是安全且操作员可见的账号标签。
	CredentialLabel string
	// PrincipalKey is the provider-reported stable account identity when available.
	// PrincipalKey 是可用时供应商报告的稳定账号身份。
	PrincipalKey string
	// Secret contains transient credential material and is never written to SQLite.
	// Secret 包含临时凭据材料且绝不写入 SQLite。
	Secret []byte
}

// OnboardSystemProvider atomically creates one complete system-provider access path with secret compensation.
// OnboardSystemProvider 通过秘密补偿原子创建一条完整系统供应商访问路径。
func (s *Service) OnboardSystemProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return s.onboardSystemProvider(ctx, input, false)
}

// OnboardKimiDeviceProvider atomically stores one server-acquired and format-validated Kimi device credential.
// OnboardKimiDeviceProvider 原子存储一个由服务端获取且格式已校验的 Kimi 设备凭据。
func (s *Service) OnboardKimiDeviceProvider(ctx context.Context, input OnboardSystemProviderInput) (providerconfig.SystemOnboarding, error) {
	return s.onboardSystemProvider(ctx, input, true)
}

// onboardSystemProvider enforces the acquisition boundary before committing one complete provider graph.
// onboardSystemProvider 在提交完整供应商图之前强制执行凭据获取边界。
func (s *Service) onboardSystemProvider(ctx context.Context, input OnboardSystemProviderInput, serverAcquiredDeviceCredential bool) (providerconfig.SystemOnboarding, error) {
	definition, errDefinition := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errDefinition != nil {
		return providerconfig.SystemOnboarding{}, errDefinition
	}
	authMethod, authMethodExists := definition.AuthMethod(input.AuthMethodID)
	if definition.Kind != providerconfig.DefinitionKindSystem || !authMethodExists {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("system provider onboarding requires an exact system definition and authentication method")
	}
	if serverAcquiredDeviceCredential {
		if definition.DriverID != "kimi" || authMethod.Type != providerconfig.AuthMethodDeviceFlow {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("server-acquired Kimi onboarding requires a Kimi device-flow definition")
		}
		if _, errToken := providerkimi.UnmarshalToken(input.Secret); errToken != nil {
			return providerconfig.SystemOnboarding{}, errToken
		}
	} else if authMethod.Type == providerconfig.AuthMethodDeviceFlow || authMethod.Type == providerconfig.AuthMethodOAuth {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("interactive provider credentials require their server-owned authorization workflow")
	}
	if len(input.Secret) == 0 {
		return providerconfig.SystemOnboarding{}, fmt.Errorf("system provider onboarding secret is required")
	}
	secretReference, errSecret := s.secrets.Put(ctx, input.Secret)
	if errSecret != nil {
		return providerconfig.SystemOnboarding{}, errSecret
	}
	onboarding, errBuild := s.buildSystemOnboarding(definition, input, secretReference)
	if errBuild != nil {
		_ = s.secrets.Delete(context.WithoutCancel(ctx), secretReference)
		return providerconfig.SystemOnboarding{}, errBuild
	}
	if errSave := s.configurations.SaveSystemOnboarding(ctx, onboarding); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), secretReference); errDelete != nil {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("save system provider onboarding: %w; compensate secret: %v", errSave, errDelete)
		}
		return providerconfig.SystemOnboarding{}, errSave
	}
	snapshot, errCatalog := buildSystemCatalog(onboarding, definition, s.now().UTC())
	if errCatalog == nil {
		errCatalog = s.catalogs.Save(ctx, snapshot)
	}
	if errCatalog != nil {
		compensationContext := context.WithoutCancel(ctx)
		errCatalogCleanup := s.catalogs.Delete(compensationContext, onboarding.Instance.ID)
		if errors.Is(errCatalogCleanup, catalog.ErrSnapshotNotFound) {
			errCatalogCleanup = nil
		}
		errConfigurationCleanup := s.configurations.DeleteSystemOnboarding(compensationContext, onboarding)
		errSecretCleanup := s.secrets.Delete(compensationContext, secretReference)
		if errCatalogCleanup != nil || errConfigurationCleanup != nil || errSecretCleanup != nil {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("save system provider catalog: %w; compensate catalog: %v; compensate configuration: %v; compensate secret: %v", errCatalog, errCatalogCleanup, errConfigurationCleanup, errSecretCleanup)
		}
		return providerconfig.SystemOnboarding{}, errCatalog
	}
	return onboarding, nil
}

// buildSystemOnboarding constructs server-owned identifiers, fixed endpoints, and bindings for one definition.
// buildSystemOnboarding 为一个定义构建服务端拥有的标识、固定端点和绑定。
func (s *Service) buildSystemOnboarding(definition providerconfig.ProviderDefinition, input OnboardSystemProviderInput, secretReference string) (providerconfig.SystemOnboarding, error) {
	instanceID, errInstanceID := generateID("pvi_")
	if errInstanceID != nil {
		return providerconfig.SystemOnboarding{}, errInstanceID
	}
	credentialID, errCredentialID := generateID("cred_")
	if errCredentialID != nil {
		return providerconfig.SystemOnboarding{}, errCredentialID
	}
	now := s.now().UTC()
	// fingerprint is derived by the trusted service so clients cannot choose duplicate-detection metadata.
	// fingerprint 由受信任服务派生，客户端不能选择排重元数据。
	fingerprintBytes := sha256.Sum256(input.Secret)
	onboarding := providerconfig.SystemOnboarding{
		Instance:   providerconfig.ProviderInstance{ID: instanceID, DefinitionID: definition.ID, Handle: input.Handle, DisplayName: input.DisplayName, Status: providerconfig.LifecycleReady, Revision: 1, DefinitionRevision: definition.Revision, CreatedAt: now, UpdatedAt: now},
		Credential: providerconfig.Credential{ID: credentialID, ProviderInstanceID: instanceID, AuthMethodID: input.AuthMethodID, Label: input.CredentialLabel, PrincipalKey: input.PrincipalKey, SecretRef: secretReference, Fingerprint: hex.EncodeToString(fingerprintBytes[:]), Status: providerconfig.CredentialActive, Revision: 1},
	}
	// channelPresets rejects ambiguous multi-region definitions until management explicitly selects one preset.
	// channelPresets 在管理端显式选择预设前拒绝存在歧义的多区域定义。
	channelPresets := make(map[string]providerconfig.EndpointPreset, len(definition.EndpointPresets))
	for _, preset := range definition.EndpointPresets {
		if _, exists := channelPresets[preset.ChannelID]; exists {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("provider definition channel %q has multiple endpoint presets and requires explicit preset selection", preset.ChannelID)
		}
		channelPresets[preset.ChannelID] = preset
	}
	for _, channel := range definition.Channels {
		if !slices.Contains(channel.AuthMethodIDs, input.AuthMethodID) {
			continue
		}
		preset, exists := channelPresets[channel.ID]
		if !exists {
			return providerconfig.SystemOnboarding{}, fmt.Errorf("provider definition channel %q has no onboarding endpoint preset", channel.ID)
		}
		endpointID, errEndpointID := generateID("ep_")
		if errEndpointID != nil {
			return providerconfig.SystemOnboarding{}, errEndpointID
		}
		bindingID, errBindingID := generateID("bind_")
		if errBindingID != nil {
			return providerconfig.SystemOnboarding{}, errBindingID
		}
		onboarding.Endpoints = append(onboarding.Endpoints, providerconfig.Endpoint{ID: endpointID, ProviderInstanceID: instanceID, ChannelID: channel.ID, BaseURL: preset.BaseURL, Region: preset.Region, Status: providerconfig.EndpointReady, Revision: 1})
		onboarding.Bindings = append(onboarding.Bindings, providerconfig.AccessBinding{ID: bindingID, ProviderInstanceID: instanceID, ChannelID: channel.ID, EndpointID: endpointID, CredentialID: credentialID, Priority: channel.Priority, Enabled: true, Revision: 1})
	}
	return onboarding, nil
}

var (
	// ErrConfigurationIncomplete reports an instance that cannot enter ready state.
	// ErrConfigurationIncomplete 表示供应商实例无法进入 Ready 状态。
	ErrConfigurationIncomplete = errors.New("provider configuration is incomplete")
	// ErrSystemDefinitionImmutable reports a management mutation attempted against a code-owned system definition.
	// ErrSystemDefinitionImmutable 表示管理变更尝试作用于代码拥有的系统定义。
	ErrSystemDefinitionImmutable = errors.New("system provider definition is immutable")
	// ErrCustomCatalogRequiresCustomProvider reports a user-declared catalog operation attempted against a system provider.
	// ErrCustomCatalogRequiresCustomProvider 表示用户声明目录操作尝试作用于系统供应商。
	ErrCustomCatalogRequiresCustomProvider = errors.New("user-declared catalogs are allowed only for custom providers")
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
	// catalogs persists instance-isolated system model metadata created during onboarding.
	// catalogs 持久化录入期间创建的实例隔离系统模型元数据。
	catalogs catalog.Store
	// now returns the authoritative lifecycle timestamp.
	// now 返回权威生命周期时间戳。
	now func() time.Time
}

// NewService creates one provider configuration application service.
// NewService 创建一个供应商配置应用服务。
func NewService(configurations providerconfig.Store, secrets secret.Store, catalogs catalog.Store) (*Service, error) {
	if configurations == nil || secrets == nil || catalogs == nil {
		return nil, errors.New("provider configuration, secret, and catalog stores are required")
	}
	return &Service{configurations: configurations, secrets: secrets, catalogs: catalogs, now: time.Now}, nil
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
	definition := customDefinition(definitionID, 1, input)
	if errSave := s.configurations.SaveCustomDefinition(ctx, definition); errSave != nil {
		return providerconfig.ProviderDefinition{}, errSave
	}
	return definition, nil
}

// UpdateCustomDefinitionInput contains every editable field of one existing custom provider definition.
// UpdateCustomDefinitionInput 包含一个既有自定义供应商定义的全部可编辑字段。
type UpdateCustomDefinitionInput struct {
	// DefinitionID identifies the exact custom definition to replace.
	// DefinitionID 标识要替换的精确自定义定义。
	DefinitionID string
	// DisplayName is the replacement management-facing provider name.
	// DisplayName 是替换后的管理界面供应商名称。
	DisplayName string
	// ProtocolProfileID selects the replacement executable protocol profile.
	// ProtocolProfileID 选择替换后的可执行协议规格。
	ProtocolProfileID string
	// AuthMethod selects the replacement custom-provider authentication mechanism.
	// AuthMethod 选择替换后的自定义供应商认证机制。
	AuthMethod providerconfig.AuthMethodType
}

// UpdateCustomDefinition replaces one custom definition and marks its existing instances as migration-required.
// UpdateCustomDefinition 替换一个自定义定义并将其既有实例标记为需要迁移。
func (s *Service) UpdateCustomDefinition(ctx context.Context, input UpdateCustomDefinitionInput) (providerconfig.ProviderDefinition, error) {
	current, errCurrent := s.configurations.GetDefinition(ctx, input.DefinitionID)
	if errCurrent != nil {
		return providerconfig.ProviderDefinition{}, errCurrent
	}
	if current.Kind != providerconfig.DefinitionKindCustom {
		return providerconfig.ProviderDefinition{}, fmt.Errorf("%w: %s", ErrSystemDefinitionImmutable, current.ID)
	}
	// updated rebuilds the constrained one-channel custom shape rather than preserving incompatible stale fields.
	// updated 重建受约束的单通道自定义形态，而不是保留可能不兼容的旧字段。
	updated := customDefinition(current.ID, current.Revision+1, CreateCustomDefinitionInput{
		DisplayName:       input.DisplayName,
		ProtocolProfileID: input.ProtocolProfileID,
		AuthMethod:        input.AuthMethod,
	})
	if errSave := s.configurations.SaveCustomDefinition(ctx, updated); errSave != nil {
		return providerconfig.ProviderDefinition{}, errSave
	}
	instances, errInstances := s.configurations.ListInstances(ctx, current.ID)
	if errInstances != nil {
		return providerconfig.ProviderDefinition{}, errInstances
	}
	// migrationTime is shared so all transitioned instances form one management operation snapshot.
	// migrationTime 被共享，使全部转换实例形成一次管理操作快照。
	migrationTime := s.now().UTC()
	for _, instance := range instances {
		instance.DefinitionRevision = updated.Revision
		instance.Status = providerconfig.LifecycleMigrationRequired
		instance.Revision++
		instance.UpdatedAt = migrationTime
		if errSaveInstance := s.configurations.SaveInstance(ctx, instance); errSaveInstance != nil {
			return providerconfig.ProviderDefinition{}, fmt.Errorf("mark provider instance %s migration required: %w", instance.ID, errSaveInstance)
		}
	}
	return updated, nil
}

// customDefinition builds the sole supported generic custom provider shape from explicit management input.
// customDefinition 根据显式管理输入构建唯一受支持的通用自定义供应商形态。
func customDefinition(definitionID string, revision uint64, input CreateCustomDefinitionInput) providerconfig.ProviderDefinition {
	return providerconfig.ProviderDefinition{
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
		Revision: revision,
	}
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

// UpdateInstanceInput contains editable identity fields of one existing provider instance.
// UpdateInstanceInput 包含一个既有供应商实例的可编辑身份字段。
type UpdateInstanceInput struct {
	// ProviderInstanceID identifies the exact instance to update.
	// ProviderInstanceID 标识要更新的精确实例。
	ProviderInstanceID string
	// Handle is the replacement stable workspace routing alias.
	// Handle 是替换后的稳定工作区路由别名。
	Handle string
	// DisplayName is the replacement management-facing instance name.
	// DisplayName 是替换后的管理界面实例名称。
	DisplayName string
}

// UpdateInstance replaces editable instance identity fields without altering provider ownership or lifecycle.
// UpdateInstance 替换可编辑实例身份字段且不改变供应商归属或生命周期。
func (s *Service) UpdateInstance(ctx context.Context, input UpdateInstanceInput) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	instance.Handle = input.Handle
	instance.DisplayName = input.DisplayName
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
	if errSave := s.configurations.SaveInstance(ctx, instance); errSave != nil {
		return providerconfig.ProviderInstance{}, errSave
	}
	return instance, nil
}

// SetInstanceEnabled transitions one instance to disabled or validates it back into ready state.
// SetInstanceEnabled 将一个实例转换为禁用状态或校验后恢复为就绪状态。
func (s *Service) SetInstanceEnabled(ctx context.Context, instanceID string, enabled bool) (providerconfig.ProviderInstance, error) {
	if enabled {
		return s.ActivateInstance(ctx, instanceID)
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	if instance.Status == providerconfig.LifecycleDisabled {
		return instance, nil
	}
	instance.Status = providerconfig.LifecycleDisabled
	instance.Revision++
	instance.UpdatedAt = s.now().UTC()
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

// UpdateEndpointInput contains every editable field of one existing endpoint.
// UpdateEndpointInput 包含一个既有端点的全部可编辑字段。
type UpdateEndpointInput struct {
	// ProviderInstanceID owns the endpoint and prevents cross-instance updates.
	// ProviderInstanceID 拥有该端点并阻止跨实例更新。
	ProviderInstanceID string
	// EndpointID identifies the exact endpoint to replace.
	// EndpointID 标识要替换的精确端点。
	EndpointID string
	// ChannelID selects the replacement provider channel.
	// ChannelID 选择替换后的供应商通道。
	ChannelID string
	// BaseURL is the replacement validated upstream base URL.
	// BaseURL 是替换后的已校验上游基础 URL。
	BaseURL string
	// Region is the replacement optional provider-defined region.
	// Region 是替换后的可选供应商定义区域。
	Region string
	// Status is the replacement endpoint availability state.
	// Status 是替换后的端点可用性状态。
	Status providerconfig.EndpointStatus
}

// UpdateEndpoint replaces one same-instance endpoint while preserving its immutable identifier.
// UpdateEndpoint 替换一个同实例端点，同时保留其不可变标识。
func (s *Service) UpdateEndpoint(ctx context.Context, input UpdateEndpointInput) (providerconfig.Endpoint, error) {
	endpoint, errEndpoint := s.endpoint(ctx, input.ProviderInstanceID, input.EndpointID)
	if errEndpoint != nil {
		return providerconfig.Endpoint{}, errEndpoint
	}
	endpoint.ChannelID = input.ChannelID
	endpoint.BaseURL = input.BaseURL
	endpoint.Region = input.Region
	endpoint.Status = input.Status
	endpoint.Revision++
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
	if errAuth := s.validateDirectSecretAuthMethod(ctx, input.ProviderInstanceID, input.AuthMethodID); errAuth != nil {
		return providerconfig.Credential{}, errAuth
	}
	if len(input.Secret) == 0 {
		return providerconfig.Credential{}, fmt.Errorf("provider credential secret is required")
	}
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

// UpdateCredentialInput contains editable non-secret fields of one existing credential.
// UpdateCredentialInput 包含一个既有凭据的可编辑非秘密字段。
type UpdateCredentialInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance updates.
	// ProviderInstanceID 拥有该凭据并阻止跨实例更新。
	ProviderInstanceID string
	// CredentialID identifies the exact credential to update.
	// CredentialID 标识要更新的精确凭据。
	CredentialID string
	// Label is the replacement management-facing credential label.
	// Label 是替换后的管理界面凭据标签。
	Label string
	// PrincipalKey is the replacement optional upstream account identity.
	// PrincipalKey 是替换后的可选上游账号身份。
	PrincipalKey string
	// Fingerprint is the replacement irreversible duplicate-detection value.
	// Fingerprint 是替换后的不可逆排重值。
	Fingerprint string
	// ScopeRefs is the replacement set of commercial and organizational scopes.
	// ScopeRefs 是替换后的商业和组织作用域集合。
	ScopeRefs []providerconfig.ScopeReference
}

// UpdateCredential replaces non-secret credential metadata without reading or returning secret bytes.
// UpdateCredential 替换非秘密凭据元数据且不读取或返回 Secret 字节。
func (s *Service) UpdateCredential(ctx context.Context, input UpdateCredentialInput) (providerconfig.Credential, error) {
	credential, errCredential := s.credential(ctx, input.ProviderInstanceID, input.CredentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	credential.Label = input.Label
	credential.PrincipalKey = input.PrincipalKey
	credential.Fingerprint = input.Fingerprint
	credential.ScopeRefs = append([]providerconfig.ScopeReference(nil), input.ScopeRefs...)
	credential.Revision++
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		return providerconfig.Credential{}, errSave
	}
	return credential, nil
}

// RotateCredentialSecretInput contains the only fields needed to replace credential secret bytes safely.
// RotateCredentialSecretInput 包含安全替换凭据 Secret 字节所需的唯一字段。
type RotateCredentialSecretInput struct {
	// ProviderInstanceID owns the credential and prevents cross-instance rotation.
	// ProviderInstanceID 拥有该凭据并阻止跨实例轮换。
	ProviderInstanceID string
	// CredentialID identifies the exact credential whose secret changes.
	// CredentialID 标识其 Secret 发生变化的精确凭据。
	CredentialID string
	// Secret contains the transient replacement credential bytes.
	// Secret 包含临时替换凭据字节。
	Secret []byte
	// Fingerprint is the replacement irreversible duplicate-detection value for the new secret.
	// Fingerprint 是新 Secret 的替换不可逆排重值。
	Fingerprint string
}

// RotateCredentialSecret writes a replacement secret before changing metadata and cleans up the old secret afterwards.
// RotateCredentialSecret 在变更元数据前写入替换 Secret，并在之后清理旧 Secret。
func (s *Service) RotateCredentialSecret(ctx context.Context, input RotateCredentialSecretInput) (providerconfig.Credential, error) {
	credential, errCredential := s.credential(ctx, input.ProviderInstanceID, input.CredentialID)
	if errCredential != nil {
		return providerconfig.Credential{}, errCredential
	}
	if errAuth := s.validateDirectSecretAuthMethod(ctx, input.ProviderInstanceID, credential.AuthMethodID); errAuth != nil {
		return providerconfig.Credential{}, errAuth
	}
	if len(input.Secret) == 0 {
		return providerconfig.Credential{}, fmt.Errorf("replacement provider credential secret is required")
	}
	// replacementReference is written first so the existing credential remains usable if protection fails.
	// replacementReference 先写入，因此保护失败时既有凭据仍可用。
	replacementReference, errPut := s.secrets.Put(ctx, input.Secret)
	if errPut != nil {
		return providerconfig.Credential{}, errPut
	}
	previousReference := credential.SecretRef
	credential.SecretRef = replacementReference
	credential.Fingerprint = input.Fingerprint
	credential.Revision++
	if errSave := s.configurations.SaveCredential(ctx, credential); errSave != nil {
		if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), replacementReference); errDelete != nil {
			return providerconfig.Credential{}, fmt.Errorf("save rotated credential metadata: %v; compensate replacement secret: %w", errSave, errDelete)
		}
		return providerconfig.Credential{}, errSave
	}
	if errDelete := s.secrets.Delete(context.WithoutCancel(ctx), previousReference); errDelete != nil {
		return providerconfig.Credential{}, fmt.Errorf("persisted rotated credential but could not delete previous secret: %w", errDelete)
	}
	return credential, nil
}

// validateDirectSecretAuthMethod permits operator-supplied bytes only for non-interactive authentication methods declared by the exact instance definition.
// validateDirectSecretAuthMethod 仅允许精确实例定义声明的非交互认证方式接收操作员提供的字节。
func (s *Service) validateDirectSecretAuthMethod(ctx context.Context, instanceID string, authMethodID string) error {
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	authMethod, exists := definition.AuthMethod(authMethodID)
	if !exists {
		return fmt.Errorf("provider credential requires an exact definition-owned authentication method")
	}
	if authMethod.Type == providerconfig.AuthMethodDeviceFlow || authMethod.Type == providerconfig.AuthMethodOAuth {
		return fmt.Errorf("interactive provider credentials require their server-owned authorization workflow")
	}
	return nil
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

// UpdateBindingInput contains every editable field of one existing access binding.
// UpdateBindingInput 包含一个既有访问绑定的全部可编辑字段。
type UpdateBindingInput struct {
	// ProviderInstanceID owns all referenced records and prevents cross-instance updates.
	// ProviderInstanceID 拥有全部引用记录并阻止跨实例更新。
	ProviderInstanceID string
	// BindingID identifies the exact binding to replace.
	// BindingID 标识要替换的精确绑定。
	BindingID string
	// ChannelID is the replacement exact provider channel.
	// ChannelID 是替换后的精确供应商通道。
	ChannelID string
	// EndpointID references the replacement same-instance endpoint.
	// EndpointID 引用替换后的同实例端点。
	EndpointID string
	// CredentialID references the replacement same-instance credential.
	// CredentialID 引用替换后的同实例凭据。
	CredentialID string
	// AllowedModelIDs restricts the replacement binding to explicit models when non-empty.
	// AllowedModelIDs 非空时将替换绑定限制到明确模型。
	AllowedModelIDs []string
	// Priority is the replacement deterministic same-pool order.
	// Priority 是替换后的确定性同账号池顺序。
	Priority int
	// Enabled controls whether the binding participates in resolution.
	// Enabled 控制绑定是否参与解析。
	Enabled bool
}

// UpdateBinding replaces one same-instance access binding while preserving its immutable identifier.
// UpdateBinding 替换一个同实例访问绑定，同时保留其不可变标识。
func (s *Service) UpdateBinding(ctx context.Context, input UpdateBindingInput) (providerconfig.AccessBinding, error) {
	binding, errBinding := s.binding(ctx, input.ProviderInstanceID, input.BindingID)
	if errBinding != nil {
		return providerconfig.AccessBinding{}, errBinding
	}
	binding.ChannelID = input.ChannelID
	binding.EndpointID = input.EndpointID
	binding.CredentialID = input.CredentialID
	binding.AllowedModelIDs = append([]string(nil), input.AllowedModelIDs...)
	binding.Priority = input.Priority
	binding.Enabled = input.Enabled
	binding.Revision++
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

// endpoint returns one endpoint only when it belongs to the requested provider instance.
// endpoint 仅在端点属于请求的供应商实例时返回该端点。
func (s *Service) endpoint(ctx context.Context, instanceID string, endpointID string) (providerconfig.Endpoint, error) {
	endpoints, errEndpoints := s.configurations.ListEndpoints(ctx, instanceID)
	if errEndpoints != nil {
		return providerconfig.Endpoint{}, errEndpoints
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == endpointID {
			return endpoint, nil
		}
	}
	return providerconfig.Endpoint{}, fmt.Errorf("%w: provider endpoint %s", providerconfig.ErrNotFound, endpointID)
}

// credential returns one credential only when it belongs to the requested provider instance.
// credential 仅在凭据属于请求的供应商实例时返回该凭据。
func (s *Service) credential(ctx context.Context, instanceID string, credentialID string) (providerconfig.Credential, error) {
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return providerconfig.Credential{}, errCredentials
	}
	for _, credential := range credentials {
		if credential.ID == credentialID {
			return credential, nil
		}
	}
	return providerconfig.Credential{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
}

// binding returns one access binding only when it belongs to the requested provider instance.
// binding 仅在访问绑定属于请求的供应商实例时返回该绑定。
func (s *Service) binding(ctx context.Context, instanceID string, bindingID string) (providerconfig.AccessBinding, error) {
	bindings, errBindings := s.configurations.ListBindings(ctx, instanceID)
	if errBindings != nil {
		return providerconfig.AccessBinding{}, errBindings
	}
	for _, binding := range bindings {
		if binding.ID == bindingID {
			return binding, nil
		}
	}
	return providerconfig.AccessBinding{}, fmt.Errorf("%w: access binding %s", providerconfig.ErrNotFound, bindingID)
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
	instance, errInstance := s.customInstance(ctx, input.ProviderInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
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
	// models copies caller data before the service owns the catalog revision metadata.
	// models 在服务接管目录修订元数据前复制调用方数据。
	models := append([]catalog.ProviderModel(nil), input.Models...)
	for index := range models {
		models[index].Revision = revision
	}
	// offerings copies caller data before assigning the authoritative catalog and capability revisions.
	// offerings 在分配权威目录和能力修订前复制调用方数据。
	offerings := append([]catalog.ModelOffering(nil), input.Offerings...)
	for index := range offerings {
		offerings[index].CapabilityRevision = revision
		offerings[index].Revision = revision
	}
	// profiles copies caller data before assigning the authoritative catalog and capability revisions.
	// profiles 在分配权威目录和能力修订前复制调用方数据。
	profiles := append([]catalog.ExecutionProfile(nil), input.Profiles...)
	for index := range profiles {
		profiles[index].CapabilityRevision = revision
		profiles[index].Revision = revision
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models:             models,
		Offerings:          offerings,
		Profiles:           profiles,
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

// GetCustomCatalog returns the current user-declared catalog only for a custom provider instance.
// GetCustomCatalog 仅为自定义供应商实例返回当前用户声明的目录。
func (s *CustomCatalogService) GetCustomCatalog(ctx context.Context, providerInstanceID string) (catalog.Snapshot, error) {
	instance, errInstance := s.customInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	return s.catalogs.Get(ctx, instance.ID)
}

// customInstance verifies that one instance is owned by a user-editable custom provider definition.
// customInstance 校验一个实例由可编辑的自定义供应商定义拥有。
func (s *CustomCatalogService) customInstance(ctx context.Context, providerInstanceID string) (providerconfig.ProviderInstance, error) {
	instance, errInstance := s.configurations.GetInstance(ctx, providerInstanceID)
	if errInstance != nil {
		return providerconfig.ProviderInstance{}, errInstance
	}
	definition, errDefinition := s.configurations.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return providerconfig.ProviderInstance{}, errDefinition
	}
	if definition.Kind != providerconfig.DefinitionKindCustom {
		return providerconfig.ProviderInstance{}, fmt.Errorf("%w: %s", ErrCustomCatalogRequiresCustomProvider, instance.ID)
	}
	return instance, nil
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
