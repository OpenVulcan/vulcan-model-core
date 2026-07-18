package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Store defines persistence behavior for custom definitions and provider instance configuration.
// Store 定义自定义定义和供应商实例配置的持久化行为。
type Store interface {
	// SaveCustomDefinition creates or updates one custom provider definition.
	// SaveCustomDefinition 创建或更新一个自定义供应商定义。
	SaveCustomDefinition(context.Context, ProviderDefinition) error
	// GetDefinition resolves one system or custom provider definition.
	// GetDefinition 解析一个系统或自定义供应商定义。
	GetDefinition(context.Context, string) (ProviderDefinition, error)
	// ListDefinitions returns all visible system and custom provider definitions.
	// ListDefinitions 返回全部可见的系统和自定义供应商定义。
	ListDefinitions(context.Context) ([]ProviderDefinition, error)
	// SaveInstance creates or updates one provider instance.
	// SaveInstance 创建或更新一个供应商实例。
	SaveInstance(context.Context, ProviderInstance) error
	// GetInstance returns one provider instance.
	// GetInstance 返回一个供应商实例。
	GetInstance(context.Context, string) (ProviderInstance, error)
	// ListInstances returns provider instances, optionally filtered by definition identifier.
	// ListInstances 返回供应商实例，并可按定义标识筛选。
	ListInstances(context.Context, string) ([]ProviderInstance, error)
	// SaveEndpoint creates or updates one endpoint.
	// SaveEndpoint 创建或更新一个端点。
	SaveEndpoint(context.Context, Endpoint) error
	// ListEndpoints returns endpoints owned by one provider instance.
	// ListEndpoints 返回一个供应商实例拥有的端点。
	ListEndpoints(context.Context, string) ([]Endpoint, error)
	// SaveCredential creates or updates one non-secret credential record.
	// SaveCredential 创建或更新一个非秘密凭据记录。
	SaveCredential(context.Context, Credential) error
	// ListCredentials returns credentials owned by one provider instance.
	// ListCredentials 返回一个供应商实例拥有的凭据。
	ListCredentials(context.Context, string) ([]Credential, error)
	// SaveBinding creates or updates one access binding.
	// SaveBinding 创建或更新一个访问绑定。
	SaveBinding(context.Context, AccessBinding) error
	// ListBindings returns bindings owned by one provider instance.
	// ListBindings 返回一个供应商实例拥有的访问绑定。
	ListBindings(context.Context, string) ([]AccessBinding, error)
}

// MemoryStore is a thread-safe configuration store for tests and framework bootstrap.
// MemoryStore 是用于测试和框架启动的线程安全配置存储。
type MemoryStore struct {
	// mu protects all persisted configuration maps.
	// mu 保护全部持久化配置映射。
	mu sync.RWMutex
	// protocols validates custom provider protocol ownership.
	// protocols 校验自定义供应商协议所有权。
	protocols *ProtocolRegistry
	// systems resolves code-owned immutable provider definitions.
	// systems 解析代码拥有的不可变供应商定义。
	systems *SystemRegistry
	// customDefinitions stores user-owned provider definitions.
	// customDefinitions 存储用户拥有的供应商定义。
	customDefinitions map[string]ProviderDefinition
	// instances stores provider instances by immutable identifier.
	// instances 按不可变标识存储供应商实例。
	instances map[string]ProviderInstance
	// endpoints stores endpoints by immutable identifier.
	// endpoints 按不可变标识存储端点。
	endpoints map[string]Endpoint
	// credentials stores non-secret credentials by immutable identifier.
	// credentials 按不可变标识存储非秘密凭据。
	credentials map[string]Credential
	// bindings stores access bindings by immutable identifier.
	// bindings 按不可变标识存储访问绑定。
	bindings map[string]AccessBinding
}

// NewMemoryStore creates an empty configuration store backed by immutable registries.
// NewMemoryStore 创建一个由不可变注册表支持的空配置存储。
func NewMemoryStore(protocols *ProtocolRegistry, systems *SystemRegistry) (*MemoryStore, error) {
	if protocols == nil || systems == nil {
		return nil, errors.New("protocol and system provider registries are required")
	}
	return &MemoryStore{
		protocols:         protocols,
		systems:           systems,
		customDefinitions: make(map[string]ProviderDefinition),
		instances:         make(map[string]ProviderInstance),
		endpoints:         make(map[string]Endpoint),
		credentials:       make(map[string]Credential),
		bindings:          make(map[string]AccessBinding),
	}, nil
}

// SaveCustomDefinition creates or updates one validated custom definition.
// SaveCustomDefinition 创建或更新一个经过校验的自定义定义。
func (s *MemoryStore) SaveCustomDefinition(ctx context.Context, definition ProviderDefinition) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := ValidateCustomDefinition(definition, s.protocols); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.customDefinitions[definition.ID]; exists && definition.Revision <= current.Revision {
		return invalid("custom provider definition revision must increase")
	}
	s.customDefinitions[definition.ID] = cloneProviderDefinition(definition)
	return nil
}

// GetDefinition resolves one system or custom provider definition.
// GetDefinition 解析一个系统或自定义供应商定义。
func (s *MemoryStore) GetDefinition(ctx context.Context, definitionID string) (ProviderDefinition, error) {
	if err := contextError(ctx); err != nil {
		return ProviderDefinition{}, err
	}
	if definition, exists := s.systems.Lookup(definitionID); exists {
		return definition, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	definition, exists := s.customDefinitions[definitionID]
	if !exists {
		return ProviderDefinition{}, fmt.Errorf("%w: provider definition %s", ErrNotFound, definitionID)
	}
	return cloneProviderDefinition(definition), nil
}

// ListDefinitions returns stable sorted system and custom definition snapshots.
// ListDefinitions 返回稳定排序的系统和自定义定义快照。
func (s *MemoryStore) ListDefinitions(ctx context.Context) ([]ProviderDefinition, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	definitions := s.systems.List()
	s.mu.RLock()
	for _, definition := range s.customDefinitions {
		definitions = append(definitions, cloneProviderDefinition(definition))
	}
	s.mu.RUnlock()
	sort.Slice(definitions, func(left int, right int) bool {
		return definitions[left].ID < definitions[right].ID
	})
	return definitions, nil
}

// SaveInstance creates or updates one provider instance after definition validation.
// SaveInstance 在定义校验后创建或更新一个供应商实例。
func (s *MemoryStore) SaveInstance(ctx context.Context, instance ProviderInstance) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := instance.Validate(); err != nil {
		return err
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if instance.DefinitionRevision != definition.Revision {
		return invalid("provider instance definition revision does not match current definition")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for instanceID, current := range s.instances {
		if current.Handle == instance.Handle && instanceID != instance.ID {
			return fmt.Errorf("%w: provider handle %s", ErrAlreadyRegistered, instance.Handle)
		}
	}
	if current, exists := s.instances[instance.ID]; exists && instance.Revision <= current.Revision {
		return invalid("provider instance revision must increase")
	}
	s.instances[instance.ID] = cloneProviderInstance(instance)
	return nil
}

// GetInstance returns one provider instance snapshot.
// GetInstance 返回一个供应商实例快照。
func (s *MemoryStore) GetInstance(ctx context.Context, instanceID string) (ProviderInstance, error) {
	if err := contextError(ctx); err != nil {
		return ProviderInstance{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	instance, exists := s.instances[instanceID]
	if !exists {
		return ProviderInstance{}, fmt.Errorf("%w: provider instance %s", ErrNotFound, instanceID)
	}
	return cloneProviderInstance(instance), nil
}

// ListInstances returns stable sorted provider instance snapshots.
// ListInstances 返回稳定排序的供应商实例快照。
func (s *MemoryStore) ListInstances(ctx context.Context, definitionID string) ([]ProviderInstance, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	instances := make([]ProviderInstance, 0, len(s.instances))
	for _, instance := range s.instances {
		if definitionID == "" || instance.DefinitionID == definitionID {
			instances = append(instances, cloneProviderInstance(instance))
		}
	}
	sort.Slice(instances, func(left int, right int) bool {
		return instances[left].ID < instances[right].ID
	})
	return instances, nil
}

// SaveEndpoint creates or updates one endpoint owned by an existing instance and channel.
// SaveEndpoint 创建或更新一个由现有实例和通道拥有的端点。
func (s *MemoryStore) SaveEndpoint(ctx context.Context, endpoint Endpoint) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := endpoint.Validate(); err != nil {
		return err
	}
	instance, errInstance := s.GetInstance(ctx, endpoint.ProviderInstanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if !definition.HasChannel(endpoint.ChannelID) {
		return invalid("endpoint references channel outside its provider definition")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.endpoints[endpoint.ID]; exists && endpoint.Revision <= current.Revision {
		return invalid("endpoint revision must increase")
	}
	s.endpoints[endpoint.ID] = endpoint
	return nil
}

// ListEndpoints returns stable sorted endpoint snapshots for one provider instance.
// ListEndpoints 返回一个供应商实例的稳定排序端点快照。
func (s *MemoryStore) ListEndpoints(ctx context.Context, instanceID string) ([]Endpoint, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	endpoints := make([]Endpoint, 0)
	for _, endpoint := range s.endpoints {
		if endpoint.ProviderInstanceID == instanceID {
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Slice(endpoints, func(left int, right int) bool {
		return endpoints[left].ID < endpoints[right].ID
	})
	return endpoints, nil
}

// SaveCredential creates or updates one non-secret credential owned by an existing instance.
// SaveCredential 创建或更新一个由现有实例拥有的非秘密凭据。
func (s *MemoryStore) SaveCredential(ctx context.Context, credential Credential) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	instance, errInstance := s.GetInstance(ctx, credential.ProviderInstanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if !definition.HasAuthMethod(credential.AuthMethodID) {
		return invalid("credential references auth method outside its provider definition")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for credentialID, current := range s.credentials {
		if credentialID == credential.ID || current.ProviderInstanceID != credential.ProviderInstanceID {
			continue
		}
		if current.Fingerprint == credential.Fingerprint {
			return fmt.Errorf("%w: credential fingerprint", ErrAlreadyRegistered)
		}
		if credential.PrincipalKey != "" && current.PrincipalKey == credential.PrincipalKey {
			return fmt.Errorf("%w: credential principal", ErrAlreadyRegistered)
		}
	}
	if current, exists := s.credentials[credential.ID]; exists && credential.Revision <= current.Revision {
		return invalid("credential revision must increase")
	}
	s.credentials[credential.ID] = cloneCredential(credential)
	return nil
}

// ListCredentials returns stable sorted credential snapshots for one provider instance.
// ListCredentials 返回一个供应商实例的稳定排序凭据快照。
func (s *MemoryStore) ListCredentials(ctx context.Context, instanceID string) ([]Credential, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	credentials := make([]Credential, 0)
	for _, credential := range s.credentials {
		if credential.ProviderInstanceID == instanceID {
			credentials = append(credentials, cloneCredential(credential))
		}
	}
	sort.Slice(credentials, func(left int, right int) bool {
		return credentials[left].ID < credentials[right].ID
	})
	return credentials, nil
}

// SaveBinding creates or updates one validated same-instance access binding.
// SaveBinding 创建或更新一个经过校验的同实例访问绑定。
func (s *MemoryStore) SaveBinding(ctx context.Context, binding AccessBinding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	instance, errInstance := s.GetInstance(ctx, binding.ProviderInstanceID)
	if errInstance != nil {
		return errInstance
	}
	definition, errDefinition := s.GetDefinition(ctx, instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if !definition.HasChannel(binding.ChannelID) {
		return invalid("access binding references channel outside its provider definition")
	}
	s.mu.RLock()
	endpoint, endpointExists := s.endpoints[binding.EndpointID]
	credential, credentialExists := s.credentials[binding.CredentialID]
	s.mu.RUnlock()
	if !endpointExists || !credentialExists {
		return fmt.Errorf("%w: access binding endpoint or credential", ErrNotFound)
	}
	if endpoint.ProviderInstanceID != binding.ProviderInstanceID || credential.ProviderInstanceID != binding.ProviderInstanceID {
		return invalid("access binding cannot cross provider instances")
	}
	if endpoint.ChannelID != binding.ChannelID || !definition.ChannelAllowsAuth(binding.ChannelID, credential.AuthMethodID) {
		return invalid("access binding channel is incompatible with endpoint or credential auth method")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.bindings[binding.ID]; exists && binding.Revision <= current.Revision {
		return invalid("access binding revision must increase")
	}
	s.bindings[binding.ID] = cloneAccessBinding(binding)
	return nil
}

// ListBindings returns stable sorted access binding snapshots for one provider instance.
// ListBindings 返回一个供应商实例的稳定排序访问绑定快照。
func (s *MemoryStore) ListBindings(ctx context.Context, instanceID string) ([]AccessBinding, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	bindings := make([]AccessBinding, 0)
	for _, binding := range s.bindings {
		if binding.ProviderInstanceID == instanceID {
			bindings = append(bindings, cloneAccessBinding(binding))
		}
	}
	sort.Slice(bindings, func(left int, right int) bool {
		if bindings[left].Priority != bindings[right].Priority {
			return bindings[left].Priority < bindings[right].Priority
		}
		return bindings[left].ID < bindings[right].ID
	})
	return bindings, nil
}

// cloneCredential returns a mutation-safe credential value.
// cloneCredential 返回一个防止外部修改的凭据值。
func cloneCredential(credential Credential) Credential {
	credential.ScopeRefs = append([]ScopeReference(nil), credential.ScopeRefs...)
	return credential
}

// cloneProviderInstance returns a mutation-safe provider instance value.
// cloneProviderInstance 返回一个防止外部修改的供应商实例值。
func cloneProviderInstance(instance ProviderInstance) ProviderInstance {
	instance.DisabledModelIDs = append([]string(nil), instance.DisabledModelIDs...)
	return instance
}

// cloneAccessBinding returns a mutation-safe access binding value.
// cloneAccessBinding 返回一个防止外部修改的访问绑定值。
func cloneAccessBinding(binding AccessBinding) AccessBinding {
	binding.AllowedModelIDs = append([]string(nil), binding.AllowedModelIDs...)
	return binding
}

// contextError returns an already-completed context error before a store mutation.
// contextError 在存储变更前返回已经结束的上下文错误。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	return ctx.Err()
}
