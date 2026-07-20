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
	// ListProviderGroups returns code-owned management-only provider groups.
	// ListProviderGroups 返回代码拥有且仅供管理使用的供应商分组。
	ListProviderGroups(context.Context) ([]ProviderGroup, error)
	// SaveCustomDefinition creates one custom provider definition; replacements require an atomic migration.
	// SaveCustomDefinition 创建一个自定义供应商定义；替换必须使用原子迁移。
	SaveCustomDefinition(context.Context, ProviderDefinition) error
	// SaveCustomDefinitionMigration atomically replaces one custom definition and transitions its complete instance set.
	// SaveCustomDefinitionMigration 原子替换一个自定义定义并转换其完整实例集合。
	SaveCustomDefinitionMigration(context.Context, CustomDefinitionMigration) error
	// GetDefinition resolves one system or custom provider definition.
	// GetDefinition 解析一个系统或自定义供应商定义。
	GetDefinition(context.Context, string) (ProviderDefinition, error)
	// ListDefinitions returns all visible system and custom provider definitions.
	// ListDefinitions 返回全部可见的系统和自定义供应商定义。
	ListDefinitions(context.Context) ([]ProviderDefinition, error)
	// SaveSystemOnboarding atomically creates one complete system-provider configuration.
	// SaveSystemOnboarding 原子创建一份完整的系统供应商配置。
	SaveSystemOnboarding(context.Context, SystemOnboarding) error
	// DeleteSystemOnboarding removes one newly created configuration during cross-store compensation.
	// DeleteSystemOnboarding 在跨存储补偿期间删除一份新创建配置。
	DeleteSystemOnboarding(context.Context, SystemOnboarding) error
	// SaveCustomOnboarding atomically creates one custom definition and its complete initial access graph.
	// SaveCustomOnboarding 原子创建一个自定义 Definition 及其完整初始访问图。
	SaveCustomOnboarding(context.Context, CustomOnboarding) error
	// DeleteCustomOnboarding removes one unchanged newly created custom definition and access graph during compensation.
	// DeleteCustomOnboarding 在补偿期间删除一个未变化的新建自定义 Definition 与访问图。
	DeleteCustomOnboarding(context.Context, CustomOnboarding) error
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

// SaveSystemOnboarding atomically commits one new system-provider configuration in memory.
// SaveSystemOnboarding 在内存中原子提交一份新的系统供应商配置。
func (s *MemoryStore) SaveSystemOnboarding(ctx context.Context, onboarding SystemOnboarding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	definition, errDefinition := s.GetDefinition(ctx, onboarding.Instance.DefinitionID)
	if errDefinition != nil {
		return errDefinition
	}
	if errValidate := ValidateSystemOnboarding(onboarding, definition); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.instances[onboarding.Instance.ID]; exists {
		return fmt.Errorf("%w: provider instance %s", ErrAlreadyRegistered, onboarding.Instance.ID)
	}
	for _, current := range s.instances {
		if current.Handle == onboarding.Instance.Handle {
			return fmt.Errorf("%w: provider handle %s", ErrAlreadyRegistered, onboarding.Instance.Handle)
		}
	}
	if _, exists := s.credentials[onboarding.Credential.ID]; exists {
		return fmt.Errorf("%w: credential %s", ErrAlreadyRegistered, onboarding.Credential.ID)
	}
	for _, endpoint := range onboarding.Endpoints {
		if _, exists := s.endpoints[endpoint.ID]; exists {
			return fmt.Errorf("%w: provider endpoint %s", ErrAlreadyRegistered, endpoint.ID)
		}
	}
	for _, binding := range onboarding.Bindings {
		if _, exists := s.bindings[binding.ID]; exists {
			return fmt.Errorf("%w: access binding %s", ErrAlreadyRegistered, binding.ID)
		}
	}
	s.instances[onboarding.Instance.ID] = cloneProviderInstance(onboarding.Instance)
	for _, endpoint := range onboarding.Endpoints {
		s.endpoints[endpoint.ID] = endpoint
	}
	s.credentials[onboarding.Credential.ID] = cloneCredential(onboarding.Credential)
	for _, binding := range onboarding.Bindings {
		s.bindings[binding.ID] = cloneAccessBinding(binding)
	}
	return nil
}

// DeleteSystemOnboarding removes one complete instance-owned configuration graph atomically in memory.
// DeleteSystemOnboarding 在内存中原子删除一个完整实例拥有的配置图。
func (s *MemoryStore) DeleteSystemOnboarding(ctx context.Context, onboarding SystemOnboarding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	instance, exists := s.instances[onboarding.Instance.ID]
	if !exists {
		return fmt.Errorf("%w: provider instance %s", ErrNotFound, onboarding.Instance.ID)
	}
	if instance.DefinitionID != onboarding.Instance.DefinitionID || instance.Revision != onboarding.Instance.Revision {
		return fmt.Errorf("system onboarding compensation target changed")
	}
	for _, binding := range onboarding.Bindings {
		current, bindingExists := s.bindings[binding.ID]
		if !bindingExists || current.ProviderInstanceID != onboarding.Instance.ID || current.Revision != binding.Revision {
			return fmt.Errorf("system onboarding compensation binding %s changed", binding.ID)
		}
	}
	for _, endpoint := range onboarding.Endpoints {
		current, endpointExists := s.endpoints[endpoint.ID]
		if !endpointExists || current.ProviderInstanceID != onboarding.Instance.ID || current.Revision != endpoint.Revision {
			return fmt.Errorf("system onboarding compensation endpoint %s changed", endpoint.ID)
		}
	}
	credential, credentialExists := s.credentials[onboarding.Credential.ID]
	if !credentialExists || credential.ProviderInstanceID != onboarding.Instance.ID || credential.Revision != onboarding.Credential.Revision {
		return fmt.Errorf("system onboarding compensation credential %s changed", onboarding.Credential.ID)
	}
	for _, binding := range onboarding.Bindings {
		delete(s.bindings, binding.ID)
	}
	for _, endpoint := range onboarding.Endpoints {
		delete(s.endpoints, endpoint.ID)
	}
	delete(s.credentials, onboarding.Credential.ID)
	delete(s.instances, onboarding.Instance.ID)
	return nil
}

// SaveCustomOnboarding atomically commits one new custom definition and executable graph in memory.
// SaveCustomOnboarding 在内存中原子提交一个新的自定义 Definition 与可执行图。
func (s *MemoryStore) SaveCustomOnboarding(ctx context.Context, onboarding CustomOnboarding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if errDefinition := ValidateCustomDefinition(onboarding.Definition, s.protocols); errDefinition != nil {
		return errDefinition
	}
	if errValidate := ValidateCustomOnboarding(onboarding); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.customDefinitions[onboarding.Definition.ID]; exists {
		return fmt.Errorf("%w: custom provider definition %s", ErrAlreadyRegistered, onboarding.Definition.ID)
	}
	if _, exists := s.instances[onboarding.Instance.ID]; exists {
		return fmt.Errorf("%w: provider instance %s", ErrAlreadyRegistered, onboarding.Instance.ID)
	}
	for _, current := range s.instances {
		if current.Handle == onboarding.Instance.Handle {
			return fmt.Errorf("%w: provider handle %s", ErrAlreadyRegistered, onboarding.Instance.Handle)
		}
	}
	if _, exists := s.endpoints[onboarding.Endpoint.ID]; exists {
		return fmt.Errorf("%w: provider endpoint %s", ErrAlreadyRegistered, onboarding.Endpoint.ID)
	}
	if _, exists := s.credentials[onboarding.Credential.ID]; exists {
		return fmt.Errorf("%w: credential %s", ErrAlreadyRegistered, onboarding.Credential.ID)
	}
	if _, exists := s.bindings[onboarding.Binding.ID]; exists {
		return fmt.Errorf("%w: access binding %s", ErrAlreadyRegistered, onboarding.Binding.ID)
	}
	s.customDefinitions[onboarding.Definition.ID] = cloneProviderDefinition(onboarding.Definition)
	s.instances[onboarding.Instance.ID] = cloneProviderInstance(onboarding.Instance)
	s.endpoints[onboarding.Endpoint.ID] = onboarding.Endpoint
	s.credentials[onboarding.Credential.ID] = cloneCredential(onboarding.Credential)
	s.bindings[onboarding.Binding.ID] = cloneAccessBinding(onboarding.Binding)
	return nil
}

// DeleteCustomOnboarding removes one exact unchanged custom onboarding graph atomically in memory.
// DeleteCustomOnboarding 在内存中原子删除一个精确且未变化的自定义录入图。
func (s *MemoryStore) DeleteCustomOnboarding(ctx context.Context, onboarding CustomOnboarding) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	definition, definitionExists := s.customDefinitions[onboarding.Definition.ID]
	instance, instanceExists := s.instances[onboarding.Instance.ID]
	endpoint, endpointExists := s.endpoints[onboarding.Endpoint.ID]
	credential, credentialExists := s.credentials[onboarding.Credential.ID]
	binding, bindingExists := s.bindings[onboarding.Binding.ID]
	if !definitionExists || !instanceExists || !endpointExists || !credentialExists || !bindingExists {
		return fmt.Errorf("%w: custom onboarding graph", ErrNotFound)
	}
	if definition.Revision != onboarding.Definition.Revision || instance.DefinitionID != definition.ID || instance.Revision != onboarding.Instance.Revision || endpoint.ProviderInstanceID != instance.ID || endpoint.Revision != onboarding.Endpoint.Revision || credential.ProviderInstanceID != instance.ID || credential.Revision != onboarding.Credential.Revision || binding.ProviderInstanceID != instance.ID || binding.Revision != onboarding.Binding.Revision {
		return errors.New("custom onboarding compensation target changed")
	}
	delete(s.bindings, onboarding.Binding.ID)
	delete(s.credentials, onboarding.Credential.ID)
	delete(s.endpoints, onboarding.Endpoint.ID)
	delete(s.instances, onboarding.Instance.ID)
	delete(s.customDefinitions, onboarding.Definition.ID)
	return nil
}

// ListProviderGroups returns code-owned groups without reading persisted execution configuration.
// ListProviderGroups 返回代码拥有的分组，且不读取持久化执行配置。
func (s *MemoryStore) ListProviderGroups(ctx context.Context) ([]ProviderGroup, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return s.systems.ListGroups(), nil
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

// SaveCustomDefinition creates one validated custom definition and reserves replacement for the migration operation.
// SaveCustomDefinition 创建一个经过校验的自定义定义，并将替换操作保留给迁移接口。
func (s *MemoryStore) SaveCustomDefinition(ctx context.Context, definition ProviderDefinition) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := ValidateCustomDefinition(definition, s.protocols); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.customDefinitions[definition.ID]; exists {
		return fmt.Errorf("%w: provider definition %s", ErrAlreadyRegistered, definition.ID)
	}
	s.customDefinitions[definition.ID] = cloneProviderDefinition(definition)
	return nil
}

// SaveCustomDefinitionMigration atomically replaces one custom definition and transitions every owned instance in memory.
// SaveCustomDefinitionMigration 在内存中原子替换一个自定义定义并转换其拥有的全部实例。
func (s *MemoryStore) SaveCustomDefinitionMigration(ctx context.Context, migration CustomDefinitionMigration) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentDefinition, exists := s.customDefinitions[migration.Definition.ID]
	if !exists {
		return fmt.Errorf("%w: provider definition %s", ErrNotFound, migration.Definition.ID)
	}
	// currentInstances captures the exact definition-owned set under the same write lock used for commit.
	// currentInstances 在提交所用的同一写锁下捕获精确的定义所属集合。
	currentInstances := make([]ProviderInstance, 0)
	for _, instance := range s.instances {
		if instance.DefinitionID == migration.Definition.ID {
			currentInstances = append(currentInstances, cloneProviderInstance(instance))
		}
	}
	if errMigration := ValidateCustomDefinitionMigration(migration, currentDefinition, currentInstances, s.protocols); errMigration != nil {
		return errMigration
	}
	s.customDefinitions[migration.Definition.ID] = cloneProviderDefinition(migration.Definition)
	for _, instance := range migration.Instances {
		s.instances[instance.ID] = cloneProviderInstance(instance)
	}
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
	systemDefinition, systemExists := s.systems.Lookup(instance.DefinitionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	definition := systemDefinition
	if !systemExists {
		customDefinition, customExists := s.customDefinitions[instance.DefinitionID]
		if !customExists {
			return fmt.Errorf("%w: provider definition %s", ErrNotFound, instance.DefinitionID)
		}
		definition = customDefinition
	}
	if instance.DefinitionRevision != definition.Revision {
		return invalid("provider instance definition revision does not match current definition")
	}
	for instanceID, current := range s.instances {
		if current.Handle == instance.Handle && instanceID != instance.ID {
			return fmt.Errorf("%w: provider handle %s", ErrAlreadyRegistered, instance.Handle)
		}
	}
	if current, exists := s.instances[instance.ID]; exists {
		if errMutation := current.ValidateMutation(instance); errMutation != nil {
			return errMutation
		}
		if instance.Revision <= current.Revision {
			return invalid("provider instance revision must increase")
		}
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
	if errPreset := definition.ValidateEndpointPreset(endpoint); errPreset != nil {
		return errPreset
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.endpoints[endpoint.ID]; exists {
		if endpoint.Revision <= current.Revision {
			return invalid("endpoint revision must increase")
		}
		if errMutation := definition.ValidateEndpointMutation(current, endpoint); errMutation != nil {
			return errMutation
		}
	}
	s.endpoints[endpoint.ID] = cloneEndpoint(endpoint)
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
			endpoints = append(endpoints, cloneEndpoint(endpoint))
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
	if current, exists := s.credentials[credential.ID]; exists {
		if errMutation := current.ValidateMutation(credential); errMutation != nil {
			return errMutation
		}
		if credential.Revision <= current.Revision {
			return invalid("credential revision must increase")
		}
	}
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
	if current, exists := s.bindings[binding.ID]; exists {
		if errMutation := current.ValidateMutation(binding); errMutation != nil {
			return errMutation
		}
		if binding.Revision <= current.Revision {
			return invalid("access binding revision must increase")
		}
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
	instance.DisabledServiceIDs = append([]string(nil), instance.DisabledServiceIDs...)
	return instance
}

// cloneEndpoint returns a mutation-safe endpoint value.
// cloneEndpoint 返回一个防止外部修改的端点值。
func cloneEndpoint(endpoint Endpoint) Endpoint {
	endpoint.Parameters = append([]EndpointParameterValue(nil), endpoint.Parameters...)
	return endpoint
}

// cloneAccessBinding returns a mutation-safe access binding value.
// cloneAccessBinding 返回一个防止外部修改的访问绑定值。
func cloneAccessBinding(binding AccessBinding) AccessBinding {
	binding.AllowedModelIDs = append([]string(nil), binding.AllowedModelIDs...)
	binding.AllowedServiceIDs = append([]string(nil), binding.AllowedServiceIDs...)
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
