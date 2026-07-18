package providerconfig

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	// ErrAlreadyRegistered reports a duplicate immutable registry identifier.
	// ErrAlreadyRegistered 表示不可变注册表标识重复。
	ErrAlreadyRegistered = errors.New("provider configuration already registered")
	// ErrNotFound reports a missing provider configuration record.
	// ErrNotFound 表示供应商配置记录不存在。
	ErrNotFound = errors.New("provider configuration not found")
)

// ProtocolRegistry stores immutable upstream protocol profile metadata.
// ProtocolRegistry 存储不可变的上游协议 Profile 元数据。
type ProtocolRegistry struct {
	// mu protects immutable profile registration and snapshot reads.
	// mu 保护不可变 Profile 注册和快照读取。
	mu sync.RWMutex
	// profiles stores profiles by stable protocol identifier.
	// profiles 按稳定协议标识存储 Profile。
	profiles map[string]ProtocolProfile
}

// NewProtocolRegistry creates an empty upstream protocol metadata registry.
// NewProtocolRegistry 创建一个空的上游协议元数据注册表。
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{profiles: make(map[string]ProtocolProfile)}
}

// Register adds one immutable protocol profile and rejects duplicate ownership.
// Register 添加一个不可变协议 Profile 并拒绝重复所有权。
func (r *ProtocolRegistry) Register(profile ProtocolProfile) error {
	if r == nil {
		return errors.New("protocol registry is nil")
	}
	if err := profile.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.profiles[profile.ID]; exists {
		return fmt.Errorf("%w: protocol profile %s", ErrAlreadyRegistered, profile.ID)
	}
	r.profiles[profile.ID] = cloneProtocolProfile(profile)
	return nil
}

// Lookup returns one protocol profile snapshot by exact identifier.
// Lookup 按精确标识返回一个协议 Profile 快照。
func (r *ProtocolRegistry) Lookup(profileID string) (ProtocolProfile, bool) {
	if r == nil {
		return ProtocolProfile{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	profile, exists := r.profiles[profileID]
	return cloneProtocolProfile(profile), exists
}

// List returns a stable sorted protocol profile snapshot.
// List 返回稳定排序的协议 Profile 快照。
func (r *ProtocolRegistry) List() []ProtocolProfile {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	profiles := make([]ProtocolProfile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		profiles = append(profiles, cloneProtocolProfile(profile))
	}
	sort.Slice(profiles, func(left int, right int) bool {
		return profiles[left].ID < profiles[right].ID
	})
	return profiles
}

// SystemRegistry stores code-owned immutable provider definitions.
// SystemRegistry 存储代码拥有的不可变供应商定义。
type SystemRegistry struct {
	// mu protects immutable definition registration and snapshot reads.
	// mu 保护不可变定义注册和快照读取。
	mu sync.RWMutex
	// protocols resolves protocol profiles referenced by system definitions.
	// protocols 解析系统定义引用的协议 Profile。
	protocols *ProtocolRegistry
	// groups stores management-only system provider groups by stable identifier.
	// groups 按稳定标识存储仅供管理使用的系统供应商分组。
	groups map[string]ProviderGroup
	// definitions stores system definitions by stable identifier.
	// definitions 按稳定标识存储系统定义。
	definitions map[string]ProviderDefinition
}

// NewSystemRegistry creates an empty system provider registry backed by protocol metadata.
// NewSystemRegistry 创建一个由协议元数据支持的空系统供应商注册表。
func NewSystemRegistry(protocols *ProtocolRegistry) (*SystemRegistry, error) {
	if protocols == nil {
		return nil, errors.New("protocol registry is required")
	}
	return &SystemRegistry{
		protocols:   protocols,
		groups:      make(map[string]ProviderGroup),
		definitions: make(map[string]ProviderDefinition),
	}, nil
}

// RegisterGroup adds one immutable management-only system provider group.
// RegisterGroup 添加一个不可变且仅供管理使用的系统供应商分组。
func (r *SystemRegistry) RegisterGroup(group ProviderGroup) error {
	if r == nil {
		return errors.New("system provider registry is nil")
	}
	if err := group.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.groups[group.ID]; exists {
		return fmt.Errorf("%w: system provider group %s", ErrAlreadyRegistered, group.ID)
	}
	r.groups[group.ID] = group
	return nil
}

// ListGroups returns a stable management ordering of code-owned provider groups.
// ListGroups 返回代码拥有供应商分组的稳定管理排序。
func (r *SystemRegistry) ListGroups() []ProviderGroup {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	groups := make([]ProviderGroup, 0, len(r.groups))
	for _, group := range r.groups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(left int, right int) bool {
		if groups[left].SortOrder != groups[right].SortOrder {
			return groups[left].SortOrder < groups[right].SortOrder
		}
		return groups[left].ID < groups[right].ID
	})
	return groups
}

// Register adds one code-owned system provider definition.
// Register 添加一个代码拥有的系统供应商定义。
func (r *SystemRegistry) Register(definition ProviderDefinition) error {
	if r == nil {
		return errors.New("system provider registry is nil")
	}
	if definition.Kind != DefinitionKindSystem {
		return invalid("system registry accepts only system provider definitions")
	}
	if err := definition.Validate(); err != nil {
		return err
	}
	for _, channel := range definition.Channels {
		profile, exists := r.protocols.Lookup(channel.ProtocolProfileID)
		if !exists {
			return invalid("system provider channel %q references unknown protocol profile %q", channel.ID, channel.ProtocolProfileID)
		}
		if !profile.RuntimeReady {
			return invalid("system provider channel %q references a protocol profile that is not runtime ready", channel.ID)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if definition.GroupID != "" {
		if _, exists := r.groups[definition.GroupID]; !exists {
			return invalid("system provider definition %q references unknown provider group %q", definition.ID, definition.GroupID)
		}
	}
	if _, exists := r.definitions[definition.ID]; exists {
		return fmt.Errorf("%w: system provider definition %s", ErrAlreadyRegistered, definition.ID)
	}
	r.definitions[definition.ID] = cloneProviderDefinition(definition)
	return nil
}

// Lookup returns one system provider definition snapshot by exact identifier.
// Lookup 按精确标识返回一个系统供应商定义快照。
func (r *SystemRegistry) Lookup(definitionID string) (ProviderDefinition, bool) {
	if r == nil {
		return ProviderDefinition{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	definition, exists := r.definitions[definitionID]
	return cloneProviderDefinition(definition), exists
}

// List returns a stable sorted system provider definition snapshot.
// List 返回稳定排序的系统供应商定义快照。
func (r *SystemRegistry) List() []ProviderDefinition {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	definitions := make([]ProviderDefinition, 0, len(r.definitions))
	for _, definition := range r.definitions {
		definitions = append(definitions, cloneProviderDefinition(definition))
	}
	sort.Slice(definitions, func(left int, right int) bool {
		return definitions[left].ID < definitions[right].ID
	})
	return definitions
}

// ValidateCustomDefinition verifies that a custom definition uses one configurable ready protocol.
// ValidateCustomDefinition 校验自定义定义仅使用一个可配置且就绪的协议。
func ValidateCustomDefinition(definition ProviderDefinition, protocols *ProtocolRegistry) error {
	if protocols == nil {
		return errors.New("protocol registry is required")
	}
	if definition.Kind != DefinitionKindCustom {
		return invalid("custom definition validation requires custom ownership")
	}
	if err := definition.Validate(); err != nil {
		return err
	}
	channel := definition.Channels[0]
	profile, exists := protocols.Lookup(channel.ProtocolProfileID)
	if !exists {
		return invalid("custom provider references unknown protocol profile %q", channel.ProtocolProfileID)
	}
	if !profile.UserConfigurable || !profile.RuntimeReady || !channel.RuntimeReady {
		return invalid("custom provider protocol profile %q is not user configurable and runtime ready", profile.ID)
	}
	allowedAuthTypes := make(map[AuthMethodType]struct{}, len(profile.AllowedAuthMethods))
	for _, authMethodType := range profile.AllowedAuthMethods {
		allowedAuthTypes[authMethodType] = struct{}{}
	}
	for _, authMethod := range definition.AuthMethods {
		switch authMethod.Type {
		case AuthMethodBearer, AuthMethodHeaderKey, AuthMethodQueryKey, AuthMethodNone:
		default:
			return invalid("custom provider auth method %q is not supported", authMethod.Type)
		}
		if _, exists := allowedAuthTypes[authMethod.Type]; !exists {
			return invalid("protocol profile %q does not allow auth method %q", profile.ID, authMethod.Type)
		}
	}
	return nil
}

// cloneProtocolProfile returns a mutation-safe protocol profile value.
// cloneProtocolProfile 返回一个防止外部修改的协议 Profile 值。
func cloneProtocolProfile(profile ProtocolProfile) ProtocolProfile {
	profile.Capabilities = append([]ProtocolCapabilityFact(nil), profile.Capabilities...)
	profile.AllowedAuthMethods = append([]AuthMethodType(nil), profile.AllowedAuthMethods...)
	return profile
}

// cloneProviderDefinition returns a mutation-safe provider definition value.
// cloneProviderDefinition 返回一个防止外部修改的供应商定义值。
func cloneProviderDefinition(definition ProviderDefinition) ProviderDefinition {
	definition.Channels = append([]ProviderChannel(nil), definition.Channels...)
	for index := range definition.Channels {
		definition.Channels[index].AuthMethodIDs = append([]string(nil), definition.Channels[index].AuthMethodIDs...)
	}
	definition.AuthMethods = append([]AuthMethodDefinition(nil), definition.AuthMethods...)
	definition.EndpointPresets = append([]EndpointPreset(nil), definition.EndpointPresets...)
	return definition
}
