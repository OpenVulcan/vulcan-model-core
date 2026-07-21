// Package routingstate owns persistent Router policy and high-frequency credential-model availability.
// Package routingstate 管理持久化 Router 策略与高频凭据模型可用状态。
// State semantics in this file are copied and adapted from CLIProxyAPI sdk/cliproxy/auth/types.go and cooldown_state.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本文件状态语义复制并改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 sdk/cliproxy/auth/types.go 与 cooldown_state.go。
package routingstate

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

var (
	// ErrNotFound reports missing settings or credential-model state.
	// ErrNotFound 表示缺少设置或凭据模型状态。
	ErrNotFound = errors.New("routing state not found")
	// ErrRevisionConflict reports a stale or duplicate state update.
	// ErrRevisionConflict 表示状态更新过期或重复。
	ErrRevisionConflict = errors.New("routing state revision conflict")
)

// CredentialModelStatus describes model-specific runtime eligibility for one credential.
// CredentialModelStatus 描述一个凭据针对特定模型的运行时资格。
type CredentialModelStatus string

const (
	// ModelReady allows the credential-model pair to participate.
	// ModelReady 允许凭据模型组合参与执行。
	ModelReady CredentialModelStatus = "ready"
	// ModelCooling excludes the pair until a known recovery time.
	// ModelCooling 在已知恢复时间前排除该组合。
	ModelCooling CredentialModelStatus = "cooling"
	// ModelTemporarilyUnavailable excludes the pair after a trusted transient failure.
	// ModelTemporarilyUnavailable 在可信临时失败后排除该组合。
	ModelTemporarilyUnavailable CredentialModelStatus = "temporarily_unavailable"
	// ModelDisabled permanently excludes the pair until an explicit metadata or operator update.
	// ModelDisabled 在显式元数据或操作员更新前永久排除该组合。
	ModelDisabled CredentialModelStatus = "disabled"
)

// Settings contains Router-wide defaults inherited by provider instances.
// Settings 包含供应商实例继承的 Router 全局默认值。
type Settings struct {
	// DefaultRoutingStrategy is used when an instance has no override.
	// DefaultRoutingStrategy 在实例没有覆盖值时使用。
	DefaultRoutingStrategy providerconfig.RoutingStrategy
	// Revision is the latest persisted settings revision.
	// Revision 是最新持久化设置修订号。
	Revision uint64
	// UpdatedAt records the latest persisted update time.
	// UpdatedAt 记录最新持久化更新时间。
	UpdatedAt time.Time
}

// CredentialModelState records classified runtime state without rewriting an atomic catalog snapshot.
// CredentialModelState 记录分类后的运行状态且无需重写原子目录快照。
type CredentialModelState struct {
	// ProviderInstanceID owns this state.
	// ProviderInstanceID 拥有该状态。
	ProviderInstanceID string
	// CredentialID identifies the affected account.
	// CredentialID 标识受影响账号。
	CredentialID string
	// ProviderModelID identifies the affected provider model.
	// ProviderModelID 标识受影响供应商模型。
	ProviderModelID string
	// Status is the current model-specific runtime eligibility.
	// Status 是当前模型专属运行时资格。
	Status CredentialModelStatus
	// FailureCategory is the stable provider error category.
	// FailureCategory 是稳定供应商错误类别。
	FailureCategory string
	// RuleID identifies the trusted classification rule.
	// RuleID 标识可信分类规则。
	RuleID string
	// QuotaExhausted reports whether runtime evidence indicates model quota exhaustion.
	// QuotaExhausted 表示运行证据是否表明模型额度耗尽。
	QuotaExhausted bool
	// CoolingUntil is the earliest time at which selection may resume.
	// CoolingUntil 是选择可以恢复的最早时间。
	CoolingUntil *time.Time
	// BackoffLevel is the bounded consecutive quota-failure level.
	// BackoffLevel 是有界的连续额度失败等级。
	BackoffLevel int
	// LastSuccessAt records the newest successful execution.
	// LastSuccessAt 记录最新成功执行时间。
	LastSuccessAt *time.Time
	// LastFailureAt records the newest classified failure.
	// LastFailureAt 记录最新分类失败时间。
	LastFailureAt *time.Time
	// Revision is the latest persisted state revision.
	// Revision 是最新持久化状态修订号。
	Revision uint64
}

// RuntimeScope identifies one non-model provider-owned availability boundary.
// RuntimeScope 标识一个非模型供应商拥有的可用性边界。
type RuntimeScope string

const (
	// ScopeCredential affects one complete credential.
	// ScopeCredential 影响一个完整凭据。
	ScopeCredential RuntimeScope = "credential"
	// ScopeSubscription affects credentials sharing one subscription identifier.
	// ScopeSubscription 影响共享一个订阅标识的凭据。
	ScopeSubscription RuntimeScope = "subscription"
	// ScopeBillingAccount affects credentials sharing one billing account identifier.
	// ScopeBillingAccount 影响共享一个计费账号标识的凭据。
	ScopeBillingAccount RuntimeScope = "billing_account"
	// ScopeEndpoint affects one exact upstream endpoint.
	// ScopeEndpoint 影响一个精确上游入口。
	ScopeEndpoint RuntimeScope = "endpoint"
	// ScopeProvider affects one complete provider instance.
	// ScopeProvider 影响一个完整供应商实例。
	ScopeProvider RuntimeScope = "provider"
)

// RuntimeScopeState records classified availability for one non-model provider resource.
// RuntimeScopeState 记录一个非模型供应商资源的分类可用状态。
type RuntimeScopeState struct {
	// ProviderInstanceID owns the resource state.
	// ProviderInstanceID 拥有该资源状态。
	ProviderInstanceID string
	// Scope identifies the closed resource family.
	// Scope 标识封闭资源类别。
	Scope RuntimeScope
	// ScopeID identifies the exact credential, shared account, endpoint, or provider instance.
	// ScopeID 标识精确凭据、共享账号、入口或供应商实例。
	ScopeID string
	// Status is the current runtime eligibility.
	// Status 是当前运行时资格。
	Status CredentialModelStatus
	// FailureCategory is the stable classified category.
	// FailureCategory 是稳定分类类别。
	FailureCategory string
	// RuleID identifies the trusted classification rule.
	// RuleID 标识可信分类规则。
	RuleID string
	// CoolingUntil is the earliest eligible time for temporary failures.
	// CoolingUntil 是临时失败最早恢复资格的时间。
	CoolingUntil *time.Time
	// BackoffLevel is the bounded consecutive quota-failure level.
	// BackoffLevel 是有界连续额度失败等级。
	BackoffLevel int
	// LastSuccessAt records the newest target success.
	// LastSuccessAt 记录最新 Target 成功时间。
	LastSuccessAt *time.Time
	// LastFailureAt records the newest classified failure.
	// LastFailureAt 记录最新分类失败时间。
	LastFailureAt *time.Time
	// Revision is the latest persisted state revision.
	// Revision 是最新持久化状态修订号。
	Revision uint64
}

// EligibleAt reports whether the scoped provider resource may be selected now.
// EligibleAt 表示该作用域供应商资源当前是否可被选择。
func (s RuntimeScopeState) EligibleAt(now time.Time) bool {
	switch s.Status {
	case "", ModelReady:
		return true
	case ModelCooling, ModelTemporarilyUnavailable:
		return s.CoolingUntil != nil && !s.CoolingUntil.After(now)
	default:
		return false
	}
}

// EligibleAt reports whether this exact credential-model pair may be selected now.
// EligibleAt 报告该精确凭据模型组合当前是否可以被选择。
func (s CredentialModelState) EligibleAt(now time.Time) bool {
	switch s.Status {
	case "", ModelReady:
		return true
	case ModelCooling, ModelTemporarilyUnavailable:
		return s.CoolingUntil != nil && !s.CoolingUntil.After(now)
	default:
		return false
	}
}

// Store persists global policy and exact credential-model state.
// Store 持久化全局策略与精确凭据模型状态。
type Store interface {
	// GetSettings returns Router-wide settings.
	// GetSettings 返回 Router 全局设置。
	GetSettings(context.Context) (Settings, error)
	// SaveSettings persists a strictly newer settings revision.
	// SaveSettings 持久化严格更新的设置修订号。
	SaveSettings(context.Context, Settings) error
	// GetCredentialModelState returns one exact runtime state.
	// GetCredentialModelState 返回一个精确运行状态。
	GetCredentialModelState(context.Context, string, string, string) (CredentialModelState, error)
	// ListCredentialModelStates returns all states owned by one provider instance.
	// ListCredentialModelStates 返回一个供应商实例拥有的全部状态。
	ListCredentialModelStates(context.Context, string) ([]CredentialModelState, error)
	// SaveCredentialModelState persists a strictly newer model-state revision.
	// SaveCredentialModelState 持久化严格更新的模型状态修订号。
	SaveCredentialModelState(context.Context, CredentialModelState) error
	// GetRuntimeScopeState returns one exact non-model runtime state.
	// GetRuntimeScopeState 返回一个精确非模型运行状态。
	GetRuntimeScopeState(context.Context, string, RuntimeScope, string) (RuntimeScopeState, error)
	// ListRuntimeScopeStates returns all non-model states owned by one provider instance.
	// ListRuntimeScopeStates 返回一个供应商实例拥有的全部非模型状态。
	ListRuntimeScopeStates(context.Context, string) ([]RuntimeScopeState, error)
	// SaveRuntimeScopeState persists a strictly newer non-model state.
	// SaveRuntimeScopeState 持久化严格更新的非模型状态。
	SaveRuntimeScopeState(context.Context, RuntimeScopeState) error
}

// MemoryStore provides deterministic tests and ephemeral deployments.
// MemoryStore 为测试与临时部署提供确定性实现。
type MemoryStore struct {
	// mu protects settings and model states.
	// mu 保护设置与模型状态。
	mu sync.RWMutex
	// settings contains the current global policy.
	// settings 包含当前全局策略。
	settings Settings
	// states indexes exact credential-model identities.
	// states 索引精确凭据模型身份。
	states map[string]CredentialModelState
	// scopeStates indexes exact non-model provider resource identities.
	// scopeStates 索引精确非模型供应商资源身份。
	scopeStates map[string]RuntimeScopeState
}

// NewMemoryStore creates a store with the safe round-robin default.
// NewMemoryStore 创建一个使用安全均衡默认值的仓库。
func NewMemoryStore(now time.Time) *MemoryStore {
	return &MemoryStore{settings: Settings{DefaultRoutingStrategy: providerconfig.RoutingRoundRobin, Revision: 1, UpdatedAt: now}, states: make(map[string]CredentialModelState), scopeStates: make(map[string]RuntimeScopeState)}
}

// GetSettings returns the current global settings snapshot.
// GetSettings 返回当前全局设置快照。
func (s *MemoryStore) GetSettings(context.Context) (Settings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings, nil
}

// SaveSettings persists a strictly newer settings revision.
// SaveSettings 持久化严格更新的设置修订号。
func (s *MemoryStore) SaveSettings(_ context.Context, settings Settings) error {
	if errValidate := settings.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if settings.Revision <= s.settings.Revision {
		return ErrRevisionConflict
	}
	s.settings = settings
	return nil
}

// GetCredentialModelState returns one exact state.
// GetCredentialModelState 返回一个精确状态。
func (s *MemoryStore) GetCredentialModelState(_ context.Context, instanceID string, credentialID string, modelID string) (CredentialModelState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, exists := s.states[stateKey(instanceID, credentialID, modelID)]
	if !exists {
		return CredentialModelState{}, ErrNotFound
	}
	return cloneState(state), nil
}

// ListCredentialModelStates returns stable ordered instance-owned states.
// ListCredentialModelStates 返回稳定排序的实例所属状态。
func (s *MemoryStore) ListCredentialModelStates(_ context.Context, instanceID string) ([]CredentialModelState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	states := make([]CredentialModelState, 0)
	for _, state := range s.states {
		if state.ProviderInstanceID == instanceID {
			states = append(states, cloneState(state))
		}
	}
	sort.Slice(states, func(left int, right int) bool {
		if states[left].CredentialID != states[right].CredentialID {
			return states[left].CredentialID < states[right].CredentialID
		}
		return states[left].ProviderModelID < states[right].ProviderModelID
	})
	return states, nil
}

// SaveCredentialModelState persists a strictly newer exact state.
// SaveCredentialModelState 持久化严格更新的精确状态。
func (s *MemoryStore) SaveCredentialModelState(_ context.Context, state CredentialModelState) error {
	if errValidate := state.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := stateKey(state.ProviderInstanceID, state.CredentialID, state.ProviderModelID)
	if current, exists := s.states[key]; exists && state.Revision <= current.Revision {
		return ErrRevisionConflict
	}
	s.states[key] = cloneState(state)
	return nil
}

// GetRuntimeScopeState returns one exact non-model state.
// GetRuntimeScopeState 返回一个精确非模型状态。
func (s *MemoryStore) GetRuntimeScopeState(_ context.Context, instanceID string, scope RuntimeScope, scopeID string) (RuntimeScopeState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, exists := s.scopeStates[runtimeScopeKey(instanceID, scope, scopeID)]
	if !exists {
		return RuntimeScopeState{}, ErrNotFound
	}
	return cloneRuntimeScopeState(state), nil
}

// ListRuntimeScopeStates returns stable ordered non-model states.
// ListRuntimeScopeStates 返回稳定排序的非模型状态。
func (s *MemoryStore) ListRuntimeScopeStates(_ context.Context, instanceID string) ([]RuntimeScopeState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	states := make([]RuntimeScopeState, 0)
	for _, state := range s.scopeStates {
		if state.ProviderInstanceID == instanceID {
			states = append(states, cloneRuntimeScopeState(state))
		}
	}
	sort.Slice(states, func(left int, right int) bool {
		if states[left].Scope != states[right].Scope {
			return states[left].Scope < states[right].Scope
		}
		return states[left].ScopeID < states[right].ScopeID
	})
	return states, nil
}

// SaveRuntimeScopeState persists a strictly newer non-model state.
// SaveRuntimeScopeState 持久化严格更新的非模型状态。
func (s *MemoryStore) SaveRuntimeScopeState(_ context.Context, state RuntimeScopeState) error {
	if errValidate := state.Validate(); errValidate != nil {
		return errValidate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := runtimeScopeKey(state.ProviderInstanceID, state.Scope, state.ScopeID)
	if current, exists := s.scopeStates[key]; exists && state.Revision <= current.Revision {
		return ErrRevisionConflict
	}
	s.scopeStates[key] = cloneRuntimeScopeState(state)
	return nil
}

// Validate verifies Router settings.
// Validate 校验 Router 设置。
func (s Settings) Validate() error {
	if (s.DefaultRoutingStrategy != providerconfig.RoutingRoundRobin && s.DefaultRoutingStrategy != providerconfig.RoutingFillFirst) || s.Revision == 0 || s.UpdatedAt.IsZero() {
		return errors.New("routing settings are invalid")
	}
	return nil
}

// Validate verifies one exact credential-model state.
// Validate 校验一个精确凭据模型状态。
func (s CredentialModelState) Validate() error {
	if s.ProviderInstanceID == "" || s.CredentialID == "" || s.ProviderModelID == "" || s.Revision == 0 || s.BackoffLevel < 0 {
		return errors.New("credential model state identity, revision, or backoff is invalid")
	}
	switch s.Status {
	case ModelReady, ModelCooling, ModelTemporarilyUnavailable, ModelDisabled:
	default:
		return errors.New("credential model state status is invalid")
	}
	if (s.Status == ModelCooling || s.Status == ModelTemporarilyUnavailable) && s.CoolingUntil == nil {
		return errors.New("temporary credential model state requires recovery time")
	}
	return nil
}

// Validate verifies one exact non-model runtime scope state.
// Validate 校验一个精确非模型运行时作用域状态。
func (s RuntimeScopeState) Validate() error {
	if s.ProviderInstanceID == "" || s.ScopeID == "" || s.Revision == 0 || s.BackoffLevel < 0 {
		return errors.New("runtime scope state identity, revision, or backoff is invalid")
	}
	switch s.Scope {
	case ScopeCredential, ScopeSubscription, ScopeBillingAccount, ScopeEndpoint, ScopeProvider:
	default:
		return errors.New("runtime scope state scope is invalid")
	}
	switch s.Status {
	case ModelReady, ModelCooling, ModelTemporarilyUnavailable, ModelDisabled:
	default:
		return errors.New("runtime scope state status is invalid")
	}
	if (s.Status == ModelCooling || s.Status == ModelTemporarilyUnavailable) && s.CoolingUntil == nil {
		return errors.New("temporary runtime scope state requires recovery time")
	}
	return nil
}

// stateKey forms one collision-free in-memory identity.
// stateKey 构建一个无冲突内存身份。
func stateKey(instanceID string, credentialID string, modelID string) string {
	return instanceID + "\x00" + credentialID + "\x00" + modelID
}

// runtimeScopeKey forms one collision-free non-model state identity.
// runtimeScopeKey 构建一个无冲突非模型状态身份。
func runtimeScopeKey(instanceID string, scope RuntimeScope, scopeID string) string {
	return instanceID + "\x00" + string(scope) + "\x00" + scopeID
}

// cloneState returns mutation-safe time pointers.
// cloneState 返回防止外部修改的时间指针。
func cloneState(state CredentialModelState) CredentialModelState {
	state.CoolingUntil = cloneTime(state.CoolingUntil)
	state.LastSuccessAt = cloneTime(state.LastSuccessAt)
	state.LastFailureAt = cloneTime(state.LastFailureAt)
	return state
}

// cloneRuntimeScopeState returns mutation-safe time pointers.
// cloneRuntimeScopeState 返回防止外部修改的时间指针。
func cloneRuntimeScopeState(state RuntimeScopeState) RuntimeScopeState {
	state.CoolingUntil = cloneTime(state.CoolingUntil)
	state.LastSuccessAt = cloneTime(state.LastSuccessAt)
	state.LastFailureAt = cloneTime(state.LastFailureAt)
	return state
}

// cloneTime returns an owned optional timestamp.
// cloneTime 返回一个自有可选时间戳。
func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
