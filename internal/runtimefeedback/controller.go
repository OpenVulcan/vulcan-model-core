// Portions of this file are copied and adapted from CLIProxyAPI sdk/cliproxy/auth/conductor.go at commit 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66.
// 本文件部分逻辑复制并改编自 CLIProxyAPI 固定提交 9f4f53ca5a4d1474e3f7eb61d6ffc984995f1f66 中的 sdk/cliproxy/auth/conductor.go。
// Package runtimefeedback applies classified execution outcomes to persistent same-provider routing state.
// Package runtimefeedback 将分类执行结果应用到持久化同供应商路由状态。
package runtimefeedback

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/routingstate"
)

const (
	// quotaBackoffBase is CLIProxyAPI's exact initial quota cooldown.
	// quotaBackoffBase 是 CLIProxyAPI 的精确初始额度冷却时间。
	quotaBackoffBase = time.Second
	// quotaBackoffMax is CLIProxyAPI's exact maximum quota cooldown.
	// quotaBackoffMax 是 CLIProxyAPI 的精确最大额度冷却时间。
	quotaBackoffMax = 30 * time.Minute
	// transientErrorCooldown is CLIProxyAPI's exact default transient cooldown.
	// transientErrorCooldown 是 CLIProxyAPI 的精确默认临时冷却时间。
	transientErrorCooldown = time.Minute
)

// Controller applies trusted classified execution results to persistent model state.
// Controller 将可信分类执行结果应用到持久化模型状态。
type Controller struct {
	// store owns revisioned state.
	// store 拥有带修订号状态。
	store routingstate.Store
}

// scopeIdentity identifies one exact non-model runtime state record.
// scopeIdentity 标识一个精确的非模型运行时状态记录。
type scopeIdentity struct {
	// scope is the classified runtime resource boundary.
	// scope 是分类后的运行时资源边界。
	scope routingstate.RuntimeScope
	// scopeID is the immutable identifier inside that boundary.
	// scopeID 是该边界内的不可变标识。
	scopeID string
}

// NewController creates one runtime feedback controller.
// NewController 创建一个运行时反馈控制器。
func NewController(store routingstate.Store) (*Controller, error) {
	if dependency.IsNil(store) {
		return nil, errors.New("routing state store is required")
	}
	return &Controller{store: store}, nil
}

// RecordFailure applies one classified failure to its exact model, credential, shared account, endpoint, or provider scope.
// RecordFailure 将一次分类失败应用到精确模型、凭据、共享账号、入口或供应商作用域。
func (c *Controller) RecordFailure(ctx context.Context, request provider.ExecutionRequest, classified provider.ClassifiedError, now time.Time) error {
	target := request.Binding.Target
	if classified.Scope != provider.ErrorScopeModel {
		return c.recordScopeFailure(ctx, request, classified, now)
	}
	if target.ProviderModelID == "" {
		return nil
	}
	state, errState := c.store.GetCredentialModelState(ctx, target.ProviderInstanceID, target.CredentialID, target.ProviderModelID)
	if errors.Is(errState, routingstate.ErrNotFound) {
		state = routingstate.CredentialModelState{ProviderInstanceID: target.ProviderInstanceID, CredentialID: target.CredentialID, ProviderModelID: target.ProviderModelID}
	} else if errState != nil {
		return errState
	}
	recoveryAt := classified.RetryAt
	quotaExhausted := classified.Category == "quota_exhausted"
	if recoveryAt == nil {
		if quotaExhausted {
			next, nextLevel := quotaCooldownAfterFailure(state, now)
			recoveryAt = &next
			state.BackoffLevel = nextLevel
		} else {
			next := now.Add(transientErrorCooldown)
			recoveryAt = &next
		}
	}
	state.Status = routingstate.ModelCooling
	state.FailureCategory = classified.Category
	state.RuleID = classified.RuleID
	state.QuotaExhausted = quotaExhausted
	state.CoolingUntil = cloneTime(recoveryAt)
	state.LastFailureAt = cloneTime(&now)
	state.Revision++
	if errSave := c.store.SaveCredentialModelState(ctx, state); errSave != nil {
		return fmt.Errorf("save classified credential model failure: %w", errSave)
	}
	return nil
}

// RecordSuccess clears temporary model, credential, endpoint, and provider state proven healthy by one request.
// RecordSuccess 清除由一次请求证明健康的临时模型、凭据、入口与供应商状态。
func (c *Controller) RecordSuccess(ctx context.Context, request provider.ExecutionRequest, now time.Time) error {
	target := request.Binding.Target
	var recordedErrors []error
	if target.ProviderModelID != "" {
		if errModel := c.recordModelSuccess(ctx, target.ProviderInstanceID, target.CredentialID, target.ProviderModelID, now); errModel != nil {
			recordedErrors = append(recordedErrors, errModel)
		}
	}
	for _, scopedIdentity := range []scopeIdentity{{routingstate.ScopeCredential, target.CredentialID}, {routingstate.ScopeEndpoint, target.EndpointID}, {routingstate.ScopeProvider, target.ProviderInstanceID}} {
		if errScope := c.recordScopeSuccess(ctx, target.ProviderInstanceID, scopedIdentity.scope, scopedIdentity.scopeID, now); errScope != nil {
			recordedErrors = append(recordedErrors, errScope)
		}
	}
	return errors.Join(recordedErrors...)
}

// recordModelSuccess clears one exact successful account-model pair.
// recordModelSuccess 清除一个精确成功账号模型组合。
func (c *Controller) recordModelSuccess(ctx context.Context, instanceID string, credentialID string, modelID string, now time.Time) error {
	state, errState := c.store.GetCredentialModelState(ctx, instanceID, credentialID, modelID)
	if errors.Is(errState, routingstate.ErrNotFound) {
		return nil
	}
	if errState != nil {
		return errState
	}
	state.Status = routingstate.ModelReady
	state.FailureCategory = ""
	state.RuleID = ""
	state.QuotaExhausted = false
	state.CoolingUntil = nil
	state.BackoffLevel = 0
	state.LastSuccessAt = cloneTime(&now)
	state.Revision++
	if errSave := c.store.SaveCredentialModelState(ctx, state); errSave != nil {
		return fmt.Errorf("save successful credential model state: %w", errSave)
	}
	return nil
}

// recordScopeFailure persists one classified non-model provider resource failure.
// recordScopeFailure 持久化一个分类后的非模型供应商资源失败。
func (c *Controller) recordScopeFailure(ctx context.Context, request provider.ExecutionRequest, classified provider.ClassifiedError, now time.Time) error {
	scope, scopeID, recordable, errIdentity := classifiedScopeIdentity(request, classified.Scope)
	if errIdentity != nil || !recordable {
		return errIdentity
	}
	instanceID := request.Binding.Target.ProviderInstanceID
	state, errState := c.store.GetRuntimeScopeState(ctx, instanceID, scope, scopeID)
	if errors.Is(errState, routingstate.ErrNotFound) {
		state = routingstate.RuntimeScopeState{ProviderInstanceID: instanceID, Scope: scope, ScopeID: scopeID}
	} else if errState != nil {
		return errState
	}
	recoveryAt := classified.RetryAt
	if recoveryAt == nil {
		if classified.Category == "quota_exhausted" {
			next, nextLevel := scopeQuotaCooldownAfterFailure(state, now)
			recoveryAt = &next
			state.BackoffLevel = nextLevel
		} else {
			next := now.Add(transientErrorCooldown)
			recoveryAt = &next
		}
	}
	state.Status = routingstate.ModelCooling
	state.FailureCategory = classified.Category
	state.RuleID = classified.RuleID
	state.CoolingUntil = cloneTime(recoveryAt)
	state.LastFailureAt = cloneTime(&now)
	state.Revision++
	if errSave := c.store.SaveRuntimeScopeState(ctx, state); errSave != nil {
		return fmt.Errorf("save classified runtime scope failure: %w", errSave)
	}
	return nil
}

// recordScopeSuccess clears one exact temporary non-model resource failure when present.
// recordScopeSuccess 在存在时清除一个精确临时非模型资源失败。
func (c *Controller) recordScopeSuccess(ctx context.Context, instanceID string, scope routingstate.RuntimeScope, scopeID string, now time.Time) error {
	if scopeID == "" {
		return nil
	}
	state, errState := c.store.GetRuntimeScopeState(ctx, instanceID, scope, scopeID)
	if errors.Is(errState, routingstate.ErrNotFound) {
		return nil
	}
	if errState != nil {
		return errState
	}
	state.Status = routingstate.ModelReady
	state.FailureCategory = ""
	state.RuleID = ""
	state.CoolingUntil = nil
	state.BackoffLevel = 0
	state.LastSuccessAt = cloneTime(&now)
	state.Revision++
	if errSave := c.store.SaveRuntimeScopeState(ctx, state); errSave != nil {
		return fmt.Errorf("save successful runtime scope state: %w", errSave)
	}
	return nil
}

// classifiedScopeIdentity resolves one exact state key without guessing an absent shared account identifier.
// classifiedScopeIdentity 在不猜测缺失共享账号标识的情况下解析一个精确状态键。
func classifiedScopeIdentity(request provider.ExecutionRequest, scope provider.ErrorScope) (routingstate.RuntimeScope, string, bool, error) {
	target := request.Binding.Target
	switch scope {
	case provider.ErrorScopeRequest:
		return "", "", false, nil
	case provider.ErrorScopeCredential:
		return routingstate.ScopeCredential, target.CredentialID, true, nil
	case provider.ErrorScopeEndpoint:
		return routingstate.ScopeEndpoint, target.EndpointID, true, nil
	case provider.ErrorScopeProvider:
		return routingstate.ScopeProvider, target.ProviderInstanceID, true, nil
	case provider.ErrorScopeSubscription, provider.ErrorScopeBillingAccount:
		stateScope := routingstate.ScopeSubscription
		if scope == provider.ErrorScopeBillingAccount {
			stateScope = routingstate.ScopeBillingAccount
		}
		scopeIDs := matchingScopeReferenceIDs(request.Binding.Credential.ScopeRefs, string(scope))
		if len(scopeIDs) != 1 {
			return "", "", false, fmt.Errorf("classified %s failure requires exactly one credential scope reference", scope)
		}
		return stateScope, scopeIDs[0], true, nil
	default:
		return "", "", false, fmt.Errorf("unsupported classified runtime scope %q", scope)
	}
}

// matchingScopeReferenceIDs returns exact identifiers for one closed credential scope kind.
// matchingScopeReferenceIDs 返回一个封闭凭据作用域类别的精确标识。
func matchingScopeReferenceIDs(scopeReferences []providerconfig.ScopeReference, kind string) []string {
	identifiers := make([]string, 0, 1)
	for _, scopeReference := range scopeReferences {
		if scopeReference.Kind == kind {
			identifiers = append(identifiers, scopeReference.ID)
		}
	}
	return identifiers
}

// scopeQuotaCooldownAfterFailure copies the model backoff ladder for one non-model quota scope.
// scopeQuotaCooldownAfterFailure 为一个非模型额度作用域复制模型退避阶梯。
func scopeQuotaCooldownAfterFailure(state routingstate.RuntimeScopeState, now time.Time) (time.Time, int) {
	if state.CoolingUntil != nil && state.CoolingUntil.After(now) {
		return *state.CoolingUntil, state.BackoffLevel
	}
	cooldown, nextLevel := nextQuotaCooldown(state.BackoffLevel)
	return now.Add(cooldown), nextLevel
}

// quotaCooldownAfterFailure copies CLIProxyAPI's once-per-window escalation behavior.
// quotaCooldownAfterFailure 复制 CLIProxyAPI 每个窗口最多升级一次的行为。
func quotaCooldownAfterFailure(state routingstate.CredentialModelState, now time.Time) (time.Time, int) {
	if state.CoolingUntil != nil && state.CoolingUntil.After(now) {
		return *state.CoolingUntil, state.BackoffLevel
	}
	cooldown, nextLevel := nextQuotaCooldown(state.BackoffLevel)
	return now.Add(cooldown), nextLevel
}

// nextQuotaCooldown copies CLIProxyAPI's bounded exponential quota ladder with an overflow guard.
// nextQuotaCooldown 复制 CLIProxyAPI 有界指数额度退避阶梯并增加溢出保护。
func nextQuotaCooldown(previousLevel int) (time.Duration, int) {
	if previousLevel < 0 {
		previousLevel = 0
	}
	if previousLevel >= 11 {
		return quotaBackoffMax, previousLevel
	}
	cooldown := quotaBackoffBase * time.Duration(1<<previousLevel)
	if cooldown >= quotaBackoffMax {
		return quotaBackoffMax, previousLevel
	}
	return cooldown, previousLevel + 1
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
