// Package refresh coordinates trusted provider metadata readers into one atomic catalog snapshot.
// refresh 包将受信任供应商元数据读取器协调为一个原子目录快照。
package refresh

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
)

var (
	// ErrDriverNotFound reports a system definition without a trusted registered driver.
	// ErrDriverNotFound 表示系统定义没有已注册的受信任 Driver。
	ErrDriverNotFound = errors.New("trusted provider driver not found")
)

const (
	// credentialRefreshLeadTime refreshes short-lived provider tokens before the next metadata scan can cross expiry.
	// credentialRefreshLeadTime 在下一次元数据扫描可能跨过到期时间前刷新短期供应商令牌。
	credentialRefreshLeadTime = 5 * time.Minute
)

// DriverRegistry resolves one trusted system-provider driver by definition identifier.
// DriverRegistry 按定义标识解析一个受信任系统供应商 Driver。
type DriverRegistry interface {
	// Lookup returns the exact trusted driver for one system definition.
	// Lookup 返回一个系统定义的精确受信任 Driver。
	Lookup(string) (provider.Driver, bool)
}

// CredentialRefresher replaces one protected refreshable credential without exposing token material.
// CredentialRefresher 替换一个受保护的可刷新凭据且不暴露令牌材料。
type CredentialRefresher interface {
	// RefreshCredential returns the persisted replacement metadata for one exact credential.
	// RefreshCredential 返回一个精确凭据的持久化替换元数据。
	RefreshCredential(context.Context, string, string) (providerconfig.Credential, error)
}

// Service refreshes provider-native metadata without implementing any protocol translation.
// Service 刷新供应商原生元数据且不实现任何协议转换。
type Service struct {
	// configurations supplies provider instances and non-secret credential metadata.
	// configurations 提供供应商实例与非秘密凭据元数据。
	configurations providerconfig.Store
	// catalogs atomically persists the complete provider model and resource snapshot.
	// catalogs 原子持久化完整供应商模型与资源快照。
	catalogs catalog.Store
	// drivers resolves code-owned provider behavior.
	// drivers 解析代码拥有的供应商行为。
	drivers DriverRegistry
	// resolver derives local account pool summaries from the collected snapshot.
	// resolver 根据收集到的快照派生本地账号池摘要。
	resolver *resolve.Resolver
	// credentialRefreshers maps exact provider definitions to their proven protected token lifecycle implementation.
	// credentialRefreshers 将精确供应商定义映射到其已验证的受保护令牌生命周期实现。
	credentialRefreshers map[string]CredentialRefresher
	// refreshLocksMu protects the bounded provider-instance refresh lock registry.
	// refreshLocksMu 保护有界的供应商实例刷新锁注册表。
	refreshLocksMu sync.Mutex
	// refreshLocks serializes complete catalog replacements for each provider instance.
	// refreshLocks 按供应商实例串行化完整目录替换。
	refreshLocks map[string]*instanceRefreshLock
}

// instanceRefreshLock serializes one provider instance and tracks waiting or active callers for safe cleanup.
// instanceRefreshLock 串行化一个供应商实例，并跟踪等待或活动调用方以安全清理。
type instanceRefreshLock struct {
	// mutex owns the one-at-a-time provider-instance refresh boundary.
	// mutex 拥有单次仅允许一个调用方的供应商实例刷新边界。
	mutex sync.Mutex
	// references counts active and waiting callers that still use this lock.
	// references 统计仍使用该锁的活动与等待调用方。
	references int
}

// credentialMetadataScope identifies one explicit account-metadata replacement boundary.
// credentialMetadataScope 标识一个显式账号元数据替换边界。
type credentialMetadataScope string

const (
	// credentialMetadataAll refreshes every declared account metadata dimension in one provider observation.
	// credentialMetadataAll 在一次供应商观测中刷新全部已声明账号元数据维度。
	credentialMetadataAll credentialMetadataScope = "all"
	// credentialMetadataEntitlements refreshes plan and authorization evidence without touching usage.
	// credentialMetadataEntitlements 刷新套餐与授权证据且不修改用量。
	credentialMetadataEntitlements credentialMetadataScope = "entitlements"
	// credentialMetadataAllowances refreshes consumable usage without touching plan or authorization evidence.
	// credentialMetadataAllowances 刷新可消费用量且不修改套餐或授权证据。
	credentialMetadataAllowances credentialMetadataScope = "allowances"
)

// NewService creates one provider metadata refresh coordinator.
// NewService 创建一个供应商元数据刷新协调器。
func NewService(configurations providerconfig.Store, catalogs catalog.Store, drivers DriverRegistry) (*Service, error) {
	return NewServiceWithCredentialRefreshers(configurations, catalogs, drivers, nil)
}

// NewServiceWithCredentialRefreshers creates one metadata service with exact provider-owned token refreshers.
// NewServiceWithCredentialRefreshers 创建一个具有精确供应商所属令牌刷新器的元数据服务。
func NewServiceWithCredentialRefreshers(configurations providerconfig.Store, catalogs catalog.Store, drivers DriverRegistry, refreshers map[string]CredentialRefresher) (*Service, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) || dependency.IsNil(drivers) {
		return nil, errors.New("provider configuration, catalog, and driver registries are required")
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return nil, errResolver
	}
	isolatedRefreshers := make(map[string]CredentialRefresher, len(refreshers))
	for definitionID, refresher := range refreshers {
		if definitionID == "" || dependency.IsNil(refresher) {
			return nil, errors.New("credential refresher definition and implementation are required")
		}
		isolatedRefreshers[definitionID] = refresher
	}
	return &Service{configurations: configurations, catalogs: catalogs, drivers: drivers, resolver: targetResolver, credentialRefreshers: isolatedRefreshers, refreshLocks: make(map[string]*instanceRefreshLock)}, nil
}

// lockInstanceRefresh acquires the one exact provider-instance mutation boundary and returns its release function.
// lockInstanceRefresh 获取一个精确供应商实例的变更边界，并返回其释放函数。
func (s *Service) lockInstanceRefresh(instanceID string) func() {
	s.refreshLocksMu.Lock()
	refreshLock := s.refreshLocks[instanceID]
	if refreshLock == nil {
		refreshLock = &instanceRefreshLock{}
		s.refreshLocks[instanceID] = refreshLock
	}
	refreshLock.references++
	s.refreshLocksMu.Unlock()

	refreshLock.mutex.Lock()
	return func() {
		refreshLock.mutex.Unlock()
		s.refreshLocksMu.Lock()
		refreshLock.references--
		if refreshLock.references == 0 && s.refreshLocks[instanceID] == refreshLock {
			delete(s.refreshLocks, instanceID)
		}
		s.refreshLocksMu.Unlock()
	}
}

// Refresh updates only account metadata exposed by each active credential while preserving the code-owned static model catalog.
// Refresh 仅更新每个已启用凭据暴露的账号元数据，并保留代码拥有的静态模型目录。
func (s *Service) Refresh(ctx context.Context, instanceID string, now time.Time) (catalog.Snapshot, error) {
	if ctx == nil {
		return catalog.Snapshot{}, errors.New("context is required")
	}
	if errContext := ctx.Err(); errContext != nil {
		return catalog.Snapshot{}, errContext
	}
	if strings.TrimSpace(instanceID) == "" || now.IsZero() {
		return catalog.Snapshot{}, errors.New("provider instance and refresh evaluation time are required")
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	driver, exists := s.drivers.Lookup(instance.DefinitionID)
	if !exists {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", ErrDriverNotFound, instance.DefinitionID)
	}
	definition := driver.Definition()
	if errReaders := validateDeclaredMetadataReaders(driver, definition); errReaders != nil {
		return catalog.Snapshot{}, errReaders
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return catalog.Snapshot{}, errCredentials
	}
	snapshot, errSnapshot := s.catalogs.Get(ctx, instanceID)
	if errSnapshot != nil {
		return catalog.Snapshot{}, errSnapshot
	}
	// attemptedRefreshes counts credentials whose authentication method declares readable account metadata.
	// attemptedRefreshes 统计其认证方式声明可读取账号元数据的凭据数量。
	attemptedRefreshes := 0
	// successfulRefreshes counts atomic credential metadata replacements completed in this aggregate refresh.
	// successfulRefreshes 统计本次聚合刷新中成功完成的凭据元数据原子替换数量。
	successfulRefreshes := 0
	// refreshErrors retains exact provider failures so an all-failed aggregate refresh remains explicit.
	// refreshErrors 保留精确供应商错误，使全部失败的聚合刷新仍可显式返回错误。
	var refreshErrors []error
	for _, credential := range credentials {
		if credential.Status != providerconfig.CredentialActive {
			continue
		}
		readerFeatures, readerFeaturesExist := definition.ReaderFeaturesForAuthMethod(credential.AuthMethodID)
		if !readerFeaturesExist {
			return catalog.Snapshot{}, errors.New("credential references an unknown authentication method")
		}
		if readerFeatures.PlanReader == providerconfig.SupportSupported || readerFeatures.EntitlementReader == providerconfig.SupportSupported || readerFeatures.AllowanceReader == providerconfig.SupportSupported {
			attemptedRefreshes++
			refreshedSnapshot, errRefresh := s.refreshCredentialMetadata(ctx, instanceID, credential.ID, now, credentialMetadataAll)
			if errRefresh != nil {
				if errContext := ctx.Err(); errContext != nil {
					return catalog.Snapshot{}, errContext
				}
				refreshErrors = append(refreshErrors, fmt.Errorf("refresh credential %s metadata: %w", credential.ID, errRefresh))
				continue
			}
			snapshot = refreshedSnapshot
			successfulRefreshes++
		}
	}
	if attemptedRefreshes > 0 && successfulRefreshes == 0 {
		return catalog.Snapshot{}, errors.Join(refreshErrors...)
	}
	return snapshot, nil
}

// RefreshCredentialEntitlements replaces only one credential's plan and authorization evidence.
// RefreshCredentialEntitlements 仅替换一个凭据的套餐与授权证据。
func (s *Service) RefreshCredentialEntitlements(ctx context.Context, instanceID string, credentialID string, now time.Time) (catalog.Snapshot, error) {
	return s.refreshCredentialMetadata(ctx, instanceID, credentialID, now, credentialMetadataEntitlements)
}

// RefreshCredentialAllowances replaces only one credential's supported usage observations.
// RefreshCredentialAllowances 仅替换一个凭据受支持的用量观测。
func (s *Service) RefreshCredentialAllowances(ctx context.Context, instanceID string, credentialID string, now time.Time) (catalog.Snapshot, error) {
	return s.refreshCredentialMetadata(ctx, instanceID, credentialID, now, credentialMetadataAllowances)
}

// refreshCredentialMetadata performs one reader-bounded account update and preserves every unrelated snapshot collection.
// refreshCredentialMetadata 执行一次受 Reader 边界约束的账号更新，并保留所有无关快照集合。
func (s *Service) refreshCredentialMetadata(ctx context.Context, instanceID string, credentialID string, now time.Time, scope credentialMetadataScope) (catalog.Snapshot, error) {
	if ctx == nil {
		return catalog.Snapshot{}, errors.New("context is required")
	}
	if errContext := ctx.Err(); errContext != nil {
		return catalog.Snapshot{}, errContext
	}
	if strings.TrimSpace(instanceID) == "" || strings.TrimSpace(credentialID) == "" || now.IsZero() {
		return catalog.Snapshot{}, errors.New("provider instance, credential, and refresh evaluation time are required")
	}
	unlockRefresh := s.lockInstanceRefresh(instanceID)
	defer unlockRefresh()
	if errContext := ctx.Err(); errContext != nil {
		return catalog.Snapshot{}, errContext
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	driver, exists := s.drivers.Lookup(instance.DefinitionID)
	if !exists {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", ErrDriverNotFound, instance.DefinitionID)
	}
	definition := driver.Definition()
	if errReaders := validateDeclaredMetadataReaders(driver, definition); errReaders != nil {
		return catalog.Snapshot{}, errReaders
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return catalog.Snapshot{}, errCredentials
	}
	credential, credentialExists := credentialByIdentifier(credentials, credentialID)
	if !credentialExists {
		return catalog.Snapshot{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
	}
	readerFeatures, readerFeaturesExist := definition.ReaderFeaturesForAuthMethod(credential.AuthMethodID)
	if !readerFeaturesExist {
		return catalog.Snapshot{}, errors.New("credential references an unknown authentication method")
	}
	switch scope {
	case credentialMetadataAll:
		if readerFeatures.PlanReader != providerconfig.SupportSupported && readerFeatures.EntitlementReader != providerconfig.SupportSupported && readerFeatures.AllowanceReader != providerconfig.SupportSupported {
			return catalog.Snapshot{}, errors.New("credential authentication method does not support metadata refresh")
		}
	case credentialMetadataEntitlements:
		if readerFeatures.PlanReader != providerconfig.SupportSupported && readerFeatures.EntitlementReader != providerconfig.SupportSupported {
			return catalog.Snapshot{}, errors.New("credential authentication method does not support entitlement refresh")
		}
	case credentialMetadataAllowances:
		if readerFeatures.AllowanceReader != providerconfig.SupportSupported {
			return catalog.Snapshot{}, errors.New("credential authentication method does not support usage refresh")
		}
	default:
		return catalog.Snapshot{}, errors.New("credential metadata refresh scope is invalid")
	}
	preparedCredential, errPrepare := s.prepareCredential(ctx, definition, credential, now)
	if errPrepare != nil {
		return catalog.Snapshot{}, errPrepare
	}
	if !preparedCredential.RuntimeEligibleAt(now) {
		return catalog.Snapshot{}, errors.New("credential is not runtime eligible for metadata refresh")
	}
	credential = preparedCredential
	current, errCurrent := s.catalogs.Get(ctx, instanceID)
	if errCurrent != nil {
		return catalog.Snapshot{}, errCurrent
	}
	metadata := provider.CredentialMetadataResult{}
	if aggregateReader, supported := driver.(provider.CredentialMetadataReader); supported {
		observed, errObserved := aggregateReader.ReadCredentialMetadata(ctx, instance, credential)
		if errObserved != nil {
			return catalog.Snapshot{}, errObserved
		}
		metadata = observed
	} else {
		if scope != credentialMetadataAllowances && readerFeatures.PlanReader == providerconfig.SupportSupported {
			planReader, supported := driver.(provider.PlanReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares plan reading without a PlanReader")
			}
			plan, errPlan := planReader.ReadPlan(ctx, instance, credential)
			if errPlan != nil {
				return catalog.Snapshot{}, errPlan
			}
			metadata.Plan = &plan
		}
		if scope != credentialMetadataAllowances && readerFeatures.EntitlementReader == providerconfig.SupportSupported {
			entitlementReader, supported := driver.(provider.EntitlementReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares entitlement reading without an EntitlementReader")
			}
			entitlements, errEntitlements := entitlementReader.ReadEntitlements(ctx, instance, credential)
			if errEntitlements != nil {
				return catalog.Snapshot{}, errEntitlements
			}
			metadata.Entitlements = entitlements
		}
		if scope != credentialMetadataEntitlements && readerFeatures.AllowanceReader == providerconfig.SupportSupported {
			allowanceReader, supported := driver.(provider.AllowanceReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares allowance reading without an AllowanceReader")
			}
			allowances, errAllowances := allowanceReader.ReadAllowances(ctx, instance, credential)
			if errAllowances != nil {
				return catalog.Snapshot{}, errAllowances
			}
			metadata.Allowances = allowances
		}
	}
	if errOwnership := validateCredentialMetadataOwnership(credential, metadata.Plan, metadata.Entitlements, metadata.ServiceEntitlements, metadata.Allowances); errOwnership != nil {
		return catalog.Snapshot{}, fmt.Errorf("validate provider metadata ownership for credential %s: %w", credential.ID, errOwnership)
	}
	updated := current
	if scope != credentialMetadataAllowances {
		if readerFeatures.PlanReader == providerconfig.SupportSupported {
			if metadata.Plan == nil {
				return catalog.Snapshot{}, errors.New("provider metadata omitted its declared plan")
			}
			updated.Plans = plansWithoutCredential(current.Plans, credential.ID)
			updated.Plans = append(updated.Plans, *metadata.Plan)
		}
		if readerFeatures.EntitlementReader == providerconfig.SupportSupported {
			updated.Entitlements = entitlementsWithoutCredential(current.Entitlements, credential.ID)
			updated.Entitlements = append(updated.Entitlements, metadata.Entitlements...)
			if metadata.ServiceEntitlements != nil {
				updated.ServiceEntitlements = serviceEntitlementsWithoutCredential(current.ServiceEntitlements, credential.ID)
				updated.ServiceEntitlements = append(updated.ServiceEntitlements, metadata.ServiceEntitlements...)
			}
		}
	}
	if scope != credentialMetadataEntitlements && readerFeatures.AllowanceReader == providerconfig.SupportSupported {
		updated.Allowances = allowancesWithoutCredentialOwnership(current.Allowances, credential)
		updated.Allowances = append(updated.Allowances, metadata.Allowances...)
	}
	return s.saveCredentialMetadataSnapshot(ctx, updated, now)
}

// saveCredentialMetadataSnapshot validates, re-summarizes, and atomically persists one account-only revision.
// saveCredentialMetadataSnapshot 校验、重新汇总并原子持久化一个仅账号变更的修订。
func (s *Service) saveCredentialMetadataSnapshot(ctx context.Context, snapshot catalog.Snapshot, now time.Time) (catalog.Snapshot, error) {
	snapshot.Revision++
	snapshot.ObservedAt = now.UTC()
	pools, errPools := s.resolver.SummarizeSnapshot(ctx, snapshot, now, snapshot.Revision)
	if errPools != nil {
		return catalog.Snapshot{}, fmt.Errorf("summarize refreshed credential metadata: %w", errPools)
	}
	snapshot.Pools = pools
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	if errSave := s.catalogs.Save(ctx, snapshot); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return snapshot, nil
}

// credentialByIdentifier returns one exact configured credential without fallback selection.
// credentialByIdentifier 返回一个精确配置凭据且不进行回退选择。
func credentialByIdentifier(credentials []providerconfig.Credential, credentialID string) (providerconfig.Credential, bool) {
	for _, credential := range credentials {
		if credential.ID == credentialID {
			return credential, true
		}
	}
	return providerconfig.Credential{}, false
}

// plansWithoutCredential removes only one credential's prior plan observation.
// plansWithoutCredential 仅删除一个凭据之前的套餐观测。
func plansWithoutCredential(plans []catalog.PlanSnapshot, credentialID string) []catalog.PlanSnapshot {
	retained := make([]catalog.PlanSnapshot, 0, len(plans))
	for _, plan := range plans {
		if plan.CredentialID != credentialID {
			retained = append(retained, plan)
		}
	}
	return retained
}

// entitlementsWithoutCredential removes only one credential's prior model authorization evidence.
// entitlementsWithoutCredential 仅删除一个凭据之前的模型授权证据。
func entitlementsWithoutCredential(entitlements []catalog.ModelEntitlement, credentialID string) []catalog.ModelEntitlement {
	retained := make([]catalog.ModelEntitlement, 0, len(entitlements))
	for _, entitlement := range entitlements {
		if entitlement.CredentialID != credentialID {
			retained = append(retained, entitlement)
		}
	}
	return retained
}

// serviceEntitlementsWithoutCredential removes only one credential's prior special-service authorization evidence.
// serviceEntitlementsWithoutCredential 仅删除一个凭据之前的特殊服务授权证据。
func serviceEntitlementsWithoutCredential(entitlements []catalog.ServiceEntitlement, credentialID string) []catalog.ServiceEntitlement {
	retained := make([]catalog.ServiceEntitlement, 0, len(entitlements))
	for _, entitlement := range entitlements {
		if entitlement.CredentialID != credentialID {
			retained = append(retained, entitlement)
		}
	}
	return retained
}

// allowancesWithoutCredentialOwnership removes direct and explicitly bound shared allowances owned by one credential.
// allowancesWithoutCredentialOwnership 删除一个凭据拥有的直接额度与显式绑定共享额度。
func allowancesWithoutCredentialOwnership(allowances []catalog.AllowanceSnapshot, credential providerconfig.Credential) []catalog.AllowanceSnapshot {
	retained := make([]catalog.AllowanceSnapshot, 0, len(allowances))
	for _, allowance := range allowances {
		owned := allowance.Scope == catalog.ScopeCredential && allowance.ScopeID == credential.ID
		if !owned {
			owned = credentialOwnsSharedAllowanceScope(credential, allowance)
		}
		if !owned {
			retained = append(retained, allowance)
		}
	}
	return retained
}

// prepareCredential refreshes only active, refreshable credentials whose known expiry is inside the safety lead time.
// prepareCredential 仅刷新已启用、可刷新且已知到期时间进入安全提前量的凭据。
func (s *Service) prepareCredential(ctx context.Context, definition providerconfig.ProviderDefinition, credential providerconfig.Credential, now time.Time) (providerconfig.Credential, error) {
	if credential.Status != providerconfig.CredentialActive || credential.ExpiresAt == nil || credential.ExpiresAt.After(now.Add(credentialRefreshLeadTime)) {
		return credential, nil
	}
	authMethod, authMethodExists := definition.AuthMethod(credential.AuthMethodID)
	if !authMethodExists || !authMethod.Refreshable {
		return credential, nil
	}
	refresher, refresherExists := s.credentialRefreshers[definition.ID]
	if !refresherExists {
		return credential, nil
	}
	refreshed, errRefresh := refresher.RefreshCredential(ctx, credential.ProviderInstanceID, credential.ID)
	if errRefresh != nil {
		return providerconfig.Credential{}, errRefresh
	}
	if refreshed.ID != credential.ID || refreshed.ProviderInstanceID != credential.ProviderInstanceID || refreshed.AuthMethodID != credential.AuthMethodID {
		return providerconfig.Credential{}, errors.New("credential refresher changed immutable ownership")
	}
	if !refreshed.RuntimeEligibleAt(now) {
		return providerconfig.Credential{}, errors.New("credential refresher returned an ineligible credential")
	}
	return refreshed, nil
}

// validateCredentialMetadataOwnership verifies that one reader cannot attach account metadata to another credential or unbound shared scope.
// validateCredentialMetadataOwnership 校验一个读取器不能把账号元数据挂到其他凭据或未绑定的共享作用域。
func validateCredentialMetadataOwnership(credential providerconfig.Credential, plan *catalog.PlanSnapshot, entitlements []catalog.ModelEntitlement, serviceEntitlements []catalog.ServiceEntitlement, allowances []catalog.AllowanceSnapshot) error {
	if plan != nil {
		if plan.ProviderInstanceID != credential.ProviderInstanceID {
			return fmt.Errorf("plan %s belongs to provider instance %s, not %s", plan.ID, plan.ProviderInstanceID, credential.ProviderInstanceID)
		}
		if plan.CredentialID != credential.ID {
			return fmt.Errorf("plan %s belongs to credential %s, not %s", plan.ID, plan.CredentialID, credential.ID)
		}
	}
	for _, entitlement := range entitlements {
		if entitlement.ProviderInstanceID != credential.ProviderInstanceID {
			return fmt.Errorf("entitlement %s belongs to provider instance %s, not %s", entitlement.ID, entitlement.ProviderInstanceID, credential.ProviderInstanceID)
		}
		if entitlement.CredentialID != credential.ID {
			return fmt.Errorf("entitlement %s belongs to credential %s, not %s", entitlement.ID, entitlement.CredentialID, credential.ID)
		}
	}
	for _, entitlement := range serviceEntitlements {
		if entitlement.ProviderInstanceID != credential.ProviderInstanceID {
			return fmt.Errorf("service entitlement %s belongs to provider instance %s, not %s", entitlement.ID, entitlement.ProviderInstanceID, credential.ProviderInstanceID)
		}
		if entitlement.CredentialID != credential.ID {
			return fmt.Errorf("service entitlement %s belongs to credential %s, not %s", entitlement.ID, entitlement.CredentialID, credential.ID)
		}
	}
	for _, allowance := range allowances {
		if allowance.ProviderInstanceID != credential.ProviderInstanceID {
			return fmt.Errorf("allowance %s belongs to provider instance %s, not %s", allowance.ID, allowance.ProviderInstanceID, credential.ProviderInstanceID)
		}
		switch allowance.Scope {
		case catalog.ScopeCredential:
			if allowance.ScopeID != credential.ID {
				return fmt.Errorf("allowance %s belongs to credential %s, not %s", allowance.ID, allowance.ScopeID, credential.ID)
			}
		case catalog.ScopeSubscription, catalog.ScopeOrganization, catalog.ScopeProject, catalog.ScopeBillingAccount:
			if !credentialOwnsSharedAllowanceScope(credential, allowance) {
				return fmt.Errorf("allowance %s belongs to unbound %s scope %s", allowance.ID, allowance.Scope, allowance.ScopeID)
			}
		}
	}
	return nil
}

// preserveCredentialMetadata retains only unexpired last-known-good account facts after one credential refresh failure.
// preserveCredentialMetadata 在单个凭据刷新失败后仅保留未过期的最后可信账号事实。
func preserveCredentialMetadata(credential providerconfig.Credential, current catalog.Snapshot, now time.Time, planByID map[string]catalog.PlanSnapshot, plans *[]catalog.PlanSnapshot, entitlementByID map[string]catalog.ModelEntitlement, entitlements *[]catalog.ModelEntitlement, allowanceByID map[string]catalog.AllowanceSnapshot, allowances *[]catalog.AllowanceSnapshot) error {
	for _, plan := range current.Plans {
		if plan.CredentialID == credential.ID && metadataCurrent(plan.ObservedAt, plan.ExpiresAt, now) {
			if errAppend := appendUnique(plan.ID, plan, planByID, plans); errAppend != nil {
				return errAppend
			}
		}
	}
	for _, entitlement := range current.Entitlements {
		if entitlement.CredentialID == credential.ID && metadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) {
			if errAppend := appendUnique(entitlement.ID, entitlement, entitlementByID, entitlements); errAppend != nil {
				return errAppend
			}
		}
	}
	for _, allowance := range current.Allowances {
		owned := allowance.Scope == catalog.ScopeCredential && allowance.ScopeID == credential.ID
		if !owned {
			owned = credentialOwnsSharedAllowanceScope(credential, allowance)
		}
		if owned && metadataCurrent(allowance.ObservedAt, allowance.ExpiresAt, now) {
			if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, allowances); errAppend != nil {
				return errAppend
			}
		}
	}
	return nil
}

// metadataCurrent reports whether provider, token, system, or operator evidence remains current.
// metadataCurrent 报告供应商、Token、系统或操作员证据是否仍然有效。
func metadataCurrent(observedAt time.Time, expiresAt time.Time, now time.Time) bool {
	return !observedAt.IsZero() && !observedAt.After(now) && (expiresAt.IsZero() || expiresAt.After(now))
}

// removeCredentialServiceEntitlements replaces one credential's prior service facts before appending a fresh atomic observation.
// removeCredentialServiceEntitlements 在追加新的原子观测前替换一个凭据之前的服务事实。
func removeCredentialServiceEntitlements(current []catalog.ServiceEntitlement, byID map[string]catalog.ServiceEntitlement, credentialID string) []catalog.ServiceEntitlement {
	filtered := make([]catalog.ServiceEntitlement, 0, len(current))
	for _, entitlement := range current {
		if entitlement.CredentialID == credentialID {
			delete(byID, entitlement.ID)
			continue
		}
		filtered = append(filtered, entitlement)
	}
	return filtered
}

// credentialOwnsSharedAllowanceScope reports whether one provider-reported shared allowance matches an exact stored credential scope reference.
// credentialOwnsSharedAllowanceScope 报告供应商返回的共享额度是否精确匹配已存储的凭据作用域引用。
func credentialOwnsSharedAllowanceScope(credential providerconfig.Credential, allowance catalog.AllowanceSnapshot) bool {
	for _, scopeReference := range credential.ScopeRefs {
		if scopeReference.Kind == string(allowance.Scope) && scopeReference.ID == allowance.ScopeID {
			return true
		}
	}
	return false
}

// validateDeclaredMetadataReaders rejects supported feature declarations that have no concrete trusted reader.
// validateDeclaredMetadataReaders 拒绝没有具体受信任读取器的已支持功能声明。
func validateDeclaredMetadataReaders(driver provider.Driver, definition providerconfig.ProviderDefinition) error {
	_, supportsAggregate := driver.(provider.CredentialMetadataReader)
	_, supportsPlan := driver.(provider.PlanReader)
	_, supportsEntitlements := driver.(provider.EntitlementReader)
	_, supportsAllowances := driver.(provider.AllowanceReader)
	if definition.Features.PlanReader == providerconfig.SupportSupported && !supportsAggregate && !supportsPlan {
		return errors.New("provider declares plan reading without a PlanReader")
	}
	if definition.Features.EntitlementReader == providerconfig.SupportSupported && !supportsAggregate && !supportsEntitlements {
		return errors.New("provider declares entitlement reading without an EntitlementReader")
	}
	if definition.Features.AllowanceReader == providerconfig.SupportSupported && !supportsAggregate && !supportsAllowances {
		return errors.New("provider declares allowance reading without an AllowanceReader")
	}
	return nil
}

// appendUnique appends one provider record or accepts an identical shared-scope duplicate.
// appendUnique 追加一个供应商记录，或接受内容相同的共享作用域重复记录。
func appendUnique[T any](identifier string, value T, existing map[string]T, destination *[]T) error {
	if current, exists := existing[identifier]; exists {
		if reflect.DeepEqual(current, value) {
			return nil
		}
		return fmt.Errorf("provider returned conflicting records with identifier %s", identifier)
	}
	existing[identifier] = value
	*destination = append(*destination, value)
	return nil
}
