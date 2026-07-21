// Package refresh coordinates trusted provider metadata readers into one atomic catalog snapshot.
// refresh 包将受信任供应商元数据读取器协调为一个原子目录快照。
package refresh

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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
	credentialRefreshLeadTime = time.Minute
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
}

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
	return &Service{configurations: configurations, catalogs: catalogs, drivers: drivers, resolver: targetResolver, credentialRefreshers: isolatedRefreshers}, nil
}

// Refresh reads one exact system provider instance and atomically replaces its catalog.
// Refresh 读取一个精确系统供应商实例并原子替换其目录。
func (s *Service) Refresh(ctx context.Context, instanceID string, now time.Time) (catalog.Snapshot, error) {
	return s.refresh(ctx, instanceID, nil, now)
}

// RefreshWithCredential performs model discovery with one explicitly selected same-instance credential.
// RefreshWithCredential 使用一个显式选择的同实例凭据执行模型发现。
func (s *Service) RefreshWithCredential(ctx context.Context, instanceID string, credentialID string, now time.Time) (catalog.Snapshot, error) {
	if ctx == nil {
		return catalog.Snapshot{}, errors.New("context is required")
	}
	if errContext := ctx.Err(); errContext != nil {
		return catalog.Snapshot{}, errContext
	}
	if strings.TrimSpace(credentialID) == "" || now.IsZero() {
		return catalog.Snapshot{}, errors.New("credential-scoped discovery requires credential and evaluation time")
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	driver, exists := s.drivers.Lookup(instance.DefinitionID)
	if !exists {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", ErrDriverNotFound, instance.DefinitionID)
	}
	if driver.Definition().Features.ModelDiscovery != providerconfig.SupportSupported {
		return catalog.Snapshot{}, errors.New("provider does not support credential-scoped model discovery")
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instanceID)
	if errCredentials != nil {
		return catalog.Snapshot{}, errCredentials
	}
	for _, credential := range credentials {
		if credential.ID == credentialID {
			return s.refresh(ctx, instanceID, &credential, now)
		}
	}
	return catalog.Snapshot{}, fmt.Errorf("%w: provider credential %s", providerconfig.ErrNotFound, credentialID)
}

// refresh executes one atomic metadata replacement with an optional exact discovery credential.
// refresh 使用一个可选的精确发现凭据执行一次原子元数据替换。
func (s *Service) refresh(ctx context.Context, instanceID string, discoveryCredential *providerconfig.Credential, now time.Time) (catalog.Snapshot, error) {
	if ctx == nil {
		return catalog.Snapshot{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return catalog.Snapshot{}, err
	}
	if now.IsZero() {
		return catalog.Snapshot{}, errors.New("refresh evaluation time is required")
	}
	instance, errInstance := s.configurations.GetInstance(ctx, instanceID)
	if errInstance != nil {
		return catalog.Snapshot{}, errInstance
	}
	driver, exists := s.drivers.Lookup(instance.DefinitionID)
	if !exists {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", ErrDriverNotFound, instance.DefinitionID)
	}
	driverDefinition := driver.Definition()
	if errReaders := validateDeclaredMetadataReaders(driver, driverDefinition); errReaders != nil {
		return catalog.Snapshot{}, errReaders
	}
	discoverer, supportsDiscovery := driver.(provider.ModelDiscoverer)
	// discovery preserves the prior model catalog when this provider exposes only account metadata readers.
	// discovery 在供应商只暴露账号元数据读取器时保留之前的模型目录。
	discovery := provider.ModelDiscoveryResult{ObservedAt: now}
	currentSnapshot, errCurrentSnapshot := s.catalogs.Get(ctx, instance.ID)
	if errCurrentSnapshot == nil {
		discovery.Models = append([]catalog.ProviderModel(nil), currentSnapshot.Models...)
		discovery.Offerings = append([]catalog.ModelOffering(nil), currentSnapshot.Offerings...)
		discovery.Profiles = append([]catalog.ExecutionProfile(nil), currentSnapshot.Profiles...)
	} else if !errors.Is(errCurrentSnapshot, catalog.ErrSnapshotNotFound) {
		return catalog.Snapshot{}, errCurrentSnapshot
	}
	if driverDefinition.Features.ModelDiscovery == providerconfig.SupportSupported {
		if !supportsDiscovery {
			return catalog.Snapshot{}, errors.New("provider declares model discovery without a ModelDiscoverer")
		}
		freshDiscovery, errDiscovery := discoverer.DiscoverModels(ctx, provider.DiscoveryRequest{ProviderInstance: instance, Credential: discoveryCredential})
		if errDiscovery != nil {
			return catalog.Snapshot{}, fmt.Errorf("discover provider models: %w", errDiscovery)
		}
		if freshDiscovery.ObservedAt.IsZero() {
			return catalog.Snapshot{}, errors.New("provider model discovery observed time is required")
		}
		discovery = freshDiscovery
	}
	credentials, errCredentials := s.configurations.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		return catalog.Snapshot{}, errCredentials
	}
	plans := make([]catalog.PlanSnapshot, 0)
	entitlements := make([]catalog.ModelEntitlement, 0)
	serviceEntitlements := make([]catalog.ServiceEntitlement, 0)
	allowances := make([]catalog.AllowanceSnapshot, 0)
	planByID := make(map[string]catalog.PlanSnapshot)
	entitlementByID := make(map[string]catalog.ModelEntitlement)
	serviceEntitlementByID := make(map[string]catalog.ServiceEntitlement)
	allowanceByID := make(map[string]catalog.AllowanceSnapshot)
	if errCurrentSnapshot == nil && driverDefinition.Features.PlanReader != providerconfig.SupportSupported {
		for _, plan := range currentSnapshot.Plans {
			if metadataCurrent(plan.ObservedAt, plan.ExpiresAt, now) {
				if errAppend := appendUnique(plan.ID, plan, planByID, &plans); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
		}
	}
	if errCurrentSnapshot == nil && driverDefinition.Features.EntitlementReader != providerconfig.SupportSupported {
		for _, entitlement := range currentSnapshot.Entitlements {
			if metadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) {
				if errAppend := appendUnique(entitlement.ID, entitlement, entitlementByID, &entitlements); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
		}
	}
	if errCurrentSnapshot == nil && driverDefinition.Features.AllowanceReader != providerconfig.SupportSupported {
		for _, allowance := range currentSnapshot.Allowances {
			if metadataCurrent(allowance.ObservedAt, allowance.ExpiresAt, now) {
				if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, &allowances); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
		}
	}
	if errCurrentSnapshot == nil {
		for _, entitlement := range currentSnapshot.ServiceEntitlements {
			if !metadataCurrent(entitlement.ObservedAt, entitlement.ExpiresAt, now) {
				continue
			}
			if errAppend := appendUnique(entitlement.ID, entitlement, serviceEntitlementByID, &serviceEntitlements); errAppend != nil {
				return catalog.Snapshot{}, errAppend
			}
		}
	}
	for _, credential := range credentials {
		preparedCredential, errPrepare := s.prepareCredential(ctx, driverDefinition, credential, now)
		if errPrepare != nil {
			if errPreserve := preserveCredentialMetadata(credential, currentSnapshot, now, planByID, &plans, entitlementByID, &entitlements, allowanceByID, &allowances); errPreserve != nil {
				return catalog.Snapshot{}, errPreserve
			}
			continue
		}
		credential = preparedCredential
		if !credential.RuntimeEligibleAt(now) {
			if errPreserve := preserveCredentialMetadata(credential, currentSnapshot, now, planByID, &plans, entitlementByID, &entitlements, allowanceByID, &allowances); errPreserve != nil {
				return catalog.Snapshot{}, errPreserve
			}
			continue
		}
		// aggregateReader preserves consistency when one provider response contains multiple metadata classes.
		// aggregateReader 在一个供应商响应包含多类元数据时保持一致性。
		if aggregateReader, supported := driver.(provider.CredentialMetadataReader); supported {
			metadata, errMetadata := aggregateReader.ReadCredentialMetadata(ctx, instance, credential)
			if errMetadata != nil {
				if errPreserve := preserveCredentialMetadata(credential, currentSnapshot, now, planByID, &plans, entitlementByID, &entitlements, allowanceByID, &allowances); errPreserve != nil {
					return catalog.Snapshot{}, errPreserve
				}
				continue
			}
			if errOwnership := validateCredentialMetadataOwnership(credential, metadata.Plan, metadata.Entitlements, metadata.ServiceEntitlements, metadata.Allowances); errOwnership != nil {
				return catalog.Snapshot{}, fmt.Errorf("validate provider metadata ownership for credential %s: %w", credential.ID, errOwnership)
			}
			if driverDefinition.Features.PlanReader == providerconfig.SupportSupported {
				if metadata.Plan == nil {
					return catalog.Snapshot{}, errors.New("provider aggregate metadata omitted its declared plan")
				}
				if errAppend := appendUnique(metadata.Plan.ID, *metadata.Plan, planByID, &plans); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			} else if metadata.Plan != nil {
				return catalog.Snapshot{}, errors.New("provider aggregate metadata returned an undeclared plan")
			}
			if driverDefinition.Features.EntitlementReader != providerconfig.SupportSupported && len(metadata.Entitlements) > 0 {
				return catalog.Snapshot{}, errors.New("provider aggregate metadata returned undeclared entitlements")
			}
			for _, entitlement := range metadata.Entitlements {
				if errAppend := appendUnique(entitlement.ID, entitlement, entitlementByID, &entitlements); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
			if metadata.ServiceEntitlements != nil {
				serviceEntitlements = removeCredentialServiceEntitlements(serviceEntitlements, serviceEntitlementByID, credential.ID)
			}
			for _, entitlement := range metadata.ServiceEntitlements {
				if errAppend := appendUnique(entitlement.ID, entitlement, serviceEntitlementByID, &serviceEntitlements); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
			if driverDefinition.Features.AllowanceReader != providerconfig.SupportSupported && len(metadata.Allowances) > 0 {
				return catalog.Snapshot{}, errors.New("provider aggregate metadata returned undeclared allowances")
			}
			for _, allowance := range metadata.Allowances {
				if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, &allowances); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
			continue
		}
		// credentialMetadata stages independent reader results so a later read failure cannot commit a partial account refresh.
		// credentialMetadata 暂存独立读取器结果，避免后续读取失败提交部分账号刷新。
		credentialMetadata := provider.CredentialMetadataResult{}
		readFailed := false
		if driverDefinition.Features.PlanReader == providerconfig.SupportSupported {
			planReader, supported := driver.(provider.PlanReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares plan reading without a PlanReader")
			}
			plan, errPlan := planReader.ReadPlan(ctx, instance, credential)
			if errPlan != nil {
				readFailed = true
			} else {
				credentialMetadata.Plan = &plan
			}
		}
		if !readFailed && driverDefinition.Features.EntitlementReader == providerconfig.SupportSupported {
			entitlementReader, supported := driver.(provider.EntitlementReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares entitlement reading without an EntitlementReader")
			}
			credentialEntitlements, errEntitlements := entitlementReader.ReadEntitlements(ctx, instance, credential)
			if errEntitlements != nil {
				readFailed = true
			} else {
				credentialMetadata.Entitlements = credentialEntitlements
			}
		}
		if !readFailed && driverDefinition.Features.AllowanceReader == providerconfig.SupportSupported {
			allowanceReader, supported := driver.(provider.AllowanceReader)
			if !supported {
				return catalog.Snapshot{}, errors.New("provider declares allowance reading without an AllowanceReader")
			}
			credentialAllowances, errAllowances := allowanceReader.ReadAllowances(ctx, instance, credential)
			if errAllowances != nil {
				readFailed = true
			} else {
				credentialMetadata.Allowances = credentialAllowances
			}
		}
		if readFailed {
			if errPreserve := preserveCredentialMetadata(credential, currentSnapshot, now, planByID, &plans, entitlementByID, &entitlements, allowanceByID, &allowances); errPreserve != nil {
				return catalog.Snapshot{}, errPreserve
			}
			continue
		}
		if errOwnership := validateCredentialMetadataOwnership(credential, credentialMetadata.Plan, credentialMetadata.Entitlements, nil, credentialMetadata.Allowances); errOwnership != nil {
			return catalog.Snapshot{}, fmt.Errorf("validate provider metadata ownership for credential %s: %w", credential.ID, errOwnership)
		}
		if credentialMetadata.Plan != nil {
			if errAppend := appendUnique(credentialMetadata.Plan.ID, *credentialMetadata.Plan, planByID, &plans); errAppend != nil {
				return catalog.Snapshot{}, errAppend
			}
		}
		for _, entitlement := range credentialMetadata.Entitlements {
			if errAppend := appendUnique(entitlement.ID, entitlement, entitlementByID, &entitlements); errAppend != nil {
				return catalog.Snapshot{}, errAppend
			}
		}
		for _, allowance := range credentialMetadata.Allowances {
			if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, &allowances); errAppend != nil {
				return catalog.Snapshot{}, errAppend
			}
		}
	}
	revision := uint64(1)
	if errCurrentSnapshot == nil {
		revision = currentSnapshot.Revision + 1
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID:  instance.ID,
		Models:              append([]catalog.ProviderModel(nil), discovery.Models...),
		Offerings:           append([]catalog.ModelOffering(nil), discovery.Offerings...),
		Profiles:            append([]catalog.ExecutionProfile(nil), discovery.Profiles...),
		Services:            append([]catalog.ProviderService(nil), currentSnapshot.Services...),
		ServiceOfferings:    append([]catalog.ServiceOffering(nil), currentSnapshot.ServiceOfferings...),
		Entitlements:        entitlements,
		ServiceEntitlements: serviceEntitlements,
		Plans:               plans,
		Allowances:          allowances,
		Revision:            revision,
		ObservedAt:          discovery.ObservedAt,
	}
	if errValidate := snapshot.Validate(); errValidate != nil {
		return catalog.Snapshot{}, errValidate
	}
	pools, errPools := s.resolver.SummarizeSnapshot(ctx, snapshot, now, revision)
	if errPools != nil {
		return catalog.Snapshot{}, fmt.Errorf("summarize provider account pools: %w", errPools)
	}
	snapshot.Pools = pools
	if errSave := s.catalogs.Save(ctx, snapshot); errSave != nil {
		return catalog.Snapshot{}, errSave
	}
	return snapshot, nil
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
