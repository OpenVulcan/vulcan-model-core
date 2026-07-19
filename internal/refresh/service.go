// Package refresh coordinates trusted provider metadata readers into one atomic catalog snapshot.
// refresh 包将受信任供应商元数据读取器协调为一个原子目录快照。
package refresh

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

// DriverRegistry resolves one trusted system-provider driver by definition identifier.
// DriverRegistry 按定义标识解析一个受信任系统供应商 Driver。
type DriverRegistry interface {
	// Lookup returns the exact trusted driver for one system definition.
	// Lookup 返回一个系统定义的精确受信任 Driver。
	Lookup(string) (provider.Driver, bool)
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
}

// NewService creates one provider metadata refresh coordinator.
// NewService 创建一个供应商元数据刷新协调器。
func NewService(configurations providerconfig.Store, catalogs catalog.Store, drivers DriverRegistry) (*Service, error) {
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) || dependency.IsNil(drivers) {
		return nil, errors.New("provider configuration, catalog, and driver registries are required")
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return nil, errResolver
	}
	return &Service{configurations: configurations, catalogs: catalogs, drivers: drivers, resolver: targetResolver}, nil
}

// Refresh reads one exact system provider instance and atomically replaces its catalog.
// Refresh 读取一个精确系统供应商实例并原子替换其目录。
func (s *Service) Refresh(ctx context.Context, instanceID string, now time.Time) (catalog.Snapshot, error) {
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
		freshDiscovery, errDiscovery := discoverer.DiscoverModels(ctx, provider.DiscoveryRequest{ProviderInstance: instance})
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
	allowances := make([]catalog.AllowanceSnapshot, 0)
	planByID := make(map[string]catalog.PlanSnapshot)
	entitlementByID := make(map[string]catalog.ModelEntitlement)
	allowanceByID := make(map[string]catalog.AllowanceSnapshot)
	for _, credential := range credentials {
		if !credential.RuntimeEligibleAt(now) {
			continue
		}
		// aggregateReader preserves consistency when one provider response contains multiple metadata classes.
		// aggregateReader 在一个供应商响应包含多类元数据时保持一致性。
		if aggregateReader, supported := driver.(provider.CredentialMetadataReader); supported {
			metadata, errMetadata := aggregateReader.ReadCredentialMetadata(ctx, instance, credential)
			if errMetadata != nil {
				return catalog.Snapshot{}, fmt.Errorf("read provider metadata for credential %s: %w", credential.ID, errMetadata)
			}
			if errOwnership := validateCredentialMetadataOwnership(credential, metadata.Plan, metadata.Entitlements, metadata.Allowances); errOwnership != nil {
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
		if planReader, supported := driver.(provider.PlanReader); driverDefinition.Features.PlanReader == providerconfig.SupportSupported && supported {
			plan, errPlan := planReader.ReadPlan(ctx, instance, credential)
			if errPlan != nil {
				return catalog.Snapshot{}, fmt.Errorf("read provider plan for credential %s: %w", credential.ID, errPlan)
			}
			if errOwnership := validateCredentialMetadataOwnership(credential, &plan, nil, nil); errOwnership != nil {
				return catalog.Snapshot{}, fmt.Errorf("validate provider plan ownership for credential %s: %w", credential.ID, errOwnership)
			}
			if errAppend := appendUnique(plan.ID, plan, planByID, &plans); errAppend != nil {
				return catalog.Snapshot{}, errAppend
			}
		}
		if entitlementReader, supported := driver.(provider.EntitlementReader); driverDefinition.Features.EntitlementReader == providerconfig.SupportSupported && supported {
			credentialEntitlements, errEntitlements := entitlementReader.ReadEntitlements(ctx, instance, credential)
			if errEntitlements != nil {
				return catalog.Snapshot{}, fmt.Errorf("read provider entitlements for credential %s: %w", credential.ID, errEntitlements)
			}
			if errOwnership := validateCredentialMetadataOwnership(credential, nil, credentialEntitlements, nil); errOwnership != nil {
				return catalog.Snapshot{}, fmt.Errorf("validate provider entitlement ownership for credential %s: %w", credential.ID, errOwnership)
			}
			for _, entitlement := range credentialEntitlements {
				if errAppend := appendUnique(entitlement.ID, entitlement, entitlementByID, &entitlements); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
		}
		if allowanceReader, supported := driver.(provider.AllowanceReader); driverDefinition.Features.AllowanceReader == providerconfig.SupportSupported && supported {
			credentialAllowances, errAllowances := allowanceReader.ReadAllowances(ctx, instance, credential)
			if errAllowances != nil {
				return catalog.Snapshot{}, fmt.Errorf("read provider allowances for credential %s: %w", credential.ID, errAllowances)
			}
			if errOwnership := validateCredentialMetadataOwnership(credential, nil, nil, credentialAllowances); errOwnership != nil {
				return catalog.Snapshot{}, fmt.Errorf("validate provider allowance ownership for credential %s: %w", credential.ID, errOwnership)
			}
			for _, allowance := range credentialAllowances {
				if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, &allowances); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
		}
	}
	revision := uint64(1)
	if errCurrentSnapshot == nil {
		revision = currentSnapshot.Revision + 1
	}
	snapshot := catalog.Snapshot{
		ProviderInstanceID: instance.ID,
		Models:             append([]catalog.ProviderModel(nil), discovery.Models...),
		Offerings:          append([]catalog.ModelOffering(nil), discovery.Offerings...),
		Profiles:           append([]catalog.ExecutionProfile(nil), discovery.Profiles...),
		Entitlements:       entitlements,
		Plans:              plans,
		Allowances:         allowances,
		Revision:           revision,
		ObservedAt:         discovery.ObservedAt,
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

// validateCredentialMetadataOwnership verifies that one reader cannot attach account metadata to another credential or unbound shared scope.
// validateCredentialMetadataOwnership 校验一个读取器不能把账号元数据挂到其他凭据或未绑定的共享作用域。
func validateCredentialMetadataOwnership(credential providerconfig.Credential, plan *catalog.PlanSnapshot, entitlements []catalog.ModelEntitlement, allowances []catalog.AllowanceSnapshot) error {
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
