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
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
)

var (
	// ErrDriverNotFound reports a system definition without a trusted registered driver.
	// ErrDriverNotFound 表示系统定义没有已注册的受信任 Driver。
	ErrDriverNotFound = errors.New("trusted provider driver not found")
	// ErrModelDiscoveryUnsupported reports a driver that cannot build model metadata.
	// ErrModelDiscoveryUnsupported 表示 Driver 无法构建模型元数据。
	ErrModelDiscoveryUnsupported = errors.New("provider model discovery is unsupported")
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
	if configurations == nil || catalogs == nil || drivers == nil {
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
	discoverer, supportsDiscovery := driver.(provider.ModelDiscoverer)
	if driverDefinition.Features.ModelDiscovery != providerconfig.SupportSupported || !supportsDiscovery {
		return catalog.Snapshot{}, fmt.Errorf("%w: %s", ErrModelDiscoveryUnsupported, instance.DefinitionID)
	}
	discovery, errDiscovery := discoverer.DiscoverModels(ctx, provider.DiscoveryRequest{ProviderInstance: instance})
	if errDiscovery != nil {
		return catalog.Snapshot{}, fmt.Errorf("discover provider models: %w", errDiscovery)
	}
	if discovery.ObservedAt.IsZero() {
		return catalog.Snapshot{}, errors.New("provider model discovery observed time is required")
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
		if planReader, supported := driver.(provider.PlanReader); driverDefinition.Features.PlanReader == providerconfig.SupportSupported && supported {
			plan, errPlan := planReader.ReadPlan(ctx, instance, credential)
			if errPlan != nil {
				return catalog.Snapshot{}, fmt.Errorf("read provider plan for credential %s: %w", credential.ID, errPlan)
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
			for _, allowance := range credentialAllowances {
				if errAppend := appendUnique(allowance.ID, allowance, allowanceByID, &allowances); errAppend != nil {
					return catalog.Snapshot{}, errAppend
				}
			}
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
