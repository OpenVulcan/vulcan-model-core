package management

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/vcp"
)

// ReconcileCustomConversationCatalogs restores executable delivery modes omitted by historical custom-provider model builders.
// ReconcileCustomConversationCatalogs 恢复历史自定义供应商模型构建器遗漏的可执行交付模式。
func ReconcileCustomConversationCatalogs(ctx context.Context, configurations providerconfig.Store, catalogs catalog.Store) (int, error) {
	if ctx == nil {
		return 0, errors.New("context is required")
	}
	if dependency.IsNil(configurations) || dependency.IsNil(catalogs) {
		return 0, errors.New("provider configuration and catalog stores are required")
	}
	instances, errInstances := configurations.ListInstances(ctx, "")
	if errInstances != nil {
		return 0, fmt.Errorf("list provider instances for custom delivery reconciliation: %w", errInstances)
	}
	targetResolver, errResolver := resolve.New(configurations, catalogs)
	if errResolver != nil {
		return 0, errResolver
	}
	reconciliationTime := time.Now().UTC()
	changedInstances := 0
	for _, instance := range instances {
		definition, errDefinition := configurations.GetDefinition(ctx, instance.DefinitionID)
		if errDefinition != nil {
			return changedInstances, fmt.Errorf("get custom provider definition %s: %w", instance.DefinitionID, errDefinition)
		}
		if definition.Kind != providerconfig.DefinitionKindCustom {
			continue
		}
		expectedDelivery, errDelivery := defaultCustomDelivery(definition.ProtocolProfileID)
		if errDelivery != nil {
			return changedInstances, errDelivery
		}
		current, errCurrent := catalogs.Get(ctx, instance.ID)
		if errors.Is(errCurrent, catalog.ErrSnapshotNotFound) {
			continue
		}
		if errCurrent != nil {
			return changedInstances, fmt.Errorf("get custom provider catalog %s: %w", instance.ID, errCurrent)
		}
		migrated, changed, errMigrate := migrateCustomConversationDelivery(current, definition.ProtocolProfileID, expectedDelivery, reconciliationTime)
		if errMigrate != nil {
			return changedInstances, fmt.Errorf("migrate custom provider delivery %s: %w", instance.ID, errMigrate)
		}
		if !changed {
			continue
		}
		migrated.Pools, errResolver = targetResolver.SummarizeSnapshot(ctx, migrated, reconciliationTime, migrated.Revision)
		if errResolver != nil {
			return changedInstances, fmt.Errorf("summarize migrated custom provider catalog %s: %w", instance.ID, errResolver)
		}
		if errSave := catalogs.Save(ctx, migrated); errSave != nil {
			return changedInstances, fmt.Errorf("save migrated custom provider catalog %s: %w", instance.ID, errSave)
		}
		changedInstances++
	}
	return changedInstances, nil
}

// migrateCustomConversationDelivery restores the protocol-guaranteed modes and closed conversation operation omitted by historical custom models.
// migrateCustomConversationDelivery 恢复历史自定义模型遗漏的协议保证交付模式与封闭会话操作。
func migrateCustomConversationDelivery(current catalog.Snapshot, channelID string, expected catalog.DeliveryCapabilities, observedAt time.Time) (catalog.Snapshot, bool, error) {
	migrated := current
	migrated.Offerings = append([]catalog.ModelOffering(nil), current.Offerings...)
	migrated.Profiles = append([]catalog.ExecutionProfile(nil), current.Profiles...)
	changed := false
	for index := range migrated.Offerings {
		if migrated.Offerings[index].ChannelID != channelID || hasDeliveryMode(migrated.Offerings[index].Capabilities.Delivery) {
			continue
		}
		if migrated.Offerings[index].Revision == math.MaxUint64 || migrated.Offerings[index].CapabilityRevision == math.MaxUint64 {
			return catalog.Snapshot{}, false, errors.New("custom provider offering revision is exhausted")
		}
		migrated.Offerings[index].Capabilities.Delivery = expected
		migrated.Offerings[index].Revision++
		migrated.Offerings[index].CapabilityRevision++
		changed = true
	}
	for index := range migrated.Profiles {
		needsDelivery := !hasDeliveryMode(migrated.Profiles[index].Capabilities.Delivery)
		needsOperation := migrated.Profiles[index].Operation == ""
		needsProfileDriver := !migrated.Profiles[index].ProfileDriver
		if !needsDelivery && !needsOperation && !needsProfileDriver {
			continue
		}
		if migrated.Profiles[index].Revision == math.MaxUint64 || migrated.Profiles[index].CapabilityRevision == math.MaxUint64 {
			return catalog.Snapshot{}, false, errors.New("custom provider profile revision is exhausted")
		}
		if needsDelivery {
			migrated.Profiles[index].Capabilities.Delivery = expected
		}
		if needsOperation {
			migrated.Profiles[index].Operation = vcp.OperationConversationRespond
		}
		if needsProfileDriver {
			migrated.Profiles[index].ProfileDriver = true
		}
		migrated.Profiles[index].Revision++
		migrated.Profiles[index].CapabilityRevision++
		changed = true
	}
	if !changed {
		return current, false, nil
	}
	if migrated.Revision == math.MaxUint64 {
		return catalog.Snapshot{}, false, errors.New("custom provider catalog revision is exhausted")
	}
	migrated.Revision++
	migrated.ObservedAt = observedAt.UTC()
	if errValidate := migrated.Validate(); errValidate != nil {
		return catalog.Snapshot{}, false, errValidate
	}
	return migrated, true, nil
}

// hasDeliveryMode reports whether at least one concrete result-delivery mode is declared.
// hasDeliveryMode 报告是否已经声明至少一种具体结果交付模式。
func hasDeliveryMode(delivery catalog.DeliveryCapabilities) bool {
	return delivery.Synchronous || delivery.Streaming || delivery.Asynchronous
}
