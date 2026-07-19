package provider

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/OpenVulcan/vulcan-model-core/internal/dependency"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
)

// Registry stores trusted system-provider libraries by immutable definition identifier.
// Registry 按不可变定义标识存储受信任系统供应商库。
type Registry struct {
	// mu protects driver registration and snapshot reads.
	// mu 保护 Driver 注册和快照读取。
	mu sync.RWMutex
	// definitions registers immutable system definition metadata.
	// definitions 注册不可变系统定义元数据。
	definitions *providerconfig.SystemRegistry
	// drivers stores trusted libraries by system provider definition identifier.
	// drivers 按系统供应商定义标识存储受信任库。
	drivers map[string]Driver
}

// NewRegistry creates an empty trusted provider library registry.
// NewRegistry 创建一个空的受信任供应商库注册表。
func NewRegistry(definitions *providerconfig.SystemRegistry) (*Registry, error) {
	if definitions == nil {
		return nil, errors.New("system provider definition registry is required")
	}
	return &Registry{definitions: definitions, drivers: make(map[string]Driver)}, nil
}

// Register validates a driver capability contract and registers its immutable definition.
// Register 校验 Driver 能力合同并注册其不可变定义。
func (r *Registry) Register(driver Driver) error {
	if dependency.IsNil(driver) {
		return errors.New("provider driver is required")
	}
	definition := driver.Definition()
	if definition.Kind != providerconfig.DefinitionKindSystem {
		return errors.New("trusted provider registry accepts only system definitions")
	}
	if err := validateFeatureContracts(driver, definition.Features); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.drivers[definition.ID]; exists {
		return fmt.Errorf("provider driver %s is already registered", definition.ID)
	}
	registeredDefinition, exists := r.definitions.Lookup(definition.ID)
	if exists {
		if !reflect.DeepEqual(registeredDefinition, definition) {
			return fmt.Errorf("provider driver definition %s differs from the registered system definition", definition.ID)
		}
	} else if err := r.definitions.Register(definition); err != nil {
		return err
	}
	r.drivers[definition.ID] = driver
	return nil
}

// Lookup returns the exact trusted driver for one system provider definition.
// Lookup 返回一个系统供应商定义的精确受信任 Driver。
func (r *Registry) Lookup(definitionID string) (Driver, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	driver, exists := r.drivers[definitionID]
	return driver, exists
}

// DefinitionIDs returns a stable sorted trusted driver identifier snapshot.
// DefinitionIDs 返回稳定排序的受信任 Driver 标识快照。
func (r *Registry) DefinitionIDs() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	definitionIDs := make([]string, 0, len(r.drivers))
	for definitionID := range r.drivers {
		definitionIDs = append(definitionIDs, definitionID)
	}
	sort.Strings(definitionIDs)
	return definitionIDs
}

// validateFeatureContracts verifies that supported metadata capabilities have concrete library contracts.
// validateFeatureContracts 校验声明支持的元数据能力具有具体库合同。
func validateFeatureContracts(driver Driver, features providerconfig.ProviderFeatureSet) error {
	if features.ModelDiscovery == providerconfig.SupportSupported {
		if _, ok := driver.(ModelDiscoverer); !ok {
			return errors.New("provider declares model discovery but does not implement ModelDiscoverer")
		}
	}
	if features.PlanReader == providerconfig.SupportSupported {
		if _, ok := driver.(PlanReader); !ok {
			return errors.New("provider declares plan reading but does not implement PlanReader")
		}
	}
	if features.EntitlementReader == providerconfig.SupportSupported {
		if _, ok := driver.(EntitlementReader); !ok {
			return errors.New("provider declares entitlement reading but does not implement EntitlementReader")
		}
	}
	if features.AllowanceReader == providerconfig.SupportSupported {
		if _, ok := driver.(AllowanceReader); !ok {
			return errors.New("provider declares allowance reading but does not implement AllowanceReader")
		}
	}
	return nil
}
