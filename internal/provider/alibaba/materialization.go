package alibaba

import (
	"fmt"
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// alibabaObjectURI returns one exact Router-managed temporary OSS handle.
// alibabaObjectURI 返回一个精确的 Router 管理临时 OSS 句柄。
func alibabaObjectURI(input resource.MaterializedInput, category error) (string, error) {
	if input.Mode != catalog.MaterializationProviderObjectURI || input.ProviderAssetKind != resource.ProviderAssetObject || !strings.HasPrefix(strings.TrimSpace(input.ProviderHandle), "oss://") || strings.TrimSpace(strings.TrimPrefix(input.ProviderHandle, "oss://")) == "" {
		return "", fmt.Errorf("%w: Alibaba provider object materialization is invalid", category)
	}
	return input.ProviderHandle, nil
}
