package alibaba

import (
	"strings"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// alibabaJSONHeaders copies bailian-cli's conditional OSS resolution and asynchronous request headers.
// alibabaJSONHeaders 复制 bailian-cli 的条件式 OSS 解析头与异步请求头。
func alibabaJSONHeaders(inputs []resource.MaterializedInput, asynchronous bool) []transport.Header {
	headers := []transport.Header{{Name: "Content-Type", Value: "application/json"}}
	if asynchronous {
		headers = append(headers, transport.Header{Name: "X-DashScope-Async", Value: "enable"})
	}
	for _, input := range inputs {
		if input.Mode == catalog.MaterializationProviderObjectURI && input.ProviderAssetKind == resource.ProviderAssetObject && strings.HasPrefix(strings.TrimSpace(input.ProviderHandle), "oss://") && strings.TrimSpace(strings.TrimPrefix(input.ProviderHandle, "oss://")) != "" {
			headers = append(headers, transport.Header{Name: "X-DashScope-OssResourceResolve", Value: "enable"})
			break
		}
	}
	return headers
}
