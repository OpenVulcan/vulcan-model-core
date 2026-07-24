package alibaba

import (
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
)

// TestAlibabaJSONHeadersMatchCopiedOSSRule verifies only validated OSS materializations receive the required resolution header.
// TestAlibabaJSONHeadersMatchCopiedOSSRule 验证只有已校验的 OSS 物化资源才会获得必需解析头。
func TestAlibabaJSONHeadersMatchCopiedOSSRule(t *testing.T) {
	plain := alibabaJSONHeaders([]resource.MaterializedInput{{Mode: catalog.MaterializationDirectRemoteURL, RemoteURL: "https://example.com/a.png"}}, false)
	if len(plain) != 1 || plain[0].Name != "Content-Type" {
		t.Fatalf("plain headers = %#v", plain)
	}
	object := alibabaJSONHeaders([]resource.MaterializedInput{{Mode: catalog.MaterializationProviderObjectURI, ProviderHandle: "oss://bucket/a.png", ProviderAssetKind: resource.ProviderAssetObject}}, true)
	if len(object) != 3 || object[1].Name != "X-DashScope-Async" || object[2].Name != "X-DashScope-OssResourceResolve" || object[2].Value != "enable" {
		t.Fatalf("object headers = %#v", object)
	}
	// promptLikeHandle proves an arbitrary string-shaped handle cannot impersonate a validated provider object.
	// promptLikeHandle 证明任意字符串形态的句柄不能冒充已验证的供应商对象。
	promptLikeHandle := alibabaJSONHeaders([]resource.MaterializedInput{{Mode: catalog.MaterializationDirectRemoteURL, ProviderHandle: "oss://mentioned-in-text"}}, false)
	if len(promptLikeHandle) != 1 {
		t.Fatalf("prompt-like headers = %#v", promptLikeHandle)
	}
}
