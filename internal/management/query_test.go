package management

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-model-core/internal/catalog"
)

// TestQueryServiceRedactsCredentialSecretMetadata verifies every management query view excludes secret references and identity correlation fields.
// TestQueryServiceRedactsCredentialSecretMetadata 验证每个管理查询视图均排除 Secret 引用和身份关联字段。
func TestQueryServiceRedactsCredentialSecretMetadata(t *testing.T) {
	// ctx fixes one shared configuration operation scope.
	// ctx 固定一个共享配置操作范围。
	ctx := context.Background()
	// commands and configurations share the memory-backed provider configuration state.
	// commands 和 configurations 共享内存后端供应商配置状态。
	commands, configurations, _ := managementTestService(t)
	instance, errInstance := commands.CreateInstance(ctx, CreateInstanceInput{
		ID: "pvi_query_redaction", DefinitionID: "system_management_test", Handle: "query-redaction", DisplayName: "Query Redaction",
	})
	if errInstance != nil {
		t.Fatalf("create provider instance: %v", errInstance)
	}
	endpoint, errEndpoint := commands.AddEndpoint(ctx, AddEndpointInput{
		ID: "ep_query_redaction", ProviderInstanceID: instance.ID, ChannelID: "anthropic", BaseURL: "https://query-redaction.example/v1",
	})
	if errEndpoint != nil {
		t.Fatalf("create endpoint: %v", errEndpoint)
	}
	credential, errCredential := commands.AddCredential(ctx, AddCredentialInput{
		ID: "cred_query_redaction", ProviderInstanceID: instance.ID, AuthMethodID: "oauth", Label: "Safe Label",
		PrincipalKey: "sensitive-principal", Fingerprint: "sensitive-fingerprint", Secret: []byte("sensitive-secret"),
	})
	if errCredential != nil {
		t.Fatalf("create credential: %v", errCredential)
	}
	if _, errBinding := commands.AddBinding(ctx, AddBindingInput{
		ID: "bind_query_redaction", ProviderInstanceID: instance.ID, ChannelID: "anthropic", EndpointID: endpoint.ID, CredentialID: credential.ID,
	}); errBinding != nil {
		t.Fatalf("create binding: %v", errBinding)
	}
	// queries uses a catalog store even though these configuration-only routes do not read a snapshot.
	// queries 使用目录存储，即使这些仅配置路由不读取快照。
	queries, errQueries := NewQueryService(configurations, catalog.NewMemoryStore())
	if errQueries != nil {
		t.Fatalf("create query service: %v", errQueries)
	}
	credentialViews, errCredentials := queries.ListCredentials(ctx, instance.ID)
	if errCredentials != nil {
		t.Fatalf("list credential views: %v", errCredentials)
	}
	if len(credentialViews) != 1 || credentialViews[0].ID != credential.ID || credentialViews[0].Label != "Safe Label" {
		t.Fatalf("credential views = %+v", credentialViews)
	}
	encodedViews, errEncode := json.Marshal(credentialViews)
	if errEncode != nil {
		t.Fatalf("encode credential views: %v", errEncode)
	}
	// encodedText is checked as an external caller would observe the management response.
	// encodedText 按外部调用方可观察的管理响应进行检查。
	encodedText := strings.ToLower(string(encodedViews))
	for _, forbidden := range []string{"secret_ref", "sensitive-secret", "sensitive-principal", "sensitive-fingerprint", "principal_key", "fingerprint"} {
		if strings.Contains(encodedText, forbidden) {
			t.Fatalf("credential query leaked %q in %s", forbidden, encodedViews)
		}
	}
	endpointViews, errEndpoints := queries.ListEndpoints(ctx, instance.ID)
	if errEndpoints != nil || len(endpointViews) != 1 || endpointViews[0].ID != endpoint.ID {
		t.Fatalf("endpoint views = %+v, error = %v", endpointViews, errEndpoints)
	}
	bindingViews, errBindings := queries.ListBindings(ctx, instance.ID)
	if errBindings != nil || len(bindingViews) != 1 || bindingViews[0].CredentialID != credential.ID {
		t.Fatalf("binding views = %+v, error = %v", bindingViews, errBindings)
	}
}
