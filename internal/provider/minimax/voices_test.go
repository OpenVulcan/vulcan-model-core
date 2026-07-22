package minimax

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
)

// TestReadVoicesUsesExactRegionCredentialAndNormalizesCatalog verifies the released endpoint, body, and account scope.
// TestReadVoicesUsesExactRegionCredentialAndNormalizesCatalog 验证已发布端点、正文与账号作用域。
func TestReadVoicesUsesExactRegionCredentialAndNormalizesCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.URL.Path != miniMaxVoiceCatalogPath || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer minimax-key" || string(body) != `{"voice_type":"system"}` {
			t.Errorf("request method=%q path=%q authorization=%q body=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"), body)
		}
		_, _ = io.WriteString(writer, `{"system_voice":[{"voice_id":"English_expressive_narrator","voice_name":"Expressive Narrator","description":["English","Narration","English"]}],"base_resp":{"status_code":0}}`)
	}))
	defer server.Close()
	secrets := secret.NewMemoryStore()
	secretRef, errSecret := secrets.Put(context.Background(), []byte("minimax-key"))
	if errSecret != nil {
		t.Fatalf("put secret: %v", errSecret)
	}
	definition := providerconfig.ProviderDefinition{ID: "system_minimax_api", EndpointPresets: []providerconfig.EndpointPreset{{ID: "default", BaseURL: server.URL, Region: "Global"}}}
	driver, errDriver := NewAllowanceDriver(definition, secrets, server.Client())
	if errDriver != nil {
		t.Fatalf("NewAllowanceDriver() error = %v", errDriver)
	}
	observedAt := time.Date(2026, time.July, 21, 10, 0, 0, 0, time.UTC)
	driver.now = func() time.Time { return observedAt }
	instance := providerconfig.ProviderInstance{ID: "pvi_minimax_voice", DefinitionID: definition.ID}
	credential := providerconfig.Credential{ID: "cred_minimax_voice", ProviderInstanceID: instance.ID, AuthMethodID: "api_key", SecretRef: secretRef}
	voices, errVoices := driver.ReadVoices(context.Background(), instance, credential)
	if errVoices != nil {
		t.Fatalf("ReadVoices() error = %v", errVoices)
	}
	if len(voices) != 1 || voices[0].VoiceID != "English_expressive_narrator" || voices[0].DisplayName != "Expressive Narrator" || voices[0].CredentialID != credential.ID || len(voices[0].Descriptions) != 2 || !voices[0].ExpiresAt.Equal(observedAt.Add(miniMaxVoiceCacheLifetime)) {
		t.Fatalf("voices = %#v", voices)
	}
}
